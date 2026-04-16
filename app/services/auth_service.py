from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import decode_token, hash_password, password_matches_hash, sha256_hex
from app.models.enums import UserRole
from app.models.password_reset_token import PasswordResetToken
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.services.audit_service import AuditService
from app.services.email_sender import EmailDeliveryError, EmailSender
from app.services.email_otp_service import EmailOtpService
from app.services.mfa_service import MfaService
from app.services.password_policy import password_was_recently_used, validate_password_strength
from app.services.rate_limiter import LoginRateLimiter
from app.services.os_auth import get_os_auth_provider
from app.services.token_service import TokenService


@dataclass
class RegistrationResult:
    user: User
    provisioning_uri: str | None = None
    qr_code_data_uri: str | None = None


@dataclass
class LoginResult:
    mfa_token: str
    mfa_method: str
    delivery_hint: str | None = None
    test_otp: str | None = None


@dataclass
class ForgotPasswordResult:
    detail: str
    debug_reset_token: str | None = None


@dataclass
class AuthenticatedSession:
    access_token: str
    refresh_token: str
    expires_at: datetime


class AuthService:
    def __init__(self, db: Session, settings: Settings, audit_service: AuditService | None = None) -> None:
        self.db = db
        self.settings = settings
        self.users = UserRepository(db)
        self.tokens = TokenService(settings)
        self.mfa = MfaService(settings)
        self.email_otp = EmailOtpService(settings, self.users)
        self.email_sender = EmailSender(settings)
        self.os_auth = get_os_auth_provider(settings)
        self.audit = audit_service or AuditService(db, settings)
        self.rate_limiter = LoginRateLimiter(settings.login_rate_limit_attempts, settings.login_rate_limit_window_seconds)

    @staticmethod
    def _as_utc(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def register(self, username: str, email: str, password: str, role: str = UserRole.user.value, ip_address: str | None = None) -> RegistrationResult:
        normalized_username = username.strip()
        normalized_email = email.strip().lower()
        try:
            validate_password_strength(password)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        if self.users.get_by_username(normalized_username):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
        if self.users.get_by_email(normalized_email):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")
        if role != UserRole.user.value:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Public registration only supports user role")
        password_hash = hash_password(password)
        provisioning_uri = None
        qr_uri = None
        encrypted_secret = None
        if self.settings.mfa_method.strip().lower() == "totp":
            _, encrypted_secret, provisioning_uri, qr_uri = self.mfa.create_setup_payload(normalized_username)
        now = datetime.now(timezone.utc)
        user = User(
            username=normalized_username,
            email=normalized_email,
            password_hash=password_hash,
            role=role,
            mfa_enabled=True,
            mfa_secret_encrypted=encrypted_secret,
            password_changed_at=now,
            password_expires_at=now + timedelta(days=self.settings.password_expiry_days),
        )
        self.users.create(user)
        self.users.add_password_history(user.id, password_hash)
        self.db.commit()
        self.audit.record("register", True, user_id=user.id, ip_address=ip_address, detail=f"username={normalized_username}")
        return RegistrationResult(user=user, provisioning_uri=provisioning_uri, qr_code_data_uri=qr_uri)

    def login(self, username: str, password: str, ip_address: str | None = None, user_agent: str | None = None) -> LoginResult:
        normalized_username = username.strip()
        if not self.rate_limiter.allow(f"{ip_address}:{normalized_username}").allowed:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts")
        user = self.users.get_by_username(normalized_username)
        if not user or not user.is_active:
            self.audit.record("login", False, detail="unknown user or inactive", ip_address=ip_address)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        now = datetime.now(timezone.utc)
        locked_until = self._as_utc(user.locked_until)
        password_expires_at = self._as_utc(user.password_expires_at)
        if locked_until and locked_until > now:
            raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account locked")
        if password_expires_at and password_expires_at < now:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Password expired")
        backend = self.settings.auth_backend.strip().lower()
        if backend == "pam":
            try:
                credentials_valid = self.os_auth.authenticate(normalized_username, password)
            except Exception:
                credentials_valid = False
        else:
            credentials_valid = password_matches_hash(password, user.password_hash)

        if not credentials_valid:
            locked_until = None
            if user.failed_login_attempts + 1 >= self.settings.max_failed_attempts:
                locked_until = now + timedelta(minutes=self.settings.lockout_minutes)
            self.users.register_failed_attempt(user, locked_until)
            self.db.commit()
            self.audit.record("login", False, user_id=user.id, ip_address=ip_address, detail="bad password")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        self.users.reset_failed_attempts(user)
        self.db.commit()
        mfa_token = self.tokens.create_mfa_token(user.id, user.role)
        mfa_method = self.settings.mfa_method.strip().lower()
        delivery_hint = None
        test_otp = None
        if mfa_method == "email":
            code = self.email_otp.issue_challenge(user)
            self.db.commit()
            delivery_hint = self.email_otp.delivery_hint(user.email)
            non_production = self.settings.environment.strip().lower() != "production"
            delivery_ok = False
            try:
                self.email_sender.send_otp(user.email, code)
                delivery_ok = True
            except EmailDeliveryError:
                if self.settings.expose_email_otp_in_response:
                    test_otp = code
                    delivery_hint = "Email delivery is unavailable. Using test OTP display in non-production mode."
                elif non_production:
                    test_otp = code
                    delivery_hint = "Email delivery is unavailable. Using test OTP display in non-production mode."
                else:
                    self.audit.record(
                        "mfa_email_otp_delivery_failed",
                        False,
                        user_id=user.id,
                        ip_address=ip_address,
                        detail="smtp not configured or delivery failed",
                    )
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Email OTP delivery is unavailable. Contact support.",
                    )
            if non_production:
                # Keep local/dev login usable even when mailbox access is delayed.
                test_otp = code
            if self.settings.expose_email_otp_in_response and not test_otp:
                test_otp = code
            detail = f"email={user.email} delivered={delivery_ok}"
            self.audit.record("mfa_email_otp_issued", True, user_id=user.id, ip_address=ip_address, detail=detail)

        self.audit.record("login", True, user_id=user.id, ip_address=ip_address, detail="password accepted")
        return LoginResult(mfa_token=mfa_token, mfa_method=mfa_method or "totp", delivery_hint=delivery_hint, test_otp=test_otp)

    def verify_mfa(self, mfa_token: str, otp: str, ip_address: str | None = None, user_agent: str | None = None) -> AuthenticatedSession:
        normalized_otp = "".join(ch for ch in str(otp).strip() if ch.isdigit())
        try:
            payload = decode_token(mfa_token, self.settings.secret_key)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token") from exc
        if payload.get("typ") != "mfa_pending":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token")
        user = self.users.get_by_id(payload["sub"])
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user state")

        mfa_method = self.settings.mfa_method.strip().lower()
        if mfa_method == "email":
            email_verified = self.email_otp.verify_challenge(user.id, normalized_otp)
            # Admins can recover from mailbox delivery issues by using enrolled authenticator OTP.
            admin_totp_verified = bool(
                user.role == UserRole.admin.value
                and user.mfa_secret_encrypted
                and self.mfa.verify_otp(user.mfa_secret_encrypted, normalized_otp)
            )
            if not email_verified and not admin_totp_verified:
                self.db.commit()
                self.audit.record("mfa", False, user_id=user.id, ip_address=ip_address, detail="bad email otp")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
            self.db.commit()
        else:
            if not user.mfa_secret_encrypted or not self.mfa.verify_otp(user.mfa_secret_encrypted, normalized_otp):
                self.audit.record("mfa", False, user_id=user.id, ip_address=ip_address, detail="bad otp")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")

        access_token = self.tokens.create_access_token(user.id, user.role)
        refresh_token, token_hash, refresh_jti, expires_at = self.tokens.create_refresh_token(user.id, user.role)
        stored_refresh = RefreshToken(
            user_id=user.id,
            jti=refresh_jti,
            token_hash=token_hash,
            user_agent=user_agent,
            ip_address=ip_address,
            expires_at=expires_at,
        )
        self.users.store_refresh_token(stored_refresh)
        self.db.commit()
        self.audit.record("mfa", True, user_id=user.id, ip_address=ip_address, detail="otp accepted")
        return AuthenticatedSession(access_token=access_token, refresh_token=refresh_token, expires_at=expires_at)

    def refresh(self, refresh_token: str, ip_address: str | None = None, user_agent: str | None = None) -> AuthenticatedSession:
        try:
            payload = decode_token(refresh_token, self.settings.secret_key)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from exc
        if payload.get("typ") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        token_hash = sha256_hex(refresh_token)
        stored = self.users.get_refresh_token_by_hash(token_hash)
        if not stored or stored.revoked_at is not None or stored.expires_at < datetime.now(timezone.utc):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked or expired")
        user = self.users.get_by_id(payload["sub"])
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user")
        self.users.revoke_refresh_token(stored)
        new_access = self.tokens.create_access_token(user.id, user.role)
        new_refresh, new_hash, refresh_jti, expires_at = self.tokens.create_refresh_token(user.id, user.role)
        self.users.store_refresh_token(
            RefreshToken(
                user_id=user.id,
                jti=refresh_jti,
                token_hash=new_hash,
                user_agent=user_agent,
                ip_address=ip_address,
                expires_at=expires_at,
            )
        )
        self.db.commit()
        self.audit.record("refresh", True, user_id=user.id, ip_address=ip_address, detail="rotated refresh token")
        return AuthenticatedSession(access_token=new_access, refresh_token=new_refresh, expires_at=expires_at)

    def logout(self, refresh_token: str, ip_address: str | None = None) -> None:
        try:
            payload = decode_token(refresh_token, self.settings.secret_key)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from exc
        token_hash = sha256_hex(refresh_token)
        stored = self.users.get_refresh_token_by_hash(token_hash)
        if stored:
            self.users.revoke_refresh_token(stored)
            self.db.commit()
        self.audit.record("logout", True, user_id=payload.get("sub"), ip_address=ip_address, detail="logout")

    def forgot_password(self, email: str, ip_address: str | None = None) -> ForgotPasswordResult:
        normalized_email = email.strip().lower()
        user = self.users.get_by_email(normalized_email)
        detail = "If the account exists, password reset instructions were sent."
        if not user or not user.is_active:
            self.audit.record("forgot_password", False, ip_address=ip_address, detail=f"unknown email={normalized_email}")
            return ForgotPasswordResult(detail=detail)

        now = datetime.now(timezone.utc)
        self.users.invalidate_active_password_reset_tokens(user.id, now)
        raw_token = secrets.token_urlsafe(32)
        token_hash = sha256_hex(raw_token)
        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=now + timedelta(minutes=self.settings.password_reset_ttl_minutes),
        )
        self.users.create_password_reset_token(reset_token)
        self.db.commit()

        debug_token = None
        try:
            self.email_sender.send_password_reset(user.email, raw_token)
        except EmailDeliveryError:
            if self.settings.environment.strip().lower() != "production" or self.settings.expose_password_reset_token_in_response:
                debug_token = raw_token
            self.audit.record(
                "forgot_password_delivery_failed",
                False,
                user_id=user.id,
                ip_address=ip_address,
                detail="smtp not configured or delivery failed",
            )
            return ForgotPasswordResult(detail=detail, debug_reset_token=debug_token)

        self.audit.record("forgot_password", True, user_id=user.id, ip_address=ip_address, detail=f"email={user.email}")
        return ForgotPasswordResult(detail=detail, debug_reset_token=debug_token)

    def reset_password(self, token: str, new_password: str, ip_address: str | None = None) -> None:
        token_hash = sha256_hex(token.strip())
        reset_token = self.users.get_password_reset_token_by_hash(token_hash)
        now = datetime.now(timezone.utc)
        if not reset_token:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")

        expires_at = self._as_utc(reset_token.expires_at)
        if reset_token.used_at is not None or not expires_at or expires_at <= now:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")

        user = self.users.get_by_id(reset_token.user_id)
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid reset request")

        try:
            validate_password_strength(new_password)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

        recent_hashes = self.users.get_recent_password_hashes(user.id, self.settings.password_history_count)
        if password_was_recently_used(new_password, recent_hashes):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"New password must not match your last {self.settings.password_history_count} passwords",
            )

        new_hash = hash_password(new_password)
        user.password_hash = new_hash
        user.password_changed_at = now
        user.password_expires_at = now + timedelta(days=self.settings.password_expiry_days)
        self.users.add_password_history(user.id, new_hash)
        self.users.reset_failed_attempts(user)
        self.users.mark_password_reset_token_used(reset_token, now)
        self.db.commit()
        self.audit.record("reset_password", True, user_id=user.id, ip_address=ip_address, detail="password reset")

    def can_reuse_password(self, user_id: str, candidate_password: str) -> bool:
        history = self.users.get_recent_password_hashes(user_id, self.settings.password_history_count)
        return password_was_recently_used(candidate_password, history)

    def change_password(self, user_id: str, current_password: str, new_password: str, ip_address: str | None = None) -> None:
        user = self.users.get_by_id(user_id)
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if user.role == UserRole.admin.value:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin credentials are protected")

        if not password_matches_hash(current_password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")

        try:
            validate_password_strength(new_password)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

        recent_hashes = self.users.get_recent_password_hashes(user.id, self.settings.password_history_count)
        if password_was_recently_used(new_password, recent_hashes):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"New password must not match your last {self.settings.password_history_count} passwords",
            )

        new_hash = hash_password(new_password)
        now = datetime.now(timezone.utc)
        user.password_hash = new_hash
        user.password_changed_at = now
        user.password_expires_at = now + timedelta(days=self.settings.password_expiry_days)
        self.users.add_password_history(user.id, new_hash)
        self.users.reset_failed_attempts(user)
        self.db.commit()
        self.audit.record("password_change", True, user_id=user.id, ip_address=ip_address, detail="password updated")
