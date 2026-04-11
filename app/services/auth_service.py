from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import decode_token, hash_password, password_matches_hash
from app.models.enums import UserRole
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.services.audit_service import AuditService
from app.services.mfa_service import MfaService
from app.services.password_policy import password_was_recently_used, validate_password_strength
from app.services.rate_limiter import LoginRateLimiter
from app.services.token_service import TokenService


@dataclass
class RegistrationResult:
    user: User
    provisioning_uri: str
    qr_code_data_uri: str


@dataclass
class LoginResult:
    mfa_token: str


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
        if role not in {UserRole.admin.value, UserRole.user.value}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role")
        password_hash = hash_password(password)
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
        if not self.rate_limiter.allow(f"{ip_address}:{username}").allowed:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts")
        user = self.users.get_by_username(username.strip())
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
        if not password_matches_hash(password, user.password_hash):
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
        self.audit.record("login", True, user_id=user.id, ip_address=ip_address, detail="password accepted")
        return LoginResult(mfa_token=mfa_token)

    def verify_mfa(self, mfa_token: str, otp: str, ip_address: str | None = None, user_agent: str | None = None) -> AuthenticatedSession:
        try:
            payload = decode_token(mfa_token, self.settings.secret_key)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token") from exc
        if payload.get("typ") != "mfa_pending":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token")
        user = self.users.get_by_id(payload["sub"])
        if not user or not user.is_active or not user.mfa_secret_encrypted:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user state")
        if not self.mfa.verify_otp(user.mfa_secret_encrypted, otp):
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

    def can_reuse_password(self, user_id: str, candidate_password: str) -> bool:
        history = self.users.get_recent_password_hashes(user_id, self.settings.password_history_count)
        return password_was_recently_used(candidate_password, history)
