from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from app.core.config import Settings
from app.core.security import constant_time_equals, sha256_hex
from app.models.email_otp_challenge import EmailOtpChallenge
from app.models.user import User
from app.repositories.user_repository import UserRepository


class EmailOtpService:
    def __init__(self, settings: Settings, users: UserRepository) -> None:
        self.settings = settings
        self.users = users

    @staticmethod
    def _as_utc(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _generate_code(self) -> str:
        digits = "0123456789"
        return "".join(secrets.choice(digits) for _ in range(self.settings.email_otp_length))

    def issue_challenge(self, user: User) -> str:
        now = datetime.now(timezone.utc)
        self.users.expire_active_email_otp_challenges(user.id, now)
        code = self._generate_code()
        challenge = EmailOtpChallenge(
            user_id=user.id,
            otp_hash=sha256_hex(code),
            expires_at=now + timedelta(minutes=self.settings.email_otp_ttl_minutes),
        )
        self.users.create_email_otp_challenge(challenge)
        return code

    def verify_challenge(self, user_id: str, otp: str) -> bool:
        now = datetime.now(timezone.utc)
        challenge = self.users.get_latest_email_otp_challenge(user_id)
        if not challenge:
            return False

        expires_at = self._as_utc(challenge.expires_at)
        if challenge.consumed_at is not None or expires_at is None or expires_at <= now:
            return False

        if challenge.attempts >= self.settings.email_otp_max_attempts:
            return False

        otp_hash = sha256_hex(otp)
        if not constant_time_equals(challenge.otp_hash, otp_hash):
            self.users.increment_email_otp_attempt(challenge)
            return False

        self.users.consume_email_otp_challenge(challenge, now)
        return True

    def delivery_hint(self, email: str) -> str:
        masked = email
        if "@" in email:
            local, domain = email.split("@", 1)
            local_visible = (local[:2] + "***") if len(local) > 2 else "***"
            masked = f"{local_visible}@{domain}"
        return f"A one-time code was sent to {masked}"
