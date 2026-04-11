from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.config import Settings
from app.core.security import create_token, decode_token, sha256_hex


class TokenService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def create_access_token(self, user_id: str, role: str) -> str:
        return create_token(
            subject=user_id,
            role=role,
            secret_key=self.settings.secret_key,
            token_type="access",
            expires_delta=timedelta(minutes=self.settings.access_token_ttl_minutes),
        )

    def create_mfa_token(self, user_id: str, role: str) -> str:
        return create_token(
            subject=user_id,
            role=role,
            secret_key=self.settings.secret_key,
            token_type="mfa_pending",
            expires_delta=timedelta(minutes=self.settings.mfa_pending_ttl_minutes),
        )

    def create_refresh_token(self, user_id: str, role: str) -> tuple[str, str, str, datetime]:
        token = create_token(
            subject=user_id,
            role=role,
            secret_key=self.settings.secret_key,
            token_type="refresh",
            expires_delta=timedelta(days=self.settings.refresh_token_ttl_days),
        )
        payload = decode_token(token, self.settings.secret_key)
        # We use a separate hash for storage so the presented JWT is not kept at rest.
        token_hash = sha256_hex(token)
        expires_at = datetime.now(timezone.utc) + timedelta(days=self.settings.refresh_token_ttl_days)
        return token, token_hash, payload["jti"], expires_at
