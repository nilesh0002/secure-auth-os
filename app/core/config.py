from functools import lru_cache
import base64
import os
import secrets

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "SecureAuthOS"
    environment: str = "development"
    database_url: str = "sqlite:////tmp/auth.db" if os.getenv("VERCEL") else "sqlite:///./auth.db"
    secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(64))
    data_encryption_key: str = Field(
        default_factory=lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8")
    )
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7
    mfa_pending_ttl_minutes: int = 5
    password_history_count: int = 5
    password_expiry_days: int = 90
    max_failed_attempts: int = 5
    lockout_minutes: int = 15
    login_rate_limit_attempts: int = 5
    login_rate_limit_window_seconds: int = 300
    totp_issuer: str = "SecureAuthOS"
    auth_backend: str = "local"
    audit_log_path: str = "logs/audit.log"


@lru_cache
def get_settings() -> Settings:
    return Settings()
