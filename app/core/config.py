from functools import lru_cache
import base64
import os
import secrets

from pydantic import Field, AliasChoices
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "SentinelAuth OS"
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
    totp_issuer: str = "SentinelAuth OS"
    mfa_method: str = "email"
    email_otp_ttl_minutes: int = 5
    email_otp_length: int = 6
    email_otp_max_attempts: int = 5
    expose_email_otp_in_response: bool = False
    email_otp_subject: str = "Your SentinelAuth OS verification code"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_use_starttls: str | bool = True
    smtp_username: str = ""
    smtp_password: str = Field(default="", validation_alias=AliasChoices("SMTP_PASSWORD", "Mail"))
    smtp_from_email: str = ""
    auth_backend: str = "local"
    audit_log_path: str = "logs/audit.log"
    refresh_cookie_name: str = "refresh_token"
    refresh_cookie_samesite: str = "lax"
    refresh_cookie_secure: bool = Field(default_factory=lambda: os.getenv("ENVIRONMENT", "development").lower() != "development")
    bootstrap_admin_enabled: bool = True
    bootstrap_admin_username: str = "Pirate"
    bootstrap_admin_password: str = "Pirate9801"
    bootstrap_admin_email: str = "nilesh.singh7829@gmail.com"
    bootstrap_admin_totp_secret: str = "JBSWY3DPEHPK3PXP"


@lru_cache
def get_settings() -> Settings:
    return Settings()
