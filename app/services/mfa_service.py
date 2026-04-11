from __future__ import annotations

from app.core.config import Settings
from app.core.security import build_totp_uri, decrypt_secret, encrypt_secret, generate_totp_secret, qr_code_data_uri, verify_totp


class MfaService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def create_setup_payload(self, username: str) -> tuple[str, str, str, str]:
        secret = generate_totp_secret()
        encrypted_secret = encrypt_secret(secret, self.settings)
        provisioning_uri = build_totp_uri(username=username, secret=secret, issuer=self.settings.totp_issuer)
        qr_uri = qr_code_data_uri(provisioning_uri)
        return secret, encrypted_secret, provisioning_uri, qr_uri

    def verify_otp(self, encrypted_secret: str, otp: str) -> bool:
        secret = decrypt_secret(encrypted_secret, self.settings)
        return verify_totp(secret, otp)
