from __future__ import annotations

import base64
import hashlib
import hmac
import io
import secrets
from datetime import datetime, timedelta, timezone

import qrcode
import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import Settings

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def password_matches_hash(password: str, hashed_password: str) -> bool:
    try:
        return verify_password(password, hashed_password)
    except Exception:
        return False


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def build_totp_uri(username: str, secret: str, issuer: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def qr_code_data_uri(content: str) -> str:
    image = qrcode.make(content)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{encoded}"


def _encryption_key_bytes(settings: Settings) -> bytes:
    key = base64.urlsafe_b64decode(settings.data_encryption_key.encode("utf-8"))
    if len(key) != 32:
        raise ValueError("DATA_ENCRYPTION_KEY must decode to exactly 32 bytes")
    return key


def encrypt_secret(plaintext: str, settings: Settings) -> str:
    key = _encryption_key_bytes(settings)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_secret(token: str, settings: Settings) -> str:
    raw = base64.urlsafe_b64decode(token.encode("utf-8"))
    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm = AESGCM(_encryption_key_bytes(settings))
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def generate_jti() -> str:
    return secrets.token_urlsafe(32)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_token(subject: str, role: str, secret_key: str, token_type: str, expires_delta: timedelta, extra_claims: dict | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "role": role,
        "typ": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "jti": generate_jti(),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, secret_key, algorithm="HS256")


def decode_token(token: str, secret_key: str) -> dict:
    try:
        return jwt.decode(token, secret_key, algorithms=["HS256"])
    except JWTError as exc:
        raise ValueError("Invalid token") from exc


def verify_totp(secret: str, otp: str, valid_window: int = 1) -> bool:
    totp = pyotp.TOTP(secret)
    return bool(totp.verify(otp, valid_window=valid_window))


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
