import re

from app.core.security import verify_password

PASSWORD_POLICY_MESSAGE = (
    "Password must be at least 12 characters and include uppercase, lowercase, number, and special character."
)


def validate_password_strength(password: str) -> None:
    if len(password) < 12:
        raise ValueError(PASSWORD_POLICY_MESSAGE)
    if not re.search(r"[A-Z]", password):
        raise ValueError(PASSWORD_POLICY_MESSAGE)
    if not re.search(r"[a-z]", password):
        raise ValueError(PASSWORD_POLICY_MESSAGE)
    if not re.search(r"[0-9]", password):
        raise ValueError(PASSWORD_POLICY_MESSAGE)
    if not re.search(r"[^A-Za-z0-9]", password):
        raise ValueError(PASSWORD_POLICY_MESSAGE)


def password_was_recently_used(candidate_password: str, password_hashes: list[str]) -> bool:
    for password_hash in password_hashes:
        if verify_password(candidate_password, password_hash):
            return True
    return False
