from __future__ import annotations

from fastapi import HTTPException, status

from app.services.password_policy import validate_password_strength


def ensure_strong_password(password: str) -> None:
    try:
        validate_password_strength(password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
