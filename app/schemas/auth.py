from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field

from app.models.enums import UserRole


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    role: UserRole = UserRole.user


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class MfaVerifyRequest(BaseModel):
    mfa_token: str = Field(min_length=10)
    otp: str = Field(min_length=6, max_length=8)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime


class PendingMfaResponse(BaseModel):
    mfa_required: bool = True
    mfa_token: str
    mfa_method: str = "totp"
    delivery_hint: Optional[str] = None
    test_otp: Optional[str] = None
    mfa_setup_uri: Optional[str] = None
    qr_code_data_uri: Optional[str] = None


class RegistrationResponse(BaseModel):
    user_id: str
    username: str
    email: EmailStr
    role: UserRole
    mfa_setup_uri: Optional[str] = None
    qr_code_data_uri: Optional[str] = None


class RefreshRequest(BaseModel):
    refresh_token: str | None = Field(default=None, min_length=20)


class LogoutRequest(BaseModel):
    refresh_token: str | None = Field(default=None, min_length=20)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ForgotPasswordResponse(BaseModel):
    detail: str
    debug_reset_token: str | None = None


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=20)
    new_password: str = Field(min_length=1, max_length=128)


class BootstrapAdminMfaRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class BootstrapAdminMfaResponse(BaseModel):
    mfa_setup_uri: str
    qr_code_data_uri: str
