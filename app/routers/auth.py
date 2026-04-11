from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.dependencies import get_current_user, require_role
from app.db.session import get_db
from app.models.enums import UserRole
from app.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    MfaVerifyRequest,
    PendingMfaResponse,
    RefreshRequest,
    RegisterRequest,
    RegistrationResponse,
    TokenResponse,
)
from app.schemas.user import UserRead
from app.services.auth_service import AuthService

router = APIRouter()


def _service(db: Session = Depends(get_db)) -> AuthService:
    return AuthService(db, get_settings())


@router.post("/register", response_model=RegistrationResponse)
def register(payload: RegisterRequest, request: Request, service: AuthService = Depends(_service)):
    result = service.register(
        username=payload.username,
        email=payload.email,
        password=payload.password,
        role=payload.role.value,
        ip_address=request.client.host if request.client else None,
    )
    return RegistrationResponse(
        user_id=result.user.id,
        username=result.user.username,
        email=result.user.email,
        role=UserRole(result.user.role),
        mfa_setup_uri=result.provisioning_uri,
        qr_code_data_uri=result.qr_code_data_uri,
    )


@router.post("/login", response_model=PendingMfaResponse)
def login(payload: LoginRequest, request: Request, service: AuthService = Depends(_service)):
    result = service.login(
        username=payload.username,
        password=payload.password,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return PendingMfaResponse(mfa_token=result.mfa_token)


@router.post("/verify-mfa", response_model=TokenResponse)
def verify_mfa(payload: MfaVerifyRequest, request: Request, service: AuthService = Depends(_service)):
    result = service.verify_mfa(
        mfa_token=payload.mfa_token,
        otp=payload.otp,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return TokenResponse(access_token=result.access_token, refresh_token=result.refresh_token, expires_at=result.expires_at)


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, request: Request, service: AuthService = Depends(_service)):
    result = service.refresh(
        refresh_token=payload.refresh_token,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return TokenResponse(access_token=result.access_token, refresh_token=result.refresh_token, expires_at=result.expires_at)


@router.post("/logout")
def logout(payload: LogoutRequest, request: Request, service: AuthService = Depends(_service)):
    service.logout(payload.refresh_token, ip_address=request.client.host if request.client else None)
    return {"detail": "Logged out"}


@router.get("/me", response_model=UserRead)
def me(user=Depends(get_current_user)):
    return UserRead.model_validate(user, from_attributes=True)


@router.get("/admin/health")
def admin_health(user=Depends(require_role(UserRole.admin.value))):
    return {"status": "ok", "user": user.username, "role": user.role}
