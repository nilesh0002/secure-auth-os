from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import build_totp_uri, decrypt_secret, password_matches_hash, qr_code_data_uri
from app.core.dependencies import get_current_user, require_role
from app.db.session import get_db
from app.models.enums import UserRole
from app.repositories.user_repository import UserRepository
from app.schemas.auth import (
    BootstrapAdminMfaRequest,
    BootstrapAdminMfaResponse,
    ChangePasswordRequest,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    LogoutRequest,
    MfaVerifyRequest,
    PendingMfaResponse,
    ResetPasswordRequest,
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
    return PendingMfaResponse(
        mfa_token=result.mfa_token,
        mfa_method=result.mfa_method,
        delivery_hint=result.delivery_hint,
        test_otp=result.test_otp,
    )


@router.post("/bootstrap-admin/mfa-setup", response_model=BootstrapAdminMfaResponse)
def bootstrap_admin_mfa_setup(payload: BootstrapAdminMfaRequest, db: Session = Depends(get_db)):
    # Provides admin authenticator QR only after credential verification.
    settings = get_settings()
    if settings.mfa_method.strip().lower() != "totp":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authenticator setup is disabled for current MFA method")
    if not settings.bootstrap_admin_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    if payload.username.strip().lower() != settings.bootstrap_admin_username.lower():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user = UserRepository(db).get_by_username(settings.bootstrap_admin_username)
    if not user or not password_matches_hash(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if user.role != UserRole.admin.value or not user.mfa_secret_encrypted:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Admin MFA setup unavailable")

    secret = decrypt_secret(user.mfa_secret_encrypted, settings)
    uri = build_totp_uri(user.username, secret, settings.totp_issuer)
    return BootstrapAdminMfaResponse(mfa_setup_uri=uri, qr_code_data_uri=qr_code_data_uri(uri))


@router.post("/verify-mfa", response_model=TokenResponse)
def verify_mfa(payload: MfaVerifyRequest, request: Request, response: Response, service: AuthService = Depends(_service)):
    result = service.verify_mfa(
        mfa_token=payload.mfa_token,
        otp=payload.otp,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    settings = get_settings()
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=result.refresh_token,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
        max_age=settings.refresh_token_ttl_days * 24 * 60 * 60,
        path="/api",
    )
    return TokenResponse(access_token=result.access_token, expires_at=result.expires_at)


@router.post("/refresh", response_model=TokenResponse)
def refresh(request: Request, response: Response, payload: RefreshRequest | None = None, service: AuthService = Depends(_service)):
    settings = get_settings()
    refresh_token = (payload.refresh_token if payload else None) or request.cookies.get(settings.refresh_cookie_name)
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")
    result = service.refresh(
        refresh_token=refresh_token,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=result.refresh_token,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
        max_age=settings.refresh_token_ttl_days * 24 * 60 * 60,
        path="/api",
    )
    return TokenResponse(access_token=result.access_token, expires_at=result.expires_at)


@router.post("/logout")
def logout(request: Request, response: Response, payload: LogoutRequest | None = None, service: AuthService = Depends(_service)):
    settings = get_settings()
    refresh_token = (payload.refresh_token if payload else None) or request.cookies.get(settings.refresh_cookie_name)
    if refresh_token:
        service.logout(refresh_token, ip_address=request.client.host if request.client else None)
    response.delete_cookie(key=settings.refresh_cookie_name, path="/api")
    return {"detail": "Logged out"}


@router.post("/change-password")
def change_password(payload: ChangePasswordRequest, request: Request, user=Depends(get_current_user), service: AuthService = Depends(_service)):
    service.change_password(
        user_id=user.id,
        current_password=payload.current_password,
        new_password=payload.new_password,
        ip_address=request.client.host if request.client else None,
    )
    return {"detail": "Password changed successfully"}


@router.post("/forgot-password", response_model=ForgotPasswordResponse)
def forgot_password(payload: ForgotPasswordRequest, request: Request, service: AuthService = Depends(_service)):
    result = service.forgot_password(payload.email, ip_address=request.client.host if request.client else None)
    return ForgotPasswordResponse(detail=result.detail, debug_reset_token=result.debug_reset_token)


@router.post("/reset-password")
def reset_password(payload: ResetPasswordRequest, request: Request, service: AuthService = Depends(_service)):
    service.reset_password(payload.token, payload.new_password, ip_address=request.client.host if request.client else None)
    return {"detail": "Password reset successfully"}


@router.get("/me", response_model=UserRead)
def me(user=Depends(get_current_user)):
    return UserRead.model_validate(user, from_attributes=True)


@router.get("/admin/health")
def admin_health(user=Depends(require_role(UserRole.admin.value))):
    return {"status": "ok", "user": user.username, "role": user.role}
