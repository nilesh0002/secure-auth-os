from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse

from app.core.config import get_settings
from app.core.security import encrypt_secret, hash_password
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models import audit_log, email_otp_challenge, password_history, refresh_token, user  # noqa: F401
from app.models.user import User
from app.routers.auth import router as auth_router
from app.routers.users import router as users_router


settings = get_settings()


def _ensure_bootstrap_admin() -> None:
    if not settings.bootstrap_admin_enabled:
        return
    db = SessionLocal()
    try:
        existing_admin = db.query(User).filter(User.username == settings.bootstrap_admin_username).first()
        if existing_admin:
            changed = False
            if existing_admin.role != "admin":
                existing_admin.role = "admin"
                changed = True
            if existing_admin.email.endswith(".local"):
                existing_admin.email = settings.bootstrap_admin_email.lower()
                changed = True
            if not existing_admin.mfa_secret_encrypted:
                existing_admin.mfa_secret_encrypted = encrypt_secret(settings.bootstrap_admin_totp_secret, settings)
                existing_admin.mfa_enabled = True
                changed = True
            if changed:
                db.commit()
            return
        admin = User(
            username=settings.bootstrap_admin_username,
            email=settings.bootstrap_admin_email.lower(),
            password_hash=hash_password(settings.bootstrap_admin_password),
            role="admin",
            mfa_enabled=True,
            mfa_secret_encrypted=encrypt_secret(settings.bootstrap_admin_totp_secret, settings),
        )
        db.add(admin)
        db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    _ensure_bootstrap_admin()
    yield


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name, lifespan=lifespan)
    app.include_router(auth_router, prefix="/api")
    app.include_router(users_router, prefix="/api")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/", response_class=FileResponse)
    def root() -> FileResponse:
        return FileResponse(Path(__file__).parent / "static" / "index.html")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "healthy"}

    @app.get("/api")
    def api_index() -> dict[str, str]:
        return {
            "service": settings.app_name,
            "status": "ok",
            "docs": "/docs",
            "api_base": "/api",
        }

    return app


app = create_app()
