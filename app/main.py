from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from app.core.config import get_settings
from app.db.base import Base
from app.db.session import engine
from app.models import audit_log, password_history, refresh_token, user  # noqa: F401
from app.routers.auth import router as auth_router


settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name, lifespan=lifespan)
    app.include_router(auth_router, prefix="/api")

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
