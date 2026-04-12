from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

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

        @app.get("/", response_class=HTMLResponse)
        def root() -> str:
                return """
<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
    <title>SecureAuthOS</title>
    <style>
        :root {
            --bg-1: #0e1f26;
            --bg-2: #143947;
            --accent: #ffd166;
            --text: #f5f7fa;
            --muted: #b6c2cd;
            --card: rgba(6, 15, 20, 0.72);
            --line: rgba(255, 255, 255, 0.14);
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            color: var(--text);
            font-family: \"Segoe UI\", \"Helvetica Neue\", sans-serif;
            background:
                radial-gradient(circle at 10% 10%, rgba(255, 209, 102, 0.2), transparent 35%),
                radial-gradient(circle at 85% 20%, rgba(0, 187, 249, 0.16), transparent 32%),
                linear-gradient(140deg, var(--bg-1), var(--bg-2));
            display: grid;
            place-items: center;
            padding: 24px;
        }

        .card {
            width: min(860px, 100%);
            background: var(--card);
            border: 1px solid var(--line);
            border-radius: 20px;
            backdrop-filter: blur(10px);
            padding: 28px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.35);
            animation: rise 500ms ease-out;
        }

        h1 {
            margin: 0 0 8px;
            font-size: clamp(1.8rem, 2.4vw, 2.4rem);
            letter-spacing: 0.4px;
        }

        p {
            margin: 0 0 16px;
            color: var(--muted);
            line-height: 1.55;
        }

        .row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
            margin: 18px 0 22px;
        }

        .pill {
            border: 1px solid var(--line);
            border-radius: 999px;
            padding: 8px 12px;
            font-size: 0.92rem;
            color: var(--muted);
            width: fit-content;
        }

        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 8px;
        }

        a {
            text-decoration: none;
            color: #02131a;
            background: var(--accent);
            border-radius: 10px;
            padding: 11px 14px;
            font-weight: 600;
            transition: transform 120ms ease, filter 120ms ease;
        }

        a.secondary {
            background: transparent;
            color: var(--text);
            border: 1px solid var(--line);
        }

        a:hover { transform: translateY(-1px); filter: brightness(1.04); }

        ul {
            margin: 10px 0 0;
            padding-left: 18px;
            color: var(--muted);
            line-height: 1.6;
        }

        code {
            color: var(--text);
            background: rgba(255, 255, 255, 0.08);
            padding: 2px 6px;
            border-radius: 6px;
        }

        @keyframes rise {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body>
    <main class=\"card\">
        <h1>SecureAuthOS API Is Live</h1>
        <p>
            This is the public homepage for SecureAuthOS. Human users can start with the docs,
            while applications should call the API under <code>/api</code>.
        </p>

        <div class=\"row\">
            <div class=\"pill\">Status: healthy</div>
            <div class=\"pill\">Auth: Argon2 + TOTP + JWT</div>
            <div class=\"pill\">Access: RBAC (Admin/User)</div>
        </div>

        <div class=\"actions\">
            <a href=\"/docs\">Open API Docs</a>
            <a class=\"secondary\" href=\"/health\">Health Check</a>
            <a class=\"secondary\" href=\"/api/me\">Try Protected Route</a>
        </div>

        <ul>
            <li>Public status endpoint: <code>/health</code></li>
            <li>API base path: <code>/api</code></li>
            <li>Auth flow: <code>/api/register</code> -> <code>/api/login</code> -> <code>/api/verify-mfa</code></li>
        </ul>
    </main>
</body>
</html>
"""

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
