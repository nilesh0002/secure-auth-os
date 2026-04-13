from __future__ import annotations

import base64
import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "auth_test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{db_path}")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-test-secret-key-test-secret-key-123456")
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"1" * 32).decode("utf-8"))
    monkeypatch.setenv("MFA_METHOD", "totp")
    monkeypatch.setenv("EXPOSE_EMAIL_OTP_IN_RESPONSE", "false")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_PASSWORD", "admin123")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_TOTP_SECRET", "JBSWY3DPEHPK3PXP")

    from app.core.config import get_settings

    get_settings.cache_clear()

    import app.db.session as session_module
    import app.main as main_module

    importlib.reload(session_module)
    importlib.reload(main_module)

    from app.db.base import Base
    from app.models.audit_log import AuditLog  # noqa: F401
    from app.models.email_otp_challenge import EmailOtpChallenge  # noqa: F401
    from app.models.password_history import PasswordHistory  # noqa: F401
    from app.models.refresh_token import RefreshToken  # noqa: F401
    from app.models.user import User  # noqa: F401

    Base.metadata.create_all(bind=session_module.engine)

    def override_get_db():
        db = session_module.SessionLocal()
        try:
            yield db
        finally:
            db.close()

    main_module.app.dependency_overrides[session_module.get_db] = override_get_db

    with TestClient(main_module.app) as test_client:
        yield test_client
