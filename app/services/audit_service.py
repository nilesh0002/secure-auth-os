from __future__ import annotations

import logging
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import setup_audit_logger
from app.models.audit_log import AuditLog
from app.repositories.audit_repository import AuditRepository


class AuditService:
    def __init__(self, db: Session, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.repository = AuditRepository(db)
        self.logger = setup_audit_logger(settings)

    def record(self, event_type: str, success: bool, detail: str | None = None, user_id: str | None = None, ip_address: str | None = None) -> None:
        entry = AuditLog(
            event_type=event_type,
            success=success,
            detail=detail,
            user_id=user_id,
            ip_address=ip_address,
        )
        self.repository.create(entry)
        self.logger.info(
            "event=%s success=%s user_id=%s ip=%s detail=%s",
            event_type,
            success,
            user_id or "-",
            ip_address or "-",
            detail or "-",
        )
