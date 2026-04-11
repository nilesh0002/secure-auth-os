from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.repositories.base_repository import BaseRepository


class AuditRepository(BaseRepository):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    def create(self, audit_log: AuditLog) -> AuditLog:
        self.db.add(audit_log)
        self.db.flush()
        return audit_log
