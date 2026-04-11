from datetime import datetime

from sqlalchemy.orm import Session

from app.models.refresh_token import RefreshToken
from app.repositories.base_repository import BaseRepository


class TokenRepository(BaseRepository):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    def create_refresh_token(self, token: RefreshToken) -> RefreshToken:
        self.db.add(token)
        self.db.flush()
        return token

    def revoke_refresh_token(self, token: RefreshToken) -> None:
        token.revoked_at = datetime.utcnow()
        self.db.flush()
