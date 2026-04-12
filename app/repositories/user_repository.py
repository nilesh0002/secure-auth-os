from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.password_history import PasswordHistory
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.repositories.base_repository import BaseRepository


class UserRepository(BaseRepository):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    def get_by_id(self, user_id: str) -> User | None:
        return self.db.get(User, user_id)

    def get_by_username(self, username: str) -> User | None:
        statement = select(User).where(User.username == username)
        return self.db.execute(statement).scalar_one_or_none()

    def get_by_email(self, email: str) -> User | None:
        statement = select(User).where(User.email == email)
        return self.db.execute(statement).scalar_one_or_none()

    def create(self, user: User) -> User:
        self.db.add(user)
        self.db.flush()
        return user

    def list_all(self) -> list[User]:
        statement = select(User).order_by(User.created_at.desc())
        return list(self.db.execute(statement).scalars().all())

    def delete(self, user: User) -> None:
        self.db.delete(user)
        self.db.flush()

    def add_password_history(self, user_id: str, password_hash: str) -> PasswordHistory:
        history = PasswordHistory(user_id=user_id, password_hash=password_hash)
        self.db.add(history)
        self.db.flush()
        return history

    def get_recent_password_hashes(self, user_id: str, limit: int) -> list[str]:
        statement = (
            select(PasswordHistory.password_hash)
            .where(PasswordHistory.user_id == user_id)
            .order_by(PasswordHistory.created_at.desc())
            .limit(limit)
        )
        return list(self.db.execute(statement).scalars().all())

    def reset_failed_attempts(self, user: User) -> None:
        user.failed_login_attempts = 0
        user.locked_until = None
        self.db.flush()

    def register_failed_attempt(self, user: User, locked_until: datetime | None) -> None:
        user.failed_login_attempts += 1
        user.locked_until = locked_until
        self.db.flush()

    def store_refresh_token(self, refresh_token: RefreshToken) -> RefreshToken:
        self.db.add(refresh_token)
        self.db.flush()
        return refresh_token

    def get_refresh_token_by_hash(self, token_hash: str) -> RefreshToken | None:
        statement = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        return self.db.execute(statement).scalar_one_or_none()

    def get_refresh_token_by_jti(self, jti: str) -> RefreshToken | None:
        statement = select(RefreshToken).where(RefreshToken.jti == jti)
        return self.db.execute(statement).scalar_one_or_none()

    def revoke_refresh_token(self, refresh_token: RefreshToken) -> None:
        refresh_token.revoked_at = datetime.utcnow()
        self.db.flush()
