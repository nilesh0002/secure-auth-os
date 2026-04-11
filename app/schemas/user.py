from datetime import datetime

from pydantic import BaseModel, EmailStr

from app.models.enums import UserRole


class UserRead(BaseModel):
    id: str
    username: str
    email: EmailStr
    role: UserRole
    is_active: bool
    mfa_enabled: bool
    password_changed_at: datetime
    password_expires_at: datetime | None = None
