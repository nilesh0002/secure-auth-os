from datetime import datetime

from pydantic import BaseModel, EmailStr


class UserManagementRead(BaseModel):
    id: str
    username: str
    email: EmailStr
    created_at: datetime
