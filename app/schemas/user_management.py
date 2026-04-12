from datetime import datetime

from pydantic import BaseModel


class UserManagementRead(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
