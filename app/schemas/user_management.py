from datetime import datetime

from pydantic import BaseModel


class UserManagementRead(BaseModel):
    id: str
    username: str
    email: str
    created_at: datetime
