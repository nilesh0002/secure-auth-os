from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.dependencies import require_role
from app.db.session import get_db
from app.models.enums import UserRole
from app.schemas.user_management import UserManagementRead
from app.repositories.user_repository import UserRepository

router = APIRouter()


@router.get("/users", response_model=list[UserManagementRead])
def list_users(db: Session = Depends(get_db), _=Depends(require_role(UserRole.admin.value))):
    # Admin-only endpoint that returns all users for management workflows.
    users = UserRepository(db).list_all()
    return [UserManagementRead.model_validate(user, from_attributes=True) for user in users]


@router.delete("/users/{user_id}")
def delete_user(user_id: str, db: Session = Depends(get_db), _=Depends(require_role(UserRole.admin.value))):
    # Delete the user and commit in one transaction so login and token checks stop working for that identity.
    users = UserRepository(db)
    user = users.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    try:
        users.delete(user)
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete user") from exc

    return {"detail": "User deleted"}
