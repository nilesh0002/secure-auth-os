from __future__ import annotations

import argparse
from getpass import getpass

from app.core.config import get_settings
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.core.security import hash_password


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    print("Database initialized")


def create_user(username: str, email: str, role: str) -> None:
    settings = get_settings()
    password = getpass("Password: ")
    confirm = getpass("Confirm password: ")
    if password != confirm:
        raise SystemExit("Passwords do not match")
    db = SessionLocal()
    try:
        repo = UserRepository(db)
        if repo.get_by_username(username):
            raise SystemExit("Username already exists")
        user = User(username=username, email=email, password_hash=hash_password(password), role=role)
        repo.create(user)
        db.commit()
        print(f"Created user {username} with role {role}")
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureAuthOS CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init-db")

    create_user_parser = subparsers.add_parser("create-user")
    create_user_parser.add_argument("username")
    create_user_parser.add_argument("email")
    create_user_parser.add_argument("--role", choices=["admin", "user"], default="user")

    args = parser.parse_args()
    if args.command == "init-db":
        init_db()
    elif args.command == "create-user":
        create_user(args.username, args.email, args.role)


if __name__ == "__main__":
    main()
