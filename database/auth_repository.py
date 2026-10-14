"""Parameterized database operations for CloudGuard accounts."""

from database.db import get_connection, integrity_error_types
from database.models import User


class DuplicateUserError(Exception):
    """Raised when a username or email is already registered."""


class AuthRepository:
    """Persist and retrieve account records."""

    @staticmethod
    def create_user(username: str, email: str, password_hash: str) -> User:
        try:
            with get_connection() as connection:
                cursor = connection.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?) RETURNING id",
                    (username, email, password_hash),
                )
                inserted_id = cursor.fetchone()["id"]
                row = connection.execute(
                    "SELECT id, username, email, password_hash, created_at "
                    "FROM users WHERE id = ?",
                    (inserted_id,),
                ).fetchone()
        except integrity_error_types() as exc:
            raise DuplicateUserError("Username or email is already registered.") from exc
        return User(**dict(row))

    @staticmethod
    def find_by_login(login: str) -> User | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT id, username, email, password_hash, created_at FROM users "
                "WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)",
                (login, login),
            ).fetchone()
        return User(**dict(row)) if row else None

    @staticmethod
    def find_by_id(user_id: int) -> User | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT id, username, email, password_hash, created_at "
                "FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        return User(**dict(row)) if row else None
