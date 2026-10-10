"""Parameterized database operations for CloudGuard accounts."""

import sqlite3

from database.db import get_connection
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
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, password_hash),
                )
                row = connection.execute(
                    "SELECT id, username, email, password_hash, created_at "
                    "FROM users WHERE id = ?",
                    (cursor.lastrowid,),
                ).fetchone()
        except sqlite3.IntegrityError as exc:
            raise DuplicateUserError("Username or email is already registered.") from exc
        return User(**dict(row))

    @staticmethod
    def find_by_login(login: str) -> User | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT id, username, email, password_hash, created_at FROM users "
                "WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE",
                (login, login),
            ).fetchone()
        return User(**dict(row)) if row else None
