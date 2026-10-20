"""Parameterized database operations for CloudGuard accounts."""

from database.db import _postgresql_requested, get_connection, integrity_error_types
from database.models import User


class DuplicateUserError(Exception):
    """Raised when a username or email is already registered."""


class AuthRepository:
    """Persist and retrieve account records."""

    @staticmethod
    def _user(row) -> User:
        values = dict(row)
        values["email_verified"] = bool(values["email_verified"])
        return User(**values)

    @staticmethod
    def create_user(
        username: str, email: str, password_hash: str, *, email_verified: bool = True
    ) -> User:
        try:
            with get_connection() as connection:
                cursor = connection.execute(
                    "INSERT INTO users (username, email, password_hash, email_verified) "
                    "VALUES (?, ?, ?, ?) RETURNING id",
                    (username, email, password_hash, email_verified),
                )
                inserted_id = cursor.fetchone()["id"]
                row = connection.execute(
                    "SELECT id, username, email, password_hash, created_at, email_verified "
                    "FROM users WHERE id = ?",
                    (inserted_id,),
                ).fetchone()
        except integrity_error_types() as exc:
            raise DuplicateUserError("Username or email is already registered.") from exc
        return AuthRepository._user(row)

    @staticmethod
    def find_by_login(login: str) -> User | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT id, username, email, password_hash, created_at, email_verified FROM users "
                "WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)",
                (login, login),
            ).fetchone()
        return AuthRepository._user(row) if row else None

    @staticmethod
    def find_by_id(user_id: int) -> User | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT id, username, email, password_hash, created_at, email_verified "
                "FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        return AuthRepository._user(row) if row else None

    @staticmethod
    def save_email_verification(email: str, otp_hash: str, expires_at: str) -> None:
        """Replace the active verification code for an account."""
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO email_verifications (email, otp_hash, expires_at, attempts) "
                "VALUES (?, ?, ?, 0) ON CONFLICT (email) DO UPDATE SET "
                "otp_hash = excluded.otp_hash, expires_at = excluded.expires_at, attempts = 0",
                (email, otp_hash, expires_at),
            )

    @staticmethod
    def get_email_verification(email: str) -> dict | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT email, otp_hash, expires_at, attempts "
                "FROM email_verifications WHERE email = ?",
                (email,),
            ).fetchone()
        return dict(row) if row else None

    @staticmethod
    def increment_email_verification_attempts(email: str) -> int | None:
        with get_connection() as connection:
            row = connection.execute(
                "UPDATE email_verifications SET attempts = attempts + 1 WHERE email = ? "
                "RETURNING attempts",
                (email,),
            ).fetchone()
        return int(row["attempts"]) if row else None

    @staticmethod
    def delete_email_verification(email: str) -> None:
        with get_connection() as connection:
            connection.execute("DELETE FROM email_verifications WHERE email = ?", (email,))

    @staticmethod
    def consume_email_verification(email: str, otp_hash: str, now: str) -> bool:
        """Atomically consume a valid code and mark its account verified."""
        with get_connection() as connection:
            consumed = connection.execute(
                "DELETE FROM email_verifications WHERE email = ? AND otp_hash = ? "
                "AND expires_at > ? RETURNING email",
                (email, otp_hash, now),
            ).fetchone()
            if consumed is None:
                return False
            connection.execute(
                "UPDATE users SET email_verified = ? WHERE LOWER(email) = LOWER(?)",
                (True, email),
            )
        return True

    @staticmethod
    def replace_password_reset_token(user_id: int, digest: str, expires_at: str) -> None:
        """Replace active reset tokens and persist only the supplied digest."""
        with get_connection() as connection:
            # Serialize concurrent requests for the same account on PostgreSQL.
            if _postgresql_requested():
                connection.execute("SELECT id FROM users WHERE id = ? FOR UPDATE", (user_id,))
            connection.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,))
            connection.execute(
                "INSERT INTO password_reset_tokens (token_digest, user_id, expires_at) "
                "VALUES (?, ?, ?)",
                (digest, user_id, expires_at),
            )

    @staticmethod
    def consume_password_reset(digest: str, now: str, password_hash: str) -> bool:
        """Atomically consume a live reset token and replace the password hash."""
        with get_connection() as connection:
            token = connection.execute(
                "UPDATE password_reset_tokens SET used_at = ? "
                "WHERE token_digest = ? AND used_at IS NULL AND expires_at > ? "
                "RETURNING user_id",
                (now, digest, now),
            ).fetchone()
            if token is None:
                return False
            connection.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, token["user_id"]),
            )
        return True
