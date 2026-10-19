"""Database models used by CloudGuard authentication."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class User:
    """A CloudGuard account; password hashes are never exposed to the UI."""

    id: int
    username: str
    email: str
    password_hash: str = field(repr=False)
    created_at: str
    email_verified: bool = True
