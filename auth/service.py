"""Validation and account authentication workflows."""

import re

from auth.password import hash_password, verify_password
from database.auth_repository import AuthRepository, DuplicateUserError
from database.models import User

_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
_EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class AuthValidationError(ValueError):
    """Raised when signup data does not meet CloudGuard's input rules."""


def validate_signup(username: str, email: str, password: str, confirmation: str) -> tuple[str, str]:
    """Validate and normalize signup fields, returning username and email."""
    username = username.strip()
    email = email.strip().lower()
    if not _USERNAME_PATTERN.fullmatch(username):
        raise AuthValidationError("Username must be 3–32 characters using letters, numbers, ., _ or -.")
    if len(email) > 254 or not _EMAIL_PATTERN.fullmatch(email):
        raise AuthValidationError("Enter a valid email address.")
    if not password:
        raise AuthValidationError("Password must not be empty.")
    if len(password) < 8:
        raise AuthValidationError("Password must be at least 8 characters long.")
    if len(password) > 1024:
        raise AuthValidationError("Password is too long.")
    if password != confirmation:
        raise AuthValidationError("Passwords do not match.")
    return username, email


def signup(username: str, email: str, password: str, confirmation: str) -> User:
    """Validate signup information, hash the password, and create an account."""
    username, email = validate_signup(username, email, password, confirmation)
    return AuthRepository.create_user(username, email, hash_password(password))


def login(login_value: str, password: str) -> User | None:
    """Authenticate by username or email without revealing which failed."""
    if not login_value or not password:
        return None
    user = AuthRepository.find_by_login(login_value.strip())
    if user is None:
        # Spend comparable time hashing to reduce user enumeration by timing.
        hash_password("CloudGuard invalid account timing value")
        return None
    return user if verify_password(user.password_hash, password) else None


__all__ = ["AuthValidationError", "DuplicateUserError", "login", "signup"]
