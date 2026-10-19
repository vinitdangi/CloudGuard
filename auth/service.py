"""Validation and account authentication workflows."""

import re
from datetime import datetime, timedelta, timezone

from auth.password import hash_password, verify_password
from database.auth_repository import AuthRepository, DuplicateUserError
from database.models import User

_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
_EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class AuthValidationError(ValueError):
    """Raised when signup data does not meet CloudGuard's input rules."""


class EmailNotVerifiedError(ValueError):
    """Raised by the Streamlit login flow for valid credentials awaiting email proof."""


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


def signup_unverified(username: str, email: str, password: str, confirmation: str) -> User:
    """Create a Streamlit registration that must verify its email before login."""
    username, email = validate_signup(username, email, password, confirmation)
    return AuthRepository.create_user(
        username, email, hash_password(password), email_verified=False
    )


def login(login_value: str, password: str) -> User | None:
    """Authenticate by username or email without revealing which failed."""
    if not login_value or not password:
        return None
    user = AuthRepository.find_by_login(login_value.strip())
    if user is None:
        # Spend comparable time hashing to reduce user enumeration by timing.
        hash_password("CloudGuard invalid account timing value")
        return None
    if not verify_password(user.password_hash, password):
        return None
    return user if user.email_verified else None


def dashboard_login(login_value: str, password: str) -> User | None:
    """Authenticate Streamlit users while distinguishing pending email verification."""
    if not login_value or not password:
        return None
    user = AuthRepository.find_by_login(login_value.strip())
    if user is None:
        hash_password("CloudGuard invalid account timing value")
        return None
    if not verify_password(user.password_hash, password):
        return None
    if not user.email_verified:
        raise EmailNotVerifiedError
    return user


def create_email_otp(email: str, *, secret: str, now: datetime | None = None) -> str:
    """Persist a five-minute keyed digest and return the one-time code for delivery."""
    import hashlib
    import hmac
    import secrets

    if len(secret) < 32:
        raise ValueError("CLOUDGUARD_OTP_SECRET must contain at least 32 characters.")
    normalized_email = email.strip().lower()
    otp = f"{secrets.randbelow(1_000_000):06d}"
    issued_at = now or datetime.now(timezone.utc)
    expires_at = (issued_at + timedelta(minutes=5)).isoformat()
    otp_hash = hmac.new(
        secret.encode("utf-8"),
        f"{normalized_email}:{otp}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    AuthRepository.save_email_verification(normalized_email, otp_hash, expires_at)
    return otp


def verify_email_otp(
    email: str, otp: str, *, secret: str, now: datetime | None = None
) -> str:
    """Verify, rate-limit, and consume a registration OTP; return a status string."""
    import hashlib
    import hmac

    if len(secret) < 32:
        raise ValueError("CLOUDGUARD_OTP_SECRET must contain at least 32 characters.")
    normalized_email = email.strip().lower()
    record = AuthRepository.get_email_verification(normalized_email)
    if record is None:
        return "missing"
    current = now or datetime.now(timezone.utc)
    expiry = datetime.fromisoformat(record["expires_at"])
    if current >= expiry:
        AuthRepository.delete_email_verification(normalized_email)
        return "expired"
    if record["attempts"] >= 5:
        return "too_many_attempts"
    expected_hash = hmac.new(
        secret.encode("utf-8"),
        f"{normalized_email}:{otp}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(record["otp_hash"], expected_hash):
        attempts = AuthRepository.increment_email_verification_attempts(normalized_email)
        return "too_many_attempts" if attempts is not None and attempts >= 5 else "invalid"
    consumed_at = current.isoformat()
    return (
        "verified"
        if AuthRepository.consume_email_verification(normalized_email, expected_hash, consumed_at)
        else "expired"
    )


__all__ = [
    "AuthValidationError", "DuplicateUserError", "EmailNotVerifiedError",
    "create_email_otp", "dashboard_login", "login", "signup", "signup_unverified",
    "verify_email_otp",
]
