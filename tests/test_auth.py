"""Tests for CloudGuard account authentication."""

import pytest
from fastapi import HTTPException

from api.auth import (
    current_user,
    login_user,
    resend_registration_otp,
    signup_user,
    verify_registration_email,
)
from api.schemas import (
    EmailVerificationRequest,
    LoginRequest,
    ResendEmailVerificationRequest,
    SignupRequest,
)
from auth.password import hash_password, verify_password
from auth.service import (
    AuthValidationError,
    DuplicateUserError,
    EmailNotVerifiedError,
    create_email_otp,
    dashboard_login,
    login,
    signup,
    signup_unverified,
    verify_email_otp,
)
from auth.session import clear_session, establish_session
from database.auth_repository import AuthRepository
from database.db import initialize_database
from database.models import User


@pytest.fixture(autouse=True)
def initialized_database(tmp_path, monkeypatch):
    """Give every test an isolated SQLite database."""
    monkeypatch.setenv("CLOUDGUARD_AUTH_DB", str(tmp_path / "auth.sqlite3"))
    initialize_database()


def test_database_initialization_is_idempotent():
    initialize_database()
    initialize_database()


def test_signup_persists_user_with_hashed_password():
    user = signup("vinit_1", "VINIT@example.com", "strongpass123", "strongpass123")
    assert user.username == "vinit_1"
    assert user.email == "vinit@example.com"
    assert user.password_hash != "strongpass123"
    assert user.password_hash.startswith("$argon2id$")


def test_duplicate_username_is_rejected():
    signup("vinit_1", "first@example.com", "strongpass123", "strongpass123")
    with pytest.raises(DuplicateUserError):
        signup("VINIT_1", "second@example.com", "strongpass123", "strongpass123")


def test_duplicate_email_is_rejected_case_insensitively():
    signup("first_user", "first@example.com", "strongpass123", "strongpass123")
    with pytest.raises(DuplicateUserError):
        signup("second_user", "FIRST@example.com", "strongpass123", "strongpass123")


def test_password_hash_and_verification():
    password_hash = hash_password("strongpass123")
    assert verify_password(password_hash, "strongpass123")
    assert not verify_password(password_hash, "incorrect")
    assert not verify_password("not-a-valid-hash", "strongpass123")


def test_login_accepts_username_and_email():
    signup("vinit_1", "vinit@example.com", "strongpass123", "strongpass123")
    assert login("vinit_1", "strongpass123").email == "vinit@example.com"
    assert login("VINIT@example.com", "strongpass123").username == "vinit_1"


def test_api_signup_requires_otp_before_login(monkeypatch):
    import api.auth as auth_routes
    from types import SimpleNamespace

    monkeypatch.setenv("CLOUDGUARD_OTP_SECRET", "test-only-secret-value-32-bytes-long")
    monkeypatch.setattr(auth_routes, "send_verification_email", lambda *_args: None)
    original_create_otp = auth_routes.create_email_otp
    captured = {}

    def capture_otp(email, **kwargs):
        otp = original_create_otp(email, **kwargs)
        captured["otp"] = otp
        return otp

    monkeypatch.setattr(auth_routes, "create_email_otp", capture_otp)
    signup_response = signup_user(
        SignupRequest(
            username="api_user",
            email="same@example.com",
            password="StrongPass123!",
            confirmation="StrongPass123!",
        ),
    )
    assert signup_response.authenticated is False
    assert signup_response.email == "same@example.com"
    user = AuthRepository.find_by_login("same@example.com")
    assert user.email_verified is False

    with pytest.raises(HTTPException) as error:
        login_user(LoginRequest(login="same@example.com", password="StrongPass123!"), {})
    assert error.value.status_code == 403
    assert error.value.detail == "Please verify your email before logging in."

    verified = verify_registration_email(
        EmailVerificationRequest(identifier="api_user", otp=captured["otp"])
    )
    assert verified.verified is True
    assert AuthRepository.find_by_login("same@example.com").email_verified is True

    request = SimpleNamespace(session={})
    login_response = login_user(
        LoginRequest(login="same@example.com", password="StrongPass123!"), request
    )

    assert login_response.id == user.id
    assert login_response.username == "api_user"
    assert request.session["user_id"] == user.id
    assert current_user(request).email == "same@example.com"


def test_api_resend_replaces_the_old_code(monkeypatch):
    import secrets
    import api.auth as auth_routes

    monkeypatch.setenv("CLOUDGUARD_OTP_SECRET", "test-only-secret-value-32-bytes-long")
    codes = iter((111111, 222222))
    monkeypatch.setattr(secrets, "randbelow", lambda _limit: next(codes))
    user = signup_unverified(
        "resend_api", "resend-api@example.com", "StrongPass123!", "StrongPass123!"
    )
    secret = "test-only-secret-value-32-bytes-long"
    old_code = create_email_otp(user.email, secret=secret)
    captured = {}
    original_create_otp = auth_routes.create_email_otp

    def capture_otp(email, **kwargs):
        otp = original_create_otp(email, **kwargs)
        captured["otp"] = otp
        return otp

    monkeypatch.setattr(auth_routes, "create_email_otp", capture_otp)
    sent = []
    monkeypatch.setattr(auth_routes, "send_verification_email", lambda *args: sent.append(args))
    response = resend_registration_otp(
        ResendEmailVerificationRequest(identifier=user.username)
    )
    assert response.verified is False
    assert "verification code has been sent" in response.message
    assert sent == [(user.email, captured["otp"])]
    assert verify_email_otp(user.email, old_code, secret=secret) == "invalid"
    assert verify_email_otp(user.email, captured["otp"], secret=secret) == "verified"


def test_resend_does_not_reveal_or_send_for_missing_or_verified_accounts(monkeypatch):
    import api.auth as auth_routes

    verified_user = signup(
        "verified_user", "verified@example.com", "StrongPass123!", "StrongPass123!"
    )
    pending_user = signup_unverified(
        "pending_user", "pending@example.com", "StrongPass123!", "StrongPass123!"
    )
    sent = []
    monkeypatch.setenv("CLOUDGUARD_OTP_SECRET", "test-only-secret-value-32-bytes-long")
    monkeypatch.setattr(auth_routes, "send_verification_email", lambda *args: sent.append(args))

    unknown_response = resend_registration_otp(
        ResendEmailVerificationRequest(identifier="no-such-user")
    )
    verified_response = resend_registration_otp(
        ResendEmailVerificationRequest(email=verified_user.email)
    )

    assert unknown_response.model_dump() == verified_response.model_dump()
    assert not sent
    assert AuthRepository.find_by_login(pending_user.username).email_verified is False


def test_resend_delivery_failure_is_logged_without_changing_generic_response(
    monkeypatch, caplog
):
    import api.auth as auth_routes

    user = signup_unverified(
        "delivery_failure", "delivery-failure@example.com", "StrongPass123!", "StrongPass123!"
    )
    monkeypatch.setenv("CLOUDGUARD_EMAIL_PROVIDER", "resend")
    monkeypatch.setenv("CLOUDGUARD_EMAIL_API_KEY", "never-log-this-api-key")
    monkeypatch.setenv("CLOUDGUARD_EMAIL_FROM", "cloudguard@example.test")
    monkeypatch.setenv("CLOUDGUARD_OTP_SECRET", "test-only-secret-value-32-bytes-long")
    monkeypatch.setattr(
        auth_routes,
        "send_verification_email",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("provider failed")),
    )

    response = resend_registration_otp(
        ResendEmailVerificationRequest(identifier=user.username)
    )

    assert "If an unverified account matches" in response.message
    assert "verification_code_resend_failed" in caplog.text
    assert '"api_key_configured": true' in caplog.text
    assert '"sender": "cloudguard@example.test"' in caplog.text
    assert "never-log-this-api-key" not in caplog.text
    assert "provider failed" not in caplog.text


def test_api_duplicate_signup_with_same_email_is_rejected():
    signup("first_user", "same@example.com", "StrongPass123!", "StrongPass123!")
    with pytest.raises(HTTPException) as error:
        signup_user(
            SignupRequest(
                username="second_user",
                email="SAME@example.com",
                password="StrongPass123!",
                confirmation="StrongPass123!",
            ),
        )
    assert error.value.status_code == 409


@pytest.mark.parametrize(("login_value", "password"), [
    ("vinit_1", "wrong-password"),
    ("unknown@example.com", "strongpass123"),
    ("", "strongpass123"),
])
def test_invalid_login_returns_no_user(login_value, password):
    signup("vinit_1", "vinit@example.com", "strongpass123", "strongpass123")
    assert login(login_value, password) is None


@pytest.mark.parametrize(("username", "email", "password", "confirmation"), [
    ("ab", "valid@example.com", "strongpass123", "strongpass123"),
    ("valid_user", "invalid-email", "strongpass123", "strongpass123"),
    ("valid_user", "valid@example.com", "", ""),
    ("valid_user", "valid@example.com", "short", "short"),
    ("valid_user", "valid@example.com", "strongpass123", "different"),
])
def test_signup_validation(username, email, password, confirmation):
    with pytest.raises(AuthValidationError):
        signup(username, email, password, confirmation)


def test_session_login_and_logout_clear_authentication_fields():
    state = {"theme": "dark"}
    user = User(1, "vinit_1", "vinit@example.com", "hash", "now")
    establish_session(state, user)
    assert state["authenticated"] is True
    assert state["user_id"] == 1
    assert state["username"] == "vinit_1"
    clear_session(state)
    assert state == {"theme": "dark"}


def test_user_data_remains_after_database_reinitialization():
    signup("vinit_1", "vinit@example.com", "strongpass123", "strongpass123")
    initialize_database()
    assert login("vinit_1", "strongpass123") is not None


def test_streamlit_registration_requires_email_verification(monkeypatch):
    import secrets

    monkeypatch.setattr(secrets, "randbelow", lambda _limit: 123456)
    user = signup_unverified(
        "pending_user", "PENDING@example.com", "strongpass123", "strongpass123"
    )
    assert user.email_verified is False
    assert login("pending_user", "strongpass123") is None
    with pytest.raises(EmailNotVerifiedError):
        dashboard_login("PENDING@example.com", "strongpass123")

    otp = create_email_otp(user.email, secret="test-only-secret-value-32-bytes-long")
    assert otp == "123456"
    record = AuthRepository.get_email_verification(user.email)
    assert record["otp_hash"] != otp
    assert verify_email_otp(
        user.email, otp, secret="test-only-secret-value-32-bytes-long"
    ) == "verified"
    assert login("pending_user", "strongpass123").email_verified is True


def test_email_verification_rejects_wrong_expired_and_reused_codes(monkeypatch):
    from datetime import datetime, timedelta, timezone
    import secrets

    monkeypatch.setattr(secrets, "randbelow", lambda _limit: 42)
    user = signup_unverified(
        "otp_user", "otp@example.com", "strongpass123", "strongpass123"
    )
    now = datetime.now(timezone.utc)
    secret = "test-only-secret-value-32-bytes-long"
    otp = create_email_otp(user.email, secret=secret, now=now)
    assert verify_email_otp(user.email, "000000", secret=secret, now=now) == "invalid"
    assert verify_email_otp(
        user.email,
        otp,
        secret=secret,
        now=now + timedelta(minutes=6),
    ) == "expired"
    assert verify_email_otp(user.email, otp, secret=secret, now=now) == "missing"

    replacement = create_email_otp(user.email, secret=secret, now=now)
    assert verify_email_otp(user.email, replacement, secret=secret, now=now) == "verified"
    assert verify_email_otp(user.email, replacement, secret=secret, now=now) == "missing"


def test_resending_code_replaces_previous_code(monkeypatch):
    import secrets

    values = iter((111111, 222222))
    monkeypatch.setattr(secrets, "randbelow", lambda _limit: next(values))
    user = signup_unverified(
        "resend_user", "resend@example.com", "strongpass123", "strongpass123"
    )
    secret = "test-only-secret-value-32-bytes-long"
    old_otp = create_email_otp(user.email, secret=secret)
    new_otp = create_email_otp(user.email, secret=secret)
    assert verify_email_otp(user.email, old_otp, secret=secret) == "invalid"
    assert verify_email_otp(user.email, new_otp, secret=secret) == "verified"
