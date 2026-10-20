"""Password reset behavior, storage, and API privacy tests."""

import hashlib

import pytest
from fastapi import HTTPException

from api.auth import complete_password_reset, forgot_password
from api.schemas import ForgotPasswordRequest, PasswordResetRequest
from auth.password import verify_password
from auth.service import create_password_reset_token, login, reset_password, signup
from database.auth_repository import AuthRepository
from database.db import get_connection, initialize_database


@pytest.fixture(autouse=True)
def initialized_database(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDGUARD_AUTH_DB", str(tmp_path / "reset.sqlite3"))
    initialize_database()


def _token_row():
    with get_connection() as connection:
        return connection.execute(
            "SELECT token_digest, expires_at, used_at FROM password_reset_tokens"
        ).fetchone()


def test_forgot_password_has_generic_response_for_existing_and_missing_accounts(monkeypatch):
    user = signup("reset_user", "reset@example.com", "StrongPass123!", "StrongPass123!")
    delivered = []
    monkeypatch.setattr("api.auth.send_password_reset_email", lambda *args: delivered.append(args))

    existing = forgot_password(ForgotPasswordRequest(identifier=user.username))
    missing = forgot_password(ForgotPasswordRequest(identifier="no-account"))

    assert existing.model_dump() == missing.model_dump()
    assert "If an account matches" in existing.message
    assert len(delivered) == 1


def test_reset_token_is_secure_and_only_digest_is_stored():
    user = signup("digest_user", "digest@example.com", "StrongPass123!", "StrongPass123!")
    token = create_password_reset_token(user.id)
    assert len(token) >= 40
    assert _token_row()["token_digest"] == hashlib.sha256(token.encode()).hexdigest()
    assert token not in _token_row()["token_digest"]


def test_new_reset_request_invalidates_previous_token():
    user = signup("rotate_user", "rotate@example.com", "StrongPass123!", "StrongPass123!")
    old = create_password_reset_token(user.id)
    new = create_password_reset_token(user.id)
    assert not reset_password(old, "NewPass456!", "NewPass456!")
    assert reset_password(new, "NewPass456!", "NewPass456!")


def test_valid_reset_hashes_password_and_requires_login_again():
    user = signup("change_user", "change@example.com", "OldPass123!", "OldPass123!")
    token = create_password_reset_token(user.id)
    response = complete_password_reset(
        PasswordResetRequest(token=token, password="NewPass456!", confirmation="NewPass456!")
    )
    updated = AuthRepository.find_by_id(user.id)
    assert "Sign in" in response.message
    assert updated.password_hash.startswith("$argon2id$")
    assert verify_password(updated.password_hash, "NewPass456!")
    assert login("change_user", "NewPass456!") is not None
    assert login("change_user", "OldPass123!") is None
    assert _token_row()["used_at"] is not None


@pytest.mark.parametrize("token", ["unrecognized-token"])
def test_invalid_and_reused_tokens_are_rejected(token):
    with pytest.raises(HTTPException) as error:
        complete_password_reset(
            PasswordResetRequest(token=token, password="NewPass456!", confirmation="NewPass456!")
        )
    assert error.value.status_code == 400

    user = signup("reuse_user", "reuse@example.com", "OldPass123!", "OldPass123!")
    valid = create_password_reset_token(user.id)
    payload = PasswordResetRequest(token=valid, password="NewPass456!", confirmation="NewPass456!")
    complete_password_reset(payload)
    with pytest.raises(HTTPException) as reused:
        complete_password_reset(payload)
    assert reused.value.status_code == 400


def test_expired_token_is_rejected():
    user = signup("expired_user", "expired@example.com", "OldPass123!", "OldPass123!")
    token = create_password_reset_token(user.id)
    with get_connection() as connection:
        connection.execute(
            "UPDATE password_reset_tokens SET expires_at = ?",
            ("2000-01-01T00:00:00+00:00",),
        )
    assert not reset_password(token, "NewPass456!", "NewPass456!")


def test_password_validation_is_shared_and_no_session_is_created():
    from types import SimpleNamespace
    from api.auth import login_user
    from api.schemas import LoginRequest
    from auth.service import AuthValidationError

    user = signup("validation_user", "validation@example.com", "OldPass123!", "OldPass123!")
    token = create_password_reset_token(user.id)
    with pytest.raises(AuthValidationError, match="at least 8"):
        reset_password(token, "short", "short")
    request = SimpleNamespace(session={})
    complete_password_reset(
        PasswordResetRequest(token=token, password="NewPass456!", confirmation="NewPass456!")
    )
    assert request.session == {}
    assert login_user(LoginRequest(login="validation_user", password="NewPass456!"), request)

