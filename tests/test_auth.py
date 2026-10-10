"""Tests for CloudGuard account authentication."""

import pytest

from auth.password import hash_password, verify_password
from auth.service import AuthValidationError, DuplicateUserError, login, signup
from auth.session import clear_session, establish_session
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
