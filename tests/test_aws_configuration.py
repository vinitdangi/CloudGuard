"""AWS connection configuration tests using mocked boto3 sessions."""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError

from cloudguard.aws.configuration import (
    AUTH_METHOD_ACCESS_KEY,
    AUTH_METHOD_ENVIRONMENT,
    AWSConfigurationError,
    clear_aws_session_state,
    create_aws_session,
    safe_connection_error,
    test_aws_connection as check_aws_connection,
    validate_aws_configuration,
)
from cloudguard.aws.session import CloudGuardSession
from cloudguard.findings import Finding
from cloudguard.reporting.json_exporter import export_to_json
from database.db import database_path, initialize_database
from database.models import User
from engine.scan_engine import ScanEngine

FAKE_SECRET = "FAKE_TEST_" + "SECRET_DO_NOT_USE"


@pytest.mark.parametrize(
    ("access_key_id", "secret_access_key", "expected_message"),
    [
        ("", FAKE_SECRET, "Access Key ID"),
        ("AKIAFAKEKEY000000000", "", "Secret Access Key"),
    ],
)
def test_access_key_mode_requires_both_credentials(
    access_key_id, secret_access_key, expected_message
):
    with pytest.raises(AWSConfigurationError, match=expected_message):
        validate_aws_configuration(
            AUTH_METHOD_ACCESS_KEY,
            "ap-southeast-2",
            access_key_id,
            secret_access_key,
        )


def test_invalid_region_is_rejected():
    with pytest.raises(AWSConfigurationError, match="supported AWS region"):
        validate_aws_configuration(
            AUTH_METHOD_ENVIRONMENT,
            "invalid-region-1",
        )


def test_access_key_session_creation_passes_region_and_credentials():
    access_key_id = "AKIAFAKEKEY000000000"
    with patch("cloudguard.aws.session.boto3.Session") as session_factory:
        configured = create_aws_session(
            AUTH_METHOD_ACCESS_KEY,
            "ap-southeast-2",
            access_key_id,
            FAKE_SECRET,
        )

    assert isinstance(configured, CloudGuardSession)
    session_factory.assert_called_once_with(
        region_name="ap-southeast-2",
        aws_access_key_id=access_key_id,
        aws_secret_access_key=FAKE_SECRET,
    )


def test_environment_mode_preserves_boto3_credential_chain():
    with patch("cloudguard.aws.session.boto3.Session") as session_factory:
        create_aws_session(AUTH_METHOD_ENVIRONMENT, "ap-southeast-2")

    session_factory.assert_called_once_with(
        region_name="ap-southeast-2",
        aws_access_key_id=None,
        aws_secret_access_key=None,
    )


def test_connection_test_returns_safe_account_id():
    session = Mock()
    session.client.return_value.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/test",
        "UserId": "AIDATEST",
    }

    assert check_aws_connection(session) == "123456789012"
    session.client.assert_called_once_with("sts")
    session.client.return_value.get_caller_identity.assert_called_once_with()


def test_connection_error_is_sanitized(caplog):
    error = ClientError(
        {"Error": {"Code": "InvalidClientTokenId", "Message": FAKE_SECRET}},
        "GetCallerIdentity",
    )

    message = safe_connection_error(error)
    assert "authenticate" in message
    assert FAKE_SECRET not in message
    assert FAKE_SECRET not in caplog.text


def test_session_creation_failure_is_not_echoed_to_user():
    with patch(
        "cloudguard.aws.session.boto3.Session",
        side_effect=RuntimeError(FAKE_SECRET),
    ):
        with pytest.raises(RuntimeError) as error:
            create_aws_session(
                AUTH_METHOD_ACCESS_KEY,
                "ap-southeast-2",
                "AKIAFAKEKEY000000000",
                FAKE_SECRET,
            )

    assert FAKE_SECRET not in safe_connection_error(error.value)


def test_configured_session_is_passed_to_scan_engine():
    with patch("cloudguard.aws.session.boto3.Session"):
        configured_session = create_aws_session(
            AUTH_METHOD_ACCESS_KEY,
            "ap-southeast-2",
            "AKIAFAKEKEY000000000",
            FAKE_SECRET,
        )

    engine = ScanEngine(session=configured_session, disable_plugins=True)
    assert engine.session is configured_session


def test_aws_secret_is_not_persisted_in_database_or_json_report(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDGUARD_AUTH_DB", str(tmp_path / "users.sqlite3"))
    monkeypatch.chdir(tmp_path)
    initialize_database()

    raw_db = database_path().read_bytes()
    assert FAKE_SECRET.encode() not in raw_db

    export_to_json(
        [Finding(check="AWS configuration", resource="AWS", passed=True)],
        ["All"],
    )
    report = (tmp_path / "cloudguard_report.json").read_text(encoding="utf-8")
    assert FAKE_SECRET not in report
    assert json.loads(report)["findings"]


def test_logout_clears_aws_configuration_and_credentials():
    state = {
        "aws_auth_method": AUTH_METHOD_ACCESS_KEY,
        "aws_region": "ap-southeast-2",
        "aws_access_key_id": "AKIAFAKEKEY000000000",
        "aws_secret_access_key": FAKE_SECRET,
        "aws_connection_verified": True,
        "aws_account_id": "123456789012",
        "unrelated": "keep",
    }

    clear_aws_session_state(state)
    assert state == {"unrelated": "keep"}


def test_secret_is_not_in_user_visible_connection_error_or_account_model():
    safe_message = safe_connection_error(RuntimeError(FAKE_SECRET))
    account = User(1, "demo", "demo@example.com", "password-hash", "now")

    assert FAKE_SECRET not in safe_message
    assert FAKE_SECRET not in repr(account)


def test_secret_is_not_rendered_in_authenticated_dashboard_output(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("CLOUDGUARD_AUTH_DB", str(tmp_path / "users.sqlite3"))
    monkeypatch.setenv("MPLCONFIGDIR", str(tmp_path / "matplotlib"))
    dashboard_path = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
    app = AppTest.from_file(dashboard_path)
    app.session_state["authenticated"] = True
    app.session_state["user_id"] = 7
    app.session_state["username"] = "demo"
    app.session_state["email"] = "demo@example.com"
    app.session_state["aws_secret_access_key"] = FAKE_SECRET
    app.run(timeout=20)

    assert not app.exception
    visible_text = " ".join(
        str(element.value)
        for elements in (
            app.title,
            app.header,
            app.subheader,
            app.markdown,
            app.caption,
            app.info,
            app.success,
            app.warning,
            app.error,
        )
        for element in elements
    )
    assert FAKE_SECRET not in visible_text
    assert any(element.label == "AWS Secret Access Key" for element in app.text_input)
