from pathlib import Path

from streamlit.testing.v1 import AppTest

import cloudguard.aws.configuration as aws_configuration
import engine.scan_engine as scan_engine


class _FakeStsClient:
    def get_caller_identity(self):
        return {"Account": "123456789012"}


class _FakeAwsSession:
    def client(self, service_name):
        assert service_name == "sts"
        return _FakeStsClient()


class _FakeScanEngine:
    called = False

    def __init__(self, session):
        assert isinstance(session, _FakeAwsSession)

    def run(self):
        type(self).called = True
        return [], {"bucket_count": 0}


def _assert_no_credentials_in_session_state(session_state, *credentials):
    state = session_state._state.filtered_state
    state_keys = [str(key) for key in state]
    state_values = [str(value) for value in state.values()]
    for credential in credentials:
        assert credential not in state_values
        assert credential not in state_keys
    for key in ("aws_access_key_id", "aws_secret_access_key"):
        if key in state:
            assert state[key] == ""


def _submit_access_key_operation(app, submit_button_index):
    access_key_id = "AKIAFAKEKEY000000000"
    secret_access_key = "FAKE_STREAMLIT_SECRET_VALUE"
    app.text_input[0].set_value(access_key_id)
    app.text_input[1].set_value(secret_access_key)
    app.button[submit_button_index].click().run()
    _assert_no_credentials_in_session_state(
        app.session_state, access_key_id, secret_access_key
    )


def test_streamlit_connection_and_scan_do_not_retain_aws_credentials(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("CLOUDGUARD_AUTH_DB", str(tmp_path / "cloudguard.sqlite3"))
    monkeypatch.setattr(
        aws_configuration, "create_session", lambda **kwargs: _FakeAwsSession()
    )
    monkeypatch.setattr(scan_engine, "ScanEngine", _FakeScanEngine)

    dashboard_path = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
    app = AppTest.from_file(dashboard_path, default_timeout=20)
    app.session_state["authenticated"] = True
    app.session_state["user_id"] = 1
    app.session_state["username"] = "streamlit-security-test"
    app.run()

    _submit_access_key_operation(app, 0)
    assert app.session_state["aws_connection_verified"] is True

    _submit_access_key_operation(app, 1)
    assert _FakeScanEngine.called is True
    assert not app.exception
