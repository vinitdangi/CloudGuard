"""Email delivery tests that never contact external providers."""

import json
import smtplib
from urllib.error import HTTPError

import pytest

import auth.email_delivery as email_delivery
from auth.email_delivery import EmailDeliveryError, send_verification_email


class _FakeSMTP:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.message = None
        self.logged_in = False
        self.started_tls = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def ehlo(self):
        pass

    def starttls(self, **_kwargs):
        self.started_tls = True

    def login(self, username, password):
        self.logged_in = bool(username and password)

    def send_message(self, message):
        self.message = message


def test_smtp_verification_uses_tls_and_sends_the_code(monkeypatch):
    fake = _FakeSMTP("smtp.example.test", 587)
    monkeypatch.setenv("CLOUDGUARD_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("CLOUDGUARD_SMTP_PORT", "587")
    monkeypatch.setenv("CLOUDGUARD_SMTP_USERNAME", "smtp-user")
    monkeypatch.setenv("CLOUDGUARD_SMTP_PASSWORD", "smtp-password")
    monkeypatch.setenv("CLOUDGUARD_EMAIL_FROM", "cloudguard@example.test")
    monkeypatch.setattr(smtplib, "SMTP", lambda *args, **kwargs: fake)

    send_verification_email("person@example.test", "001234")

    assert fake.started_tls
    assert fake.logged_in
    assert fake.message["To"] == "person@example.test"
    assert "001234" in fake.message.get_content()
    assert "smtp-password" not in fake.message.get_content()


def test_resend_sends_https_request_with_expected_auth_and_payload(monkeypatch):
    calls = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return 200

    def fake_urlopen(request, timeout):
        calls.append((request, timeout))
        return Response()

    monkeypatch.setenv("CLOUDGUARD_EMAIL_PROVIDER", "resend")
    monkeypatch.setenv("CLOUDGUARD_EMAIL_API_KEY", "re_test_secret")
    monkeypatch.setenv("CLOUDGUARD_EMAIL_FROM", "cloudguard@example.test")
    monkeypatch.setattr(email_delivery, "urlopen", fake_urlopen)

    send_verification_email("person@example.test", "001234")

    request, timeout = calls[0]
    assert request.full_url == "https://api.resend.com/emails"
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer re_test_secret"
    assert request.get_header("Content-type") == "application/json"
    assert timeout == email_delivery.EMAIL_REQUEST_TIMEOUT_SECONDS
    payload = json.loads(request.data)
    assert payload["from"] == "cloudguard@example.test"
    assert payload["to"] == ["person@example.test"]
    assert "001234" in payload["text"]


def test_resend_non_2xx_response_raises_sanitized_error(monkeypatch, caplog):
    def fake_urlopen(_request, **_kwargs):
        raise HTTPError(
            email_delivery.RESEND_EMAIL_API,
            401,
            "invalid key re_test_secret",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setenv("CLOUDGUARD_EMAIL_PROVIDER", "resend")
    monkeypatch.setenv("CLOUDGUARD_EMAIL_API_KEY", "re_test_secret")
    monkeypatch.setenv("CLOUDGUARD_EMAIL_FROM", "cloudguard@example.test")
    monkeypatch.setattr(email_delivery, "urlopen", fake_urlopen)

    with pytest.raises(EmailDeliveryError) as error:
        send_verification_email("person@example.test", "001234")
    assert "re_test_secret" not in str(error.value)
    assert "invalid key" not in str(error.value)
    assert "re_test_secret" not in caplog.text
    assert '"api_key_configured": true' in caplog.text
    assert '"http_status": 401' in caplog.text
    assert '"sender": "cloudguard@example.test"' in caplog.text


def test_production_requires_resend_and_api_key(monkeypatch):
    monkeypatch.setenv("RAILWAY_ENVIRONMENT", "production")
    monkeypatch.setenv("CLOUDGUARD_EMAIL_PROVIDER", "smtp")
    monkeypatch.setenv("CLOUDGUARD_EMAIL_FROM", "cloudguard@example.test")

    with pytest.raises(EmailDeliveryError, match="Production email delivery must use Resend"):
        send_verification_email("person@example.test", "001234")

    monkeypatch.setenv("CLOUDGUARD_EMAIL_PROVIDER", "resend")
    monkeypatch.delenv("CLOUDGUARD_EMAIL_API_KEY", raising=False)
    with pytest.raises(EmailDeliveryError, match="Email delivery is not configured"):
        send_verification_email("person@example.test", "001234")


def test_smtp_delivery_requires_configuration(monkeypatch):
    for name in (
        "CLOUDGUARD_SMTP_HOST",
        "CLOUDGUARD_SMTP_USERNAME",
        "CLOUDGUARD_SMTP_PASSWORD",
        "CLOUDGUARD_EMAIL_FROM",
        "CLOUDGUARD_EMAIL_API_KEY",
        "CLOUDGUARD_EMAIL_PROVIDER",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(EmailDeliveryError, match="Email sender configuration is missing"):
        send_verification_email("person@example.test", "001234")
