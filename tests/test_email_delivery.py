"""SMTP delivery tests that never contact an external mail server."""

import smtplib

import pytest

from auth.email_delivery import send_verification_email


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


def test_smtp_delivery_requires_configuration(monkeypatch):
    for name in (
        "CLOUDGUARD_SMTP_HOST",
        "CLOUDGUARD_SMTP_USERNAME",
        "CLOUDGUARD_SMTP_PASSWORD",
        "CLOUDGUARD_EMAIL_FROM",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="SMTP email settings are incomplete"):
        send_verification_email("person@example.test", "001234")
