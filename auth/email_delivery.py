"""SMTP delivery for CloudGuard registration verification codes."""

from email.message import EmailMessage
import os
import smtplib
import ssl


def setting(name: str, default: str = "") -> str:
    """Read a setting from environment first, then top-level Streamlit secrets."""
    value = os.getenv(name)
    if value:
        return value
    try:
        import streamlit as st

        return str(st.secrets.get(name, default))
    except Exception:
        return default


def send_verification_email(email: str, otp: str) -> None:
    """Send a registration code without logging or persisting the plaintext OTP."""
    host = setting("CLOUDGUARD_SMTP_HOST")
    username = setting("CLOUDGUARD_SMTP_USERNAME")
    password = setting("CLOUDGUARD_SMTP_PASSWORD")
    sender = setting("CLOUDGUARD_EMAIL_FROM", username)
    try:
        port = int(setting("CLOUDGUARD_SMTP_PORT", "587"))
    except ValueError as exc:
        raise ValueError("CLOUDGUARD_SMTP_PORT must be a valid port number.") from exc
    if not all((host, username, password, sender)):
        raise ValueError("SMTP email settings are incomplete.")

    message = EmailMessage()
    message["Subject"] = "Verify your CloudGuard email"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Your CloudGuard email verification code is {otp}. "
        "It expires in 5 minutes. Do not share this code."
    )

    context = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=15, context=context) as server:
            server.login(username, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(username, password)
            server.send_message(message)
