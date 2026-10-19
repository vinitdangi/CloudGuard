"""Email delivery for CloudGuard registration verification codes."""

from email.message import EmailMessage
import json
import logging
import os
import re
import smtplib
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


RESEND_EMAIL_API = "https://api.resend.com/emails"
EMAIL_REQUEST_TIMEOUT_SECONDS = 10
logger = logging.getLogger(__name__)


class EmailDeliveryError(RuntimeError):
    """Provider-neutral failure that does not expose secrets or provider responses."""


def _safe_detail(value: str, api_key: str) -> str:
    """Remove credentials and OTP-like values before putting provider details in logs."""
    detail = value[:1000]
    if api_key:
        detail = detail.replace(api_key, "[REDACTED]")
    detail = re.sub(
        r'(?i)("?(?:authorization|api[_ -]?key|token|password|secret)"?\s*[:=]\s*)"?[^,\s}\"]+"?',
        r"\1[REDACTED]",
        detail,
    )
    detail = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "[REDACTED_EMAIL]",
        detail,
    )
    detail = re.sub(r"\b\d{6}\b", "[REDACTED_OTP]", detail)
    return detail


def _log_provider_event(level: int, event: str, **fields: object) -> None:
    logger.log(level, json.dumps({"event": event, **fields}, sort_keys=True))


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


def _is_production() -> bool:
    environment = setting("CLOUDGUARD_ENVIRONMENT").strip().lower()
    return bool(
        os.getenv("RAILWAY_ENVIRONMENT")
        or os.getenv("RAILWAY_PROJECT_ID")
        or environment in {"prod", "production"}
    )


def _provider() -> str:
    configured = setting("CLOUDGUARD_EMAIL_PROVIDER").strip().lower()
    if _is_production():
        if configured and configured != "resend":
            raise EmailDeliveryError("Production email delivery must use Resend.")
        return "resend"
    if configured:
        if configured not in {"resend", "smtp"}:
            raise EmailDeliveryError("Unsupported email provider configuration.")
        return configured
    # Keep existing local Gmail SMTP setups working. If an API key is present,
    # Resend is selected automatically; production always selects Resend above.
    if setting("CLOUDGUARD_EMAIL_API_KEY"):
        return "resend"
    smtp_settings = (
        "CLOUDGUARD_SMTP_HOST",
        "CLOUDGUARD_SMTP_USERNAME",
        "CLOUDGUARD_SMTP_PASSWORD",
    )
    return "smtp" if all(setting(name) for name in smtp_settings) else "resend"


def _send_with_resend(email: str, otp: str, sender: str) -> None:
    api_key = setting("CLOUDGUARD_EMAIL_API_KEY")
    if not api_key:
        raise EmailDeliveryError("Email delivery is not configured.")

    payload = json.dumps(
        {
            "from": sender,
            "to": [email],
            "subject": "Verify your CloudGuard email",
            "text": (
                f"Your CloudGuard email verification code is {otp}. "
                "It expires in 5 minutes. Do not share this code."
            ),
        }
    ).encode("utf-8")
    request = Request(
        RESEND_EMAIL_API,
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=EMAIL_REQUEST_TIMEOUT_SECONDS) as response:
            status = response.getcode()
            _log_provider_event(
                logging.INFO,
                "verification_email_provider_response",
                provider="resend",
                http_status=status,
                sender=sender,
            )
            if status < 200 or status >= 300:
                raise EmailDeliveryError("Email provider rejected the verification email.")
    except EmailDeliveryError:
        raise
    except HTTPError as exc:
        try:
            response_body = exc.read(1000).decode("utf-8", errors="replace")
        except Exception:
            response_body = ""
        _log_provider_event(
            logging.WARNING,
            "verification_email_provider_response",
            provider="resend",
            http_status=exc.code,
            sender=sender,
            error=_safe_detail(response_body, api_key),
        )
        exc.close()
        raise EmailDeliveryError("Email provider rejected the verification email.") from None
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        _log_provider_event(
            logging.WARNING,
            "verification_email_provider_failure",
            provider="resend",
            sender=sender,
            error=_safe_detail(str(exc), api_key),
        )
        raise EmailDeliveryError("Email provider request failed.") from None


def _send_with_smtp(email: str, otp: str, sender: str) -> None:
    host = setting("CLOUDGUARD_SMTP_HOST")
    username = setting("CLOUDGUARD_SMTP_USERNAME")
    password = setting("CLOUDGUARD_SMTP_PASSWORD")
    try:
        port = int(setting("CLOUDGUARD_SMTP_PORT", "587"))
    except ValueError:
        raise EmailDeliveryError("SMTP email configuration is invalid.") from None
    if not all((host, username, password, sender)):
        raise EmailDeliveryError("Email delivery is not configured.")

    message = EmailMessage()
    message["Subject"] = "Verify your CloudGuard email"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Your CloudGuard email verification code is {otp}. "
        "It expires in 5 minutes. Do not share this code."
    )

    context = ssl.create_default_context()
    try:
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
    except Exception:
        raise EmailDeliveryError("SMTP email delivery failed.") from None


def send_verification_email(email: str, otp: str) -> None:
    """Send a verification code without logging or persisting its plaintext."""
    sender = setting("CLOUDGUARD_EMAIL_FROM")
    api_key_configured = bool(setting("CLOUDGUARD_EMAIL_API_KEY"))
    try:
        provider = _provider()
    except EmailDeliveryError as exc:
        _log_provider_event(
            logging.WARNING,
            "verification_email_provider_configuration_failure",
            provider=setting("CLOUDGUARD_EMAIL_PROVIDER", "auto") or "auto",
            api_key_configured=api_key_configured,
            sender=sender or None,
            error=_safe_detail(str(exc), setting("CLOUDGUARD_EMAIL_API_KEY")),
        )
        raise

    _log_provider_event(
        logging.INFO,
        "verification_email_provider_selected",
        provider=provider,
        api_key_configured=api_key_configured,
        sender=sender or None,
    )
    try:
        if not sender:
            raise EmailDeliveryError("Email sender configuration is missing.")
        if provider == "resend":
            _send_with_resend(email, otp, sender)
        else:
            _send_with_smtp(email, otp, sender)
    except EmailDeliveryError as exc:
        _log_provider_event(
            logging.WARNING,
            "verification_email_delivery_failure",
            provider=provider,
            api_key_configured=api_key_configured,
            sender=sender or None,
            error=_safe_detail(str(exc), setting("CLOUDGUARD_EMAIL_API_KEY")),
        )
        raise
    _log_provider_event(
        logging.INFO,
        "verification_email_delivery_accepted",
        provider=provider,
        api_key_configured=api_key_configured,
        sender=sender,
    )
