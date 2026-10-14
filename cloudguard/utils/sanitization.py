"""Redact credential-shaped data before it reaches logs or reports."""

import re
from collections.abc import Mapping
from typing import Any


SENSITIVE_KEY_PARTS = (
    "secret",
    "password",
    "credential",
    "session",
    "token",
    "authorization",
    "accesskey",
    "access_key",
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(?:aws_)?(?:secret[_-]?access[_-]?key|access[_-]?key[_-]?id|"
    r"accesskeyid|(?:x-amz[-_])?(?:session|security)[_-]?token|authorization)"
    r"\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
AUTHORIZATION_HEADER_PATTERN = re.compile(r"(?im)\bAuthorization\s*:\s*[^\r\n]*")


def sanitize_sensitive_data(value: Any, sensitive_values: tuple[str, ...] = ()) -> Any:
    """Recursively remove credential fields and redact known credential values."""
    if isinstance(value, Mapping):
        return {
            str(key): sanitize_sensitive_data(item, sensitive_values)
            for key, item in value.items()
            if not any(
                part in re.sub(r"[^a-z0-9_]", "", str(key).lower())
                for part in SENSITIVE_KEY_PARTS
            )
        }
    if isinstance(value, (list, tuple, set)):
        return [sanitize_sensitive_data(item, sensitive_values) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value

    text = AWS_ACCESS_KEY_PATTERN.sub("[REDACTED]", str(value))
    text = AUTHORIZATION_HEADER_PATTERN.sub("Authorization: [REDACTED]", text)
    text = SENSITIVE_ASSIGNMENT_PATTERN.sub("[REDACTED]", text)
    for sensitive_value in sensitive_values:
        if sensitive_value:
            text = text.replace(sensitive_value, "[REDACTED]")
    return text
