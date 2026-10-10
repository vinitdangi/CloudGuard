"""Tests for the SQLite scan-history repository."""

import sqlite3

import pytest

from database.db import database_path, initialize_database
from database.scan_history import get_scan_history, save_scan_history
from cloudguard.security_score import calculate_security_score


def _initialize(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDGUARD_AUTH_DB", str(tmp_path / "cloudguard.sqlite3"))
    initialize_database()
    return database_path()


def _save(timestamp, **overrides):
    values = {
        "username": "security-user",
        "scan_timestamp": timestamp,
        "aws_account_id": "123456789012",
        "aws_region": "ap-southeast-2",
        "security_score": 82.5,
        "total_findings": 3,
        "critical_count": 0,
        "high_count": 1,
        "medium_count": 1,
        "low_count": 0,
        "passed_count": 1,
    }
    values.update(overrides)
    return save_scan_history(**values)


def test_initialization_creates_auth_and_scan_history_tables(tmp_path, monkeypatch):
    path = _initialize(tmp_path, monkeypatch)

    with sqlite3.connect(path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(scan_history)")
        }

    assert {"users", "scan_history"} <= tables
    assert columns == {
        "id", "username", "scan_timestamp", "aws_account_id", "aws_region",
        "security_score", "total_findings", "critical_count", "high_count",
        "medium_count", "low_count", "passed_count",
    }


def test_inserts_scan_and_retrieves_only_requested_users(tmp_path, monkeypatch):
    _initialize(tmp_path, monkeypatch)

    inserted_id = _save("2026-10-10T10:00:00+00:00")
    _save("2026-10-10T10:01:00+00:00", username="another-user")

    rows = get_scan_history("security-user")
    assert len(rows) == 1
    assert rows[0]["id"] == inserted_id
    assert rows[0]["security_score"] == 82.5
    assert rows[0]["passed_count"] == 1


def test_scan_history_is_ordered_newest_first(tmp_path, monkeypatch):
    _initialize(tmp_path, monkeypatch)
    _save("2026-10-10T09:00:00+00:00")
    _save("2026-10-10T12:00:00+00:00")
    _save("2026-10-10T10:00:00+00:00")

    assert [row["scan_timestamp"] for row in get_scan_history("security-user")] == [
        "2026-10-10T12:00:00+00:00",
        "2026-10-10T10:00:00+00:00",
        "2026-10-10T09:00:00+00:00",
    ]


def test_credentials_are_not_accepted_or_stored(tmp_path, monkeypatch):
    path = _initialize(tmp_path, monkeypatch)
    fake_access_key = "FAKE_ACCESS_KEY_DO_NOT_USE"
    fake_secret_key = "FAKE_SECRET_KEY_DO_NOT_USE"

    with pytest.raises(TypeError):
        _save(
            "2026-10-10T10:00:00+00:00",
            aws_access_key_id=fake_access_key,
            aws_secret_access_key=fake_secret_key,
        )

    _save("2026-10-10T10:00:00+00:00")
    database_bytes = path.read_bytes()
    assert fake_access_key.encode() not in database_bytes
    assert fake_secret_key.encode() not in database_bytes
    with sqlite3.connect(path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scan_history)")}
    assert "aws_access_key_id" not in columns
    assert "aws_secret_access_key" not in columns


def test_scan_history_stores_authoritative_calculated_score(tmp_path, monkeypatch):
    _initialize(tmp_path, monkeypatch)
    score = calculate_security_score([
        {"finding_id": "mfa", "check": "MFA", "resource": "user-a",
         "passed": False, "severity": "HIGH"},
        {"finding_id": "encryption", "check": "Encryption", "resource": "bucket-a",
         "passed": True},
    ])

    _save(
        "2026-10-10T10:00:00+00:00",
        security_score=score.score,
        total_findings=score.total_findings,
        critical_count=score.critical_count,
        high_count=score.high_count,
        medium_count=score.medium_count,
        low_count=score.low_count,
        passed_count=score.passed_count,
    )

    row = get_scan_history("security-user")[0]
    assert row["security_score"] == score.score
    assert row["total_findings"] == score.total_findings
    assert row["high_count"] == score.high_count
    assert row["passed_count"] == score.passed_count
