"""SQLite connection and schema management."""

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


def database_path() -> Path:
    """Return the configured auth database path or its local default."""
    configured_path = os.getenv("CLOUDGUARD_AUTH_DB")
    if configured_path:
        return Path(configured_path).expanduser().resolve()
    return Path(__file__).resolve().parents[1] / "data" / "cloudguard_users.sqlite3"


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """Open a SQLite connection with safe defaults and row-based access."""
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    """Create account and scan-history tables without overwriting stored data."""
    with get_connection() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                scan_timestamp TEXT NOT NULL,
                aws_account_id TEXT NOT NULL,
                aws_region TEXT NOT NULL,
                security_score REAL NOT NULL,
                total_findings INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                medium_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL,
                passed_count INTEGER NOT NULL
            )"""
        )

    # Account data should be readable only by the current user on POSIX hosts.
    path = database_path()
    try:
        path.chmod(0o600)
    except OSError:
        pass
