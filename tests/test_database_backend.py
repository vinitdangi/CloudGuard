"""Backend selection and initialization tests for CloudGuard persistence."""

import sys
import types

import pytest

from database import db


class _FakeCursor:
    def fetchone(self):
        return {"id": 1}


class _FakePostgreSQLConnection:
    def __init__(self):
        self.statements = []
        self.committed = False
        self.closed = False

    def execute(self, query, parameters=()):
        self.statements.append((query, parameters))
        return _FakeCursor()

    def commit(self):
        self.committed = True

    def rollback(self):
        pass

    def close(self):
        self.closed = True


def test_database_url_selects_postgresql_and_initializes_auth_schema(monkeypatch):
    fake_connection = _FakePostgreSQLConnection()
    calls = {}
    fake_psycopg = types.ModuleType("psycopg")
    fake_psycopg.connect = lambda url, **kwargs: calls.update(url=url, **kwargs) or fake_connection
    fake_psycopg.IntegrityError = type("IntegrityError", (Exception,), {})
    fake_rows = types.ModuleType("psycopg.rows")
    fake_rows.dict_row = object()
    monkeypatch.setitem(sys.modules, "psycopg", fake_psycopg)
    monkeypatch.setitem(sys.modules, "psycopg.rows", fake_rows)
    monkeypatch.setenv("DATABASE_URL", "postgres://db-user:private@postgres.internal:5432/cloudguard")
    monkeypatch.setenv("CLOUDGUARD_AUTH_DB", "/unused/local/path.sqlite3")
    monkeypatch.delenv("RAILWAY_ENVIRONMENT", raising=False)
    monkeypatch.delenv("RAILWAY_PROJECT_ID", raising=False)

    db.initialize_database()

    assert calls["url"].startswith("postgresql://")
    assert calls["row_factory"] is fake_rows.dict_row
    assert any("CREATE TABLE IF NOT EXISTS users" in sql for sql, _ in fake_connection.statements)
    assert any("CREATE TABLE IF NOT EXISTS scan_history" in sql for sql, _ in fake_connection.statements)
    assert fake_connection.committed
    assert fake_connection.closed


def test_railway_requires_database_url_instead_of_silent_sqlite_fallback(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("RAILWAY_ENVIRONMENT", "production")

    with pytest.raises(RuntimeError, match="DATABASE_URL is required"):
        with db.get_connection():
            pass
