"""Production CORS and cross-origin session-cookie configuration tests."""

import asyncio
import importlib

import pytest


PRODUCTION_ORIGIN = "https://cloud-guard-frontend-five.vercel.app"
ADDITIONAL_PRODUCTION_ORIGIN = "https://admin.cloudguard.example"


def _reset_to_local_configuration(monkeypatch, app_module):
    monkeypatch.setenv("CLOUDGUARD_ENVIRONMENT", "development")
    monkeypatch.setenv("CLOUDGUARD_SESSION_SECRET", "local-test-session-secret")
    monkeypatch.setenv("CLOUDGUARD_ALLOWED_ORIGINS", "http://localhost:3000")
    importlib.reload(app_module)


async def _request_preflight(app):
    sent_messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent_messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "OPTIONS",
        "scheme": "https",
        "path": "/api/auth/login",
        "raw_path": b"/api/auth/login",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"origin", PRODUCTION_ORIGIN.encode()),
            (b"access-control-request-method", b"POST"),
            (b"access-control-request-headers", b"accept,content-type"),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("api.example.test", 443),
    }
    await app(scope, receive, send)
    return sent_messages


def test_production_cors_allows_vercel_credentialed_login_preflight(monkeypatch):
    monkeypatch.setenv("CLOUDGUARD_ENVIRONMENT", "production")
    monkeypatch.setenv("CLOUDGUARD_SESSION_SECRET", "p" * 48)
    monkeypatch.setenv(
        "CLOUDGUARD_ALLOWED_ORIGINS",
        f"{PRODUCTION_ORIGIN},{ADDITIONAL_PRODUCTION_ORIGIN}",
    )
    from api import main

    app_module = importlib.reload(main)
    try:
        cors_config = next(
            middleware.kwargs
            for middleware in app_module.app.user_middleware
            if middleware.cls.__name__ == "CORSMiddleware"
        )
        session_config = next(
            middleware.kwargs
            for middleware in app_module.app.user_middleware
            if middleware.cls.__name__ == "SessionMiddleware"
        )
        assert PRODUCTION_ORIGIN in cors_config["allow_origins"]
        assert cors_config["allow_credentials"] is True
        assert session_config["same_site"] == "none"
        assert session_config["https_only"] is True

        messages = asyncio.run(_request_preflight(app_module.app))
        response = next(message for message in messages if message["type"] == "http.response.start")
        headers = {
            name.decode().lower(): value.decode()
            for name, value in response["headers"]
        }
        assert response["status"] in {200, 204}
        assert headers["access-control-allow-origin"] == PRODUCTION_ORIGIN
        assert headers["access-control-allow-credentials"] == "true"
        assert "post" in headers["access-control-allow-methods"].lower()
        assert "content-type" in headers["access-control-allow-headers"].lower()
    finally:
        _reset_to_local_configuration(monkeypatch, app_module)


@pytest.mark.parametrize(
    "configured_origins",
    ["", "https://other-frontend.example"],
    ids=["missing-origins", "missing-vercel-origin"],
)
def test_production_cors_fails_startup_without_required_origin(
    monkeypatch, configured_origins
):
    monkeypatch.setenv("CLOUDGUARD_ENVIRONMENT", "production")
    monkeypatch.setenv("CLOUDGUARD_SESSION_SECRET", "p" * 48)
    monkeypatch.setenv("CLOUDGUARD_ALLOWED_ORIGINS", configured_origins)
    from api import main

    try:
        with pytest.raises(RuntimeError, match="CLOUDGUARD_ALLOWED_ORIGINS"):
            importlib.reload(main)
    finally:
        _reset_to_local_configuration(monkeypatch, main)
