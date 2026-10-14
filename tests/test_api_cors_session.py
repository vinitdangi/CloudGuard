"""Render production and local-development CORS/session regression tests."""

import asyncio
import importlib

import pytest


PRODUCTION_ORIGIN = "https://cloud-guard-frontend-five.vercel.app"
OTHER_ORIGIN = "https://other-frontend.example"


def _reset_to_local_configuration(monkeypatch, app_module):
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("CLOUDGUARD_ENVIRONMENT", "development")
    monkeypatch.setenv("CLOUDGUARD_SESSION_SECRET", "local-test-session-secret")
    monkeypatch.delenv("CLOUDGUARD_ALLOWED_ORIGINS", raising=False)
    importlib.reload(app_module)


async def _request_preflight(app, origin=PRODUCTION_ORIGIN):
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
            (b"origin", origin.encode()),
            (b"access-control-request-method", b"POST"),
            (b"access-control-request-headers", b"accept,content-type"),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("api.example.test", 443),
    }
    await app(scope, receive, send)
    return sent_messages


def _response_from(messages):
    response = next(message for message in messages if message["type"] == "http.response.start")
    headers = {name.decode().lower(): value.decode() for name, value in response["headers"]}
    return response, headers


def test_render_production_allows_exact_credentialed_vercel_preflight(monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.delenv("CLOUDGUARD_ENVIRONMENT", raising=False)
    monkeypatch.setenv("CLOUDGUARD_SESSION_SECRET", "p" * 48)
    monkeypatch.delenv("CLOUDGUARD_ALLOWED_ORIGINS", raising=False)
    from api import main

    app_module = importlib.reload(main)
    try:
        assert app_module.environment == "production"
        assert app_module.allowed_origins == [PRODUCTION_ORIGIN]
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
        assert cors_config["allow_origins"] == [PRODUCTION_ORIGIN]
        assert cors_config["allow_credentials"] is True
        assert session_config["same_site"] == "none"
        assert session_config["https_only"] is True

        response, headers = _response_from(
            asyncio.run(_request_preflight(app_module.app))
        )
        assert response["status"] in {200, 204}
        assert headers["access-control-allow-origin"] == PRODUCTION_ORIGIN
        assert headers["access-control-allow-credentials"] == "true"
        assert "post" in headers["access-control-allow-methods"].lower()
        assert "content-type" in headers["access-control-allow-headers"].lower()

        rejected, rejected_headers = _response_from(
            asyncio.run(_request_preflight(app_module.app, OTHER_ORIGIN))
        )
        assert rejected["status"] == 400
        assert "access-control-allow-origin" not in rejected_headers
    finally:
        _reset_to_local_configuration(monkeypatch, app_module)


@pytest.mark.parametrize(
    ("environment", "configured_origins", "message"),
    [
        ("production", OTHER_ORIGIN, "Production CORS allows only"),
        ("development", None, "must use CLOUDGUARD_ENVIRONMENT=production"),
    ],
    ids=["production-origin-mismatch", "render-explicit-development-mode"],
)
def test_render_rejects_misconfigured_cors_environment(
    monkeypatch, environment, configured_origins, message
):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("CLOUDGUARD_ENVIRONMENT", environment)
    monkeypatch.setenv("CLOUDGUARD_SESSION_SECRET", "p" * 48)
    if configured_origins is None:
        monkeypatch.delenv("CLOUDGUARD_ALLOWED_ORIGINS", raising=False)
    else:
        monkeypatch.setenv("CLOUDGUARD_ALLOWED_ORIGINS", configured_origins)
    from api import main

    try:
        with pytest.raises(RuntimeError, match=message):
            importlib.reload(main)
    finally:
        _reset_to_local_configuration(monkeypatch, main)


def test_local_development_defaults_to_localhost(monkeypatch):
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("CLOUDGUARD_ENVIRONMENT", "development")
    monkeypatch.setenv("CLOUDGUARD_SESSION_SECRET", "local-test-session-secret")
    monkeypatch.delenv("CLOUDGUARD_ALLOWED_ORIGINS", raising=False)
    from api import main

    app_module = importlib.reload(main)
    try:
        assert app_module.environment == "development"
        assert app_module.allowed_origins == ["http://localhost:3000"]
    finally:
        _reset_to_local_configuration(monkeypatch, app_module)
