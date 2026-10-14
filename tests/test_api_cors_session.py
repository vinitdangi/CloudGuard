"""Render production and local-development CORS/session regression tests."""

import asyncio
import importlib
import json

import pytest

from auth.service import signup
from database.db import initialize_database


PRODUCTION_ORIGIN = "https://cloud-guard-frontend-five.vercel.app"
PREVIEW_ORIGIN = "https://cloud-guard-frontend-git-session-vinitdangi.vercel.app"
OTHER_ORIGIN = "https://other-frontend.example"


def _reset_to_local_configuration(monkeypatch, app_module):
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("CLOUDGUARD_ENVIRONMENT", "development")
    monkeypatch.setenv("CLOUDGUARD_SESSION_SECRET", "local-test-session-secret")
    monkeypatch.delenv("CLOUDGUARD_ALLOWED_ORIGINS", raising=False)
    importlib.reload(app_module)


async def _request(app, method, path, origin, body=None, cookie=None):
    sent_messages = []
    request_received = False

    async def receive():
        nonlocal request_received
        if not request_received:
            request_received = True
            return {"type": "http.request", "body": body or b"", "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        sent_messages.append(message)

    headers = [(b"origin", origin.encode()), (b"accept", b"application/json")]
    if body is not None:
        headers.append((b"content-type", b"application/json"))
    if cookie is not None:
        headers.append((b"cookie", cookie.encode()))
    if method == "OPTIONS":
        headers.extend(
            [
                (b"access-control-request-method", b"POST"),
                (b"access-control-request-headers", b"accept,content-type"),
            ]
        )

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("api.example.test", 443),
    }
    await app(scope, receive, send)
    return sent_messages


def _response_from(messages):
    response = next(message for message in messages if message["type"] == "http.response.start")
    headers = {name.decode().lower(): value.decode() for name, value in response["headers"]}
    body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return response, headers, body


def test_render_production_allows_exact_credentialed_vercel_preflight(monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.delenv("CLOUDGUARD_ENVIRONMENT", raising=False)
    monkeypatch.setenv("CLOUDGUARD_SESSION_SECRET", "p" * 48)
    monkeypatch.setenv("CLOUDGUARD_ALLOWED_ORIGINS", PREVIEW_ORIGIN)
    from api import main

    app_module = importlib.reload(main)
    try:
        assert app_module.environment == "production"
        assert app_module.allowed_origins == [PRODUCTION_ORIGIN, PREVIEW_ORIGIN]
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
        assert cors_config["allow_origins"] == [PRODUCTION_ORIGIN, PREVIEW_ORIGIN]
        assert cors_config["allow_credentials"] is True
        assert session_config["same_site"] == "none"
        assert session_config["https_only"] is True

        response, headers, _ = _response_from(
            asyncio.run(_request(app_module.app, "OPTIONS", "/api/auth/login", PRODUCTION_ORIGIN))
        )
        assert response["status"] in {200, 204}
        assert headers["access-control-allow-origin"] == PRODUCTION_ORIGIN
        assert headers["access-control-allow-credentials"] == "true"
        assert "post" in headers["access-control-allow-methods"].lower()
        assert "content-type" in headers["access-control-allow-headers"].lower()

        preview_response, preview_headers, _ = _response_from(
            asyncio.run(_request(app_module.app, "OPTIONS", "/api/auth/login", PREVIEW_ORIGIN))
        )
        assert preview_response["status"] in {200, 204}
        assert preview_headers["access-control-allow-origin"] == PREVIEW_ORIGIN

        rejected, rejected_headers, _ = _response_from(
            asyncio.run(_request(app_module.app, "OPTIONS", "/api/auth/login", OTHER_ORIGIN))
        )
        assert rejected["status"] == 400
        assert "access-control-allow-origin" not in rejected_headers
    finally:
        _reset_to_local_configuration(monkeypatch, app_module)


@pytest.mark.parametrize(
    ("environment", "configured_origins", "message"),
    [
        ("production", OTHER_ORIGIN, "HTTPS Vercel origins"),
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


def test_production_login_cookie_authenticates_followup_me_request(monkeypatch, tmp_path):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.delenv("CLOUDGUARD_ENVIRONMENT", raising=False)
    monkeypatch.setenv("CLOUDGUARD_SESSION_SECRET", "p" * 48)
    monkeypatch.setenv("CLOUDGUARD_AUTH_DB", str(tmp_path / "auth.sqlite3"))
    monkeypatch.delenv("CLOUDGUARD_ALLOWED_ORIGINS", raising=False)
    from api import main

    app_module = importlib.reload(main)
    try:
        initialize_database()
        signup("session_user", "session@example.com", "StrongPass123!", "StrongPass123!")

        login_response, login_headers, _ = _response_from(
            asyncio.run(
                _request(
                    app_module.app,
                    "POST",
                    "/api/auth/login",
                    PRODUCTION_ORIGIN,
                    body=json.dumps(
                        {"login": "session@example.com", "password": "StrongPass123!"}
                    ).encode(),
                )
            )
        )
        assert login_response["status"] == 200
        assert login_headers["access-control-allow-origin"] == PRODUCTION_ORIGIN
        assert login_headers["access-control-allow-credentials"] == "true"
        set_cookie = login_headers["set-cookie"]
        cookie_attributes = set_cookie.lower()
        assert "secure" in cookie_attributes
        assert "httponly" in cookie_attributes
        assert "samesite=none" in cookie_attributes
        cookie_pair = set_cookie.split(";", 1)[0]

        me_response, me_headers, me_body = _response_from(
            asyncio.run(
                _request(
                    app_module.app,
                    "GET",
                    "/api/auth/me",
                    PRODUCTION_ORIGIN,
                    cookie=cookie_pair,
                )
            )
        )
        assert me_response["status"] == 200
        assert me_headers["access-control-allow-origin"] == PRODUCTION_ORIGIN
        assert me_headers["access-control-allow-credentials"] == "true"
        assert json.loads(me_body)["username"] == "session_user"
    finally:
        _reset_to_local_configuration(monkeypatch, app_module)
