"""End-to-end HTTP registration verification flow tests."""

import asyncio
import importlib
import json


async def _asgi_request(app, method, path, body=None, cookie=None):
    messages = []
    received = False

    async def receive():
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": body or b"", "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    headers = [(b"host", b"testserver")]
    if body is not None:
        headers.append((b"content-type", b"application/json"))
    if cookie:
        headers.append((b"cookie", cookie.encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    await app(scope, receive, send)
    start = next(message for message in messages if message["type"] == "http.response.start")
    response_headers = {
        name.decode().lower(): value.decode()
        for name, value in start["headers"]
    }
    response_body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return start["status"], response_headers, response_body


def test_api_registration_cannot_authenticate_until_otp_is_verified(
    monkeypatch, tmp_path
):
    import api.auth as auth_routes
    from database.db import initialize_database

    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.delenv("RAILWAY_ENVIRONMENT", raising=False)
    monkeypatch.setenv("CLOUDGUARD_ENVIRONMENT", "development")
    monkeypatch.setenv("CLOUDGUARD_SESSION_SECRET", "local-test-session-secret")
    monkeypatch.setenv("CLOUDGUARD_AUTH_DB", str(tmp_path / "email-auth.sqlite3"))
    monkeypatch.setenv("CLOUDGUARD_OTP_SECRET", "test-only-secret-value-32-bytes-long")
    monkeypatch.delenv("CLOUDGUARD_ALLOWED_ORIGINS", raising=False)
    import api.main as app_module
    app_module = importlib.reload(app_module)

    original_create_otp = auth_routes.create_email_otp
    captured = {}

    def capture_otp(email, **kwargs):
        code = original_create_otp(email, **kwargs)
        captured["codes"] = [*captured.get("codes", []), code]
        return code

    monkeypatch.setattr(auth_routes, "create_email_otp", capture_otp)
    monkeypatch.setattr(auth_routes, "send_verification_email", lambda *_args: None)

    try:
        initialize_database()
        status, _headers, body = asyncio.run(
            _asgi_request(
                app_module.app,
                "POST",
                "/api/auth/signup",
                json.dumps({
                    "username": "http_new_user",
                    "email": "http-new@example.com",
                    "password": "StrongPass123!",
                    "confirmation": "StrongPass123!",
                }).encode(),
            )
        )
        signup_result = json.loads(body)
        assert status == 201
        assert signup_result["authenticated"] is False
        assert signup_result["email"] == "http-new@example.com"

        status, _, _ = asyncio.run(
            _asgi_request(app_module.app, "GET", "/api/auth/me")
        )
        assert status == 401

        status, _, body = asyncio.run(
            _asgi_request(
                app_module.app,
                "POST",
                "/api/auth/login",
                json.dumps({"login": "http-new@example.com", "password": "StrongPass123!"}).encode(),
            )
        )
        assert status == 403
        assert json.loads(body)["detail"] == (
                "Please verify your email before logging in."
        )

        status, _, _ = asyncio.run(
            _asgi_request(
                app_module.app,
                "POST",
                "/api/auth/verify-email",
                json.dumps({
                    "email": "http-new@example.com",
                    "otp": "000000" if captured["codes"][0] != "000000" else "999999",
                }).encode(),
            )
        )
        assert status == 400

        old_code = captured["codes"][0]
        status, _, _ = asyncio.run(
            _asgi_request(
                app_module.app,
                "POST",
                "/api/auth/resend-otp",
                json.dumps({"email": "http-new@example.com"}).encode(),
            )
        )
        assert status == 200
        assert len(captured["codes"]) == 2
        assert captured["codes"][0] != captured["codes"][1]

        status, _, _ = asyncio.run(
            _asgi_request(
                app_module.app,
                "POST",
                "/api/auth/verify-email",
                json.dumps({"email": "http-new@example.com", "otp": old_code}).encode(),
            )
        )
        assert status == 400

        status, _, body = asyncio.run(
            _asgi_request(
                app_module.app,
                "POST",
                "/api/auth/verify-email",
                json.dumps({"email": "http-new@example.com", "otp": captured["codes"][1]}).encode(),
            )
        )
        assert status == 200
        assert json.loads(body)["verified"] is True
        status, _, _ = asyncio.run(
            _asgi_request(app_module.app, "GET", "/api/auth/me")
        )
        assert status == 401

        status, headers, _ = asyncio.run(
            _asgi_request(
                app_module.app,
                "POST",
                "/api/auth/login",
                json.dumps({"login": "http-new@example.com", "password": "StrongPass123!"}).encode(),
            )
        )
        assert status == 200
        cookie = headers["set-cookie"].split(";", 1)[0]
        status, _, body = asyncio.run(
            _asgi_request(app_module.app, "GET", "/api/auth/me", cookie=cookie)
        )
        assert status == 200
        assert json.loads(body)["email"] == "http-new@example.com"
    finally:
        monkeypatch.delenv("RENDER", raising=False)
        monkeypatch.delenv("RAILWAY_ENVIRONMENT", raising=False)
        monkeypatch.setenv("CLOUDGUARD_ENVIRONMENT", "development")
        monkeypatch.setenv("CLOUDGUARD_SESSION_SECRET", "local-test-session-secret")
        monkeypatch.delenv("CLOUDGUARD_ALLOWED_ORIGINS", raising=False)
        importlib.reload(app_module)
        initialize_database()
