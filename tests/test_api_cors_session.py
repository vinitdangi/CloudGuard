"""Production CORS and cross-origin session-cookie configuration tests."""

import importlib


PRODUCTION_ORIGIN = "https://cloud-guard-frontend-five.vercel.app"
ADDITIONAL_PRODUCTION_ORIGIN = "https://admin.cloudguard.example"


def test_production_cors_and_cross_site_session_settings(monkeypatch):
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
        assert cors_config["allow_origins"] == [
            PRODUCTION_ORIGIN,
            ADDITIONAL_PRODUCTION_ORIGIN,
        ]
        assert cors_config["allow_credentials"] is True
        assert session_config["same_site"] == "none"
        assert session_config["https_only"] is True

    finally:
        # Restore a safe local configuration for any tests importing api.main later.
        monkeypatch.setenv("CLOUDGUARD_ENVIRONMENT", "development")
        monkeypatch.setenv("CLOUDGUARD_SESSION_SECRET", "local-test-session-secret")
        monkeypatch.setenv("CLOUDGUARD_ALLOWED_ORIGINS", "http://localhost:3000")
        importlib.reload(app_module)
