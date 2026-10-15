"""CloudGuard FastAPI application."""

import os
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from api.auth import router as auth_router
from api.aws import router as aws_router
from database.db import initialize_database


PRODUCTION_FRONTEND_ORIGIN = "https://cloud-guard-frontend-five.vercel.app"

running_on_render = os.getenv("RENDER", "").strip().lower() == "true"
running_on_railway = bool(os.getenv("RAILWAY_ENVIRONMENT", "").strip())
environment = os.getenv(
    "CLOUDGUARD_ENVIRONMENT",
    "production" if running_on_render or running_on_railway else "development",
).strip().lower()
if environment not in {"development", "production"}:
    raise RuntimeError("CLOUDGUARD_ENVIRONMENT must be development or production.")
if running_on_render and environment != "production":
    raise RuntimeError("CloudGuard on Render must use CLOUDGUARD_ENVIRONMENT=production.")
if running_on_railway and environment != "production":
    raise RuntimeError("CloudGuard on Railway must use CLOUDGUARD_ENVIRONMENT=production.")

session_secret = os.getenv("CLOUDGUARD_SESSION_SECRET", "").strip()
if not session_secret:
    raise RuntimeError("CLOUDGUARD_SESSION_SECRET is not configured.")
if environment == "production" and (
    len(session_secret) < 32
    or session_secret.lower().startswith(("replace", "change", "local", "example"))
):
    raise RuntimeError("Production requires a strong CLOUDGUARD_SESSION_SECRET of at least 32 characters.")


def _configured_origins() -> list[str]:
    configured = os.getenv("CLOUDGUARD_ALLOWED_ORIGINS", "").strip()
    if not configured:
        if environment == "production":
            return [PRODUCTION_FRONTEND_ORIGIN]
        return ["http://localhost:3000"]

    configured_origins = [origin.strip() for origin in configured.split(",") if origin.strip()]
    if not configured_origins or "*" in configured_origins:
        raise RuntimeError("CLOUDGUARD_ALLOWED_ORIGINS must contain explicit origins; wildcards are not allowed.")
    origins = []
    for origin in configured_origins:
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise RuntimeError("CLOUDGUARD_ALLOWED_ORIGINS must contain valid origin URLs only.")
        if environment == "production":
            if (
                parsed.scheme != "https"
                or parsed.hostname is None
                or not parsed.hostname.endswith(".vercel.app")
                or parsed.port is not None
            ):
                raise RuntimeError(
                    "Production allowed origins must be HTTPS Vercel origins without custom ports."
                )
        origins.append(f"{parsed.scheme}://{parsed.netloc}")
    if environment == "production":
        # The canonical origin is always allowed; preview deployment origins
        # are opt-in as exact comma-separated entries in the environment.
        return list(dict.fromkeys([PRODUCTION_FRONTEND_ORIGIN, *origins]))
    return origins


allowed_origins = _configured_origins()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="CloudGuard API",
    version="1.0.0",
    description="Backend API for CloudGuard AWS security assessment.",
    debug=False,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Accept", "Content-Type"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret,
    session_cookie="cloudguard_session",
    max_age=3600,
    same_site="none" if environment == "production" else "lax",
    https_only=environment == "production",
)


@app.exception_handler(RequestValidationError)
async def safe_validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
    """Report invalid fields without echoing submitted passwords or AWS keys."""
    fields = sorted({str(error["loc"][-1]) for error in exc.errors() if error.get("loc")})
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid request data.", "fields": fields},
    )


@app.exception_handler(Exception)
async def safe_internal_error(_request: Request, _exc: Exception) -> JSONResponse:
    """Keep internal exception details out of production API responses."""
    return JSONResponse(
        status_code=500,
        content={"detail": "The CloudGuard API could not complete this request."},
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if environment == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/api/health")
def health_check() -> dict[str, str]:
    """Return API health status."""
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(aws_router)
