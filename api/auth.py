"""Authentication API routes for CloudGuard."""

import json
import logging

from fastapi import APIRouter, HTTPException, Request, status

from auth.service import (
    AuthValidationError,
    DuplicateUserError,
    EmailNotVerifiedError,
    create_email_otp,
    dashboard_login,
    signup_unverified,
    verify_email_otp,
)
from auth.email_delivery import send_verification_email, setting
from database.auth_repository import AuthRepository
from api.schemas import (
    EmailVerificationRequest,
    EmailVerificationResponse,
    LoginRequest,
    ResendEmailVerificationRequest,
    SignupRequest,
    SignupResponse,
    UserResponse,
)


router = APIRouter(prefix="/api/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)


def _authenticated_user(request: Request):
    user_id = request.session.get("user_id")
    try:
        user = AuthRepository.find_by_id(int(user_id)) if user_id is not None else None
    except (TypeError, ValueError):
        user = None
    if user is None or not user.email_verified:
        request.session.clear()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    return user


def _public_user(user) -> UserResponse:
    """Convert a database user into a safe API response."""
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        created_at=user.created_at,
    )


@router.post("/signup", response_model=SignupResponse, status_code=status.HTTP_201_CREATED)
def signup_user(payload: SignupRequest) -> SignupResponse:
    """Create an unverified account and send its registration OTP."""
    try:
        user = signup_unverified(
            payload.username,
            payload.email,
            payload.password,
            payload.confirmation,
        )
    except AuthValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except DuplicateUserError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    try:
        otp = create_email_otp(
            user.email, secret=setting("CLOUDGUARD_OTP_SECRET")
        )
        send_verification_email(user.email, otp)
    except Exception:
        # Keep the account pending and let the verification UI offer a resend.
        message = "Account created, but the verification email could not be sent. Try resending the code."
    else:
        message = "Account created. Enter the verification code sent to your email."
    return SignupResponse(authenticated=False, email=user.email, message=message)


@router.post("/verify-email", response_model=EmailVerificationResponse)
def verify_registration_email(payload: EmailVerificationRequest) -> EmailVerificationResponse:
    """Verify and consume the one-time registration code."""
    identifier = payload.identifier or str(payload.email)
    user = AuthRepository.find_by_login(identifier)
    result = (
        verify_email_otp(
            user.email, payload.otp, secret=setting("CLOUDGUARD_OTP_SECRET")
        )
        if user is not None
        else "missing"
    )
    messages = {
        "verified": "Email verified. You can now sign in.",
        "invalid": "That verification code is incorrect.",
        "expired": "That verification code expired. Request a new one.",
        "too_many_attempts": "Too many incorrect attempts. Request a new code.",
        "missing": "No active verification code. Request a new one.",
    }
    if result != "verified":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=messages.get(result, "Unable to verify this code."),
        )
    return EmailVerificationResponse(verified=True, message=messages[result])


@router.post("/resend-otp", response_model=EmailVerificationResponse)
def resend_registration_otp(payload: ResendEmailVerificationRequest) -> EmailVerificationResponse:
    """Send a replacement code without disclosing whether an account matches."""
    identifier = payload.identifier or str(payload.email)
    user = AuthRepository.find_by_login(identifier)
    if user is not None and not user.email_verified:
        try:
            otp = create_email_otp(user.email, secret=setting("CLOUDGUARD_OTP_SECRET"))
            send_verification_email(user.email, otp)
        except Exception as exc:
            # Keep the response indistinguishable for missing, verified, and
            # pending accounts; another request can replace a code after setup is fixed.
            logger.warning(
                json.dumps(
                    {
                        "event": "verification_code_resend_failed",
                        "provider": setting("CLOUDGUARD_EMAIL_PROVIDER", "resend") or "resend",
                        "api_key_configured": bool(setting("CLOUDGUARD_EMAIL_API_KEY")),
                        "sender": setting("CLOUDGUARD_EMAIL_FROM") or None,
                        "error": type(exc).__name__,
                    },
                    sort_keys=True,
                )
            )
    return EmailVerificationResponse(
        verified=False,
        message="If an unverified account matches, a verification code has been sent. Check your email.",
    )


@router.post("/login", response_model=UserResponse)
def login_user(payload: LoginRequest, request: Request) -> UserResponse:
    """Authenticate a user and establish a session."""
    try:
        user = dashboard_login(payload.login, payload.password)
    except EmailNotVerifiedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email before logging in.",
        ) from exc

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/email or password.",
        )

    request.session["user_id"] = user.id
    return _public_user(user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout_user(request: Request) -> None:
    """Clear an authenticated user's session."""
    _authenticated_user(request)
    request.session.clear()


@router.get("/me", response_model=UserResponse)
def current_user(request: Request) -> UserResponse:
    """Return the currently authenticated user."""
    return _public_user(_authenticated_user(request))
