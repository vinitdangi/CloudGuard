"""Authentication API routes for CloudGuard."""

from fastapi import APIRouter, HTTPException, Request, status

from auth.service import (
    AuthValidationError,
    DuplicateUserError,
    login,
    signup,
)
from database.auth_repository import AuthRepository
from api.schemas import LoginRequest, SignupRequest, UserResponse


router = APIRouter(prefix="/api/auth", tags=["Authentication"])


def _authenticated_user(request: Request):
    user_id = request.session.get("user_id")
    try:
        user = AuthRepository.find_by_id(int(user_id)) if user_id is not None else None
    except (TypeError, ValueError):
        user = None
    if user is None:
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


@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def signup_user(payload: SignupRequest, request: Request) -> UserResponse:
    """Create a CloudGuard account and establish a session."""
    try:
        user = signup(
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

    request.session["user_id"] = user.id
    return _public_user(user)


@router.post("/login", response_model=UserResponse)
def login_user(payload: LoginRequest, request: Request) -> UserResponse:
    """Authenticate a user and establish a session."""
    user = login(payload.login, payload.password)

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
