"""Helpers for the server-side Streamlit authentication session."""


AUTH_SESSION_KEYS = ("authenticated", "user_id", "username", "email")


def establish_session(session_state, user) -> None:
    """Mark a verified account as authenticated for this Streamlit session."""
    session_state["authenticated"] = True
    session_state["user_id"] = user.id
    session_state["username"] = user.username
    session_state["email"] = user.email


def clear_session(session_state) -> None:
    """Remove authentication identity values during logout."""
    for key in AUTH_SESSION_KEYS:
        session_state.pop(key, None)
