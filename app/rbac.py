"""Role-based access control helpers."""
from __future__ import annotations

from functools import wraps
from typing import Callable

from flask import abort
from flask_login import current_user

from .models import ROLE_PERMISSIONS, Permission  # noqa: F401 — re-exported


def has_permission(user: object, perm: str) -> bool:
    """Return True if *user* holds *perm*.

    Works with both authenticated User ORM instances and anonymous proxies
    (which have no ``role`` attribute).
    """
    if not getattr(user, "is_authenticated", False):
        return False
    role = getattr(user, "role", None)
    if role is None:
        return False
    return perm in ROLE_PERMISSIONS.get(str(role), set())


def require_permission(perm: str) -> Callable:
    """View decorator: abort(403) when the current user lacks *perm*."""

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args: object, **kwargs: object) -> object:
            if not has_permission(current_user, perm):
                abort(403)
            return f(*args, **kwargs)

        return wrapper

    return decorator
