"""The ONE web-console password minimum.

Until 2026-10-03 each path carried its own rule: the reset link and the old
profile form asked for 8 characters, while Settings -> Change Password, Add
User and the admin reset accepted any non-empty password -- under placeholders
that said "At least 8 characters". Every path now asks this module.

The root CLI keeps its own, stricter rule (12) on purpose: it is the recovery
path for an administrator account.
"""
from __future__ import annotations

MIN_PASSWORD_LENGTH = 8


def password_problem(password: str | None) -> str:
    """Why ``password`` is refused, or ``""`` when it is acceptable."""
    if not password:
        return "A password is required."
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"The password must be at least {MIN_PASSWORD_LENGTH} characters."
    return ""
