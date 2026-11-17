"""The ONE password policy: at least 12 characters, at most 1024. Length only.

Until 2026-10-03 each path carried its own rule: the web console asked for 8
characters, the root CLI for 12, the plain installer for 8 and the guided
installer for 10 plus three character classes. Every path now applies this
rule -- the web forms and the CLI import it, and the two installer scripts
repeat the same two numbers (they run before the app is installed). There is
no character-class rule: length is what makes a password hard to guess.

Existing passwords are not re-validated; the rule applies when a password is
set or changed.
"""
from __future__ import annotations

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024


def password_problem(password: str | None) -> str:
    """Why ``password`` is refused, or ``""`` when it is acceptable."""
    if not password:
        return "A password is required."
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"The password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"The password must be at most {MAX_PASSWORD_LENGTH} characters."
    return ""
