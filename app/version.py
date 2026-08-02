"""Single source of truth for the application version.

The version lives in the repo-root ``VERSION`` file — the same file the
offline-bundle builders and the operator CLI read. Nothing else may carry a
version literal.

Why this module exists: the footer and Settings -> System Information each
carried a hand-written ``v1.0`` that was correct for exactly one release and
then quietly rotted through 1.1, 1.2, 1.2.1 and 1.2.2 while the release
pipeline dutifully published the real number everywhere else. A literal that
only a human can update is a literal that will be wrong.

Read once at import: the file ships inside the deployment and cannot change
without a code update, which restarts the process anyway.
"""
from __future__ import annotations

import pathlib

# app/version.py -> repo root is one level up from app/.
_VERSION_FILE = pathlib.Path(__file__).resolve().parents[1] / "VERSION"

#: Fallback when the file is missing (a partial checkout, a stripped image).
#: Deliberately not a plausible-looking number: a wrong version that looks
#: real is worse than an obvious "we do not know".
UNKNOWN = "unknown"


def _read() -> str:
    try:
        value = _VERSION_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return UNKNOWN
    return value or UNKNOWN


APP_VERSION: str = _read()


def app_version() -> str:
    """The running application version, e.g. ``1.2.2``."""
    return APP_VERSION


__all__ = ["APP_VERSION", "UNKNOWN", "app_version"]
