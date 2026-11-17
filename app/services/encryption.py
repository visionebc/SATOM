"""Fernet-based symmetric encryption for credential storage."""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def _get_fernet():
    from cryptography.fernet import Fernet

    from ..config import _ensure_fernet_key, enforce_fernet_key

    # The key policy lives in ONE place (app.config.enforce_fernet_key): an
    # explicit FERNET_KEY is used unchanged; an ephemeral one -- a DIFFERENT
    # key per gunicorn worker, scheduler and reconciler, and a new one after
    # every restart -- is refused in production unless
    # FORTINET_ALLOW_EPHEMERAL_KEY=1, and warned about once elsewhere. Checked
    # here too, not only at startup, so a production-mode process that never
    # went through create_app() cannot encrypt on a throwaway key either.
    if not os.environ.get("FERNET_KEY"):
        _ensure_fernet_key()
    enforce_fernet_key()
    key = os.environ["FERNET_KEY"]
    raw = key.encode() if isinstance(key, str) else key
    return Fernet(raw)


def encrypt(plaintext: str) -> str:
    """Encrypt *plaintext* and return a URL-safe base64 token string."""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a Fernet token string and return the original plaintext."""
    return _get_fernet().decrypt(ciphertext.encode()).decode()
