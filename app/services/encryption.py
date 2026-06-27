"""Fernet-based symmetric encryption for credential storage."""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def _get_fernet():
    from cryptography.fernet import Fernet

    key = os.environ.get("FERNET_KEY")
    if not key:
        key = Fernet.generate_key().decode()
        os.environ["FERNET_KEY"] = key
        logger.warning(
            "FERNET_KEY was not set — generated a temporary key for this process. "
            "Persisted credentials cannot be decrypted after restart. "
            "Set FERNET_KEY in your environment or .env file."
        )
    raw = key.encode() if isinstance(key, str) else key
    return Fernet(raw)


def encrypt(plaintext: str) -> str:
    """Encrypt *plaintext* and return a URL-safe base64 token string."""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a Fernet token string and return the original plaintext."""
    return _get_fernet().decrypt(ciphertext.encode()).decode()
