"""Fernet-based symmetric encryption for credential storage."""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def _get_fernet():
    from cryptography.fernet import Fernet

    key = os.environ.get("FERNET_KEY")
    if not key:
        # An ephemeral key is allowed ONLY under test. In any real run a missing
        # FERNET_KEY would silently generate a DIFFERENT key per gunicorn worker
        # and make every stored appliance credential undecryptable after a
        # restart, so refuse to start instead.
        if os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("FORTINET_ALLOW_EPHEMERAL_KEY"):
            key = Fernet.generate_key().decode()
            os.environ["FERNET_KEY"] = key
            logger.warning("FERNET_KEY not set — using an ephemeral key (test mode only).")
        else:
            raise RuntimeError(
                "FERNET_KEY is not set. Refusing to start with an ephemeral key: "
                "stored appliance credentials would be undecryptable and would "
                "diverge across gunicorn workers. Set FERNET_KEY in the environment "
                "or .env file (set FORTINET_ALLOW_EPHEMERAL_KEY=1 only for throwaway runs)."
            )
    raw = key.encode() if isinstance(key, str) else key
    return Fernet(raw)


def encrypt(plaintext: str) -> str:
    """Encrypt *plaintext* and return a URL-safe base64 token string."""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a Fernet token string and return the original plaintext."""
    return _get_fernet().decrypt(ciphertext.encode()).decode()
