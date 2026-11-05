"""Secrets at rest: Fernet with the key from the environment file."""
from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


def _f() -> Fernet:
    key = current_app.config.get("FERNET_KEY") or ""
    if not key:
        raise RuntimeError("FERNET_KEY is not set")
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt(plain: str) -> str:
    return _f().encrypt(plain.encode()).decode() if plain else ""


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _f().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("stored secret cannot be decrypted with this FERNET_KEY") from exc
