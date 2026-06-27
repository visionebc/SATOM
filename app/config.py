"""Flask configuration classes."""
from __future__ import annotations

import os
import secrets
from pathlib import Path


def _ensure_secret_key() -> str:
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    key = secrets.token_hex(32)
    _append_env("SECRET_KEY", key)
    return key


def _ensure_fernet_key() -> str:
    key = os.environ.get("FERNET_KEY")
    if key:
        return key
    from cryptography.fernet import Fernet
    key = Fernet.generate_key().decode()
    _append_env("FERNET_KEY", key)
    return key


def _append_env(var: str, value: str) -> None:
    # NOTE (2026-06-27): intentionally does NOT write to .env anymore.
    # Standalone/CLI/test runs that import config without the env loaded used
    # to append a fresh SECRET_KEY/FERNET_KEY here on every start, polluting
    # .env with duplicate keys and risking session/Fernet breakage. Now we
    # only set the value in-process; .env stays the single source of truth.
    os.environ[var] = value


class Config:
    SECRET_KEY: str = _ensure_secret_key()
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "SQLALCHEMY_DATABASE_URI",
        "sqlite:////opt/fortinet-manager/data/fortinet.db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    FERNET_KEY: str = _ensure_fernet_key()
    WTF_CSRF_TIME_LIMIT: int = 3600
    RATELIMIT_STORAGE_URL: str = "memory://"


class DevelopmentConfig(Config):
    DEBUG: bool = True
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "SQLALCHEMY_DATABASE_URI",
        "sqlite:////tmp/fmw/data/dev.db",
    )
    SESSION_COOKIE_SECURE: bool = False


class ProductionConfig(Config):
    DEBUG: bool = False


_config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config() -> type[Config]:
    env = os.environ.get("FLASK_ENV", "development")
    return _config_map.get(env, DevelopmentConfig)
