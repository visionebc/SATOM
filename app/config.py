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
    # NOTE: this SQLite default is a DEV/TEST fallback only. Production
    # (ProductionConfig) requires the env var and refuses this fallback —
    # see get_config(). (2026-06-30)
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
    # Flask-Limiter 3.x reads RATELIMIT_STORAGE_URI (the old *_URL key is
    # ignored, silently falling back to per-worker memory://). Production sets
    # redis:// in .env so the 4 gunicorn workers share ONE bucket set and
    # counters survive restarts; memory:// stays the dev/test fallback.
    RATELIMIT_STORAGE_URI: str = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    # Firmware/backup uploads — cap so a runaway upload 413s instead of
    # OOMing a gunicorn worker. Real FortiWeb .out images are ~100-500 MB.
    MAX_CONTENT_LENGTH: int = int(os.environ.get("MAX_UPLOAD_MB", "600")) * 1024 * 1024


class DevelopmentConfig(Config):
    DEBUG: bool = True
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "SQLALCHEMY_DATABASE_URI",
        "sqlite:////tmp/fmw/data/dev.db",
    )
    SESSION_COOKIE_SECURE: bool = False


class ProductionConfig(Config):
    DEBUG: bool = False
    # Static assets get a real max-age so the edge nginx (and browsers) can
    # cache them instead of hitting a gunicorn worker per CSS/JS request.
    # Flask still honours conditional requests (ETag/Last-Modified), so a
    # changed file revalidates within the day.
    SEND_FILE_MAX_AGE_DEFAULT: int = 86400


_config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config() -> type[Config]:
    env = os.environ.get("FLASK_ENV", "development")
    cfg = _config_map.get(env, DevelopmentConfig)
    # Production MUST use the configured (Postgres) database. Never silently
    # fall back to the SQLite default in Config — a process started without the
    # systemd EnvironmentFile used to drift onto data/fortinet.db, splitting
    # state from the real PG DB (the scheduler did exactly this). Fail loud
    # instead so the misconfig is caught at boot, not after silent divergence.
    # (2026-06-30)
    if cfg is ProductionConfig and not os.environ.get("SQLALCHEMY_DATABASE_URI"):
        raise RuntimeError(
            "SQLALCHEMY_DATABASE_URI is required in production "
            "(set it in /opt/fortinet-manager/.env); "
            "refusing to fall back to SQLite."
        )
    return cfg
