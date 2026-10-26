"""Flask configuration classes."""
from __future__ import annotations

import os
import secrets
from datetime import timedelta
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


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name) or default)
    except ValueError:
        return default


def _engine_options(uri: str) -> dict:
    """SQLAlchemy engine options, sized for the gthread web workers.

    ``pool_size`` + ``max_overflow`` per PROCESS: 4 web workers x (10 + 5) +
    the scheduler stays under Postgres' default max_connections (100).
    ``pool_timeout`` is short on purpose: a request that cannot get a
    connection in 10 s answers an error instead of holding a thread for the
    default 30 s while more requests queue behind it.

    ``SATOM_DB_STATEMENT_TIMEOUT_MS`` (set by satom.service only -- the web
    processes) caps one SQL statement; ``idle_in_transaction_session_timeout``
    ends a transaction a crashed request left open. Postgres only."""
    opts: dict = {
        # pool_pre_ping: a connection checked out of the pool is validated with
        # a cheap SELECT 1 first, so a Postgres restart / idle-timeout kill
        # never surfaces as a user-facing OperationalError. pool_recycle keeps
        # connections younger than typical firewall/PG idle timeouts.
        "pool_pre_ping": True,
        "pool_recycle": 1800,
    }
    if not uri.startswith("postgresql"):
        return opts
    opts.update(pool_size=_env_int("SATOM_DB_POOL_SIZE", 10),
                max_overflow=_env_int("SATOM_DB_MAX_OVERFLOW", 5),
                pool_timeout=_env_int("SATOM_DB_POOL_TIMEOUT", 10))
    pg = []
    st = _env_int("SATOM_DB_STATEMENT_TIMEOUT_MS", 0)
    if st > 0:
        pg.append("-c statement_timeout=%d" % st)
        pg.append("-c idle_in_transaction_session_timeout=%d" % max(st * 5, 300000))
    if pg:
        opts["connect_args"] = {"options": " ".join(pg)}
    return opts


class Config:
    SECRET_KEY: str = _ensure_secret_key()
    # NOTE: this SQLite default is a DEV/TEST fallback only. Production
    # (ProductionConfig) requires the env var and refuses this fallback —
    # see get_config(). (2026-06-30)
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "SQLALCHEMY_DATABASE_URI",
        "sqlite:////opt/satom/data/fortinet.db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: dict = _engine_options(
        os.environ.get("SQLALCHEMY_DATABASE_URI", ""))
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    # The login form's "remember me" sets Flask-Login's own cookie, which does
    # NOT inherit SESSION_COOKIE_*: left alone it is sent over plain HTTP, has
    # no SameSite and lives 365 days. Keep it as strict as the session cookie.
    REMEMBER_COOKIE_SECURE: bool = True
    REMEMBER_COOKIE_HTTPONLY: bool = True
    REMEMBER_COOKIE_SAMESITE: str = "Lax"
    REMEMBER_COOKIE_DURATION: timedelta = timedelta(days=14)
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
    # Extra host names (comma-separated, e.g. a public alias in front of the
    # node) that absolute links mailed out of a request may use. The node's own
    # names are always accepted; any other Host header -- forgeable on the
    # unauthenticated password-reset form -- is replaced by the node FQDN.
    # Requests are still served for every Host (by-IP probes keep working).
    LINK_HOSTS: list[str] = [
        h.strip().lower() for h in os.environ.get("LINK_HOSTS", "").split(",")
        if h.strip()]


class DevelopmentConfig(Config):
    DEBUG: bool = True
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "SQLALCHEMY_DATABASE_URI",
        "sqlite:////tmp/fmw/data/dev.db",
    )
    SESSION_COOKIE_SECURE: bool = False
    REMEMBER_COOKIE_SECURE: bool = False


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
            "(set it in /opt/satom/.env); "
            "refusing to fall back to SQLite."
        )
    return cfg
