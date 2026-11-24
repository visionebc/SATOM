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
    # Importing this module must not fail: CLI paths and tools import the
    # package without ever touching encrypted data. So a missing key is still
    # filled in-process here and RECORDED in INVENTED_ENV; whether a process
    # may actually run on it is decided at startup by enforce_fernet_key().
    key = os.environ.get("FERNET_KEY")
    if key:
        return key
    from cryptography.fernet import Fernet
    key = Fernet.generate_key().decode()
    _append_env("FERNET_KEY", key)
    return key


#: Variables this module invented because they were missing from the
#: environment at import time. A caller that loads ``.env`` AFTER importing the
#: package (``python -m app.services.route_audit``) must drop these first, or
#: the invented random SECRET_KEY/FERNET_KEY shadow the real ones.
INVENTED_ENV: set[str] = set()


def _append_env(var: str, value: str) -> None:
    # NOTE (2026-06-27): intentionally does NOT write to .env anymore.
    # Standalone/CLI/test runs that import config without the env loaded used
    # to append a fresh SECRET_KEY/FERNET_KEY here on every start, polluting
    # .env with duplicate keys and risking session/Fernet breakage. Now we
    # only set the value in-process; .env stays the single source of truth.
    os.environ[var] = value
    INVENTED_ENV.add(var)


#: The only way to run a PRODUCTION process on a throwaway key. Must be set
#: explicitly; nothing in the product sets it.
EPHEMERAL_KEY_OVERRIDE = "FORTINET_ALLOW_EPHEMERAL_KEY"

#: One WARNING per process, not one per create_app()/encrypt() call. Kept
#: across importlib.reload() (wsgi.py and route_audit re-evaluate this module).
_ephemeral_warned = globals().get("_ephemeral_warned", False)


def _is_production() -> bool:
    return os.environ.get("FLASK_ENV", "development") == "production"


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def fernet_key_is_ephemeral() -> bool:
    """True when this process has no FERNET_KEY of its own: the key in the
    environment was invented by this module (or there is none at all)."""
    return "FERNET_KEY" in INVENTED_ENV or not os.environ.get("FERNET_KEY")


def enforce_fernet_key(process: str | None = None) -> None:
    """Startup gate for FERNET_KEY -- call it before a process does real work.

    A key invented in-process is a DIFFERENT random key in every gunicorn
    worker, the scheduler and the reconciler, and a new one after every
    restart: a device credential encrypted by one process cannot be read by
    another and is lost at the next restart. So:

    * explicit FERNET_KEY in the environment: used unchanged, nothing logged;
    * production (FLASK_ENV=production) without it: RuntimeError naming the
      variable -- the process refuses to start -- unless
      FORTINET_ALLOW_EPHEMERAL_KEY=1 is set, then it starts and logs a loud
      WARNING once;
    * development / testing without it: starts on the ephemeral key and logs
      a WARNING once.
    """
    global _ephemeral_warned
    if not fernet_key_is_ephemeral():
        return
    import logging
    import sys
    who = process or os.path.basename(sys.argv[0] or "") or "satom"
    if _is_production() and not _truthy(os.environ.get(EPHEMERAL_KEY_OVERRIDE)):
        raise RuntimeError(
            "FERNET_KEY is not set (process: %s). SATOM refuses to start in "
            "production without it: an ephemeral key differs in every process "
            "and at every restart, so stored device credentials would become "
            "unreadable. Set FERNET_KEY in /opt/satom/.env (the systemd "
            "EnvironmentFile) -- the SAME key on every process and on both HA "
            "nodes -- or set %s=1 to run a throwaway node on an ephemeral key."
            % (who, EPHEMERAL_KEY_OVERRIDE))
    if _ephemeral_warned:
        return
    _ephemeral_warned = True
    if _is_production():
        msg = ("FERNET_KEY is not set and %s=1: process %s (pid %d) runs on an "
               "EPHEMERAL key. Every process has its own key and it changes at "
               "every restart -- device credentials saved now will NOT be "
               "readable by the other processes or after a restart. Never use "
               "this on a node that keeps data."
               % (EPHEMERAL_KEY_OVERRIDE, who, os.getpid()))
    else:
        msg = ("FERNET_KEY is not set: process %s (pid %d) runs on an ephemeral "
               "key (development/testing only). Credentials it encrypts are not "
               "readable by other processes or after a restart."
               % (who, os.getpid()))
    logging.getLogger("app.config").warning(msg)


#: SECRET_KEY has its OWN switch: allowing a throwaway session key must never
#: silently allow a throwaway credential key, and the reverse.
SECRET_KEY_OVERRIDE = "FORTINET_ALLOW_EPHEMERAL_SECRET_KEY"

_secret_warned = globals().get("_secret_warned", False)


def secret_key_is_ephemeral() -> bool:
    """True when this process has no SECRET_KEY of its own."""
    return "SECRET_KEY" in INVENTED_ENV or not os.environ.get("SECRET_KEY")


def enforce_secret_key(process: str | None = None) -> None:
    """Startup gate for SECRET_KEY -- the same rule as enforce_fernet_key().

    An invented SECRET_KEY differs in every gunicorn worker and changes at
    every restart: a session, CSRF token, password-reset link or 2FA recovery
    token signed by one worker is rejected by the next, so users are logged
    out at random and forms fail as "expired". Explicit key: used unchanged.
    Production without it: RuntimeError naming the variable, unless
    FORTINET_ALLOW_EPHEMERAL_SECRET_KEY=1 (then one loud WARNING per process).
    Development/testing: one WARNING per process.
    """
    global _secret_warned
    if not secret_key_is_ephemeral():
        return
    import logging
    import sys
    who = process or os.path.basename(sys.argv[0] or "") or "satom"
    if _is_production() and not _truthy(os.environ.get(SECRET_KEY_OVERRIDE)):
        raise RuntimeError(
            "SECRET_KEY is not set (process: %s). SATOM refuses to start in "
            "production without it: an ephemeral key differs in every process "
            "and at every restart, so sessions, CSRF tokens and password-reset "
            "links signed by one worker would be rejected by the others. Set "
            "SECRET_KEY in /opt/satom/.env (the systemd EnvironmentFile) -- the "
            "SAME key on every process and on both HA nodes -- or set %s=1 to "
            "run a throwaway node on an ephemeral key."
            % (who, SECRET_KEY_OVERRIDE))
    if _secret_warned:
        return
    _secret_warned = True
    if _is_production():
        msg = ("SECRET_KEY is not set and %s=1: process %s (pid %d) runs on an "
               "EPHEMERAL session key. Every process has its own and it changes "
               "at every restart -- sessions and CSRF tokens will fail across "
               "workers. Never use this on a node people log in to."
               % (SECRET_KEY_OVERRIDE, who, os.getpid()))
    else:
        msg = ("SECRET_KEY is not set: process %s (pid %d) runs on an ephemeral "
               "session key (development/testing only). Sessions do not survive "
               "a restart or cross processes." % (who, os.getpid()))
    logging.getLogger("app.config").warning(msg)


def enforce_startup_keys(process: str | None = None) -> None:
    """Both startup gates, in one call: what create_app(), the scheduler and
    the reconciler run before doing any work."""
    enforce_fernet_key(process)
    enforce_secret_key(process)


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
