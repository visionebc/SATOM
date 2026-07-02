"""System Information — real runtime facts for the Settings → General card.

The System Information card used to hardcode "SQLite app_settings", which was
wrong: production runs on PostgreSQL (see ``config.py`` — the SQLite URI is only
a dev/test fallback). This service reports the *actual* runtime instead: the DB
engine + server version behind SQLAlchemy, the Python and OS versions, and the
versions of the libraries the app is built on.

Everything is best-effort and read-only: every probe is guarded so the Settings
page can never 500 because one lookup failed (an unreachable DB just yields
"unknown" for the server version, not an exception).
"""
from __future__ import annotations

import importlib.metadata as _meta
import platform
import sys
from typing import Any

from sqlalchemy import text

from ..models import db

# Curated set of the libraries that actually shape how the app runs, in a
# sensible display order. Missing packages are simply skipped.
_LIBRARIES = (
    "Flask",
    "Werkzeug",
    "Jinja2",
    "SQLAlchemy",
    "Flask-SQLAlchemy",
    "Flask-Login",
    "Flask-WTF",
    "Flask-Limiter",
    "psycopg",
    "gunicorn",
    "paramiko",
    "httpx",
    "cryptography",
    "requests",
    "PyYAML",
)

# Human labels for SQLAlchemy dialect names.
_DIALECT_LABELS = {
    "postgresql": "PostgreSQL",
    "sqlite": "SQLite",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
}


def _os_label() -> str:
    """A friendly OS string, preferring the distro PRETTY_NAME on Linux."""
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.platform()


def _database() -> dict[str, str]:
    """Engine name, server version and (masked) host/db of the bound database."""
    info = {"engine": "unknown", "version": "unknown", "target": ""}
    try:
        dialect = db.engine.dialect.name
        info["engine"] = _DIALECT_LABELS.get(dialect, dialect.title())
    except Exception:
        return info

    # Masked target (never expose the password): host + database name only.
    try:
        url = db.engine.url
        host = url.host or ""
        port = f":{url.port}" if url.port else ""
        info["target"] = f"{host}{port}/{url.database}" if host else (url.database or "")
    except Exception:
        pass

    # Server version — a live query for Postgres, else the dialect's cached tuple.
    try:
        if db.engine.dialect.name == "postgresql":
            raw = db.session.execute(text("SELECT version()")).scalar() or ""
            # "PostgreSQL 15.7 (Debian ...) on x86_64..." -> "15.7"
            parts = raw.split()
            info["version"] = parts[1] if len(parts) > 1 else raw
        elif db.engine.dialect.name == "sqlite":
            info["version"] = db.session.execute(text("SELECT sqlite_version()")).scalar() or "unknown"
        else:
            svi = getattr(db.engine.dialect, "server_version_info", None)
            if svi:
                info["version"] = ".".join(str(p) for p in svi)
    except Exception:
        pass
    return info


def _libraries() -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for name in _LIBRARIES:
        try:
            out.append({"name": name, "version": _meta.version(name)})
        except _meta.PackageNotFoundError:
            continue
        except Exception:
            continue
    return out


def collect() -> dict[str, Any]:
    """All runtime facts for the System Information card."""
    return {
        "python": platform.python_version(),
        "python_impl": platform.python_implementation(),
        "os": _os_label(),
        "machine": platform.machine(),
        "database": _database(),
        "libraries": _libraries(),
    }
