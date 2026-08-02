"""Flask extension singletons — imported by app factory and blueprints."""
from __future__ import annotations

from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter


def real_client_ip() -> str:
    """Rate-limit / access key = the REAL client IP.

    ``request.remote_addr`` is the reverse proxy (always the fleet nginx here),
    so keying limits on it would put every user in ONE bucket — 5 failed logins
    would lock out the whole fleet. X-Forwarded-For is only honoured when the
    direct peer is a trusted proxy (``TRUSTED_PROXIES`` env), and we take the
    last (proxy-appended, non-forgeable) hop so a direct client can't spoof it.
    Falls back to the peer IP — i.e. the old behaviour — if anything is off.
    """
    import os
    from flask import request
    # Loopback only by default. A deployment-specific proxy address must be
    # configured (TRUSTED_PROXIES env, set by the installer); shipping one
    # hard-codes somebody else's network into the trust boundary, and on any
    # site whose LAN overlaps that range it hands an unrelated host the right
    # to forge the client IP this function feeds to rate limiting and audit.
    raw = os.environ.get("TRUSTED_PROXIES", "127.0.0.1,::1")
    trusted = {p.strip() for p in raw.split(",") if p.strip()}
    peer = request.remote_addr or ""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff and peer in trusted:
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        if hops:
            return hops[-1]
    return peer


db: SQLAlchemy = SQLAlchemy()
migrate: Migrate = Migrate()
login_manager: LoginManager = LoginManager()
csrf: CSRFProtect = CSRFProtect()
limiter: Limiter = Limiter(key_func=real_client_ip)
