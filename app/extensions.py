"""Flask extension singletons — imported by app factory and blueprints."""
from __future__ import annotations

from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_babel import Babel


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


#: The one author of the sentence. The flash, the JSON error and the log line
#: all render THIS string, so they cannot drift apart -- two authors of one
#: sentence is how the site footer lost its Docs link.
INSECURE_TRANSPORT_HINT = (
    "This SATOM is served over plain HTTP while its session cookies are marked "
    "Secure, so your browser never returns the session cookie and no password "
    "can be accepted. This is a deployment problem, not a wrong password: put "
    "an HTTPS reverse proxy in front of SATOM (see docs/docker.md, "
    "'TLS is not optional')."
)


def client_scheme() -> str:
    """The scheme the BROWSER used -- not the one this process was spoken to.

    A reverse proxy that terminates TLS speaks plain HTTP to the app, so
    ``request.scheme`` reads ``http`` on a perfectly healthy deployment
    (measured on satom-node-1-dock, whose HAProxy backend is plain HTTP). The
    only witness to the client's real scheme is ``X-Forwarded-Proto``.

    This reads that header WITHOUT consulting ``TRUSTED_PROXIES``, on purpose,
    and that is safe because of what the answer is used for: it gates a
    DIAGNOSTIC, never an authorisation, a cookie flag or an audit actor. A
    forged ``X-Forwarded-Proto: https`` can only suppress a warning aimed at
    whoever forged it. Requiring the trust list instead would silence the
    diagnostic on exactly the deployments it exists to describe -- the ones
    whose proxy configuration is wrong.
    """
    from flask import request

    xfp = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
    return xfp or request.scheme


def insecure_session_transport() -> bool:
    """True when this request can NEVER carry a session cookie.

    ``SESSION_COOKIE_SECURE`` instructs the browser to withhold the cookie
    from plain-HTTP origins. Serving the app over HTTP with that flag on
    therefore produces a deployment in which *no* login succeeds with *any*
    password: the POST arrives with no session, so there is no CSRF token to
    match, and the CSRF handler bounces back to the login form. The account is
    not even locked out, because the password is never compared.

    Nothing about that looks broken -- unit active, ``/healthz`` 200, login
    page rendering -- which is why it has to be stated rather than inferred.
    It is how the first container development node shipped (2026-08-31).
    """
    from flask import current_app

    if not current_app.config.get("SESSION_COOKIE_SECURE"):
        return False
    return client_scheme() != "https"


db: SQLAlchemy = SQLAlchemy()
migrate: Migrate = Migrate()
login_manager: LoginManager = LoginManager()
csrf: CSRFProtect = CSRFProtect()
limiter: Limiter = Limiter(key_func=real_client_ip)
# Locale selector is wired in the factory (app/__init__.py), not here:
# it has to read the signed-in user's stored preference, and this module
# must stay importable without the ORM.
babel: Babel = Babel()
