"""SATOM Observability (lab) — the satom-observability application, mounted in
SATOM at ``/observability/`` (operator request 2026-11-05: "exactly what we
have in the other project, as a separate URL, nothing of SATOM modified; the
inventory and everything comes from the SATOM database").

This package is the satom-observability code (repo ``satom-dev/satom-observability``
at 0.3.0, ``d9503bc``) with four differences, all in :mod:`.satom_bridge` and
the mount:

* it is served by SATOM's view ``observability_lab.proxy`` (app/views/
  observability_lab.py), so SATOM's login, permissions, ADOM gate and
  hostguard run first; the signed-in SATOM user is handed over in the WSGI
  environ (no second login, no user table here);
* the sources ARE SATOM's appliances (synced from ``appliances``, the secret
  read from SATOM at connect time and never copied);
* a connector reads the configuration from SATOM's device cache and goes to
  the device (GET only, SATOM's credential) only for what SATOM does not hold:
  live state, counters, back-end health;
* its tables live in their own Postgres schema ``observability`` of SATOM's
  database (not in SATOM's schema, no Alembic revision of SATOM), and the
  numeric history goes to SATOM's VictoriaMetrics under the ``obs_*`` names.

Read-only towards the devices by construction: :mod:`.http_ro` refuses any
method but GET/HEAD before a byte leaves the server.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from flask import Flask, g, request

from .extensions import csrf, db, login_manager

VERSION = "0.3.0-satom"
SCHEMA = "observability"


def _derive(secret: str, purpose: str) -> bytes:
    return hmac.new((secret or "").encode(), purpose.encode(), hashlib.sha256).digest()


def _db_config(satom_uri: str) -> tuple[str, dict]:
    """Same database as SATOM, own schema. SQLite (tests) gets its own file."""
    if satom_uri.startswith("sqlite"):
        if satom_uri in ("sqlite://", "sqlite:///:memory:"):
            return "sqlite://", {}
        return satom_uri + "-observability.db", {}
    return satom_uri, {"pool_pre_ping": True, "pool_size": 2, "max_overflow": 2,
                       "connect_args": {"options": "-csearch_path=%s" % SCHEMA}}


def create_app(satom_app: Flask) -> Flask:
    app = Flask(__name__)
    satom_key = satom_app.config.get("SECRET_KEY") or ""
    uri, engine_opts = _db_config(satom_app.config.get("SQLALCHEMY_DATABASE_URI", "sqlite://"))
    app.config.update(
        SECRET_KEY=_derive(satom_key, "satom-observability-lab:session").hex(),
        FERNET_KEY=base64.urlsafe_b64encode(_derive(satom_key, "satom-observability-lab:fernet")).decode(),
        SQLALCHEMY_DATABASE_URI=uri,
        SQLALCHEMY_ENGINE_OPTIONS=engine_opts,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        # SATOM's own store (loopback, no auth): obs_* series beside satom_*.
        METRICS_URL=(satom_app.config["OBS_METRICS_URL"] if "OBS_METRICS_URL" in satom_app.config
                     else _satom_vm_url()),
        # Own cookie, scoped to the mount: never touches SATOM's session.
        SESSION_COOKIE_NAME="satom_obs_session",
        SESSION_COOKIE_PATH="/observability",
        SESSION_COOKIE_SECURE=bool(satom_app.config.get("SESSION_COOKIE_SECURE", True)),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        WTF_CSRF_TIME_LIMIT=None,
        WTF_CSRF_SSL_STRICT=bool(satom_app.config.get("WTF_CSRF_SSL_STRICT", True)),
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
        TESTING=bool(satom_app.config.get("TESTING")),
        SATOM_APP=satom_app,
        OBS_COLLECTOR=bool(satom_app.config.get("OBS_COLLECTOR", not satom_app.config.get("TESTING"))),
    )

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    from . import models  # noqa: F401 — register tables
    from . import satom_bridge
    from .views import api, auth, diagrams, jobs, main, sources
    for bp in (auth.bp, main.bp, diagrams.bp, sources.bp, jobs.bp, api.bp):
        app.register_blueprint(bp)
    csrf.exempt(api.health)

    with app.app_context():
        satom_bridge.ensure_schema()

    @app.before_request
    def _nonce():
        g.csp_nonce = secrets.token_urlsafe(16)
        satom_bridge.on_request(app)

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'nonce-%s'; frame-ancestors 'none'; base-uri 'self'; "
            "form-action 'self'" % getattr(g, "csp_nonce", ""))
        return resp

    @app.context_processor
    def _ctx():
        return {"app_version": VERSION, "csp_nonce": getattr(g, "csp_nonce", ""),
                "satom_root": request.environ.get("satom.root", "")}

    # Error pages with a way out, never the bare Werkzeug "Internal Server Error".
    from flask import render_template
    from werkzeug.exceptions import HTTPException

    ERRORS = {
        403: ("shield-lock", "Not allowed", "Your account cannot do this. Ask an administrator."),
        404: ("signpost-split", "Not found", "This page or object does not exist (any more)."),
        405: ("slash-circle", "Not allowed here", "That action is not available on this page."),
        413: ("file-earmark-x", "Too large", "The upload is bigger than 8 MB."),
    }

    def _is_json() -> bool:
        return request.path.startswith("/api/") or request.path.endswith(("/overlay", "/layout", "/save"))

    @app.errorhandler(HTTPException)
    def _http_error(exc):
        if _is_json():
            return {"ok": False, "error": exc.description, "code": exc.code}, exc.code
        icon, title, text = ERRORS.get(exc.code, ("exclamation-circle", exc.name, exc.description))
        return render_template("error.html", code=exc.code, icon=icon, title=title, text=text, ref=""), exc.code

    @app.errorhandler(Exception)
    def _server_error(exc):
        if isinstance(exc, HTTPException):
            return _http_error(exc)
        ref = secrets.token_hex(4)
        app.logger.exception("observability-lab unhandled error ref=%s on %s %s", ref, request.method, request.path)
        try:
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        if _is_json():
            return {"ok": False, "error": "internal error", "ref": ref}, 500
        return render_template("error.html", code=500, icon="bug", title="Something went wrong on our side",
                               text="The error was logged. Try again; if it keeps happening, send the reference below.",
                               ref=ref), 500

    return app


def _satom_vm_url() -> str:
    try:
        from ..services import vm_store
        return vm_store.base_url()
    except Exception:  # noqa: BLE001
        return "http://127.0.0.1:8428"
