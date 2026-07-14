"""Centralised error handling, logging, and correlation IDs.

ONE place that:
  * configures a rotating file log (``data/logs/ofortmaut.log``),
  * mints a short **error ID** for every unexpected failure,
  * logs the full traceback tagged with that ID, and
  * shows the SAME ID to the user (HTML page or JSON) so a report can be
    matched to its log line with a single grep::

        grep <ERROR_ID> /opt/ofortmaut/data/logs/ofortmaut.log

The ID is the contract between the user and the operator: the user sees
"Error ID: A1B2C3D4", the operator greps that exact string and lands on the
matching traceback. (2026-06-30)
"""
from __future__ import annotations

import logging
import os
import secrets
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, render_template, request

logger = logging.getLogger("fortinet")


# ---------------------------------------------------------------------------
# Correlation IDs
# ---------------------------------------------------------------------------
def new_error_id() -> str:
    """A short, copy-friendly, case-stable error ID (8 hex chars)."""
    return secrets.token_hex(4).upper()


def _request_context() -> str:
    try:
        return f"{request.method} {request.path}"
    except Exception:  # outside an app/request context
        return "<no-request>"


from collections import deque as _deque

_AUDITED_ERROR_IDS = _deque(maxlen=512)


def _audit_error(error_id: str, exc: BaseException, where: str) -> None:
    """Best-effort: record one ``ERROR`` row in the audit log for this failure
    so a 500 (with its correlation ID) shows up in the Audit Log UI without
    SSHing to the log file. Deduped by error_id (the same failure can be logged
    twice — service_call + the global handler reuse one ID). NEVER raises."""
    if not error_id or error_id in _AUDITED_ERROR_IDS:
        return
    try:
        from flask import request, has_request_context
        from flask_login import current_user
        from .extensions import db
        from .models import AuditLog

        try:
            user_id = current_user.id if current_user.is_authenticated else None
            username = (current_user.username
                        if current_user.is_authenticated else "anonymous")
        except Exception:  # noqa: BLE001
            user_id, username = None, "system"
        try:
            ip = request.remote_addr if has_request_context() else None
        except Exception:  # noqa: BLE001
            ip = None

        extra = {
            "error_id": error_id,
            "exc": type(exc).__name__,
            "message": str(exc)[:500],
        }
        # The failed request may have poisoned the DB session — clear it first.
        try:
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        row = AuditLog(
            user_id=user_id, username=username, action="ERROR",
            target=(where or "")[:256], extra=str(extra), ip_address=ip,
        )
        db.session.add(row)
        db.session.commit()
        _AUDITED_ERROR_IDS.append(error_id)
    except Exception:  # noqa: BLE001 — auditing an error must never raise
        try:
            from .extensions import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass


def log_exception(exc: BaseException, *, context: str = "",
                  error_id: str | None = None) -> str:
    """Log ``exc`` with a full traceback tagged by an error ID.

    Returns the error ID so the caller can surface it to the user. If the
    exception already carries an ``error_id`` (e.g. a re-raised
    :class:`ServiceError`) it is reused so one failure has exactly one ID and
    one log line.
    """
    eid = error_id or getattr(exc, "error_id", None) or new_error_id()
    where = context or _request_context()
    logger.error("[%s] %s :: %s: %s", eid, where,
                 type(exc).__name__, exc, exc_info=exc)
    _audit_error(eid, exc, where)
    return eid


# ---------------------------------------------------------------------------
# Service-layer wrapper
# ---------------------------------------------------------------------------
class ServiceError(Exception):
    """A failure in the service layer, ALREADY logged and carrying its ID.

    Routes can catch this to flash a friendly message with ``error_id``; if it
    bubbles up to the global handler instead, that handler reuses the same ID
    rather than minting (and logging) a second one.
    """

    def __init__(self, message: str, *, error_id: str,
                 cause: BaseException | None = None):
        super().__init__(message)
        self.error_id = error_id
        self.user_message = message
        if cause is not None:
            self.__cause__ = cause


def service_call(fn, *args, context: str = "",
                 user_message: str | None = None, **kwargs):
    """Call a service-layer function, converting any failure into a logged
    :class:`ServiceError` carrying a correlation ID::

        from ..errors import service_call
        run = service_call(device_sync.sync_device, appl,
                           context="workspace.refresh",
                           user_message="Refresh failed")

    A :class:`ServiceError` raised inside ``fn`` passes through untouched (it
    is already logged with an ID).
    """
    try:
        return fn(*args, **kwargs)
    except ServiceError:
        raise
    except Exception as exc:  # noqa: BLE001
        eid = log_exception(exc, context=context or getattr(fn, "__name__", "service"))
        raise ServiceError(user_message or f"{type(exc).__name__}: {exc}",
                           error_id=eid, cause=exc) from exc


# ---------------------------------------------------------------------------
# Route-level helpers (log + surface the ID)
# ---------------------------------------------------------------------------
def flash_error(exc: BaseException, message: str, *, context: str = "",
                category: str = "danger") -> str:
    """Log ``exc`` with an ID and flash ``message`` + that ID to the user.
    Returns the error ID. Use in HTML routes that catch-and-flash."""
    from flask import flash
    eid = log_exception(exc, context=context)
    flash(f"{message} (Error ID: {eid})", category)
    return eid


def json_error(exc: BaseException, message: str, *, status: int = 500,
               context: str = ""):
    """Log ``exc`` and return a JSON error tuple carrying the ID.
    Use in fetch/XHR routes that return JSON."""
    eid = log_exception(exc, context=context)
    return jsonify(ok=False, error=message, error_id=eid), status


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
def configure_logging(app: Flask) -> None:
    """Attach a rotating file handler so every error_id is greppable on disk.

    Never blocks boot: any failure here is swallowed (logging is best-effort).
    Idempotent across create_app() calls and the reloader.
    """
    try:
        log_dir = os.path.abspath(
            os.path.join(app.root_path, os.pardir, "data", "logs"))
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "ofortmaut.log")
    except OSError:
        return

    if any(getattr(h, "_fortinet_file", False) for h in logger.handlers):
        return  # already configured

    handler = RotatingFileHandler(
        log_path, maxBytes=5 * 1024 * 1024, backupCount=5,
        encoding="utf-8", delay=True)
    handler._fortinet_file = True  # type: ignore[attr-defined]
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"))
    handler.setLevel(logging.INFO)

    # Our own "fortinet" channel (error IDs land here)...
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    # ...plus every "app.*" module logger (directory_auth, encryption, factory).
    app_logger = logging.getLogger("app")
    app_logger.addHandler(handler)
    app_logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Global error handlers
# ---------------------------------------------------------------------------
def _wants_json() -> bool:
    try:
        return bool(
            request.is_json
            or "application/json" in (request.headers.get("Accept") or "")
            or request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or (request.path or "").startswith("/api/"))
    except Exception:
        return False


def _safe_render(template: str, *, code: int, error_id: str | None = None) -> str:
    """Render a themed error page; fall back to minimal inline HTML if even the
    base template render fails (so the error_id always reaches the user)."""
    try:
        return render_template(template, error_id=error_id, code=code)
    except Exception:  # noqa: BLE001 — secondary failure, stay minimal
        ref = (f'<p>Reference ID: <code style="color:#fbbf24">{error_id}</code></p>'
               if error_id else "")
        return (
            '<!doctype html><meta charset="utf-8">'
            f'<title>Error {code}</title>'
            '<body style="font-family:system-ui,sans-serif;background:#080d1a;'
            'color:#e2e8f0;padding:3rem;text-align:center">'
            f'<h1 style="font-size:3rem;margin:0">{code}</h1>'
            '<p>An error occurred while processing your request.</p>'
            f'{ref}'
            '<p><a style="color:#3b82f6" href="/">Return home</a></p></body>')


def register_error_handlers(app: Flask) -> None:
    from werkzeug.exceptions import HTTPException

    @app.errorhandler(403)
    def _forbidden(exc):  # noqa: ANN001
        # Security event: record every authorization denial (permission gate,
        # access allow-list, IP allow-list) so probing / privilege-escalation
        # attempts are visible in the log without extra instrumentation.
        try:
            from flask_login import current_user
            who = getattr(current_user, "username", None) or "anonymous"
            ip = (request.headers.get("X-Forwarded-For", "").split(",")[-1].strip()
                  or request.remote_addr or "-")
            logger.warning("FORBIDDEN user=%s ip=%s %s", who, ip, _request_context())
        except Exception:  # noqa: BLE001 — logging must never turn a 403 into a 500
            pass
        if _wants_json():
            return jsonify(ok=False, error="Forbidden"), 403
        return _safe_render("errors/403.html", code=403), 403

    @app.errorhandler(404)
    def _not_found(exc):  # noqa: ANN001
        if _wants_json():
            return jsonify(ok=False, error="Not found"), 404
        return _safe_render("errors/404.html", code=404), 404

    @app.errorhandler(500)
    @app.errorhandler(Exception)
    def _internal(exc):  # noqa: ANN001
        # Pass through other HTTP errors (400/401/405/…) — they are not 500s
        # and carry their own meaning; only true server failures get an ID.
        if isinstance(exc, HTTPException) and exc.code not in (500, None):
            return exc
        eid = log_exception(exc)
        if _wants_json():
            return jsonify(ok=False,
                           error="An unexpected error occurred.",
                           error_id=eid), 500
        return _safe_render("errors/500.html", code=500, error_id=eid), 500


# ---------------------------------------------------------------------------
# Self-test routes (admin-only) — verify the error pipeline end to end
# ---------------------------------------------------------------------------
def register_selftest_routes(app: Flask) -> None:
    """Mount admin-only diagnostic routes that deliberately trigger errors so
    an operator can SEE the themed page + correlation ID in the browser and
    confirm the grep workflow works:

        /__selftest/error   -> raises -> themed 500 page with an Error ID
        /__selftest/404     -> aborts 404 (themed not-found page)
        /__selftest/403     -> aborts 403 (themed forbidden page)

    Gated on USER_MANAGE, so only admins can fire them (never a public DoS).
    """
    from functools import wraps
    from flask import abort
    from flask_login import current_user, login_required

    def _admin_only(fn):
        @wraps(fn)
        @login_required
        def _wrapped(*a, **kw):
            from .models import Permission
            if not current_user.can(Permission.USER_MANAGE):
                abort(403)
            return fn(*a, **kw)
        return _wrapped

    @app.route("/__selftest/error")
    @_admin_only
    def _selftest_error():
        raise RuntimeError(
            "Self-test: deliberate 500 to verify the error page + log ID.")

    @app.route("/__selftest/404")
    @_admin_only
    def _selftest_404():
        abort(404)

    @app.route("/__selftest/403")
    @_admin_only
    def _selftest_403():
        abort(403)
