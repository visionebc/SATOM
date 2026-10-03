"""Idle session lock — Settings -> General -> "Session Lock (minutes)".

Until 2026-10-03 the setting was saved and displayed but nothing read it: a
signed-in browser stayed signed in for Flask's default 31 days. It is now an
IDLE timeout. Every authenticated request stamps ``session['_last_seen']``
(epoch seconds); a request that arrives more than N minutes after the last
stamp signs the user out and sends them to the login page (JSON 401 for
script callers).

Background polls must NOT count as activity, or a tab left open would stay
"active" forever: the bell polls /notifications/unread every 30 s, the job dock
polls /jobs/, edit locks heartbeat, and many pages refresh a panel on a timer.
A request is treated as background when it is

* one of the known timer-polled endpoints (:data:`POLL_ENDPOINTS`), or
* a script GET/HEAD: ``X-Requested-With: XMLHttpRequest`` or a fetch()
  (``Sec-Fetch-Mode`` other than ``navigate``) that is not a Turbo Drive visit
  (Turbo marks its visits with ``X-Turbo-Request-Id``).

Background requests are still checked against the timeout -- they just do not
extend it. Page loads, Turbo visits and every POST/PUT/PATCH/DELETE do.

Bearer-token API requests carry no session and are never touched.
"""
from __future__ import annotations

import time

from flask import flash, jsonify, redirect, request, session, url_for
from flask_login import current_user, logout_user

#: Session key holding the epoch of the last user activity.
LAST_SEEN_KEY = "_last_seen"

#: Re-stamp at most this often (seconds) so the cookie is not rewritten on
#: every single request.
STAMP_GRANULARITY = 15

#: Endpoints the front-end calls on a timer (static/js and base.html).
POLL_ENDPOINTS = frozenset({
    "static", "healthz", "healthz_primary", "healthz_backups",
    "healthz_cert_renewals", "service_worker", "upload_worker", "updiag",
    "notifications.unread",          # top-bar bell (base.html, every 30 s)
    "jobs.index", "jobs.get",        # job dock + per-job toast (jobs.js)
    "jobs.response",
    "locks.heartbeat",               # edit-lock heartbeat (lock.js, 30 s)
    "api.list_appliances",           # status badges (main.js StatusPoller)
})

#: Endpoints never subject to the lock (signing in/out must always work).
EXEMPT_ENDPOINTS = frozenset({"auth.login", "auth.logout", "static"})

_TTL = 30.0
_cache: dict[str, float] = {"at": 0.0, "minutes": 0.0, "app": 0.0}


def timeout_minutes() -> int:
    """The configured idle timeout in minutes (cached briefly per process
    and per app object)."""
    from flask import current_app
    now = time.monotonic()
    app_id = float(id(current_app._get_current_object()))
    if now - _cache["at"] < _TTL and _cache["minutes"] and _cache["app"] == app_id:
        return int(_cache["minutes"])
    try:
        from ..services import settings_store as store
        minutes = int(store.general()["session_timeout"])
    except Exception:  # noqa: BLE001 - a broken settings row must not lock everyone out
        minutes = 60
    minutes = max(5, min(1440, minutes))
    _cache.update(at=now, minutes=float(minutes), app=app_id)
    return minutes


def invalidate_cache() -> None:
    """Forget the cached timeout (called when General settings are saved)."""
    _cache.update(at=0.0, minutes=0.0)


def is_background_request() -> bool:
    if (request.endpoint or "") in POLL_ENDPOINTS:
        return True
    if request.method not in ("GET", "HEAD"):
        return False
    if request.headers.get("X-Turbo-Request-Id"):
        return False
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    mode = request.headers.get("Sec-Fetch-Mode")
    return bool(mode) and mode != "navigate"


def _wants_json() -> bool:
    return (request.is_json
            or "application/json" in (request.headers.get("Accept") or "")
            or request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or (request.headers.get("Sec-Fetch-Mode") not in (None, "navigate")
                and not request.headers.get("X-Turbo-Request-Id")))


def _enforce():
    if not getattr(current_user, "is_authenticated", False):
        return None
    if (request.headers.get("Authorization") or "").lower().startswith("bearer "):
        return None
    if (request.endpoint or "") in EXEMPT_ENDPOINTS:
        return None
    now = int(time.time())
    last = session.get(LAST_SEEN_KEY)
    minutes = timeout_minutes()
    if isinstance(last, (int, float)) and now - last > minutes * 60:
        try:
            from ..services.audit import log_action
            log_action("session.idle_lock", target=current_user.username,
                       extra={"idle_minutes": int((now - last) // 60),
                              "timeout_minutes": minutes})
        except Exception:  # noqa: BLE001 - audit is best-effort
            pass
        logout_user()
        session.pop(LAST_SEEN_KEY, None)
        msg = f"Your session was locked after {minutes} minutes of inactivity."
        if _wants_json():
            return jsonify(ok=False, error=msg, session_locked=True), 401
        flash(msg, "warning")
        return redirect(url_for("auth.login", next=request.full_path.rstrip("?")
                                if request.method == "GET" else None))
    if not isinstance(last, (int, float)) or (
            not is_background_request() and now - last >= STAMP_GRANULARITY):
        session[LAST_SEEN_KEY] = now
    return None


def init_app(app) -> None:
    """Register the idle-lock check. Call before the other before_request gates
    so a locked session never reaches them."""
    app.before_request(_enforce)
