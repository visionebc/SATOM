"""Every action on a device runs as a background job that shows where it is.

The problem this solves: a POST that talks to an appliance used to run inside
the HTTP request. A slow box meant a frozen button, no feedback, and — past
gunicorn's timeout — a dead request with the device possibly half-changed.

How it works (one mechanism for ~230 routes, no per-route rewrite):

1. :func:`install` wraps the POST view of every route in
   :data:`DEVICE_BLUEPRINTS` (minus :data:`EXCLUDED`). A first
   ``before_request`` hook buffers the raw body of those requests, before
   anything parses it.
2. The wrapper creates a job and **replays the request** in a job thread:
   a fresh request context built from a copy of the WSGI environ with the
   buffered body. ``preprocess_request`` runs again there, so login, CSRF,
   the access gate, the ADOM/device gates and the view's own permission
   decorators behave exactly as they would inline.
3. The request waits :data:`INLINE_S` for the job. A fast action finishes
   inside that window and its real response is returned unchanged — the page
   never knows a job was involved. A slow one gets
   ``202 {job_id}`` + ``X-SATOM-Job`` (fetch callers — ``static/js/jobs.js``
   holds the caller's promise, shows the job in the dock and resolves it with
   the final response) or a ``303`` to ``/jobs/<id>/wait`` (classic forms).
4. Progress comes from ``services.job_progress``: every REST call / SSH
   command the action makes is one step. Writes to the same device queue
   behind each other (``Queued — waiting for …``).
5. The final response is stored and replayed by ``GET /jobs/<id>/response``,
   flash messages included.

A job is kept in the ledger only when the action reached a device or outlived
the inline window: a validation error or a pure-database edit that returned
in 40 ms leaves no trace, so the Jobs page lists device work, not every click.

Pass-through (no job): non-POST methods, API-token (Bearer) callers, a
standby node (its data/ is a mirror the primary overwrites every 5 min), the
test suite unless ``DEVICE_JOBS_ENABLED`` is set, and ``SATOM_DEVICE_JOBS=0``.
"""
from __future__ import annotations

import base64
import functools
import io
import json
import os
import re
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

from flask import Response, current_app, jsonify, redirect, request, session

from . import job_progress, jobs

# Blueprints whose POST routes act on a device. Every POST endpoint of these
# blueprints is wrapped unless listed in EXCLUDED (tests/test_device_jobs.py
# fails on a POST endpoint that is in neither list).
DEVICE_BLUEPRINTS = frozenset({
    # appliance lifecycle
    "appliances", "console", "upgrade_flow", "device_provision", "provisioning",
    "backups", "import_backup",
    # FortiWeb configuration
    "workspace", "objedit", "spo_wizard", "web_protection", "server_objects",
    "exceptions", "section_config", "structure", "segments", "signatures",
    "line_profiles", "cert_manager", "templates", "change_requests",
    # FortiADC / FAZ / FAC
    "adc", "adc_api", "faz", "faz_api", "fac_api",
    # investigation tools that query the box
    "attack_search", "txn_trace", "lua_studio", "api_explorer", "analysis",
    "logs", "scout", "reach_batch", "config_compare", "artifacts",
    "container_ops", "sentinel", "deep_monitor", "service_monitor",
})

#: endpoint -> why it stays synchronous.
EXCLUDED = {
    "appliances.upgrade_push": "already a background job (_spawn_flash_job)",
    "appliances.downgrade_push": "already a background job (_spawn_flash_job)",
    "appliances.rediscover_start": "own worker; mirrored into a job by services.rediscovery",
    "appliances.rediscover_stop": "control for a running sweep; must answer at once",
    "backups.create_backup": "already a background job",
    "deep_monitor.run": "already a background job",
    "deep_monitor.discover": "already a background job",
    "service_monitor.run": "already a background job",
    "service_monitor.discover": "already a background job",
    "signatures.sync": "already a background job",
    "console.bundle": "streams a support bundle download",
}

#: Human titles for the most used actions; the rest are derived from the
#: endpoint name ("restore_run" -> "Restore run").
TITLES = {
    "appliances.test_connection": "Test connection",
    "appliances.add_member": "Add HA member",
    "appliances.detach_member": "Detach HA member",
    "appliances.console_run": "Console command",
    "appliances.upgrade_prep_run": "Upgrade preparation",
    "appliances.upgrade_schedule": "Schedule upgrade",
    "appliances.restore_upload": "Upload configuration backup",
    "appliances.restore_fetch": "Fetch configuration backup",
    "appliances.restore_run": "Restore configuration",
    "appliances.failover_preflight": "Failover preflight",
    "appliances.failover_run": "HA failover",
    "appliances.create": "Add appliance",
    "appliances.edit_save": "Save appliance",
}

# Endpoint names that only READ from the device. They never queue behind a
# write and stay cancelable between calls. The safe side wins: a name with ANY
# write word (``ip_list_add``, ``failover_preflight``) is a write, so it takes
# the device lock on its first call and stops being cancelable once it has.
_READ_WORDS = frozenset("""
    preview plan check validate compare diff test search lookup inspect probe
    dry preflight query fetch list show render explain analyze analyse analysis
    discover status refs suggest lint parse simulate export download read view
    trace scan report where used get""".split())
_WRITE_WORDS = frozenset("""
    add create new delete del remove apply push save set update restore import
    sync commit deploy install upload rename move edit enable disable toggle
    clone assign attach detach promote failover schedule revert rollback run
    execute exec write put post bulk purge reset reboot upgrade downgrade
    approve reject submit replace attach unbind bind activate renew issue""".split())

INLINE_S = float(os.environ.get("SATOM_JOB_INLINE_S", "2.0"))
#: Largest response body kept for replay (a config export can be big).
MAX_BODY = 50 * 1024 * 1024

_SESSION_SKIP = frozenset({"_user_id", "_fresh", "_id", "csrf_token",
                           "_csp_nonce", "_remember", "_remember_seconds",
                           "_permanent"})
_DROP_HEADERS = frozenset({"set-cookie", "content-length", "content-security-policy",
                           "transfer-encoding", "connection", "x-frame-options",
                           "x-content-type-options", "x-xss-protection",
                           "referrer-policy", "vary"})

_TL = threading.local()
_events: dict[str, threading.Event] = {}
_inline: dict[str, dict] = {}
_role_cache = {"at": 0.0, "role": ""}


# ── configuration / gates ───────────────────────────────────────────────────
def enabled(app=None) -> bool:
    app = app or current_app
    if os.environ.get("SATOM_DEVICE_JOBS", "1").strip().lower() in ("0", "false", "off", "no"):
        return False
    return bool(app.config.get("DEVICE_JOBS_ENABLED", not app.testing))


def _is_standby() -> bool:
    now = time.monotonic()
    if now - _role_cache["at"] > 30:
        try:
            from .self_update import node_role
            _role_cache["role"] = node_role()
        except Exception:  # noqa: BLE001
            _role_cache["role"] = "unknown"
        _role_cache["at"] = now
    return _role_cache["role"] == "standby"


def _bearer() -> bool:
    return (request.headers.get("Authorization") or "").lower().startswith("bearer ")


def is_read(endpoint: str) -> bool:
    words = set(re.split(r"[_\W]+", endpoint.rsplit(".", 1)[-1].lower())) - {""}
    return bool(words & _READ_WORDS) and not (words & _WRITE_WORDS)


def title_for(endpoint: str) -> str:
    if endpoint in TITLES:
        return TITLES[endpoint]
    name = endpoint.rsplit(".", 1)[-1].replace("_", " ").strip()
    area = endpoint.split(".", 1)[0].replace("_", " ")
    label = (name[:1].upper() + name[1:]) if name else "Device action"
    return f"{label} ({area})" if area and area not in ("appliances",) else label


def wrapped_endpoints(app) -> frozenset:
    return app.extensions.get("device_jobs", frozenset())


# ── install ─────────────────────────────────────────────────────────────────
def install(app) -> frozenset:
    """Wrap the device POST views of ``app``. Idempotent; call once every
    route is registered (end of ``create_app``)."""
    if "device_jobs" in app.extensions:
        return app.extensions["device_jobs"]
    eps: list[str] = []
    for rule in app.url_map.iter_rules():
        if "POST" not in (rule.methods or ()):
            continue
        ep = rule.endpoint
        if "." not in ep or ep in EXCLUDED or ep in eps:
            continue
        if ep.split(".", 1)[0] not in DEVICE_BLUEPRINTS:
            continue
        eps.append(ep)
    for ep in eps:
        app.view_functions[ep] = _wrap(app.view_functions[ep], ep)
    app.before_request_funcs.setdefault(None, []).insert(0, _buffer_body)
    app.extensions["device_jobs"] = frozenset(eps)
    return app.extensions["device_jobs"]


def _buffer_body():
    """Keep the raw body of a wrapped POST before the form parser (CSRF runs
    in an earlier-registered hook) consumes the stream; werkzeug parses the
    form from this cache, and the job thread replays it."""
    if request.method != "POST" or request.endpoint not in wrapped_endpoints(current_app):
        return None
    if not enabled():
        return None
    try:
        request.get_data(cache=True, parse_form_data=False)
    except Exception:  # noqa: BLE001 — an oversized body fails later, normally
        pass
    return None


def _wrap(view, endpoint):
    @functools.wraps(view)
    def device_job_view(*args, **kwargs):
        if (request.method != "POST" or getattr(_TL, "active", False)
                or not enabled() or _bearer() or _is_standby()):
            return view(*args, **kwargs)
        return _launch(view, endpoint)
    device_job_view.__device_job__ = endpoint
    return device_job_view


# ── launch / wait ───────────────────────────────────────────────────────────
def _appliance_from_request() -> tuple[int | None, str]:
    va = request.view_args or {}
    raw = None
    for k in ("appliance_id", "aid", "device_id"):
        if va.get(k) is not None:
            raw = va[k]
            break
    if raw is None and (request.endpoint or "").startswith("appliances.") and va.get("id") is not None:
        raw = va["id"]
    if raw is None:
        src = request.form if request.form else (request.get_json(silent=True) or {})
        if isinstance(src, dict) or hasattr(src, "get"):
            raw = src.get("appliance_id") or src.get("device_id")
    try:
        aid = int(raw) if raw not in (None, "") else None
    except (TypeError, ValueError):
        aid = None
    if aid is None:
        return None, ""
    try:
        from ..extensions import db
        from ..models import Appliance
        a = db.session.get(Appliance, aid)
        return aid, (a.name if a else "")
    except Exception:  # noqa: BLE001
        return aid, ""


def _environ_copy() -> dict:
    env = {k: v for k, v in request.environ.items()
           if k not in ("werkzeug.request", "wsgi.input")}
    body = request.get_data(cache=True)
    env["wsgi.input"] = io.BytesIO(body)
    env["CONTENT_LENGTH"] = str(len(body))
    return env


def _client_mode() -> str:
    """``fetch`` (JS caller, gets 202 + header) or ``navigate`` (a classic
    form submit, gets a redirect to the wait page)."""
    sec = (request.headers.get("Sec-Fetch-Mode") or "").lower()
    if sec == "navigate" or request.headers.get("X-Turbo-Request-Id"):
        return "navigate"
    if sec in ("cors", "same-origin", "no-cors"):
        return "fetch"
    if (request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or request.is_json
            or request.accept_mimetypes.best == "application/json"):
        return "fetch"
    return "navigate"


def _launch(view, endpoint):
    from flask_login import current_user
    app = current_app._get_current_object()
    aid, aname = _appliance_from_request()
    title = title_for(endpoint) + (f" · {aname}" if aname else "")
    exclusive = not is_read(endpoint)
    meta = {"endpoint": endpoint, "path": request.path, "exclusive": exclusive,
            "device_job": True, "steps": [], "device_calls": 0}
    if aid:
        meta.update(appliance_id=aid, appliance=aname)
    job = jobs.create_job("device_action", title,
                          by=getattr(current_user, "username", "") or "",
                          meta=meta, cancelable=True, reversible=False)
    jid = job["id"]
    env = _environ_copy()
    ev = threading.Event()
    _events[jid] = ev
    jobs.run_async(app, jid,
                   lambda a, j: _worker(a, j, view, env, exclusive))
    if ev.wait(INLINE_S):
        cap = _inline.pop(jid, None)
        _events.pop(jid, None)
        if cap is not None:
            st = jobs.get_job(jid) or {}
            if not (st.get("meta") or {}).get("device_calls"):
                _forget(jid)          # never reached a device: no ledger noise
            apply_session(cap.get("session"))
            return build_response(cap)
    return _detached(jid, title)


def _detached(jid: str, title: str):
    jobs.mutate_job(jid, lambda s: s["meta"].update(detached=True))
    if _client_mode() == "fetch":
        r = jsonify({"job_id": jid, "title": title, "status_url": f"/jobs/{jid}",
                     "response_url": f"/jobs/{jid}/response",
                     "message": "Running in the background"})
        r.status_code = 202
        r.headers["X-SATOM-Job"] = jid
        r.headers["X-SATOM-Job-Title"] = quote(title)
        return r
    back = _safe_back(request.referrer)
    url = f"/jobs/{jid}/wait" + (f"?back={quote(back, safe='')}" if back else "")
    return redirect(url, code=303)


def _safe_back(ref: str | None) -> str:
    """Only a same-site path survives as the "back" link."""
    if not ref:
        return ""
    parts = urlsplit(ref)
    if parts.netloc and parts.netloc != request.host:
        return ""
    path = parts.path or "/"
    if not path.startswith("/") or path.startswith("//"):
        return ""
    return path + (f"?{parts.query}" if parts.query else "")


def _forget(jid: str) -> None:
    for p in (jobs._path(jid), _resp_path(jid)):
        try:
            p.unlink()
        except FileNotFoundError:
            pass


# ── the job thread ──────────────────────────────────────────────────────────
def _worker(app, jid, view, env, exclusive):
    cap = None
    cancelled = False
    sink = job_progress.JobSink(jid, exclusive=exclusive)
    try:
        with app.request_context(env) as ctx:
            _TL.active = True
            job_progress.bind(sink)
            before = {k: v for k, v in session.items()}
            try:
                rv = app.preprocess_request()
                if rv is None:
                    rv = view(**(request.view_args or {}))
            except jobs.JobCancelled:
                raise
            except Exception as exc:  # noqa: BLE001 — same handling as inline
                rv = app.handle_user_exception(exc)
            resp = app.make_response(rv)
            for fn in getattr(ctx, "_after_request_functions", []):
                resp = fn(resp)
            cap = capture(resp)
            cap["session"] = _session_diff(before, session)
    except jobs.JobCancelled:
        cancelled = True
        cap = _json_cap({"ok": False, "error": "Stopped before it changed anything "
                         "on the device."}, 409)
    except Exception as exc:  # noqa: BLE001
        try:
            app.logger.exception("device job %s failed", jid)
        except Exception:  # noqa: BLE001
            pass
        cap = _json_cap({"ok": False,
                         "error": f"{type(exc).__name__}: {exc}"[:300]}, 500)
    finally:
        job_progress.unbind()
        _TL.active = False
    # A Stop raised inside a view that catches every exception comes back as
    # an ordinary error response; it is still a stop, not a failure.
    if not cancelled and jobs.is_cancel_requested(jid) and not outcome(cap)[0]:
        cancelled = True
    _store(jid, cap)
    _finalize(jid, cap, cancelled)
    _inline[jid] = cap
    ev = _events.get(jid)
    if ev is not None:
        ev.set()
    else:
        _inline.pop(jid, None)   # nobody inline is waiting any more


def _json_cap(obj: dict, status: int) -> dict:
    body = json.dumps(obj).encode()
    return {"status": status, "headers": {"Content-Type": "application/json"},
            "body": base64.b64encode(body).decode(), "session": None}


def capture(resp) -> dict:
    resp.direct_passthrough = False
    body = resp.get_data()
    truncated = len(body) > MAX_BODY
    if truncated:
        body = b""
    headers = {k: v for k, v in resp.headers.items() if k.lower() not in _DROP_HEADERS}
    return {"status": resp.status_code, "headers": headers,
            "body": base64.b64encode(body).decode(), "truncated": truncated}


def _session_diff(before: dict, after) -> dict:
    out = {"set": {}, "del": []}
    for k, v in after.items():
        if k in _SESSION_SKIP:
            continue
        if k not in before or before[k] != v:
            out["set"][k] = v
    for k in before:
        if k not in _SESSION_SKIP and k not in after:
            out["del"].append(k)
    return out


def apply_session(diff) -> None:
    if not diff:
        return
    for k, v in (diff.get("set") or {}).items():
        if k == "_flashes":
            cur = list(session.get("_flashes") or [])
            for item in v or []:
                item = tuple(item)
                if item not in cur:
                    cur.append(item)
            session["_flashes"] = cur
        else:
            session[k] = v
    for k in diff.get("del") or []:
        session.pop(k, None)


def build_response(cap: dict) -> Response:
    body = base64.b64decode(cap.get("body") or "")
    resp = Response(body, status=int(cap.get("status") or 200))
    for k, v in (cap.get("headers") or {}).items():
        resp.headers[k] = v
    return resp


# ── result store + outcome ──────────────────────────────────────────────────
def _resp_dir() -> Path:
    d = jobs._state_dir() / "responses"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _resp_path(jid: str) -> Path:
    return _resp_dir() / f"{jid}.resp"


def _store(jid: str, cap: dict) -> None:
    p = _resp_path(jid)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(cap, default=str), encoding="utf-8")
    os.replace(tmp, p)


def load_response(jid: str) -> dict | None:
    try:
        return json.loads(_resp_path(jid).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _flash_texts(cap: dict) -> list[tuple[str, str]]:
    fl = ((cap.get("session") or {}).get("set") or {}).get("_flashes") or []
    out = []
    for item in fl:
        try:
            cat, msg = item[0], item[1]
        except Exception:  # noqa: BLE001
            continue
        out.append((str(cat), str(msg)))
    return out


def outcome(cap: dict) -> tuple[bool, str, str]:
    """(ok, message, kind) for a captured response. A 2xx JSON body with
    ``ok: false`` or an ``error`` is a failure even though HTTP said 200 —
    that is how most of these routes report a device refusal."""
    status = int(cap.get("status") or 200)
    headers = {k.lower(): v for k, v in (cap.get("headers") or {}).items()}
    ctype = headers.get("content-type", "")
    kind = ("redirect" if 300 <= status < 400 else
            "json" if "json" in ctype else
            "file" if "attachment" in headers.get("content-disposition", "") else
            "html" if "html" in ctype else "other")
    data = None
    if kind == "json":
        try:
            data = json.loads(base64.b64decode(cap.get("body") or "") or b"null")
        except Exception:  # noqa: BLE001
            data = None
    flashes = _flash_texts(cap)
    bad_flash = next((m for c, m in flashes if c in ("danger", "error")), "")
    if isinstance(data, dict):
        refused = data.get("ok") is False or data.get("started") is False
        err = data.get("error") or ""
        if refused and not err:
            # Routes name the reason differently: reason / detail / status / msg.
            err = next((data[k] for k in ("reason", "detail", "message", "msg", "status")
                        if isinstance(data.get(k), str) and data.get(k)), "")
        if status >= 400 or refused or err:
            return False, str(err or data.get("message") or f"HTTP {status}")[:300], kind
        msg = data.get("message") or data.get("msg") or data.get("summary") or ""
        return True, str(msg or "Done")[:300], kind
    if status >= 400:
        return False, (bad_flash or f"HTTP {status}")[:300], kind
    if bad_flash:
        return False, bad_flash[:300], kind
    last = flashes[-1][1] if flashes else ""
    return True, (last or "Done")[:300], kind


def _finalize(jid: str, cap: dict, cancelled: bool) -> None:
    ok, msg, kind = outcome(cap)
    headers = {k.lower(): v for k, v in (cap.get("headers") or {}).items()}
    result = {"http_status": cap.get("status"), "kind": kind,
              "response_url": f"/jobs/{jid}/response",
              "location": headers.get("location", "")}
    if cancelled:
        jobs.finish_cancelled(jid, message="Stopped before it changed anything "
                              "on the device.", result=result)
    elif ok:
        jobs.finish_success(jid, message=msg, result=result)
    else:
        jobs.finish_error(jid, msg)
        jobs.update_job(jid, result=result)
