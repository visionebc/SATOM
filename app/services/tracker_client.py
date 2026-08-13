# app/services/tracker_client.py
"""Issue tracker integration — open a ticket in Jira, OpenProject or Vikunja
when SATOM raises a change.

WHY THIS EXISTS ALONGSIDE THE PYTHON HOOKS
------------------------------------------
Before this module the ONLY way to get a SATOM change into a ticketing system
was for the operator to write ``data/integrations/<slug>/hook.py`` against the
``change.requested`` event. That is the right tool for a bespoke in-house CRM —
it is the wrong tool for the three trackers almost everybody actually runs.
Asking a network operator to write and maintain Python (and to get its retry,
timeout and secret handling right) so SATOM can POST one JSON document is a
configuration problem dressed up as a programming problem.

The hooks are NOT replaced. A deployment can run both: the native backend opens
the ticket, hooks still fire for whatever else the operator wires up.

SYNCHRONOUS, UNLIKE HOOKS — AND THAT IS THE POINT
-------------------------------------------------
``integration_hooks`` runs out-of-process, so a hook's ticket reference comes
back later through :func:`cr_orchestrator.record_crq`. A native backend calls
the API inline and **knows the key before the request returns**, so the CR shows
``SATOM-412`` immediately instead of "queued" plus a wait. The cost is that a
slow tracker holds a web worker, which is why every call here is time-boxed by
:data:`MAX_TIMEOUT` and the timeout is bounded on BOTH legs (connect and read):
an unbounded connect against a dead tracker is how one button turns into a hung
worker.

THE THREE BACKENDS, AND THE TRAP IN EACH
----------------------------------------
``jira`` (Jira Cloud, incl. the free 10-user tier)
    ``POST /rest/api/3/issue``, Basic auth of **email : API token** (not the
    account password — Atlassian removed password auth for the REST API).
    **The trap is the description.** API v3 does not take a string: it takes
    Atlassian Document Format, a nested JSON document. Posting
    ``"description": "text"`` to v3 returns 400 with a message about the field
    being invalid, which reads like a permissions problem and is not. We build
    the ADF envelope in :func:`_adf` rather than asking the operator to.
    ``ref`` is the issue key (``OPS-14``); the browse URL is
    ``<site>/browse/<key>``, which is NOT the ``self`` link the API returns
    (``self`` points at the REST resource — handing an approver a JSON URL is
    the same class of defect as handing them ``[17, 18, 19]``).

``openproject``
    ``POST /api/v3/projects/<id>/work_packages``, Basic auth with the **literal
    username ``apikey``** and the token as the password. The type link is
    mandatory: a work package with no ``_links.type`` is rejected. We send
    ``notify=false`` so raising a change does not mail every watcher on the
    project — a change window is not an announcement.

``vikunja``
    **``PUT`` creates and ``POST`` updates.** That is backwards from every other
    API in this product and it is Vikunja's documented behaviour, not a typo.
    Sending ``POST /api/v1/projects/<id>/tasks`` does not create a task; it is
    the reason a "working" integration silently produces nothing. Auth is a
    Bearer API token from Settings → API Tokens.

NOTHING HERE IS REQUIRED
------------------------
The product must install and run in a management network with no internet and
no tracker. ``backend="none"`` is the default, every call degrades to a NAMED
refusal rather than an exception, and a disabled integration never reports
success. Rendering the settings page performs no network I/O at all — the test
is a button, because a settings page that hangs because somebody's Jira is down
is a settings page nobody can use to turn that Jira off.
"""
from __future__ import annotations

import base64
import json as _jsonlib
import logging
import re
import time
from typing import Any, Mapping

import httpx

from . import settings_store as store

logger = logging.getLogger(__name__)

__all__ = [
    "BACKENDS", "BACKEND_SLUGS", "DEFAULT_BACKEND",
    "config", "save_config", "is_configured", "test_connection",
    "create_ticket", "describe",
]

# --------------------------------------------------------------------------- #
#  keys + limits                                                                #
# --------------------------------------------------------------------------- #
K_BACKEND = "integrations.tracker.backend"
K_ENABLED = "integrations.tracker.enabled"
K_URL = "integrations.tracker.url"
K_USER = "integrations.tracker.user"
K_TOKEN = "integrations.tracker.token"
K_PROJECT = "integrations.tracker.project"
K_ISSUE_TYPE = "integrations.tracker.issue_type"
K_VERIFY_TLS = "integrations.tracker.verify_tls"
K_TIMEOUT = "integrations.tracker.timeout"

DEFAULT_BACKEND = "none"
DEFAULT_TIMEOUT = 15
MIN_TIMEOUT = 3
MAX_TIMEOUT = 60
MAX_CONNECT_S = 10

MAX_SUMMARY = 250          # Jira's own summary cap is 255; leave headroom.
MAX_DESCRIPTION = 30000
_MAX_DETAIL = 600
REDACTED = "***"

DETAIL_DISABLED = "integration disabled"
DETAIL_NOT_CONFIGURED = "not configured"
DETAIL_TIMEOUT = "timed out"
DETAIL_UNREACHABLE = "unreachable"
DETAIL_AUTH = "authentication rejected"
DETAIL_HTTP = "HTTP"

# --------------------------------------------------------------------------- #
#  backend catalogue                                                            #
# --------------------------------------------------------------------------- #
#  ``project_label`` / ``type_label`` exist because the same box means a
#  different thing per backend and a generic "Project" label is how an operator
#  types a Jira project NAME into a field that needs its KEY. ``needs_user``
#  drives whether the username box is shown at all: OpenProject's username is
#  the constant "apikey" and Vikunja has none, so an empty box the operator is
#  invited to fill is an invitation to break the integration.
BACKENDS: dict[str, dict[str, Any]] = {
    "none": {
        "label": "None (disabled)",
        "needs_user": False, "needs_project": False, "needs_type": False,
        "project_label": "", "type_label": "", "user_label": "",
        "help": "No ticket is opened. Change requests still work; the CRQ "
                "reference stays whatever an operator or a Python hook writes.",
    },
    "jira": {
        "label": "Jira Cloud",
        "needs_user": True, "needs_project": True, "needs_type": True,
        "user_label": "Account e-mail",
        "project_label": "Project key",
        "type_label": "Issue type",
        "default_type": "Task",
        "url_hint": "https://yourorg.atlassian.net",
        "help": "Basic auth with your account e-mail and an API token from "
                "id.atlassian.com → Security → API tokens. The project KEY is "
                "the prefix on issue ids (OPS in OPS-14), not the project name.",
    },
    "openproject": {
        "label": "OpenProject",
        "needs_user": False, "needs_project": True, "needs_type": True,
        "user_label": "",
        "project_label": "Project id or identifier",
        "type_label": "Type id",
        "default_type": "1",
        "url_hint": "https://openproject.example.com",
        "help": "Basic auth with the literal username 'apikey' and your API "
                "key (My account → Access tokens). Type id 1 is Task on a "
                "default installation.",
    },
    "vikunja": {
        "label": "Vikunja",
        "needs_user": False, "needs_project": True, "needs_type": False,
        "user_label": "",
        "project_label": "Project id",
        "type_label": "",
        "url_hint": "https://vikunja.example.com",
        "help": "Bearer API token from Settings → API Tokens, scoped to at "
                "least 'Create' on tasks. The project id is the number in the "
                "project URL.",
    },
}
BACKEND_SLUGS: tuple[str, ...] = tuple(BACKENDS)

# --------------------------------------------------------------------------- #
#  redaction                                                                    #
# --------------------------------------------------------------------------- #
_AUTH_HEADER_RE = re.compile(r"((?:Authorization|Bearer|Basic)\s*[:=]?\s*)\S+",
                             re.IGNORECASE)


def _redact(value: Any, *secrets: str) -> str:
    """Strip credentials out of anything that may reach a log, a flash message
    or an audit row.

    Redaction happens at the BOUNDARY, not at each call site: a tracker that
    echoes the request back in its error body (OpenProject does) would
    otherwise put the token in the detail string that the UI prints."""
    s = "" if value is None else str(value)
    for secret in secrets:
        if secret and len(secret) >= 4:
            s = s.replace(secret, REDACTED)
    s = _AUTH_HEADER_RE.sub(r"\1" + REDACTED, s)
    return s[:_MAX_DETAIL]


# --------------------------------------------------------------------------- #
#  config                                                                       #
# --------------------------------------------------------------------------- #
def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on", "enabled")


def _clamp_timeout(raw: Any) -> int:
    try:
        val = int(str(raw).strip())
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT
    return max(MIN_TIMEOUT, min(MAX_TIMEOUT, val))


def _encrypt(secret: str) -> str:
    if not secret:
        return ""
    try:
        from .encryption import encrypt
        return encrypt(secret)
    except Exception:  # noqa: BLE001 — never block a save on a crypto glitch
        logger.warning("tracker: token encryption failed; token not stored.")
        return ""


def _decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        from .encryption import decrypt
        return decrypt(token)
    except Exception:  # noqa: BLE001
        logger.warning("tracker: token could not be decrypted.")
        return ""


def describe(slug: str) -> dict[str, Any]:
    """The catalogue row for ``slug``, falling back to ``none``. Never raises —
    the settings template asks for this while rendering."""
    return BACKENDS.get(str(slug or "").strip(), BACKENDS[DEFAULT_BACKEND])


def config(*, reveal: bool = False) -> dict[str, Any]:
    """The whole tracker config.

    ``has_token`` tells the UI a token is stored; ``token`` is EMPTY unless
    ``reveal=True`` (only the request path asks for that). ``backend`` always
    reads back as a valid slug so the dropdown has a valid selected state even
    if the row was hand-edited to garbage."""
    enc = store.get_str(K_TOKEN, "") or ""
    backend = (store.get_str(K_BACKEND, "") or "").strip()
    backend = backend if backend in BACKEND_SLUGS else DEFAULT_BACKEND
    return {
        "backend": backend,
        "backend_label": BACKENDS[backend]["label"],
        "enabled": _truthy(store.get_str(K_ENABLED, "0")),
        "url": (store.get_str(K_URL, "") or "").strip().rstrip("/"),
        "user": (store.get_str(K_USER, "") or "").strip(),
        "has_token": bool(enc),
        "token": _decrypt(enc) if reveal else "",
        "project": (store.get_str(K_PROJECT, "") or "").strip(),
        "issue_type": (store.get_str(K_ISSUE_TYPE, "") or "").strip(),
        "verify_tls": _truthy(store.get_str(K_VERIFY_TLS, "1")),
        "timeout": _clamp_timeout(store.get_str(K_TIMEOUT, DEFAULT_TIMEOUT)),
    }


def save_config(form: Mapping[str, Any]) -> None:
    """Persist the config from a form-like mapping.

    Conventions, matching NetBox and the rest of the admin console:

    * a BLANK ``token`` KEEPS the stored one — a filled-looking field in the UI
      only ever means "unchanged". ``clear_token`` truthy wipes it. There is no
      path in which saving the form drops the credential by accident.
    * a key ABSENT from the mapping leaves that setting untouched. HTML omits
      unchecked checkboxes, and defaulting an absent ``verify_tls`` to False
      would silently downgrade TLS verification on an unrelated save, so the
      form posts the flag explicitly through a hidden companion input.
    * an unknown ``backend`` raises rather than falling back. Every other field
      here is free text the operator can fix from the same page; a silently
      rewritten backend means the ticket goes somewhere they did not choose.
    """
    if "backend" in form:
        backend = str(form.get("backend") or "").strip()
        if backend not in BACKEND_SLUGS:
            raise ValueError(
                "unknown tracker backend %r — must be one of: %s"
                % (backend, ", ".join(BACKEND_SLUGS)))
        store.set_str(K_BACKEND, backend)
    if "enabled" in form:
        store.set_str(K_ENABLED, "1" if _truthy(form.get("enabled")) else "0")
    if "url" in form:
        store.set_str(K_URL, str(form.get("url") or "").strip().rstrip("/"))
    if "user" in form:
        store.set_str(K_USER, str(form.get("user") or "").strip())
    if "project" in form:
        store.set_str(K_PROJECT, str(form.get("project") or "").strip())
    if "issue_type" in form:
        store.set_str(K_ISSUE_TYPE, str(form.get("issue_type") or "").strip())
    if "verify_tls" in form:
        store.set_str(K_VERIFY_TLS,
                      "1" if _truthy(form.get("verify_tls")) else "0")
    if "timeout" in form:
        store.set_str(K_TIMEOUT, _clamp_timeout(form.get("timeout")))
    if form.get("clear_token"):
        store.set_str(K_TOKEN, "")
    else:
        token = str(form.get("token") or "").strip()
        if token:  # blank => KEEP the stored token
            store.set_str(K_TOKEN, _encrypt(token))


def is_configured() -> bool:
    """True once a real backend is selected, switched on, and has somewhere to
    talk to with something to authenticate as."""
    cfg = config()
    return bool(cfg["backend"] != "none" and cfg["enabled"]
                and cfg["url"] and cfg["has_token"] and cfg["project"])


def _gate(cfg: Mapping[str, Any]) -> str:
    """"" when a call may proceed, else the NAMED reason it may not.

    Order matters: disabled is checked FIRST and is never silent. An operator
    who switched the integration off must read "nothing was sent", not a
    missing-field error that reads like a bug."""
    backend = cfg.get("backend")
    if backend == "none" or backend not in BACKEND_SLUGS:
        return (f"{DETAIL_DISABLED}: no tracker backend is selected "
                f"({K_BACKEND}) — nothing was sent.")
    if not cfg.get("enabled"):
        return (f"{DETAIL_DISABLED} ({K_ENABLED}=0) — nothing was sent to "
                f"{BACKENDS[backend]['label']}.")
    if not cfg.get("url"):
        return f"{DETAIL_NOT_CONFIGURED}: no base URL is set ({K_URL})."
    if not cfg.get("has_token"):
        return f"{DETAIL_NOT_CONFIGURED}: no API token is stored ({K_TOKEN})."
    if not cfg.get("token"):
        return (f"{DETAIL_NOT_CONFIGURED}: the stored API token could not be "
                f"decrypted (wrong or rotated FERNET_KEY).")
    spec = BACKENDS[backend]
    if spec["needs_user"] and not cfg.get("user"):
        return (f"{DETAIL_NOT_CONFIGURED}: {BACKENDS[backend]['label']} needs "
                f"an account e-mail ({K_USER}).")
    if spec["needs_project"] and not cfg.get("project"):
        return (f"{DETAIL_NOT_CONFIGURED}: no {spec['project_label'].lower()} "
                f"is set ({K_PROJECT}).")
    return ""


# --------------------------------------------------------------------------- #
#  HTTP                                                                         #
# --------------------------------------------------------------------------- #
def _auth_headers(cfg: Mapping[str, Any]) -> dict[str, str]:
    """The Authorization header for the selected backend.

    Three different schemes, one place. Jira and OpenProject are both Basic but
    with DIFFERENT usernames — OpenProject's is the literal string ``apikey``,
    and using the operator's e-mail there fails with a 401 that looks exactly
    like a bad token."""
    backend = cfg["backend"]
    token = cfg["token"]
    if backend == "vikunja":
        return {"Authorization": f"Bearer {token}"}
    user = cfg["user"] if backend == "jira" else "apikey"
    raw = f"{user}:{token}".encode("utf-8")
    return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}


def request(method: str, path: str, *, json=None, params=None,
            cfg: Mapping[str, Any] | None = None) -> tuple[bool, Any, str]:
    """One tracker API call -> ``(ok, payload, detail)``.

    ``ok`` is True only for a 2xx. ``payload`` is the decoded body (``None``
    for 204/empty). ``detail`` is "" on success and otherwise a REDACTED human
    reason prefixed with one of the ``DETAIL_*`` constants. Never raises — a
    tracker outage must not be able to throw out of a change request."""
    cfg = dict(cfg) if cfg is not None else config(reveal=True)
    token = cfg.get("token") or ""
    blocked = _gate(cfg)
    if blocked:
        return False, None, blocked

    url = f"{cfg['url']}/{str(path or '').lstrip('/')}"
    budget = cfg["timeout"]
    timeout = httpx.Timeout(budget, connect=min(MAX_CONNECT_S, budget),
                            read=budget, write=budget, pool=budget)
    headers = {
        **_auth_headers(cfg),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    try:
        # follow_redirects=False on purpose: a tracker behind a proxy that
        # 302s to a login page would otherwise turn an auth failure into a
        # 200 with an HTML body, i.e. a green tick for a broken integration.
        with httpx.Client(verify=cfg["verify_tls"], timeout=timeout,
                          headers=headers, follow_redirects=False) as client:
            resp = client.request(str(method or "GET").upper(), url,
                                  json=json, params=params)
    except httpx.TimeoutException as exc:
        return False, None, _redact(
            f"{DETAIL_TIMEOUT} within {budget}s ({type(exc).__name__}) — it may "
            f"be down, firewalled, or the URL may be wrong.", token)
    except Exception as exc:  # noqa: BLE001 — nothing escapes this module
        return False, None, _redact(
            f"{DETAIL_UNREACHABLE}: {type(exc).__name__}: {exc}", token)

    status = getattr(resp, "status_code", 0)
    body = _body_text(resp, token)
    if status in (401, 403):
        return False, None, _redact(
            f"{DETAIL_AUTH} (HTTP {status}): {body}", token)
    if status >= 400:
        return False, None, _redact(f"{DETAIL_HTTP} {status}: {body}", token)
    if status == 204:
        return True, None, ""
    try:
        payload = resp.json()
    except Exception:  # noqa: BLE001 — a 2xx with no/!json body is still ok
        payload = None
    return True, payload, ""


def _body_text(resp: Any, token: str = "") -> str:
    try:
        return _redact(resp.text, token)
    except Exception:  # noqa: BLE001
        return ""


# --------------------------------------------------------------------------- #
#  ticket rendering                                                             #
# --------------------------------------------------------------------------- #
def _adf(text: str) -> dict[str, Any]:
    """Wrap plain text in a minimal Atlassian Document Format document.

    One paragraph node per non-empty line. ADF forbids an EMPTY text node
    (``{"type":"text","text":""}`` is rejected with a 400 that names no field),
    so blank lines are dropped rather than emitted — and a wholly empty
    description becomes a document with no content, which is valid."""
    lines = [ln for ln in str(text or "").splitlines() if ln.strip()]
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph",
             "content": [{"type": "text", "text": ln}]}
            for ln in lines
        ],
    }


def render_ticket(payload: Mapping[str, Any]) -> tuple[str, str]:
    """``(summary, description)`` for a ``change.requested``-shaped payload.

    The description carries the SAME facts the change document does — the
    devices BY NAME, the pre-flight evidence and, above all, the appliances
    with NO baseline. A ticket that says "2 devices" is a ticket an approver
    has to leave to act on, which is the defect this integration exists to
    remove."""
    ref = str(payload.get("cr_ref") or "").strip()
    title = str(payload.get("title") or "Change request").strip()
    summary = f"[{ref}] {title}" if ref else title

    devices = payload.get("devices") or []
    names = [str(d.get("appliance") or "") for d in devices
             if isinstance(d, dict) and d.get("appliance")]
    if not names:
        names = [str(i) for i in (payload.get("device_ids") or [])]
    missing = [str(m) for m in (payload.get("evidence_missing") or [])]

    lines = [
        f"SATOM change request {ref or payload.get('cr_id', '')}".strip(),
        "",
        f"Action: {payload.get('action') or '-'}",
        f"Risk: {payload.get('risk') or '-'}",
        f"Requested by: {payload.get('requested_by') or '-'}",
        f"Window: {payload.get('window_start') or '-'}"
        f" -> {payload.get('window_end') or '-'}",
        f"Appliances ({payload.get('device_count', len(names))}): "
        f"{', '.join(names) if names else '-'}",
    ]
    policy_count = payload.get("policy_count")
    if policy_count:
        shown = ", ".join(str(p) for p in (payload.get("policies") or []))
        suffix = " (list truncated)" if payload.get("policies_truncated") else ""
        lines.append(f"Policies ({policy_count}): {shown or '-'}{suffix}")
    # NAMED, never implied. "12 of 20 have a baseline" is only actionable if
    # the other 8 are on the ticket.
    lines.append(
        "Appliances with NO stored pre-upgrade run: "
        + (", ".join(missing) if missing else "none"))
    reason = str(payload.get("reason") or "").strip()
    if reason:
        lines += ["", "Reason:", reason]
    if str(payload.get("approval_mode") or "") == "external":
        lines += ["", "This ticket HOLDS THE GATE: the change cannot run in "
                      "SATOM until this ticket is approved."]
    return summary[:MAX_SUMMARY], "\n".join(lines)[:MAX_DESCRIPTION]


# --------------------------------------------------------------------------- #
#  per-backend create                                                           #
# --------------------------------------------------------------------------- #
def _create_jira(cfg, summary, description):
    body = {"fields": {
        "project": {"key": cfg["project"]},
        "summary": summary,
        "issuetype": {"name": cfg["issue_type"] or "Task"},
        "description": _adf(description),
    }}
    ok, payload, detail = request("POST", "/rest/api/3/issue",
                                  json=body, cfg=cfg)
    if not ok:
        return False, "", "", detail
    data = payload if isinstance(payload, dict) else {}
    key = str(data.get("key") or "").strip()
    if not key:
        return False, "", "", ("Jira returned 2xx with no issue key: "
                               + _redact(_jsonlib.dumps(data)[:200]))
    # NOT data["self"] — that is the REST resource, not a page a human opens.
    return True, key, f"{cfg['url']}/browse/{key}", ""


def _create_openproject(cfg, summary, description):
    type_id = (cfg["issue_type"] or "1").strip()
    body = {
        "subject": summary,
        "description": {"format": "markdown", "raw": description},
        "_links": {"type": {"href": f"/api/v3/types/{type_id}"}},
    }
    ok, payload, detail = request(
        "POST", f"/api/v3/projects/{cfg['project']}/work_packages",
        json=body, params={"notify": "false"}, cfg=cfg)
    if not ok:
        return False, "", "", detail
    data = payload if isinstance(payload, dict) else {}
    wp_id = data.get("id")
    if not wp_id:
        return False, "", "", ("OpenProject returned 2xx with no work-package "
                               "id: " + _redact(_jsonlib.dumps(data)[:200]))
    return True, f"WP-{wp_id}", f"{cfg['url']}/work_packages/{wp_id}", ""


def _create_vikunja(cfg, summary, description):
    # PUT creates in Vikunja. POST updates. This is not a typo — see module
    # docstring. A POST here returns 2xx-looking noise and creates nothing.
    ok, payload, detail = request(
        "PUT", f"/api/v1/projects/{cfg['project']}/tasks",
        json={"title": summary, "description": description}, cfg=cfg)
    if not ok:
        return False, "", "", detail
    data = payload if isinstance(payload, dict) else {}
    task_id = data.get("id")
    if not task_id:
        return False, "", "", ("Vikunja returned 2xx with no task id: "
                               + _redact(_jsonlib.dumps(data)[:200]))
    ref = str(data.get("identifier") or "").strip() or f"#{task_id}"
    return True, ref, f"{cfg['url']}/tasks/{task_id}", ""


_CREATORS = {
    "jira": _create_jira,
    "openproject": _create_openproject,
    "vikunja": _create_vikunja,
}


def create_ticket(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Open ONE ticket for a ``change.requested``-shaped payload.

    Returns the full shape every time — ``{ok, ref, url, detail, backend,
    elapsed_ms}`` — so a caller never has to guess whether a missing key meant
    failure. ``ok=False`` with a ``DETAIL_DISABLED`` detail is the normal
    answer on a deployment with no tracker, NOT an error to log loudly."""
    started = time.monotonic()
    cfg = config(reveal=True)
    blocked = _gate(cfg)
    if blocked:
        return {"ok": False, "ref": "", "url": "", "detail": blocked,
                "backend": cfg["backend"],
                "elapsed_ms": int((time.monotonic() - started) * 1000)}
    summary, description = render_ticket(payload)
    creator = _CREATORS[cfg["backend"]]
    try:
        ok, ref, url, detail = creator(cfg, summary, description)
    except Exception as exc:  # noqa: BLE001 — a tracker cannot break a CR
        logger.exception("tracker: create_ticket failed")
        ok, ref, url = False, "", ""
        detail = _redact(f"{type(exc).__name__}: {exc}", cfg.get("token") or "")
    return {"ok": bool(ok), "ref": ref, "url": url, "detail": detail,
            "backend": cfg["backend"],
            "elapsed_ms": int((time.monotonic() - started) * 1000)}


# --------------------------------------------------------------------------- #
#  test button                                                                  #
# --------------------------------------------------------------------------- #
_WHOAMI = {
    "jira": ("/rest/api/3/myself", ("displayName", "emailAddress", "accountId")),
    "openproject": ("/api/v3/users/me", ("name", "login")),
    "vikunja": ("/api/v1/user", ("username", "name")),
}
_PROJECT_PROBE = {
    "jira": "/rest/api/3/project/{project}",
    "openproject": "/api/v3/projects/{project}",
    "vikunja": "/api/v1/projects/{project}",
}


def test_connection() -> dict[str, Any]:
    """Probe identity AND the configured project, in that order.

    Two calls, not one, and the second is the one that matters: a token that
    authenticates but cannot see the project produces a green tick on the
    settings page and a 404 at the only moment anyone cares — while a change
    window is opening. The elapsed time is reported because a tick with no
    number behind it is not evidence."""
    started = time.monotonic()
    cfg = config(reveal=True)
    blocked = _gate(cfg)
    if blocked:
        return {"ok": False, "detail": blocked, "who": None, "project": None,
                "backend": cfg["backend"], "elapsed_ms": 0}

    path, who_keys = _WHOAMI[cfg["backend"]]
    ok, payload, detail = request("GET", path, cfg=cfg)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if not ok:
        return {"ok": False, "detail": detail, "who": None, "project": None,
                "backend": cfg["backend"], "elapsed_ms": elapsed_ms}
    data = payload if isinstance(payload, dict) else {}
    who = next((str(data[k]) for k in who_keys if data.get(k)), "authenticated")

    probe = _PROJECT_PROBE[cfg["backend"]].format(project=cfg["project"])
    p_ok, p_payload, p_detail = request("GET", probe, cfg=cfg)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    label = BACKENDS[cfg["backend"]]["label"]
    if not p_ok:
        return {
            "ok": False, "who": who, "project": None,
            "backend": cfg["backend"], "elapsed_ms": elapsed_ms,
            "detail": (f"Authenticated to {label} as {who}, but the configured "
                       f"{BACKENDS[cfg['backend']]['project_label'].lower()} "
                       f"{cfg['project']!r} is not reachable: {p_detail}"),
        }
    p_data = p_payload if isinstance(p_payload, dict) else {}
    project_name = str(p_data.get("name") or p_data.get("title")
                       or cfg["project"])
    return {
        "ok": True, "who": who, "project": project_name,
        "backend": cfg["backend"], "elapsed_ms": elapsed_ms,
        "detail": (f"Connected to {label} as {who}; project "
                   f"{project_name!r} is reachable."),
    }
