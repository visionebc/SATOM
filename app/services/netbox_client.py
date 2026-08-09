# app/services/netbox_client.py
"""NetBox integration — device linkage + maintenance-window bookkeeping.

SATOM plans and executes disruptive work (firmware upgrades, policy cutovers)
against appliances that a customer's NetBox already documents. This module is
the ONE place that talks to NetBox: config storage, a connection test, device
resolution, and opening/closing a maintenance window around a change request.

WHY THERE IS NO "maintenance window" BACKEND CALLED "netbox"
-----------------------------------------------------------
NetBox **core has no maintenance-window object**. Verified live against NetBox
4.6.7 (``/api/`` lists circuits, core, dcim, extras, ipam, plugins, tenancy,
users, virtualization, vpn, wireless — nothing else) on an instance with NO
plugins installed. There are community plugins that add one, and a fourth
``plugin`` backend can be added later behind the same ``ref`` contract; until
one is actually installed, offering it would be a setting that silently does
nothing. So a window is recorded through one of three CORE mechanisms, chosen
by the operator (``integrations.netbox.mw_backend``):

``journal`` (default)
    ``POST /api/extras/journal-entries/`` against ``dcim.device``. Carries the
    CR id, the window start/end and the reason as free text. ``ref`` is
    ``"journal:<entry-id>"``.

    Closing posts a **SECOND** entry that references the first — it never
    edits the opening entry. A journal is an append-only operational log: the
    opening entry is the record of *when the window opened* and mutating it
    destroys exactly the evidence an auditor asks for after a bad change. Two
    entries also give a real duration, which one mutated entry cannot.

``tag``
    Adds the ``maint-window`` tag to the device (creating the tag if absent),
    removes it on close. ``ref`` is ``"tag:<device-id>"``.

    **This backend is LOSSY and that is deliberate.** A tag records "this
    device is in *a* window" — not which window, not the CR, not when it
    started, not when it should end. It is offered anyway because it is the
    only one of the three that NetBox's UI and API can *filter on*
    (``/api/dcim/devices/?tag=maint-window``): journal entries are not
    queryable as device state. Operators who need "show me everything in a
    window right now" pick this and accept the lost detail.

``custom_field``
    PATCHes ``custom_fields.maint_window_start`` / ``maint_window_end`` on the
    device; close clears them. ``ref`` is ``"cf:<device-id>"``. Structured AND
    queryable, but it needs two custom fields that SATOM will not create for
    the customer (a custom field is a schema change on their NetBox). If they
    are missing, :func:`open_window` returns ``ok=False`` with a detail that
    NAMES the missing field — it never silently no-ops, because a window that
    was never recorded is worse than one that failed loudly.

TIME IS THE DANGEROUS PART
--------------------------
SATOM stores naive UTC; NetBox stores UTC. Every datetime this module sends is
rendered ISO-8601 with an **explicit ``+00:00`` offset** by :func:`_iso_utc`.
This is not cosmetic — verified live on NetBox 4.6.7: a naive
``"2026-08-10T02:00:00"`` PATCHed into a datetime custom field comes back as
``"2026-08-10T02:00:00"`` (no ``Z``), i.e. it was taken in the NetBox server's
own timezone, while the offset-aware form comes back normalised to
``"2026-08-10T02:00:00Z"``. On a server set to anything but UTC that is a
window that opens an hour off — an upgrade running outside its own change
window, with the monitoring suppression pointing somewhere else.

CONTRACT
--------
* The API token is Fernet-encrypted at rest (``services.encryption``) and is
  never returned, logged, or embedded in a ``detail`` string. Anything that
  could echo it goes through :func:`_redact` first.
* Every network call carries the configured timeout on BOTH the connect and
  the read leg, capped at :data:`MAX_TIMEOUT`. This product installs in
  isolated management networks where an unreachable host is the NORMAL case;
  everything external must fail fast.
* No operation raises. Failures return ``ok=False`` with a human reason whose
  prefix distinguishes disabled / not-configured / unreachable / auth-rejected
  / HTTP-error, so a caller can tell "NetBox said no" from "NetBox never
  answered". (The two *form-validation* helpers — :func:`save_device_map` — do
  raise ``ValueError``; that is a synchronous input check for the settings
  view, not a remote call.)
* Importing this module touches no DB and no network.
"""
from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Mapping

import httpx

from . import settings_store as store

logger = logging.getLogger(__name__)

# ---- keys -----------------------------------------------------------------
K_ENABLED = "integrations.netbox.enabled"        # "1" / "0"
K_URL = "integrations.netbox.url"                # base URL, e.g. http://192.0.2.200
K_TOKEN = "integrations.netbox.token"            # Fernet-encrypted, NEVER plain
K_VERIFY_TLS = "integrations.netbox.verify_tls"  # "1" / "0"
K_TIMEOUT = "integrations.netbox.timeout"        # seconds, int
K_MW_BACKEND = "integrations.netbox.mw_backend"  # journal | tag | custom_field
K_DEVICE_MAP = "integrations.netbox.device_map"  # JSON {appliance_id: device_id}

# ---- maintenance-window backends ------------------------------------------
# (slug, human label) — the Settings → Integrations dropdown renders these.
# There is deliberately NO "plugin" entry: see the module docstring.
MW_BACKENDS: tuple[tuple[str, str], ...] = (
    ("journal", "Journal entry (core, append-only — full detail, not filterable)"),
    ("tag", "Device tag (core, filterable — lossy: no CR, no times)"),
    ("custom_field", "Device custom fields (structured + filterable — needs schema)"),
)
MW_BACKEND_SLUGS: tuple[str, ...] = tuple(slug for slug, _ in MW_BACKENDS)
DEFAULT_MW_BACKEND = "journal"

# ---- timeouts -------------------------------------------------------------
DEFAULT_TIMEOUT = 8
MIN_TIMEOUT = 1
MAX_TIMEOUT = 30        # hard cap — an isolated mgmt net must fail fast
MAX_CONNECT_S = 5       # the TCP/TLS leg never gets the whole budget

# ---- NetBox object names --------------------------------------------------
DEVICE_CT = "dcim.device"
MAINT_TAG_NAME = "maint-window"
MAINT_TAG_SLUG = "maint-window"
CF_START = "maint_window_start"
CF_END = "maint_window_end"

# ---- stable detail prefixes ----------------------------------------------
# Callers (and tests) branch on these, so they are constants rather than
# literals sprinkled through the code. A caller MUST be able to tell
# "NetBox said no" (AUTH/HTTP) from "NetBox never answered" (UNREACHABLE/
# TIMEOUT) from "we never asked" (DISABLED/NOT_CONFIGURED).
DETAIL_DISABLED = "NetBox integration is disabled"
DETAIL_NOT_CONFIGURED = "NetBox integration is not configured"
DETAIL_UNREACHABLE = "NetBox unreachable"
DETAIL_TIMEOUT = "NetBox did not answer"
DETAIL_AUTH = "NetBox rejected the API token"
DETAIL_HTTP = "NetBox returned HTTP"

REDACTED = "***REDACTED***"

# "Token 0123…" in any echoed header, plus a bare 40-hex NetBox key.
_TOKEN_HEADER_RE = re.compile(r"(Token\s+)\S+", re.IGNORECASE)
_BARE_KEY_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")

_MAX_DETAIL = 300


# ---------------------------------------------------------------------------
#  secrets
# ---------------------------------------------------------------------------
def _encrypt(secret: str) -> str:
    if not secret:
        return ""
    try:
        from .encryption import encrypt
        return encrypt(secret)
    except Exception:  # noqa: BLE001 — never block a save on a crypto glitch
        logger.warning("netbox: token encryption failed; token not stored.")
        return ""


def _decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        from .encryption import decrypt
        return decrypt(token)
    except Exception:  # noqa: BLE001
        return ""


def _redact(value: Any, token: str = "") -> str:
    """Scrub anything that could carry the API token out of *value*.

    Applied to EVERY string this module hands back or logs. The token is the
    keys-to-the-kingdom credential for the customer's source of truth; a
    detail string ends up in a flash message, an audit row and a support
    ticket, so redaction happens at the boundary rather than at each call
    site."""
    s = "" if value is None else str(value)
    if token:
        s = s.replace(token, REDACTED)
    s = _TOKEN_HEADER_RE.sub(r"\1" + REDACTED, s)
    s = _BARE_KEY_RE.sub(REDACTED, s)
    return s[:_MAX_DETAIL]


# ---------------------------------------------------------------------------
#  config
# ---------------------------------------------------------------------------
def _clamp_timeout(raw: Any) -> int:
    try:
        val = int(str(raw).strip())
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT
    return max(MIN_TIMEOUT, min(MAX_TIMEOUT, val))


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on", "enabled")


def config(*, reveal: bool = False) -> dict[str, Any]:
    """The whole integration config.

    ``has_token`` tells the UI a token is stored; ``token`` is EMPTY unless
    ``reveal=True`` (only the request path asks for that). ``mw_backend`` is
    always one of :data:`MW_BACKEND_SLUGS` — an unset or corrupted row reads
    back as :data:`DEFAULT_MW_BACKEND`, so the settings dropdown always has a
    valid selected state."""
    enc = store.get_str(K_TOKEN, "") or ""
    backend = (store.get_str(K_MW_BACKEND, "") or "").strip()
    return {
        "enabled": _truthy(store.get_str(K_ENABLED, "0")),
        "url": (store.get_str(K_URL, "") or "").strip().rstrip("/"),
        "has_token": bool(enc),
        "token": _decrypt(enc) if reveal else "",
        "verify_tls": _truthy(store.get_str(K_VERIFY_TLS, "1")),
        "timeout": _clamp_timeout(store.get_str(K_TIMEOUT, DEFAULT_TIMEOUT)),
        "mw_backend": backend if backend in MW_BACKEND_SLUGS else DEFAULT_MW_BACKEND,
        "device_map": device_map(),
    }


def save_config(form: Mapping[str, Any]) -> None:
    """Persist the config from a form-like mapping.

    Conventions, matching the rest of the admin console:

    * a BLANK ``token`` keeps the stored one (a filled field in the UI only
      ever means "unchanged"); ``clear_token`` truthy wipes it. There is no
      code path in which saving the form drops the credential by accident.
    * a key ABSENT from the mapping leaves that setting untouched. HTML omits
      unchecked checkboxes, and defaulting an absent ``verify_tls`` to False
      would silently downgrade TLS verification on an unrelated save, so the
      form must post the flag explicitly (hidden companion input).
    """
    if "enabled" in form:
        store.set_str(K_ENABLED, "1" if _truthy(form.get("enabled")) else "0")
    if "url" in form:
        store.set_str(K_URL, str(form.get("url") or "").strip().rstrip("/"))
    if "verify_tls" in form:
        store.set_str(K_VERIFY_TLS, "1" if _truthy(form.get("verify_tls")) else "0")
    if "timeout" in form:
        store.set_str(K_TIMEOUT, _clamp_timeout(form.get("timeout")))
    if "mw_backend" in form:
        backend = str(form.get("mw_backend") or "").strip()
        store.set_str(K_MW_BACKEND,
                      backend if backend in MW_BACKEND_SLUGS else DEFAULT_MW_BACKEND)
    if form.get("clear_token"):
        store.set_str(K_TOKEN, "")
    else:
        token = str(form.get("token") or "").strip()
        if token:  # blank => KEEP the stored token
            store.set_str(K_TOKEN, _encrypt(token))
    if "device_map" in form:
        raw = form.get("device_map")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw) if raw.strip() else {}
            except (ValueError, TypeError) as exc:
                raise ValueError(f"device_map is not valid JSON: {exc}") from None
        save_device_map(raw or {})


def is_configured() -> bool:
    """True once the integration is switched on AND has somewhere to talk to
    with something to authenticate as."""
    cfg = config()
    return bool(cfg["enabled"] and cfg["url"] and cfg["has_token"])


# ---------------------------------------------------------------------------
#  device map
# ---------------------------------------------------------------------------
def device_map() -> dict[str, int]:
    """SATOM appliance id (str) -> NetBox device id (int).

    Rows that cannot be coerced are DROPPED rather than guessed at: a bad row
    that resolved to some other integer would point a maintenance window at
    the wrong customer device."""
    raw = store.get_json(K_DEVICE_MAP, {})
    if not isinstance(raw, dict):
        return {}
    out: dict[str, int] = {}
    for key, val in raw.items():
        try:
            dev = int(str(val).strip())
        except (TypeError, ValueError):
            continue
        appliance = str(key).strip()
        if appliance and dev > 0:
            out[appliance] = dev
    return out


def save_device_map(pairs: Mapping[str, Any]) -> None:
    """Validate and persist the appliance->device mapping.

    Raises ``ValueError`` NAMING the offending key/value — this is a settings
    form check, so the operator gets told which row is wrong instead of having
    it silently dropped. A blank value means "unmapped" and is dropped: storing
    it as ``0`` would be a real NetBox object id nobody chose."""
    if not isinstance(pairs, Mapping):
        raise ValueError("device_map must be a mapping of appliance id -> NetBox device id.")
    out: dict[str, int] = {}
    for key, val in pairs.items():
        appliance = str(key).strip()
        if not appliance:
            continue
        raw = "" if val is None else str(val).strip()
        if not raw:
            continue  # unmapped — drop, never store 0
        try:
            appliance_id = int(appliance)
        except (TypeError, ValueError):
            raise ValueError(
                f"device_map key {key!r} is not an appliance id (integer expected)."
            ) from None
        try:
            device_id = int(raw)
        except (TypeError, ValueError):
            raise ValueError(
                f"device_map[{key!r}] = {val!r} is not a NetBox device id (integer expected)."
            ) from None
        if appliance_id <= 0:
            raise ValueError(f"device_map key {key!r} is not a positive appliance id.")
        if device_id <= 0:
            raise ValueError(
                f"device_map[{key!r}] = {val!r} is not a positive NetBox device id."
            )
        out[str(appliance_id)] = device_id
    store.set_json(K_DEVICE_MAP, out)


# ---------------------------------------------------------------------------
#  time
# ---------------------------------------------------------------------------
def _iso_utc(value: Any) -> str:
    """Render *value* as ISO-8601 with an EXPLICIT UTC offset, or "" if it
    cannot be understood.

    Naive input is taken as UTC — SATOM's storage convention, the same one
    ``settings_store.to_local`` assumes. Aware input is CONVERTED. The offset
    is always emitted: see the module docstring for what a naive string costs."""
    if value in (None, ""):
        return ""
    dt = value
    if isinstance(dt, str):
        text = dt.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except (ValueError, TypeError):
            return ""
    if not isinstance(dt, datetime):
        return ""
    aware = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    return aware.isoformat()


# ---------------------------------------------------------------------------
#  refs
# ---------------------------------------------------------------------------
_REF_KINDS = {"journal": "journal", "tag": "tag", "cf": "custom_field"}
_REF_PREFIX = {"journal": "journal", "tag": "tag", "custom_field": "cf"}


def make_ref(backend: str, ident: Any) -> str:
    """``("journal", 12) -> "journal:12"``. Empty string for anything unusable."""
    prefix = _REF_PREFIX.get(str(backend or "").strip())
    try:
        num = int(str(ident).strip())
    except (TypeError, ValueError):
        return ""
    return f"{prefix}:{num}" if prefix and num > 0 else ""


def parse_ref(ref: str) -> tuple[str, int]:
    """``"journal:12" -> ("journal", 12)``; ``("", 0)`` when unparseable.

    The BACKEND IS READ FROM THE REF, never from the current setting: an
    operator who switches ``mw_backend`` between opening and closing a window
    must still close the window the way it was opened, or the device is left
    tagged / custom-fielded forever."""
    text = str(ref or "").strip()
    if ":" not in text:
        return "", 0
    prefix, _, ident = text.partition(":")
    backend = _REF_KINDS.get(prefix.strip().lower(), "")
    try:
        num = int(ident.strip())
    except (TypeError, ValueError):
        return "", 0
    return (backend, num) if backend and num > 0 else ("", 0)


# ---------------------------------------------------------------------------
#  low-level HTTP
# ---------------------------------------------------------------------------
def _gate(cfg: Mapping[str, Any]) -> str:
    """"" when a call may proceed, else the reason it may not.

    Disabled is checked FIRST and is never silent: an operator who switched
    the integration off must see "nothing was sent", not a green tick."""
    if not cfg.get("enabled"):
        return (f"{DETAIL_DISABLED} ({K_ENABLED}=0) — nothing was sent to NetBox.")
    if not cfg.get("url"):
        return f"{DETAIL_NOT_CONFIGURED}: no base URL is set ({K_URL})."
    if not cfg.get("has_token"):
        return f"{DETAIL_NOT_CONFIGURED}: no API token is stored ({K_TOKEN})."
    if not cfg.get("token"):
        return (f"{DETAIL_NOT_CONFIGURED}: the stored API token could not be "
                f"decrypted (wrong or rotated FERNET_KEY).")
    return ""


def request(method: str, path: str, *, json=None, params=None) -> tuple[bool, Any, str]:
    """One NetBox API call -> ``(ok, payload, detail)``.

    ``ok`` is True only for a 2xx. ``payload`` is the decoded body (``None``
    for 204/empty). ``detail`` is "" on success and otherwise a redacted human
    reason prefixed with one of the ``DETAIL_*`` constants. Never raises."""
    cfg = config(reveal=True)
    token = cfg["token"]
    blocked = _gate(cfg)
    if blocked:
        return False, None, blocked

    url = f"{cfg['url']}/{str(path or '').lstrip('/')}"
    budget = cfg["timeout"]
    # BOTH legs bounded: an unbounded connect is how a dead management host
    # turns one page load into a hung worker.
    timeout = httpx.Timeout(budget, connect=min(MAX_CONNECT_S, budget),
                            read=budget, write=budget, pool=budget)
    headers = {
        "Authorization": f"Token {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    try:
        with httpx.Client(verify=cfg["verify_tls"], timeout=timeout,
                          headers=headers, follow_redirects=False) as client:
            resp = client.request(str(method or "GET").upper(), url,
                                  json=json, params=params)
    except httpx.TimeoutException as exc:
        return False, None, _redact(
            f"{DETAIL_TIMEOUT} within {budget}s ({type(exc).__name__}) — "
            f"it may be down, firewalled, or the URL may be wrong.", token)
    except Exception as exc:  # noqa: BLE001 — nothing escapes this module
        return False, None, _redact(
            f"{DETAIL_UNREACHABLE}: {type(exc).__name__}: {exc}", token)

    status = getattr(resp, "status_code", 0)
    body = _body_text(resp, token)
    if status in (401, 403):
        return False, None, _redact(
            f"{DETAIL_AUTH} (HTTP {status}): {body}", token)
    if status >= 400:
        return False, None, _redact(
            f"{DETAIL_HTTP} {status}: {body}", token)
    if status == 204:
        return True, None, ""
    try:
        payload = resp.json()
    except Exception:  # noqa: BLE001 — a 2xx with no/!json body is still a success
        payload = None
    return True, payload, ""


def _body_text(resp: Any, token: str = "") -> str:
    try:
        return _redact(resp.text, token)
    except Exception:  # noqa: BLE001
        return ""


# ---------------------------------------------------------------------------
#  read helpers
# ---------------------------------------------------------------------------
def test_connection() -> dict[str, Any]:
    """Probe ``/api/status/``. Always returns the full shape so a caller never
    has to guess whether a missing key meant failure."""
    started = time.monotonic()
    ok, payload, detail = request("GET", "/api/status/")
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if not ok:
        return {"ok": False, "detail": detail, "version": None,
                "plugins": [], "elapsed_ms": elapsed_ms}
    data = payload if isinstance(payload, dict) else {}
    version = data.get("netbox-version") or data.get("netbox_version")
    raw_plugins = data.get("plugins") or {}
    plugins = (sorted(raw_plugins.keys()) if isinstance(raw_plugins, dict)
               else [str(p) for p in raw_plugins])
    note = (f"plugins: {', '.join(plugins)}" if plugins
            else "no plugins installed (core objects only)")
    return {
        "ok": True,
        "detail": f"Connected to NetBox {version or 'unknown'} — {note}.",
        "version": str(version) if version else None,
        "plugins": plugins,
        "elapsed_ms": elapsed_ms,
    }


def list_devices(limit: int = 100) -> list[dict[str, Any]]:
    """A flat, single-page device list for the mapping UI. Returns ``[]`` on
    any failure — the caller renders "none" rather than a stack trace."""
    try:
        capped = max(1, min(1000, int(limit)))
    except (TypeError, ValueError):
        capped = 100
    ok, payload, detail = request("GET", "/api/dcim/devices/",
                                  params={"limit": capped})
    if not ok:
        logger.info("netbox: device list failed: %s", detail)
        return []
    rows = (payload or {}).get("results") if isinstance(payload, dict) else None
    out: list[dict[str, Any]] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        out.append({
            "id": row.get("id"),
            "name": str(row.get("name") or row.get("display") or ""),
            "site": _nested_name(row.get("site")),
            "status": _nested_value(row.get("status")),
        })
    return out


def _nested_name(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("name") or value.get("display") or "")
    return str(value or "")


def _nested_value(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("value") or value.get("label") or "")
    return str(value or "")


def resolve_device(appliance: Any) -> int | None:
    """SATOM appliance -> NetBox device id, or ``None``.

    Order: the explicit :func:`device_map` (an operator decision always wins),
    then an EXACT name match, then ``None``. The name fallback insists on
    exactly one hit: two devices named the same is ambiguity, and guessing
    which one to put in a maintenance window is not this module's call."""
    appliance_id, name = _appliance_key(appliance)
    if appliance_id:
        mapped = device_map().get(appliance_id)
        if mapped:
            return mapped
    if not name:
        return None
    ok, payload, detail = request("GET", "/api/dcim/devices/",
                                  params={"name": name, "limit": 2})
    if not ok:
        logger.info("netbox: name lookup for %r failed: %s", name, detail)
        return None
    rows = (payload or {}).get("results") if isinstance(payload, dict) else None
    exact = [r for r in (rows or [])
             if isinstance(r, dict) and str(r.get("name") or "") == name]
    if len(exact) != 1:
        return None
    try:
        return int(exact[0].get("id"))
    except (TypeError, ValueError):
        return None


def _appliance_key(appliance: Any) -> tuple[str, str]:
    """``(appliance_id_str, name)`` from a model instance, a dict, or an id."""
    if appliance is None:
        return "", ""
    if isinstance(appliance, dict):
        raw_id, raw_name = appliance.get("id"), appliance.get("name")
    elif isinstance(appliance, (int, str)):
        raw_id, raw_name = appliance, ""
    else:
        raw_id = getattr(appliance, "id", None)
        raw_name = getattr(appliance, "name", "")
    try:
        appliance_id = str(int(str(raw_id).strip())) if raw_id not in (None, "") else ""
    except (TypeError, ValueError):
        appliance_id = ""
    return appliance_id, str(raw_name or "").strip()


# ---------------------------------------------------------------------------
#  maintenance windows
# ---------------------------------------------------------------------------
def _fail(backend: str, detail: str) -> dict[str, Any]:
    """A failed window op. ``ref`` is EMPTY — a caller storing the ref can
    never mistake a failure for a success it can later close."""
    return {"ok": False, "ref": "", "detail": detail, "backend": backend}


def _target_device(appliance_id: Any) -> tuple[int, str]:
    """``(device_id, error)``. Accepts a SATOM appliance id (resolved through
    :func:`device_map`) or an appliance object/dict (which may also fall back
    to a name lookup)."""
    if isinstance(appliance_id, (int, str)):
        key, _ = _appliance_key(appliance_id)
        if not key:
            return 0, f"{appliance_id!r} is not a usable SATOM appliance id."
        mapped = device_map().get(key)
        if not mapped:
            return 0, (f"SATOM appliance {key} is not mapped to a NetBox device "
                       f"({K_DEVICE_MAP}). Map it in Settings → Integrations first.")
        return mapped, ""
    resolved = resolve_device(appliance_id)
    if not resolved:
        key, name = _appliance_key(appliance_id)
        return 0, (f"Could not resolve SATOM appliance {key or '?'} "
                   f"({name or 'unnamed'}) to a NetBox device.")
    return resolved, ""


def open_window(appliance_id: Any, *, cr_id: Any, title: str,
                start: Any, end: Any, reason: str) -> dict[str, Any]:
    """Record the START of a maintenance window in NetBox.

    Returns ``{"ok", "ref", "detail", "backend"}``. Keep ``ref`` — it is the
    ONLY handle :func:`close_window` accepts, and it encodes which backend
    opened the window."""
    cfg = config()
    backend = cfg["mw_backend"]

    blocked = _gate(config(reveal=True))
    if blocked:
        return _fail(backend, blocked)

    iso_start, iso_end = _iso_utc(start), _iso_utc(end)
    if not iso_start or not iso_end:
        bad = "start" if not iso_start else "end"
        return _fail(backend,
                     f"Maintenance window {bad} time {(start if bad == 'start' else end)!r} "
                     f"is not a usable datetime; refusing to send an ambiguous "
                     f"timestamp to NetBox.")

    device_id, err = _target_device(appliance_id)
    if err:
        return _fail(backend, err)

    if backend == "tag":
        return _open_tag(device_id, backend)
    if backend == "custom_field":
        return _open_custom_field(device_id, backend, iso_start, iso_end)
    return _open_journal(device_id, backend, cr_id, title,
                         iso_start, iso_end, reason)


def close_window(ref: str, *, ok: bool, summary: str) -> dict[str, Any]:
    """Record the END of the window identified by *ref*.

    ``ok`` is the outcome of the WORK, not of this call: the returned
    ``{"ok": ...}`` is whether NetBox was updated."""
    backend, ident = parse_ref(ref)
    if not backend:
        return {"ok": False,
                "detail": (f"{ref!r} is not a maintenance-window reference "
                           f"(expected journal:<id>, tag:<id> or cf:<id>).")}
    blocked = _gate(config(reveal=True))
    if blocked:
        return {"ok": False, "detail": blocked}
    if backend == "tag":
        return _close_tag(ident)
    if backend == "custom_field":
        return _close_custom_field(ident)
    return _close_journal(ident, ok, summary)


# -- journal ----------------------------------------------------------------
def _open_journal(device_id: int, backend: str, cr_id: Any, title: str,
                  iso_start: str, iso_end: str, reason: str) -> dict[str, Any]:
    comments = "\n".join([
        "SATOM maintenance window OPEN",
        f"CR: {cr_id or '—'}",
        f"Title: {title or '—'}",
        f"Start: {iso_start}",
        f"End: {iso_end}",
        f"Reason: {reason or '—'}",
    ])
    ok, payload, detail = request("POST", "/api/extras/journal-entries/", json={
        "assigned_object_type": DEVICE_CT,
        "assigned_object_id": device_id,
        "kind": "warning",          # a device in a window wants attention
        "comments": comments,
    })
    if not ok:
        return _fail(backend, detail)
    entry_id = (payload or {}).get("id") if isinstance(payload, dict) else None
    ref = make_ref("journal", entry_id)
    if not ref:
        return _fail(backend, "NetBox accepted the journal entry but returned no id.")
    return {"ok": True, "ref": ref, "backend": backend,
            "detail": f"Maintenance window opened on NetBox device {device_id} "
                      f"(journal entry {entry_id})."}


def _close_journal(entry_id: int, work_ok: bool, summary: str) -> dict[str, Any]:
    """Post a SECOND entry referencing the first. The opening entry is never
    touched — see the module docstring."""
    ok, payload, detail = request("GET", f"/api/extras/journal-entries/{entry_id}/")
    if not ok:
        return {"ok": False,
                "detail": f"Could not read opening journal entry {entry_id}: {detail}"}
    device_id = (payload or {}).get("assigned_object_id") if isinstance(payload, dict) else None
    if not device_id:
        return {"ok": False,
                "detail": (f"Journal entry {entry_id} is not assigned to a device; "
                           f"refusing to guess which device the window belonged to.")}
    comments = "\n".join([
        f"SATOM maintenance window CLOSE (opened by journal entry #{entry_id})",
        f"Result: {'OK' if work_ok else 'FAILED'}",
        f"Summary: {summary or '—'}",
    ])
    ok, payload, detail = request("POST", "/api/extras/journal-entries/", json={
        "assigned_object_type": DEVICE_CT,
        "assigned_object_id": device_id,
        "kind": "success" if work_ok else "danger",
        "comments": comments,
    })
    if not ok:
        return {"ok": False, "detail": detail}
    new_id = (payload or {}).get("id") if isinstance(payload, dict) else None
    return {"ok": True,
            "detail": f"Maintenance window closed on NetBox device {device_id} "
                      f"(journal entry {new_id} references {entry_id})."}


# -- tag --------------------------------------------------------------------
def _ensure_tag() -> tuple[bool, str]:
    ok, payload, detail = request("GET", "/api/extras/tags/",
                                  params={"slug": MAINT_TAG_SLUG, "limit": 1})
    if not ok:
        return False, detail
    results = (payload or {}).get("results") if isinstance(payload, dict) else None
    if results:
        return True, ""
    # NetBox requires BOTH name and slug on create (verified: a name-only POST
    # returns 400 {"slug": ["This field is required."]}).
    ok, _payload, detail = request("POST", "/api/extras/tags/", json={
        "name": MAINT_TAG_NAME, "slug": MAINT_TAG_SLUG,
        "description": "SATOM: device is inside a maintenance window",
    })
    return (True, "") if ok else (False, f"Could not create the {MAINT_TAG_NAME!r} tag: {detail}")


def _device_tag_names(device_id: int) -> tuple[list[str] | None, str]:
    ok, payload, detail = request("GET", f"/api/dcim/devices/{device_id}/")
    if not ok:
        return None, detail
    tags = (payload or {}).get("tags") if isinstance(payload, dict) else None
    names: list[str] = []
    for tag in tags or []:
        name = tag.get("name") if isinstance(tag, dict) else tag
        if name:
            names.append(str(name))
    return names, ""


def _patch_device_tags(device_id: int, names: list[str]) -> tuple[bool, str]:
    # NetBox REPLACES the tag list on PATCH, so the full desired set is sent —
    # never just the one tag, or every other tag on the customer's device
    # silently disappears.
    ok, _payload, detail = request(
        "PATCH", f"/api/dcim/devices/{device_id}/",
        json={"tags": [{"name": n} for n in names]})
    return ok, detail


def _open_tag(device_id: int, backend: str) -> dict[str, Any]:
    ok, detail = _ensure_tag()
    if not ok:
        return _fail(backend, detail)
    names, detail = _device_tag_names(device_id)
    if names is None:
        return _fail(backend, detail)
    if MAINT_TAG_NAME not in names:
        names = names + [MAINT_TAG_NAME]
    ok, detail = _patch_device_tags(device_id, names)
    if not ok:
        return _fail(backend, detail)
    return {"ok": True, "ref": make_ref("tag", device_id), "backend": backend,
            "detail": (f"NetBox device {device_id} tagged {MAINT_TAG_NAME!r}. "
                       f"NOTE: the tag backend records THAT a window is open, "
                       f"not which one — the CR id, start and end are not stored.")}


def _close_tag(device_id: int) -> dict[str, Any]:
    names, detail = _device_tag_names(device_id)
    if names is None:
        return {"ok": False, "detail": detail}
    remaining = [n for n in names if n != MAINT_TAG_NAME]
    if len(remaining) == len(names):
        return {"ok": True,
                "detail": (f"NetBox device {device_id} was not tagged "
                           f"{MAINT_TAG_NAME!r}; nothing to remove.")}
    ok, detail = _patch_device_tags(device_id, remaining)
    if not ok:
        return {"ok": False, "detail": detail}
    return {"ok": True,
            "detail": f"{MAINT_TAG_NAME!r} removed from NetBox device {device_id}."}


# -- custom_field -----------------------------------------------------------
def _missing_custom_fields() -> tuple[list[str], str]:
    """Which of the two window custom fields this NetBox does NOT define."""
    ok, payload, detail = request("GET", "/api/extras/custom-fields/",
                                  params={"limit": 500})
    if not ok:
        return [], detail
    defined = set()
    rows = (payload or {}).get("results") if isinstance(payload, dict) else None
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        types = row.get("object_types") or []
        applies = (not types) or any(str(t) == DEVICE_CT for t in types)
        if applies and row.get("name"):
            defined.add(str(row["name"]))
    return [f for f in (CF_START, CF_END) if f not in defined], ""


def _open_custom_field(device_id: int, backend: str,
                       iso_start: str, iso_end: str) -> dict[str, Any]:
    missing, detail = _missing_custom_fields()
    if detail:
        return _fail(backend, detail)
    if missing:
        # NAME the field. NetBox's own 400 says the same thing, but the
        # pre-check means we say it before touching the customer's device,
        # and we never treat "field absent" as a quiet success.
        return _fail(backend, (
            f"NetBox has no custom field(s) {', '.join(repr(m) for m in missing)} "
            f"on {DEVICE_CT}. Create them (type: date/time) in NetBox → "
            f"Customization → Custom Fields, or switch the maintenance-window "
            f"backend. Nothing was written."))
    ok, _payload, detail = request(
        "PATCH", f"/api/dcim/devices/{device_id}/",
        json={"custom_fields": {CF_START: iso_start, CF_END: iso_end}})
    if not ok:
        return _fail(backend, detail)
    return {"ok": True, "ref": make_ref("custom_field", device_id), "backend": backend,
            "detail": (f"Maintenance window {iso_start} → {iso_end} written to "
                       f"NetBox device {device_id} custom fields.")}


def _close_custom_field(device_id: int) -> dict[str, Any]:
    ok, _payload, detail = request(
        "PATCH", f"/api/dcim/devices/{device_id}/",
        json={"custom_fields": {CF_START: None, CF_END: None}})
    if not ok:
        return {"ok": False, "detail": detail}
    return {"ok": True,
            "detail": f"Maintenance window cleared on NetBox device {device_id}."}


__all__ = [
    "K_ENABLED", "K_URL", "K_TOKEN", "K_VERIFY_TLS", "K_TIMEOUT",
    "K_MW_BACKEND", "K_DEVICE_MAP",
    "MW_BACKENDS", "MW_BACKEND_SLUGS", "DEFAULT_MW_BACKEND",
    "DEFAULT_TIMEOUT", "MIN_TIMEOUT", "MAX_TIMEOUT",
    "DETAIL_DISABLED", "DETAIL_NOT_CONFIGURED", "DETAIL_UNREACHABLE",
    "DETAIL_TIMEOUT", "DETAIL_AUTH", "DETAIL_HTTP", "REDACTED",
    "MAINT_TAG_NAME", "CF_START", "CF_END",
    "config", "save_config", "is_configured",
    "device_map", "save_device_map",
    "make_ref", "parse_ref",
    "request", "test_connection", "list_devices", "resolve_device",
    "open_window", "close_window",
]
