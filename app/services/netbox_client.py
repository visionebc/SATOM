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
K_DEVICE_MAP = "integrations.netbox.device_map"  # JSON {appliance_id: "7" | "vm:95"}

# ---- maintenance-window backends ------------------------------------------
# (slug, human label) — the Settings → Integrations dropdown renders these.
# There is deliberately NO "plugin" entry: see the module docstring.
MW_BACKENDS: tuple[tuple[str, str], ...] = (
    ("journal", "Journal entry (core, append-only — full detail, not filterable)"),
    ("tag", "Object tag (core, filterable — lossy: no CR, no times)"),
    ("custom_field", "Object custom fields (structured + filterable — needs schema)"),
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
VM_CT = "virtualization.virtualmachine"

# A window target is (kind, id) -- NEVER an id on its own. NetBox models a
# virtual machine as a different object type from a device: different API
# path, different content type, and a SEPARATE id space. VM 95 and device 95
# are two unrelated objects, so a ref that carried only "95" would let a
# window opened on a VM be closed against somebody else's device.
KIND_DEVICE = "device"
KIND_VM = "vm"
KINDS: tuple[str, ...] = (KIND_DEVICE, KIND_VM)
_KIND_PATH = {KIND_DEVICE: "/api/dcim/devices/",
              KIND_VM: "/api/virtualization/virtual-machines/"}
_KIND_CT = {KIND_DEVICE: DEVICE_CT, KIND_VM: VM_CT}
_CT_KIND = {DEVICE_CT: KIND_DEVICE, VM_CT: KIND_VM}
_KIND_LABEL = {KIND_DEVICE: "device", KIND_VM: "virtual machine"}


def object_path(kind: str, obj_id: Any) -> str:
    """Detail URL for a target, or "" when the kind is not one we serve."""
    base = _KIND_PATH.get(str(kind or "").strip())
    try:
        num = int(str(obj_id).strip())
    except (TypeError, ValueError):
        return ""
    return f"{base}{num}/" if base and num > 0 else ""


def kind_label(kind: str) -> str:
    """"device" / "virtual machine", for a sentence an operator reads."""
    return _KIND_LABEL.get(str(kind or "").strip(), "object")


def target_text(kind: str, obj_id: Any) -> str:
    """``("device", 7) -> "7"``; ``("vm", 95) -> "vm:95"``.

    A device stays a BARE NUMBER so every mapping written before virtual
    machines were supported keeps rendering, and meaning, exactly what it
    did."""
    try:
        num = int(str(obj_id).strip())
    except (TypeError, ValueError):
        return ""
    if num <= 0 or str(kind) not in KINDS:
        return ""
    return str(num) if kind == KIND_DEVICE else f"{KIND_VM}:{num}"


def parse_target(text: Any) -> tuple[str, int]:
    """``"7" -> ("device", 7)``; ``"vm:95" -> ("vm", 95)``; ``("", 0)`` else.

    Single author of "what object is this", used by the stored map, the refs
    and the settings form -- three spellings of it is how a window comes to be
    opened on one object and closed on another."""
    raw = str(text if text is not None else "").strip()
    if not raw:
        return "", 0
    kind = KIND_DEVICE
    if ":" in raw:
        prefix, _, rest = raw.partition(":")
        kind = prefix.strip().lower()
        raw = rest.strip()
        if kind not in KINDS:
            return "", 0
    try:
        num = int(raw)
    except (TypeError, ValueError):
        return "", 0
    return (kind, num) if num > 0 else ("", 0)
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
def device_map() -> dict[str, str]:
    """SATOM appliance id (str) -> NetBox target text (``"7"`` / ``"vm:95"``).

    The value is TEXT, not an int, because a NetBox id is only half an
    address: the same number is a different object depending on whether it
    names a device or a virtual machine. A bare number still means a device,
    so maps written before VM support keep their meaning.

    Rows that cannot be parsed are DROPPED rather than guessed at: a bad row
    that resolved to some other integer would point a maintenance window at
    the wrong customer object."""
    raw = store.get_json(K_DEVICE_MAP, {})
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for key, val in raw.items():
        kind, obj_id = parse_target(val)
        appliance = str(key).strip()
        if appliance and obj_id:
            out[appliance] = target_text(kind, obj_id)
    return out


def is_mapped(appliance_id: Any) -> bool:
    """True when an operator has EXPLICITLY bound this appliance to a device id.

    This is the cheap half of the question only. It is NOT "can a window be
    opened": :func:`resolve_plan` also matches an exact object name, which is
    the documented fallback the Integrations page promises. Gating a button on
    this alone switches it off for every appliance NetBox documents under its
    own name -- which is what it did until 2026-09-21. Ask
    :func:`resolve_plan`; this stays for the settings page, which really is
    asking about the stored map."""
    key, _ = _appliance_key(appliance_id)
    return bool(key and device_map().get(key))


def save_device_map(pairs: Mapping[str, Any]) -> None:
    """Validate and persist the appliance->device mapping.

    Raises ``ValueError`` NAMING the offending key/value — this is a settings
    form check, so the operator gets told which row is wrong instead of having
    it silently dropped. A blank value means "unmapped" and is dropped: storing
    it as ``0`` would be a real NetBox object id nobody chose."""
    if not isinstance(pairs, Mapping):
        raise ValueError("device_map must be a mapping of appliance id -> NetBox target.")
    out: dict[str, str] = {}
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
        kind, device_id = parse_target(raw)
        if not kind or device_id <= 0:
            raise ValueError(
                f"device_map[{key!r}] = {val!r} is not a NetBox target: expected a "
                f"device id like '7', or a virtual machine like 'vm:95'."
            ) from None
        if appliance_id <= 0:
            raise ValueError(f"device_map key {key!r} is not a positive appliance id.")
        out[str(appliance_id)] = target_text(kind, device_id)
    store.set_json(K_DEVICE_MAP, out)


# ---------------------------------------------------------------------------
#  reconciliation, in bounded rounds
# ---------------------------------------------------------------------------
#: How many appliances ONE round asks NetBox about. A round is bounded because
#: its answer is WRITTEN to the device map: on a large fleet an unbounded sweep
#: is one request that either times out or rewrites the whole map in one go,
#: and neither is something an operator can watch converge.
DEFAULT_PER_ROUND = 25
MAX_PER_ROUND = 500


def clamp_per_round(value: Any, default: int = DEFAULT_PER_ROUND) -> int:
    """Round size within [1, MAX_PER_ROUND]; anything unreadable -> default."""
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(1, min(MAX_PER_ROUND, n))


def reconcile(*, per_round: Any = None, appliances: Any = None,
              dry_run: bool = False) -> dict[str, Any]:
    """Bind the still-unmapped appliances that NetBox already documents.

    ONE ROUND = at most ``per_round`` appliances, lowest id first, taken ONLY
    from those with no explicit map entry. What NetBox answers by name is
    written into the map as an explicit (kind, id) target -- that is what makes
    the binding survive a rename on either side, which the name fallback does
    not.

    Three outcomes are kept apart on purpose:

    * **mapped** -- NetBox answered with exactly one object; written.
    * **unresolved** -- NetBox answered, and has no such object (or has more
      than one). Reported BY NAME, never as a count: a number sends nobody
      anywhere.
    * **not checked** -- NetBox could not be asked at all (disabled, down,
      timeout). NOTHING is written and ``checked`` is False. Unknown is not
      absent: a round that turned an outage into "NetBox documents none of
      these" would let an outage rewrite the operator's inventory.

    Creates NOTHING in NetBox, and never drops a map row somebody wrote: the
    round's pairs are MERGED onto the stored map.
    """
    from ..models import Appliance

    limit = clamp_per_round(per_round)
    rows = list(appliances) if appliances is not None else (
        Appliance.query.order_by(Appliance.id.asc()).all())
    mapping = device_map()
    pending = [a for a in rows if str(getattr(a, "id", "") or "") not in mapping]
    batch = pending[:limit]
    out: dict[str, Any] = {
        "checked": True, "error": "", "per_round": limit,
        "fleet": len(rows), "pending": len(pending), "scanned": len(batch),
        "mapped": [], "unresolved": [], "unknown": [],
        "remaining": max(0, len(pending) - len(batch)),
        "dry_run": bool(dry_run), "log": "",
    }
    if not batch:
        return out

    blocked = _gate(config(reveal=True))
    if blocked:
        # Disabled or unconfigured: nothing was asked, so nothing is claimed.
        out["checked"], out["error"] = False, blocked
        return out

    plan = resolve_plan(batch)
    pairs: dict[str, str] = {}
    lines: list[str] = []
    first_error = ""
    for slot, entry in plan.items():
        name = entry.get("name") or slot
        detail = entry.get("error") or ""
        if not entry.get("checked"):
            out["unknown"].append(name)
            first_error = first_error or detail
            lines.append("%s: not checked - %s" % (name, detail))
            continue
        key = str(entry.get("id") or "")
        try:
            obj_id = int(entry.get("device_id") or 0)
        except (TypeError, ValueError):
            obj_id = 0
        if key and obj_id > 0:
            kind = entry.get("kind") or KIND_DEVICE
            pairs[key] = target_text(kind, obj_id)
            out["mapped"].append("%s -> %s %d" % (name, kind_label(kind), obj_id))
            lines.append("%s: %s %d (via %s)"
                         % (name, kind_label(kind), obj_id, entry.get("via") or "?"))
        else:
            out["unresolved"].append(name)
            lines.append("%s: unresolved - %s" % (name, detail))

    if batch and len(out["unknown"]) == len(batch):
        # Not one appliance got an answer: the round did not happen.
        out["checked"] = False
        out["error"] = first_error or DETAIL_UNREACHABLE
    elif pairs and not dry_run:
        merged = dict(device_map())
        merged.update(pairs)
        save_device_map(merged)
    out["log"] = "\n".join(lines)[:4000]
    return out


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


def make_ref(backend: str, ident: Any, kind: str = KIND_DEVICE) -> str:
    """``("journal", 12) -> "journal:12"``; ``("tag", 95, "vm") -> "tag:vm:95"``.

    A DEVICE ref keeps its old two-part shape, so every window opened before
    virtual machines were supported still parses and still closes. The kind is
    spelled out only when it is not the historical default -- which is exactly
    the case that would otherwise be closed against the wrong object."""
    prefix = _REF_PREFIX.get(str(backend or "").strip())
    try:
        num = int(str(ident).strip())
    except (TypeError, ValueError):
        return ""
    if not prefix or num <= 0:
        return ""
    if str(kind) not in KINDS:
        return ""
    if backend == "journal" or kind == KIND_DEVICE:
        # A journal entry id is kind-free: the entry itself records which
        # object it is assigned to, and that is what close reads.
        return f"{prefix}:{num}"
    return f"{prefix}:{kind}:{num}"


def parse_ref(ref: str) -> tuple[str, str, int]:
    """``"journal:12" -> ("journal", "device", 12)``; ``"tag:vm:95" ->
    ("tag", "vm", 95)``; ``("", "", 0)`` when unparseable.

    A ref WITHOUT a kind is a device -- that is what every ref written before
    2026-09-21 is, and re-reading one as a virtual machine would clear a tag
    from an unrelated object.

    The BACKEND IS READ FROM THE REF, never from the current setting: an
    operator who switches ``mw_backend`` between opening and closing a window
    must still close the window the way it was opened, or the device is left
    tagged / custom-fielded forever."""
    text = str(ref or "").strip()
    if ":" not in text:
        return "", "", 0
    prefix, _, rest = text.partition(":")
    backend = _REF_KINDS.get(prefix.strip().lower(), "")
    # The remainder is read by the SAME parser the stored map uses, so
    # "vm:95" cannot mean one object in a mapping and another in a ref.
    kind, num = parse_target(rest)
    if not backend or not kind or num <= 0:
        return "", "", 0
    return backend, kind, num


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


def request(method: str, path: str, *, json=None, params=None,
            timeout: float | None = None) -> tuple[bool, Any, str]:
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
    if timeout is not None:
        # A caller may only ask for LESS time, never more: the operator's
        # configured budget is a ceiling. A page render that wants a fast
        # answer must not be able to widen a timeout an operator narrowed.
        try:
            budget = max(MIN_TIMEOUT, min(budget, int(float(timeout))))
        except (TypeError, ValueError):
            pass
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


#: The page asks this question while an operator waits for HTML, so its leg is
#: bounded tighter than a write's. It can only ever SHORTEN the configured
#: budget (see :func:`request`).
GATE_BUDGET_S = 3


def _unresolved_detail(key: str, name: str, near: str = "") -> str:
    """Why this appliance has no NetBox device, and the two ways to fix it.

    Both remedies are named because they are genuinely different situations:
    the device may not exist in NetBox at all, or it may exist under another
    name. "not mapped" alone sends an operator to a settings form to type an
    id for an object nobody has created."""
    if near:
        return (f"NetBox has no device or virtual machine named {name!r}; it "
                f"does have {near!r}, which is a DIFFERENT object - names are "
                f"matched exactly, letter for letter. Map SATOM appliance "
                f"{key or '?'} to a target in Settings -> Integrations "
                f"(a device id like '7', or a virtual machine like 'vm:95'), "
                f"or make the two names identical.")
    return (f"NetBox does not document {name or 'this appliance'}: no device "
            f"and no virtual machine is named {name!r}, and SATOM appliance "
            f"{key or '?'} is not mapped to one ({K_DEVICE_MAP}). Create it in "
            f"NetBox, or map it in Settings -> Integrations (a device id like "
            f"'7', or a virtual machine like 'vm:95').")


def resolve_plan(appliances: Any, *, budget: float | None = None) -> dict[str, dict]:
    """Resolve MANY appliances to NetBox devices in ONE lookup.

    Keyed by appliance id (or by name for an appliance without one). Each entry
    is ``{"id", "name", "device_id", "via", "error", "checked", "near"}``:

    * ``via`` is ``"map"`` (an explicit operator decision, which always wins),
      ``"name"`` (an exact device-name match) or ``""``.
    * ``checked`` is FALSE when NetBox could not be asked at all. Unknown is
      not the same answer as no: a page that turns a timeout into "NetBox does
      not document this" tells the operator their inventory is wrong when the
      truth is that the integration is down.
    * ``near`` names a case-insensitive near miss, because NetBox's ``name``
      filter is case-insensitive while this module's match is not - without it
      the operator reads "no such device" while looking straight at one in the
      NetBox UI.

    One request for N appliances: ``?name=a&name=b`` is an OR filter (measured
    against NetBox 4.6.7, 2026-09-21). Per-appliance lookups would make the
    page's cost grow with the size of the change."""
    plan: dict[str, dict] = {}
    pending: dict[str, list[str]] = {}
    mapping = device_map()
    for appliance in (appliances or []):
        key, name = _appliance_key(appliance)
        slot = key or name
        if not slot:
            continue
        entry = {"id": key, "name": name, "device_id": 0, "via": "",
                 "error": "", "checked": True, "near": "", "kind": KIND_DEVICE}
        mapped_kind, mapped = parse_target(mapping.get(key)) if key else ("", 0)
        if mapped:
            entry["device_id"], entry["via"] = mapped, "map"
            entry["kind"] = mapped_kind
        elif name:
            pending.setdefault(name, []).append(slot)
        else:
            entry["error"] = (
                f"SATOM appliance {key} is not mapped to a NetBox device "
                f"({K_DEVICE_MAP}), and no appliance name came with it to "
                f"match on. Map it in Settings -> Integrations.")
        plan[slot] = entry
    if not pending:
        return plan

    blocked = _gate(config(reveal=True))
    if blocked:
        # Not configured is UNKNOWN, not absent: nothing was asked.
        for slots in pending.values():
            for slot in slots:
                plan[slot]["checked"] = False
                plan[slot]["error"] = blocked
        return plan

    names = sorted(pending)
    exact: dict[str, list[tuple[str, int]]] = {}
    folded: dict[str, set[str]] = {}
    # Devices first, then -- only for the names it did not answer -- virtual
    # machines. On this fleet the FortiWebs are VMs on a Proxmox cluster, so a
    # device-only lookup calls a fully documented appliance undocumented
    # (measured 2026-09-21: 13 devices, 87 VMs, all four appliances VMs).
    for kind in KINDS:
        unresolved = [n for n in names if not exact.get(n)]
        if kind != KIND_DEVICE and not unresolved:
            break
        ask = names if kind == KIND_DEVICE else unresolved
        ok, payload, detail = request(
            "GET", _KIND_PATH[kind],
            params={"name": ask, "limit": max(20, len(ask) * 4)},
            timeout=budget)
        if not ok:
            logger.info("netbox: %s name lookup for %s failed: %s",
                        kind, ask, detail)
            if kind == KIND_DEVICE:
                # Nothing was answered at all: unknown, not absent.
                for slots in pending.values():
                    for slot in slots:
                        plan[slot]["checked"] = False
                        plan[slot]["error"] = detail
                return plan
            # Devices answered but VMs did not: the names still unresolved are
            # unknown, not absent. The ones a device already matched stand.
            for name in unresolved:
                for slot in pending.get(name, []):
                    plan[slot]["checked"] = False
                    plan[slot]["error"] = detail
            break
        rows = (payload or {}).get("results") if isinstance(payload, dict) else None
        for row in (rows or []):
            if not isinstance(row, dict):
                continue
            row_name = str(row.get("name") or "")
            try:
                device_id = int(row.get("id"))
            except (TypeError, ValueError):
                continue
            if not row_name or device_id <= 0:
                continue
            exact.setdefault(row_name, []).append((kind, device_id))
            folded.setdefault(row_name.casefold(), set()).add(row_name)

    for name, slots in pending.items():
        hits = exact.get(name) or []
        misses = sorted(n for n in folded.get(name.casefold(), set()) if n != name)
        for slot in slots:
            entry = plan[slot]
            if not entry["checked"]:
                continue            # the VM leg never answered for this name
            if len(hits) == 1:
                entry["kind"], entry["device_id"] = hits[0]
                entry["via"] = "name"
            elif len(hits) > 1:
                entry["error"] = (
                    f"NetBox has {len(hits)} objects named {name!r} "
                    f"({', '.join(sorted({kind_label(k) for k, _ in hits}))}); "
                    f"refusing to guess which one to put in maintenance. Map "
                    f"SATOM appliance {entry['id'] or '?'} to one in "
                    f"Settings -> Integrations.")
            else:
                entry["near"] = misses[0] if misses else ""
                entry["error"] = _unresolved_detail(entry["id"], name,
                                                    entry["near"])
    return plan


def resolve_device(appliance: Any) -> int | None:
    """SATOM appliance -> NetBox device id, or ``None``.

    Order: the explicit :func:`device_map` (an operator decision always wins),
    then an EXACT name match -- a DEVICE first, then a virtual machine -- then
    ``None``. The name fallback insists on exactly one hit: two objects named
    the same is ambiguity, and guessing which one to put in a maintenance
    window is not this module's call.

    Returns the id ONLY, so it cannot say which kind of object it found;
    callers that go on to write to NetBox must use :func:`resolve_plan`.

    Delegates to :func:`resolve_plan` rather than repeating the rules: two
    spellings of "which device is this" is how the page and the call came to
    disagree."""
    key, name = _appliance_key(appliance)
    slot = key or name
    if not slot:
        return None
    return resolve_plan([appliance]).get(slot, {}).get("device_id") or None


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
def _fail(backend: str, detail: str, *, sent: bool = True) -> dict[str, Any]:
    """A failed window op. ``ref`` is EMPTY — a caller storing the ref can
    never mistake a failure for a success it can later close.

    ``sent`` says whether this process actually transmitted anything to NetBox.
    The caller turns it into change state, and ``mw_state='error'`` is rendered
    on the change page as "a device may still be shown in maintenance there" —
    a sentence a refusal that never opened a socket may not produce. It
    DEFAULTS TO TRUE so an unknown path errs toward the cautious answer; pass
    ``sent=False`` only from a refusal raised before the request is made."""
    return {"ok": False, "ref": "", "detail": detail, "backend": backend,
            "sent": sent}


def _target_device(appliance_id: Any) -> tuple[str, int, str]:
    """``(kind, object_id, error)``. Accepts a SATOM appliance id or an appliance
    object/dict; the object also carries a name, which is what makes the
    documented exact-name fallback reachable.

    Single author with the page: both go through :func:`resolve_plan`, so a
    button that is offered and a call that refuses cannot disagree."""
    key, name = _appliance_key(appliance_id)
    if not key and not name:
        return "", 0, f"{appliance_id!r} is not a usable SATOM appliance id."
    entry = resolve_plan([appliance_id]).get(key or name) or {}
    device_id = entry.get("device_id") or 0
    kind = entry.get("kind") or KIND_DEVICE
    if device_id and kind in KINDS:
        return kind, device_id, ""
    return "", 0, entry.get("error") or _unresolved_detail(key, name)


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
        return _fail(backend, blocked, sent=False)

    iso_start, iso_end = _iso_utc(start), _iso_utc(end)
    if not iso_start or not iso_end:
        bad = "start" if not iso_start else "end"
        return _fail(backend,
                     f"Maintenance window {bad} time {(start if bad == 'start' else end)!r} "
                     f"is not a usable datetime; refusing to send an ambiguous "
                     f"timestamp to NetBox.", sent=False)

    kind, device_id, err = _target_device(appliance_id)
    if err:
        return _fail(backend, err, sent=False)

    if backend == "tag":
        res = _open_tag(kind, device_id, backend)
    elif backend == "custom_field":
        res = _open_custom_field(kind, device_id, backend, iso_start, iso_end)
    else:
        res = _open_journal(kind, device_id, backend, cr_id, title,
                            iso_start, iso_end, reason)
    # Past _target_device every path went through request(): the call WAS made,
    # whatever came back. A timeout counts as sent — NetBox may have applied the
    # window before the read leg gave up. Stamped here, once, so a backend added
    # later cannot forget to answer the question.
    res.setdefault("sent", True)
    return res


def close_window(ref: str, *, ok: bool, summary: str) -> dict[str, Any]:
    """Record the END of the window identified by *ref*.

    ``ok`` is the outcome of the WORK, not of this call: the returned
    ``{"ok": ...}`` is whether NetBox was updated."""
    backend, kind, ident = parse_ref(ref)
    if not backend:
        return {"ok": False,
                "detail": (f"{ref!r} is not a maintenance-window reference "
                           f"(expected journal:<id>, tag:[vm:]<id> or "
                           f"cf:[vm:]<id>).")}
    blocked = _gate(config(reveal=True))
    if blocked:
        return {"ok": False, "detail": blocked}
    if backend == "tag":
        return _close_tag(kind, ident)
    if backend == "custom_field":
        return _close_custom_field(kind, ident)
    return _close_journal(ident, ok, summary)


# -- journal ----------------------------------------------------------------
def _open_journal(kind: str, device_id: int, backend: str, cr_id: Any,
                  title: str, iso_start: str, iso_end: str,
                  reason: str) -> dict[str, Any]:
    comments = "\n".join([
        "SATOM maintenance window OPEN",
        f"CR: {cr_id or '—'}",
        f"Title: {title or '—'}",
        f"Start: {iso_start}",
        f"End: {iso_end}",
        f"Reason: {reason or '—'}",
    ])
    ok, payload, detail = request("POST", "/api/extras/journal-entries/", json={
        "assigned_object_type": _KIND_CT.get(kind, DEVICE_CT),
        "assigned_object_id": device_id,
        "kind": "warning",          # an object in a window wants attention
        "comments": comments,
    })
    if not ok:
        return _fail(backend, detail)
    entry_id = (payload or {}).get("id") if isinstance(payload, dict) else None
    ref = make_ref("journal", entry_id, kind)
    if not ref:
        return _fail(backend, "NetBox accepted the journal entry but returned no id.")
    return {"ok": True, "ref": ref, "backend": backend,
            "detail": f"Maintenance window opened on NetBox "
                      f"{kind_label(kind)} {device_id} "
                      f"(journal entry {entry_id})."}


def _close_journal(entry_id: int, work_ok: bool, summary: str) -> dict[str, Any]:
    """Post a SECOND entry referencing the first. The opening entry is never
    touched — see the module docstring."""
    ok, payload, detail = request("GET", f"/api/extras/journal-entries/{entry_id}/")
    if not ok:
        return {"ok": False,
                "detail": f"Could not read opening journal entry {entry_id}: {detail}"}
    device_id = (payload or {}).get("assigned_object_id") if isinstance(payload, dict) else None
    # The closing note is assigned to WHATEVER the opening note was assigned
    # to, read back from NetBox. Hardcoding the device type here would file the
    # close against a device that merely shares the virtual machine's number.
    object_ct = (payload or {}).get("assigned_object_type") if isinstance(payload, dict) else None
    object_ct = str(object_ct or DEVICE_CT)
    if object_ct not in _CT_KIND:
        return {"ok": False,
                "detail": (f"Journal entry {entry_id} is assigned to a "
                           f"{object_ct!r}, which SATOM does not put in "
                           f"maintenance; refusing to write to it.")}
    if not device_id:
        return {"ok": False,
                "detail": (f"Journal entry {entry_id} is not assigned to an object; "
                           f"refusing to guess which one the window belonged to.")}
    comments = "\n".join([
        f"SATOM maintenance window CLOSE (opened by journal entry #{entry_id})",
        f"Result: {'OK' if work_ok else 'FAILED'}",
        f"Summary: {summary or '—'}",
    ])
    ok, payload, detail = request("POST", "/api/extras/journal-entries/", json={
        "assigned_object_type": object_ct,
        "assigned_object_id": device_id,
        "kind": "success" if work_ok else "danger",
        "comments": comments,
    })
    if not ok:
        return {"ok": False, "detail": detail}
    new_id = (payload or {}).get("id") if isinstance(payload, dict) else None
    return {"ok": True,
            "detail": f"Maintenance window closed on NetBox "
                      f"{kind_label(_CT_KIND[object_ct])} {device_id} "
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


def _device_tag_names(kind: str, device_id: int) -> tuple[list[str] | None, str]:
    path = object_path(kind, device_id)
    if not path:
        return None, f"{kind!r} is not a NetBox object kind SATOM can address."
    ok, payload, detail = request("GET", path)
    if not ok:
        return None, detail
    tags = (payload or {}).get("tags") if isinstance(payload, dict) else None
    names: list[str] = []
    for tag in tags or []:
        name = tag.get("name") if isinstance(tag, dict) else tag
        if name:
            names.append(str(name))
    return names, ""


def _patch_device_tags(kind: str, device_id: int,
                       names: list[str]) -> tuple[bool, str]:
    # NetBox REPLACES the tag list on PATCH, so the full desired set is sent —
    # never just the one tag, or every other tag on the customer's object
    # silently disappears.
    path = object_path(kind, device_id)
    if not path:
        return False, f"{kind!r} is not a NetBox object kind SATOM can address."
    ok, _payload, detail = request(
        "PATCH", path, json={"tags": [{"name": n} for n in names]})
    return ok, detail


def _open_tag(kind: str, device_id: int, backend: str) -> dict[str, Any]:
    ok, detail = _ensure_tag()
    if not ok:
        return _fail(backend, detail)
    names, detail = _device_tag_names(kind, device_id)
    if names is None:
        return _fail(backend, detail)
    if MAINT_TAG_NAME not in names:
        names = names + [MAINT_TAG_NAME]
    ok, detail = _patch_device_tags(kind, device_id, names)
    if not ok:
        return _fail(backend, detail)
    return {"ok": True, "ref": make_ref("tag", device_id, kind), "backend": backend,
            "detail": (f"NetBox {kind_label(kind)} {device_id} tagged "
                       f"{MAINT_TAG_NAME!r}. "
                       f"NOTE: the tag backend records THAT a window is open, "
                       f"not which one — the CR id, start and end are not stored.")}


def _close_tag(kind: str, device_id: int) -> dict[str, Any]:
    names, detail = _device_tag_names(kind, device_id)
    if names is None:
        return {"ok": False, "detail": detail}
    remaining = [n for n in names if n != MAINT_TAG_NAME]
    if len(remaining) == len(names):
        return {"ok": True,
                "detail": (f"NetBox {kind_label(kind)} {device_id} was not tagged "
                           f"{MAINT_TAG_NAME!r}; nothing to remove.")}
    ok, detail = _patch_device_tags(kind, device_id, remaining)
    if not ok:
        return {"ok": False, "detail": detail}
    return {"ok": True,
            "detail": (f"{MAINT_TAG_NAME!r} removed from NetBox "
                       f"{kind_label(kind)} {device_id}.")}


# -- custom_field -----------------------------------------------------------
def _missing_custom_fields(kind: str = KIND_DEVICE) -> tuple[list[str], str]:
    """Which of the two window custom fields this NetBox does NOT define ON
    THE TARGET'S OWN OBJECT TYPE. A field defined for devices does not exist
    on a virtual machine, and NetBox would answer a PATCH naming it with a
    400 the operator has no way to read as "wrong object type"."""
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
        want = _KIND_CT.get(kind, DEVICE_CT)
        applies = (not types) or any(str(t) == want for t in types)
        if applies and row.get("name"):
            defined.add(str(row["name"]))
    return [f for f in (CF_START, CF_END) if f not in defined], ""


def _open_custom_field(kind: str, device_id: int, backend: str,
                       iso_start: str, iso_end: str) -> dict[str, Any]:
    missing, detail = _missing_custom_fields(kind)
    if detail:
        return _fail(backend, detail)
    if missing:
        # NAME the field. NetBox's own 400 says the same thing, but the
        # pre-check means we say it before touching the customer's device,
        # and we never treat "field absent" as a quiet success.
        return _fail(backend, (
            f"NetBox has no custom field(s) {', '.join(repr(m) for m in missing)} "
            f"on {_KIND_CT.get(kind, DEVICE_CT)}. Create them (type: date/time) "
            f"in NetBox → Customization → Custom Fields, or switch the "
            f"maintenance-window backend. Nothing was written."))
    path = object_path(kind, device_id)
    if not path:
        return _fail(backend,
                     f"{kind!r} is not a NetBox object kind SATOM can address.",
                     sent=False)
    ok, _payload, detail = request(
        "PATCH", path,
        json={"custom_fields": {CF_START: iso_start, CF_END: iso_end}})
    if not ok:
        return _fail(backend, detail)
    return {"ok": True, "ref": make_ref("custom_field", device_id, kind),
            "backend": backend,
            "detail": (f"Maintenance window {iso_start} → {iso_end} written to "
                       f"NetBox {kind_label(kind)} {device_id} custom fields.")}


def _close_custom_field(kind: str, device_id: int) -> dict[str, Any]:
    path = object_path(kind, device_id)
    if not path:
        return {"ok": False,
                "detail": f"{kind!r} is not a NetBox object kind SATOM can address."}
    ok, _payload, detail = request(
        "PATCH", path,
        json={"custom_fields": {CF_START: None, CF_END: None}})
    if not ok:
        return {"ok": False, "detail": detail}
    return {"ok": True,
            "detail": (f"Maintenance window cleared on NetBox "
                       f"{kind_label(kind)} {device_id}.")}


__all__ = [
    "K_ENABLED", "K_URL", "K_TOKEN", "K_VERIFY_TLS", "K_TIMEOUT",
    "K_MW_BACKEND", "K_DEVICE_MAP", "VM_CT", "KIND_DEVICE", "KIND_VM", "KINDS",
    "object_path", "kind_label", "target_text", "parse_target",
    "MW_BACKENDS", "MW_BACKEND_SLUGS", "DEFAULT_MW_BACKEND",
    "DEFAULT_TIMEOUT", "MIN_TIMEOUT", "MAX_TIMEOUT",
    "DETAIL_DISABLED", "DETAIL_NOT_CONFIGURED", "DETAIL_UNREACHABLE",
    "DETAIL_TIMEOUT", "DETAIL_AUTH", "DETAIL_HTTP", "REDACTED",
    "MAINT_TAG_NAME", "CF_START", "CF_END",
    "config", "save_config", "is_configured",
    "device_map", "save_device_map",
    "DEFAULT_PER_ROUND", "MAX_PER_ROUND", "clamp_per_round", "reconcile",
    "make_ref", "parse_ref",
    "request", "test_connection", "list_devices", "resolve_device",
    "open_window", "close_window",
]
