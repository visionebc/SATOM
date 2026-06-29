"""Fleet-wide FortiWeb object browser — LIVE aggregation across appliances.

Web port of the desktop app's ``settings_page._fleet_objects_page`` /
``_FLEET_OBJECT_TYPES``. The desktop reads a *local object cache* (the v10/v11
hybrid projections in its store); this web version instead aggregates the same
object types **live** across every FortiWeb appliance — it calls each device's
REST API, normalises the cmdb objects into flat rows and tags every row with the
owning ``device``.

Four modes (mirroring the desktop):
  * ``server_policy`` — Server Policy table
  * ``wpp``           — Web Protection Profile table
  * ``server_pool``   — Server Pool table
  * ``search``        — generic "find any value in any field of any object"

Each typed mode declares its columns and a couple of filterable columns; the
``search`` mode flattens every collected object into (device, section, type,
object, field, value) rows and substring-matches the query.

Live reads are wrapped per-device (one dead appliance can't break the page) and
memoised in the short-TTL process cache so repeated page loads / filter changes
don't hammer the devices. The live cmdb field names differ from the desktop's
normalised snake_case keys, so every column maps to a *list* of candidate source
keys (hyphenated live key first); a missing key simply renders blank.
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any

from ..clients.fortiweb import FortiWebClient
from ..models import Appliance
from .cache import cache_get, cache_set

# Short TTL so the typed tables / filter dropdowns / search reuse one set of
# device reads instead of re-querying every appliance on each interaction.
CACHE_TTL: int = 60
# Hard cap on generic-search result rows (mirrors the desktop's limit=500).
SEARCH_LIMIT: int = 1000

DEVICE_COLUMN: tuple[str, str] = ("device", "Device")
DEFAULT_TYPE: str = "server_policy"

# Object-type catalogue. Each typed entry carries:
#   label       friendly name (type switcher + search "Type" column)
#   method      FortiWebClient method that lists the objects
#   cache_key   per-appliance cache slot
#   section     cmdb-ish section name (search "Section" column)
#   columns     (key, label, [candidate source keys]) — "device" is prepended
#               automatically by columns_for(); the first present, non-empty
#               source key wins. Hyphenated live keys come first, then the
#               desktop's snake_case fallbacks.
#   filters     (key, label) of the columns exposed as filter dropdowns.
# The "search" entry is special (search=True): its columns are the flattened
# field view and it has no typed query.
TYPES: dict[str, dict[str, Any]] = {
    "server_policy": {
        "label": "Server Policy",
        "method": "list_server_policies",
        "cache_key": "fleet:server_policies",
        "section": "server-policy",
        "columns": [
            ("name", "Name", ["name", "mkey"]),
            ("deployment_mode", "Deployment mode", ["deployment-mode", "deployment_mode"]),
            ("vserver", "Virtual server", ["vserver", "vs"]),
            ("server_pool", "Server pool", ["server-pool", "server_pool", "pool"]),
            ("web_protection_profile", "Web Protection Profile",
             ["web-protection-profile", "web_protection_profile", "wpp"]),
            ("status", "Status", ["status", "enable"]),
        ],
        "filters": [
            ("deployment_mode", "Mode"),
            ("status", "Status"),
            ("web_protection_profile", "WPP"),
        ],
    },
    "wpp": {
        "label": "Web Protection Profile",
        "method": "list_wpp",
        "cache_key": "fleet:wpp",
        "section": "web-protection-profile",
        "columns": [
            ("name", "Name", ["name", "mkey"]),
            ("kind", "Kind", ["kind", "type", "profile-type"]),
            ("signature_rule", "Signature rule",
             ["signature-rule", "signature_rule", "signatures"]),
            ("ip_intelligence", "IP intelligence",
             ["ip-intelligence", "ip_intelligence"]),
            ("file_upload_policy", "File upload",
             ["file-upload-restriction-policy", "file-upload-policy", "file_upload_policy"]),
            ("webshell_detection", "Webshell",
             ["web-shell-detection-policy", "webshell-detection", "webshell_detection"]),
        ],
        "filters": [
            ("kind", "Kind"),
            ("ip_intelligence", "IP intel"),
            ("signature_rule", "Signature rule"),
        ],
    },
    "server_pool": {
        "label": "Server Pool",
        "method": "list_pools",
        "cache_key": "fleet:server_pools",
        "section": "server-pool",
        "columns": [
            ("name", "Name", ["name", "mkey"]),
            ("type", "Type", ["type", "server-pool-type", "pool-type"]),
            ("protocol", "Protocol", ["protocol"]),
        ],
        "filters": [
            ("type", "Type"),
            ("protocol", "Protocol"),
        ],
    },
    # Generic cross-type search: the Find box IS the query. Flattens every
    # collected object of every typed section into one field-per-row view.
    "search": {
        "label": "Search (any field)",
        "search": True,
        "columns": [
            ("device", "Device"),
            ("section", "Section"),
            ("logical", "Type"),
            ("mkey", "Object"),
            ("field", "Field"),
            ("value", "Value"),
        ],
        "filters": [],
    },
}

# Ordered type switcher (matches the desktop ordering).
TYPE_ORDER: list[str] = ["server_policy", "wpp", "server_pool", "search"]
# Typed sections scanned by the generic search mode.
SEARCH_SECTIONS: list[str] = ["server_policy", "wpp", "server_pool"]


# --------------------------------------------------------------------------- #
# Value / object helpers
# --------------------------------------------------------------------------- #
def _to_text(value: Any) -> str:
    """Coerce a cmdb field value to a flat display string.

    FortiWeb reference fields are usually plain strings, but some come back as
    booleans, nested ``{name: ...}`` objects or lists; keep them searchable."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "enable" if value else "disable"
    if isinstance(value, (str, int, float)):
        return str(value)
    if isinstance(value, dict):
        for k in ("name", "mkey", "id"):
            if value.get(k):
                return str(value[k])
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if isinstance(value, list):
        parts = [_to_text(v) for v in value]
        return ", ".join(p for p in parts if p)
    return str(value)


def _pick(obj: dict, sources: list[str]) -> str:
    """First present, non-empty source key (in preference order) as text."""
    for src in sources:
        if src in obj and obj[src] not in (None, ""):
            return _to_text(obj[src])
    return ""


def _flatten(obj: dict):
    """Yield (field, value_text) for every field of a cmdb object."""
    if not isinstance(obj, dict):
        return
    for key, value in obj.items():
        yield str(key), _to_text(value)


def _as_list(raw: Any) -> list:
    """Unwrap a FortiWeb cmdb response into a plain object list.

    The list_* client methods return the raw ``.json()`` which is normally a
    ``{"results": [...]}`` (or ``{"data": [...]}``) envelope; tolerate a bare
    list / single object too."""
    if isinstance(raw, dict):
        res = raw.get("results", raw.get("data"))
        if isinstance(res, list):
            return res
        if isinstance(res, dict):
            return [res]
        return []
    if isinstance(raw, list):
        return raw
    return []


def _fortiweb_appliances() -> list[Appliance]:
    """All FortiWeb appliances (skip FortiADC / other kinds), name-sorted."""
    rows = Appliance.query.order_by(Appliance.name).all()
    return [a for a in rows if (a.kind or "fortiweb") == "fortiweb"]


# DB-FIRST: each fleet type maps to one or more cached logical names in the
# Postgres source-of-truth (device_objects). The appliance is NEVER touched on a
# page load — refresh happens explicitly (the section pages' ⟳) or via the
# Automation device_sync action. Keyed by the type's stable cache_key.
_DB_LOGICALS: dict[str, list[str]] = {
    "fleet:server_policies": ["server_policy"],
    "fleet:wpp": ["webprotection_profile_inline", "webprotection_profile_offline"],
    "fleet:server_pools": ["server_pool"],
}


def _fetch_objects(appl: Appliance, spec: dict) -> list:
    """DB-FIRST read of a type's objects for one appliance, from the local
    Postgres cache (device_objects) — no network. Payloads keep the raw
    hyphenated FortiWeb shape so _pick/_flatten render unchanged. A device with
    no cached data simply yields nothing (run a refresh / Automation sync)."""
    from . import read_layer
    logicals = _DB_LOGICALS.get(spec.get("cache_key", ""), [])
    out: list = []
    for logical in logicals:
        payloads, _meta = read_layer.read_objects(appl.id, logical)
        if logical.startswith("webprotection_profile_"):
            kind = "inline-protection" if "inline" in logical else "offline-protection"
            for p in payloads:
                if isinstance(p, dict) and not p.get("kind"):
                    p = {**p, "kind": kind}
                out.append(p)
        else:
            out.extend(payloads)
    return out


# --------------------------------------------------------------------------- #
# Public API used by the view
# --------------------------------------------------------------------------- #
def type_choices() -> list[tuple[str, str]]:
    """Ordered (key, label) pairs for the 4-mode type switcher."""
    return [(k, TYPES[k]["label"]) for k in TYPE_ORDER]


def columns_for(type_key: str) -> list[tuple[str, str]]:
    """(key, label) columns for the rendered table / CSV (device first)."""
    spec = TYPES[type_key]
    if spec.get("search"):
        return [(k, lbl) for k, lbl in spec["columns"]]
    return [DEVICE_COLUMN] + [(k, lbl) for k, lbl, _src in spec["columns"]]


def collect_objects(type_key: str) -> tuple[list[dict], list[dict]]:
    """DB-first aggregate a typed object across the whole fleet (Postgres cache).

    Returns (rows, errors). Each row is a flat dict keyed by the type's column
    keys plus ``device``. ``errors`` is a list of {device, error} for any
    appliance that could not be read (it is skipped, not fatal)."""
    spec = TYPES[type_key]
    rows: list[dict] = []
    errors: list[dict] = []
    for appl in _fortiweb_appliances():
        try:
            objs = _fetch_objects(appl, spec)
        except Exception as exc:  # noqa: BLE001 — one dead device must not 500
            errors.append({"device": appl.name, "error": str(exc)})
            continue
        for obj in objs:
            if not isinstance(obj, dict):
                continue
            row = {"device": appl.name}
            for key, _label, sources in spec["columns"]:
                row[key] = _pick(obj, sources)
            rows.append(row)
    return rows, errors


def collect_search(q: str) -> tuple[list[dict], list[dict]]:
    """Generic any-field substring search across all collected objects.

    Returns (rows, errors). Empty query → no rows (the Find box IS the query).
    Each row is {device, section, logical, mkey, field, value}."""
    needle = (q or "").strip().lower()
    rows: list[dict] = []
    errors: list[dict] = []
    if not needle:
        return rows, errors
    for appl in _fortiweb_appliances():
        try:
            per_section = {tk: _fetch_objects(appl, TYPES[tk]) for tk in SEARCH_SECTIONS}
        except Exception as exc:  # noqa: BLE001 — skip unreachable device
            errors.append({"device": appl.name, "error": str(exc)})
            continue
        for tk in SEARCH_SECTIONS:
            spec = TYPES[tk]
            for obj in per_section[tk]:
                if not isinstance(obj, dict):
                    continue
                mkey = _pick(obj, ["name", "mkey"])
                for field, value in _flatten(obj):
                    if needle in value.lower() or needle in field.lower():
                        rows.append({
                            "device": appl.name,
                            "section": spec["section"],
                            "logical": spec["label"],
                            "mkey": mkey,
                            "field": field,
                            "value": value,
                        })
    return rows[:SEARCH_LIMIT], errors


def distinct_values(rows: list[dict], filter_keys: list[str]) -> dict[str, list[str]]:
    """Sorted distinct non-empty values per filter column (for the dropdowns)."""
    out: dict[str, list[str]] = {}
    for fkey in filter_keys:
        out[fkey] = sorted({r.get(fkey, "") for r in rows if r.get(fkey)})
    return out


def apply_filters(
    rows: list[dict],
    selected: dict[str, str],
    q: str,
    columns: list[tuple[str, str]],
) -> list[dict]:
    """Typed-mode in-memory filtering: exact match on selected dropdowns, then a
    substring Find over the visible columns."""
    out = rows
    if selected:
        out = [r for r in out if all(r.get(k, "") == v for k, v in selected.items())]
    needle = (q or "").strip().lower()
    if needle:
        keys = [c[0] for c in columns]
        out = [r for r in out if any(needle in str(r.get(k, "")).lower() for k in keys)]
    return out


def to_csv(columns: list[tuple[str, str]], rows: list[dict]) -> str:
    """Render the current view (header + rows) as CSV text."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([label for _key, label in columns])
    for row in rows:
        writer.writerow([_to_text(row.get(key, "")) for key, _label in columns])
    return buf.getvalue()
