"""External log sources Scout may search -- OPTIONAL, off until an admin adds one.

Why this exists
---------------
Everything Scout could read about logs until now came from Fortinet: the
appliance's own syslog, Sentinel's events, a FortiAnalyzer behind an edge-map
row. A service path is rarely all Fortinet. The switch, the router or the
firewall in front of a FortiWeb (a Cisco, typically) logs to the customer's
SIEM, never to a FortiAnalyzer, and a diagnosis that cannot see that hop says
"no evidence" about the part of the path most likely to be at fault. This
module lets an admin point Scout at that SIEM -- read only -- so the model can
put those lines next to the Path Diagnostics report and the metrics.

Rules that are load-bearing
---------------------------
* **Optional and off by default.** No source exists until an admin saves one in
  Settings -> AI -> Log sources; with none configured Scout says "no external
  source configured", never "the logs are clean".
* **Every failure is an ERROR, never an empty list.** :func:`search` returns
  ``(rows, error)`` and does not raise -- the same contract as ``faz_logs``.
  An HTTP 200 is not success on its own: the body is read, and a Splunk
  ``FATAL``/``ERROR`` message is an error even when the status code says 200.
* **Read only by construction.** The SIEM token should belong to a read-only
  role (the user guide says so), but SATOM does not rely on that: the model's
  text only ever reaches the query as ONE quoted literal term, so it cannot
  close the quote and pipe into a command that writes (``| delete``,
  ``| outputlookup``, ``| collect``, ``| sendemail``). The admin-written
  ``search_prefix`` is the only part of the query that is not quoted.
* **TLS verified against the trust store.** ``verify_tls=False`` exists for a
  lab SIEM with a self-signed certificate, is set by an admin per source, and is
  never a fallback after a verification failure.
* **The secret never leaves the store.** Fernet-encrypted under a per-source
  key, never returned by :func:`list_sources`, never logged, never in a result.

Kinds
-----
``splunk`` -- the REST export endpoint (``POST /services/search/jobs/export``,
management port 8089, ``output_mode=json`` = one JSON object per line).
# TODO verify: Splunk Enterprise 9.x search/jobs/export -- there is no Splunk in
# the lab; the shape below follows Splunk's documentation and is exercised only
# against simulated responses. The UI labels the kind "unverified on a live
# Splunk" until it is measured.

Adding a kind = one ``_search_<kind>`` function returning ``(rows, error)`` and
one entry in :data:`KINDS`; Scout's tool and the settings page need no change.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from . import encryption
from . import settings_store as sstore

K_SOURCES = "scout.log_sources"           # JSON list of source dicts (no secrets)

KINDS = {
    "splunk": {"label": "Splunk (REST search export)", "verified": False},
}

DEFAULT_TIMEOUT = 20.0
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MAX_FIELD_CHARS = 400

_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$")


def _secret_key(key: str) -> str:
    return f"scout.log_source.{key}.secret"


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------

def list_sources() -> list[dict]:
    rows = sstore.get_json(K_SOURCES, [])
    out = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict) or not r.get("key"):
            continue
        row = dict(r)
        row["has_secret"] = bool(sstore.get_str(_secret_key(row["key"])))
        row["verified"] = bool(KINDS.get(row.get("kind"), {}).get("verified"))
        out.append(row)
    return out


def get_source(key: str) -> dict | None:
    for s in list_sources():
        if s.get("key") == key:
            return s
    return None


def enabled_sources() -> list[dict]:
    return [s for s in list_sources() if s.get("enabled") is not False]


def validate(*, key: str, kind: str, base_url: str, device_field: str = "") -> list[str]:
    errors = []
    if not _KEY_RE.match(key or ""):
        errors.append("key must be a lowercase slug (a-z, 0-9, - and _; max 40)")
    if kind not in KINDS:
        errors.append(f"unknown log source kind {kind!r}")
    if not (base_url or "").lower().startswith(("https://", "http://")):
        errors.append("base URL must start with https:// (or http:// for a lab)")
    if device_field and not _FIELD_RE.match(device_field):
        errors.append("device field must be a plain field name (for example host)")
    return errors


def save_source(*, key: str, kind: str, label: str, base_url: str,
                search_prefix: str = "", device_field: str = "host",
                verify_tls: bool = True, token: str | None = None,
                enabled: bool = True) -> None:
    errors = validate(key=key, kind=kind, base_url=base_url, device_field=device_field)
    if errors:
        raise ValueError("; ".join(errors))
    rows = sstore.get_json(K_SOURCES, [])
    rows = [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
    rows = [r for r in rows if r.get("key") != key]
    rows.append({
        "key": key, "kind": kind, "label": (label or key)[:80],
        "base_url": base_url.rstrip("/"),
        "search_prefix": (search_prefix or "").strip()[:500],
        "device_field": (device_field or "").strip(),
        "verify_tls": bool(verify_tls), "enabled": bool(enabled),
    })
    sstore.set_json(K_SOURCES, rows)
    if token:
        sstore.set_str(_secret_key(key), encryption.encrypt(token))


def delete_source(key: str) -> None:
    rows = sstore.get_json(K_SOURCES, [])
    rows = [r for r in rows if isinstance(r, dict) and r.get("key") != key]
    sstore.set_json(K_SOURCES, rows)
    sstore.set_str(_secret_key(key), "")


def _token(key: str) -> str:
    enc = sstore.get_str(_secret_key(key), "") or ""
    if not enc:
        return ""
    try:
        return encryption.decrypt(enc)
    except Exception:  # noqa: BLE001 -- a rotated key reads as "no token", loudly below
        return ""


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------

def spl_literal(text: str) -> str:
    """One SPL search term, quoted. Backslash and double quote are escaped, so
    nothing inside can end the literal -- a ``|`` stays a character to match,
    never the start of a command. Newlines are flattened for the same reason."""
    s = re.sub(r"[\r\n\t]+", " ", str(text or ""))[:300]
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_spl(src: dict, *, device_terms=(), query: str = "",
              limit: int = DEFAULT_LIMIT) -> str:
    parts = ["search"]
    prefix = (src.get("search_prefix") or "").strip()
    if prefix:
        parts.append(prefix)
    field = (src.get("device_field") or "").strip()
    terms = [t for t in (device_terms or ()) if str(t or "").strip()]
    if field and terms:
        parts.append("(" + " OR ".join(f"{field}={spl_literal(t)}" for t in terms) + ")")
    if (query or "").strip():
        parts.append(spl_literal(query.strip()))
    return " ".join(parts) + f" | head {int(limit)}"


def _clip(v):
    if isinstance(v, list):
        v = ", ".join(str(x) for x in v[:5])
    s = str(v if v is not None else "")
    return s if len(s) <= MAX_FIELD_CHARS else s[:MAX_FIELD_CHARS] + "…"


def parse_splunk_export(body: str) -> tuple[list[dict], str | None]:
    """One JSON object per line. ``result`` lines are rows; a ``messages``
    entry of type FATAL or ERROR is an error even inside an HTTP 200."""
    rows, problems = [], []
    for line in (body or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            problems.append("unparseable line: " + line[:120])
            continue
        if not isinstance(obj, dict):
            continue
        for m in obj.get("messages") or []:
            if isinstance(m, dict) and str(m.get("type", "")).upper() in ("FATAL", "ERROR"):
                problems.append(str(m.get("text", ""))[:200])
        res = obj.get("result")
        if isinstance(res, dict):
            rows.append({k: _clip(v) for k, v in res.items()
                         if k in ("_time", "host", "source", "sourcetype", "_raw")
                         or not k.startswith("_")})
    if problems:
        return rows, "Splunk reported: " + "; ".join(problems[:3])
    return rows, None


def _epoch(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _search_splunk(src, token, spl, start, end, timeout, transport):
    import httpx
    from . import trust_store
    url = src["base_url"].rstrip("/") + "/services/search/jobs/export"
    # Epoch seconds: Splunk reads them the same whatever its own timezone and
    # time_format are. SATOM's datetimes are naive UTC.
    data = {"search": spl, "output_mode": "json",
            "earliest_time": str(_epoch(start)), "latest_time": str(_epoch(end))}
    verify = trust_store.verify_param() if src.get("verify_tls", True) else False
    post = transport or httpx.post
    r = post(url, data=data, headers={"Authorization": f"Bearer {token}"},
             timeout=timeout, verify=verify)
    if r.status_code in (401, 403):
        return [], f"Splunk refused the token (HTTP {r.status_code})"
    if r.status_code >= 400:
        _rows, err = parse_splunk_export(r.text)
        return [], f"Splunk answered HTTP {r.status_code}" + (f" -- {err}" if err else "")
    return parse_splunk_export(r.text)


def search(src: dict, *, device_terms=(), query: str = "", start: datetime,
           end: datetime, limit: int = DEFAULT_LIMIT,
           timeout: float = DEFAULT_TIMEOUT, transport=None):
    """``(rows, error, query_text)`` -- never raises, and a failure is never
    ``[]`` with no error. ``transport`` replaces ``httpx.post`` in tests; it is
    not a second client."""
    try:
        limit = max(1, min(int(limit), MAX_LIMIT))
    except (TypeError, ValueError):
        limit = DEFAULT_LIMIT
    kind = src.get("kind")
    # Looked up by name at call time: one function per kind, nothing cached.
    fn = globals().get(f"_search_{kind}") if kind in KINDS else None
    if fn is None:
        return [], f"unknown log source kind {kind!r}", ""
    spl = build_spl(src, device_terms=device_terms, query=query, limit=limit)
    token = _token(src.get("key", ""))
    if not token:
        return [], "no token stored for this source (or it no longer decrypts)", spl
    try:
        rows, err = fn(src, token, spl, start, end, timeout, transport)
    except Exception as exc:  # noqa: BLE001 -- transport failure is data, not a crash
        return [], f"{type(exc).__name__}: {str(exc)[:200]}", spl
    return rows[:limit], err, spl


__all__ = ["KINDS", "list_sources", "get_source", "enabled_sources", "validate",
           "save_source", "delete_source", "spl_literal", "build_spl",
           "parse_splunk_export", "search"]
