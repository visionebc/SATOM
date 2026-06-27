"""Centralised, DB-backed application settings (key/value in ``AppSetting``).

The desktop app keeps these in ``config.json``; the multi-user web app keeps
them in the ``app_settings`` table (``AppSetting.get/set``) so every gunicorn
worker and every admin share ONE source of truth. The previous Settings view
wrote to ``current_app.config`` — per-worker, in-memory, lost on restart — which
is why nothing persisted. JSON-encoded values cover the structured sections
(naming overrides, classification catalogs, network segments), mirroring the
desktop's ``cfg.naming`` / ``cfg.segments`` / classification catalogs.
"""
from __future__ import annotations

import json
from typing import Any

from ..models import AppSetting

# ---- keys -----------------------------------------------------------------
K_APP_NAME = "general.app_name"
K_DEFAULT_KIND = "general.default_kind"
K_SESSION_TIMEOUT = "general.session_timeout"      # minutes
K_POLL_INTERVAL = "general.poll_interval"          # seconds
K_SHOW_RAW = "general.show_raw_config"             # "1" / "0"
K_LOG_LEVELS = "general.log_levels"                # JSON list
K_NAMING = "naming.scheme"                          # JSON dict of overrides
K_CLS_PREFIX = "classification."                    # + zones|lines|departments -> JSON list
K_SEGMENTS = "network.segments"                     # JSON list of dicts

LOG_LEVELS_ALL = ["DEBUG", "INFO", "WARNING", "ERROR"]
CLASSIFICATION_KINDS = ("zones", "lines", "departments")
SEGMENT_FIELDS = ("name", "zone", "line", "department", "cidr", "interface", "gateway", "note")

DEFAULTS = {
    K_APP_NAME: "Fortinet Manager Web",
    K_DEFAULT_KIND: "FortiWeb",
    K_SESSION_TIMEOUT: "60",
    K_POLL_INTERVAL: "30",
    K_SHOW_RAW: "0",
}


# ---- low-level ------------------------------------------------------------
def get_str(key: str, default: str | None = None) -> str | None:
    val = AppSetting.get(key)
    if val is None:
        return DEFAULTS.get(key, default)
    return val


def set_str(key: str, value: Any) -> None:
    AppSetting.set(key, "" if value is None else str(value))


def get_json(key: str, default: Any) -> Any:
    raw = AppSetting.get(key)
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return default


def set_json(key: str, value: Any) -> None:
    AppSetting.set(key, json.dumps(value))


def _to_int(val: Any, fallback: int) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return fallback


# ---- General --------------------------------------------------------------
def general() -> dict[str, Any]:
    return {
        "app_name": get_str(K_APP_NAME),
        "default_kind": get_str(K_DEFAULT_KIND),
        "session_timeout": _to_int(get_str(K_SESSION_TIMEOUT), 60),
        "poll_interval": _to_int(get_str(K_POLL_INTERVAL), 30),
        "show_raw_config": get_str(K_SHOW_RAW) == "1",
        "log_levels": [lv for lv in get_json(K_LOG_LEVELS, LOG_LEVELS_ALL) if lv in LOG_LEVELS_ALL],
    }


def save_general(app_name: str, default_kind: str, session_timeout: Any,
                 poll_interval: Any, show_raw_config: bool,
                 log_levels: list[str]) -> None:
    set_str(K_APP_NAME, (app_name or "Fortinet Manager Web").strip())
    set_str(K_DEFAULT_KIND, default_kind if default_kind in ("FortiWeb", "FortiWeb-Cloud", "FortiADC") else "FortiWeb")
    set_str(K_SESSION_TIMEOUT, max(5, min(1440, _to_int(session_timeout, 60))))
    set_str(K_POLL_INTERVAL, max(10, min(3600, _to_int(poll_interval, 30))))
    set_str(K_SHOW_RAW, "1" if show_raw_config else "0")
    set_json(K_LOG_LEVELS, [lv for lv in log_levels if lv in LOG_LEVELS_ALL] or ["INFO", "WARNING", "ERROR"])


# ---- Naming ---------------------------------------------------------------
def naming_overrides() -> dict[str, str]:
    return get_json(K_NAMING, {})


def save_naming(scheme: dict[str, str]) -> None:
    # Store only non-empty overrides; empties revert to the default pattern via
    # naming.effective_scheme(), exactly like the desktop's "clear → default".
    clean = {k: v.strip() for k, v in (scheme or {}).items() if isinstance(v, str) and v.strip()}
    set_json(K_NAMING, clean)


def reset_naming() -> None:
    set_json(K_NAMING, {})


# ---- Classification (zones / lines / departments) -------------------------
def classification(kind: str) -> list[str]:
    if kind not in CLASSIFICATION_KINDS:
        return []
    return [str(x).strip() for x in get_json(K_CLS_PREFIX + kind, []) if str(x).strip()]


def all_classification() -> dict[str, list[str]]:
    return {k: classification(k) for k in CLASSIFICATION_KINDS}


def save_classification(kind: str, values: list[str]) -> None:
    if kind not in CLASSIFICATION_KINDS:
        return
    seen: list[str] = []
    for v in values:
        v = (v or "").strip()
        if v and v.lower() not in {s.lower() for s in seen}:
            seen.append(v)
    set_json(K_CLS_PREFIX + kind, seen)


# ---- Network segments -----------------------------------------------------
def segments() -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for row in get_json(K_SEGMENTS, []):
        if isinstance(row, dict):
            out.append({f: str(row.get(f, "") or "") for f in SEGMENT_FIELDS})
    return out


def save_segments(rows: list[dict[str, str]]) -> None:
    clean: list[dict[str, str]] = []
    for row in rows:
        name = (row.get("name") or "").strip()
        cidr = (row.get("cidr") or "").strip()
        if not name and not cidr:
            continue  # skip wholly-blank rows
        clean.append({f: (row.get(f, "") or "").strip() for f in SEGMENT_FIELDS})
    set_json(K_SEGMENTS, clean)
