"""Signature DB freshness per device (contract C8).

Signatures never travel in a knowledge pack: every FortiWeb downloads its own
from FortiGuard. What SATOM can do is notice when one stops doing so. The
``signature_check`` scheduled action reads, once a day and per FortiWeb, ONLY
the signature database version string (``diagnose system update info``, the
"FortiWeb signature" block), stores it with the time it last changed, and
refreshes the cached signature catalog (``data/signatures.json``) only when a
version changed — the catalog walk is hundreds of REST reads, the version read
is one CLI command.

The alert engine (``alerts._check_signatures``, family ``device``) raises a
finding when a device's signature DB is older than ``alerts.signature_max_days``
(default 7) or could not be read.

Verified against the lab FortiWeb 7.6.8 (2026-10-08): the command is read-only
(``ssh_ops.assert_readonly`` accepts ``diagnose``), and on a box that never
reached FortiGuard it answers ``Version: 0.00271`` with ``Last Update Date: Wed
Dec 31 16:00:00 1969`` — the epoch, i.e. "never updated", which is stale.
FortiADC and the other products: not verified, so not checked.

State lives in ``app_settings`` (``signatures.db_state``, JSON keyed by
appliance id) so it replicates to the standby with everything else.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

VERSION_CMD = "diagnose system update info"
PRODUCTS = ("fortiweb",)
K_STATE = "signatures.db_state"
K_MAX_DAYS = "alerts.signature_max_days"
DEFAULT_MAX_DAYS = 7

_HEADER_RE = re.compile(r"^\s*FortiWeb signature\s*$", re.I)
_VERSION_RE = re.compile(r"^\s*Version\s*:\s*(\S.*?)\s*$", re.I)
_UPDATED_RE = re.compile(r"^\s*Last Update Date\s*:\s*(.+?)\s*$", re.I)
_DATE_FORMATS = ("%a %b %d %H:%M:%S %Y", "%a %b %d %Y", "%Y-%m-%d %H:%M:%S",
                 "%Y-%m-%d")


def parse_update_info(text: str) -> dict:
    """``{"version", "last_update", "never_updated"}`` from the command output.

    ``version`` is ``""`` when the block is missing (unreadable).
    ``last_update`` is an ISO timestamp or ``""``; ``never_updated`` is True
    when the device reports the epoch (1969/1970) — it never pulled an update.
    """
    out = {"version": "", "last_update": "", "never_updated": False}
    lines = (text or "").splitlines()
    start = next((i for i, ln in enumerate(lines) if _HEADER_RE.match(ln)), None)
    if start is None:
        return out
    for ln in lines[start + 1:]:
        if re.match(r"^\s*Historical versions", ln, re.I):
            break
        m = _VERSION_RE.match(ln)
        if m and not out["version"]:
            out["version"] = m.group(1)
            continue
        m = _UPDATED_RE.match(ln)
        if m and not out["last_update"]:
            raw = m.group(1)
            for fmt in _DATE_FORMATS:
                try:
                    at = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
                if at.year <= 1970:
                    out["never_updated"] = True
                else:
                    out["last_update"] = at.isoformat(timespec="seconds")
                break
    return out


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------
def load_state() -> dict:
    from ..models import AppSetting
    try:
        doc = json.loads(AppSetting.get(K_STATE) or "{}")
    except (ValueError, Exception):  # noqa: BLE001
        return {}
    return doc if isinstance(doc, dict) else {}


def _save_state(state: dict) -> None:
    from ..models import AppSetting
    AppSetting.set(K_STATE, json.dumps(state, sort_keys=True))


def max_days() -> int:
    from ..models import AppSetting
    try:
        n = int(float(str(AppSetting.get(K_MAX_DAYS) or DEFAULT_MAX_DAYS)))
    except (TypeError, ValueError, OverflowError):
        return DEFAULT_MAX_DAYS
    return max(1, min(365, n))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: str):
    try:
        at = datetime.fromisoformat(str(ts or ""))
    except ValueError:
        return None
    return at if at.tzinfo else at.replace(tzinfo=timezone.utc)


def update_entry(prev: dict | None, appliance, parsed: dict | None, error: str,
                 now: datetime) -> tuple[dict, bool]:
    """The new state entry for one device and whether its version CHANGED.

    Pure. A failed read keeps the last known version and its change time (so
    the age keeps counting) and records the error."""
    prev = dict(prev or {})
    entry = {"name": getattr(appliance, "name", "") or prev.get("name", ""),
             "product": getattr(appliance, "kind", "") or prev.get("product", ""),
             "checked_at": now.isoformat(timespec="seconds"),
             "version": prev.get("version", ""),
             "last_change": prev.get("last_change", ""),
             "device_last_update": prev.get("device_last_update", ""),
             "never_updated": bool(prev.get("never_updated")),
             "error": ""}
    if error or not parsed or not parsed.get("version"):
        entry["error"] = error or "no 'FortiWeb signature' version in the answer"
        return entry, False
    changed = parsed["version"] != prev.get("version")
    entry["version"] = parsed["version"]
    entry["device_last_update"] = parsed.get("last_update") or ""
    entry["never_updated"] = bool(parsed.get("never_updated"))
    if changed or not entry["last_change"]:
        entry["last_change"] = now.isoformat(timespec="seconds")
    return entry, changed and bool(prev.get("version"))


def assess(entry: dict, now: datetime | None = None, limit_days: int | None = None) -> dict:
    """``{"status": ok|stale|unreadable, "age_days", "since", "reason"}``. Pure.

    The age is measured from the device's own "Last Update Date" when it gives
    a real one, else from when SATOM last saw the version change. A device that
    reports the epoch never updated: stale whatever the version says."""
    now = now or _now()
    limit = limit_days if limit_days is not None else DEFAULT_MAX_DAYS
    if entry.get("error"):
        return {"status": "unreadable", "age_days": None, "since": "",
                "reason": entry["error"]}
    if entry.get("never_updated"):
        return {"status": "stale", "age_days": None, "since": "",
                "reason": "the device reports it never downloaded a signature update"}
    since = _parse(entry.get("device_last_update")) or _parse(entry.get("last_change"))
    if since is None:
        return {"status": "unreadable", "age_days": None, "since": "",
                "reason": "no update time known"}
    age = (now - since).days
    if now - since > timedelta(days=limit):
        return {"status": "stale", "age_days": age, "since": since.isoformat(),
                "reason": "signature DB %s is %d day(s) old (limit %d)"
                          % (entry.get("version") or "?", age, limit)}
    return {"status": "ok", "age_days": age, "since": since.isoformat(), "reason": ""}


def rows(now: datetime | None = None) -> list[dict]:
    """The stored state, assessed, for the Signatures page and the alert check."""
    limit = max_days()
    out = []
    for aid, entry in sorted(load_state().items(), key=lambda kv: kv[1].get("name", "")):
        if not isinstance(entry, dict):
            continue
        out.append(dict(entry, appliance_id=aid, **assess(entry, now, limit)))
    return out


# ---------------------------------------------------------------------------
# the scheduled action
# ---------------------------------------------------------------------------
def _read_version(appliance) -> tuple[dict | None, str]:
    from . import ssh_ops
    try:
        text = ssh_ops.run_command(appliance, VERSION_CMD, timeout=25.0)
    except Exception as exc:  # noqa: BLE001 — SSH off, auth, timeout: unreadable
        return None, "%s: %s" % (type(exc).__name__, exc)
    return parse_update_info(text), ""


def _refresh_catalog(appliance) -> str:
    """The signature catalog walk (``signature_sync``), run because a version
    changed. Best effort; the version state is already stored."""
    import os
    from flask import current_app
    from . import signature_catalog
    client = appliance.build_client()
    sset = signature_catalog.pick_signature_set(client)
    if not sset:
        return "no signature set on %s" % appliance.name
    sig_db = signature_catalog.sync_signature_database(
        client, sset, firmware=getattr(appliance, "fw_version", "") or "")
    path = os.path.join(os.path.dirname(current_app.root_path), "data", "signatures.json")
    signature_catalog.save_signature_db(sig_db, path)
    return "%d signatures cached from %s" % (len(sig_db.signatures), appliance.name)


def run_check(*, dry_run: bool = False, refresh_catalog: bool = True,
              reader=None, now: datetime | None = None) -> dict:
    """Read every FortiWeb's signature DB version. ``{"ok", "summary", "log"}``.

    ``ok`` = the round ran; per-device problems are findings for the alert
    engine, not a red action. ``reader(appliance) -> (parsed, error)`` is
    injectable for tests."""
    from ..models import Appliance
    now = now or _now()
    reader = reader or _read_version
    devices = (Appliance.query.filter(Appliance.kind.in_(PRODUCTS))
               .order_by(Appliance.id).all())
    due = [a for a in devices if not getattr(a, "maintenance", False)]
    parked = [a.name for a in devices if getattr(a, "maintenance", False)]
    if dry_run:
        return {"ok": True,
                "summary": "[dry-run] would read the signature DB version of %d "
                           "FortiWeb(s)%s" % (len(due), (", %d in maintenance"
                                                        % len(parked)) if parked else ""),
                "log": "\n".join(a.name for a in due)[:4000]}
    state = load_state()
    limit = max_days()
    lines, changed_devs = [], []
    counts = {"ok": 0, "stale": 0, "unreadable": 0}
    for ap in due:
        parsed, err = reader(ap)
        entry, changed = update_entry(state.get(str(ap.id)), ap, parsed, err, now)
        state[str(ap.id)] = entry
        verdict = assess(entry, now, limit)
        counts[verdict["status"]] = counts.get(verdict["status"], 0) + 1
        if changed:
            changed_devs.append(ap)
        lines.append("[%s] %s: %s%s" % (verdict["status"], ap.name,
                                        entry.get("version") or "-",
                                        (" (" + verdict["reason"] + ")")
                                        if verdict["reason"] else ""))
    # Devices that left the fleet leave the state too.
    live = {str(a.id) for a in devices}
    for aid in [k for k in state if k not in live]:
        state.pop(aid, None)
    _save_state(state)
    if refresh_catalog and changed_devs:
        try:
            lines.append("catalog: " + _refresh_catalog(changed_devs[0]))
        except Exception as exc:  # noqa: BLE001
            lines.append("catalog refresh failed: %s: %s" % (type(exc).__name__, exc))
    summary = ("%d FortiWeb(s): %d current, %d stale, %d unreadable, %d changed"
               % (len(due), counts["ok"], counts["stale"], counts["unreadable"],
                  len(changed_devs)))
    if parked:
        summary += "; in maintenance, skipped: " + ", ".join(parked)
    return {"ok": True, "summary": summary, "log": "\n".join(lines)[:8000]}


# ---------------------------------------------------------------------------
# enrichment from knowledge_signature_meta
# ---------------------------------------------------------------------------
def meta_for(product: str, sig_ids) -> dict:
    """``{sig_id: {name, severity, category, cve, url, summary, origin}}`` for
    the ids that have public metadata in ``knowledge_signature_meta``. Never
    raises: no table yet (no pack imported) is simply no enrichment."""
    ids = sorted({str(s) for s in sig_ids or [] if s})
    if not ids:
        return {}
    try:
        from ..models_knowledge import KnowledgeSignatureMeta as M
        out = {}
        for i in range(0, len(ids), 500):
            for r in M.query.filter(M.product == product, M.sig_id.in_(ids[i:i + 500])):
                out[r.sig_id] = {"name": r.name or "", "severity": r.severity or "",
                                 "category": r.category or "",
                                 "cve": list(r.cve or []), "url": r.url or "",
                                 "summary": r.summary or "", "origin": r.origin or ""}
        return out
    except Exception:  # noqa: BLE001
        try:
            from ..models import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return {}


def meta_count(product: str) -> int:
    try:
        from ..models_knowledge import KnowledgeSignatureMeta as M
        return M.query.filter(M.product == product).count()
    except Exception:  # noqa: BLE001
        try:
            from ..models import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return 0


__all__ = ["VERSION_CMD", "K_STATE", "K_MAX_DAYS", "DEFAULT_MAX_DAYS",
           "parse_update_info", "load_state", "update_entry", "assess", "rows",
           "run_check", "meta_for", "meta_count", "max_days"]
