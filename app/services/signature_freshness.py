"""Signature DB freshness per device (contract C8) and the daily collection
from the signature source.

Signatures never travel in a knowledge pack: every FortiWeb downloads its own
from FortiGuard. The ``signature_check`` scheduled action does two things:

1. **Freshness, every FortiWeb.** It reads ONLY the database versions, over
   REST — ``GET /api/v2.0/system/config.fortiguard`` answers every FortiGuard
   database (attack signatures, antivirus, IP reputation, GeoIP, known bots,
   ...) with its version, last update and licence validity in one call. When
   REST does not answer, ``diagnose system update info`` over SSH is the
   fallback (signature DB only). The alert engine
   (``alerts._check_signatures``, family ``device``) raises a finding when a
   device's signature DB is older than ``alerts.signature_max_days`` (default
   7) or could not be read.
2. **Collection, the source only.** The operator picks ONE FortiWeb as the
   signature source (``signature_index``). When the source's signature DB
   version is not the one the local index holds, the whole catalog is read
   off it and indexed: a snapshot, the delta (new / changed / removed
   signatures) and a bell notification to the administrators. No source
   configured is an alert finding, not a silent green.

Verified against the lab FortiWeb 7.6.8 and 8.0.6 (2026-10-08): both answer
``config.fortiguard`` (``securityService.buildNumber`` = the CLI's "FortiWeb
signature" version, ``0.00271`` on an unlicensed box whose
``lastUpdateTime`` is ``1969-12-31``: the epoch, i.e. never updated). The CLI
command is read-only (``ssh_ops.assert_readonly`` accepts ``diagnose``).
FortiADC and the other products: not verified, so not checked.

State lives in ``app_settings`` (``signatures.db_state``, JSON keyed by
appliance id) so it replicates to the standby with everything else.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

VERSION_CMD = "diagnose system update info"
REST_PATH = "/api/v2.0/system/config.fortiguard"
PRODUCTS = ("fortiweb",)
K_STATE = "signatures.db_state"
K_MAX_DAYS = "alerts.signature_max_days"
DEFAULT_MAX_DAYS = 7

_HEADER_RE = re.compile(r"^\s*FortiWeb signature\s*$", re.I)
_VERSION_RE = re.compile(r"^\s*Version\s*:\s*(\S.*?)\s*$", re.I)
_UPDATED_RE = re.compile(r"^\s*Last Update Date\s*:\s*(.+?)\s*$", re.I)
_DATE_FORMATS = ("%a %b %d %H:%M:%S %Y", "%a %b %d %Y", "%Y-%m-%d %H:%M:%S",
                 "%Y-%m-%d")


def _device_date(raw) -> tuple[str, bool]:
    """``(iso, never_updated)`` from a device date string. The epoch
    (1969/1970) means the device never pulled an update."""
    raw = str(raw or "").strip()
    for fmt in _DATE_FORMATS:
        try:
            at = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if at.year <= 1970:
            return "", True
        return at.isoformat(timespec="seconds"), False
    return "", False


# config.fortiguard block -> (database label, version key). The signature DB is
# ``securityService``; the others are reported alongside, never assessed.
REST_DATABASES = (
    ("securityService", "signature", "buildNumber"),
    ("antivirusService", "antivirus", "regularVirusDatabaseVersion"),
    ("reputationService", "ip_reputation", "reputationBuildNumber"),
    ("geodbService", "geodb", "geodbVersion"),
    ("knownBotService", "known_bots", "knownBotVersion"),
    ("fuzzyWebshellService", "webshell", "fuzzyWebshellVersion"),
    ("credentialStuffingDefense", "credential_stuffing", "databaseVersion"),
    ("dlpSignature", "dlp", "databaseVersion"),
    ("sbclService", "sandbox_cloud", "sandboxCloudVersion"),
)


def parse_fortiguard_config(doc) -> dict:
    """The ``config.fortiguard`` answer as ``{"version", "engine",
    "last_update", "never_updated", "licence_valid", "databases"}``.

    ``version`` is ``""`` when the signature block is missing (unreadable).
    ``databases`` maps a label to ``{"version", "last_update",
    "never_updated", "valid"}`` for every block the firmware reports."""
    res = doc.get("results", doc) if isinstance(doc, dict) else {}
    res = res if isinstance(res, dict) else {}
    out = {"version": "", "engine": "", "last_update": "", "never_updated": False,
           "licence_valid": None, "databases": {}}
    for block, label, key in REST_DATABASES:
        b = res.get(block)
        if not isinstance(b, dict):
            continue
        last, never = _device_date(b.get("lastUpdateTime"))
        valid = b.get("is_valid")
        out["databases"][label] = {
            "version": str(b.get(key) or ""), "last_update": last,
            "never_updated": never, "valid": valid if isinstance(valid, bool) else None}
    sig = out["databases"].get("signature")
    if sig:
        out["version"] = sig["version"]
        out["last_update"] = sig["last_update"]
        out["never_updated"] = sig["never_updated"]
        out["licence_valid"] = sig["valid"]
        out["engine"] = str((res.get("securityService") or {}).get("engineVersion") or "")
    return out


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
        if m and not out["last_update"] and not out["never_updated"]:
            out["last_update"], out["never_updated"] = _device_date(m.group(1))
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
             "licence_valid": prev.get("licence_valid"),
             "engine": prev.get("engine", ""),
             "channel": prev.get("channel", ""),
             "databases": prev.get("databases") or {},
             "error": ""}
    if error or not parsed or not parsed.get("version"):
        entry["error"] = error or "no 'FortiWeb signature' version in the answer"
        return entry, False
    changed = parsed["version"] != prev.get("version")
    entry["version"] = parsed["version"]
    entry["device_last_update"] = parsed.get("last_update") or ""
    entry["never_updated"] = bool(parsed.get("never_updated"))
    entry["licence_valid"] = parsed.get("licence_valid")
    entry["engine"] = parsed.get("engine") or ""
    entry["channel"] = parsed.get("channel") or ""
    entry["databases"] = parsed.get("databases") or {}
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
    unlicensed = entry.get("licence_valid") is False
    if entry.get("never_updated"):
        return {"status": "stale", "age_days": None, "since": "",
                "reason": "the device reports it never downloaded a signature update"
                          + ("; its FortiGuard licence is not valid" if unlicensed else "")}
    since = _parse(entry.get("device_last_update")) or _parse(entry.get("last_change"))
    if since is None:
        return {"status": "unreadable", "age_days": None, "since": "",
                "reason": "no update time known"}
    age = (now - since).days
    if now - since > timedelta(days=limit):
        return {"status": "stale", "age_days": age, "since": since.isoformat(),
                "reason": "signature DB %s is %d day(s) old (limit %d)%s"
                          % (entry.get("version") or "?", age, limit,
                             "; its FortiGuard licence is not valid" if unlicensed else "")}
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
def read_version_rest(client) -> tuple[dict | None, str]:
    """The signature DB version (and every other FortiGuard DB) over REST.
    ``(parsed, "")`` or ``(None, error)``. One GET, read-only."""
    try:
        doc = client.api_call("GET", REST_PATH).json()
    except Exception as exc:  # noqa: BLE001 — REST off, auth, timeout
        return None, "REST %s: %s: %s" % (REST_PATH, type(exc).__name__, exc)
    parsed = parse_fortiguard_config(doc)
    if not parsed["version"]:
        return None, "REST %s answered no signature version" % REST_PATH
    parsed["channel"] = "rest"
    return parsed, ""


def read_version_cli(appliance) -> tuple[dict | None, str]:
    """The fallback: ``diagnose system update info`` over SSH."""
    from . import ssh_ops
    try:
        text = ssh_ops.run_command(appliance, VERSION_CMD, timeout=25.0)
    except Exception as exc:  # noqa: BLE001 — SSH off, auth, timeout: unreadable
        return None, "CLI: %s: %s" % (type(exc).__name__, exc)
    parsed = parse_update_info(text)
    parsed["channel"] = "cli"
    return parsed, ""


def _read_version(appliance) -> tuple[dict | None, str]:
    """REST first; the CLI only when REST does not give a version."""
    try:
        client = appliance.build_client()
    except Exception as exc:  # noqa: BLE001
        parsed, rest_err = None, "REST client: %s: %s" % (type(exc).__name__, exc)
    else:
        parsed, rest_err = read_version_rest(client)
    if parsed:
        return parsed, ""
    parsed, cli_err = read_version_cli(appliance)
    if parsed and parsed.get("version"):
        return parsed, ""
    return parsed, "; ".join(e for e in (rest_err, cli_err) if e)


def _collect_from_source(src, entry: dict, collector) -> tuple[bool, str]:
    """``(ok, line)`` for the catalog step of the round."""
    from . import signature_index as sidx
    if getattr(src, "maintenance", False):
        return True, "catalog: source %s is in maintenance — not read" % src.name
    if not entry or entry.get("error") or not entry.get("version"):
        return True, ("catalog: source %s unreadable this round — index kept"
                      % src.name)
    if not sidx.needs_collect(src.kind or "fortiweb", entry["version"]):
        return True, "catalog: index already at %s" % entry["version"]
    try:
        res = collector(src)
    except Exception as exc:  # noqa: BLE001 — a failed read is a red round
        return False, ("catalog read from %s failed: %s: %s"
                       % (src.name, type(exc).__name__, exc))
    try:
        sidx.announce(res)
    except Exception:  # noqa: BLE001 — the index is written; the bell is a courtesy
        pass
    return True, "catalog: " + sidx.headline(res) + " (from %s)" % src.name


def run_check(*, dry_run: bool = False, refresh_catalog: bool = True,
              reader=None, collector=None, now: datetime | None = None) -> dict:
    """Read every FortiWeb's FortiGuard DB versions, then index the catalog
    off the signature source when its version is new. ``{"ok", "summary",
    "log"}``.

    ``ok`` = the round ran; per-device problems are findings for the alert
    engine, not a red action. A configured source whose catalog read FAILED
    is red. ``reader(appliance) -> (parsed, error)`` and
    ``collector(appliance) -> dict`` are injectable for tests."""
    from ..models import Appliance
    from . import signature_index as sidx
    now = now or _now()
    reader = reader or _read_version
    collector = collector or (lambda ap: sidx.collect(ap, taken_by="scheduled"))
    devices = (Appliance.query.filter(Appliance.kind.in_(PRODUCTS))
               .order_by(Appliance.id).all())
    due = [a for a in devices if not getattr(a, "maintenance", False)]
    parked = [a.name for a in devices if getattr(a, "maintenance", False)]
    src = sidx.source_appliance("fortiweb")
    if dry_run:
        return {"ok": True,
                "summary": "[dry-run] would read the FortiGuard DB versions of %d "
                           "FortiWeb(s)%s; signature source: %s"
                           % (len(due), (", %d in maintenance" % len(parked))
                              if parked else "", src.name if src else "none"),
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
        lines.append("[%s] %s: %s%s%s" % (
            verdict["status"], ap.name, entry.get("version") or "-",
            (" via " + entry["channel"]) if entry.get("channel") and not entry.get("error") else "",
            (" (" + verdict["reason"] + ")") if verdict["reason"] else ""))
    # Devices that left the fleet leave the state too.
    live = {str(a.id) for a in devices}
    for aid in [k for k in state if k not in live]:
        state.pop(aid, None)
    _save_state(state)
    ok = True
    if refresh_catalog:
        if src is not None:
            ok, line = _collect_from_source(src, state.get(str(src.id)), collector)
            lines.append(line)
        elif devices:
            lines.append("catalog: no signature source configured — choose one on "
                         "the Signatures page")
    summary = ("%d FortiWeb(s): %d current, %d stale, %d unreadable, %d changed"
               % (len(due), counts["ok"], counts["stale"], counts["unreadable"],
                  len(changed_devs)))
    if not devices:
        summary = "0 FortiWeb(s) registered — nothing to read"
    if parked:
        summary += "; in maintenance, skipped: " + ", ".join(parked)
    if refresh_catalog and devices:
        summary += "; " + (lines[-1] if lines and lines[-1].startswith("catalog")
                           else "catalog not read")
    return {"ok": ok, "summary": summary[:500], "log": "\n".join(lines)[:8000]}


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


__all__ = ["VERSION_CMD", "REST_PATH", "K_STATE", "K_MAX_DAYS", "DEFAULT_MAX_DAYS",
           "parse_update_info", "parse_fortiguard_config", "read_version_rest",
           "read_version_cli", "load_state", "update_entry", "assess", "rows",
           "run_check", "meta_for", "meta_count", "max_days"]
