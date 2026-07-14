"""Pre-flight / post-flight health snapshots.

A single, reusable "is the system healthy" snapshot taken BEFORE and AFTER any
risky change — a machine/app upgrade (``self_update_runner.process``) or a
device config restore (the canary). ``compare(before, after)`` turns two
snapshots into a pass/fail verdict with an explicit list of regressions, so a
change that degrades reachability, health, or replication is caught instead of
silently shipped.

Design notes
------------
* Reuses the exact data sources the alert engine already trusts
  (``cert_service.current``, ``git_service.git_info``, ``Appliance`` +
  socket probe, ``/healthz``) so preflight and the alerts never disagree.
* Every field is captured under its own ``try/except`` — a snapshot must never
  raise, because it wraps operations whose failure is the whole point of taking
  it. A field that could not be read becomes ``{"error": "..."}`` and is
  treated conservatively by ``compare`` (unknown-after ≠ regression, but a
  known-good-before → unknown-after on health IS flagged).
* Pure stdlib + existing services; no new dependencies.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import urllib.request
from datetime import datetime, timezone

HEALTH_URL = os.environ.get("FM_HEALTH_URL", "https://127.0.0.1:8443/healthz")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _node() -> str:
    try:
        from .alerts import _node as an  # reuse the canonical node-name resolver
        return an()
    except Exception:  # noqa: BLE001
        return socket.gethostname()


def _healthz() -> dict:
    """Hit the local TLS health endpoint; report code + peer_authenticated."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(HEALTH_URL, method="GET")
        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
            code = r.getcode()
            try:
                body = json.loads(r.read().decode("utf-8", "replace") or "{}")
            except Exception:  # noqa: BLE001
                body = {}
        return {"code": code, "ok": code == 200,
                "peer_authenticated": body.get("peer_authenticated")}
    except Exception as exc:  # noqa: BLE001
        # Fall back to the plain :8000 edge path before declaring it down.
        try:
            with urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=6) as r:
                return {"code": r.getcode(), "ok": r.getcode() == 200,
                        "peer_authenticated": None, "via": "8000-fallback"}
        except Exception:  # noqa: BLE001
            return {"code": None, "ok": False, "error": str(exc)}


def _git() -> dict:
    try:
        from . import git_service
        info = git_service.git_info() or {}
        raw_head = info.get("sha") or info.get("head") or info.get("commit") or ""
        head = str(raw_head).split()[0] if raw_head else None  # SHA token only
        return {"head": head,
                "ahead": int(info.get("ahead") or 0),
                "behind": int(info.get("behind") or 0),
                "branch": info.get("branch")}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _cert() -> dict:
    try:
        from . import cert_service
        cur = cert_service.current() or {}
        return {"days_left": cur.get("days_left"), "not_after": cur.get("not_after"),
                "source": cur.get("source")}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _pg() -> dict:
    """Replication role: is this node a read-only replica right now?"""
    try:
        from ..models import db
        from sqlalchemy import text
        row = db.session.execute(text("SELECT pg_is_in_recovery()")).scalar()
        return {"in_recovery": bool(row)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _devices() -> dict:
    """Per-appliance TCP reachability — the canary/upgrade must not knock a
    managed device off the map."""
    out: dict[str, dict] = {}
    try:
        from ..models import Appliance
        for a in Appliance.query.all():
            host, port = a.host, int(a.port or 443)
            ok = False
            try:
                with socket.create_connection((host, port), timeout=4):
                    ok = True
            except Exception:  # noqa: BLE001
                ok = False
            out[a.name] = {"host": host, "port": port, "reachable": ok,
                           "kind": getattr(a, "kind", None),
                           "maintenance": bool(getattr(a, "maintenance", False))}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
    return out


def _versions() -> dict:
    try:
        from . import system_info
        libs = {}
        for name, meta in (getattr(system_info, "_LIBRARIES", {}) or {}).items():
            v = meta.get("version") if isinstance(meta, dict) else meta
            libs[name] = v
        return libs
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _flight_dir() -> str:
    """Where baselines live: ``data/flight/`` next to the app (per-node, not in
    git — it is host-local state like update-status)."""
    base = os.environ.get("FM_DATA_DIR") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
    d = os.path.join(base, "flight")
    os.makedirs(d, exist_ok=True)
    return d


def save(snap: dict, path: str | None = None) -> str:
    path = path or os.path.join(_flight_dir(), "last-preflight.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(snap, fh, indent=2)
    return path


def load(path: str | None = None) -> dict:
    path = path or os.path.join(_flight_dir(), "last-preflight.json")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def snapshot(label: str = "") -> dict:
    """Capture a full health baseline. Never raises."""
    return {
        "at": _now_iso(),
        "label": label,
        "node": _node(),
        "health": _healthz(),
        "git": _git(),
        "cert": _cert(),
        "pg": _pg(),
        "devices": _devices(),
        "versions": _versions(),
    }


# --------------------------------------------------------------------------- #
# Comparison                                                                   #
# --------------------------------------------------------------------------- #
def compare(before: dict, after: dict) -> dict:
    """Diff two snapshots into a verdict. A *regression* is a thing that was
    healthy before and is not after — those FAIL the flight. Improvements and
    unknown→unknown transitions are informational only."""
    regressions: list[str] = []
    warnings: list[str] = []

    # --- health: 200-before → not-200-after is the headline regression -------
    hb, ha = before.get("health", {}), after.get("health", {})
    if hb.get("ok") and not ha.get("ok"):
        regressions.append(
            f"health: was 200, now {ha.get('code')} ({ha.get('error', 'not ok')})")
    if hb.get("peer_authenticated") and ha.get("peer_authenticated") is False:
        warnings.append("health: peer authentication went true → false")

    # --- devices: a reachable device must stay reachable ---------------------
    db_, da = before.get("devices", {}), after.get("devices", {})
    if isinstance(db_, dict) and isinstance(da, dict):
        for name, b in db_.items():
            if not isinstance(b, dict):
                continue
            a = da.get(name) or {}
            if b.get("reachable") and not a.get("reachable"):
                if a.get("maintenance"):
                    warnings.append(f"device {name}: unreachable but in maintenance")
                else:
                    regressions.append(
                        f"device {name} ({b.get('host')}:{b.get('port')}): "
                        f"was reachable, now unreachable")

    # --- pg role: an unexpected recovery flip is worth a warning -------------
    pb, pa = before.get("pg", {}), after.get("pg", {})
    if "in_recovery" in pb and "in_recovery" in pa and pb["in_recovery"] != pa["in_recovery"]:
        warnings.append(
            f"pg role changed: in_recovery {pb['in_recovery']} → {pa['in_recovery']}")

    # --- git: note the HEAD move (expected on an upgrade, not on a restore) ---
    gb, ga = before.get("git", {}), after.get("git", {})
    head_moved = gb.get("head") != ga.get("head")
    if isinstance(ga, dict) and ga.get("ahead", 0) and ga.get("behind", 0):
        regressions.append("git: histories diverged after the change (ahead AND behind)")

    return {
        "passed": not regressions,
        "regressions": regressions,
        "warnings": warnings,
        "head_moved": head_moved,
        "before_head": gb.get("head"),
        "after_head": ga.get("head"),
        "before_at": before.get("at"),
        "after_at": after.get("at"),
        "node": after.get("node") or before.get("node"),
    }
