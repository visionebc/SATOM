"""Manager High-Availability / cluster state — the ONE place the admin sees the
whole HA picture (nodes, roles, live streaming replication, scheduler, the load
balancer probe, and the staged-update interlock) AND can trigger a guarded,
manual failover.

All reads are local (the app's own Postgres) — a page load never touches a
FortiWeb. The promote WRITE is an ENQUEUE only: the privileged
``fortinet-manager-updater`` root runner performs the actual ``pg_ctlcluster
promote`` (via ``deploy/fm-promote.sh``), so the unprivileged web worker never
needs privilege. Automatic failover is deliberately NOT wired — with two
standalone Postgres hosts and no quorum, an auto-promote would invite
split-brain; promotion is always an explicit, confirmed operator action.
"""
from __future__ import annotations

import glob
import json
import os
from datetime import datetime
from pathlib import Path

from . import self_update as su

APP_DIR = Path(os.environ.get("FM_APP_DIR", "/opt/fortinet-manager"))
REQ_DIR = APP_DIR / "data" / "update-requests"
STA_DIR = APP_DIR / "data" / "update-status"
SCHED_UNIT = "fortinet-manager-scheduler.service"

# The health endpoint a load balancer should probe to route only to the
# read-write primary (200 = primary, 503 = standby). Wired in app/__init__.py.
LB_PROBE_PATH = "/healthz/primary"


def _probe_peer(host: str, timeout: float = 1.5) -> dict:
    """Actively probe a peer node over HTTP (from THIS node) so the admin sees
    the secondary's real role + revision + app health WITHOUT SSH access to it.
    role: /healthz/primary (200=primary, 503=standby); revision + app_up:
    /healthz. Best-effort — an unreachable peer just reports reachable=False."""
    import urllib.request
    import urllib.error
    base = "http://%s:8000" % host
    out = {"reachable": False, "role": None, "revision": None, "app_up": False, "db": None}
    try:
        with urllib.request.urlopen(base + "/healthz/primary", timeout=timeout) as r:
            out["reachable"] = True
            out["role"] = "primary" if r.status == 200 else "standby"
    except urllib.error.HTTPError as e:
        out["reachable"] = True
        out["role"] = "standby" if e.code == 503 else None
    except Exception:
        pass
    try:
        with urllib.request.urlopen(base + "/healthz", timeout=timeout) as r:
            out["reachable"] = True
            d = json.loads(r.read().decode("utf-8", "replace"))
            out["app_up"] = bool(d.get("ok"))
            out["revision"] = {"short": d.get("revision"), "sha": d.get("sha")}
            out["db"] = d.get("db")
    except Exception:
        pass
    return out


def _num(v):
    """Coerce a Postgres numeric/Decimal to a JSON-safe int (bytes of WAL lag)."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def replication() -> dict:
    """Live streaming-replication state from the LOCAL Postgres.

    On the primary  → the sender side (``pg_stat_replication``: who's connected,
                      their state, and the WAL bytes they're behind).
    On a standby    → the receiver side (public WAL LSN functions: how far behind
                      apply is, and whether WAL is still arriving).
    """
    out = {"role": su.node_role(), "senders": [], "receiver": None,
           "streaming": False, "error": None}
    try:
        from ..models import db
        from sqlalchemy import text
        if out["role"] == "primary":
            rows = db.session.execute(text(
                "SELECT client_addr, state, sync_state, "
                "  pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) AS lag_bytes "
                "FROM pg_stat_replication")).mappings().all()
            out["senders"] = [{
                "client_addr": str(r["client_addr"]) if r["client_addr"] else None,
                "state": r["state"],
                "sync_state": r["sync_state"],
                "lag_bytes": _num(r["lag_bytes"]),
            } for r in rows]
            out["streaming"] = any(s["state"] == "streaming" for s in out["senders"])
        elif out["role"] == "standby":
            row = db.session.execute(text(
                "SELECT pg_last_wal_receive_lsn() AS recv, "
                "  pg_last_wal_replay_lsn() AS replay, "
                "  pg_wal_lsn_diff(pg_last_wal_receive_lsn(), "
                "                  pg_last_wal_replay_lsn()) AS apply_lag")).mappings().first()
            if row:
                out["receiver"] = {
                    "receive_lsn": str(row["recv"]) if row["recv"] else None,
                    "replay_lsn": str(row["replay"]) if row["replay"] else None,
                    "apply_lag_bytes": _num(row["apply_lag"]),
                }
                out["streaming"] = bool(row["recv"])
    except Exception as e:  # never let a bad txn poison the request session
        try:
            from ..models import db
            db.session.rollback()
        except Exception:
            pass
        out["error"] = str(e)[:200]
    return out


def db_summary(rep: dict | None = None) -> dict:
    """Compact, display-ready DB/replication status for ONE node — shown on the
    HA card and embedded in /healthz so a peer can render our DB state too (no
    SSH needed). Symmetric across failover: the primary shows its sender/replica
    view, a standby shows its apply-lag view."""
    rep = rep if rep is not None else replication()
    role = rep.get("role")
    if rep.get("error"):
        return {"role": role, "state": "error", "healthy": False,
                "lag_bytes": None, "detail": rep.get("error")}
    if role == "primary":
        senders = rep.get("senders", [])
        streaming = bool(rep.get("streaming"))
        lag = max([s.get("lag_bytes") or 0 for s in senders], default=0)
        if streaming:
            state = "streaming"
        elif senders:
            state = senders[0].get("state") or "connected"
        else:
            state = "no standby"
        return {"role": "primary", "state": state, "healthy": streaming,
                "replicas": len(senders),
                "sync_state": (senders[0].get("sync_state") if senders else None),
                "lag_bytes": (lag if senders else None)}
    if role == "standby":
        recv = rep.get("receiver") or {}
        streaming = bool(rep.get("streaming"))
        return {"role": "standby",
                "state": "replicating" if streaming else "not receiving",
                "healthy": streaming, "replicas": None, "sync_state": None,
                "lag_bytes": recv.get("apply_lag_bytes")}
    return {"role": role, "state": "unknown", "healthy": None, "lag_bytes": None}


def scheduler_local() -> dict:
    """Is the single-instance scheduler firing on THIS node? It only fires on the
    primary (guarded by ``pg_is_in_recovery()``); on a standby it idle-waits."""
    from .system_health import service_status
    s = next(iter(service_status((SCHED_UNIT,))), None)
    return {"active": bool(s and s.get("active")), "ok": bool(s and s.get("ok")),
            "detail": (s or {}).get("detail", "")}


def promote_eligible() -> bool:
    """A node may be promoted only when it is currently a standby AND the
    deployment mode is HA (standalone mode disables failover entirely)."""
    return su.ha_mode() == "ha" and su.node_role() == "standby"


def request_promote(by: str) -> str:
    """Enqueue a guarded failover. The privileged root runner picks this up,
    runs ``deploy/fm-promote.sh`` (pg promote + start app), and writes a status
    JSON the UI polls. Returns the request uid."""
    REQ_DIR.mkdir(parents=True, exist_ok=True)
    uid = "promote-" + datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    payload = {
        "kind": "promote",
        "id": uid,
        "requested_by": by,
        "node": su.this_node_name(),
        "role": su.node_role(),
        "requested_at": datetime.utcnow().isoformat() + "Z",
    }
    # Write OUTSIDE the watched dir then atomically move in, so the .path unit
    # sees a complete file (never a half-written one).
    tmp = APP_DIR / "data" / (uid + ".json.tmp")
    tmp.write_text(json.dumps(payload))
    os.replace(tmp, REQ_DIR / (uid + ".json"))
    return uid


def promote_status(uid: str) -> dict | None:
    try:
        return json.loads((STA_DIR / (uid + ".json")).read_text())
    except Exception:
        return None


def last_promote() -> dict | None:
    files = sorted(glob.glob(str(STA_DIR / "promote-*.json")))
    if not files:
        return None
    try:
        return json.loads(Path(files[-1]).read_text())
    except Exception:
        return None


def manager_summary() -> dict:
    """Compact HA health for the Monitoring redundancy panel (fixes the old
    hardcoded 'single instance — no standby' lie)."""
    reps = su.node_reports()
    role = su.node_role()
    mode = su.ha_mode()
    primaries = [n for n in reps
                 if ((n.get("report") or {}).get("role")) == "primary"]
    standbys = [n for n in reps
                if ((n.get("report") or {}).get("role")) == "standby"]
    rep = replication()
    sched = scheduler_local()
    # The standby can't publish its own self-report to the shared (replicated)
    # settings — that store lives on the primary and replication is one-way. So
    # derive "a standby exists" from what the PRIMARY authoritatively sees: a
    # live streaming replica in pg_stat_replication.
    standby_present = (len(standbys) > 0
                       or bool([s for s in rep.get("senders", [])
                                if s.get("state") == "streaming"]))
    split = len(primaries) > 1
    if mode == "standalone":
        note = ("Standalone mode (admin-set) — HA interlock, peer probes and "
                "failover are disabled. Recovery = nightly DB dump + git-published "
                "reports.")
    elif len(reps) <= 1:
        note = ("Single node registered — no hot standby. Recovery = nightly DB "
                "dump + git-published reports.")
    elif split:
        note = ("SPLIT-BRAIN: more than one node reports PRIMARY. Demote one "
                "before writes diverge.")
    elif rep.get("streaming"):
        note = ("Active-passive: %d node(s), streaming replication live." % len(reps))
    else:
        note = ("%d nodes registered but replication is NOT streaming right now "
                "— check the standby." % len(reps))
    return {
        "instances": len(reps),
        "mode": mode,
        "standby": standby_present,
        "this_role": role,
        "primaries": len(primaries),
        "streaming": bool(rep.get("streaming")),
        "split_brain": split,
        "scheduler_ok": sched["ok"],
        "lb_probe": LB_PROBE_PATH,
        "note": note,
    }


def full_state() -> dict:
    """Everything the HA admin panel renders, in one call."""
    role = su.node_role()
    rep = replication()
    nodes = su.node_reports()
    # On the primary, synthesize a report for any peer that is a live streaming
    # replica but hasn't self-reported (the standby can't write the shared,
    # replicated store — see manager_summary()). Match by host == client_addr.
    this = su.this_node_name()
    mode = su.ha_mode()
    addrs = {sn.get("client_addr") for sn in rep.get("senders", [])
             if sn.get("state") == "streaming"}
    # For every PEER (not self) actively probe its HTTP endpoints — this works
    # even when the operator has no SSH to the secondary, and is authoritative
    # for a running peer. Fall back to the replication view if unreachable.
    for n in nodes:
        if n.get("name") == this:
            rpt = n.get("report") or {}
            rpt["db"] = db_summary(rep)
            n["report"] = rpt
            continue
        if mode != "ha":
            n["report"] = {"role": None, "healthy": None, "revision": None,
                           "reported_at": "standalone mode — probe disabled",
                           "source": "disabled", "reachable": None, "db": None}
            continue
        host = n.get("host")
        pr = _probe_peer(host) if host and host != "127.0.0.1" else {"reachable": False}
        if pr.get("reachable"):
            n["report"] = {
                "role": pr.get("role") or ("standby" if host in addrs else None),
                "healthy": pr.get("app_up"),
                "revision": pr.get("revision"),
                "reported_at": "live probe",
                "source": "probe",
                "reachable": True,
                "db": pr.get("db"),
            }
        elif not n.get("report") and host in addrs:
            snd = next((s for s in rep.get("senders", [])
                        if s.get("client_addr") == host), None)
            n["report"] = {"role": "standby", "healthy": True, "revision": None,
                           "reported_at": "replicating (app unreachable)",
                           "source": "replication", "reachable": False,
                           "db": {"role": "standby", "state": "replicating",
                                  "healthy": True,
                                  "lag_bytes": (snd.get("lag_bytes") if snd else None)}}
        elif not n.get("report"):
            n["report"] = {"role": None, "healthy": False, "revision": None,
                           "reported_at": "unreachable", "source": "none",
                           "reachable": False, "db": None}
    return {
        "this_node": su.this_node_name(),
        "this_role": role,
        "nodes": nodes,
        "replication": rep,
        "scheduler": scheduler_local(),
        "interlock": su.validated_state(),
        "mode": mode,
        "promote_eligible": mode == "ha" and role == "standby",
        "last_promote": last_promote(),
        "lb_probe": LB_PROBE_PATH,
        "reconcile": _reconcile_view(),
    }


def _reconcile_view() -> dict:
    """Deploy-automation mode + the reconciler's last published tick, for the
    HA panel. Kept import-lazy to avoid any import-order coupling."""
    try:
        from . import reconciler as _rec
        return {"mode": _rec.deploy_mode_orm(), "last": _rec.last_status_orm()}
    except Exception:
        return {"mode": "manual", "last": None}
