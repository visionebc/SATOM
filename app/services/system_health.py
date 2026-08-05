"""Manager SELF-monitoring: host (LXC) resources, database, services, redundancy.

Pure stdlib (no psutil dependency): /proc + shutil + `systemctl is-active`.
Everything is best-effort — a failed probe returns None/'' and never raises,
so the Monitoring dashboard renders whatever it can.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

from sqlalchemy import text as sa_text

from ..models import db, Appliance

#: Units whose state the Monitoring page reports.
#:
#: What belongs here: a unit whose being down breaks something the operator can
#: see in this console. ``satom-metrics`` (the local time-series store) is the
#: 2026-08-05 addition — Analytics boards and the Collection page read from it,
#: so a stopped store turns those pages into errors while every other signal
#: stays green.
#:
#: What deliberately does NOT belong here: units that are inactive **by design**
#: on this node. ``satom-ha-datasync.timer`` is role-guarded and inert on the
#: primary; ``satom-git-publish.timer`` was retired with the git SoT. Listing
#: either would show a permanent red for correct behaviour, and a check that
#: always complains is a check the operator learns to skip -- the same false
#: positive that had to be removed from ``get system health`` twice.
MONITORED_UNITS = (
    "satom.service",
    "satom-scheduler.service",
    "satom-reconciler.service",
    "satom-metrics.service",
    "satom-updater.path",
    "nginx.service",
    "postgresql.service",
    "redis-server.service",
    "nftables.service",
)

DB_BACKUP_DIR = "/var/backups/fortinet-db"


# ---------------------------------------------------------------------------
# Host (the LXC running the manager)
# ---------------------------------------------------------------------------

def _meminfo() -> dict:
    out = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            parts = line.split()
            if parts and parts[0].rstrip(":") in ("MemTotal", "MemAvailable"):
                out[parts[0].rstrip(":")] = int(parts[1])  # kB
    except Exception:
        pass
    return out


def host_stats() -> dict:
    mem = _meminfo()
    total_mb = int(mem.get("MemTotal", 0) / 1024) or None
    avail_mb = int(mem.get("MemAvailable", 0) / 1024) or None
    used_mb = (total_mb - avail_mb) if total_mb and avail_mb is not None else None
    try:
        load1, load5, load15 = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = None
    cpus = os.cpu_count() or None
    disks = []
    seen_totals = set()
    for label, path in (("/", "/"), ("app data", "/opt/satom"),
                        ("logs", "/var/log")):
        try:
            du = shutil.disk_usage(path)
        except OSError:
            continue
        if du.total in seen_totals:  # same filesystem — don't repeat it
            continue
        seen_totals.add(du.total)
        disks.append({"mount": label, "total_gb": round(du.total / 1e9, 1),
                      "used_gb": round(du.used / 1e9, 1),
                      "pct": round(100 * du.used / du.total, 1)})
    uptime_s = None
    try:
        uptime_s = int(float(Path("/proc/uptime").read_text().split()[0]))
    except Exception:
        pass
    return {
        "hostname": socket.gethostname(),
        "cpus": cpus,
        "load": [round(v, 2) for v in (load1, load5, load15)] if load1 is not None else None,
        "load_pct": round(100 * load1 / cpus, 1) if (load1 is not None and cpus) else None,
        "mem_total_mb": total_mb, "mem_used_mb": used_mb,
        "mem_pct": round(100 * used_mb / total_mb, 1) if (total_mb and used_mb is not None) else None,
        "disks": disks,
        "uptime_s": uptime_s,
    }


def service_status(units: tuple[str, ...] = MONITORED_UNITS) -> list[dict]:
    """State of each monitored unit, separating *broken* from *not installed*.

    ``systemctl is-active`` answers ``inactive`` for a unit that does not exist
    on this host, which is indistinguishable from a unit that exists and is
    stopped. Those are different findings: a standalone install with no
    ``nftables`` package is fine, a node whose ``satom-metrics`` died is not.
    ``LoadState`` tells them apart, so a missing unit is reported with
    ``ok=None`` (neutral, grey) instead of red.
    """
    out = []
    for u in units:
        state, installed = "unknown", True
        try:
            r = subprocess.run(["systemctl", "show", "-p", "LoadState",
                                "--value", u],
                               capture_output=True, text=True, timeout=5)
            installed = (r.stdout or "").strip() != "not-found"
        except Exception:
            pass
        if not installed:
            out.append({"unit": u, "state": "not installed",
                        "ok": None, "installed": False})
            continue
        try:
            r = subprocess.run(["systemctl", "is-active", u],
                               capture_output=True, text=True, timeout=5)
            state = (r.stdout or "").strip() or "unknown"
        except Exception:
            pass
        out.append({"unit": u, "state": state, "ok": state == "active",
                    "installed": True})
    return out


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def db_stats() -> dict:
    info: dict = {"dialect": "", "ok": False, "latency_ms": None, "size": None,
                  "version": "", "tables": {}, "replicas": None,
                  "last_backup": None}
    try:
        info["dialect"] = db.engine.dialect.name
        t0 = time.monotonic()
        db.session.execute(sa_text("SELECT 1"))
        info["latency_ms"] = round((time.monotonic() - t0) * 1000, 1)
        info["ok"] = True
    except Exception as exc:
        info["error"] = str(exc)[:200]
        return info
    if info["dialect"].startswith("postgres"):
        try:
            info["version"] = db.session.execute(
                sa_text("SHOW server_version")).scalar() or ""
        except Exception:
            pass
        try:
            info["size"] = db.session.execute(sa_text(
                "SELECT pg_size_pretty(pg_database_size(current_database()))"
            )).scalar()
        except Exception:
            pass
        try:  # streaming replication (redundancy) — usually needs privileges
            info["replicas"] = db.session.execute(sa_text(
                "SELECT count(*) FROM pg_stat_replication")).scalar()
        except Exception:
            db.session.rollback()
            info["replicas"] = None
    for table in ("appliances", "device_objects", "audit_logs", "users",
                  "config_backups", "device_certificates", "capacity_limits"):
        try:
            info["tables"][table] = db.session.execute(
                sa_text(f"SELECT count(*) FROM {table}")).scalar()
        except Exception:
            db.session.rollback()
    # nightly pg_dump freshness
    try:
        files = sorted(Path(DB_BACKUP_DIR).glob("*"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
        if files:
            st = files[0].stat()
            info["last_backup"] = {"file": files[0].name,
                                   "age_h": round((time.time() - st.st_mtime) / 3600, 1),
                                   "size_mb": round(st.st_size / 1e6, 2)}
    except Exception:
        pass
    return info


# ---------------------------------------------------------------------------
# Redundancy — device HA clusters + the manager's own footprint
# ---------------------------------------------------------------------------

def _manager_summary() -> dict:
    """Real manager-HA health (nodes/roles/streaming/scheduler) — replaces the
    old hardcoded 'single instance' stub. Lazy import avoids a circular ref."""
    try:
        from . import cluster
        return cluster.manager_summary()
    except Exception as exc:
        return {"instances": 1, "standby": False, "scheduler_ok": False,
                "note": "HA summary unavailable: %s" % str(exc)[:120]}


def redundancy() -> dict:
    """Device HA posture + the manager's own redundancy.

    Until 2026-08-05 the device half read ``Appliance.members`` and nothing
    else. That table is written ONLY by the appliance form, so on a fleet whose
    harvest had ``system_ha`` cached for every box the panel rendered
    *"No HA clusters registered"* and threw away the standalone count it had
    just computed. ``ha_inventory`` derives the posture from the cache, which is
    where the truth already was.
    """
    devices, clusters = [], []
    counts = {"clustered": 0, "standalone": 0, "unknown": 0}
    try:
        from . import ha_inventory
        roll = ha_inventory.fleet(Appliance.query.order_by(Appliance.name).all())
        devices, clusters, counts = roll["devices"], roll["clusters"], roll["counts"]
    except Exception:
        pass
    return {
        "device_clusters": clusters,
        "device_posture": devices,
        "device_counts": counts,
        # Kept for API compatibility with anything reading the old key.
        "device_standalone": counts.get("standalone", 0),
        "manager": _manager_summary(),
    }
