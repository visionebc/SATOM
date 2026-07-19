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

MONITORED_UNITS = (
    "satom.service",
    "satom-scheduler.service",
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
    out = []
    for u in units:
        state = "unknown"
        try:
            r = subprocess.run(["systemctl", "is-active", u],
                               capture_output=True, text=True, timeout=5)
            state = (r.stdout or "").strip() or "unknown"
        except Exception:
            pass
        out.append({"unit": u, "state": state, "ok": state == "active"})
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
    clusters = []
    standalone = 0
    try:
        all_apps = Appliance.query.order_by(Appliance.name).all()
        member_ids: set[int] = set()
        node0_ids: set[int] = set()
        for a in all_apps:
            members = list(getattr(a, "members", None) or [])
            if members:
                node0_ids.add(a.id)
                member_ids.update(m.id for m in members)
                clusters.append({
                    "name": a.name, "mode": a.ha_mode or "", "vip": a.ha_vip or "",
                    "members": [{"name": m.name,
                                 "role": m.ha_role_hint or ""} for m in members],
                })
        standalone = sum(1 for a in all_apps
                         if a.id not in member_ids and a.id not in node0_ids)
    except Exception:
        pass
    sched = next((s for s in service_status(("satom-scheduler.service",))), None)
    return {
        "device_clusters": clusters,
        "device_standalone": standalone,
        "manager": _manager_summary(),
    }
