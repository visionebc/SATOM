"""Manager SELF-monitoring: host (LXC) resources, database, services, redundancy.

Pure stdlib (no psutil dependency): /proc + shutil + `systemctl is-active`.
Everything is best-effort — a failed probe returns None/'' and never raises,
so the Monitoring dashboard renders whatever it can.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from sqlalchemy import text as sa_text

from ..models import db

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


# --- CPU -------------------------------------------------------------------
# ``os.getloadavg()`` MUST NOT be used to grade this node. lxcfs does not
# virtualise /proc/loadavg (nor /proc/uptime), so inside an LXC both are the
# HYPERVISOR's. Dividing the host's load average by the container's core count
# mixes a host numerator with a container denominator: on 2026-08-11 hypervisor06 sat
# at load 6.6 -- 27% of its 24 cores, healthy -- and this function reported
# "220% of 3 cores" on a standby and "165% of 4 cores" on a primary in
# the same second, while every process in both containers was at 0.0% CPU.
# Two containers cannot share an uptime and a load average to the decimal; that
# they did is the proof. /proc/meminfo IS virtualised, which is why memory was
# right and only CPU lied.
#
# The cgroup's own CPU accounting is the container's, so that is what we read.
CPU_SAMPLE_FILE = "satom-cpu-sample.json"
#: Below this the window is too short to mean anything -- and the caller is
#: usually the health page, whose own render is the CPU being measured.
CPU_MIN_WINDOW_S = 2.0
#: Above this the counter is too stale to trust (suspend, clock jump).
CPU_MAX_WINDOW_S = 3600.0
CPU_INLINE_SAMPLE_S = 0.25


def _cgroup_cpu_usec() -> int | None:
    """Cumulative CPU time of THIS cgroup, in microseconds. cgroup v2, then v1."""
    try:
        for line in Path("/sys/fs/cgroup/cpu.stat").read_text().splitlines():
            key, _, val = line.partition(" ")
            if key == "usage_usec":
                return int(val)
    except Exception:
        pass
    try:  # cgroup v1 reports nanoseconds
        return int(Path("/sys/fs/cgroup/cpuacct/cpuacct.usage")
                   .read_text().strip()) // 1000
    except Exception:
        return None


def _cpu_sample_path() -> Path:
    return Path(tempfile.gettempdir()) / CPU_SAMPLE_FILE


def _read_cpu_sample() -> dict | None:
    """Previous (time, counter) sample, or None if it cannot be trusted.

    Stamped with the hostname because ``data/`` is rsynced between the HA pair
    and a peer's counter would produce a nonsense delta. The file lives in the
    temp dir precisely so it is NOT replicated, but the stamp costs nothing and
    the failure it prevents is silent.
    """
    try:
        d = json.loads(_cpu_sample_path().read_text())
    except Exception:
        return None
    if d.get("host") != socket.gethostname():
        return None
    return d if isinstance(d.get("t"), (int, float)) and \
        isinstance(d.get("usec"), int) else None


def _write_cpu_sample(t: float, usec: int) -> None:
    try:
        _cpu_sample_path().write_text(json.dumps(
            {"host": socket.gethostname(), "t": t, "usec": usec}))
    except Exception:
        pass


def cpu_pct() -> float | None:
    """Percent of THIS container's cores busy. ``None`` when unmeasurable.

    Averaged over the window since the last call -- ~15 min when the alert
    timer is the caller, which is the smoothing the load average used to give.
    A sub-second window would make a page render register as a CPU spike, so
    windows shorter than :data:`CPU_MIN_WINDOW_S` fall back to a brief inline
    sample and deliberately do NOT advance the stored one.
    """
    cpus = os.cpu_count() or 0
    now, usec = time.time(), _cgroup_cpu_usec()
    if not cpus or usec is None:
        return None
    prev = _read_cpu_sample()
    if prev:
        window = now - prev["t"]
        # usec < prev means the cgroup was recreated (container restart).
        if CPU_MIN_WINDOW_S <= window <= CPU_MAX_WINDOW_S and usec >= prev["usec"]:
            _write_cpu_sample(now, usec)
            return round(100.0 * (usec - prev["usec"]) / (window * 1e6 * cpus), 1)
        if window < CPU_MIN_WINDOW_S:
            return _cpu_pct_inline(cpus)
    _write_cpu_sample(now, usec)
    return _cpu_pct_inline(cpus)


def _cpu_pct_inline(cpus: int) -> float | None:
    a = _cgroup_cpu_usec()
    if a is None:
        return None
    t0 = time.monotonic()
    time.sleep(CPU_INLINE_SAMPLE_S)
    b, elapsed = _cgroup_cpu_usec(), time.monotonic() - t0
    if b is None or elapsed <= 0:
        return None
    return round(100.0 * (b - a) / (elapsed * 1e6 * cpus), 1)


def container_uptime_s() -> int | None:
    """Uptime of THIS container. /proc/uptime alone is the hypervisor's.

    PID 1 of our PID namespace is the container's init, and its start time is
    expressed in ticks since HOST boot -- the same origin /proc/uptime counts
    from -- so the subtraction is well defined. On bare metal PID 1 started at
    boot and the result degrades to the host uptime, which is then correct.
    """
    try:
        host_up = float(Path("/proc/uptime").read_text().split()[0])
    except Exception:
        return None
    try:
        stat = Path("/proc/1/stat").read_text()
        # comm (field 2) may contain spaces and parens: index past the LAST ')'
        tail = stat[stat.rindex(")") + 2:].split()
        ticks = float(tail[19])            # field 22 = starttime
        hz = os.sysconf("SC_CLK_TCK") or 100
        return max(0, int(host_up - ticks / hz))
    except Exception:
        return int(host_up)


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
    return {
        "hostname": socket.gethostname(),
        "cpus": cpus,
        # The load average is the HYPERVISOR's inside an LXC. Kept because it
        # is genuinely useful (a busy host slows us down) and labelled so, but
        # NOT graded -- see the note above cpu_pct(). ``load_pct`` was removed
        # rather than corrected: leaving the key would let a caller keep
        # dividing a host numerator by a container denominator.
        "load": [round(v, 2) for v in (load1, load5, load15)] if load1 is not None else None,
        "load_scope": "host" if is_container() else "self",
        "cpu_pct": cpu_pct(),
        "mem_total_mb": total_mb, "mem_used_mb": used_mb,
        "mem_pct": round(100 * used_mb / total_mb, 1) if (total_mb and used_mb is not None) else None,
        "disks": disks,
        "uptime_s": container_uptime_s(),
    }


def is_container() -> bool:
    """True when /proc/loadavg and /proc/uptime describe someone else.

    Each probe is tried INDEPENDENTLY. Chaining them with ``or`` inside one
    ``try`` looked equivalent and was not: /proc/1/environ is root-only, so as
    the unprivileged service user the PermissionError skipped the second probe
    and this returned False on a machine that is plainly an LXC.
    """
    try:
        if Path("/run/systemd/container").exists():
            return True
    except Exception:
        pass
    try:
        if Path("/proc/1/environ").read_bytes().find(b"container=") >= 0:
            return True
    except Exception:
        pass
    return False


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
    """The MANAGER's own redundancy. Appliance HA lives on Device health.

    This function feeds ``/monitoring/satom`` — "this installation". It used to
    carry the per-appliance HA posture too, and that was the defect: a counter
    reading ``0 clustered · 1 standalone`` on a page about the installation says
    SATOM is a single node, when SATOM was a two-node streaming pair and the
    number described the *appliances*. Right number, wrong page.

    Two reasons the device half moved to ``/monitoring/data`` rather than merely
    being hidden here:

    * **Scope.** It was built from an unscoped ``Appliance.query``. Rendered on a
      page that every ADOM can reach, that leaks FortiADC boxes into the FortiWeb
      ADOM — the exact contract §9c exists to hold.
    * **Cost.** The device feed already walks every visible appliance; the
      manager feed has no reason to walk any.

    ``manager_posture`` states the installation's own HA in the same
    clustered/standalone/unknown vocabulary the device rows use, so the two
    pages can be read with one set of eyes.
    """
    summary = _manager_summary()
    posture = {"status": "unknown", "mode": "", "role": "", "evidence": [],
               "note": summary.get("note", ""), "split_brain": False}
    try:
        from . import ha_inventory
        posture = ha_inventory.manager_posture(summary)
    except Exception:
        pass
    return {"manager": summary, "manager_posture": posture}
