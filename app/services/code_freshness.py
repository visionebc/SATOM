"""Is each long-running SATOM process running the code that is on disk?

The operator CLI has asked this since 2.x (``satom diagnose code``), but only
when somebody typed it. On 2026-10-13 satom-scheduler on the primary had been
running code from two days earlier for 45 hours: deploys restarted only
``satom.service``, and the scheduler's hourly ``device_sync`` kept reporting
"6/6 ok" while leaving out the FortiGate the new code had added. Nothing
alerted, because nothing that runs on its own looked.

This module is the app-side half: :func:`stale` feeds the alert engine
(``alerts._check_code``). Same rule as the CLI — a process is stale when it
started before the newest ``.py`` it loads — plus a grace window, because the
engine can tick between ``git pull`` and ``restart-all`` of a normal deploy.

Templates are not checked here. A stale Jinja cache shows old markup; a stale
module runs old logic on the scheduled path, which is the failure worth a mail.
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

#: Long-running processes that import ``app/``. Same aliases as the CLI.
UNITS = {
    "web": "satom.service",
    "scheduler": "satom-scheduler.service",
    "reconciler": "satom-reconciler.service",
}

#: A deploy pulls first and restarts seconds later; the engine must not mail
#: about the gap. Fifteen minutes is far longer than ``restart-all`` takes and
#: far shorter than the 45 hours this check exists for.
GRACE_S = 15 * 60


def app_root() -> Path:
    """The checkout this process was imported from (``/opt/satom``)."""
    return Path(__file__).resolve().parents[2]


def newest_source(root: Path | None = None) -> tuple[Path | None, float]:
    """``(path, mtime)`` of the newest importable ``.py`` under ``app/``.

    Skips ``__pycache__`` and dot-paths (scratch files nothing can import) —
    the same filter as ``satom diagnose code``.
    """
    root = root or app_root()
    newest, newest_m = None, 0.0
    pkg = root / "app"
    for p in (pkg.rglob("*.py") if pkg.is_dir() else ()):
        rel = p.relative_to(root).parts
        if "__pycache__" in rel or any(part.startswith(".") for part in rel):
            continue
        try:
            m = p.stat().st_mtime
        except OSError:
            continue
        if m > newest_m:
            newest, newest_m = p, m
    return newest, newest_m


def proc_start_epoch(pid: int) -> float | None:
    """Absolute start time of ``pid`` from /proc (no ``ps``, no date parsing)."""
    try:
        with open("/proc/stat") as fh:
            btime = next(int(line.split()[1]) for line in fh if line.startswith("btime "))
        with open("/proc/%d/stat" % int(pid)) as fh:
            fields = fh.read().rsplit(") ", 1)[1].split()
        return btime + int(fields[19]) / os.sysconf("SC_CLK_TCK")
    except Exception:  # noqa: BLE001
        return None


def main_pid(unit: str) -> int | None:
    """systemd's MainPID for ``unit``; None when stopped or unknown."""
    try:
        r = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", unit],
                           capture_output=True, text=True, timeout=5)
        return int((r.stdout or "").strip() or 0) or None
    except Exception:  # noqa: BLE001
        return None


def stale(*, root: Path | None = None, now: float | None = None,
          pid_of=main_pid, start_of=proc_start_epoch) -> list[dict]:
    """Running processes older than the newest source, past the grace window.

    ``[{"alias", "unit", "behind_h", "newest"}]``. A unit that is not running,
    or whose start time cannot be read, is not reported: "is it running" is
    the unit-health check's question, not this one.
    """
    newest, newest_m = newest_source(root)
    if newest is None:
        return []
    now = time.time() if now is None else now
    if now - newest_m < GRACE_S:
        return []
    base = root or app_root()
    out = []
    for alias, unit in UNITS.items():
        pid = pid_of(unit)
        started = start_of(pid) if pid else None
        if started is None or started >= newest_m:
            continue
        out.append({"alias": alias, "unit": unit,
                    "behind_h": round((newest_m - started) / 3600.0, 1),
                    "newest": str(newest.relative_to(base))})
    return out


__all__ = ["UNITS", "GRACE_S", "newest_source", "proc_start_epoch", "main_pid", "stale"]
