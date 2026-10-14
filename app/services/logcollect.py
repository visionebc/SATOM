"""Diagnostic log collection over SSH — the read-only ``get``/``diagnose`` battery.

Web port of the desktop ``app/services/logcollect.py`` (the Logs / Log Collection
page). Tick one or more appliances of the active ADOM, open ONE read-only SSH session per
box and run a curated battery of read-only commands, writing each run to a
labelled ``.txt`` under ``data/diagnostics/``.

Read-only by construction: every command — battery or custom — is asserted
read-only via :func:`app.services.ssh_ops.assert_readonly` (``get``/``show``/
``diagnose`` only), so a log run can never mutate configuration. Credentials are
the appliance's SSH login (``ssh_login``/``ssh_secret``: the separate CLI user
and password when set, else the API ones); host keys are
trust-on-first-use (handled by :class:`FortiWebReadonlySSH`).

Long fleet runs happen in a background thread; progress is reported through a
FILE (``data/diagnostics/_progress.json``) so it survives across gunicorn
workers — the same worker-proof pattern as :mod:`app.services.rediscovery` (an
in-memory dict would be invisible to the worker that handles the poll).

Since 2026-10-14 the page runs the active ADOM's battery
(:mod:`app.services.diag_battery`, chosen in Administrator → Diagnostic
Battery) on that ADOM's devices. Each target carries a PLAN computed in the
request context (:func:`app.services.diag_battery.plan`): commands the
device's build does not have, or the battery rule now refuses, are not sent
and the report says why (``SKIPPED: …`` / ``SKIPPED (blocked): …``). A command
that is sent and answered with the CLI's "no such command" errors is marked
``[not available on this build]``. :data:`DIAGNOSTIC_COMMANDS` stays the
FortiWeb default.

Pure helpers (``parse_commands``/``report_filename``/``_parse_meta``/
``not_available``) are network-free and unit-tested; ``collect``/``start``
need a live appliance (or a fake SSH class).
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Iterable

from .ssh_ops import FortiWebReadonlySSH, assert_readonly

# The full field battery — all read-only get/diagnose (status, HA, hardware,
# disk, network…). Ported verbatim from the desktop logcollect battery; the
# union of the field scripts' ``rec_logs`` with the originals' stray double
# spaces normalised and the trailing ``exit`` dropped.
#
# Measured on fortiweb17 (7.6.8) and fortiweb18 (8.0.6), 2026-10-14: two
# entries of the desktop battery never produced data on either build and were
# dropped -- ``diagnose hardware harddisk`` alone answers "you must specify
# cmd" (its list/info/health/errors/attributes children stay), and
# ``diagnose system ha export-eventlog`` answers "The number of parameters is
# incorrect." ``diagnose hardware cpu`` printed nothing; ``... cpu list`` (the
# form Device Health already used) answers on both, so the battery uses it.
# Three more print nothing on those KVM units without HA (dbsync status, ha
# dev-info, debug netstatlog show) and stay: they are expected to answer on
# hardware or HA units. ``diagnose debug proxy log 3`` left later the same day:
# it printed nothing on either build and the device describes ``diagnose debug
# proxy`` as "set/get debug for proxyd" -- the trailing 3 SETS a debug level,
# which the battery rule (services/diag_policy.py) refuses.
DIAGNOSTIC_COMMANDS: list[str] = [
    "get system status",
    "get system performance",
    "diagnose system update info",
    "diagnose system mount list",
    "diagnose system dbsync status",
    "diagnose system ha confd_status",
    "diagnose system ha dev-info",
    "diagnose system ha interface-macinfo",
    "diagnose system ha nodes",
    "diagnose system ha status",
    "diagnose system ha sync-stat",
    "diagnose system securitylevel",
    "diagnose hardware sysinfo vm",
    "diagnose hardware cpu list",
    "diagnose hardware harddisk list",
    "diagnose hardware harddisk info",
    "diagnose hardware harddisk health",
    "diagnose hardware harddisk errors",
    "diagnose hardware harddisk attributes",
    "diagnose hardware logdisk info",
    "diagnose hardware interrupts list",
    "diagnose hardware nic list",
    "diagnose network info routing-table all",
    "diagnose network route list",
    "diagnose debug netstatlog show",
    "diagnose network arp list",
    "diagnose hardware mem list",
    "diagnose debug memory",
]


#: What a build answers for a command it does not have (measured on FortiWeb,
#: FortiADC, FortiGate, FortiAnalyzer and FortiAuthenticator CLIs). Matched
#: case-insensitively against the first lines of the answer only, so a log
#: that merely QUOTES one of these phrases further down is not mislabelled.
NOT_AVAILABLE_MARKERS: tuple[str, ...] = (
    "command fail",
    "unknown action",
    "parsing error",
    "command parse error",
    "you must specify",
    "the number of parameters is incorrect",
    "incorrect number of parameters",  # FortiADC 7.6.7 / 8.0.4
    "incomplete command",
)
NOT_AVAILABLE_NOTE = "[not available on this build]"
_HEAD_LINES = 5


def not_available(output: str | None) -> bool:
    """True when ``output`` is the CLI saying this build lacks the command."""
    head = [ln.strip() for ln in (output or "").splitlines() if ln.strip()]
    text = "\n".join(head[:_HEAD_LINES]).lower()
    return any(m in text for m in NOT_AVAILABLE_MARKERS)


def skipped_line(step: dict) -> str:
    """The report line for a command the plan does not send."""
    detail = step.get("detail") or ""
    if step.get("state") == "blocked":
        return f"SKIPPED (blocked): {detail}"
    return f"SKIPPED: {detail}"


def _default_plan(commands: list[str] | None) -> list[dict]:
    cmds = list(commands) if commands else list(DIAGNOSTIC_COMMANDS)
    return [{"command": c, "action": "run", "state": "", "detail": ""} for c in cmds]


def _diag_dir() -> Path:
    """``/opt/satom/data/diagnostics`` — beside the app package.

    ``FORTINET_DIAG_DIR`` overrides it (tests point it at a tmp dir so the
    status endpoint never reads the production progress file).
    """
    override = os.environ.get("FORTINET_DIAG_DIR")
    d = Path(override) if override else (
        Path(__file__).resolve().parents[2] / "data" / "diagnostics")
    d.mkdir(parents=True, exist_ok=True)
    return d


# Name parity with the desktop service.
default_log_dir = _diag_dir


def _progress_path() -> Path:
    return _diag_dir() / "_progress.json"


def _write_json(path: Path, obj) -> None:
    """Atomic write so a poller never reads a half-written file."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)


def parse_commands(text: str) -> list[str]:
    """Sanitise a free-text block (one command per line) into a read-only list.

    Blank lines and ``#`` comments are dropped; every remaining line is asserted
    read-only (the SAME guard the battery uses), raising ``ReadOnlyViolation``
    naming the first offending line — so a custom run can never mutate config.
    Returns the validated commands in order.
    """
    cmds: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        assert_readonly(line)  # raises ReadOnlyViolation on a write/exec line
        cmds.append(line)
    return cmds


def _safe(token: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in (token or "")) or "x"


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def report_filename(appliance_id, label: str, stamp: str | None = None) -> str:
    """``<id>_logs_<label>_<stamp>.txt`` — filesystem-safe."""
    return (
        f"{_safe(str(appliance_id))}_logs_"
        f"{_safe(label) if label else 'manual'}_{stamp or _stamp()}.txt"
    )


def collect(
    appliance,
    secret: str | None = None,
    *,
    label: str = "manual",
    commands: list[str] | None = None,
    plan: list[dict] | None = None,
    on_log: Callable[[str], None] | None = None,
    stats: dict | None = None,
) -> Path:
    """Run a read-only diagnostic battery over SSH into a labelled log file.

    ``plan`` (from :func:`app.services.diag_battery.plan`) decides per command
    whether it is sent; without one every command of ``commands`` (default:
    :data:`DIAGNOSTIC_COMMANDS`) is sent. Skipped commands are written to the
    report with their reason. ``stats``, when given, receives ``ran``,
    ``skipped`` and ``unavailable`` counts.

    Returns the local log path. A single failing command is recorded inline and
    the battery continues; connect/auth failures propagate from
    :class:`FortiWebReadonlySSH`.
    """
    log = on_log or (lambda _m: None)
    steps = [dict(p) for p in plan] if plan is not None else _default_plan(commands)
    for st in steps:  # security gate — refuse the whole run if anything can mutate
        if st.get("action") == "run":
            assert_readonly(st["command"])

    out = _diag_dir()
    path = out / report_filename(appliance.id, label)
    total = len(steps)
    name = getattr(appliance, "name", str(appliance.id))
    port = getattr(appliance, "ssh_port", 22) or 22
    counts = {"ran": 0, "skipped": 0, "unavailable": 0}

    log(f"[{name}] connecting via SSH (port {port})…")
    with FortiWebReadonlySSH(appliance, secret) as ssh, \
            open(path, "w", encoding="utf-8") as f:
        f.write(
            f"=== {name} ({appliance.host}) — logs '{label}' — {datetime.now()} ===\n"
        )
        for i, st in enumerate(steps, 1):
            cmd = st["command"]
            f.write(f"\n{'=' * 60}\nCOMMAND: {cmd}\n{'=' * 60}\n")
            if st.get("action") != "run":
                counts["skipped"] += 1
                f.write(skipped_line(st) + "\n")
                log(f"[{name}] {i}/{total}  skipped  {cmd}")
                continue
            counts["ran"] += 1
            try:
                text = ssh.run_readonly(cmd)
                f.write(text + "\n")
                if not_available(text):
                    counts["unavailable"] += 1
                    f.write(NOT_AVAILABLE_NOTE + "\n")
            except Exception as e:  # noqa: BLE001 — record and keep going
                f.write(f"[error: {e}]\n")
            log(f"[{name}] {i}/{total}  {cmd}")
        f.write(
            f"\n=== end — ran {counts['ran']}, skipped {counts['skipped']}"
            f" — {datetime.now()} ===\n"
        )
    if stats is not None:
        stats.update(counts)
    log(f"[{name}] saved: {path.name} (ran {counts['ran']}, skipped {counts['skipped']})")
    return path


def _parse_meta(fname: str) -> dict:
    """Best-effort ``{device_id, label, stamp}`` from a report filename.

    Layout is ``<id>_logs_<label>_<stamp>.txt``; the label may itself contain
    underscores, so the trailing token after the last underscore is the stamp.
    """
    stem = fname[:-4] if fname.endswith(".txt") else fname
    parts = stem.split("_logs_", 1)
    dev = parts[0] if parts else ""
    label = stamp = ""
    if len(parts) == 2:
        rest = parts[1]
        if "_" in rest:
            label, stamp = rest.rsplit("_", 1)
        else:
            label = rest
    return {"device_id": dev, "label": label, "stamp": stamp}


def history() -> list[dict]:
    """Saved log files, newest first: ``{name, label, device_id, size, modified}``."""
    out: list[dict] = []
    for p in _diag_dir().glob("*.txt"):
        try:
            st = p.stat()
        except OSError:
            continue
        meta = _parse_meta(p.name)
        out.append({
            "name": p.name,
            "label": meta["label"] or "manual",
            "device_id": meta["device_id"],
            "size": st.st_size,
            "modified": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            "mtime": st.st_mtime,
        })
    out.sort(key=lambda d: d["mtime"], reverse=True)
    return out


def read_log(name: str) -> str | None:
    """Return the text of a saved log by basename, or None if missing/invalid.

    Path-traversal safe: only a bare ``*.txt`` basename inside the diagnostics
    folder is ever read (``os.path.basename`` strips any ``..``/separators).
    """
    base = os.path.basename(name or "")
    if not base.endswith(".txt"):
        return None
    p = _diag_dir() / base
    if not p.is_file():
        return None
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def status() -> dict | None:
    """Current/last fleet-collection progress (None if never run)."""
    p = _progress_path()
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _plan_of(tgt, commands: list[str] | None) -> list[dict]:
    plan = getattr(tgt, "plan", None)
    return list(plan) if plan is not None else _default_plan(commands)


def _run(targets: list[SimpleNamespace], label: str,
         commands: list[str] | None, by: str, custom: bool = False) -> None:
    prog = _progress_path()
    total = len(targets)
    state = {
        "state": "running", "total": total, "done": 0, "percent": 0,
        "label": label, "by": by, "custom": custom,
        "command_count": len(commands) if commands else len(DIAGNOSTIC_COMMANDS),
        "current": "", "results": [], "errors": [], "log": [],
        "started": datetime.utcnow().isoformat(), "finished": None,
    }
    _write_json(prog, state)
    lines: list[str] = []

    def on_log(msg: str) -> None:
        lines.append(msg)
        state["log"] = lines[-40:]
        _write_json(prog, state)

    ok = 0
    for i, tgt in enumerate(targets, 1):
        state["current"] = tgt.name
        _write_json(prog, state)
        plan = _plan_of(tgt, commands)
        planned_skips = sum(1 for p in plan if p.get("action") != "run")
        stats: dict = {}
        try:
            path = collect(tgt, tgt.password, label=label, plan=plan,
                           on_log=on_log, stats=stats)
            ok += 1
            state["results"].append({
                "device": tgt.name, "ok": True, "file": path.name,
                "ran": stats.get("ran", 0), "skipped": stats.get("skipped", 0),
                "unavailable": stats.get("unavailable", 0)})
        except Exception as e:  # noqa: BLE001 — one box failing never sinks the run
            state["results"].append({"device": tgt.name, "ok": False,
                                     "error": str(e)[:200], "ran": 0,
                                     "skipped": planned_skips, "unavailable": 0})
            state["errors"].append({"device": tgt.name, "error": str(e)[:200]})
            on_log(f"[{tgt.name}] error: {e}")
        state.update(done=i, percent=int(i * 100 / total) if total else 100)
        _write_json(prog, state)

    state.update(state="done", current="", finished=datetime.utcnow().isoformat(),
                 summary=f"{ok}/{total} collection(s) successful")
    _write_json(prog, state)


def start(targets: Iterable[SimpleNamespace], *, label: str = "manual",
          commands: list[str] | None = None, by: str = "",
          custom: bool | None = None) -> dict:
    """Kick off a fleet collection in a background thread.

    ``targets`` are credential SNAPSHOTS (``SimpleNamespace`` with
    id/name/host/username/ssh_login/password/ssh_port, and optionally the
    ``plan`` for that device) captured in the request context — the worker
    thread never touches the ORM. ``password`` is the SSH secret. Refuses to
    start a second run while one looks live (<15 min). Returns the initial
    progress dict.
    """
    custom = bool(commands) if custom is None else bool(custom)
    targets = list(targets)
    if not targets:
        return {"started": False, "reason": "no devices selected"}
    cur = status()
    if cur and cur.get("state") == "running":
        try:
            # ``started`` is naive UTC; .timestamp() would read it as LOCAL
            # time and skew the age by the node's UTC offset.
            age = (datetime.utcnow() - datetime.fromisoformat(cur["started"])).total_seconds()
        except Exception:  # noqa: BLE001
            age = 0
        if age < 900:
            return {"started": False, "reason": "a collection is already running",
                    "progress": cur}
    for tgt in targets:  # fail fast before spawning the thread
        for st in _plan_of(tgt, commands):
            if st.get("action") == "run":
                assert_readonly(st["command"])

    init = {"state": "running", "total": len(targets), "done": 0, "percent": 0,
            "label": label, "by": by, "custom": custom, "results": [],
            "command_count": len(commands) if commands else len(DIAGNOSTIC_COMMANDS),
            "errors": [], "log": [], "current": "",
            "started": datetime.utcnow().isoformat(), "finished": None}
    _write_json(_progress_path(), init)
    threading.Thread(target=_run, args=(targets, label, commands, by, custom),
                     daemon=True).start()
    return {"started": True, "progress": init}


__all__ = [
    "DIAGNOSTIC_COMMANDS", "NOT_AVAILABLE_MARKERS", "default_log_dir",
    "parse_commands", "report_filename", "not_available", "skipped_line",
    "collect", "history", "read_log", "status", "start",
]
