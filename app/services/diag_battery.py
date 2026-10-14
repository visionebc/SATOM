"""Per-ADOM diagnostic batteries and per-build discovery catalogs.

The administrator picks, per ADOM, the commands Diagnose Log Collection runs
(Administrator → Diagnostic Battery). The candidates come from a DISCOVERY
walk of a real device of that ADOM (:mod:`app.services.diag_tree`), stored per
(product, build) in :class:`app.models_diag.DiagCatalog`. At run time every
command is checked against the catalog of the target device's build: a command
the build does not have is not sent and the report says so.

Every command — picked from the catalog, typed by hand, or a product default —
passes :func:`app.services.diag_policy.battery_reason` on save AND again on
run, so a battery saved before a rule tightened can never send what the rule
now refuses.

Discovery runs in a background thread (one at a time, fleet-wide); progress is
a FILE under ``data/diagnostics/`` so every gunicorn worker reads the same
state — the pattern :mod:`app.services.logcollect` uses.
"""
from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from .diag_policy import battery_reason
from . import diag_tree

# Products a battery exists for (the device ADOMs). Global has none: it has no
# devices of its own, and a battery runs on one product's CLI.
PRODUCTS: tuple[str, ...] = (
    "fortiweb", "fortiadc", "fortigate", "fortianalyzer", "fortiauthenticator")

# What an ADOM runs before an administrator picks anything. FortiWeb keeps the
# measured field battery (services/logcollect.py). The other four start from
# commands answered by the lab devices of 2026-10-14 (fortiadc10 7.6.7,
# fgt02 8.0.1, faz02 7.6.7, fac01 8.0.3) — read-only, terminating, and
# present in those builds' discovery walks.
def _fortiweb_default() -> list[str]:
    from .logcollect import DIAGNOSTIC_COMMANDS
    return list(DIAGNOSTIC_COMMANDS)


DEFAULTS: dict[str, list[str]] = {
    "fortiadc": [
        # ``diagnose hardware get sysinfo`` / ``deviceinfo`` bare answer
        # "Incorrect number of parameters" on 7.6.7 and 8.0.4: their leaves.
        "get system status",
        "get system performance",
        "diagnose hardware get sysinfo cpu",
        "diagnose hardware get sysinfo memory",
        "diagnose hardware get sysinfo df",
        "diagnose hardware get deviceinfo nic",
        "diagnose system df",
        "diagnose system memory",
        "diagnose system ps",
        "diagnose debug info",
    ],
    "fortigate": [
        "get system status",
        "get system performance status",
        "get hardware status",
        "get system ha status",
        "diagnose sys ha status",
        "diagnose hardware deviceinfo disk",
        "diagnose sys session stat",
        "diagnose debug crashlog read",
        "diagnose autoupdate versions",
        "get router info routing-table all",
    ],
    "fortianalyzer": [
        "get system status",
        "get system performance",
        "diagnose system route list",
        "diagnose system print loadavg",
        "diagnose system print partitions",
        "diagnose system ntp status",
        "diagnose fortilogd lograte",
        "diagnose debug sysinfo",
    ],
    "fortiauthenticator": [
        "get system status",
        "diagnose system ntp status",
        "diagnose netlink interface list",
        "diagnose netlink arp list",
        "diagnose debug info",
    ],
}


def default_battery(product: str) -> list[str]:
    if product == "fortiweb":
        return _fortiweb_default()
    return list(DEFAULTS.get(product, []))


def build_of(firmware: str | None) -> str:
    """``"FortiWeb-KVM 7.6.8,build1128(GA.M)"`` → ``"7.6.8"`` (one definition)."""
    from .firmware_versions import normalize
    return normalize(firmware or "")


# ── validation ──────────────────────────────────────────────────────────────
class BatteryError(ValueError):
    """A battery that may not be saved or run, naming the first bad line."""


def _ancestor_reason(command: str, nodes: dict[str, dict] | None) -> str | None:
    """The help text of the command or of any ancestor the catalog describes."""
    if not nodes:
        return None
    toks = command.split()
    if toks and toks[0] == "diag":
        toks[0] = "diagnose"
    for i in range(2, len(toks) + 1):
        n = nodes.get(" ".join(toks[:i]))
        if n is None:
            continue
        if n.get("blocked"):
            return n["blocked"]
        why = battery_reason(" ".join(toks[:i]), n.get("desc") or "")
        if why:
            return why
    return None


def command_reason(command: str, nodes: dict[str, dict] | None = None) -> str | None:
    """Why ``command`` may not be part of a battery, or None.

    The verb gate (get/show/diagnose only, no control characters, no
    chaining) is :func:`app.services.ssh_ops.assert_readonly`; on top of it
    the strict battery rule, and — when a catalog is known — the device's own
    description of the command and of every ancestor.
    """
    from .ssh_ops import assert_readonly, ReadOnlyViolation
    try:
        assert_readonly(command)
    except ReadOnlyViolation as e:
        return str(e)
    if "\n" in command.strip():
        return "one command per line"
    return battery_reason(command) or _ancestor_reason(command, nodes)


def clean_commands(lines, nodes: dict[str, dict] | None = None) -> list[str]:
    """Normalise + validate a battery. Raises :class:`BatteryError`.

    Whitespace is collapsed, blank lines and ``#`` comments dropped, duplicates
    removed (first wins, order kept).
    """
    out: list[str] = []
    seen: set[str] = set()
    for raw in lines or []:
        c = " ".join(str(raw or "").split())
        if not c or c.startswith("#"):
            continue
        why = command_reason(c, nodes)
        if why:
            raise BatteryError(f"{c!r}: {why}")
        if c.lower() not in seen:
            seen.add(c.lower())
            out.append(c)
    return out


# ── storage ─────────────────────────────────────────────────────────────────
def get_battery(adom_key: str) -> tuple[list[str], dict]:
    """``(commands, meta)``. ``meta``: ``{source: 'saved'|'default', updated_by,
    updated_at}``."""
    from ..models_diag import DiagBattery
    from ..extensions import db
    row = db.session.get(DiagBattery, adom_key)
    if row is None:
        return default_battery(adom_key), {"source": "default"}
    return row.commands, {"source": "saved", "updated_by": row.updated_by,
                          "updated_at": row.updated_at}


def save_battery(adom_key: str, commands: list[str], by: str) -> list[str]:
    """Validate against the union of this product's catalogs and store."""
    if adom_key not in PRODUCTS:
        raise BatteryError(f"no battery for ADOM {adom_key!r}")
    from ..models_diag import DiagBattery
    from ..extensions import db
    nodes = merged_nodes(adom_key)
    cmds = clean_commands(commands, nodes)
    if not cmds:
        raise BatteryError("a battery needs at least one command")
    row = db.session.get(DiagBattery, adom_key)
    if row is None:
        row = DiagBattery(adom_key=adom_key)
        db.session.add(row)
    row.commands = cmds
    row.updated_by = by
    db.session.commit()
    return cmds


def reset_battery(adom_key: str) -> None:
    from ..models_diag import DiagBattery
    from ..extensions import db
    row = db.session.get(DiagBattery, adom_key)
    if row is not None:
        db.session.delete(row)
        db.session.commit()


def catalogs(product: str) -> list:
    from ..models_diag import DiagCatalog
    rows = DiagCatalog.query.filter_by(product=product).all()

    def _key(r):
        try:
            return tuple(int(p) for p in r.build.split("."))
        except ValueError:
            return (0,)
    return sorted(rows, key=_key, reverse=True)


def catalog_for(product: str, build: str):
    from ..models_diag import DiagCatalog
    if not build:
        return None
    return DiagCatalog.query.filter_by(product=product, build=build).first()


def merged_nodes(product: str) -> dict[str, dict]:
    """Every node any build of ``product`` reported (newest build wins)."""
    out: dict[str, dict] = {}
    for cat in reversed(catalogs(product)):
        out.update(cat.node_map())
    return out


# ── run-time plan ───────────────────────────────────────────────────────────
def plan(product: str, firmware: str | None, commands: list[str]) -> list[dict]:
    """What to do with each command on one device.

    ``[{command, action: 'run'|'skip', state, detail}]`` — ``skip`` when the
    battery rule refuses it now, or when the catalog of the device's build
    says the build does not have it.
    """
    build = build_of(firmware)
    cat = catalog_for(product, build)
    nodes = cat.node_map() if cat else None
    out: list[dict] = []
    for c in commands:
        why = command_reason(c, nodes)
        if why:
            out.append({"command": c, "action": "skip", "state": "blocked",
                        "detail": why})
            continue
        if nodes is None:
            out.append({"command": c, "action": "run", "state": diag_tree.UNKNOWN,
                        "detail": (f"build {build} not discovered yet" if build
                                   else "firmware unknown")})
            continue
        state, detail = diag_tree.presence(c, nodes)
        if state == diag_tree.ABSENT:
            out.append({"command": c, "action": "skip", "state": state,
                        "detail": f"not present in {build}: {detail}"})
        else:
            out.append({"command": c, "action": "run", "state": state,
                        "detail": detail})
    return out


# ── discovery job ───────────────────────────────────────────────────────────
def _progress_path() -> Path:
    from .logcollect import _diag_dir
    return _diag_dir() / "_discovery.json"


def _write(obj) -> None:
    p = _progress_path()
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=1, default=str), encoding="utf-8")
    os.replace(tmp, p)


def discovery_status() -> dict | None:
    p = _progress_path()
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def snapshot(appliance) -> SimpleNamespace:
    """A DB-detached copy of what an SSH session needs (decrypted here, in
    the request context; the worker thread never touches the ORM)."""
    return SimpleNamespace(
        id=appliance.id, name=appliance.name, host=appliance.host,
        kind=appliance.kind or "fortiweb", firmware=appliance.firmware or "",
        username=appliance.ssh_login, ssh_login=appliance.ssh_login,
        password=appliance.ssh_secret, ssh_port=appliance.ssh_port or 22)


#: Parallel SSH sessions per discovery. Three keeps a FortiGate walk (thousands
#: of nodes) inside a quarter of an hour without crowding the admin session
#: limit of a small unit.
SESSIONS = 3
DEADLINE_S = 3600.0
BUDGET = 8000


#: A node that drops the session is asked again by TAB on a new session. A
#: FortiWeb 7.6.8 walk drops on every single-child node (dozens), so the limit
#: is generous; past it something else is wrong (session limit, the box going
#: away) and the shard stops.
MAX_RECONNECTS = 150


def _walk(snap, roots, budget, deadline_s, tick) -> diag_tree.Walker:
    from .ssh_ops import FortiWebReadonlySSH
    w = diag_tree.Walker(None, budget=budget, deadline_s=deadline_s,
                         on_progress=tick)
    todo = list(roots)
    w.dropped: list[str] = []
    while True:
        with FortiWebReadonlySSH(snap, snap.password, timeout=20) as ssh:
            w.session = ssh
            w.walk(todo)
        if not w.lost_at:
            break
        w.dropped.append(w.lost_at)
        w.lost_at = ""
        if not w.pending or w.truncated or len(w.dropped) > MAX_RECONNECTS:
            if w.pending and not w.truncated:
                w.truncated = (f"the session failed {len(w.dropped)} "
                               f"times; walk stopped")
            break
        todo = w.pending
    return w


def _run_discovery(app, snap, by: str, sessions: int) -> None:
    state = discovery_status() or {}
    started = time.monotonic()
    lock = threading.Lock()
    counter = {"n": 0, "path": ""}

    def tick(_n, path):
        with lock:
            counter["n"] += 1
            counter["path"] = path
            if counter["n"] % 10 == 0:
                state.update(probed=counter["n"], current=path)
                _write(state)

    try:
        first = _walk(snap, [(diag_tree.ROOT, "")], 1, DEADLINE_S, tick)
        nodes = dict(first.nodes)
        roots = [(n.path, n.desc) for n in first.nodes.values()
                 if n.path != diag_tree.ROOT and not n.blocked]
        # Each top-level branch already exists as a node; the workers re-probe
        # it (cheap) and everything below.
        shards = [roots[i::max(1, sessions)] for i in range(max(1, sessions))]
        shards = [s for s in shards if s]
        truncated = []
        per = max(200, BUDGET // max(1, len(shards)))
        remaining = max(60.0, DEADLINE_S - (time.monotonic() - started))
        with ThreadPoolExecutor(max_workers=len(shards) or 1) as pool:
            futs = [pool.submit(_walk, snap, s, per, remaining, tick) for s in shards]
            for f in futs:
                w = f.result()
                nodes.update(w.nodes)
                if w.truncated:
                    truncated.append(w.truncated)
        out = sorted((n.as_dict() for n in nodes.values()), key=lambda d: d["path"])
        with app.app_context():
            from ..models_diag import DiagCatalog
            from ..extensions import db
            build = build_of(snap.firmware)
            row = catalog_for(snap.kind, build)
            if row is None:
                row = DiagCatalog(product=snap.kind, build=build)
                db.session.add(row)
            row.firmware = snap.firmware
            row.appliance_name = snap.name
            row.discovered_by = by
            row.discovered_at = datetime.utcnow()
            row.duration_s = int(time.monotonic() - started)
            row.probed = counter["n"]
            row.truncated = "; ".join(sorted(set(truncated))) or None
            row.nodes = out
            db.session.commit()
            counts = row.counts()
            cat_id = row.id
            try:
                from .audit import log_action
                log_action("diag_battery.discover", target=snap.name,
                           extra={"product": snap.kind, "build": build,
                                  "probed": counter["n"], **counts})
            except Exception:  # noqa: BLE001 — the audit row must not lose the catalog
                pass
        state.update(state="done", probed=counter["n"], current="",
                     finished=datetime.utcnow().isoformat(), catalog_id=cat_id,
                     counts=counts,
                     truncated="; ".join(sorted(set(truncated))) or None)
        _write(state)
    except Exception as e:  # noqa: BLE001 — the page must show why it stopped
        state.update(state="error", error=str(e)[:300], current="",
                     finished=datetime.utcnow().isoformat())
        _write(state)


def start_discovery(appliance, by: str, *, sessions: int = SESSIONS) -> dict:
    """Start a discovery walk of ``appliance`` in the background.

    One walk at a time, fleet-wide: a second request while one looks live
    (<70 min) is refused with the running state.
    """
    from flask import current_app
    cur = discovery_status()
    if cur and cur.get("state") == "running":
        try:
            # ``started`` is a naive UTC stamp (utcnow): compare it with
            # utcnow. ``.timestamp()`` would read it as LOCAL time, so on a
            # UTC+2 host every run looked two hours old and the guard never
            # refused.
            age = (datetime.utcnow()
                   - datetime.fromisoformat(cur["started"])).total_seconds()
        except Exception:  # noqa: BLE001
            age = 0
        if age < DEADLINE_S + 600:
            return {"started": False, "reason": "a discovery is already running",
                    "progress": cur}
    kind = appliance.kind or "fortiweb"
    if kind not in PRODUCTS:
        return {"started": False, "reason": f"no discovery for {kind!r}"}
    if not build_of(appliance.firmware):
        return {"started": False,
                "reason": "the firmware of this device is unknown; refresh it "
                          "(Appliances) before discovering its commands"}
    snap = snapshot(appliance)
    init = {"state": "running", "appliance": snap.name, "product": kind,
            "build": build_of(snap.firmware), "by": by, "probed": 0,
            "current": "", "started": datetime.utcnow().isoformat(),
            "finished": None}
    _write(init)
    app = current_app._get_current_object()
    threading.Thread(target=_run_discovery, args=(app, snap, by, sessions),
                     daemon=True).start()
    return {"started": True, "progress": init}


__all__ = [
    "PRODUCTS", "DEFAULTS", "default_battery", "build_of", "BatteryError",
    "command_reason", "clean_commands", "get_battery", "save_battery",
    "reset_battery", "catalogs", "catalog_for", "merged_nodes", "plan",
    "discovery_status", "start_discovery", "snapshot",
]
