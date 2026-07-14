"""Self-update service — update the manager's OWN code + Python deps.

The web process runs UNPRIVILEGED (user ``fortinet``, ``NoNewPrivileges`` +
``ProtectSystem=strict``) so it can neither restart itself nor install files.
The real update therefore runs in a SEPARATE privileged oneshot service
(``ofortmaut-updater.service``) triggered by a systemd ``.path`` unit
that watches ``data/update-requests/``. This module is the app-side half: it
inspects the current git revision, checks the remote for a newer one, and
ENQUEUES an update request (a JSON file the root runner picks up). It never
runs a privileged command itself.

Scope ("solo la paqueteria que usa"): git app code + pip requirements +
``flask db upgrade``. NEVER OS packages.

Staged rollout ("un equipo primero, luego el otro"): the interlock lives in
``AppSetting`` (Postgres → replicated to both HA nodes). A target revision must
be validated on the STANDBY (updated + health-checked) before the PRIMARY
button unlocks.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import uuid
from datetime import datetime
from pathlib import Path

APP_DIR = Path(os.environ.get("FM_APP_DIR", "/opt/ofortmaut"))
REQ_DIR = APP_DIR / "data" / "update-requests"
STATUS_DIR = APP_DIR / "data" / "update-status"
NODES_FILE = APP_DIR / "data" / "ha_nodes.json"
BRANCH = os.environ.get("FM_UPDATE_BRANCH", "main")

# AppSetting keys — Postgres-backed, so they replicate across the HA pair.
_K_NODE_REPORT = "ha.node.%s"          # per-node last self-report (version/role/health)
_K_VALIDATED = "ha.update.validated"   # {"target": sha, "node": name, "at": iso}
_K_MODE = "ha.mode"                    # "ha" | "standalone" (admin-set, replicated)


# ---------------------------------------------------------------------------
# git helpers (read-only from the app side; the privileged writes are the runner)
# ---------------------------------------------------------------------------
def _git(*args, timeout: int = 120) -> subprocess.CompletedProcess:
    """Run a git command in the app repo as the current user."""
    return subprocess.run(
        ["git", "-C", str(APP_DIR), "-c", "safe.directory=%s" % APP_DIR, *args],
        capture_output=True, text=True, timeout=timeout,
    )


def current_revision() -> dict:
    r = _git("log", "-1", "--pretty=%H%x1f%h%x1f%s%x1f%cI")
    branch = _git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    if r.returncode != 0 or not r.stdout.strip():
        return {"sha": "", "short": "unknown", "subject": "", "date": "", "branch": branch}
    parts = (r.stdout.strip().split("\x1f") + ["", "", "", ""])[:4]
    sha, short, subject, date = parts
    return {"sha": sha, "short": short, "subject": subject, "date": date, "branch": branch}


def check_remote(fetch: bool = True) -> dict:
    """``git fetch`` + compare local HEAD vs ``origin/BRANCH``."""
    err = ""
    if fetch:
        f = _git("fetch", "origin", BRANCH, timeout=120)
        if f.returncode != 0:
            err = (f.stderr or "git fetch failed").strip()
    cur = current_revision()
    tgt = _git("rev-parse", "origin/%s" % BRANCH).stdout.strip()
    behind_raw = _git("rev-list", "--count", "HEAD..origin/%s" % BRANCH).stdout.strip()
    log = _git("log", "--pretty=%h %s (%cr)", "HEAD..origin/%s" % BRANCH).stdout.strip()
    commits = [ln for ln in log.splitlines() if ln.strip()]
    return {
        "current": cur,
        "target_sha": tgt,
        "behind": int(behind_raw) if behind_raw.isdigit() else 0,
        "commits": commits,
        "error": err,
        "checked_at": datetime.utcnow().isoformat() + "Z",
    }


# ---------------------------------------------------------------------------
# node identity / role (role is LIVE from Postgres, not stored)
# ---------------------------------------------------------------------------
def this_node_name() -> str:
    return os.environ.get("FM_NODE_NAME") or socket.gethostname()


def node_role() -> str:
    """``primary`` | ``standby`` | ``unknown`` from ``pg_is_in_recovery()``."""
    try:
        from ..models import db
        from sqlalchemy import text
        val = db.session.execute(text("SELECT pg_is_in_recovery()")).scalar()
        return "standby" if val else "primary"
    except Exception:
        return "unknown"


def ha_mode() -> str:
    """Admin-set deployment mode: 'ha' (staged-update interlock, peer probes,
    failover promote, data-sync) or 'standalone' (all HA behavior off).
    Stored in AppSetting so it replicates to the standby — ONE source of
    truth, set from the PRIMARY. Unset -> derived: 'ha' when a peer is
    registered, else 'standalone' (backward compatible)."""
    try:
        from ..models import AppSetting
        v = (AppSetting.get(_K_MODE) or "").strip().lower()
        if v in ("ha", "standalone"):
            return v
    except Exception:
        pass
    others = [n for n in _nodes_raw() if n.get("name") != this_node_name()]
    return "ha" if others else "standalone"


def set_ha_mode(mode: str) -> None:
    """Persist the deployment mode (replicated AppSetting). Writable only
    where Postgres is read-write, i.e. on the primary."""
    if mode not in ("ha", "standalone"):
        raise ValueError("mode must be 'ha' or 'standalone'")
    from ..models import AppSetting
    AppSetting.set(_K_MODE, mode)


def load_nodes() -> list[dict]:
    """The HA node registry (``data/ha_nodes.json``). Absent → this node only."""
    try:
        data = json.loads(NODES_FILE.read_text())
        if isinstance(data, list) and data:
            return data
    except Exception:
        pass
    return [{"name": this_node_name(), "host": "127.0.0.1", "self": True}]


def _nodes_raw() -> list[dict]:
    """The literal ha_nodes.json list (empty if absent) — unlike load_nodes(),
    it does NOT substitute a synthetic self entry, so writers don't persist it."""
    try:
        data = json.loads(NODES_FILE.read_text())
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def save_nodes(nodes: list[dict]) -> None:
    """Persist the HA node registry (data/ha_nodes.json). Rsync propagates it to
    the peer; git never tracks it (per-deployment infra, not code)."""
    NODES_FILE.parent.mkdir(parents=True, exist_ok=True)
    clean = []
    for n in nodes:
        name = (n.get("name") or "").strip()
        host = (n.get("host") or "").strip()
        if not name or not host:
            continue
        row = {"name": name, "host": host}
        if n.get("desc"):
            row["desc"] = str(n["desc"]).strip()
        clean.append(row)
    tmp = NODES_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(clean, indent=2))
    os.replace(tmp, NODES_FILE)


def upsert_node(name: str, host: str, desc: str = "") -> None:
    """Add or update one node in the registry, keeping every other entry and
    guaranteeing THIS node stays registered (so the panel always shows both)."""
    name = (name or "").strip()
    host = (host or "").strip()
    nodes = _nodes_raw()
    found = False
    for n in nodes:
        if n.get("name") == name:
            n["host"] = host
            if desc:
                n["desc"] = desc
            found = True
    if not found:
        row = {"name": name, "host": host}
        if desc:
            row["desc"] = desc
        nodes.append(row)
    this = this_node_name()
    if not any(n.get("name") == this for n in nodes):
        nodes.insert(0, {"name": this, "host": "127.0.0.1"})
    save_nodes(nodes)


def remove_node(name: str) -> None:
    """Remove a node from the registry. Never removes THIS node (self)."""
    if (name or "").strip() == this_node_name():
        return
    save_nodes([n for n in _nodes_raw() if n.get("name") != name])


def self_report() -> dict:
    """Write THIS node's (role, revision, health) into the shared (replicated)
    settings so the UI on either node sees every node's state."""
    rep = {
        "name": this_node_name(),
        "role": node_role(),
        "revision": current_revision(),
        "healthy": True,
        "reported_at": datetime.utcnow().isoformat() + "Z",
    }
    try:
        from ..models import AppSetting
        # A standby's Postgres is read-only (the shared settings live on the
        # primary and replicate one-way), so don't attempt the write there — it
        # would poison this request's DB session. The primary publishes for all;
        # a standby's role/health is derived from replication (cluster.full_state).
        if (rep.get("role") or node_role()) != "standby":
            AppSetting.set(_K_NODE_REPORT % this_node_name(), json.dumps(rep))
    except Exception:
        try:
            from ..models import db
            db.session.rollback()
        except Exception:
            pass
    return rep


def node_reports() -> list[dict]:
    out = []
    try:
        from ..models import AppSetting
    except Exception:
        AppSetting = None
    for n in load_nodes():
        rep = None
        if AppSetting is not None:
            raw = AppSetting.get(_K_NODE_REPORT % n.get("name", ""))
            if raw:
                try:
                    rep = json.loads(raw)
                except Exception:
                    rep = None
        out.append({**n, "report": rep})
    return out


# ---------------------------------------------------------------------------
# the staged-rollout interlock (the "seguro")
# ---------------------------------------------------------------------------
def validated_state() -> dict:
    try:
        from ..models import AppSetting
        raw = AppSetting.get(_K_VALIDATED)
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


def mark_validated(target_sha: str, node: str) -> None:
    try:
        from ..models import AppSetting
        AppSetting.set(_K_VALIDATED, json.dumps({
            "target": target_sha, "node": node,
            "at": datetime.utcnow().isoformat() + "Z"}))
    except Exception:
        pass


def can_apply_to_primary(target_sha: str) -> bool:
    """The PRIMARY may update to ``target_sha`` only once the STANDBY has
    validated that EXACT revision (updated + passed health checks).
    In STANDALONE mode the staged-rollout interlock is off by admin choice
    — updates apply directly."""
    if ha_mode() == "standalone":
        return True
    st = validated_state()
    return bool(target_sha) and st.get("target") == target_sha


def reconcile_interlock(status: dict | None) -> None:
    """Called by the status poll (which has a DB session): when a STANDBY
    finishes a target successfully, record it as validated so the PRIMARY
    button unlocks."""
    if not status:
        return
    if status.get("state") == "success" and status.get("role") == "standby":
        tgt = status.get("result_sha") or status.get("target")
        if tgt:
            mark_validated(tgt, status.get("node", "standby"))


# ---------------------------------------------------------------------------
# enqueue + status (the privileged runner does the actual work)
# ---------------------------------------------------------------------------
def request_update(target: str, by: str, *, do_pip: bool = True,
                   do_migrate: bool = True, role: str | None = None,
                   origin: str = "manual") -> str:
    REQ_DIR.mkdir(parents=True, exist_ok=True)
    STATUS_DIR.mkdir(parents=True, exist_ok=True)
    uid = datetime.utcnow().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    req = {
        "id": uid,
        "target": target or ("origin/%s" % BRANCH),
        "branch": BRANCH,
        "do_pip": bool(do_pip),
        "do_migrate": bool(do_migrate),
        "requested_by": by,
        "requested_at": datetime.utcnow().isoformat() + "Z",
        "node": this_node_name(),
        "role": role or node_role(),
        "origin": origin,
    }
    # A "queued" status up front so the UI has something to poll immediately.
    (STATUS_DIR / (uid + ".json")).write_text(json.dumps({
        "id": uid, "state": "queued", "steps": [],
        "requested_by": by, "target": req["target"],
        "node": req["node"], "role": req["role"],
        "origin": req.get("origin", "manual"),
        "updated_at": datetime.utcnow().isoformat() + "Z"}))
    # Write to a hidden temp then rename INTO the watched dir → atomic trigger.
    tmp = REQ_DIR / ("." + uid + ".tmp")
    tmp.write_text(json.dumps(req))
    tmp.rename(REQ_DIR / (uid + ".json"))
    return uid


LIB_VERSIONS_DIR = APP_DIR / "data" / "lib-versions"


def _pip_allowlist() -> set[str]:
    """Curated libraries the GUI may pip-change — single source of truth is
    system_info._LIBRARIES (the same set the card renders)."""
    try:
        from .system_info import _LIBRARIES
        return {n for n in _LIBRARIES}
    except Exception:
        return set()


def lib_versions() -> dict:
    """Per-package rollback points written by the privileged runner
    (``data/lib-versions/<pkg>.json``). Feeds the card's 'Rollback to X' button.
    Per-node, because each node has its own venv."""
    out: dict = {}
    if not LIB_VERSIONS_DIR.exists():
        return out
    for p in LIB_VERSIONS_DIR.glob("*.json"):
        try:
            d = json.loads(p.read_text())
            if d.get("package"):
                out[d["package"]] = d
        except Exception:
            pass
    return out


def request_pip_change(package: str, version: str, by: str, *,
                       action: str = "upgrade",
                       bump_requirements: bool = True) -> str:
    """Enqueue a curated-only per-package pip change for the privileged runner.

    Validates against the curated allowlist HERE (the runner re-validates as
    defense in depth) so a request for an arbitrary package never reaches the
    queue. Node-local: the runner on THIS node installs into THIS node's venv.
    """
    package = (package or "").strip()
    version = (version or "").strip()
    if package not in _pip_allowlist():
        raise ValueError("package %r is not in the curated allowlist" % package)
    if action not in ("upgrade", "rollback"):
        raise ValueError("action must be 'upgrade' or 'rollback'")
    if not version:
        raise ValueError("a target version is required")

    REQ_DIR.mkdir(parents=True, exist_ok=True)
    STATUS_DIR.mkdir(parents=True, exist_ok=True)
    uid = datetime.utcnow().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    req = {
        "id": uid,
        "kind": "pip",
        "package": package,
        "version": version,
        "action": action,
        "bump_requirements": bool(bump_requirements),
        "requested_by": by,
        "requested_at": datetime.utcnow().isoformat() + "Z",
        "node": this_node_name(),
        "role": node_role(),
        "origin": "libraries-card",
    }
    (STATUS_DIR / (uid + ".json")).write_text(json.dumps({
        "id": uid, "state": "queued", "steps": [], "kind": "pip",
        "package": package, "action": action, "target": version,
        "requested_by": by, "node": req["node"], "role": req["role"],
        "origin": "libraries-card",
        "updated_at": datetime.utcnow().isoformat() + "Z"}))
    tmp = REQ_DIR / ("." + uid + ".tmp")
    tmp.write_text(json.dumps(req))
    tmp.rename(REQ_DIR / (uid + ".json"))
    return uid


def update_status(uid: str) -> dict | None:
    p = STATUS_DIR / (uid + ".json")
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def recent_updates(limit: int = 15) -> list[dict]:
    if not STATUS_DIR.exists():
        return []
    files = sorted(STATUS_DIR.glob("*.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    out = []
    for p in files[:limit]:
        try:
            out.append(json.loads(p.read_text()))
        except Exception:
            pass
    return out
