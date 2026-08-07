"""Self-update service — update the manager's OWN code + Python deps.

The web process runs UNPRIVILEGED (user ``fortinet``, ``NoNewPrivileges`` +
``ProtectSystem=strict``) so it can neither restart itself nor install files.
The real update therefore runs in a SEPARATE privileged oneshot service
(``satom-updater.service``) triggered by a systemd ``.path`` unit
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
import re
import socket
import subprocess
import uuid
from datetime import datetime
from pathlib import Path

APP_DIR = Path(os.environ.get("FM_APP_DIR", "/opt/satom"))
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
    # Deriving the mode is only sound when the registry can actually be READ.
    # ``_nodes_raw()`` answers [] both for "no peers" and for "this file is
    # garbage", and deriving 'standalone' from the second disarms the
    # staged-rollout interlock in can_apply_to_primary() — the PRIMARY would
    # then take a revision no STANDBY ever validated. An unreadable registry is
    # not evidence of a single-node deployment; keep the interlock ARMED and
    # let the admin either fix the file or set the mode explicitly.
    if nodes_registry_state() == "unreadable":
        return "ha"
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


def nodes_registry_state() -> str:
    """``absent`` | ``ok`` | ``unreadable`` for ``data/ha_nodes.json``.

    ``_nodes_raw()`` and ``load_nodes()`` both answer a missing file and a
    corrupt one identically, which is fine for listing peers and fatal for
    deriving HA mode from the result. This is the fact those two throw away:
    absent is a legitimate single-node deployment, unreadable is a broken
    registry and must not be mistaken for one.
    """
    try:
        if not NODES_FILE.exists():
            return "absent"
        data = json.loads(NODES_FILE.read_text())
    except Exception:  # noqa: BLE001 — unreadable file, bad JSON, bad perms
        return "unreadable"
    return "ok" if isinstance(data, list) else "unreadable"


def _nodes_raw() -> list[dict]:
    """The literal ha_nodes.json list (empty if absent) — unlike load_nodes(),
    it does NOT substitute a synthetic self entry, so writers don't persist it.

    Callers that make a SAFETY decision from the emptiness of this list must
    consult :func:`nodes_registry_state` first: [] here means "no peers" and
    "the file is garbage" alike."""
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


# Shape guards for what may reach a pip command line. Mirrors the privileged
# runner's own pair (deploy/self_update_runner.py) on purpose: the runner is the
# last line, this is the first, and BOTH sides re-check because a request can
# now arrive from the peer node instead of from this node's own button.
_PKG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_VER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")


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
                       bump_requirements: bool = True,
                       origin: str = "libraries-card") -> str:
    """Enqueue a curated-only per-package pip change for the privileged runner.

    Validates against THIS node's curated allowlist and THIS node's regexes
    (the runner re-validates again as defense in depth) so a request for an
    arbitrary package or a version carrying pip flags / shell metacharacters
    never reaches the queue. Node-local: the runner on THIS node installs into
    THIS node's venv — which is exactly why a peer that wants the same change
    calls this same function on ITSELF instead of being handed a package.
    """
    package = (package or "").strip()
    version = (version or "").strip()
    if not _PKG_RE.match(package) or package not in _pip_allowlist():
        raise ValueError("package %r is not in the curated allowlist" % package)
    if action not in ("upgrade", "rollback"):
        raise ValueError("action must be 'upgrade' or 'rollback'")
    if not version:
        raise ValueError("a target version is required")
    if not _VER_RE.match(version):
        raise ValueError("version %r is not a valid version string" % version)

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
        "origin": origin,
    }
    (STATUS_DIR / (uid + ".json")).write_text(json.dumps({
        "id": uid, "state": "queued", "steps": [], "kind": "pip",
        "package": package, "action": action, "target": version,
        "requested_by": by, "node": req["node"], "role": req["role"],
        "origin": origin,
        "updated_at": datetime.utcnow().isoformat() + "Z"}))
    tmp = REQ_DIR / ("." + uid + ".tmp")
    tmp.write_text(json.dumps(req))
    tmp.rename(REQ_DIR / (uid + ".json"))
    return uid


# ---------------------------------------------------------------------------
# HA fan-out: the SAME pip change on the peer node(s)
# ---------------------------------------------------------------------------
# The venv is NODE-LOCAL — not in git, not in the data rsync — so a library
# change applied here leaves the other node behind and the pair drifts silently.
# The fan-out reuses the two things that already exist instead of inventing a
# third: the authenticated node-to-node channel (node_security, X-FM-Node-Key
# over :8443) and the per-node privileged updater. We ask the peer to ENQUEUE
# the same request on ITSELF. We never ship a package, never run pip from the
# web worker, and never write into the peer's data/update-requests/ — that
# directory stays out of the rsync on purpose (syncing it would spuriously fire
# the standby's updater).
PEER_PIP_PATH = "/settings/peer/library-pip"
PEER_LIB_PATH = "/settings/peer/libraries"
_PEER_TIMEOUT = 6.0


def peer_nodes() -> list[dict]:
    """Registered nodes other than this one. Uses ``_nodes_raw()`` so a missing
    registry yields no peers instead of a synthetic self entry."""
    this = this_node_name()
    return [n for n in _nodes_raw()
            if n.get("name") != this and (n.get("host") or "").strip()]


def _peer_answer(raw: bytes) -> dict | None:
    """A peer's JSON object, or None when the body is not one (an nginx error
    page, a truncated read, a proxy interstitial — all of which must NOT be
    mistaken for a successful enqueue)."""
    try:
        d = json.loads((raw or b"").decode("utf-8", "replace") or "{}")
    except Exception:
        return None
    return d if isinstance(d, dict) else None


def request_pip_change_on_peers(package: str, version: str, by: str, *,
                                action: str = "upgrade") -> list[dict]:
    """Ask every registered PEER to enqueue the same pip change on itself.

    One row per peer, with an explicit ``state``:

    * ``queued``      — the peer accepted it; its own privileged runner applies it
    * ``rejected``    — the peer answered and refused (its own allowlist/regex)
    * ``unreachable`` — no answer on :8443 or :8000, or an answer we cannot read

    ``unreachable`` is never collapsed into success and never into "already up
    to date": not knowing is its own state, and the operator has to see it or
    the pair drifts while the UI says everything is fine.
    """
    from . import node_security as nsec
    body = json.dumps({"package": package, "version": version,
                       "action": action, "requested_by": by,
                       "origin_node": this_node_name()}).encode()
    out: list[dict] = []
    for n in peer_nodes():
        row = {"node": n.get("name"), "host": n.get("host"), "uid": None,
               "error": None, "secure": None}
        try:
            st, raw, secure = nsec.peer_post(n["host"], PEER_PIP_PATH, body,
                                             timeout=_PEER_TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — any transport fault at all
            out.append({**row, "state": "unreachable", "error": str(exc)})
            continue
        row["secure"] = bool(secure)
        if st is None:
            out.append({**row, "state": "unreachable",
                        "error": "no answer on :%d or :%d" % (nsec.HTTPS_PORT,
                                                              nsec.HTTP_PORT)})
            continue
        ans = _peer_answer(raw)
        if ans is None:
            out.append({**row, "state": "unreachable",
                        "error": "HTTP %s with an unreadable body" % st})
            continue
        if 200 <= int(st) < 300 and ans.get("uid"):
            out.append({**row, "state": "queued", "uid": ans.get("uid")})
            continue
        out.append({**row, "state": "rejected",
                    "error": ans.get("error") or ("HTTP %s" % st)})
    return out


# ---------------------------------------------------------------------------
# per-node version drift (the card has to SHOW whether the pair is level)
# ---------------------------------------------------------------------------
def local_lib_versions() -> dict:
    """THIS node's installed versions for the curated set (name -> version)."""
    try:
        from .system_info import _libraries
        return {d["name"]: d["version"] for d in _libraries()}
    except Exception:
        return {}


def peer_lib_report(host: str, timeout: float = _PEER_TIMEOUT) -> dict:
    """A peer's installed curated versions over the same authenticated channel.
    Anything short of a readable 2xx JSON map is ``reachable: False`` — an
    unknown peer must never be rendered as an agreeing one."""
    from . import node_security as nsec
    try:
        st, raw, secure = nsec.peer_get(host, PEER_LIB_PATH, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "error": str(exc), "libraries": {}}
    if st is None:
        return {"reachable": False, "libraries": {},
                "error": "no answer on :%d or :%d" % (nsec.HTTPS_PORT,
                                                      nsec.HTTP_PORT)}
    ans = _peer_answer(raw)
    if not (200 <= int(st) < 300) or ans is None:
        return {"reachable": False, "libraries": {}, "error": "HTTP %s" % st}
    libs = ans.get("libraries")
    if not isinstance(libs, dict):
        return {"reachable": False, "libraries": {},
                "error": "peer answered without a library map"}
    return {"reachable": True, "secure": bool(secure), "libraries": libs,
            "role": ans.get("role"), "error": None}


def lib_version_drift() -> dict:
    """Per-node installed versions of the curated libraries + a level verdict.

    A node we could not reach contributes NO versions and forces ``level``
    False for every package and for the pair: "I don't know" must never render
    as "in sync" — that is precisely the silent drift this card exists to
    expose.
    """
    nodes = [{"name": this_node_name(), "host": "127.0.0.1", "self": True,
              "role": node_role(), "reachable": True, "secure": None,
              "error": None, "libraries": local_lib_versions()}]
    for n in peer_nodes():
        rep = peer_lib_report(n["host"])
        nodes.append({"name": n.get("name"), "host": n.get("host"), "self": False,
                      "role": rep.get("role"), "reachable": bool(rep.get("reachable")),
                      "secure": rep.get("secure"), "error": rep.get("error"),
                      "libraries": rep.get("libraries") or {}})
    all_reachable = all(bool(nd["reachable"]) for nd in nodes)
    names = sorted({p for nd in nodes for p in nd["libraries"]})
    packages = []
    for p in names:
        versions = {nd["name"]: nd["libraries"].get(p) for nd in nodes}
        seen = [v for v in versions.values() if v]
        level = bool(all_reachable and len(seen) == len(nodes)
                     and len(set(seen)) == 1)
        packages.append({"package": p, "versions": versions, "level": level})
    return {"nodes": nodes, "packages": packages, "peers": len(nodes) - 1,
            "all_reachable": all_reachable,
            "level": bool(all_reachable and all(x["level"] for x in packages))}


#: Request ids are minted here and nowhere else, always as
#: ``%Y%m%d-%H%M%S-<6 hex>`` -- digits, dashes and hex. Anything outside that
#: class is not an id we ever wrote.  [SATOM-UID-SAFE]
UID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def update_status(uid: str) -> dict | None:
    # The id reaches here from a URL segment, so it is untrusted input used to
    # build a filesystem path. Validating in each caller would leave the next
    # caller to remember; the check belongs where the path is assembled. A
    # traversing id turned this reader into "read any .json this account can
    # read" -- narrow by construction is cheaper than narrow by discipline.
    if not uid or not UID_RE.match(uid):
        return None
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
