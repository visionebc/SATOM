"""Auto-reconciler for the manager's OWN code across the HA pair.

Runs on BOTH nodes as a periodic tick (``satom-reconciler.service``),
DB-FREE by design: the standby cannot boot the Flask app (create_all writes to
its read-only replica), so this module never calls ``create_app()``. It reads
the two replicated settings it needs via raw ``psql`` (reads work on a hot
standby) and does everything else with git + the filesystem queue that
``self_update`` already defines.

Deploy modes ("both of them" -- both coexist; the operator toggles between them):

  * MANUAL  -- observe only. Records the drift and what it *would* do, logs it,
               but NEVER enqueues. The operator's Self-Update buttons stay the
               only writer. (default -- safe to ship)
  * AUTO    -- drive the SAME staged rollout the operator drives by hand:
               the STANDBY self-updates to origin first (code-only + import
               smoke, which writes the "validated" marker onto the primary);
               only THEN the PRIMARY self-updates (health-gated, auto-rollback).
               Standby-first + health-gate is what makes "auto to both" safe.

Every tick is logged (journald, via the service) and mirrored into a small
status record the Self-Update page renders, so the admin always sees the state
the reconciler is in and what it is doing -- and whether the last change came
from the operator (manual) or the reconciler (auto).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path

from . import self_update as su

log = logging.getLogger("fm.reconciler")

APP_DIR = Path(os.environ.get("FM_APP_DIR", "/opt/satom"))

# THIS node's last tick. Node-local on purpose, and therefore NOT under data/:
# satom-ha-datasync rsyncs the primary's data/ onto the standby with --delete
# every five minutes, so a status file there was the PRIMARY's copy on the
# standby ("node": "satom-node-1" on a2). On 2026-10-11 the standby's fetches
# timed out for hours while every file a human could read said up-to-date; its
# real state existed only in its own journal. state/ is the node-local home the
# certificate journal and the metrics peer state already use (gitignored,
# outside every replication path), and each node publishes its own copy over
# /healthz/reconciler so the primary can render the standby's real state.
STATE_DIR = Path(os.environ.get("SATOM_STATE_DIR") or (APP_DIR / "state"))
STATUS_FILE = STATE_DIR / "reconciler-status.json"
# Where it used to live. Removed on every tick: left in place on the primary,
# the datasync would keep planting it on the standby as if it were the
# standby's own, which is the exact lie this move exists to end.
LEGACY_STATUS_FILE = APP_DIR / "data" / "reconciler-status.json"

# The peer probe publishes the error text, unauthenticated. Two things in a git
# error must never leave the node: credentials in an http(s) remote URL (the
# primary's origin carries a token in its userinfo) and anything long enough to
# be a dump. Short, single-line, redacted -- the same budget /healthz/backups
# spends on bundle names.
_URL_USERINFO = re.compile(r"(?i)\b(https?://)[^/@\s]+@")
PUBLIC_ERROR_MAX = 200

_K_DEPLOY_MODE = "ha.deploy.mode"        # "auto" | "manual" (replicated AppSetting)
_K_RECON_STATUS = "ha.reconcile.status"  # last tick, primary-published (replicated)

# Do not re-enqueue after a FAILED attempt within this window (avoid a tight
# auto-retry loop against a genuinely broken revision).
FAIL_COOLDOWN = timedelta(minutes=15)

# --- dependency convergence -------------------------------------------------
# The reconciler converges CODE (it enqueues the runner's staged update). A
# commit that adds a pin to requirements.txt must also converge the PACKAGES,
# or a failover lands on a node whose code imports what its venv lacks. The
# runner's `pip install -r` covers updates it ran; this is the structural
# net: the sha256 of the requirements.txt last installed successfully lives in
# state/ (node-local), and any difference (or no record) triggers an install.
REQ_STATE_FILE = STATE_DIR / "reconciler-requirements.json"
PIP_TIMEOUT = 900                        # same budget as self_update_runner
DEPS_FAIL_BACKOFF = 15 * 60              # seconds between attempts after a failure
DEPS_TAIL_MAX = 400
DEPS_FAILED = "deps-install-failed"


def _read_requirements_bytes() -> bytes:
    """requirements.txt bytes, read without following a planted link.

    Mirrors ``self_update_runner._read_requirements``: O_NOFOLLOW + regular
    file check, so a requirements.txt -> /etc/shadow link is refused."""
    fd = os.open(str(APP_DIR / "requirements.txt"),
                 os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise ValueError("not a regular file")
        return fh.read()


def _app_user() -> str | None:
    """Service account to run pip as, or None to run as the current user.

    Owner of the app tree (same rule as self_update_runner). Only relevant when
    we are root: pip as root into a satom-owned venv would leave root-owned
    files behind."""
    if os.geteuid() != 0:
        return None
    try:
        import pwd
        name = os.environ.get("FM_APP_USER") or pwd.getpwuid(APP_DIR.stat().st_uid).pw_name
    except Exception:  # noqa: BLE001
        return None
    return None if name == "root" else name


def _pip_argv() -> list[str]:
    argv = [str(APP_DIR / "venv" / "bin" / "pip"), "install",
            "--disable-pip-version-check", "--no-input",
            "-r", str(APP_DIR / "requirements.txt")]
    user = _app_user()
    return ["runuser", "-u", user, "--"] + argv if user else argv


def _default_runner(argv, timeout):
    # Environment is inherited on purpose: PIP_* from the unit's EnvironmentFile
    # and pip.conf (--find-links / index of an offline install) apply exactly as
    # they do for the runner's own pip call.
    return subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout, cwd=str(APP_DIR))


def _load_req_state() -> dict:
    try:
        d = json.loads(REQ_STATE_FILE.read_text())
        return d if isinstance(d, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _save_req_state(d: dict) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATE_DIR / (".%s.tmp" % REQ_STATE_FILE.name)
        tmp.write_text(json.dumps(d, indent=2))
        if os.geteuid() == 0:
            try:
                st = APP_DIR.stat()
                os.chown(tmp, st.st_uid, st.st_gid)
            except OSError:
                pass
        os.replace(tmp, REQ_STATE_FILE)
    except Exception:  # noqa: BLE001 -- never kills a tick
        pass


def ensure_requirements(runner=None, clock=time.time) -> dict | None:
    """Install requirements.txt when it differs from the last good install.

    Returns None when nothing was needed or the attempt is backing off, else
    ``{"ok": bool, "detail": str}``. Never raises, never touches the DB."""
    try:
        digest = hashlib.sha256(_read_requirements_bytes()).hexdigest()
    except Exception as exc:  # noqa: BLE001 -- missing / symlink / not a file
        return {"ok": False, "detail": "requirements.txt unreadable: %s: %s"
                % (type(exc).__name__, exc)}
    state = _load_req_state()
    if state.get("sha256") == digest:
        return None
    now_ts = clock()
    last_fail = state.get("failed_at")
    if (state.get("failed_sha256") == digest and isinstance(last_fail, (int, float))
            and now_ts - last_fail < DEPS_FAIL_BACKOFF):
        return None   # back-off: retry at most once per 15 min after a failure
    try:
        p = (runner or _default_runner)(_pip_argv(), PIP_TIMEOUT)
        ok = p.returncode == 0
        tail = ((p.stderr or "") + (p.stdout or "") if not ok else "")[-DEPS_TAIL_MAX:]
    except Exception as exc:  # noqa: BLE001 -- timeout, runuser missing, ...
        ok, tail = False, "%s: %s" % (type(exc).__name__, exc)
    if ok:
        _save_req_state({"sha256": digest, "installed_at": now_ts})
        log.info("requirements.txt installed (sha256 %s)", digest[:12])
        return {"ok": True, "detail": "installed sha256 %s" % digest[:12]}
    new = {k: v for k, v in state.items() if k == "sha256"}
    new.update({"failed_sha256": digest, "failed_at": now_ts, "failed_tail": tail})
    _save_req_state(new)
    log.warning("pip install -r requirements.txt failed: %s", tail)
    return {"ok": False, "detail": tail}


def now() -> str:
    return datetime.utcnow().isoformat() + "Z"


# --- raw psql (DB-free: works on the read-only standby, no create_app) --------
def _db_creds():
    """(user, password, dbname) parsed from .env SQLALCHEMY_DATABASE_URI."""
    try:
        for line in (APP_DIR / ".env").read_text().splitlines():
            if line.startswith("SQLALCHEMY_DATABASE_URI="):
                uri = line.split("=", 1)[1].strip().strip('"').strip("'")
                m = re.search(r"://([^:]+):([^@]+)@[^/:]+(?::\d+)?/([A-Za-z0-9_]+)", uri)
                if m:
                    return m.group(1), m.group(2), m.group(3)
    except Exception:
        pass
    return None


def _psql(sql: str, timeout: int = 15):
    creds = _db_creds()
    if not creds:
        return None
    user, pw, dbname = creds
    env = dict(os.environ, PGPASSWORD=pw)
    try:
        r = subprocess.run(
            ["psql", "-h", "127.0.0.1", "-p", "5432", "-U", user, "-d", dbname,
             "-tAc", sql],
            capture_output=True, text=True, timeout=timeout, env=env)
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return None


def _setting(key: str):
    val = _psql("SELECT value FROM app_settings WHERE key = %s"
                % ("'" + key.replace("'", "''") + "'"))
    return val or None


def node_role() -> str:
    v = _psql("SELECT pg_is_in_recovery()")
    if v == "t":
        return "standby"
    if v == "f":
        return "primary"
    return "unknown"


def deploy_mode() -> str:
    """Loop-side (DB-free) read of the deploy mode. Default MANUAL (safe)."""
    v = (_setting(_K_DEPLOY_MODE) or "").strip().lower()
    return v if v in ("auto", "manual") else "manual"


# --- web-side (ORM) helpers: the Flask request already has a session ----------
def deploy_mode_orm() -> str:
    try:
        from ..models import AppSetting
        v = (AppSetting.get(_K_DEPLOY_MODE) or "").strip().lower()
        return v if v in ("auto", "manual") else "manual"
    except Exception:
        return "manual"


def set_deploy_mode(mode: str) -> None:
    """Persist the deploy mode into the replicated app_settings. Writable only
    where Postgres is read-write (the primary)."""
    if mode not in ("auto", "manual"):
        raise ValueError("mode must be 'auto' or 'manual'")
    from ..models import AppSetting
    AppSetting.set(_K_DEPLOY_MODE, mode)


def last_status_orm() -> dict | None:
    """The reconciler's last published tick (primary-published, replicated) so
    the UI on either node can render 'what is it doing'."""
    try:
        from ..models import AppSetting
        raw = AppSetting.get(_K_RECON_STATUS)
        return json.loads(raw) if raw else None
    except Exception:
        return None


# --- drift / interlock reads (DB-free) ----------------------------------------
def _validated_target():
    raw = _setting("ha.update.validated")
    if not raw:
        return None
    try:
        return (json.loads(raw) or {}).get("target")
    except Exception:
        return None


def _can_apply_primary(target: str) -> bool:
    """Mirror of su.can_apply_to_primary but DB-free: the PRIMARY may auto-apply
    a target only once the STANDBY has validated that EXACT revision (marker in
    ha.update.validated). Standalone / single-node -> no interlock."""
    mode = (_setting("ha.mode") or "").strip().lower()
    if mode == "standalone":
        return True
    if mode not in ("ha", "standalone"):
        try:
            nodes = json.loads((APP_DIR / "data" / "ha_nodes.json").read_text())
            others = [n for n in nodes if n.get("name") != su.this_node_name()]
            if not others:
                return True  # effectively standalone
        except Exception:
            return True
    return bool(target) and _validated_target() == target


def _active_update() -> bool:
    for st in su.recent_updates(limit=10):
        if st.get("state") in ("queued", "running"):
            return True
    return False


def _recent_fail() -> bool:
    """Back off if any self-update failed within the cooldown window."""
    for st in su.recent_updates(limit=10):
        if st.get("state") == "failed":
            try:
                t = datetime.fromisoformat((st.get("updated_at") or "").replace("Z", ""))
                if datetime.utcnow() - t < FAIL_COOLDOWN:
                    return True
            except Exception:
                pass
    return False


def _write_local(rec: dict) -> None:
    """Atomically replace THIS node's status file (best-effort, never raises).

    tmp + rename so the web worker reading it mid-write never gets half a JSON
    document -- the probe would report that as "no status", which reads as a
    dead reconciler. A legacy unit still declaring ``User=root`` would create
    state/ and the file as root and lock the service account out of the
    certificate journal next to it, so ownership follows the app tree.
    """
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATE_DIR / (".%s.tmp" % STATUS_FILE.name)
        tmp.write_text(json.dumps(rec, indent=2))
        if os.geteuid() == 0:
            try:
                st = APP_DIR.stat()
                os.chown(STATE_DIR, st.st_uid, st.st_gid)
                os.chown(tmp, st.st_uid, st.st_gid)
            except OSError:
                pass
        os.replace(tmp, STATUS_FILE)
    except Exception:  # noqa: BLE001 -- a status write must not kill a tick
        pass
    try:
        LEGACY_STATUS_FILE.unlink()
    except OSError:
        pass


def local_status() -> dict | None:
    """THIS node's last tick, or None.

    A record naming another node is refused rather than shown: it can only be
    a copy (a restore, a hand-copied tree, a pre-move file), and rendering a
    copy as this node's own state is the bug the node-local file fixes.

    The legacy ``data/`` file is read only as a fallback, and only when it
    names this node: a reconciler process started before this release keeps
    writing there until it is restarted (updates restart it from this release
    on -- see ``restart_reconciler`` in deploy/self_update_runner.py), and its
    own record is still the truth about this node. The primary's copy that the
    datasync plants there names the primary and is refused like any copy.
    """
    me = su.this_node_name()
    for path in (STATUS_FILE, LEGACY_STATUS_FILE):
        try:
            rec = json.loads(path.read_text())
        except Exception:  # noqa: BLE001 -- missing / half-written / unreadable
            continue
        if isinstance(rec, dict) and rec.get("node") == me:
            return rec
    return None


def public_error(text: str) -> str:
    """An error string safe for the unauthenticated probe: one line, URL
    credentials redacted, bounded."""
    one = " ".join(str(text or "").split())
    one = _URL_USERINFO.sub(r"\1***@", one)
    if len(one) > PUBLIC_ERROR_MAX:
        one = one[:PUBLIC_ERROR_MAX - 1] + "…"
    return one


#: The ONLY fields /healthz/reconciler publishes. An allowlist, not a filter:
#: a field added to the record later (commit subjects, paths, the detail text)
#: stays private until someone decides here that it may leave the node.
PUBLIC_FIELDS = ("node", "role", "mode", "decision", "behind", "at",
                 "fetch_error_since", "fetch_failures", "fetch_ok_at")


def public_status() -> dict | None:
    """The minimal view of THIS node's reconciler for the peer probe."""
    rec = local_status()
    if rec is None:
        return None
    out = {k: rec.get(k) for k in PUBLIC_FIELDS}
    out["target"] = (rec.get("target") or "")[:12]
    out["current"] = (rec.get("current") or "")[:12]
    out["error"] = public_error(rec.get("error") or "")
    return out


def _carry_streak(rec: dict, prev: dict | None) -> None:
    """Stamp how long fetching has been failing, carried across ticks.

    One failed fetch is noise (the primary restarting, a network blip). What
    the operator and the alert need is the STREAK: since when, and how many in
    a row -- "cannot fetch since 23:49Z" is the sentence that would have named
    the 2026-10-11 incident at a glance. ``fetch_ok_at`` survives the streak so
    the record still says when this node last got through.
    """
    prev = prev or {}
    if rec.get("decision") == "fetch-error":
        if prev.get("decision") == "fetch-error" and prev.get("fetch_error_since"):
            rec["fetch_error_since"] = prev["fetch_error_since"]
            rec["fetch_failures"] = int(prev.get("fetch_failures") or 0) + 1
        else:
            rec["fetch_error_since"] = rec["at"]
            rec["fetch_failures"] = 1
        rec["fetch_ok_at"] = prev.get("fetch_ok_at")
    else:
        rec["fetch_error_since"] = None
        rec["fetch_failures"] = 0
        rec["fetch_ok_at"] = rec["at"]


def _publish(rec: dict) -> None:
    _write_local(rec)
    # Only the primary can write the replicated setting (standby is read-only).
    if rec.get("role") == "primary":
        payload = json.dumps(rec).replace("'", "''")
        _psql("INSERT INTO app_settings(key,value,updated_at) VALUES "
              "('%s','%s',now()) ON CONFLICT (key) DO UPDATE SET "
              "value=EXCLUDED.value, updated_at=now()" % (_K_RECON_STATUS, payload))


def tick() -> dict:
    """One reconciliation pass. Never raises: returns the decision record."""
    role = node_role()
    mode = deploy_mode()
    prev = local_status()
    # [SATOM-UPDATE-METHODS] "Signed packages only" switches off the UPSTREAM
    # repository: no fetch, no alarm about a remote nobody uses. A standby
    # still follows its primary -- its origin is the primary, and that is how
    # a package applied there reaches it (update_methods module note).
    from . import update_methods as um
    method = um.effective()
    upstream_off = role != "standby" and not um.allows_git(method)
    try:
        if upstream_off:
            info = {"behind": 0, "target_sha": "", "commits": [], "error": "",
                    "current": su.current_revision()}
        else:
            info = su.check_remote(fetch=True)   # git fetch + compare (pure git, DB-free)
    except Exception as exc:  # noqa: BLE001 -- the promise above is "never raises"
        # Anything check_remote did not anticipate still has to become a
        # DECISION. An exception here used to kill the tick before _publish, so
        # the failure was recorded nowhere but the journal -- the shape of the
        # 2026-10-11 outage, where every tick for hours ended in a traceback.
        info = {"behind": 0, "target_sha": "", "current": {}, "commits": [],
                "error": "%s: %s" % (type(exc).__name__, exc)}
    behind = int(info.get("behind", 0) or 0)
    target = info.get("target_sha") or ""
    cur = (info.get("current") or {}).get("sha", "")
    rec = {"at": now(), "node": su.this_node_name(), "role": role, "mode": mode,
           "behind": behind, "target": target, "current": cur,
           "commits": info.get("commits", []), "error": info.get("error", "")}

    held = (not upstream_off and behind > 0 and role != "standby"
            and not info.get("error") and um.git_target(target)["is_downgrade"])
    rec["method"] = method

    if upstream_off:
        decision, detail = "disabled", ("update method is '%s': the git "
                                        "repository is not fetched; updates "
                                        "arrive as signed packages" % um.LABELS[method])
    elif info.get("error"):
        decision, detail = "fetch-error", info["error"]
    elif role == "unknown":
        decision, detail = "no-db", "cannot determine role (Postgres unreachable)"
    elif behind == 0:
        decision, detail = "up-to-date", "HEAD matches origin/%s" % su.BRANCH
    elif _active_update():
        decision, detail = "in-flight", "an update is already queued/running"
    elif _recent_fail():
        decision, detail = "cooldown", "backing off after a recent failed update"
    elif held:
        v = um.git_target(target)
        decision, detail = "held", ("origin/%s is version %s, older than the "
                                    "running %s (a newer signed package is "
                                    "installed): this node is not moved back"
                                    % (su.BRANCH, v["target"], v["running"]))
    elif mode == "manual":
        decision, detail = "observe", ("MANUAL mode -- %d commit(s) behind; the "
                                       "operator applies via Self-Update" % behind)
    else:  # AUTO
        if role == "standby":
            uid = su.request_update(target, by="auto-reconciler", origin="auto",
                                    role="standby", do_pip=True, do_migrate=False)
            decision, detail = "enqueued-standby", ("auto: standby self-update to "
                                                    "%s (uid %s)" % (target[:12], uid))
        elif role == "primary":
            if _can_apply_primary(target):
                uid = su.request_update(target, by="auto-reconciler", origin="auto",
                                        role="primary", do_pip=True, do_migrate=True)
                decision, detail = "enqueued-primary", ("auto: primary self-update "
                                                        "to %s (uid %s)" % (target[:12], uid))
            else:
                decision, detail = "await-standby", ("auto: primary waits for the "
                                                     "standby to validate %s" % target[:12])
        else:
            decision, detail = "idle", "unresolved role"

    rec["decision"] = decision
    rec["detail"] = detail
    _carry_streak(rec, prev)
    # Packages follow the code, independently of the decision above and never
    # blocking it (the update is already enqueued). Skipped while an update is
    # queued/running: the runner owns pip then, and two pips on one venv race.
    try:
        deps = None if _active_update() else ensure_requirements()
    except Exception as exc:  # noqa: BLE001
        deps = {"ok": False, "detail": "%s: %s" % (type(exc).__name__, exc)}
    if deps is not None and not deps["ok"]:
        rec["warning"] = DEPS_FAILED
        rec["warning_detail"] = deps["detail"]
        log.warning("%s: %s", DEPS_FAILED, deps["detail"])
    elif deps is None:
        # still backing off after a failure: keep the warning visible
        st = _load_req_state()
        if st.get("failed_sha256") and st.get("failed_sha256") != st.get("sha256"):
            rec["warning"] = DEPS_FAILED
            rec["warning_detail"] = st.get("failed_tail", "")
    # A fetch error is logged at WARNING with its streak, so a journal grep for
    # the outage finds one line per tick that says how long it has lasted.
    log.log(logging.WARNING if decision == "fetch-error" else logging.INFO,
            "role=%s mode=%s behind=%s decision=%s target=%s :: %s%s",
            role, mode, behind, decision, target[:12], detail,
            (" (failing since %s, %d in a row)"
             % (rec.get("fetch_error_since"), rec.get("fetch_failures") or 0)
             if decision == "fetch-error" else ""))
    _publish(rec)
    return rec
