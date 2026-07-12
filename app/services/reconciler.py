"""Auto-reconciler for the manager's OWN code across the HA pair.

Runs on BOTH nodes as a periodic tick (``fortinet-manager-reconciler.service``),
DB-FREE by design: the standby cannot boot the Flask app (create_all writes to
its read-only replica), so this module never calls ``create_app()``. It reads
the two replicated settings it needs via raw ``psql`` (reads work on a hot
standby) and does everything else with git + the filesystem queue that
``self_update`` already defines.

Deploy modes ("las 2" -- both coexist; the operator toggles between them):

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

import json
import logging
import os
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from . import self_update as su

log = logging.getLogger("fm.reconciler")

APP_DIR = Path(os.environ.get("FM_APP_DIR", "/opt/fortinet-manager"))
STATUS_FILE = APP_DIR / "data" / "reconciler-status.json"   # local, per-node (UI reads)

_K_DEPLOY_MODE = "ha.deploy.mode"        # "auto" | "manual" (replicated AppSetting)
_K_RECON_STATUS = "ha.reconcile.status"  # last tick, primary-published (replicated)

# Do not re-enqueue after a FAILED attempt within this window (avoid a tight
# auto-retry loop against a genuinely broken revision).
FAIL_COOLDOWN = timedelta(minutes=15)


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


def _publish(rec: dict) -> None:
    try:
        STATUS_FILE.write_text(json.dumps(rec, indent=2))
    except Exception:
        pass
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
    info = su.check_remote(fetch=True)   # git fetch + compare (pure git, DB-free)
    behind = int(info.get("behind", 0) or 0)
    target = info.get("target_sha") or ""
    cur = (info.get("current") or {}).get("sha", "")
    rec = {"at": now(), "node": su.this_node_name(), "role": role, "mode": mode,
           "behind": behind, "target": target, "current": cur,
           "commits": info.get("commits", []), "error": info.get("error", "")}

    if info.get("error"):
        decision, detail = "fetch-error", info["error"]
    elif role == "unknown":
        decision, detail = "no-db", "cannot determine role (Postgres unreachable)"
    elif behind == 0:
        decision, detail = "up-to-date", "HEAD matches origin/%s" % su.BRANCH
    elif _active_update():
        decision, detail = "in-flight", "an update is already queued/running"
    elif _recent_fail():
        decision, detail = "cooldown", "backing off after a recent failed update"
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
    log.info("role=%s mode=%s behind=%s decision=%s target=%s :: %s",
             role, mode, behind, decision, target[:12], detail)
    _publish(rec)
    return rec
