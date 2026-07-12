#!/usr/bin/env python3
"""Privileged self-update runner (runs as ROOT).

Triggered by ``fortinet-manager-updater.path`` whenever
``data/update-requests/`` becomes non-empty. It performs the actual, privileged
update the unprivileged web worker cannot: git checkout of the app code, pip
install of the Python deps, ``flask db upgrade``, refreshing the unit files and
restarting the service — with an AUTOMATIC ROLLBACK to the previous commit if
the post-restart health check fails.

Because it runs in its OWN service (not the gunicorn worker), restarting the
web app does not kill the update mid-flight. It is DB-free: progress is written
to a status JSON the web UI polls.

Scope: git app code + pip requirements + migrations. NEVER OS packages.
"""
import glob
import json
import os
import re
import socket
import subprocess
import time
import urllib.request
from datetime import datetime
from pathlib import Path

APP = Path(os.environ.get("FM_APP_DIR", "/opt/fortinet-manager"))
REQ = APP / "data" / "update-requests"
STA = APP / "data" / "update-status"
VENV = APP / "venv" / "bin"
SERVICE = "fortinet-manager.service"
SCHED = "fortinet-manager-scheduler.service"
APP_USER = os.environ.get("FM_APP_USER", "fortinet")
HEALTH_URL = os.environ.get("FM_HEALTH_URL", "http://127.0.0.1:8000/healthz")
HEALTH_TIMEOUT = int(os.environ.get("FM_HEALTH_TIMEOUT", "90"))
UNIT_FILES = (
    "fortinet-manager.service", "fortinet-manager-scheduler.service",
    "fortinet-manager-updater.service", "fortinet-manager-updater.path",
    "fortinet-manager-reconciler.service",
)


def now():
    return datetime.utcnow().isoformat() + "Z"


def run(cmd, timeout=600, user=None, cwd=None, env=None):
    if user:
        cmd = ["runuser", "-u", user, "--"] + cmd
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, cwd=cwd, env=env)


def git(*a, timeout=600):
    return run(["git", "-C", str(APP), "-c", "safe.directory=%s" % APP, *a],
               timeout=timeout, user=APP_USER)


def pg_in_recovery():
    """True when local Postgres is a hot standby (read-only replica).

    On the HA standby the app cannot run (create_all/_ensure_columns write on
    boot) and migrations must NOT run (the schema arrives via streaming
    replication from the primary), so the update path diverges: code + deps +
    unit files only, validated by an import smoke instead of an HTTP health
    check. Promotion is what turns this node into a serving primary."""
    try:
        r = subprocess.run(
            ["runuser", "-u", "postgres", "--", "psql", "-tAc",
             "select pg_is_in_recovery()"],
            capture_output=True, text=True, timeout=15)
        return r.stdout.strip() == "t"
    except Exception:
        return False


def import_smoke_ok():
    """Standby validation: the new code imports cleanly (no create_app, which
    would write to the read-only replica). Proves syntax/import health."""
    try:
        r = run([str(VENV / "python"), "-c", "import app"],
                timeout=60, user=APP_USER, cwd=str(APP))
        return r.returncode == 0, (r.stderr or r.stdout)
    except Exception as e:
        return False, str(e)


def _peer_host():
    """The OTHER HA node's host from ha_nodes.json (failover-agnostic)."""
    try:
        nodes = json.loads((APP / "data" / "ha_nodes.json").read_text())
        me = os.environ.get("FM_NODE_NAME") or socket.gethostname()
        for n in nodes:
            if n.get("name") != me and n.get("host"):
                return n["host"]
    except Exception:
        pass
    return None


def _env_db_creds():
    """(user, password, dbname) from the .env SQLALCHEMY_DATABASE_URI."""
    try:
        for line in (APP / ".env").read_text().splitlines():
            if line.startswith("SQLALCHEMY_DATABASE_URI="):
                uri = line.split("=", 1)[1].strip().strip('"').strip("'")
                m = re.search(r"://([^:]+):([^@]+)@[^/]+/([A-Za-z0-9_]+)", uri)
                if m:
                    return m.group(1), m.group(2), m.group(3)
    except Exception:
        pass
    return None


def mark_validated_on_primary(sha, node):
    """After a STANDBY validates a target revision, write the staged-rollout
    'validated' marker into the PRIMARY's (read-write) Postgres so the primary's
    update button unlocks (services.self_update.can_apply_to_primary reads
    ha.update.validated). The standby's own DB is read-only, hence the cross-node
    write to the peer discovered from ha_nodes.json."""
    host = _peer_host()
    creds = _env_db_creds()
    if not host or not creds:
        return False, "no peer host or db creds (ha_nodes.json / .env)"
    user, pw, dbname = creds
    payload = json.dumps({"target": sha, "node": node, "at": now()})
    lit = "'" + payload.replace("'", "''") + "'"
    sql = ("INSERT INTO app_settings(key,value,updated_at) VALUES "
           "('ha.update.validated', %s, now()) "
           "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now();" % lit)
    env = dict(os.environ, PGPASSWORD=pw)
    try:
        r = subprocess.run(["psql", "-h", host, "-p", "5432", "-U", user, "-d", dbname,
                            "-v", "ON_ERROR_STOP=1", "-c", sql],
                           capture_output=True, text=True, timeout=30, env=env)
        return r.returncode == 0, (r.stderr or r.stdout)
    except Exception as e:
        return False, str(e)


def health_ok(timeout=HEALTH_TIMEOUT):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(HEALTH_URL, timeout=5) as r:
                if getattr(r, "status", r.getcode()) == 200:
                    return True
        except Exception:
            pass
        time.sleep(3)
    return False


class Status:
    def __init__(self, uid, req):
        self.p = STA / (uid + ".json")
        self.d = {
            "id": uid, "state": "running", "steps": [],
            "target": req.get("target"), "branch": req.get("branch"),
            "requested_by": req.get("requested_by"),
            "node": req.get("node"), "role": req.get("role"),
            "origin": req.get("origin", "manual"),
            "started_at": now(), "updated_at": now(),
        }
        self.flush()

    def step(self, name, ok=True, detail=""):
        self.d["steps"].append({"name": name, "ok": bool(ok),
                                "detail": (detail or "").strip()[-500:], "at": now()})
        self.d["updated_at"] = now()
        self.flush()

    def finish(self, state, **extra):
        self.d["state"] = state
        self.d.update(extra)
        self.d["updated_at"] = now()
        self.flush()

    def flush(self):
        STA.mkdir(parents=True, exist_ok=True)
        self.p.write_text(json.dumps(self.d, indent=2))


def process(req_path):
    req = json.loads(Path(req_path).read_text())
    uid = req["id"]
    st = Status(uid, req)
    # Dequeue immediately so the .path unit does not re-trigger us in a loop.
    try:
        os.remove(req_path)
    except OSError:
        pass

    snapshot = git("rev-parse", "HEAD").stdout.strip()
    st.step("snapshot current commit", True, snapshot[:12])

    # HA role: explicit request wins; else detect from the local DB. A standby
    # updates code-only (no migration, no app restart, import-smoke validation).
    role = req.get("role") or ("standby" if pg_in_recovery() else "primary")
    is_standby = (role == "standby")
    st.step("ha role", True, role)

    try:
        branch = req.get("branch", "main")
        f = git("fetch", "origin", branch)
        st.step("git fetch origin %s" % branch, f.returncode == 0, f.stderr)
        if f.returncode != 0:
            raise RuntimeError("git fetch failed")

        target = req.get("target") or ("origin/%s" % branch)
        r = git("reset", "--hard", target)
        st.step("checkout %s" % target[:20], r.returncode == 0, r.stderr)
        if r.returncode != 0:
            raise RuntimeError("checkout/reset failed")
        # keep the local branch pointer on the branch tip when we tracked it
        git("checkout", "-B", branch, target)

        if req.get("do_pip", True):
            p = run([str(VENV / "pip"), "install", "-q", "-r",
                     str(APP / "requirements.txt")], timeout=900, user=APP_USER)
            st.step("pip install -r requirements.txt", p.returncode == 0, p.stderr)
            if p.returncode != 0:
                raise RuntimeError("pip install failed")

        # Migrations run on the PRIMARY only; on a standby the schema arrives
        # via streaming replication, and `flask db upgrade` would fail on the
        # read-only replica.
        if req.get("do_migrate", True) and not is_standby:
            env = dict(os.environ, FLASK_APP="wsgi.py")
            m = run([str(VENV / "flask"), "db", "upgrade"], timeout=600,
                    user=APP_USER, cwd=str(APP), env=env)
            # Best-effort: the app's authoritative schema step is boot-time
            # create_all()/_ensure_columns(); a spurious alembic error must not
            # block the update — the post-restart health check is the real gate.
            st.step("flask db upgrade (best-effort)", m.returncode == 0,
                    (m.stderr or m.stdout))
        elif is_standby:
            st.step("flask db upgrade", True, "skipped (standby; schema via replication)")

        # Refresh unit files (they may have changed in the update).
        for unit in UNIT_FILES:
            src = APP / "deploy" / unit
            if src.exists():
                subprocess.run(["cp", str(src), "/etc/systemd/system/" + unit])
        subprocess.run(["systemctl", "daemon-reload"])

        if is_standby:
            # Do NOT start the app (gunicorn crashes on a read-only replica).
            # The scheduler guard idle-waits; a restart just reloads its code.
            subprocess.run(["systemctl", "restart", SCHED], timeout=60)
            st.step("restart services", True, "scheduler only (standby; app stays stopped)")
            ok, detail = import_smoke_ok()
            if not ok:
                raise RuntimeError("import smoke failed: %s" % detail[:300])
            new = git("rev-parse", "HEAD").stdout.strip()
            st.step("import smoke", True, "new code imports on revision %s" % new[:12])
            # Unlock the primary: write the validated marker into the PRIMARY's
            # read-write DB (our own replica is read-only). Best-effort — a failed
            # marker write doesn't fail the standby update, but it IS the seguro.
            mok, mdetail = mark_validated_on_primary(new, req.get("node") or socket.gethostname())
            st.step("mark validated on primary", mok,
                    "primary update unlocked for %s" % new[:12] if mok else mdetail[:200])
            st.finish("success", result_sha=new, rolled_back=False, standby=True,
                      validated_on_primary=mok)
            return

        subprocess.run(["systemctl", "restart", SERVICE], timeout=120)
        subprocess.run(["systemctl", "restart", SCHED], timeout=60)
        st.step("restart services", True, "%s + scheduler" % SERVICE)

        if not health_ok():
            raise RuntimeError("health check did not return 200 within %ds" % HEALTH_TIMEOUT)
        new = git("rev-parse", "HEAD").stdout.strip()
        st.step("health check", True, "200 OK on new revision %s" % new[:12])
        st.finish("success", result_sha=new, rolled_back=False)
        return

    except Exception as e:
        st.step("ERROR", False, str(e))
        # ---------------- rollback to the snapshot ----------------
        try:
            git("reset", "--hard", snapshot)
            if req.get("do_pip", True):
                run([str(VENV / "pip"), "install", "-q", "-r",
                     str(APP / "requirements.txt")], timeout=900, user=APP_USER)
            subprocess.run(["systemctl", "restart", SCHED], timeout=60)
            if is_standby:
                ok, _ = import_smoke_ok()
            else:
                subprocess.run(["systemctl", "restart", SERVICE], timeout=120)
                ok = health_ok()
            st.step("rollback to %s" % snapshot[:12], ok,
                    "recovered" if ok else "STILL UNHEALTHY after rollback")
            st.finish("failed", result_sha=snapshot, rolled_back=True,
                      recovered=ok, error=str(e))
        except Exception as e2:
            st.finish("failed", rolled_back=True, recovered=False,
                      error="%s ; rollback error: %s" % (e, e2))


def promote(req_path):
    """Guarded failover handler (root): promote this node's Postgres standby and
    bring the app up via deploy/fm-promote.sh. Enqueued by the web UI after a
    typed-hostname confirmation; never auto-invoked."""
    req = json.loads(Path(req_path).read_text())
    uid = req.get("id") or Path(req_path).stem
    st = Status(uid, req)
    try:
        os.remove(req_path)  # dequeue so the .path unit stops re-firing
    except OSError:
        pass
    if not pg_in_recovery():
        st.step("precheck", False,
                "local Postgres is NOT a standby (already primary?) — refusing")
        st.finish("failed", error="not a standby")
        return
    script = APP / "deploy" / "fm-promote.sh"
    st.step("promote standby -> primary", True,
            "running fm-promote.sh (pg promote + start app)")
    try:
        r = subprocess.run(["bash", str(script)], capture_output=True,
                           text=True, timeout=300)
    except Exception as e:
        st.step("fm-promote.sh", False, str(e))
        st.finish("failed", error=str(e)[:300])
        return
    tail = ((r.stdout or "") + (r.stderr or "")).strip()[-500:]
    ok = (r.returncode == 0) and (not pg_in_recovery())
    st.step("fm-promote.sh exit %d" % r.returncode, ok, tail)
    if ok and health_ok():
        st.step("health check", True, "this node is now the read-write PRIMARY")
        st.finish("success", rolled_back=False, promoted=True)
    else:
        st.finish("failed", rolled_back=False,
                  error=(r.stderr or "promotion did not complete")[-300:])


def main():
    for rp in sorted(glob.glob(str(REQ / "*.json"))):
        try:
            kind = ""
            try:
                kind = (json.loads(Path(rp).read_text()) or {}).get("kind", "")
            except Exception:
                kind = ""
            if kind == "promote":
                promote(rp)
            else:
                process(rp)
        except Exception:
            try:
                os.remove(rp)  # never crash-loop on a malformed request
            except OSError:
                pass


if __name__ == "__main__":
    main()
