#!/usr/bin/env python3
"""Privileged self-update runner (runs as ROOT).

Triggered by ``satom-updater.path`` whenever
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

APP = Path(os.environ.get("FM_APP_DIR", "/opt/satom"))
REQ = APP / "data" / "update-requests"
STA = APP / "data" / "update-status"
VENV = APP / "venv" / "bin"
SERVICE = "satom.service"
SCHED = "satom-scheduler.service"


def _app_user_from_tree():
    """Dueño del árbol de la app = cuenta de servicio. Única fuente de verdad:
    una env var (FM_APP_USER) se olvida al instalar un nodo nuevo, el dueño del
    directorio no. Devuelve 'root' en una instalación sin degradar."""
    try:
        import pwd
        return pwd.getpwuid(APP.stat().st_uid).pw_name
    except Exception:
        return "root"


APP_USER = os.environ.get("FM_APP_USER") or _app_user_from_tree()
HEALTH_URL = os.environ.get("FM_HEALTH_URL", "http://127.0.0.1:8000/healthz")
HEALTH_TIMEOUT = int(os.environ.get("FM_HEALTH_TIMEOUT", "90"))


def _unit_templates():
    """Toda plantilla de unidad que deploy/ envía, LEÍDA DEL DIRECTORIO.

    Esto era una lista escrita a mano de seis nombres mientras deploy/ enviaba
    diez: satom-alerts.{service,timer} y satom-cert-renew.{service,timer} no se
    refrescaban NUNCA, así que la copia instalada seguía declarando
    User=fortinet — una cuenta que ya no existe en el nodo. Sólo arrancaban
    porque el drop-in las tapaba, y a ese drop-in no lo replica nada: un
    `systemctl revert` (o un nodo restaurado de una imagen anterior) convierte
    la renovación de certificado en status=217/USER, en silencio, que es
    exactamente lo que la señal cert.renew_failed existe para evitar.

    Una lista escrita a mano ES una copia del listado del directorio, y las
    copias se pudren: derivarla es la única forma de que la próxima unidad
    añadida a deploy/ no repita esto sin que nadie se entere.

    OJO — refrescar el FICHERO de una unidad NO es armarla. Aquí no se llama a
    `systemctl enable` en ningún caso, así que el estado enabled/disabled del
    nodo se conserva tal cual. Y sólo entra lo que deploy/ envía: por eso
    quedan fuera satom-ha-datasync.* (la escribe el instalador en línea y sólo
    en modo cluster) y satom-git-publish.* (RETIRADA el 2026-08-05).
    """
    names = set()
    for pat in ("*.service", "*.timer", "*.path"):
        try:
            names.update(p.name for p in (APP / "deploy").glob(pat))
        except OSError:
            pass
    return tuple(sorted(names))


UNIT_FILES = _unit_templates()

# Unidades que pueden existir INSTALADAS en un nodo pero que no son plantillas
# de deploy/: el instalador escribe satom-ha-datasync.{service,timer} en línea
# (sólo en modo cluster) y satom-git-publish.* quedó retirada el 2026-08-05. No
# se distribuyen ni se arman desde aquí; se listan sólo para que el drop-in de
# cuenta de servicio las siga cubriendo SI están instaladas — sin él, una
# unidad heredada que aún declare un usuario inexistente muere con
# status=217/USER.
LEGACY_NONROOT_UNITS = (
    "satom-ha-datasync.service",
    "satom-git-publish.service",
)

# Unidades que DEBEN correr como la cuenta de servicio. satom-updater.{service,
# path} está deliberadamente fuera: ES el runner privilegiado. Derivada por el
# mismo motivo que UNIT_FILES: las plantillas declaran User=root y cada update
# las recopia, así que una plantilla nueva que se olvidara aquí volvería a root
# en el siguiente update sin que nada avisara.
NONROOT_UNITS = tuple(sorted(
    ({u for u in UNIT_FILES if u.endswith(".service")}
     - {"satom-updater.service"})
    | set(LEGACY_NONROOT_UNITS)))

UNIT_DROPIN = """# Generado por SATOM (instalador / migrate-deprivilege.sh / self_update_runner).
# Vive en un drop-in y no en la unidad porque las plantillas de deploy/ declaran
# User=root y cada update las recopia: el drop-in sobrevive a esa copia.
# NO editar a mano.
[Service]
User=%s
Group=%s
"""


def enforce_unit_user(user):
    """Fija User=/Group= por drop-in en las unidades no privilegiadas."""
    if not user or user == "root":
        return
    for unit in NONROOT_UNITS:
        p = Path("/etc/systemd/system/" + unit)
        if not p.exists():
            continue
        d = Path(str(p) + ".d")
        try:
            d.mkdir(parents=True, exist_ok=True)
            (d / "10-app-user.conf").write_text(UNIT_DROPIN % (user, user))
        except OSError:
            pass


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


def flight(kind, label):
    """Run 'flask preflight' / 'flask postflight' as the app user and return
    (ok, detail). BEST-EFFORT and NON-FATAL: these are the before/after health
    snapshots wrapped around the upgrade. The authoritative rollback gate stays
    health_ok(); a postflight regression is surfaced in the update log (and by
    the alert engine on its next tick), it does not itself trigger a rollback,
    because a device blip can be unrelated to the code change."""
    try:
        env = dict(os.environ, FLASK_APP="wsgi.py")
        args = [str(VENV / "flask"), kind]
        if label:
            args += ["--label", label]
        p = run(args, timeout=90, user=APP_USER, cwd=str(APP), env=env)
        detail = (p.stdout or "")[-400:] or (p.stderr or "")[-400:]
        return p.returncode == 0, detail
    except Exception as exc:  # noqa: BLE001
        return False, "flight(%s) error: %s" % (kind, exc)


def preserve_local_commits(target, snapshot, st):
    """Park commits that exist here but not on *target* under ``refs/backup/``
    before a destructive reset, plus any uncommitted worktree state.

    Returns True when something was preserved, None when there was nothing to
    preserve, and False when preservation was needed but FAILED **or could not
    be evaluated** (the caller aborts the update in that case).

    That second clause is the fix of 2026-08-07. A ``git rev-list`` that FAILED
    (bad ref, a held index.lock, a timeout, a safe.directory refusal) left
    ``n == 0``, which is byte-for-byte the same answer as "there is nothing
    here to preserve": this returned None, ``None is not False``, and the
    caller walked straight into ``git reset --hard``. docs/safeguards.md
    promises that a guard which cannot do its job aborts the operation — and a
    guard that cannot even determine whether it was NEEDED has not done its
    job. Same for ``git status``: a failure yielded empty output and therefore
    ``dirty = False``, declaring uncommitted work absent.

    Uncommitted changes go through ``git stash create``, which builds a commit
    object without touching the index or the worktree — so this guard has zero
    effect on the update path that follows."""
    c = git("rev-list", "--count", "%s..HEAD" % target, timeout=60)
    if c.returncode != 0:
        st.step("count local commits", False,
                "git rev-list failed (rc=%d) — cannot tell whether there is "
                "anything to preserve: %s"
                % (c.returncode, (c.stderr or "")[:200]))
        return False
    try:
        n = int((c.stdout or "0").strip() or 0)
    except ValueError:
        st.step("count local commits", False,
                "git rev-list returned an uncountable answer: %r"
                % ((c.stdout or "")[:200],))
        return False
    # --untracked-files=no ON PURPOSE. `git reset --hard` does not touch
    # untracked files, so they never needed parking -- and `git stash create`
    # does not include them either, so it returns empty and this step reported
    # FAIL on every run where the only local state was untracked. A guard that
    # always complains is a guard operators learn to scroll past.
    s = git("status", "--porcelain", "--untracked-files=no", timeout=60)
    if s.returncode != 0:
        st.step("detect uncommitted changes", False,
                "git status failed (rc=%d) — cannot tell whether the worktree "
                "is dirty: %s" % (s.returncode, (s.stderr or "")[:200]))
        return False
    dirty = bool((s.stdout or "").strip())
    if not n and not dirty:
        return None

    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    ok = True
    if n:
        ref = "refs/backup/pre-reset-%s" % stamp
        u = git("update-ref", ref, snapshot, timeout=60)
        ok = ok and u.returncode == 0
        st.step("preserve %d local commit(s)" % n, u.returncode == 0,
                ("%s → %s (recover: git log %s)" % (ref, snapshot[:12], ref))
                if u.returncode == 0 else (u.stderr or "update-ref failed"))
    if dirty:
        s = git("stash", "create", "pre-reset %s" % stamp, timeout=120)
        sha = (s.stdout or "").strip()
        if s.returncode == 0 and sha:
            ref = "refs/backup/pre-reset-%s-dirty" % stamp
            u = git("update-ref", ref, sha, timeout=60)
            st.step("preserve uncommitted changes", u.returncode == 0,
                    "%s → %s" % (ref, sha[:12]) if u.returncode == 0
                    else (u.stderr or "update-ref failed"))
            # A dirty worktree is normal here (device_sync rewrites reports/
            # between publishes) and is regenerated on the next sync, so a
            # failure to stash it is reported but does NOT abort the update.
        else:
            st.step("preserve uncommitted changes", False,
                    "git stash create failed: %s" % (s.stderr or "")[:200])
    return ok


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

    # PRE-FLIGHT: health baseline before we touch anything (primary only — the
    # standby never restarts the app, so there is no health delta to catch).
    if not is_standby:
        pok, pdetail = flight("preflight", "upgrade-%s" % snapshot[:12])
        st.step("preflight (before)", pok, pdetail)

    try:
        branch = req.get("branch", "main")
        f = git("fetch", "origin", branch)
        st.step("git fetch origin %s" % branch, f.returncode == 0, f.stderr)
        if f.returncode != 0:
            raise RuntimeError("git fetch failed")

        target = req.get("target") or ("origin/%s" % branch)

        # ── SAFETY GUARD before the reset ────────────────────────────────
        # `reset --hard <target>` rewrites this checkout to the remote tip.
        # Anything committed here and NOT on the remote becomes unreachable
        # and is eventually gc'd. That is not a theoretical case: local code
        # commits (hotfixes, another session's work) can exist with nothing
        # to push to while Gitea is unreachable, and the
        # reconciler in AUTO mode can fire this path on its own the moment
        # Gitea comes back. Park those commits on a permanent ref first —
        # refs are never pruned, `git log <ref>` recovers them, and the git
        # bundles (data/git-bundles, created with --all) carry them off-box.
        # If the parking fails we ABORT: losing history silently is worse
        # than a deferred update.
        preserved = preserve_local_commits(target, snapshot, st)
        if preserved is False:
            raise RuntimeError("refusing to reset: local commits could not be "
                               "preserved")

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
        # ...y VOLVER a fijar la cuenta de servicio. Las plantillas de deploy/
        # declaran User=root, así que la copia de arriba degradaría el modelo de
        # privilegio en cada update si no fuera por el drop-in.
        enforce_unit_user(APP_USER)
        subprocess.run(["systemctl", "daemon-reload"])
        # Refresh the ROOT-OWNED copies that live OUTSIDE the app tree: the
        # operator CLI, the update runner, and the /usr/local/sbin helper
        # scripts (install-runner.sh installs those last -- see
        # [SATOM-SBIN-ROOT-COPY]). They are outside on purpose (a sudo/root
        # target writable by the service account is a root escalation), which
        # means a code update does NOT reach them -- so they must be
        # re-installed here or they silently age behind the app. That is not
        # hypothetical: /usr/local/sbin/satom-ha-datasync.sh sat 11 days and
        # two bug-fixes behind git because its only installer was a one-shot
        # migration, and the replicator reported SUCCESS while replicating
        # nothing.
        try:
            for _script, _label in (("install-cli.sh", "operator CLI"),
                                    ("install-runner.sh",
                                     "update runner + /usr/local/sbin helpers")):
                _p = APP / "deploy" / _script
                if _p.exists():
                    cr = subprocess.run(["bash", str(_p)], capture_output=True,
                                        text=True, timeout=180)
                    st.step("refresh %s" % _label, cr.returncode == 0,
                            (cr.stdout or cr.stderr or "").strip()[:200])
        except Exception as exc:  # noqa: BLE001
            # Never fail an update because the console tool did not refresh.
            st.step("refresh operator CLI", False, str(exc)[:200])

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
        # POST-FLIGHT: compare the after-state against the preflight baseline.
        # Non-fatal: the health gate above already passed; this surfaces device /
        # replication / cert deltas the bare health check can't see.
        fok, fdetail = flight("postflight", "upgrade-%s" % new[:12])
        st.step("postflight (after)", fok,
                fdetail if fok else "REGRESSION vs preflight — review: %s" % fdetail)
        st.finish("success", result_sha=new, rolled_back=False, postflight_ok=fok)
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


_PKG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_VER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")


def _pip_allowlist():
    """The curated set of libraries the card shows — the ONLY packages this
    runner will touch. Loaded from the app's own system_info._LIBRARIES so the
    allowlist has exactly one source of truth; a hardcoded fallback guarantees
    the runner still refuses arbitrary names if the import ever fails."""
    fallback = {
        "Flask", "Werkzeug", "Jinja2", "SQLAlchemy", "Flask-SQLAlchemy",
        "Flask-Login", "Flask-WTF", "Flask-Limiter", "psycopg", "gunicorn",
        "paramiko", "httpx", "cryptography", "requests", "PyYAML",
    }
    # [SATOM-RUNNER-NO-APP-IMPORT] Deliberately NOT imported from
    # app.services.system_info. That import executes the application package
    # -- as root, from a tree the service account owns -- which is the same
    # escalation install-runner.sh exists to close. The list below is asserted
    # equal to system_info._LIBRARIES by tests/test_update_package.py, so the
    # two cannot drift.
    return fallback


def _installed_version(pkg):
    """Currently-installed version of pkg in the venv, or '' if absent."""
    r = run([str(VENV / "python"), "-c",
             "import importlib.metadata as m,sys;"
             "sys.stdout.write(m.version(sys.argv[1]))", pkg],
            timeout=30, user=APP_USER, cwd=str(APP))
    return r.stdout.strip() if r.returncode == 0 else ""


def _pip_install(spec):
    """pip install a single pinned spec (pkg==ver) as the app user."""
    return run([str(VENV / "pip"), "install", "-q", spec],
               timeout=900, user=APP_USER)


def _record_lib_version(pkg, previous, current, action, by):
    """Persist the per-node rollback point for pkg so the card can offer a
    'Rollback to <previous>' button. One file per package under
    data/lib-versions/ (per-node, because the venv is per-node)."""
    d = APP / "data" / "lib-versions"
    d.mkdir(parents=True, exist_ok=True)
    (d / (pkg + ".json")).write_text(json.dumps({
        "package": pkg, "previous": previous, "current": current,
        "action": action, "by": by, "at": now()}, indent=2))


def _bump_requirements(pkg, version):
    """Rewrite pkg's pin in requirements.txt to ==version (so the next code
    update's `pip install -r` does not silently revert this change). Matches
    the package line case-insensitively on the distribution name. Returns
    (changed, detail)."""
    req = APP / "requirements.txt"
    try:
        lines = req.read_text().splitlines()
    except Exception as e:
        return False, "read failed: %s" % e
    name_re = re.compile(r"^\s*%s\s*([<>=!~].*)?$" % re.escape(pkg), re.IGNORECASE)
    out, hit = [], False
    for ln in lines:
        if name_re.match(ln) and not ln.lstrip().startswith("#"):
            out.append("%s==%s" % (pkg, version))
            hit = True
        else:
            out.append(ln)
    if not hit:
        out.append("%s==%s" % (pkg, version))
    req.write_text("\n".join(out) + "\n")
    return True, ("updated pin" if hit else "added pin")


def _git_commit_push_requirements(pkg, version, by):
    """Commit + push the requirements.txt bump on the PRIMARY only (single git
    writer). Non-fatal: a push failure (conflict/offline) leaves the lib
    installed and the pin committed locally — reported as a warning step."""
    git("add", "requirements.txt")
    msg = "chore(deps): pin %s==%s via Libraries GUI (by %s)" % (pkg, version, by)
    c = git("commit", "-m", msg)
    if c.returncode != 0:
        # nothing to commit (pin already matched) is fine
        return True, (c.stdout or c.stderr or "nothing to commit").strip()[-200:]
    p = git("push", "origin", "HEAD", timeout=120)
    return (p.returncode == 0), (p.stderr or p.stdout or "").strip()[-200:]


def pip_change(req_path):
    """Per-package pip upgrade/rollback (root-triggered, curated-only).

    The unprivileged web worker only ENQUEUES a JSON request; this handler does
    the privileged install. It is strictly bounded: the package MUST be in the
    curated allowlist and both names are regex-validated, so a forged request
    can never turn this into 'pip install <arbitrary>'. Records the prior
    version for a one-click rollback, auto-reverts on a failed health/import
    check, and (on the primary) bumps requirements.txt so the change survives
    the next code update."""
    req = json.loads(Path(req_path).read_text())
    uid = req.get("id") or Path(req_path).stem
    st = Status(uid, req)
    try:
        os.remove(req_path)  # dequeue so the .path unit stops re-firing
    except OSError:
        pass

    pkg = (req.get("package") or "").strip()
    version = (req.get("version") or "").strip()
    action = req.get("action") or "upgrade"
    by = req.get("requested_by") or "?"
    bump = bool(req.get("bump_requirements", True))
    st.d["package"] = pkg
    st.d["action"] = action
    st.flush()

    # ---- hard guardrails (defense in depth; the web side validates too) ----
    if not _PKG_RE.match(pkg) or pkg not in _pip_allowlist():
        st.step("validate package", False, "%r not in curated allowlist" % pkg)
        st.finish("failed", error="package not allowed")
        return
    if not _VER_RE.match(version):
        st.step("validate version", False, "%r is not a valid version" % version)
        st.finish("failed", error="bad version")
        return
    st.step("validate", True, "%s -> %s (%s)" % (pkg, version, action))

    role = req.get("role") or ("standby" if pg_in_recovery() else "primary")
    previous = _installed_version(pkg)
    st.step("snapshot installed version", True, "%s==%s" % (pkg, previous or "(absent)"))
    if previous == version:
        st.step("noop", True, "already at %s" % version)
        _record_lib_version(pkg, previous, version, action, by)
        st.finish("success", package=pkg, previous_version=previous,
                  new_version=version, rolled_back=False)
        return

    try:
        p = _pip_install("%s==%s" % (pkg, version))
        st.step("pip install %s==%s" % (pkg, version), p.returncode == 0, p.stderr or p.stdout)
        if p.returncode != 0:
            raise RuntimeError("pip install failed")

        ok, detail = import_smoke_ok()
        st.step("import smoke", ok, "app imports with new %s" % pkg if ok else detail[:300])
        if not ok:
            raise RuntimeError("import smoke failed: %s" % detail[:200])

        # Reload the running workers so the new lib is actually loaded.
        subprocess.run(["systemctl", "restart", SERVICE], timeout=120)
        subprocess.run(["systemctl", "restart", SCHED], timeout=60)
        st.step("restart services", True, "%s + scheduler" % SERVICE)
        if not health_ok():
            raise RuntimeError("health check did not return 200 within %ds" % HEALTH_TIMEOUT)
        st.step("health check", True, "200 OK with %s==%s" % (pkg, version))

        _record_lib_version(pkg, previous, version, action, by)

        # Keep requirements.txt honest so the next code update doesn't revert us
        # (primary only — single git writer). Non-fatal.
        if bump and role == "primary":
            ch, d1 = _bump_requirements(pkg, version)
            st.step("bump requirements.txt", ch, d1)
            gok, d2 = _git_commit_push_requirements(pkg, version, by)
            st.step("commit + push requirements.txt", gok,
                    d2 if gok else "installed OK but push failed: %s" % d2)
        elif bump:
            st.step("bump requirements.txt", True, "skipped on standby (primary is the git writer)")

        st.finish("success", package=pkg, previous_version=previous,
                  new_version=version, rolled_back=False)
        return

    except Exception as e:
        st.step("ERROR", False, str(e))
        # ---- auto-rollback to the previously-installed version ----
        try:
            if previous:
                rb = _pip_install("%s==%s" % (pkg, previous))
                subprocess.run(["systemctl", "restart", SERVICE], timeout=120)
                subprocess.run(["systemctl", "restart", SCHED], timeout=60)
                ok = health_ok()
                st.step("rollback to %s==%s" % (pkg, previous),
                        rb.returncode == 0 and ok,
                        "recovered" if ok else "STILL UNHEALTHY after rollback")
            else:
                st.step("rollback", False, "no previous version recorded — cannot auto-revert")
                ok = False
            st.finish("failed", package=pkg, previous_version=previous,
                      new_version=previous, rolled_back=True, recovered=ok, error=str(e))
        except Exception as e2:
            st.finish("failed", package=pkg, rolled_back=True, recovered=False,
                      error="%s ; rollback error: %s" % (e, e2))



# ---------------------------------------------------------------------------
# offline update packages (kind: "package")
# ---------------------------------------------------------------------------
UPLOADS = APP / "data" / "update-uploads"
TRUST_DIR = os.environ.get("SATOM_TRUST_DIR", "/etc/satom/update-keys")
RUNNER_LIB = "/usr/local/lib/satom-runner"


def _load_update_package():
    """Load the signature verifier that sits NEXT TO THIS FILE.

    Deliberately a sibling and not ``APP/deploy``: when this runner is properly
    installed both live in the root-owned copy, so the verifier is exactly as
    trustworthy as the code that calls it. Loading the verifier from the app
    tree while running hardened would reintroduce the escalation the hardening
    removes.
    """
    import importlib.util
    path = Path(__file__).resolve().parent / "update_package.py"
    spec = importlib.util.spec_from_file_location("satom_update_package", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def runner_integrity_problem():
    """Why this runner must not be trusted to verify a package, or None.

    [SATOM-RUNNER-ROOT-COPY] Running as root out of a directory the service
    account can write means the account can choose the code root executes.
    Signature verification performed by that code proves nothing. The git
    update path keeps working (it is gated by the remote, not by us), but an
    uploaded package is refused until ``install-runner.sh`` has been run.
    """
    here = Path(__file__).resolve().parent
    try:
        up = _load_update_package()
    except Exception as exc:  # noqa: BLE001
        return "cannot load the signature verifier: %s" % exc
    problem = up.root_owned_problem(here, "*.py")
    if problem:
        return ("%s — run 'bash %s/deploy/install-runner.sh' as root to install "
                "the hardened copy" % (problem, APP))
    return None


def _new_untracked(before):
    """Untracked, non-ignored paths that appeared since ``before``.

    Rollback removes only these. A blanket ``git clean -fd`` would also delete
    untracked files that predate the update and have nothing to do with it —
    destroying an operator's work to undo ours.
    """
    out = git("ls-files", "--others", "--exclude-standard", timeout=120).stdout or ""
    now = {ln.strip() for ln in out.splitlines() if ln.strip()}
    return sorted(now - before)


def _untracked_set():
    out = git("ls-files", "--others", "--exclude-standard", timeout=120).stdout or ""
    return {ln.strip() for ln in out.splitlines() if ln.strip()}


def _chown_tree():
    """Give the extracted tree back to the service account.

    Root wrote these files, and a root-owned app tree is the exact state in
    which enforce_unit_user() stops writing the User= drop-in — the next update
    would silently put the web app back to running as root.
    """
    if not APP_USER or APP_USER == "root":
        return True, "running un-deprivileged; nothing to hand back"
    r = subprocess.run(["chown", "-R", "%s:%s" % (APP_USER, APP_USER), str(APP)],
                       capture_output=True, text=True, timeout=300)
    env = APP / ".env"
    if env.exists():
        subprocess.run(["chown", "root:%s" % APP_USER, str(env)],
                       capture_output=True, text=True, timeout=30)
        subprocess.run(["chmod", "640", str(env)],
                       capture_output=True, text=True, timeout=30)
    return r.returncode == 0, (r.stderr or "tree owned by %s" % APP_USER)[:200]


def _current_version():
    try:
        return (APP / "VERSION").read_text().strip()
    except OSError:
        return ""


def _venv_tag():
    r = run([str(VENV / "python"), "-c",
             "import sys;print('cp%d%d' % sys.version_info[:2])"],
            timeout=30, user=APP_USER)
    return (r.stdout or "").strip()


def package_change(req_path):
    """Apply a SIGNED OFFLINE UPDATE PACKAGE uploaded through the web console.

    The web worker only staged a file and wrote this request. Everything that
    decides whether the package is trustworthy happens HERE, as root, against a
    trust store the worker cannot write:

        hardened?  ->  signature  ->  every hash  ->  version rules  ->  apply

    and the order is not cosmetic. A writable runner makes the signature
    meaningless; an unverified manifest makes the hashes meaningless; unchecked
    version rules let a valid-but-wrong package through. Each stage only makes
    sense once the previous one passed.
    """
    req = json.loads(Path(req_path).read_text())
    uid = req.get("id") or Path(req_path).stem
    st = Status(uid, req)
    try:
        os.remove(req_path)
    except OSError:
        pass

    st.d["kind"] = "package"
    st.d["package"] = req.get("package")
    st.flush()

    import shutil
    import tempfile

    up = None
    stage = None
    snapshot = git("rev-parse", "HEAD").stdout.strip()
    untracked_before = _untracked_set()
    freeze = None
    role = req.get("role") or ("standby" if pg_in_recovery() else "primary")
    is_standby = (role == "standby")

    try:
        # -- 0. is this runner allowed to make a trust decision at all? ------
        problem = runner_integrity_problem()
        if problem:
            st.step("runner integrity", False, problem)
            raise RuntimeError("refusing to verify a package from a runner the "
                               "service account can rewrite")
        st.step("runner integrity", True,
                "running root-owned from %s" % Path(__file__).resolve().parent)
        up = _load_update_package()

        # -- 1. resolve the package from a NAME, never a path ---------------
        name = (req.get("package") or "").strip()
        if not up.PKG_NAME_RE.match(name):
            raise RuntimeError("%r is not an acceptable package name" % name)
        pkg_file = UPLOADS / name
        if not pkg_file.is_file():
            raise RuntimeError("%s is not staged on this node" % name)
        st.step("locate package", True, "%s (%d bytes)"
                % (name, pkg_file.stat().st_size))

        # -- 2. extract ONCE into root-only space ---------------------------
        # The staging directory is writable by the service account, so anything
        # verified in place could be swapped afterwards. Copying into a
        # root-only temp collapses read-verify-use into a single read.
        stage = Path(tempfile.mkdtemp(prefix="satom-pkg-", dir="/var/tmp"))
        os.chmod(stage, 0o700)
        pkg_dir = up.extract_package(pkg_file, stage)
        st.step("extract to root-only staging", True, str(stage))

        # -- 3. signature + integrity ---------------------------------------
        verified = up.verify_package(pkg_dir, TRUST_DIR)
        manifest = verified["manifest"]
        key = verified["key"]
        st.step("verify signature", True, "signed by %s (%s)"
                % (key["fingerprint"], key["comment"] or key["name"]))
        st.step("verify %d file hash(es)" % len(manifest.get("files") or {}),
                True, "every file matches the signed manifest")

        # -- 4. version rules ------------------------------------------------
        cur = _current_version()
        new = str(manifest.get("version") or "")
        st.d["target"] = new
        cmp_ = up.compare_versions(new, cur)
        if cmp_ < 0 and not req.get("allow_downgrade"):
            raise RuntimeError("package %s is OLDER than the installed %s and "
                               "the request did not allow a downgrade" % (new, cur))
        min_from = str(manifest.get("min_from_version") or "")
        if min_from and up.compare_versions(cur, min_from) < 0:
            raise RuntimeError("package requires %s or newer; this node runs %s"
                               % (min_from, cur))
        tags = list(manifest.get("python_tags") or [])
        mine = _venv_tag()
        if tags and "*" not in tags and mine and mine not in tags:
            raise RuntimeError("package carries wheels for %s; this venv is %s"
                               % (", ".join(tags), mine))
        st.step("version rules", True, "%s -> %s%s"
                % (cur, new, " (DOWNGRADE, explicitly allowed)" if cmp_ < 0 else ""))

        # -- 5. backup BEFORE anything is replaced ---------------------------
        # A downgrade does not reverse migrations, so the database dump is the
        # only honest way back. If it cannot be taken, do not proceed.
        if req.get("do_backup", True) and not is_standby:
            b = subprocess.run(["/usr/local/sbin/satom", "execute", "backup", "db"],
                               capture_output=True, text=True, timeout=1200)
            ok = b.returncode == 0
            st.step("database backup", ok,
                    (b.stdout or b.stderr or "").strip()[-300:])
            if not ok:
                raise RuntimeError("database backup failed; refusing to replace "
                                   "code without a way back")
        elif is_standby:
            st.step("database backup", True,
                    "skipped (standby; its database is a replica of the primary)")

        freeze = Path("/root/satom-venv-freeze-pre-package-%s.txt"
                      % datetime.utcnow().strftime("%Y%m%d-%H%M%S"))
        fr = run([str(VENV / "pip"), "freeze"], timeout=180, user=APP_USER)
        if fr.returncode == 0:
            freeze.write_text(fr.stdout)
            st.step("freeze current dependencies", True, str(freeze))
        else:
            freeze = None
            st.step("freeze current dependencies", False,
                    "pip freeze failed; a dependency rollback will not be possible")

        # -- 6. park anything local, then lay the tree down ------------------
        preserved = preserve_local_commits(snapshot, snapshot, st)
        if preserved is False:
            raise RuntimeError("refusing to replace the tree: local commits "
                               "could not be preserved")

        app_tar = pkg_dir / "app.tar.gz"
        if not app_tar.is_file():
            raise RuntimeError("package has no app.tar.gz")
        # [SATOM-PKG-DELETIONS]
        tracked_now = {ln.strip() for ln in
                          (git("ls-files", timeout=120).stdout or "").splitlines()
                          if ln.strip()}
        written = up.extract_app_tree(app_tar, APP)
        st.step("install application tree", True, "%d file(s) from %s"
                % (len(written), name))

        # Laying a tarball over a checkout adds and overwrites; it never
        # deletes. Without this, a module removed in the new revision stays on
        # disk and keeps importing -- an update that silently half-applies.
        # app.tar.gz comes from `git archive`, so its member list IS the
        # complete tracked set of the target revision; anything tracked here
        # and absent there was deleted upstream. Only TRACKED paths are
        # considered, so data/, pki/ and .env cannot be caught by this.
        stale = sorted(tracked_now - set(written))
        for rel in stale:
            try:
                (APP / rel).unlink()
            except OSError:
                pass
        if stale:
            st.step("remove %d file(s) the new revision dropped" % len(stale),
                    True, ", ".join(stale[:8]))
        cok, cdetail = _chown_tree()
        st.step("restore tree ownership", cok, cdetail)

        # -- 7. dependencies, strictly offline -------------------------------
        wheels = pkg_dir / "wheels"
        p = run([str(VENV / "pip"), "install", "-q", "--no-index",
                 "--find-links", str(wheels), "-r", str(APP / "requirements.txt")],
                timeout=1800, user=APP_USER)
        st.step("pip install (offline, from the package)", p.returncode == 0,
                (p.stderr or p.stdout or "")[-400:])
        if p.returncode != 0:
            raise RuntimeError("offline pip install failed")

        # -- 8. migrations (primary only) ------------------------------------
        if not is_standby:
            env = dict(os.environ, FLASK_APP="wsgi.py")
            m = run([str(VENV / "flask"), "db", "upgrade"], timeout=600,
                    user=APP_USER, cwd=str(APP), env=env)
            st.step("flask db upgrade (best-effort)", m.returncode == 0,
                    (m.stderr or m.stdout or "")[-300:])
        else:
            st.step("flask db upgrade", True,
                    "skipped (standby; schema arrives by replication)")

        # -- 9. units, CLI and the runner itself -----------------------------
        for unit in UNIT_FILES:
            src = APP / "deploy" / unit
            if src.exists():
                subprocess.run(["cp", str(src), "/etc/systemd/system/" + unit])
        enforce_unit_user(APP_USER)
        subprocess.run(["systemctl", "daemon-reload"])
        # install-runner.sh also re-installs the /usr/local/sbin helper
        # scripts ([SATOM-SBIN-ROOT-COPY]); they live outside the tree and no
        # code update reaches them otherwise.
        for script, label in (("install-cli.sh", "operator CLI"),
                              ("install-runner.sh",
                               "update runner + /usr/local/sbin helpers")):
            sp = APP / "deploy" / script
            if sp.exists():
                cr = subprocess.run(["bash", str(sp)], capture_output=True,
                                    text=True, timeout=180)
                st.step("refresh %s" % label, cr.returncode == 0,
                        (cr.stdout or cr.stderr or "").strip()[-200:])

        # -- 10. restart and prove it works ----------------------------------
        if is_standby:
            subprocess.run(["systemctl", "restart", SCHED], timeout=60)
            ok, detail = import_smoke_ok()
            if not ok:
                raise RuntimeError("import smoke failed: %s" % detail[:300])
            st.step("import smoke", True, "new code imports on version %s" % new)
        else:
            subprocess.run(["systemctl", "restart", SERVICE], timeout=120)
            subprocess.run(["systemctl", "restart", SCHED], timeout=60)
            st.step("restart services", True, "%s + scheduler" % SERVICE)
            if not health_ok():
                raise RuntimeError("health check did not return 200 within %ds"
                                   % HEALTH_TIMEOUT)
            st.step("health check", True, "200 OK on version %s" % new)

        # -- 11. record what is deployed -------------------------------------
        # Without a commit the tree stays permanently dirty, `satom diagnose
        # git` reports drift for ever, and the reconciler in AUTO mode would
        # reset the package away on its next pass. Committing as the service
        # account (never root: root-owned objects in .git break git-publish).
        # Stage exactly what this package touched. `git add -A` would also
        # commit whatever else happened to be uncommitted in the tree --
        # another session's work in progress, attributed to this apply. That
        # is not hypothetical: the first live apply swept 4553 lines of an
        # unrelated feature branch into its own commit.
        paths = sorted(set(written) | set(stale))
        for _i in range(0, len(paths), 200):
            git("add", "--", *paths[_i:_i + 200], timeout=120)
        c = git("commit", "-m",
                "apply update package %s (%s) by %s"
                % (new, (manifest.get("commit") or "")[:12],
                   req.get("requested_by") or "?"))
        st.step("record deployed revision", True,
                (c.stdout or c.stderr or "nothing to commit").strip()[-200:])

        st.finish("success", package=name, applied_version=new,
                  previous_version=cur, rolled_back=False,
                  signed_by=key["fingerprint"],
                  downgrade=bool(cmp_ < 0))
        return

    except Exception as e:  # noqa: BLE001
        st.step("ERROR", False, str(e)[:400])
        try:
            git("reset", "--hard", snapshot)
            stray = _new_untracked(untracked_before)
            for rel in stray:
                target = APP / rel
                try:
                    if target.is_file() or target.is_symlink():
                        target.unlink()
                except OSError:
                    pass
            if stray:
                st.step("remove %d file(s) the package added" % len(stray), True,
                        ", ".join(stray[:8]))
            if freeze and freeze.exists():
                run([str(VENV / "pip"), "install", "-q", "-r", str(freeze)],
                    timeout=1800, user=APP_USER)
            _chown_tree()
            subprocess.run(["systemctl", "restart", SCHED], timeout=60)
            if is_standby:
                ok, _ = import_smoke_ok()
            else:
                subprocess.run(["systemctl", "restart", SERVICE], timeout=120)
                ok = health_ok()
            st.step("rollback to %s" % snapshot[:12], ok,
                    "recovered" if ok else "STILL UNHEALTHY after rollback")
            st.finish("failed", result_sha=snapshot, rolled_back=True,
                      recovered=ok, error=str(e)[:400])
        except Exception as e2:  # noqa: BLE001
            st.finish("failed", rolled_back=True, recovered=False,
                      error="%s ; rollback error: %s" % (e, e2))
    finally:
        if stage:
            import shutil as _sh
            _sh.rmtree(stage, ignore_errors=True)


def promote(req_path):
    """Guarded failover handler (root): promote this node's Postgres standby and
    bring the app up via deploy/satom-promote.sh. Enqueued by the web UI after a
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
    script = APP / "deploy" / "satom-promote.sh"
    st.step("promote standby -> primary", True,
            "running satom-promote.sh (pg promote + start app)")
    try:
        r = subprocess.run(["bash", str(script)], capture_output=True,
                           text=True, timeout=300)
    except Exception as e:
        st.step("satom-promote.sh", False, str(e))
        st.finish("failed", error=str(e)[:300])
        return
    tail = ((r.stdout or "") + (r.stderr or "")).strip()[-500:]
    ok = (r.returncode == 0) and (not pg_in_recovery())
    st.step("satom-promote.sh exit %d" % r.returncode, ok, tail)
    if ok and health_ok():
        st.step("health check", True, "this node is now the read-write PRIMARY")
        st.finish("success", rolled_back=False, promoted=True)
    else:
        st.finish("failed", rolled_back=False,
                  error=(r.stderr or "promotion did not complete")[-300:])


# ---------------------------------------------------------------------------
# systemd service control (kind: "service")   [SATOM-SERVICE-CONTROL]
# ---------------------------------------------------------------------------
# The unprivileged web worker cannot run systemctl and must not be granted it:
# a generic `sudo systemctl` reaches every unit on the box, so it IS root, just
# spelled differently. It enqueues a request; this applies it.
#
# The allowlist is duplicated from app/services/service_control.py ON PURPOSE.
# Importing that module would execute the Flask package as root out of a tree
# the service account can write -- the exact escalation the curated pip
# allowlist was moved out of. tests/test_service_control.py fails if the two
# copies drift, which is what keeps a duplicate honest.
_SVC_UNIT_RE = re.compile(r"^[A-Za-z0-9@:._-]+\.(service|timer|path)$")
_SVC_ACTIONS = ("start", "stop", "restart")

# Denied even if a future edit lists them: satom-updater IS this runner.
# Stopping it means no later request can ever be processed -- including the one
# that would start it again -- so the button would brick its own escalation
# path while reporting success. Restarting it kills the operation in flight.
_SVC_FORBIDDEN = ("satom-updater.service", "satom-updater.path")

_SERVICE_POLICY = {
    "satom.service": ("restart",),
    "satom-scheduler.service": ("start", "stop", "restart"),
    "satom-reconciler.service": ("start", "stop", "restart"),
    "satom-metrics.service": ("start", "stop", "restart"),
    "satom-alerts.timer": ("start", "stop", "restart"),
    "satom-cert-renew.timer": ("start", "stop", "restart"),
    "satom-ha-datasync.timer": ("start", "stop", "restart"),
    "nginx.service": ("start", "restart"),
    "postgresql.service": ("restart",),
}

# Units whose action can take the console down. Anything else is verified by
# its own state alone -- running health_ok() after stopping the alert timer
# would pass trivially and teach nobody anything.
_SVC_HEALTH_CRITICAL = ("satom.service", "nginx.service", "postgresql.service")


def _svc_prop(unit, prop):
    try:
        r = subprocess.run(["systemctl", "show", "-p", prop, "--value", unit],
                           capture_output=True, text=True, timeout=10)
        return (r.stdout or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def _svc_active(unit):
    return _svc_prop(unit, "ActiveState") or "unknown"


def front_ok(timeout=25):
    """The TLS front answers on :443.

    health_ok() talks to gunicorn on :8000 directly, so it stays GREEN with
    nginx down -- nginx is the one unit whose failure the existing check cannot
    see. Certificate validity is irrelevant here (a node may serve an internal
    CA leaf), so the handshake is deliberately unverified: this asks 'is the
    front answering', not 'is the front trusted'.
    """
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen("https://127.0.0.1/healthz",
                                        timeout=5, context=ctx) as r:
                if getattr(r, "status", r.getcode()) == 200:
                    return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(3)
    return False


def service_action(req_path):
    """Apply an allowlisted start/stop/restart (root-triggered, table-bounded).

    Validates unit AND action against the table above before touching systemd,
    so a forged request can never become `systemctl <anything> <anything>`.
    Verifies the unit actually reached the state that was asked for -- a
    systemctl exit code of 0 means 'the job was accepted', not 'the daemon came
    up', and a service that exits three seconds later would otherwise be
    reported as a success.
    """
    req = json.loads(Path(req_path).read_text())
    uid = req.get("id") or Path(req_path).stem
    st = Status(uid, req)
    try:
        os.remove(req_path)  # dequeue so the .path unit stops re-firing
    except OSError:
        pass

    unit = (req.get("unit") or "").strip()
    action = (req.get("action") or "").strip().lower()
    st.d["unit"] = unit
    st.d["action"] = action
    st.d["kind"] = "service"
    st.flush()

    # ---- hard guardrails (defence in depth; the web side validates too) ----
    if unit in _SVC_FORBIDDEN:
        st.step("validate unit", False,
                "%s is the privileged runner itself and is never controllable "
                "from the console" % unit)
        st.finish("failed", error="unit forbidden")
        return
    if not _SVC_UNIT_RE.match(unit) or unit not in _SERVICE_POLICY:
        st.step("validate unit", False, "%r is not an allowlisted unit" % unit)
        st.finish("failed", error="unit not allowed")
        return
    if action not in _SVC_ACTIONS or action not in _SERVICE_POLICY[unit]:
        st.step("validate action", False,
                "%r is not permitted on %s (allowed: %s)"
                % (action, unit, ", ".join(_SERVICE_POLICY[unit])))
        st.finish("failed", error="action not allowed")
        return
    if _svc_prop(unit, "LoadState") == "not-found":
        st.step("validate unit", False, "%s is not installed on this node" % unit)
        st.finish("failed", error="unit not installed")
        return
    st.step("validate", True, "%s %s (requested by %s)"
            % (action, unit, req.get("requested_by") or "?"))

    before = _svc_active(unit)
    st.step("state before", True, "%s is %s" % (unit, before))

    try:
        p = subprocess.run(["systemctl", action, unit],
                           capture_output=True, text=True, timeout=180)
        detail = (p.stderr or p.stdout or "").strip()[-400:]
        st.step("systemctl %s %s" % (action, unit), p.returncode == 0,
                detail or "accepted")
        if p.returncode != 0:
            raise RuntimeError("systemctl exited %s: %s" % (p.returncode, detail))

        # systemd returns as soon as the job is queued; give a restarted daemon
        # a moment to either settle or die before believing its state.
        time.sleep(2)
        after = _svc_active(unit)
        if action == "stop":
            reached = after not in ("active", "activating")
        else:
            reached = after in ("active", "activating")
        st.step("state after", reached, "%s is %s" % (unit, after))
        if not reached:
            raise RuntimeError("%s is %s after %s" % (unit, after, action))

        # ---- did the console survive it? ----
        if unit in _SVC_HEALTH_CRITICAL:
            ok = health_ok()
            st.step("app health check", ok,
                    "healthz 200" if ok else
                    "healthz did not answer 200 within %ds" % HEALTH_TIMEOUT)
            if not ok and unit == "postgresql.service":
                # A recycled cluster leaves the app holding dead pooled
                # connections. Bouncing the workers is the actual fix and it is
                # cheap; leaving it would hand the operator a 500 they did not
                # ask for and no obvious cause.
                subprocess.run(["systemctl", "restart", SERVICE], timeout=180)
                ok = health_ok()
                st.step("recycle app connection pool", ok,
                        "restarted %s after the database bounce" % SERVICE)
            if not ok:
                raise RuntimeError("the app is not answering after %s %s"
                                   % (action, unit))
            if unit == "nginx.service":
                fok = front_ok()
                st.step("TLS front check", fok,
                        "https://127.0.0.1/healthz 200" if fok else
                        "the front did not answer on :443")
                if not fok:
                    raise RuntimeError("nginx is running but not serving")

        st.finish("success", unit=unit, action=action,
                  state_before=before, state_after=after)
        return

    except Exception as e:  # noqa: BLE001
        st.step("ERROR", False, str(e))
        st.finish("failed", unit=unit, action=action, state_before=before,
                  state_after=_svc_active(unit), error=str(e))


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
            elif kind == "pip":
                pip_change(rp)
            elif kind == "package":
                package_change(rp)
            elif kind == "service":
                service_action(rp)
            else:
                process(rp)
        except Exception:
            try:
                os.remove(rp)  # never crash-loop on a malformed request
            except OSError:
                pass


if __name__ == "__main__":
    main()
