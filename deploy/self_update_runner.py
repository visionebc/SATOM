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

Scope: git app code + pip requirements + migrations. OS packages ONLY from
the curated ``_SYSPKG`` table (install, never remove) -- see syspkg_install.
"""
import glob
import json
import os
import re
import secrets
import socket
import stat
import subprocess
import sys
import time
import tempfile
import urllib.request
from datetime import datetime
from pathlib import Path

APP = Path(os.environ.get("FM_APP_DIR", "/opt/satom"))
REQ = APP / "data" / "update-requests"
STA = APP / "data" / "update-status"
VENV = APP / "venv" / "bin"
SERVICE = "satom.service"
SCHED = "satom-scheduler.service"
RECONCILER = "satom-reconciler.service"

# [SATOM-RUNNER-INPUT] The queue is written by the service account, so every
# request value that reaches a file name or a git command line is re-checked
# here, as root. UID_RE is a COPY of app/services/self_update.py's UID_RE
# ([SATOM-UID-SAFE]) -- copied, not imported: [SATOM-RUNNER-NO-APP-IMPORT].
UID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
# A file name the runner itself writes (never a path).
_FILE_NAME_RE = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,200}$")

# [SATOM-RELEASE-TRUST] A second, OPT-IN safeguard lives further down (see
# _release_trust / _resolve_release / _staged_deploy_dir): when a ROOT-OWNED
# release-signature anchor is installed, the systemd units root installs and
# the install-*.sh scripts root runs are taken from a root-only staging copy of
# the newest SIGNED release instead of the service-account-owned deploy/. An
# unsigned target whose deploy/ differs from that release still updates the app
# (it runs as the service account anyway) but the root-side refresh is HELD --
# a warning, not a failure, so HA keeps converging. With no anchor (today's
# default on every node) the behaviour is byte-for-byte unchanged.


def _valid_ref(value):
    return (isinstance(value, str) and bool(_REF_RE.fullmatch(value))
            and ".." not in value)


def _valid_target(value):
    return isinstance(value, str) and (bool(_SHA_RE.fullmatch(value))
                                       or _valid_ref(value))


def _log(msg):
    """One line to the journal (stderr of satom-updater.service)."""
    print("satom-updater: %s" % msg, file=sys.stderr, flush=True)


def _read_request(req_path):
    """The request JSON, read without following a link planted in the queue."""
    fd = os.open(str(req_path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r", encoding="utf-8") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise ValueError("%s is not a regular file" % req_path)
        return json.loads(fh.read())


def _open_dir_nofollow(dirpath):
    """O_DIRECTORY fd of ``dirpath``, never through a symlink below APP.

    Everything under APP belongs to the service account, so each component
    below APP is opened relative to its parent with O_NOFOLLOW (created when
    missing): a planted ``data/update-status -> /etc`` -- or ``data -> /`` --
    makes this fail instead of steering a root write. APP itself is trusted
    (its parent is root-owned). A directory outside APP (only in tests) gets
    the O_NOFOLLOW check on its last component.
    """
    dirpath = Path(dirpath)
    try:
        rel = dirpath.relative_to(APP)
        fd = os.open(str(APP), os.O_RDONLY | os.O_DIRECTORY)
    except ValueError:
        dirpath.parent.mkdir(parents=True, exist_ok=True)
        rel = Path(dirpath.name)
        fd = os.open(str(dirpath.parent), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in rel.parts:
            if part in (".", ".."):
                raise ValueError("refusing a '%s' path component" % part)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            try:
                nfd = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, 0o755, dir_fd=fd)
                nfd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _write_nofollow(dirpath, name, text):
    """[SATOM-RUNNER-NOFOLLOW] Write ``dirpath/name`` as root, safely.

    Every file the runner writes sits in a directory the service account
    owns. A plain ``write_text`` follows whatever that account left at the
    name (``x.json -> /etc/profile.d/zz.sh``) -- a root write of content the
    request influences. Instead: the directory is reached without links, the
    content goes to a fresh O_EXCL|O_NOFOLLOW temp file, and an atomic rename
    replaces the NAME (a link at the name is replaced, never followed; a hard
    link's other names are untouched). The file is handed to the service
    account, as the in-place write used to leave it.
    """
    if not isinstance(name, str) or not _FILE_NAME_RE.fullmatch(name):
        raise ValueError("refusing to write a file named %r" % (name,))
    dfd = _open_dir_nofollow(dirpath)
    tmp = ".%s.%s.tmp" % (name, secrets.token_hex(6))
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o644, dir_fd=dfd)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                os.fchmod(fh.fileno(), 0o644)
                ids = _app_ids()
                if ids:
                    os.fchown(fh.fileno(), ids[0], ids[1])
                fh.write(text)
            os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
            raise
    finally:
        os.close(dfd)


def _app_ids():
    """(uid, gid) of the service account when running as root, else None."""
    if not APP_USER or APP_USER == "root" or os.geteuid() != 0:
        return None
    try:
        import pwd
        pw = pwd.getpwnam(APP_USER)
        return pw.pw_uid, pw.pw_gid
    except KeyError:
        return None


def _link_below(base, rel):
    """True when ``base/rel`` cannot be used as root: an absolute or ``..``
    path, or an existing component (below ``base``) that is a symlink."""
    rel = Path(rel)
    if rel.is_absolute() or ".." in rel.parts:
        return True
    cur = Path(base)
    for part in rel.parts:
        cur = cur / part
        try:
            if stat.S_ISLNK(os.lstat(cur).st_mode):
                return True
        except FileNotFoundError:
            return False
        except OSError:
            return True
    return False


def restart_reconciler():
    """Restart the reconciler loop IF it is running (``try-restart``).

    It is a long-running process that imports the app's modules once, so a
    code update that does not restart it leaves it running the previous
    release indefinitely. On 2026-10-11 satom-node-2's reconciler had been up
    since 11:00Z while its tree was at a commit from 23:55Z. Restarting it in
    the same places as the scheduler keeps "the code on disk" and "the code
    that reconciles" the same thing. ``try-restart`` leaves a stopped or
    disabled reconciler alone. Never fails the update.
    """
    try:
        subprocess.run(["systemctl", "try-restart", RECONCILER], timeout=60)
    except Exception:  # noqa: BLE001
        pass


def _app_user_from_tree():
    """Owner of the app tree = service account. Single source of truth: an env
    var (FM_APP_USER) gets forgotten when a new node is installed, the
    directory's owner does not. Returns 'root' on a non-deprivileged install."""
    try:
        import pwd
        return pwd.getpwuid(APP.stat().st_uid).pw_name
    except Exception:
        return "root"


APP_USER = os.environ.get("FM_APP_USER") or _app_user_from_tree()
HEALTH_URL = os.environ.get("FM_HEALTH_URL", "http://127.0.0.1:8000/healthz")
HEALTH_TIMEOUT = int(os.environ.get("FM_HEALTH_TIMEOUT", "90"))


def _unit_templates():
    """Every unit template deploy/ ships, READ FROM THE DIRECTORY.

    This used to be a hand-written list of six names while deploy/ shipped
    ten: satom-alerts.{service,timer} and satom-cert-renew.{service,timer} were
    NEVER refreshed, so the installed copy kept declaring User=fortinet — an
    account that no longer exists on the node. They only started because the
    drop-in masked it, and nothing replicates that drop-in: a
    `systemctl revert` (or a node restored from an older image) turns the
    certificate renewal into status=217/USER, silently, which is exactly what
    the cert.renew_failed signal exists to prevent.

    A hand-written list IS a copy of the directory listing, and copies rot:
    deriving it is the only way the next unit added to deploy/ does not repeat
    this without anyone noticing.

    CAREFUL — refreshing a unit's FILE is NOT arming it. `systemctl enable` is
    never called here, so the node's enabled/disabled state is kept exactly as
    it is. And only what deploy/ ships is included: that is why
    satom-ha-datasync.* (written inline by the installer, and only in cluster
    mode) and satom-git-publish.* (RETIRED on 2026-08-05) are left out.
    """
    return _units_in(APP / "deploy")


def _units_in(deploy_dir):
    names = set()
    for pat in ("*.service", "*.timer", "*.path"):
        try:
            names.update(p.name for p in Path(deploy_dir).glob(pat))
        except OSError:
            pass
    return tuple(sorted(names))


UNIT_FILES = _unit_templates()

# Units that may exist INSTALLED on a node but are not deploy/ templates: the
# installer writes satom-ha-datasync.{service,timer} inline (only in cluster
# mode) and satom-git-publish.* was retired on 2026-08-05. They are neither
# distributed nor armed from here; they are listed only so the service-account
# drop-in keeps covering them IF they are installed — without it, a legacy
# unit that still declares a non-existent user dies with status=217/USER.
LEGACY_NONROOT_UNITS = (
    "satom-ha-datasync.service",
    "satom-git-publish.service",
)

# Units that MUST run as the service account. satom-updater.{service,path} is
# deliberately left out: it IS the privileged runner. Derived for the same
# reason as UNIT_FILES: the templates declare User=root and every update
# re-copies them, so a new template forgotten here would go back to root on
# the next update without anything warning about it.
NONROOT_UNITS = tuple(sorted(
    ({u for u in UNIT_FILES if u.endswith(".service")}
     - {"satom-updater.service"})
    | set(LEGACY_NONROOT_UNITS)))

UNIT_DROPIN = """# Generated by SATOM (installer / migrate-deprivilege.sh / self_update_runner).
# Lives in a drop-in rather than in the unit because the deploy/ templates
# declare User=root and every update re-copies them: the drop-in survives that.
# Do NOT edit by hand.
[Service]
User=%s
Group=%s
"""


def _nonroot_units(names):
    return tuple(sorted(({u for u in names if u.endswith(".service")}
                         - {"satom-updater.service"}) | set(LEGACY_NONROOT_UNITS)))


def enforce_unit_user(user, names=None):
    """Pin User=/Group= via drop-in on the unprivileged units.

    ``names``: the unit list of the deploy/ actually being installed. Without
    it the import-time list is used, which predates the update's checkout.
    """
    if not user or user == "root":
        return
    for unit in (NONROOT_UNITS if names is None else _nonroot_units(names)):
        p = SYSTEMD_DIR / unit
        if not p.exists():
            continue
        d = Path(str(p) + ".d")
        try:
            d.mkdir(parents=True, exist_ok=True)
            (d / "10-app-user.conf").write_text(UNIT_DROPIN % (user, user))
        except OSError:
            pass


SYSTEMD_DIR = Path("/etc/systemd/system")
# Units this runner has armed itself, so a late arm happens at most once and an
# operator who disables one afterwards keeps it disabled. Root-owned, outside
# the app tree.
ARMED_REGISTRY = Path("/var/lib/satom-runner/armed-units.json")
# Units that reached nodes INSTALLED BUT NOT ARMED: introduced while the
# previous runner (which never enabled anything) was still the one applying
# updates, so the current runner saw them as "already installed". Armed once.
_LATE_ARM = ("satom-scripts.path",)


def _armed_registry():
    try:
        data = json.loads(ARMED_REGISTRY.read_text())
        return set(data) if isinstance(data, list) else set()
    except (OSError, ValueError):
        return set()


def _remember_armed(units):
    if not units:
        return
    try:
        ARMED_REGISTRY.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(ARMED_REGISTRY.parent), 0o700)
        ARMED_REGISTRY.write_text(json.dumps(sorted(_armed_registry() | set(units))))
    except OSError:
        pass


def refresh_units(deploy_dir, st=None):
    """Copy every unit template of ``deploy_dir``, pin the service account,
    reload systemd, and ARM what arrived for the first time.

    The list is read from ``deploy_dir`` NOW, not from the import-time
    ``UNIT_FILES``: this process imported before the update's checkout, so a
    unit introduced by this very update was otherwise skipped until the next
    one, and its .service missed the User= drop-in.

    Arming: a ``.path`` or ``.timer`` with no installed copy before this call
    is ``enable --now``-ed once -- exactly what the installer does for every
    one of them. A unit that was already installed keeps the enabled state the
    operator gave it; this never enables or disables anything else.
    """
    names = _units_in(deploy_dir)
    fresh = []
    for unit in names:
        src = Path(deploy_dir) / unit
        if not src.exists():
            continue
        dst = SYSTEMD_DIR / unit
        is_new = not dst.exists()
        subprocess.run(["cp", str(src), str(dst)])
        if is_new and unit.endswith((".path", ".timer")):
            fresh.append(unit)
    enforce_unit_user(APP_USER, names)
    subprocess.run(["systemctl", "daemon-reload"])
    done = _armed_registry()
    late = [u for u in _LATE_ARM if u in names and u not in fresh and u not in done
            and (SYSTEMD_DIR / u).exists()]
    armed = []
    for unit in fresh + late:
        p = subprocess.run(["systemctl", "enable", "--now", unit],
                           capture_output=True, text=True, timeout=60)
        if p.returncode == 0:
            armed.append(unit)
        if st is not None:
            st.step("arm %s unit %s" % ("new" if unit in fresh else "late", unit),
                    p.returncode == 0, (p.stderr or p.stdout or "enabled").strip()[-300:])
    _remember_armed(armed)
    return names, fresh + late


# ── [SATOM-RELEASE-TRUST] opt-in release-signature enforcement ─────────────
# The update paths below copy systemd units out of deploy/ and run
# deploy/install-*.sh AS ROOT. deploy/ lives in the app tree the SERVICE
# ACCOUNT owns, so without a trust anchor that account can commit a malicious
# unit/script, point an update's target at that commit, and have root run it.
# Enforcement is OPT-IN and FAIL-SAFE: with no anchor the paths behave exactly
# as before; installing a root-owned anchor switches it on. The resolution
# itself (root-only mirror, signature walk, staging) lives in release_trust.py,
# shared with the root operator CLI -- see its docstring for why root never
# runs git inside the service account's repository.
TRUST_ANCHOR = Path("/etc/satom/release-trust.allowed_signers")
_TRUST_PUB_FALLBACK = Path("/etc/satom/release-trust.pub")
RELEASE_MIRROR = Path("/var/lib/satom-release/mirror.git")


def _release_trust():
    """The root-owned release trust anchor, or None when enforcement is OFF.

    None is the DEFAULT on every current node (no anchor installed) and means
    the update behaves exactly as before. An anchor only counts when it is a
    regular file, owned by root (st_uid == 0) and non-empty: a half-written or
    non-root file is ignored rather than allowed to WEAKEN the check into
    passing. The ``.allowed_signers`` (ssh allowed-signers) form is preferred;
    ``.pub`` (a single key) is accepted as a fallback -- whichever exists."""
    for p in (TRUST_ANCHOR, _TRUST_PUB_FALLBACK):
        try:
            ss = os.stat(p)
        except OSError:
            continue
        if stat.S_ISREG(ss.st_mode) and ss.st_uid == 0 and ss.st_size > 0:
            return p
    return None


def _root_only_stage(prefix="satom-rel-"):
    """A fresh 0700 directory root owns, under /run (tmpfs) when present else
    /var/lib. The caller removes it once it is done with the staged copy."""
    base = (Path("/run") if os.path.isdir("/run") and os.access("/run", os.W_OK)
            else Path(tempfile.gettempdir()) if os.geteuid() != 0
            else Path("/var/lib"))
    d = Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))
    os.chmod(d, 0o700)
    return d


def _load_release_trust():
    """release_trust.py from the ROOT-OWNED place this runner lives in, or None.

    Same discipline as _load_update_package(): a sibling of this file (the
    root-owned copy install-runner.sh installs), never APP/deploy. The second
    candidate only exists in a source checkout (the runner run from deploy/,
    where the module lives in the CLI package) -- i.e. the tests."""
    import importlib.util
    here = Path(__file__).resolve().parent
    for path in (here / "release_trust.py", here / "satom_cli" / "release_trust.py"):
        if path.is_file():
            spec = importlib.util.spec_from_file_location("satom_release_trust", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


def _resolve_release(target_sha, trust, st):
    """Where root-side content comes from for ``target_sha``; records the step.

    Returns ``{"mode": "signed"|"pinned"|"held", "signed": sha|None, ...}``.
    Never raises and never refuses the update: anything that prevents a trust
    decision (helper missing, mirror unusable, fetch failed) HOLDS the
    root-side refresh -- the units and root-owned copies already installed keep
    running -- because a hardening must not stop HA from converging."""
    def _held(detail):
        st.step("root-side refresh held", True, "WARNING: " + detail, warn=True)
        return {"mode": "held", "signed": None, "detail": detail}

    if not isinstance(target_sha, str) or not _SHA_RE.fullmatch(target_sha) \
            or len(target_sha) != 40:
        return _held("cannot resolve the target commit (%r); root-side refresh "
                     "held" % (target_sha,))
    rt = _load_release_trust()
    if rt is None:
        return _held("release_trust.py is not installed next to the runner "
                     "(%s); root-side refresh held -- run 'satom execute "
                     "reinstall runner'" % Path(__file__).resolve().parent)
    st.begin("verify release signature")
    try:
        res = rt.resolve(APP, target_sha, trust, app_user=APP_USER,
                         mirror=RELEASE_MIRROR)
    except Exception as exc:  # noqa: BLE001 -- fail safe: hold, never escalate
        return _held("release signature could not be checked (%s); root-side "
                     "refresh held" % str(exc)[:300])
    if res["mode"] == "held":
        return _held(res["detail"])
    st.step("verify release signature", True, res["detail"])
    return res


def _staged_deploy_dir(verified_sha):
    """Root-only staging dir holding deploy/ at ``verified_sha``, or None when
    enforcement is OFF (the caller then uses APP/deploy unchanged).

    ``git archive <sha> deploy | tar -x`` from the ROOT-ONLY release mirror
    into a 0700 dir root owns: the bytes come from objects whose ids root
    recomputed, at the verified commit -- never from the service-account-owned
    worktree or object store, and never through that repository's config."""
    if _release_trust() is None:
        return None
    rt = _load_release_trust()
    if rt is None:
        raise RuntimeError("release_trust.py is not installed next to the runner")
    stage = _root_only_stage()
    try:
        rt.stage_deploy(verified_sha, stage, mirror=RELEASE_MIRROR)
    except BaseException:
        import shutil as _sh
        _sh.rmtree(stage, ignore_errors=True)
        raise
    return stage


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


#: Child program for :func:`db_smoke_ok`. Reads the app's own URI from .env
#: (never passed on argv or in the environment) and runs SELECT 1 through
#: SQLAlchemy, i.e. through the same driver the app will load.
_DB_SMOKE = r"""
import re, sys
uri = ""
for line in open(".env", encoding="utf-8"):
    if line.startswith("SQLALCHEMY_DATABASE_URI="):
        uri = line.split("=", 1)[1].strip().strip('"').strip("'")
if not uri:
    sys.exit("no SQLALCHEMY_DATABASE_URI in .env")
import sqlalchemy as sa
eng = sa.create_engine(uri, pool_pre_ping=False)
with eng.connect() as c:
    assert c.execute(sa.text("SELECT 1")).scalar() == 1
eng.dispose()
"""


def db_smoke_ok():
    """The new code can actually TALK to Postgres: one connection, SELECT 1.

    An import smoke cannot see a driver that imports and then breaks on the
    first connect. That is not hypothetical: psycopg 3.3.6 with
    psycopg-binary 3.3.4 imported fine and every connection raised TypeError
    (wait_c() got an unexpected keyword 'timeout'), which took both nodes
    down. Read-only, so it is safe on the standby too."""
    try:
        r = run([str(VENV / "python"), "-c", _DB_SMOKE],
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


def compile_catalogues(st, label="pybabel compile (language catalogues)"):
    """Rebuild the compiled language catalogues from the .po now in the tree.

    The .mo files are DERIVED and travel neither in the repository nor in an
    update package (whose app.tar.gz is a ``git archive``), so EVERY path that
    replaces the code tree -- a git update, an offline package, and the
    rollback of either -- has to run this, or the node keeps serving the
    catalogue of another revision: new strings fall back to English, and a
    msgid that changed keeps the old translation.

    Never aborts: an old catalogue is worse than a new one, but both beat a
    reverted update. A failure is recorded as a failed step and the caller
    carries on.
    """
    st.begin(label)
    try:
        pb = run([str(VENV / "pybabel"), "compile", "-d",
                  str(APP / "app" / "translations")], timeout=300, user=APP_USER)
        st.step(label, pb.returncode == 0, pb.stderr)
    except Exception as exc:  # noqa: BLE001 -- best effort by design
        st.step(label, False, str(exc)[:300])


def import_shipped_api_pack(st):
    """Import the API library pack the new release carries (api-packs/).

    Before this, an update brought the new pack onto the disk and left the
    library on the old one until someone pressed Import -- which nothing
    prompted them to do. The import only ADDS (items this node measured or
    already holds are skipped), so repeating it on every update is harmless.

    Primary only (the caller checks): a standby's Postgres is read-only and its
    library arrives by replication. NON-FATAL by design: the code update has
    already passed its health gate, and API knowledge missing for a while is
    not a reason to roll a healthy node back. ``SATOM_API_PACK_AUTO=0`` turns
    it off. Runs through the operator CLI, which imports as the service
    account every shipped pack this node has not imported yet: the newest
    API pack (schema /2 lane ``api_pack``, or a 2.x release pack), then the
    newest knowledge pack (``satom-apipack-kb-*``, built by satom-harvester).
    A /2 pack is verified with the lane keys the NEW code tree ships
    (``deploy/pack-keys/<lane>/``), so this step needs no key installed
    beforehand and has no ordering dependency on the trust store; a 2.x pack
    still verifies with the update trust store.
    """
    if os.environ.get("SATOM_API_PACK_AUTO", "1").strip() == "0":
        st.step("import shipped API pack", True, "skipped (SATOM_API_PACK_AUTO=0)")
        return
    if not any((APP / "api-packs").glob("satom-apipack-*.tar.gz")):
        st.step("import shipped API pack", True, "skipped (this release ships no pack)")
        return
    cli = "/usr/local/sbin/satom"
    st.begin("import shipped API pack")
    try:
        p = subprocess.run([cli, "execute", "apipack", "import", "shipped", "--yes"],
                           capture_output=True, text=True, timeout=1800)
        out = (p.stdout or p.stderr or "").strip()
        ok = p.returncode == 0
        detail = out[-300:] if ok else (
            "%s -- the update itself is fine; retry with: "
            "sudo %s execute apipack import shipped --yes" % (out[-250:], cli))
    except Exception as exc:  # noqa: BLE001
        ok, detail = False, "%s -- retry with: sudo %s execute apipack import shipped --yes" % (
            str(exc)[:200], cli)
    st.step("import shipped API pack", ok, detail)


def tighten_data_dir(st):
    """[SATOM-DATA-PERMS] Close data/ to every account but the service account.

    Runs the operator CLI's ``execute repair data --yes`` -- the same code an
    operator runs by hand, from the root-owned copy refreshed just before this
    call -- so a node installed before the fix converges on its next update
    instead of waiting for someone to read `satom diagnose data`. It only
    narrows modes (data/ 0750, the vault and bundle trees 0700/0600) and is a
    no-op on a clean node. NON-FATAL: an exposed directory is a finding, not a
    reason to roll a healthy update back.
    """
    cli = "/usr/local/sbin/satom"
    st.begin("data/ permissions")
    try:
        p = subprocess.run([cli, "execute", "repair", "data", "--yes"],
                           capture_output=True, text=True, timeout=300)
        out = (p.stdout or p.stderr or "").strip()
        ok = p.returncode == 0
        detail = out[-300:] if ok else (
            "%s -- the update itself is fine; retry with: "
            "sudo %s execute repair data --yes" % (out[-250:], cli))
    except Exception as exc:  # noqa: BLE001
        ok, detail = False, "%s -- retry with: sudo %s execute repair data --yes" % (
            str(exc)[:200], cli)
    st.step("data/ permissions", ok, detail)


def route_audit_ok():
    """Every ``url_for()`` endpoint written in a template exists in the url_map.

    Neither existing gate can see this class of failure: ``import app`` only
    proves the modules parse, and ``/healthz`` renders no template. A template
    naming an endpoint that is not registered raises BuildError -- HTTP 500 --
    at request time, on the page, for a user.

    Returns (status, detail) where status is "ok", "missing" or "unmeasured".
    "unmeasured" is deliberately NOT "ok": a check that could not run has found
    nothing, which is not the same as having found nothing wrong.
    """
    try:
        r = run([str(VENV / "python"), "-m", "app.services.route_audit"],
                timeout=180, user=APP_USER, cwd=str(APP))
        out = (r.stdout or "")
        detail = (out + (r.stderr or "")).strip()
        # Read the OUTPUT, not just the return code. A non-zero rc from a
        # failure to even start the check (runuser denied, venv missing,
        # import error) is indistinguishable from a real finding by rc alone,
        # and reporting 'the templates are broken' for 'the check could not
        # run' would roll a healthy update back. Only the audit's own markers
        # promote a result out of "unmeasured".
        if r.returncode == 0 and out.startswith("templates="):
            return "ok", detail
        if r.returncode == 1 and "MISSING " in out:
            return "missing", detail
        return "unmeasured", detail
    except Exception as exc:  # noqa: BLE001
        return "unmeasured", str(exc)


def restart_and_validate(st, is_standby, app_was_active, label):
    """Restart what was ACTUALLY running, then prove the new code serves.

    The standby branch used to be 'never restart the app -- it cannot run on a
    read-only replica'. That premise was false on a standby that serves
    traffic: on 2026-08-17 satom-node-2 was enabled, active and published, so
    the code on disk advanced while the workers kept the previous url_map.
    Every authenticated page returned 500 for ~15 hours and the update still
    reported SUCCESS -- because ``import app`` runs in a FRESH interpreter (it
    is green precisely when the running workers are stale) and ``/healthz``
    renders no template (blind to a BuildError by construction).

    So: ask systemd what state the node was in, restore that state, and
    validate with the strongest check that state allows.
    """
    st.begin("restart services")
    subprocess.run(["systemctl", "restart", SCHED], timeout=60)
    restart_reconciler()
    if app_was_active:
        subprocess.run(["systemctl", "restart", SERVICE], timeout=120)
        st.step("restart services", True, "%s + scheduler%s"
                % (SERVICE, " (standby serving traffic)" if is_standby else ""))
        st.begin("health check")
        if not health_ok():
            raise RuntimeError("health check did not return 200 within %ds"
                               % HEALTH_TIMEOUT)
        st.step("health check", True, "200 OK on %s" % label)
    else:
        ok, detail = import_smoke_ok()
        if not ok:
            raise RuntimeError("import smoke failed: %s" % detail[:300])
        st.step("restart services", True,
                "scheduler only (%s was not running before the update)" % SERVICE)
        st.step("import smoke", True, "new code imports on %s" % label)

    st.begin("route audit")
    status, detail = route_audit_ok()
    if status == "missing":
        raise RuntimeError("route audit: template references an endpoint that "
                           "does not exist: %s" % detail[:400])
    st.step("route audit", status == "ok", detail[:300] if detail else status)


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
        # The id becomes a file name root writes. Refusing here (ValueError,
        # main() drops the request) covers every handler, present and future.
        if not isinstance(uid, str) or not UID_RE.fullmatch(uid):
            raise ValueError("refusing request id %r" % (uid,))
        self.name = uid + ".json"
        self.p = STA / self.name
        self.d = {
            "id": uid, "state": "running", "steps": [],
            "target": req.get("target"), "branch": req.get("branch"),
            "requested_by": req.get("requested_by"),
            "node": req.get("node"), "role": req.get("role"),
            "origin": req.get("origin", "manual"),
            "started_at": now(), "updated_at": now(),
        }
        self.flush()

    def begin(self, name):
        """Announce the step that is RUNNING now, before it ends.

        Steps are only appended when they finish, and the slow ones (database
        backup, offline pip install, migrations, restart) take minutes. Without
        this the console and the CLI showed nothing new for that whole time and
        an operator could not tell a working update from a hung one. The next
        step() or finish() clears it.
        """
        self.d["current"] = {"name": name, "since": now()}
        self.d["updated_at"] = now()
        self.flush()

    def step(self, name, ok=True, detail="", warn=False):
        self.d.pop("current", None)
        rec = {"name": name, "ok": bool(ok),
               "detail": (detail or "").strip()[-500:], "at": now()}
        if warn:
            # A NON-FATAL condition the operator must see (e.g. the root-side
            # refresh held by [SATOM-RELEASE-TRUST]). ok stays True so nothing
            # that reads "ok" treats the update as failed or backs off.
            rec["warn"] = True
            self.d.setdefault("warnings", []).append(name)
        self.d["steps"].append(rec)
        self.d["updated_at"] = now()
        self.flush()

    def finish(self, state, **extra):
        self.d.pop("current", None)
        self.d["state"] = state
        self.d.update(extra)
        self.d["updated_at"] = now()
        self.flush()

    def flush(self):
        _write_nofollow(STA, self.name, json.dumps(self.d, indent=2))


def process(req_path):
    req = _read_request(req_path)
    uid = req["id"]
    st = Status(uid, req)
    # Dequeue immediately so the .path unit does not re-trigger us in a loop.
    try:
        os.remove(req_path)
    except OSError:
        pass

    # Both reach git as arguments: a leading '-' is an option, '..' a range.
    branch = req.get("branch", "main")
    target = req.get("target") or ("origin/%s" % branch)
    if not _valid_ref(branch) or not _valid_target(target):
        bad = "refusing branch %r / target %r" % (branch, target)
        st.step("validate request", False, bad)
        st.finish("failed", error=bad)
        return

    # The package index for the dependency step (Settings -> General -> Update
    # sources), checked before anything is touched.
    try:
        pip_env, where, secret = _pip_index_env(req)
    except ValueError as e:
        st.step("package index", False, str(e))
        st.finish("failed", error="bad package index")
        return
    if req.get("do_pip", True):
        problem = req.get("index_problem")
        note = problem or req.get("index_note")
        st.step("package index", True,
                str(note)[:300] if isinstance(note, str) and note else where,
                warn=isinstance(problem, str) and bool(problem))

    snapshot = git("rev-parse", "HEAD").stdout.strip()
    st.step("snapshot current commit", True, snapshot[:12])

    # HA role: explicit request wins; else detect from the local DB. A standby
    # updates code-only (no migration, no app restart, import-smoke validation).
    role = req.get("role") or ("standby" if pg_in_recovery() else "primary")
    is_standby = (role == "standby")
    # Snapshot what the node is ACTUALLY doing, before anything is touched.
    # The restart step restores this state instead of the state the role
    # implies -- see restart_and_validate().
    app_was_active = _svc_active(SERVICE) == "active"
    st.step("ha role", True, role)

    # PRE-FLIGHT: health baseline before we touch anything (primary only — the
    # standby never restarts the app, so there is no health delta to catch).
    if not is_standby:
        pok, pdetail = flight("preflight", "upgrade-%s" % snapshot[:12])
        st.step("preflight (before)", pok, pdetail)

    try:
        st.begin("git fetch origin %s" % branch)
        f = git("fetch", "origin", branch)
        st.step("git fetch origin %s" % branch, f.returncode == 0, f.stderr)
        if f.returncode != 0:
            raise RuntimeError("git fetch failed")

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

        st.begin("checkout %s" % target[:20])
        r = git("reset", "--hard", target)
        st.step("checkout %s" % target[:20], r.returncode == 0, r.stderr)
        if r.returncode != 0:
            raise RuntimeError("checkout/reset failed")
        # keep the local branch pointer on the branch tip when we tracked it
        git("checkout", "-B", branch, target)

        if req.get("do_pip", True):
            st.begin("pip install -r requirements.txt")
            p = run([str(VENV / "pip"), "install", "-q", "-r",
                     str(APP / "requirements.txt")], timeout=900, user=APP_USER,
                    env=pip_env)
            st.step("pip install -r requirements.txt", p.returncode == 0,
                    _redact(p.stderr, secret))
            if p.returncode != 0:
                raise RuntimeError("pip install failed")

        # The .mo files are DERIVED and no longer travel in the repo, so an
        # update that brings new .po files leaves the interface in English
        # until they are recompiled. Outside the do_pip block on purpose: a
        # code-only update also brings catalogues.
        compile_catalogues(st)

        # Migrations run on the PRIMARY only; on a standby the schema arrives
        # via streaming replication, and `flask db upgrade` would fail on the
        # read-only replica.
        if req.get("do_migrate", True) and not is_standby:
            env = dict(os.environ, FLASK_APP="wsgi.py")
            st.begin("flask db upgrade")
            m = run([str(VENV / "flask"), "db", "upgrade"], timeout=600,
                    user=APP_USER, cwd=str(APP), env=env)
            # [SATOM-ALEMBIC-STAMP] Fatal. This step used to be best-effort on
            # the theory that boot-time create_all()/_ensure_columns() is the
            # real schema step -- but those only ADD. A migration that
            # transforms data has nowhere else to run, and on every installed
            # node (no alembic_version) the first revision died, the error was
            # logged as a warning, and the update finished green having
            # migrated nothing. Every migration is idempotent now
            # (app.migration_guard), so a failure here is a real one.
            st.step("flask db upgrade", m.returncode == 0,
                    (m.stderr or m.stdout))
            if m.returncode != 0:
                raise RuntimeError(MIGRATION_FAILED)
        elif is_standby:
            st.step("flask db upgrade", True, "skipped (standby; schema via replication)")

        # Refresh unit files and re-run the installers. [SATOM-RELEASE-TRUST]
        # By default (no root trust anchor) deploy_dir is APP/deploy and this is
        # byte-for-byte the historical path. With an anchor present, deploy/ is
        # STAGED into a root-only dir from the newest SIGNED release (the target
        # itself, or its signed ancestor when deploy/ is byte-identical), so the
        # service account cannot choose a unit or an install-*.sh root runs.
        # When deploy/ has unsigned changes the app update above stands and
        # only this root-side refresh is HELD (a warning, not a failure).
        trust = _release_trust()
        stage_root = None
        hold_root_side = False
        if trust is None:
            st.step("release signature enforcement", True,
                    "OFF (no root trust anchor at %s)" % TRUST_ANCHOR)
            deploy_dir = APP / "deploy"
            script_env = None
        else:
            target_sha = git("rev-parse", "HEAD").stdout.strip()
            rel = _resolve_release(target_sha, trust, st)
            deploy_dir = None
            script_env = None
            if rel["mode"] != "held":
                try:
                    stage_root = _staged_deploy_dir(rel["signed"])
                except Exception as exc:  # noqa: BLE001 -- fail safe: hold
                    stage_root = None
                    st.step("root-side refresh held", True,
                            "WARNING: staging signed release %s failed (%s); "
                            "root-side refresh held"
                            % (rel["signed"][:12], str(exc)[:200]), warn=True)
                if stage_root is not None:
                    deploy_dir = stage_root / "deploy"
                    # The install scripts read FM_APP_DIR to aim their drop-ins
                    # at the real app, and SATOM_DEPLOY_SRC to take what they
                    # install from the STAGED copy, never from APP/deploy.
                    script_env = dict(os.environ, FM_APP_DIR=str(APP),
                                      SATOM_DEPLOY_SRC=str(deploy_dir))
                    st.step("stage verified release", True,
                            "%s from %s" % (deploy_dir, rel["signed"][:12]))
            hold_root_side = deploy_dir is None
            st.d["release_trust"] = rel["mode"] if not hold_root_side else "held"
        try:
            # Refresh unit files (they may have changed in the update) and pin
            # the service account AGAIN: the deploy/ templates declare
            # User=root, so the copy would downgrade the privilege model on
            # every update were it not for the drop-in. refresh_units also
            # arms a .path/.timer this update introduces.
            if hold_root_side:
                enforce_unit_user(APP_USER)
                subprocess.run(["systemctl", "daemon-reload"])
            else:
                refresh_units(deploy_dir, st)
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
                                         "update runner + /usr/local/sbin helpers"),
                                        ("install-metrics-store.sh",
                                         "metrics store"),
                                        # [SATOM-CONSOLE-RO-ROLE] primary only;
                                        # skips itself on a standby.
                                        ("install-console-role.sh",
                                         "database console role")):
                    if hold_root_side:
                        break
                    _p = deploy_dir / _script
                    if _p.exists():
                        st.begin("refresh %s" % _label)
                        cr = subprocess.run(["bash", str(_p)], capture_output=True,
                                            text=True, timeout=180, env=script_env)
                        st.step("refresh %s" % _label, cr.returncode == 0,
                                (cr.stdout or cr.stderr or "").strip()[:200])
            except Exception as exc:  # noqa: BLE001
                # Never fail an update because the console tool did not refresh.
                st.step("refresh operator CLI", False, str(exc)[:200])
        finally:
            if stage_root is not None:
                import shutil as _sh
                _sh.rmtree(stage_root, ignore_errors=True)
        # After the CLI refresh: the verb it runs ships with this release.
        tighten_data_dir(st)

        new = git("rev-parse", "HEAD").stdout.strip()
        restart_and_validate(st, is_standby, app_was_active,
                             "revision %s" % new[:12])

        if is_standby:
            # Unlock the primary: write the validated marker into the PRIMARY's
            # read-write DB (our own replica is read-only). Best-effort — a failed
            # marker write doesn't fail the standby update, but it IS the seguro.
            mok, mdetail = mark_validated_on_primary(new, req.get("node") or socket.gethostname())
            st.step("mark validated on primary", mok,
                    "primary update unlocked for %s" % new[:12] if mok else mdetail[:200])
            st.finish("success", result_sha=new, rolled_back=False, standby=True,
                      validated_on_primary=mok)
            return
        import_shipped_api_pack(st)
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
            st.begin("rollback to %s" % snapshot[:12])
            git("reset", "--hard", snapshot)
            if req.get("do_pip", True):
                run([str(VENV / "pip"), "install", "-q", "-r",
                     str(APP / "requirements.txt")], timeout=900, user=APP_USER,
                    env=pip_env)
            # The update already compiled the NEW .po; put back the catalogue
            # of the code that runs again.
            compile_catalogues(st, "pybabel compile (rolled-back catalogues)")
            subprocess.run(["systemctl", "restart", SCHED], timeout=60)
            restart_reconciler()
            if not app_was_active:
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


def _pip_install(spec, env=None):
    """pip install a single pinned spec (pkg==ver) as the app user. ``env``
    (from :func:`_pip_index_env`) points pip at the configured index."""
    return run([str(VENV / "pip"), "install", "-q", spec],
               timeout=900, user=APP_USER, env=env)


#: A package index the request may name: https, a host, an optional port and a
#: path. No userinfo (credentials arrive in their own fields), no query, no
#: whitespace -- this value ends up in pip's environment.
_INDEX_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%+/-]*)?$")
_CRED_BAD = re.compile(r"[\x00-\x1f\x7f]")


def _pip_index_env(req):
    """``(env, where, secret)`` for a pip change.

    No ``index_url`` in the request: ``(None, "pip default ...", "")`` -- pip uses
    its own configuration, as before. Otherwise the index (Settings -> General ->
    Update sources) goes to pip as ``PIP_INDEX_URL``, with the user and token
    percent-encoded into it. Through the ENVIRONMENT, never argv: a process's
    command line is readable by every local user, its environment only by its
    owner and root. ``where`` names the index without the credentials, for the
    status log; ``secret`` is what :func:`_redact` must remove from any output.
    Raises ``ValueError`` on anything malformed: a request the web side did not
    validate is refused here, not handed to pip.
    """
    from urllib.parse import quote
    url = (req.get("index_url") or "").strip()
    if not url:
        return None, "pip default (pypi.org unless pip.conf names another index)", ""
    if not _INDEX_URL_RE.match(url) or len(url) > 500:
        raise ValueError("refusing package index URL %r" % url)
    user = req.get("index_user") or ""
    token = req.get("index_token") or ""
    if not isinstance(user, str) or not isinstance(token, str):
        raise ValueError("refusing malformed index credentials")
    if user or token:
        if (not user or not token or ":" in user or len(user) > 128
                or len(token) > 1024 or _CRED_BAD.search(user + token)):
            raise ValueError("refusing malformed index credentials")
        full = "https://%s:%s@%s" % (quote(user, safe=""), quote(token, safe=""),
                                     url[len("https://"):])
        where = "%s (as %s)" % (url, user)
    else:
        full, where = url, url
    env = dict(os.environ)
    env["PIP_INDEX_URL"] = full
    return env, where, token


def _redact(text, secret):
    """``text`` with the token (raw and percent-encoded) masked."""
    if not text or not secret:
        return text
    from urllib.parse import quote
    for s in {secret, quote(secret, safe="")}:
        if s:
            text = text.replace(s, "****")
    return text


def _record_lib_version(pkg, previous, current, action, by):
    """Persist the per-node rollback point for pkg so the card can offer a
    'Rollback to <previous>' button. One file per package under
    data/lib-versions/ (per-node, because the venv is per-node)."""
    if not isinstance(pkg, str) or not _PKG_RE.fullmatch(pkg):
        raise ValueError("refusing package name %r" % (pkg,))
    _write_nofollow(APP / "data" / "lib-versions", pkg + ".json", json.dumps({
        "package": pkg, "previous": previous, "current": current,
        "action": action, "by": by, "at": now()}, indent=2))


_EXTRAS_RE = r"(\[\s*[A-Za-z0-9][A-Za-z0-9._,\s-]*\])?"


def _read_requirements():
    """requirements.txt lines, read without following a planted link."""
    # O_NOFOLLOW: a requirements.txt -> /etc/shadow link must not be read
    # by root and written back as a file the service account owns.
    fd = os.open(str(APP / "requirements.txt"),
                 os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r", encoding="utf-8") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise ValueError("not a regular file")
        return fh.read().splitlines()


def _req_line_re(pkg):
    return re.compile(r"^\s*%s\s*%s\s*([<>=!~].*)?$" % (re.escape(pkg), _EXTRAS_RE),
                      re.IGNORECASE)


def _req_extras(pkg):
    """The extras requirements.txt pins pkg with ("[binary]" for psycopg), or ''.

    Installing the bare name drops them: upgrading psycopg alone to 3.3.6 left
    psycopg-binary at 3.3.4, whose C wait_c() rejects the new timeout= keyword,
    and every worker died on its first connection (2026-10-15)."""
    try:
        lines = _read_requirements()
    except Exception:
        return ""
    name_re = _req_line_re(pkg)
    for ln in lines:
        if ln.lstrip().startswith("#"):
            continue
        m = name_re.match(ln)
        if m and m.group(1):
            return re.sub(r"\s+", "", m.group(1))
    return ""


def _bump_requirements(pkg, version):
    """Rewrite pkg's pin in requirements.txt to ==version (so the next code
    update's `pip install -r` does not silently revert this change). Matches
    the package line case-insensitively on the distribution name. Returns
    (changed, detail)."""
    if not (isinstance(pkg, str) and _PKG_RE.fullmatch(pkg)
            and isinstance(version, str) and _VER_RE.fullmatch(version)):
        return False, "refusing %r==%r" % (pkg, version)
    try:
        lines = _read_requirements()
    except Exception as e:
        return False, "read failed: %s" % e
    name_re = _req_line_re(pkg)
    out, hit = [], False
    for ln in lines:
        m = name_re.match(ln)
        if m and not ln.lstrip().startswith("#"):
            # keep the extras: "psycopg[binary]==x" must not become "psycopg==x"
            out.append("%s%s==%s" % (pkg, re.sub(r"\s+", "", m.group(1) or ""), version))
            hit = True
        else:
            out.append(ln)
    if not hit:
        out.append("%s==%s" % (pkg, version))
    try:
        _write_nofollow(APP, "requirements.txt", "\n".join(out) + "\n")
    except (OSError, ValueError) as e:
        return False, "write failed: %s" % e
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
    req = _read_request(req_path)
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
    is_standby = (role == "standby")
    app_was_active = _svc_active(SERVICE) == "active"
    previous = _installed_version(pkg)
    st.step("snapshot installed version", True, "%s==%s" % (pkg, previous or "(absent)"))
    if previous == version:
        st.step("noop", True, "already at %s" % version)
        _record_lib_version(pkg, previous, version, action, by)
        st.finish("success", package=pkg, previous_version=previous,
                  new_version=version, rolled_back=False)
        return

    try:
        pip_env, where, secret = _pip_index_env(req)
    except ValueError as e:
        st.step("package index", False, str(e))
        st.finish("failed", error="bad package index")
        return
    # Where the bytes come from, in the job log: an operator asking "where did
    # this version come from?" reads it here.
    st.step("package index", True, where)

    extras = _req_extras(pkg)
    try:
        p = _pip_install("%s%s==%s" % (pkg, extras, version), env=pip_env)
        st.step("pip install %s%s==%s" % (pkg, extras, version), p.returncode == 0,
                _redact(p.stderr or p.stdout, secret))
        if p.returncode != 0:
            raise RuntimeError("pip install failed")

        ok, detail = import_smoke_ok()
        st.step("import smoke", ok, "app imports with new %s" % pkg if ok else detail[:300])
        if not ok:
            raise RuntimeError("import smoke failed: %s" % detail[:200])
        ok, detail = db_smoke_ok()
        st.step("database smoke", ok,
                "SELECT 1 through the new %s" % pkg if ok else detail[-300:])
        if not ok:
            raise RuntimeError("database smoke failed: %s" % detail[-200:])

        # Reload the running workers so the new lib is actually loaded.
        restart_and_validate(st, is_standby, app_was_active,
                             "%s==%s" % (pkg, version))

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
        st.step("ERROR", False, _redact(str(e), secret))
        # ---- auto-rollback to the previously-installed version ----
        try:
            if previous:
                rb = _pip_install("%s%s==%s" % (pkg, extras, previous), env=pip_env)
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
                      new_version=previous, rolled_back=True, recovered=ok,
                      error=_redact(str(e), secret))
        except Exception as e2:
            st.finish("failed", package=pkg, rolled_back=True, recovered=False,
                      error=_redact("%s ; rollback error: %s" % (e, e2), secret))



# ---------------------------------------------------------------------------
# offline update packages (kind: "package")
# ---------------------------------------------------------------------------
# What the operator reads when a migration fails. The rollback restores code and
# dependencies; it cannot un-run DDL, so say so and say where the way back is.
MIGRATION_FAILED = (
    "flask db upgrade failed -- the update is rolled back (code and Python "
    "dependencies). The DATABASE is not rolled back: if the migration got part "
    "of the way, restore the newest bundle from 'satom get backup list' "
    "with 'satom execute restore db <bundle> --yes' before retrying.")

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


ADOPT_IDENTITY = ("-c", "user.name=SATOM", "-c", "user.email=satom@localhost")


def adopt_tree():
    """(ok, detail). Make an application tree that is not a git checkout into one.

    [SATOM-ADOPT-TREE] An offline install extracts the bundle's app.tar.gz:
    there is no .git. Every step of a package apply leans on git -- the
    snapshot it rolls back to, parking local commits, the list of files the new
    revision dropped, the commit that records what is deployed -- so on every
    offline-installed node before 2.5.0 the first package was refused at
    "count local commits" and nothing could ever be applied.

    One commit of the tree as it stands is the right baseline: the tree IS the
    release archive. On a fresh offline install `git add -A` (honouring the
    shipped .gitignore, which keeps data/, venv/, .env, pki/ and the other
    node-local paths out) selects exactly the archive's files, no more. A
    no-op on a checkout.
    """
    if (APP / ".git").exists():
        return True, "already a git checkout"
    for args in (("init", "-q"), ("add", "-A"),
                 ADOPT_IDENTITY + ("commit", "-q", "-m",
                  "baseline: SATOM %s as installed (adopted for package updates)"
                  % (_current_version() or "?"))):
        r = git(*args, timeout=300)
        if r.returncode != 0:
            return False, "git %s failed: %s" % (args[-1] if args[0] == "-c" else args[0],
                                                 (r.stderr or r.stdout or "")[-300:])
    n = len((git("ls-files", timeout=120).stdout or "").splitlines())
    return True, "baseline commit of %d tracked file(s)" % n


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
    # Through an O_NOFOLLOW fd, not `chown`/`chmod` on the path: those follow
    # a .env -> /etc/shadow link and would make the target group-readable by
    # the service account.
    try:
        import grp
        fd = os.open(str(APP / ".env"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if stat.S_ISREG(os.fstat(fd).st_mode):
                os.fchown(fd, 0, grp.getgrnam(APP_USER).gr_gid)
                os.fchmod(fd, 0o640)
        finally:
            os.close(fd)
    except (OSError, KeyError):
        pass
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


PIP_DRY_RUN_SINCE = (22, 2)
_PIP_MISSING_RES = (
    re.compile(r"No matching distribution found for ([^\s;]+)"),
    re.compile(r"Could not find a version that satisfies the requirement ([^\s;]+)"),
)
_REQ_MEMBERS = ("requirements.txt", "./requirements.txt")


def _make_wheelhouse(pkg_dir, up):
    """Root-owned, world-READABLE copy of the package's wheels plus the NEW
    requirements.txt (read straight out of the verified app.tar.gz).

    pip runs as the service account, and the staging directory is 0700 root on
    purpose (the account must not be able to swap a verified file). So pip
    could never read ``pkg_dir/wheels`` -- an apply that needed a new wheel
    failed at step 7, after the tree was already replaced. Root owns every
    entry here and nothing is writable by the account, so readable is enough.
    """
    import shutil
    import tarfile
    house = Path(tempfile.mkdtemp(prefix="satom-wheels-", dir="/var/tmp"))
    os.chmod(house, 0o755)
    wdir = house / "wheels"
    wdir.mkdir()
    os.chmod(wdir, 0o755)
    for w in sorted((Path(pkg_dir) / "wheels").glob("*.whl")):
        if not w.is_file() or w.is_symlink():
            continue
        shutil.copyfile(w, wdir / w.name)
        os.chmod(wdir / w.name, 0o644)
    req = None
    with tarfile.open(Path(pkg_dir) / "app.tar.gz", "r:gz") as tf:
        for name in _REQ_MEMBERS:
            try:
                m = tf.getmember(name)
            except KeyError:
                continue
            if m.isfile() and m.size < 1024 * 1024:
                req = tf.extractfile(m).read()
            break
    if req is None:
        raise up.PackageError("app.tar.gz has no requirements.txt")
    (house / "requirements.txt").write_bytes(req)
    os.chmod(house / "requirements.txt", 0o644)
    return house


def _pip_dry_run_ok():
    """(supported, 'pip X.Y'): `pip install --dry-run` exists since 22.2."""
    r = run([str(VENV / "python"), "-m", "pip", "--version"], timeout=60,
            user=APP_USER)
    m = re.search(r"pip (\d+)\.(\d+)", r.stdout or "")
    if not m:
        return False, "pip (version unknown)"
    return (int(m.group(1)), int(m.group(2))) >= PIP_DRY_RUN_SINCE, m.group(0)


def dependency_preflight(st, wheelhouse, manifest, cur):
    """Refuse, before anything changes, a package whose requirements this
    node's venv cannot meet from what is installed plus what is shipped."""
    st.begin("dependency preflight")
    shipped = len(list((Path(wheelhouse) / "wheels").glob("*.whl")))
    mode = manifest.get("wheels_mode") or "full"
    supported, pipv = _pip_dry_run_ok()
    if not supported:
        st.step("dependency preflight", True,
                "skipped: %s has no --dry-run (22.2+); %s package, %d wheel(s)"
                % (pipv, mode, shipped))
        return
    p = run([str(VENV / "pip"), "install", "--dry-run", "--quiet", "--no-index",
             "--find-links", str(Path(wheelhouse) / "wheels"),
             "-r", str(Path(wheelhouse) / "requirements.txt")],
            timeout=600, user=APP_USER)
    if p.returncode == 0:
        st.step("dependency preflight", True,
                "every requirement is installed or shipped (%s package, %d wheel(s))"
                % (mode, shipped))
        return
    out = (p.stderr or "") + "\n" + (p.stdout or "")
    missing = sorted({m.group(1) for rx in _PIP_MISSING_RES for m in rx.finditer(out)})
    msg = ("dependencies cannot be met offline: %s neither installed in this venv "
           "nor shipped in the package (%s, %d wheel(s)). Nothing was changed. "
           "Apply an earlier full update package or one built with a "
           "min_from_version at or below %s, then retry"
           % (", ".join(missing) or "(see pip output)", mode, shipped, cur))
    st.step("dependency preflight", False,
            msg if missing else (msg + " | " + out.strip()[-300:]))
    raise RuntimeError(msg)


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
    req = _read_request(req_path)
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
    wheelhouse = None
    ok_adopt, adopt_detail = adopt_tree()
    if adopt_detail != "already a git checkout" or not ok_adopt:
        st.step("adopt the installed tree into git", ok_adopt, adopt_detail)
    if not ok_adopt:
        st.finish("failed", package=req.get("package"), rolled_back=False,
                  error="the application tree is not a git checkout and could "
                        "not be adopted: %s" % adopt_detail)
        return
    snapshot = git("rev-parse", "HEAD").stdout.strip()
    untracked_before = _untracked_set()
    freeze = None
    role = req.get("role") or ("standby" if pg_in_recovery() else "primary")
    is_standby = (role == "standby")
    # Snapshot what the node is ACTUALLY doing, before anything is touched.
    # The restart step restores this state instead of the state the role
    # implies -- see restart_and_validate().
    app_was_active = _svc_active(SERVICE) == "active"

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
        st.begin("extract to root-only staging")
        pkg_dir = up.extract_package(pkg_file, stage)
        st.step("extract to root-only staging", True, str(stage))

        # -- 3. signature + integrity ---------------------------------------
        st.begin("verify signature")
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
            raise RuntimeError("package requires %s or newer; this node runs %s. "
                               "Apply an earlier update package whose minimum "
                               "version this node meets first, then this one"
                               % (min_from, cur))
        tags = list(manifest.get("python_tags") or [])
        mine = _venv_tag()
        if tags and "*" not in tags and mine and mine not in tags:
            raise RuntimeError("package carries wheels for %s; this venv is %s"
                               % (", ".join(tags), mine))
        st.step("version rules", True, "%s -> %s%s"
                % (cur, new, " (DOWNGRADE, explicitly allowed)" if cmp_ < 0 else ""))

        # -- 4b. can the dependencies be met? Decided BEFORE anything changes.
        # A package may ship only the wheels a supported node could be missing
        # (select_wheels in update_package.py), so "is every requirement either
        # installed or shipped?" is now a real question. Asked after step 6 it
        # used to cost a replaced tree and a rollback.
        wheelhouse = _make_wheelhouse(pkg_dir, up)
        dependency_preflight(st, wheelhouse, manifest, cur)

        # -- 5. backup BEFORE anything is replaced ---------------------------
        # A downgrade does not reverse migrations, so the database dump is the
        # only honest way back. If it cannot be taken, do not proceed.
        if req.get("do_backup", True) and not is_standby:
            st.begin("database backup")
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
        st.begin("freeze current dependencies")
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
        st.begin("install application tree")
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
            # The tracked list comes from a .git the service account owns:
            # never unlink through a planted directory link.
            if _link_below(APP, Path(rel).parent):
                continue
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
        # From the wheelhouse, not from pkg_dir: pip runs as the service
        # account, which cannot traverse the 0700 root-only staging directory.
        wheels = wheelhouse / "wheels"
        st.begin("pip install (offline, from the package)")
        p = run([str(VENV / "pip"), "install", "-q", "--no-index",
                 "--find-links", str(wheels), "-r", str(APP / "requirements.txt")],
                timeout=1800, user=APP_USER)
        st.step("pip install (offline, from the package)", p.returncode == 0,
                (p.stderr or p.stdout or "")[-400:])
        if p.returncode != 0:
            raise RuntimeError("offline pip install failed")

        # app.tar.gz is a `git archive`: it brings the new .po and no .mo, so
        # without this the node goes on serving the previous release's
        # catalogue.
        compile_catalogues(st)

        # -- 8. migrations (primary only) ------------------------------------
        if not is_standby:
            env = dict(os.environ, FLASK_APP="wsgi.py")
            st.begin("flask db upgrade")
            m = run([str(VENV / "flask"), "db", "upgrade"], timeout=600,
                    user=APP_USER, cwd=str(APP), env=env)
            # [SATOM-ALEMBIC-STAMP] Fatal, same reason as the git path.
            st.step("flask db upgrade", m.returncode == 0,
                    (m.stderr or m.stdout or "")[-300:])
            if m.returncode != 0:
                raise RuntimeError(MIGRATION_FAILED)
        else:
            st.step("flask db upgrade", True,
                    "skipped (standby; schema arrives by replication)")

        # -- 9. units, CLI and the runner itself -----------------------------
        # [SATOM-RELEASE-TRUST] With a root trust anchor present, run the units
        # and install-*.sh from a root-only copy of the ALREADY-VERIFIED package
        # (its Ed25519 signature and per-file hashes were checked at step 3),
        # not from the service-account-owned APP/deploy that was just
        # overwritten -- so a post-verification edit cannot change what root
        # runs. With no anchor (today's default) this is byte-for-byte unchanged.
        trust = _release_trust()
        stage_root = None
        if trust is None:
            st.step("release signature enforcement", True,
                    "OFF (no root trust anchor at %s)" % TRUST_ANCHOR)
            deploy_dir = APP / "deploy"
            script_env = None
        else:
            stage_root = _root_only_stage()
            up.extract_app_tree(app_tar, stage_root)
            deploy_dir = stage_root / "deploy"
            # SATOM_DEPLOY_SRC: the scripts copy what they install (CLI package,
            # runner, sbin helpers) from the staged copy too, not APP/deploy.
            script_env = dict(os.environ, FM_APP_DIR=str(APP),
                              SATOM_DEPLOY_SRC=str(deploy_dir))
            st.step("stage verified release scripts", True, str(deploy_dir))
        try:
            refresh_units(deploy_dir, st)
            # install-runner.sh also re-installs the /usr/local/sbin helper
            # scripts ([SATOM-SBIN-ROOT-COPY]); they live outside the tree and no
            # code update reaches them otherwise.
            for script, label in (("install-cli.sh", "operator CLI"),
                                  ("install-runner.sh",
                                   "update runner + /usr/local/sbin helpers"),
                                  ("install-metrics-store.sh", "metrics store"),
                                  ("install-console-role.sh",
                                   "database console role")):
                sp = deploy_dir / script
                if sp.exists():
                    st.begin("refresh %s" % label)
                    cr = subprocess.run(["bash", str(sp)], capture_output=True,
                                        text=True, timeout=180, env=script_env)
                    st.step("refresh %s" % label, cr.returncode == 0,
                            (cr.stdout or cr.stderr or "").strip()[-200:])
        finally:
            if stage_root is not None:
                import shutil as _sh
                _sh.rmtree(stage_root, ignore_errors=True)
        tighten_data_dir(st)

        # -- 10. restart and prove it works ----------------------------------
        restart_and_validate(st, is_standby, app_was_active,
                             "version %s" % new)

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

        if not is_standby:
            import_shipped_api_pack(st)

        st.finish("success", package=name, applied_version=new,
                  previous_version=cur, rolled_back=False,
                  signed_by=key["fingerprint"],
                  downgrade=bool(cmp_ < 0))
        return

    except Exception as e:  # noqa: BLE001
        st.step("ERROR", False, str(e)[:400])
        try:
            st.begin("rollback to %s" % snapshot[:12])
            git("reset", "--hard", snapshot)
            stray = _new_untracked(untracked_before)
            for rel in stray:
                target = APP / rel
                if _link_below(APP, Path(rel).parent):
                    continue
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
            compile_catalogues(st, "pybabel compile (rolled-back catalogues)")
            subprocess.run(["systemctl", "restart", SCHED], timeout=60)
            restart_reconciler()
            if not app_was_active:
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
        if wheelhouse:
            import shutil as _sh
            _sh.rmtree(wheelhouse, ignore_errors=True)


PROMOTE_SCRIPT = Path("/usr/local/sbin/satom-promote.sh")


def _root_owned_script_problem(path):
    """Why root must not execute ``path``, or None (same rule as the runner's
    own copy: a regular file, root-owned, not group/world-writable, all the
    way up the parent chain)."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return "%s is not a regular file" % path
    except OSError as exc:
        return "%s is not installed (%s)" % (path, exc.strerror or exc)
    try:
        return _load_update_package().root_owned_problem(path)
    except Exception as exc:  # noqa: BLE001
        return "cannot check %s: %s" % (path, exc)


def promote(req_path):
    """Guarded failover handler (root): promote this node's Postgres standby and
    bring the app up via the root-owned /usr/local/sbin/satom-promote.sh.
    Enqueued by the web UI after a typed-hostname confirmation; never
    auto-invoked."""
    req = _read_request(req_path)
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
    # The ROOT-OWNED copy install-runner.sh installs ([SATOM-SBIN-ROOT-COPY]),
    # never deploy/satom-promote.sh: the service account can rewrite that one,
    # and this runs it as root. No fallback to the tree copy.
    script = PROMOTE_SCRIPT
    problem = _root_owned_script_problem(script)
    if problem:
        st.step("promote script", False,
                "%s -- refusing to run the copy in the app tree; install the "
                "root-owned one with 'bash %s/deploy/install-runner.sh' as root"
                % (problem, APP))
        st.finish("failed", error="root-owned %s is not usable: %s"
                  % (script, problem))
        return
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
_SVC_ACTIONS = ("start", "stop", "restart", "reload")

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
    "nginx.service": ("start", "restart", "reload"),
    "postgresql.service": ("restart",),
    # The HA link repair (app/services/ha_link.py). Restart only: a stopped
    # logind refuses every new login on the box, the operator's included.
    "systemd-logind.service": ("restart",),
}

# Units only a PRIMARY may act on, re-checked here against this node's own
# Postgres rather than trusted from the request's "role" field (which the web
# side writes and a forged request can write too). logind is listed because
# the repair exists for the primary's side of the standby's git fetch; on a
# standby nothing fetches from it, so a restart there fixes nothing and is
# refused rather than "succeeding".
_SVC_PRIMARY_ONLY = ("systemd-logind.service",)


def _svc_node_role():
    """'primary' | 'standby' | 'unknown' from this node's Postgres.

    Tri-state on purpose. ``pg_in_recovery()`` answers False when it cannot
    ask, which is the right default for the update path and the wrong one for
    a guard: "could not tell" must refuse, not pass as primary.
    """
    try:
        r = subprocess.run(
            ["runuser", "-u", "postgres", "--", "psql", "-tAc",
             "select pg_is_in_recovery()"],
            capture_output=True, text=True, timeout=15)
    except Exception:  # noqa: BLE001
        return "unknown"
    v = (r.stdout or "").strip()
    return "standby" if v == "t" else "primary" if v == "f" else "unknown"

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
    req = _read_request(req_path)
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
    if unit in _SVC_PRIMARY_ONLY:
        role = _svc_node_role()
        if role != "primary":
            st.step("validate role", False,
                    "%s is acted on only on the PRIMARY; this node is %s"
                    % (unit, role))
            st.finish("failed", error="primary only")
            return
    if _svc_prop(unit, "LoadState") == "not-found":
        st.step("validate unit", False, "%s is not installed on this node" % unit)
        st.finish("failed", error="unit not installed")
        return
    st.step("validate", True, "%s %s (requested by %s)"
            % (action, unit, req.get("requested_by") or "?"))

    before = _svc_active(unit)
    st.step("state before", True, "%s is %s" % (unit, before))

    if unit == "nginx.service" and action in ("reload", "restart"):
        # A reload with a broken config is accepted by systemd and silently
        # ignored by nginx; a restart with one takes the front down. Either
        # way the config is tested first. This is also the certificate
        # activation path when the host's sudo policy refuses the
        # /etc/sudoers.d/satom allowlist (cert_service._reload_nginx).
        try:
            t = subprocess.run(["nginx", "-t"], capture_output=True, text=True,
                               timeout=60)
            tok, tdetail = t.returncode == 0, (t.stderr or t.stdout or "")
        except Exception as e:  # noqa: BLE001
            tok, tdetail = False, str(e)
        st.step("nginx -t", tok, tdetail.strip()[-400:])
        if not tok:
            st.finish("failed", unit=unit, action=action, state_before=before,
                      state_after=before, error="nginx -t failed")
            return

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


# Settings -> Node TLS -> Postgres SSL. The web process runs as the service
# account and cannot become the postgres OS user, so the ALTER SYSTEM is done
# here, as root, after re-validating the two values against the SAME rules as
# app/services/pg_ssl.py (this module must not import the app package).
_PG_PROTOCOLS = ("TLSv1.2", "TLSv1.3")
_PG_CIPHER_RE = re.compile(r"^[A-Za-z0-9:+!_,@=\- ]{1,255}$")


def pg_ssl_apply(req_path):
    """Apply ssl_min_protocol_version / ssl_ciphers on the local Postgres."""
    req = _read_request(req_path)
    uid = req.get("id") or Path(req_path).stem
    st = Status(uid, req)
    try:
        os.remove(req_path)  # dequeue so the .path unit stops re-firing
    except OSError:
        pass
    st.d["kind"] = "pg_ssl"
    proto = (req.get("min_protocol") or "").strip()
    ciphers = (req.get("ciphers") or "").strip()
    if proto not in _PG_PROTOCOLS or (ciphers and not _PG_CIPHER_RE.match(ciphers)):
        st.step("validate", False, "refused: protocol %r / cipher string" % proto)
        st.finish("failed", error="invalid Postgres SSL policy")
        return
    st.step("validate", True, "min %s, ciphers %s (requested by %s)"
            % (proto, ciphers or "(unchanged)", req.get("requested_by") or "?"))
    stmts = ["ALTER SYSTEM SET ssl_min_protocol_version = '%s';" % proto]
    if ciphers:
        stmts.append("ALTER SYSTEM SET ssl_ciphers = '%s';" % ciphers)
    stmts.append("SELECT pg_reload_conf();")
    fd, path = tempfile.mkstemp(suffix=".sql", dir="/tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(stmts) + "\n")
        os.chmod(path, 0o644)
        r = subprocess.run(["runuser", "-u", "postgres", "--", "psql",
                            "-v", "ON_ERROR_STOP=1", "-f", path],
                           capture_output=True, text=True, timeout=60)
        ok = r.returncode == 0
        st.step("ALTER SYSTEM + reload", ok, (r.stderr or r.stdout or "").strip()[-400:])
        if ok:
            st.finish("success", min_protocol=proto, ciphers=ciphers)
        else:
            st.finish("failed", error="psql exited %s" % r.returncode)
    except Exception as e:  # noqa: BLE001
        st.step("ERROR", False, str(e))
        st.finish("failed", error=str(e))
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _reject(rp, req, reason):
    """Dequeue a request the runner will not act on, and say why: in the
    journal always, in its status file when its id is one we can write."""
    _log("rejected request %s: %s" % (os.path.basename(rp), reason))
    try:
        os.remove(rp)
    except OSError:
        pass
    uid = req.get("id") if isinstance(req, dict) else None
    if isinstance(uid, str) and UID_RE.fullmatch(uid):
        try:
            st = Status(uid, req)
            st.step("validate request", False, reason)
            st.finish("failed", error=reason)
        except Exception:  # noqa: BLE001
            pass


# Every kind this runner executes. A request without a kind is a code update
# (app/services/self_update.request_update() writes none); any OTHER kind is
# refused -- it used to fall through to the git reset + root scripts path.
# ---------------------------------------------------------------------------
# curated OS packages (kind: "syspkg") -- Settings > General > System packages
# ---------------------------------------------------------------------------
# [SATOM-RUNNER-NO-APP-IMPORT] A COPY of app/services/system_packages.PACKAGES
# (keys + binary), asserted equal by tests/test_system_packages.py. The web
# side only ever sends a KEY; the distro package name comes from here, so a
# forged request cannot name a package, a flag or a version.
_SYSPKG = {
    "bubblewrap": {"binary": "bwrap",
                   "names": {"apt": "bubblewrap", "dnf": "bubblewrap",
                             "yum": "bubblewrap", "zypper": "bubblewrap",
                             "pacman": "bubblewrap"}},
}
_SYSPKG_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,63}$")


def _pkg_manager():
    import shutil
    for m in ("apt-get", "dnf", "yum", "zypper", "pacman"):
        if shutil.which(m):
            return "apt" if m == "apt-get" else m
    return ""


def _pkg_install_cmd(mgr, name):
    return {
        "apt": ["apt-get", "install", "-y", "-q", "--no-install-recommends", name],
        "dnf": ["dnf", "install", "-y", "-q", name],
        "yum": ["yum", "install", "-y", "-q", name],
        "zypper": ["zypper", "--non-interactive", "--quiet", "install", name],
        "pacman": ["pacman", "-S", "--noconfirm", "--needed", name],
    }[mgr]


# [SATOM-RUNNER-NO-APP-IMPORT] A COPY of app/services/sandbox.root_dirs_argv,
# asserted equal by tests/test_sandbox_root_dirs.py. Mirrors the host's /bin,
# /sbin, /lib, /lib64: symlinks on a usr-merged host, real directories on
# SLES/Leap 15, where /lib64 holds the ELF loader (SA-0002).
_ROOT_DIRS = ("bin", "sbin", "lib", "lib64")


def _root_dirs_argv(root="/"):
    out = []
    for name in _ROOT_DIRS:
        host = os.path.join(root, name)
        if os.path.islink(host):
            out += ["--symlink", os.readlink(host), "/" + name]
        elif os.path.isdir(host):
            out += ["--ro-bind", host, "/" + name]
    return out


def _bwrap_works_for_app_user():
    """bubblewrap installed is not bubblewrap usable: the app user must be
    allowed to create namespaces. Same flags the product's jail uses."""
    p = run(["bwrap", "--unshare-all", "--die-with-parent",
             "--ro-bind", "/usr", "/usr"] + _root_dirs_argv()
            + ["--proc", "/proc", "--dev", "/dev", "/usr/bin/true"],
            timeout=30, user=APP_USER, cwd="/")
    return p.returncode == 0, (p.stderr or p.stdout or "").strip()


def syspkg_install(req_path):
    """Install ONE curated OS package on this node (root, table-bounded)."""
    import shutil
    req = _read_request(req_path)
    uid = req.get("id") or Path(req_path).stem
    st = Status(uid, req)
    try:
        os.remove(req_path)  # dequeue so the .path unit stops re-firing
    except OSError:
        pass
    key = req.get("package")
    key = key.strip() if isinstance(key, str) else ""
    st.d["kind"] = "syspkg"
    st.d["package"] = key
    st.d["action"] = "install"
    st.flush()

    if not _SYSPKG_KEY_RE.match(key) or key not in _SYSPKG:
        st.step("validate package", False, "%r is not a curated system package" % key)
        st.finish("failed", error="package not allowed")
        return
    if (req.get("action") or "install") != "install":
        st.step("validate action", False, "only 'install' is supported")
        st.finish("failed", error="action not allowed")
        return
    spec = _SYSPKG[key]
    mgr = _pkg_manager()
    if not mgr:
        st.step("package manager", False, "no apt-get/dnf/yum/zypper/pacman found")
        st.finish("failed", error="unsupported distribution")
        return
    st.step("validate", True, "%s via %s" % (key, mgr))

    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    if shutil.which(spec["binary"]):
        st.step("already installed", True, shutil.which(spec["binary"]))
    else:
        if mgr == "apt":
            st.begin("apt-get update")
            u = run(["apt-get", "update", "-q"], timeout=600, env=env)
            # A stale mirror list is a warning: the install below may still
            # succeed from the cached index, and its own result is what counts.
            st.step("apt-get update", True, (u.stderr or u.stdout)[-300:],
                    warn=u.returncode != 0)
        cmd = _pkg_install_cmd(mgr, spec["names"][mgr])
        st.begin(" ".join(cmd))
        p = run(cmd, timeout=900, env=env)
        st.step(" ".join(cmd), p.returncode == 0, (p.stderr or p.stdout)[-500:])
        if p.returncode != 0 or not shutil.which(spec["binary"]):
            st.finish("failed", error="install failed" if p.returncode != 0
                      else "%s still not on PATH" % spec["binary"])
            return
        st.step("binary present", True, shutil.which(spec["binary"]))

    if key == "bubblewrap":
        ok, detail = _bwrap_works_for_app_user()
        st.step("sandbox works for %s" % APP_USER, ok,
                detail or "namespaces created and torn down")
        if not ok:
            st.finish("failed", error="installed, but %s cannot create namespaces: %s"
                      % (APP_USER, detail[:200]))
            return
    st.finish("success", package=key)


# ---------------------------------------------------------------------------
# deploy clone (kind: "clone") -- Settings > Source of Truth & Backup
# ---------------------------------------------------------------------------
# [SATOM-RUNNER-NO-APP-IMPORT] The console queues; this runs the INSTALLED CLI
# ('satom execute clone export|import --yes'), which is root-owned and comes
# from the last signed deploy/ -- the same code an operator runs by hand. An
# import has to stop satom.service, the worker that queued it, which is why it
# cannot run anywhere but here.
#
# The passphrase is taken out of the request and the request file is deleted
# before anything else; it reaches the CLI in its environment, and no step,
# detail or field of the status file ever carries it.
_CLONE_ACTIONS = ("export", "import")
_CLONE_NAME_RE = re.compile(r"^satom-clone-[A-Za-z0-9._-]+\.tar\.gz$")
_CLONE_MIN_PASSPHRASE = 16
#: Below satom-updater.service's TimeoutStartSec (1800): a CLI killed by
#: systemd mid-import would leave the console stopped with nobody to restart it.
_CLONE_TIMEOUT = 1500
#: What the CLI import stops; started again here if the CLI itself is killed.
_CLONE_UNITS = ("satom.service", "satom-scheduler.service", "satom-reconciler.service")


def _clone_cli():
    import shutil
    for c in (shutil.which("satom"), "/usr/local/sbin/satom"):
        if c and os.path.isfile(c):
            st = os.stat(c)
            # root-owned and not writable by anyone else: the CLI is what root
            # runs here, so a copy the service account can edit is refused.
            if st.st_uid == 0 and not st.st_mode & 0o022:
                return c
    return ""


def clone_job(req_path):
    """Export or import a deploy clone for the console (root, CLI-bounded)."""
    req = _read_request(req_path)
    uid = req.get("id") or Path(req_path).stem
    passphrase = req.pop("passphrase", None)
    try:
        os.remove(req_path)  # dequeue -- and the only copy of the passphrase on disk
    except OSError:
        pass
    st = Status(uid, req)
    action = req.get("action")
    action = action if isinstance(action, str) else ""
    st.d["kind"] = "clone"
    st.d["action"] = action
    st.flush()

    if action not in _CLONE_ACTIONS:
        st.step("validate action", False, "%r is not a clone action" % action)
        st.finish("failed", error="action not allowed")
        return
    if not isinstance(passphrase, str) or len(passphrase) < _CLONE_MIN_PASSPHRASE \
            or any(c in passphrase for c in "\x00\r\n"):
        st.step("validate passphrase", False, "missing or malformed")
        st.finish("failed", error="passphrase refused")
        return
    path = None
    if action == "import":
        name = req.get("bundle")
        if not isinstance(name, str) or not _CLONE_NAME_RE.match(name):
            st.step("validate bundle", False, "%r is not a clone bundle name" % (name,))
            st.finish("failed", error="bundle refused")
            return
        path = APP / "data" / "clone-imports" / name
        try:
            import stat as _stat
            ok = _stat.S_ISREG(os.lstat(path).st_mode)
        except OSError:
            ok = False
        if not ok:
            st.step("validate bundle", False, "%s is not a regular file in the import inbox"
                    % name)
            st.finish("failed", error="bundle missing")
            return
        st.d["target"] = name
    role = _svc_node_role()
    if role != "primary":
        st.step("validate role", False, "clones run on the PRIMARY; this node is %s" % role)
        st.finish("failed", error="primary only")
        return
    cli = _clone_cli()
    if not cli:
        st.step("satom CLI", False, "no root-owned satom CLI on this node; "
                "reinstall it with 'sudo bash %s/deploy/install-cli.sh'" % APP)
        st.finish("failed", error="CLI missing")
        return
    st.step("validate", True, "%s requested by %s" % (action, req.get("requested_by") or "?"))

    cmd = [cli, "--json", "execute", "clone", action]
    if path is not None:
        cmd.append(str(path))
    cmd.append("--yes")
    env = dict(os.environ, SATOM_CLONE_PASSPHRASE=passphrase)
    passphrase = None
    st.begin("satom execute clone %s" % action)
    try:
        p = run(cmd, timeout=_CLONE_TIMEOUT, env=env)
    except subprocess.TimeoutExpired:
        env = None
        st.step("satom execute clone %s" % action, False,
                "no result after %d s; the CLI was stopped" % _CLONE_TIMEOUT)
        if action == "import":
            for unit in _CLONE_UNITS:
                r = run(["systemctl", "start", unit], timeout=180)
                st.step("start %s" % unit, r.returncode == 0, (r.stderr or "")[-200:])
            st.step("GET /healthz", health_ok(), "")
        st.finish("failed", error="timed out -- run it from a shell with "
                  "'sudo satom execute clone %s'" % action)
        return
    env = None
    try:
        out = json.loads(p.stdout or "")
    except ValueError:
        out = None
    if not isinstance(out, dict):
        st.step("satom execute clone %s" % action, False,
                ((p.stderr or "") + (p.stdout or ""))[-400:] or "no output")
        st.finish("failed", error="the CLI gave no result")
        return
    ok = out.get("status") in ("ok", "warn") and p.returncode == 0
    data = out.get("data") if isinstance(out.get("data"), dict) else {}
    if action == "export":
        # Only the machine fields: the CLI's text sections are not copied for
        # an export, so nothing it prints can land in this file.
        if ok:
            rk = data.get("rekey") if isinstance(data.get("rekey"), dict) else {}
            st.step("bundle written", True, "%s (%s bytes, %s tables, %s rows, %s secrets "
                    "re-encrypted)" % (data.get("name"), data.get("size"), data.get("tables"),
                                       data.get("rows"), rk.get("rekeyed", 0)))
            if rk.get("vaulted"):
                st.step("external vault", True, "%s secret(s) live in the external vault; "
                        "the target reaches them through the same vault configuration"
                        % rk["vaulted"], warn=True)
            st.finish("success", bundle=data.get("name"), size=data.get("size"))
        else:
            st.step("export", False, " ".join(str(n) for n in out.get("notes") or [])[-400:]
                    or str(out.get("title") or ""))
            st.finish("failed", error=str(out.get("title") or "export failed"))
        return
    for sec in out.get("sections") or []:
        if not isinstance(sec, dict):
            continue
        if sec.get("kind") == "lines":
            # e.g. "secrets this node cannot open" -- names, never values
            st.step(str(sec.get("heading")), False,
                    "; ".join(str(x) for x in sec.get("body") or []))
            continue
        if sec.get("kind") != "rows":
            continue
        for row in sec.get("body") or []:
            if isinstance(row, (list, tuple)) and len(row) == 2:
                st.step("%s: %s" % (sec.get("heading"), row[0]), True, str(row[1]))
    for note in out.get("notes") or []:
        st.step("note", True, str(note))
    if ok:
        st.finish("success", bundle=req.get("bundle"))
    else:
        st.finish("failed", error=str(out.get("title") or "import failed"))


_HANDLERS = {
    "": "process",
    "clone": "clone_job",
    "promote": "promote",
    "pip": "pip_change",
    "package": "package_change",
    "service": "service_action",
    "pg_ssl": "pg_ssl_apply",
    "syspkg": "syspkg_install",
}


def main():
    for rp in sorted(glob.glob(str(REQ / "*.json"))):
        try:
            try:
                req = _read_request(rp)
            except Exception as exc:  # noqa: BLE001
                _reject(rp, None, "unreadable request: %s" % exc)
                continue
            if not isinstance(req, dict):
                _reject(rp, None, "a request must be a JSON object")
                continue
            kind = req.get("kind")
            if kind is None:
                kind = ""
            handler = _HANDLERS.get(kind) if isinstance(kind, str) else None
            if handler is None:
                _reject(rp, req, "unknown request kind %r" % (kind,))
                continue
            globals()[handler](rp)
        except Exception as exc:  # noqa: BLE001
            _log("dropped request %s: %s" % (os.path.basename(rp), exc))
            try:
                os.remove(rp)  # never crash-loop on a malformed request
            except OSError:
                pass


if __name__ == "__main__":
    main()
