"""Execution context for the SATOM operator CLI.

STDLIB ONLY. This module — and every module in this package — must import
cleanly on a node whose venv is corrupt, whose database is down and whose web
service will not start. That is the entire reason the CLI exists, so a
module-level ``import flask`` here would defeat it. ``tests/test_cli.py``
enforces this with an AST check, not with good intentions.
"""
import grp
import os
import pwd
import shutil
import socket
import subprocess
from pathlib import Path

APP_DIR = Path(os.environ.get("FM_APP_DIR", "/opt/satom"))
ENV_FILE = APP_DIR / ".env"
VENV = APP_DIR / "venv" / "bin"
LOG_DIR = Path("/var/log/satom")

# Units the CLI knows about. Short alias -> unit name. The alias is what the
# operator types; the unit name is what systemd knows. Keeping the alias table
# here (and not in the command tree) means `get service status` and
# `execute restart` can never disagree about what "web" means.
UNITS = {
    "web": "satom.service",
    "scheduler": "satom-scheduler.service",
    "reconciler": "satom-reconciler.service",
    "updater": "satom-updater.path",
    "alerts": "satom-alerts.timer",
    "cert-renew": "satom-cert-renew.timer",
    "git-publish": "satom-git-publish.timer",
    "datasync": "satom-ha-datasync.timer",
    "nginx": "nginx.service",
    "postgres": "postgresql.service",
}

# Units an operator may start/stop/restart from the CLI. `satom-updater` is
# deliberately ABSENT: it is the privileged root runner, and a CLI verb that
# restarts it is a CLI verb that re-enters the privilege boundary sideways.
RESTARTABLE = ("web", "scheduler", "reconciler", "alerts", "cert-renew",
               "git-publish", "datasync", "nginx")


def run(cmd, timeout=60, env=None, cwd=None, input_=None):
    """Run a command. Never raises: returns (rc, stdout, stderr).

    A CLI whose job is to diagnose a broken box must not itself explode when a
    binary is missing — a traceback tells the operator nothing they can act on.
    """
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=env, cwd=cwd, input=input_)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except FileNotFoundError:
        return 127, "", "not found: %s" % (cmd[0] if cmd else "?")
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except Exception as exc:  # noqa: BLE001
        return 1, "", "%s: %s" % (type(exc).__name__, exc)


def _app_user():
    """Service account = owner of the app tree. Same single source of truth the
    privileged runner uses (`_app_user_from_tree`): an env var is forgotten when
    a new node is installed, the directory owner is not."""
    try:
        return pwd.getpwuid(APP_DIR.stat().st_uid).pw_name
    except Exception:  # noqa: BLE001
        return "root"


class Ctx:
    """Everything a command handler needs, resolved once and cached."""

    def __init__(self, json_mode=False, quiet=False):
        self.json_mode = json_mode
        self.quiet = quiet
        self.uid = os.geteuid()
        self.is_root = (self.uid == 0)
        try:
            self.user = pwd.getpwuid(self.uid).pw_name
        except Exception:  # noqa: BLE001
            self.user = str(self.uid)
        self.host = socket.gethostname()
        self.app_dir = APP_DIR
        self.app_user = _app_user()
        # Output policy, set by main() once flags are parsed.
        self.style = None
        self._env = None
        self._role = None

    # -- environment ------------------------------------------------------
    @property
    def env(self):
        """Parsed .env, or {} when unreadable.

        `.env` is 640 root:<service account> ON PURPOSE (the app only reads it,
        so a write primitive cannot rewrite its own secrets). An operator who is
        neither root nor in that group gets {} — which must DEGRADE the affected
        commands, never crash them.
        """
        if self._env is None:
            self._env = {}
            try:
                for line in ENV_FILE.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    self._env[k.strip()] = v.strip().strip('"').strip("'")
            except Exception:  # noqa: BLE001
                self._env = {}
        return self._env

    @property
    def env_readable(self):
        return bool(self.env)

    def db_uri(self):
        return self.env.get("SQLALCHEMY_DATABASE_URI", "")

    def db_parts(self):
        """(user, password, host, port, dbname) from the app's own URI, or None.

        Derived, never hardcoded: a fresh install uses role `satom` and whatever
        database name the URI says, while 248/249 adopted the pre-existing
        `satom` (and `fortinet` / `fortinet_mgr` on installs predating the
        2026-08 rename). A hardcoded name is how
        `scheduler_guard.sh` silently broke.
        """
        uri = self.db_uri()
        if "://" not in uri:
            return None
        try:
            tail = uri.split("://", 1)[1]
            creds, hostpart = tail.rsplit("@", 1)
            user, _, pw = creds.partition(":")
            hostport, _, dbname = hostpart.partition("/")
            host, _, port = hostport.partition(":")
            dbname = dbname.split("?")[0]
            from urllib.parse import unquote
            return (unquote(user), unquote(pw), host or "127.0.0.1",
                    port or "5432", dbname)
        except Exception:  # noqa: BLE001
            return None

    def psql(self, sql, timeout=15):
        """(rc, out, err) for a one-shot query using the APP's credentials.

        Not `runuser -u postgres`: that only works as root, which is exactly the
        bug that killed `scheduler_guard.sh` and `satom-git-publish.sh` when the
        units dropped to the service account on 2026-07-26. TCP + password works
        at every privilege level.
        """
        parts = self.db_parts()
        if not parts:
            return 1, "", "database credentials unavailable (.env unreadable as %s)" % self.user
        user, pw, host, port, dbname = parts
        env = dict(os.environ, PGPASSWORD=pw)
        return run(["psql", "-h", host, "-p", port, "-U", user, "-d", dbname,
                    "-tAc", sql], timeout=timeout, env=env)

    # -- HA role ----------------------------------------------------------
    @property
    def role(self):
        """primary | standby | unknown.

        NOT "standalone": this is derived purely from pg_is_in_recovery(), and
        a standalone node's database is not in recovery, so it reports
        "primary". There is no signal here that distinguishes a lone node from
        a cluster primary -- for that, ask whether a PEER is configured
        (cmd_checks.configured_peers). Callers that write
        `role in ("primary", "standalone")` are carrying a dead branch; they
        happen to be correct because "primary" already covers the lone node.
        """
        if self._role is None:
            rc, out, _ = self.psql("SELECT pg_is_in_recovery();")
            if rc != 0:
                self._role = "unknown"
            elif out.strip() == "t":
                self._role = "standby"
            elif out.strip() == "f":
                self._role = "primary"
            else:
                self._role = "unknown"
        return self._role

    # -- systemd ----------------------------------------------------------
    def unit(self, alias):
        return UNITS.get(alias, alias)

    def unit_state(self, alias):
        u = self.unit(alias)
        rc, out, _ = run(["systemctl", "show", u, "--no-pager",
                          "--property=ActiveState,SubState,UnitFileState,"
                          "ExecMainStartTimestamp,NRestarts,Result"])
        d = {}
        for line in out.splitlines():
            k, _, v = line.partition("=")
            d[k] = v
        return {
            "unit": u,
            "active": d.get("ActiveState", "?"),
            "sub": d.get("SubState", "?"),
            "enabled": d.get("UnitFileState", "?"),
            "since": d.get("ExecMainStartTimestamp", "") or "-",
            "restarts": d.get("NRestarts", "0"),
            "result": d.get("Result", "-"),
        }

    def journal(self, alias, lines=30):
        rc, out, err = run(["journalctl", "-u", self.unit(alias), "-n", str(int(lines)),
                            "--no-pager", "-o", "short-iso"], timeout=30)
        return out or err

    # -- misc probes ------------------------------------------------------
    def http(self, url, timeout=6, insecure=True):
        """(code, body) using stdlib only — curl may not exist on a minimal image."""
        import ssl
        import urllib.error
        import urllib.request
        c = ssl.create_default_context()
        if insecure:
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(url, timeout=timeout, context=c) as r:
                return r.getcode(), r.read(4096).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except Exception as exc:  # noqa: BLE001
            return 0, "%s: %s" % (type(exc).__name__, exc)

    def version(self):
        try:
            return (self.app_dir / "VERSION").read_text().strip()
        except Exception:  # noqa: BLE001
            return "unknown"

    def git_head(self):
        rc, out, _ = run(["git", "-C", str(self.app_dir), "rev-parse", "--short", "HEAD"])
        return out if rc == 0 else "unknown"

    def in_service_group(self):
        try:
            gid = grp.getgrnam(self.app_user).gr_gid
            return gid in os.getgroups()
        except Exception:  # noqa: BLE001
            return False

    def have(self, binary):
        return shutil.which(binary) is not None
