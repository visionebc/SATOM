"""'diagnose' — active probes that answer "why is it broken". Read-only.

These run as ANY user. Where a probe needs a credential the caller cannot read,
it reports 'degraded' with the reason. A probe that cannot run must never
render as a pass — that is the exact failure that let the Fleet health badge
show four dead appliances as healthy (docs/safeguards.md §9b).
"""
import os
import stat
from pathlib import Path

from .context import UNITS, run
from .render import Result

# Modules the app imports INSIDE functions. Nothing imports them at collection
# time, so a SyntaxError in one is invisible to the app, to /healthz and to the
# whole test suite — which is exactly how a broken cert_service.py shipped
# inside the 1.2 and 1.2.1 offline bundles. They must be imported explicitly.
LAZY_MODULES = (
    "app.services.cert_service",
    "app.services.cert_renew_log",
    "app.services.sot_store",
    "app.services.vm_store",
    "app.services.metrics_collect",
    "app.services.git_backup",
    "app.services.backup_server",
    "app.services.library_updates",
    "app.services.encryption_health",
    "app.services.node_security",
)


def _fail(r, msg):
    r.status = "bad"
    r.note(msg)
    return r


def service(ctx, args):
    """Deep-dive one unit: state, why it stopped, and its journal."""
    if not args:
        r = Result("bad", "usage: diagnose service <name>", exit_code=2)
        r.lines("known services", sorted(UNITS))
        return r
    alias = args[0]
    if alias not in UNITS:
        r = Result("bad", "unknown service: %s" % alias, exit_code=2)
        r.lines("known services", sorted(UNITS))
        return r
    st = ctx.unit_state(alias)
    r = Result("ok" if st["active"] in ("active", "activating") else "bad",
               "diagnose %s" % st["unit"])
    r.rows("state", sorted(st.items()))
    rc, out, _ = run(["systemctl", "show", st["unit"], "--no-pager",
                      "--property=User,ExecStart,FragmentPath,DropInPaths"])
    r.lines("definition", out.splitlines())
    if "User=root" in out and alias in ("web", "scheduler", "reconciler"):
        r.worst("warn")
        r.note("This unit resolves to User=root. Since 2026-07-26 it should run "
               "as '%s' via a drop-in. Run 'satom execute reinstall units' "
               "(a plain unit edit does NOT survive a self-update: the runner "
               "re-copies deploy/<unit> every time)." % ctx.app_user)
    r.lines("last 40 journal lines", ctx.journal(alias, 40).splitlines())
    if st["active"] == "failed":
        r.note("Unit failed. Fix the cause, then: satom execute restart %s" % alias)
    return r


def database(ctx, args):
    parts = ctx.db_parts()
    if not parts:
        r = Result("warn", "diagnose database — degraded", exit_code=4)
        r.lines("why", [".env unreadable as %s; re-run as root." % ctx.user])
        return r
    user, _pw, host, port, dbname = parts
    r = Result("ok", "diagnose database %s@%s:%s/%s" % (user, host, port, dbname))
    st = ctx.unit_state("postgres")
    r.rows("server unit", [("state", "%s/%s" % (st["active"], st["sub"]))])
    rc, out, err = ctx.psql("SELECT 1;")
    if rc != 0:
        _fail(r, "Cannot connect. Check that postgresql is running and that "
                 "pg_hba allows this host (replication is enforced hostssl "
                 "clientcert=verify-ca since 2026-07-13).")
        r.lines("error", (err or "").splitlines())
        return r
    rows = []
    for label, sql in (("in recovery", "SELECT pg_is_in_recovery();"),
                       ("ssl in use", "SELECT ssl, version, cipher FROM pg_stat_ssl "
                                      "WHERE pid = pg_backend_pid();"),
                       ("blocked queries", "SELECT count(*) FROM pg_stat_activity "
                                           "WHERE wait_event_type='Lock';")):
        c, o, _ = ctx.psql(sql)
        rows.append((label, o if c == 0 else "?"))
    r.rows("", rows)
    return r


def python(ctx, args):
    """venv integrity + import smoke.

    'The app starts' is NOT proof the code is importable: every caller of
    cert_service imports it inside a function, so a hard SyntaxError in it left
    /healthz at 200 and 757 tests green while the nightly cert renewal died.
    This check imports the lazy modules on purpose.
    """
    r = Result("ok", "diagnose python / venv")
    venv = ctx.app_dir / "venv" / "bin" / "python3"
    if not venv.exists():
        return _fail(Result("bad", "venv missing at %s" % venv),
                     "Rebuild it: sudo satom execute reinstall venv")
    rc, out, _ = run([str(venv), "-V"])
    r.rows("interpreter", [("venv python", out or "?"), ("path", str(venv))])
    rc, out, err = run([str(venv), "-m", "pip", "check"], timeout=120)
    r.lines("pip check", (out or err or "clean").splitlines()[:15])
    if rc != 0:
        r.worst("warn")

    # Compile the whole tree: catches SyntaxError anywhere, imports nothing.
    # In MEMORY, not with compileall: compileall writes __pycache__, and this
    # command frequently runs as root in a tree owned by the service account —
    # a diagnostic that leaves root-owned files behind is a diagnostic that
    # causes the drift the next check reports.
    checker = (
        "import pathlib, sys\n"
        "bad = []\n"
        "roots = [pathlib.Path(p) for p in sys.argv[1:]]\n"
        "for root in roots:\n"
        "    for f in root.rglob('*.py'):\n"
        "        if '__pycache__' in f.parts:\n"
        "            continue\n"
        "        try:\n"
        "            compile(f.read_bytes(), str(f), 'exec')\n"
        "        except Exception as exc:\n"
        "            bad.append('%s: %s: %s' % (f, type(exc).__name__, exc))\n"
        "print('COMPILE_OK' if not bad else 'COMPILE_BAD')\n"
        "[print(' ', b) for b in bad]\n")
    rc, out, err = run([str(venv), "-c", checker,
                        str(ctx.app_dir / "app"), str(ctx.app_dir / "deploy")],
                       timeout=180)
    if rc != 0 or "COMPILE_BAD" in out:
        _fail(r, "A module does not COMPILE. This is the class of failure that "
                 "hides behind a healthy /healthz — fix before anything else.")
        r.lines("compile", (out + "\n" + err).splitlines()[:25])
        return r
    r.rows("compile", [("app/ + deploy/", "all modules compile")])

    code = ("import importlib,sys\n"
            "from app import create_app\n"
            "a=create_app()\n"
            "bad=[]\n"
            "with a.app_context():\n"
            "    for m in %r:\n"
            "        try: importlib.import_module(m)\n"
            "        except Exception as e: bad.append('%%s: %%s: %%s'%%(m,type(e).__name__,e))\n"
            "print('LAZY_OK' if not bad else 'LAZY_BAD')\n"
            "[print(' ',b) for b in bad]\n" % (list(LAZY_MODULES),))
    env = dict(os.environ)
    for k, v in ctx.env.items():
        env.setdefault(k, v)
    # Importing writes bytecode too. Same reason as above.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    rc, out, err = run([str(venv), "-c", code], timeout=180,
                       cwd=str(ctx.app_dir), env=env)
    if "LAZY_OK" in out:
        r.rows("lazy-import smoke", [("%d modules" % len(LAZY_MODULES), "import cleanly")])
    else:
        _fail(r, "A lazily-imported module fails to import. Nothing in the web "
                 "app or the test suite would have told you.")
        r.lines("detail", (out + "\n" + err).splitlines()[:25])
    return r


def privilege(ctx, args):
    """Integrity of the CLI installation itself.

    The threat is concrete: if /usr/local/sbin/satom (or the package it loads)
    is writable by the service account, then a compromised web worker rewrites
    it and waits for an operator to type 'sudo satom'. That is instant root and
    it undoes the entire deprivilege work.
    """
    r = Result("ok", "diagnose privilege")
    launcher = Path("/usr/local/sbin/satom")
    home = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    rows = [("running as", "%s (uid %s)" % (ctx.user, ctx.uid)),
            ("service account", ctx.app_user),
            ("cli code loaded from", str(home))]

    if str(home).startswith(str(ctx.app_dir)):
        rows.append(("code location", "INSIDE the app tree"))
        _fail(r, "The CLI is running from %s, which is writable by '%s'. A "
                 "compromised web worker could rewrite the code you run with "
                 "sudo. Reinstall the root-owned copy: "
                 "sudo bash %s/deploy/install-cli.sh"
                 % (home, ctx.app_user, ctx.app_dir))
    else:
        rows.append(("code location", "outside the app tree (correct)"))

    for p in (launcher, home):
        if not p.exists():
            rows.append((str(p), "MISSING"))
            r.worst("warn")
            continue
        st = p.stat()
        try:
            import pwd as _pwd
            owner = _pwd.getpwuid(st.st_uid).pw_name
        except Exception:  # noqa: BLE001
            owner = str(st.st_uid)
        world_or_group_writable = bool(st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
        rows.append((str(p), "owner=%s mode=%s%s" % (
            owner, oct(st.st_mode & 0o777),
            "  GROUP/WORLD-WRITABLE" if world_or_group_writable else "")))
        if owner != "root" or world_or_group_writable:
            _fail(r, "%s must be root-owned and not group/world writable." % p)
        if p.is_symlink():
            _fail(r, "%s is a SYMLINK. The sudo target must be a fixed real path." % p)
    r.rows("", rows)

    rc, out, _ = run(["sudo", "-n", "-l"]) if ctx.have("sudo") else (1, "", "")
    if out:
        r.lines("your sudo rights", out.splitlines()[-12:])

    sd = Path("/etc/sudoers.d/satom")
    if sd.exists():
        try:
            body = sd.read_text()
            r.lines("/etc/sudoers.d/satom (service account)", body.strip().splitlines())
            if "satom" in body and "/usr/local/sbin/satom" in body:
                _fail(r, "The SERVICE ACCOUNT has been granted the satom CLI. "
                         "That is equivalent to NOPASSWD: ALL for the web worker. "
                         "Remove that line.")
        except Exception:  # noqa: BLE001
            r.note("/etc/sudoers.d/satom exists but is unreadable as %s." % ctx.user)
    return r


def network(ctx, args):
    r = Result("ok", "diagnose network")
    rows = []
    for port, what in ((80, "nginx http/ACME"), (443, "nginx app"),
                       (8443, "peer probes"), (8000, "gunicorn"), (5432, "postgres")):
        rc, out, _ = run(["ss", "-lnt", "sport = :%d" % port])
        listening = len(out.splitlines()) > 1
        rows.append(("%-5d %s" % (port, what), "listening" if listening else "closed"))
        if port in (443, 8000) and not listening:
            r.worst("bad")
    r.rows("ports", rows)
    if ctx.have("nginx"):
        rc, out, err = run(["nginx", "-t"])
        r.lines("nginx -t", (err or out).splitlines())
        if rc != 0:
            _fail(r, "nginx config is invalid — it will NOT survive a reload.")
    code, _ = ctx.http("https://127.0.0.1/healthz")
    r.rows("app", [("GET https://127.0.0.1/healthz", code or "unreachable")])
    if code != 200:
        r.worst("bad")
    return r


def certificate(ctx, args):
    from . import cmd_get
    r = cmd_get.certificate_status(ctx, args)
    r.title = "diagnose certificate"
    code, _ = ctx.http("https://127.0.0.1/healthz")
    r.rows("served", [("TLS handshake on :443", "ok" if code else "failed")])
    if not code:
        r.worst("bad")
    st = ctx.unit_state("cert-renew")
    r.rows("renew timer", [("state", "%s/%s" % (st["active"], st["sub"])),
                           ("last result", st["result"])])
    if st["result"] not in ("success", "-", ""):
        _fail(r, "The nightly renewal timer last exited with result=%s. Its "
                 "failures used to be invisible until the T-14 expiry email; "
                 "the journal is at state/cert-renew.jsonl." % st["result"])
    return r


def peer(ctx, args):
    from . import cmd_get
    r = cmd_get.node_status(ctx, args)
    r.title = "diagnose peer"
    key = ctx.app_dir / ".ssh" / "id_ha_rsync"
    if key.exists():
        st = key.stat()
        r.rows("datasync key", [("path", str(key)), ("mode", oct(st.st_mode & 0o777))])
        if st.st_mode & 0o077:
            _fail(r, "The datasync private key is group/world readable.")
    else:
        r.rows("datasync key", [("path", "absent (normal on a primary)")])
    dst = ctx.unit_state("datasync")
    r.rows("datasync timer", [("state", "%s/%s" % (dst["active"], dst["sub"])),
                              ("last result", dst["result"])])
    return r


def all_checks(ctx, args):
    """Everything, folded into one exit code. The command to run before saying
    a node is healthy — and the one to paste into a ticket."""
    r = Result("ok", "diagnose all — %s (%s)" % (ctx.host, ctx.role))
    from . import cmd_checks as k
    from . import cmd_get
    from . import cmd_ops as o
    # Ordered cheapest-and-most-decisive first: an operator who reads only the
    # top of the output should already know whether the node is armed.
    checks = (
        ("health", cmd_get.system_health),
        ("install", k.install),
        ("config", k.config),
        ("units", k.units),
        ("code", k.code),
        ("network", network),
        ("nginx", k.nginx),
        ("database", database),
        ("certificate", certificate),
        ("acme", k.acme),
        ("peer", peer),
        ("privilege", privilege),
        ("updates", _updates),
        ("python", python),
        ("scheduler", k.scheduler),
        ("backups", o.backup_status),
        ("alerting", o.alerts_status),
        ("disk", o.system_disk),
        ("time", o.system_time),
        ("timers", o.timer_status),
        ("git", k.git),
        ("recovery", k.recovery),
        ("jobs", o.job_list),
        ("devices", o.device_status),
        ("monitors", o.monitor_status),
        ("users", o.user_list),
    )
    rows = []
    for name, fn in checks:
        try:
            sub = fn(ctx, [])
            rows.append((name, {"ok": "pass", "info": "pass", "warn": "WARN",
                                "bad": "FAIL"}.get(sub.status, sub.status)))
            r.worst(sub.status)
            # Only from checks that are NOT clean: a note under a passing check
            # is context, and context repeated 24 times is noise that buries
            # the two lines that were findings.
            if sub.status in ("warn", "bad"):
                for n in sub.notes:
                    r.note("[%s] %s" % (name, n))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, "ERROR: %s" % exc))
            r.worst("bad")
    r.rows("checks", rows)
    r.lines("next", ["Re-run any failing check on its own for the full detail,",
                     "e.g.  satom diagnose python"])
    return r


def _updates(ctx, args):
    """The offline-update path, folded into 'diagnose all'."""
    from . import cmd_trust
    return cmd_trust.diagnose_updates(ctx, args)
