"""Additional 'execute' verbs. STDLIB ONLY (see context.py). ALL require root.

Same two rules as cmd_execute.py: delegate to the app anything the app already
knows how to do (a second writer of a schema is a schema that drifts), and do
in this root process only what the service account deliberately cannot do —
never by widening its sudoers.

One rule of its own: anything that DELETES or REPLACES state prints the plan
and exits 2 unless it is given ``--yes``. The confirmation is not ceremony; it
is the difference between a recovery tool and a footgun on a node that is
already having a bad day.
"""
import getpass
import io
import json
import os
import re
import secrets
import shutil
import string
import tarfile
import tempfile
import time
from contextlib import redirect_stdout
from pathlib import Path

from . import cmd_checks, cmd_ops, dbq
from .cmd_checks import NGINX_VHOST_DIRS, satom_vhosts
from .context import UNITS, run
from .cmd_execute import _app_call
from .render import Result

# Units an operator may enable/disable. Timers and paths only: these are the
# switches that silently strand automation when they are off, which is exactly
# the class of fault this CLI is for.
TOGGLEABLE = ("updater", "alerts", "cert-renew", "datasync")

SEED_PLAN = [
    ("device_sync", "Hourly fleet sync (source of truth)", "interval",
     {"every": 60, "unit": "minutes"}, {}, "fortiweb"),
    ("device_inspect", "Nightly SoT snapshot + off-box push (all devices)", "daily",
     {"time": "02:45"}, {}, "fortiweb"),
    ("system_backup", "Nightly system backup (Postgres + JSON -> server)", "daily",
     {"time": "01:30"}, {"push_server": True}, "fortiweb"),
    ("deep_monitor", "Deep monitors + Service Monitor — probe sweep", "interval",
     {"every": 3, "unit": "minutes"}, {}, "global"),
    ("metrics_scrape", "Fleet metrics — scrape to the local store", "interval",
     {"every": 3, "unit": "minutes"}, {}, "global"),
    # Period summaries. Each fires AFTER its period has closed, so it describes
    # a COMPLETE window: a daily report fired at 23:00 would summarise a day
    # still an hour from finishing, and "throughput fell 80 %" would mean
    # nothing. `keep` bounds the stored history — without it a daily schedule
    # accumulates one row a day forever.
    ("monitor_report", "Daily monitoring report", "daily",
     {"time": "02:00"}, {"period": "daily", "email": True, "push_server": True, "keep": 90}, "global"),
    ("monitor_report", "Weekly monitoring report", "weekly",
     {"weekday": 0, "time": "02:10"},
     {"period": "weekly", "email": True, "push_server": True, "keep": 53}, "global"),
    ("monitor_report", "Monthly monitoring report", "monthly",
     {"day": 1, "time": "02:20"},
     {"period": "monthly", "email": True, "push_server": True, "keep": 36}, "global"),
]


def _yes(args):
    return "--yes" in args


def _opt_int(args, flag, default):
    try:
        return int(args[args.index(flag) + 1])
    except (ValueError, IndexError):
        return default


def _app_stdin(ctx, code, payload, timeout=120):
    """Run a snippet in the app venv, handing it its argument on STDIN.

    Secrets and operator-supplied names never go in argv: argv lands in the
    shell history and is world-readable in /proc for the lifetime of the call.
    """
    venv = ctx.app_dir / "venv" / "bin" / "python3"
    if not venv.exists():
        return 127, "", "venv missing at %s" % venv
    env = dict(os.environ)
    for k, v in ctx.env.items():
        env.setdefault(k, v)
    return run([str(venv), "-c", code], timeout=timeout, cwd=str(ctx.app_dir),
               env=env, input_=payload)


# -- unit switches ---------------------------------------------------------
def _toggle(ctx, args, action):
    if not args or args[0] not in TOGGLEABLE:
        r = Result("bad", "usage: execute %s <unit>" % action, exit_code=2)
        r.lines("toggleable units", sorted(TOGGLEABLE))
        r.note("Only timers and .path units. Services are start/stop/restart.")
        return r
    alias = args[0]
    if action == "disable" and alias == "updater":
        r = Result("bad", "refusing to disable the privileged runner", exit_code=1)
        r.lines("why", [
            "satom-updater.path is what turns an enqueued update into work.",
            "Disabled, every request sits at 'queued' forever and NOTHING",
            "reports an error — the exact failure this CLI exists to surface.",
            "If you really must, do it with systemctl and write down why.",
        ])
        return r
    unit = ctx.unit(alias)
    extra = ["--now"] if action == "enable" else []
    rc, out, err = run(["systemctl", action] + extra + [unit], timeout=60)
    st = ctx.unit_state(alias)
    r = Result("ok" if rc == 0 else "bad", "%s %s" % (action, unit))
    r.rows("", [("unit file state", st["enabled"]),
                ("active", "%s/%s" % (st["active"], st["sub"]))])
    if rc != 0:
        r.lines("error", (err or out).splitlines()[:8])
        return r
    if alias == "updater" and action == "enable":
        r.note("Enable it on BOTH nodes. A standby with this disabled accepts "
               "updates and never applies them.")
    return r


def enable(ctx, args):
    return _toggle(ctx, args, "enable")


def disable(ctx, args):
    return _toggle(ctx, args, "disable")


def restart_all(ctx, args):
    """Restart the application stack in dependency order and verify."""
    from .cmd_execute import _systemctl
    r = Result("ok", "restart the application stack")
    rows = []
    for alias in ("web", "scheduler", "reconciler"):
        st = ctx.unit_state(alias)
        if st["enabled"] == "not-found":
            rows.append((alias, "not installed — skipped"))
            continue
        sub = _systemctl(ctx, "restart", alias)
        rows.append((alias, sub.status))
        r.worst(sub.status)
        for n in sub.notes:
            r.note("[%s] %s" % (alias, n))
    rc, out, err = run(["nginx", "-t"])
    if rc == 0:
        run(["systemctl", "reload", "nginx"])
        rows.append(("nginx", "reloaded"))
    elif rc != 127:
        rows.append(("nginx", "config INVALID — not reloaded"))
        r.worst("bad")
    r.rows("", rows)
    code_, _ = ctx.http("https://127.0.0.1/healthz", timeout=8)
    r.rows("verify", [("GET /healthz via nginx", code_ or "no answer")])
    if code_ != 200:
        r.worst("bad")
    return r


# -- arming a node ---------------------------------------------------------
_SEED_CODE = """
import json, sys
from app import create_app
from app.models import ScheduledAction
from app.extensions import db
from app.services.scheduler import compute_next_run
plan = json.loads(sys.stdin.read())
apply_ = plan.pop("apply")
out = {"created": [], "existing": []}
app = create_app()
with app.app_context():
    # Identity is (action, schedule_kind), not the action alone: `monitor_report`
    # is seeded three times and its rows differ only by their schedule. Keying on
    # the action would arm one period and report the other two as already
    # present. A rename by the operator still matches, which the name would not.
    have = {(row.action, row.schedule_kind) for row in ScheduledAction.query.all()}
    for key, name, kind, sched, params, product in plan["rows"]:
        if (key, kind) in have:
            out["existing"].append(name)
            continue
        have.add((key, kind))
        out["created"].append(name)
        if not apply_:
            continue
        row = ScheduledAction(
            name=name, scope="admin", product=product, action=key,
            targets="[]", params=json.dumps(params), schedule_kind=kind,
            schedule=json.dumps(sched), enabled=True, catch_up=True,
            created_by="cli")
        row.next_run = compute_next_run(kind, sched)
        db.session.add(row)
    if apply_:
        db.session.commit()
print(json.dumps(out))
"""


def seed_actions(ctx, args):
    """Create the minimum set of scheduled actions a node needs to defend itself.

    Nothing seeds these — not the installer, not create-db, not a boot hook —
    because ScheduledAction rows are DATA and operator edits win over code
    defaults in this product. The consequence is that a brand-new node has
    every capability and zero coverage, and looks perfectly healthy while it
    takes no backups at all.
    """
    if ctx.role == "standby":
        r = Result("bad", "refusing: this node is the standby", exit_code=1)
        r.note("Its Postgres is a read-only replica. Seed on the primary; "
               "streaming replication carries the rows here.")
        return r
    apply_ = _yes(args)
    payload = json.dumps({"apply": apply_, "rows": SEED_PLAN})
    rc, out, err = _app_stdin(ctx, _SEED_CODE, payload, timeout=180)
    if rc != 0:
        r = Result("bad", "could not read the action catalogue", exit_code=4)
        r.lines("error", (err or out).splitlines()[-12:])
        return r
    try:
        res = json.loads(out.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        r = Result("bad", "unexpected output from the app", exit_code=4)
        r.lines("output", (out or err).splitlines()[-12:])
        return r
    created, existing = res.get("created", []), res.get("existing", [])
    if not created:
        r = Result("ok", "already armed — all %d actions exist" % len(existing))
        r.lines("present", existing)
        return r
    if not apply_:
        r = Result("warn", "%d action(s) would be created" % len(created), exit_code=2)
        r.rows("plan", [(n, dict((p[1], "%s %s" % (p[2], p[3])) for p in SEED_PLAN)
                         .get(n, "")) for n in created])
        if existing:
            r.lines("already present", existing)
        r.lines("apply", ["  sudo satom execute seed actions --yes"])
        r.note("Nothing has been changed. Existing rows are never touched — "
               "your edits win, this only fills gaps.")
        return r
    r = Result("ok", "created %d scheduled action(s)" % len(created))
    r.lines("created", created)
    if existing:
        r.lines("left alone", existing)
    r.note("They fire from satom-scheduler on the PRIMARY. Confirm with "
           "'satom diagnose scheduler'.")
    return r


# -- backups and restore ---------------------------------------------------
def backup_git(ctx, args):
    """git bundle --all — includes the refs/backup/* the update runner parks."""
    code = ("from app import create_app\n"
            "from app.services import git_backup\n"
            "a=create_app()\n"
            "with a.app_context():\n"
            "    print(git_backup.create_bundle(label='cli'))\n")
    rc, out, err = _app_call(ctx, code, timeout=1800)
    r = Result("ok" if rc == 0 else "bad", "git repository bundle")
    r.lines("", (out or err).splitlines()[-14:])
    if rc != 0:
        return r
    if ctx.role == "standby":
        r.note("Bundle deletions are primary-only: the primary's rsync "
               "--delete would resurrect anything removed here.")
    return r


_RESTORE_CODE = """
import json, sys
from app import create_app
from app.services import system_backup as sb
arg = json.loads(sys.stdin.read())
app = create_app()
with app.app_context():
    print(json.dumps(sb.restore_backup(arg["name"], restore_reports=arg["reports"])))
"""


def restore_db(ctx, args):
    """Replace the application database from a bundle. Heavily gated.

    The extraction, the safety bundle and the pg_restore are the APP's
    (``system_backup.restore_backup``) — a second implementation of the bundle
    format is a format that drifts, and the app's version already takes its own
    safety copy first. What the CLI adds is the part a web request cannot do:
    stopping the writers around the restore and verifying the node afterwards.
    Restoring underneath a live gunicorn is how you get a half-migrated schema
    served to users.
    """
    if not args:
        r = Result("bad", "usage: execute restore db <bundle> --yes", exit_code=2)
        r.lines("available bundles", ["  satom get backup list"])
        return r
    if ctx.role == "standby":
        r = Result("bad", "refusing: this node is the standby", exit_code=1)
        r.note("Its Postgres is a read-only replica — a restore cannot be "
               "written here. Restore on the primary and let streaming "
               "replication carry it over.")
        return r
    name = Path(args[0]).name          # basename only: the app resolves it
    src = ctx.app_dir / "data" / "system_backups" / name
    if not name.startswith("fmw-backup-") or not src.is_file():
        r = Result("bad", "no such bundle: %s" % name, exit_code=2)
        r.lines("available bundles", ["  satom get backup list"])
        return r
    keep_reports = "--no-reports" not in args
    if not _yes(args):
        r = Result("warn", "restore requires explicit confirmation", exit_code=2)
        r.rows("would restore", [
            ("bundle", name),
            ("size", "%.1f MB" % (src.stat().st_size / 1e6)),
            ("node", "%s (%s)" % (ctx.host, ctx.role)),
            ("reports/", "restored too" if keep_reports else "left alone (--no-reports)"),
        ])
        r.lines("what happens", [
            "1. the app takes its own safety bundle of the CURRENT state",
            "2. stop web, scheduler, reconciler",
            "3. extract the bundle and pg_restore --clean",
            "4. start them again and verify /healthz",
            "",
            "Re-run:  sudo satom execute restore db %s --yes" % name,
        ])
        return r

    r = Result("ok", "restore %s" % name)
    steps = []
    stopped = []
    for alias in ("web", "scheduler", "reconciler"):
        if ctx.unit_state(alias)["active"] == "active":
            run(["systemctl", "stop", ctx.unit(alias)], timeout=120)
            stopped.append(alias)
    steps.append(("stopped", ", ".join(stopped) or "(none were running)"))

    rc, out, err = _app_stdin(ctx, _RESTORE_CODE,
                              json.dumps({"name": name, "reports": keep_reports}),
                              timeout=3600)
    res = {}
    if rc == 0:
        try:
            res = json.loads(out.strip().splitlines()[-1])
        except Exception:  # noqa: BLE001
            res = {}
    restore_ok = bool(res.get("ok"))
    steps.append(("restore", res.get("detail", "") if res else "FAILED to run"))
    if res.get("safety"):
        steps.append(("safety bundle", res["safety"]))

    for alias in stopped:
        run(["systemctl", "start", ctx.unit(alias)], timeout=180)
    steps.append(("restarted", ", ".join(stopped) or "(none)"))

    code_ = 0
    deadline = time.time() + 45
    while time.time() < deadline:
        code_, _ = ctx.http("http://127.0.0.1:8000/healthz", timeout=4)
        if code_ == 200:
            break
        time.sleep(2)
    steps.append(("GET /healthz", str(code_ or "no answer within 45s")))
    r.rows("steps", steps)
    if not restore_ok:
        r.status = "bad"
        r.lines("output", ((res.get("stderr") or "") or (err or out)).splitlines()[-20:])
        r.note("The services were started again regardless — you are not left "
               "with a stopped node. Roll back with the safety bundle above.")
    elif code_ != 200:
        r.status = "bad"
        r.note("The data was restored but the app is not answering. "
               "'satom diagnose python' — a schema older than the code fails "
               "at import time, not at query time.")
    else:
        r.note("Rollback point if this restore was wrong: %s"
               % (res.get("safety") or "(the safety bundle the app just took)"))
    return r


# -- reclaiming space ------------------------------------------------------
def repair_nginx(ctx, args):
    """Bring an installed vhost to the shape the installer now emits.

    Exists because the vhost is NOT in git: a node updates its code and keeps
    serving whatever configuration its installer built. Without this verb the
    only fix is a hand edit, and a hand edit is erased by the next reinstall --
    which is exactly how this defect survived being diagnosed twice.
    """
    r = Result("ok", "execute repair nginx")
    targets = satom_vhosts()
    if not targets:
        r.worst("warn")
        r.rows("", [("vhost", "none found under " + ", ".join(NGINX_VHOST_DIRS))])
        return r

    rc, fqdn, _ = run(["hostname", "-f"])
    fqdn = (fqdn or "").strip().lower().rstrip(".")
    if rc != 0 or "." not in fqdn:
        fqdn = ""

    plan, staged = [], []
    for path, txt in targets:
        new = re.sub(r"(proxy_set_header\s+Host\s+)\$host\s*;",
                     r"\1$http_host;", txt)
        if new != txt:
            plan.append((str(path), "Host $host -> $http_host"))
        if fqdn:
            def _add(m, _path=path):
                indent, names = m.group(1), m.group(2)
                toks = [x.lower().rstrip(".") for x in names.split()]
                # `server_name _;` is the ACME catch-all. Adding a name there
                # would turn a deliberate catch-all into a named vhost and
                # change which server wins the port -- left alone on purpose.
                if toks == ["_"] or fqdn in toks:
                    return m.group(0)
                plan.append((str(_path), "server_name += " + fqdn))
                return "%sserver_name %s %s;" % (indent, names.strip(), fqdn)
            new = re.sub(r"^([ \t]*)server_name\s+([^;]+);", _add, new, flags=re.M)
        if new != txt:
            staged.append((path, txt, new))

    # Un mismo fichero puede tener varios bloques server; el operador quiere
    # saber QUE cambia, no cuantas veces.
    seen, uniq = set(), []
    for row in plan:
        if row not in seen:
            seen.add(row)
            uniq.append(row)
    plan = uniq

    if not plan:
        r.rows("", [("state", "already correct - nothing to repair")])
        return r
    if "--yes" not in args:
        out = Result("warn", "execute repair nginx", exit_code=2)
        out.rows("plan", plan)
        out.lines("apply", ["  sudo satom execute repair nginx --yes"])
        out.note("Nothing written.")
        return out
    r.rows("plan", plan)

    stamp = time.strftime("%Y%m%d-%H%M%S")
    backups = []
    for path, old, new in staged:
        bak = Path("/root") / ("%s.pre-repair-nginx-%s" % (path.name, stamp))
        bak.write_text(old)
        backups.append((path, old, bak))
        path.write_text(new)
    rc, out_, err = run(["nginx", "-t"])
    if rc != 0:
        # Restaurar SIEMPRE antes de reportar: dejar una config invalida en
        # disco convierte el siguiente reload ajeno en una caida.
        for path, old, _bak in backups:
            path.write_text(old)
        r.status = "bad"
        r.lines("nginx -t FAILED - every file restored",
                (err or out_).splitlines()[:10])
        return r
    r.rows("backups", [(str(b), "saved") for _p, _o, b in backups])
    rc, out_, err = run(["systemctl", "reload", "nginx"])
    r.rows("reload", [("systemctl reload nginx",
                       "ok" if rc == 0 else (err or "failed").strip())])
    if rc != 0:
        r.worst("warn")
    return r


def repair_tmp(ctx, args):
    """Delete aged scratch under data/tmp. Nothing else prunes it."""
    days = _opt_int(args, "--older-than", 7)
    d = ctx.app_dir / "data" / "tmp"
    if not d.is_dir():
        return Result("ok", "no data/tmp on this node")
    cutoff = time.time() - days * 86400
    victims, total = [], 0
    try:
        for p in d.iterdir():
            try:
                if p.stat().st_mtime >= cutoff:
                    continue
                size = 0
                if p.is_dir():
                    for q in p.rglob("*"):
                        if q.is_file():
                            size += q.stat().st_size
                else:
                    size = p.stat().st_size
                victims.append((p, size))
                total += size
            except OSError:
                continue
    except Exception as exc:  # noqa: BLE001
        return Result("bad", "cannot read %s: %s" % (d, exc), exit_code=4)
    if not victims:
        return Result("ok", "nothing under %s is older than %d days" % (d, days))
    if not _yes(args):
        r = Result("warn", "%d entries (%.1f MB) older than %d days"
                   % (len(victims), total / 1e6, days), exit_code=2)
        r.lines("oldest", [p.name for p, _ in sorted(
            victims, key=lambda x: x[0].stat().st_mtime)[:10]])
        r.lines("apply", ["  sudo satom execute repair tmp --older-than %d --yes" % days])
        return r
    removed, failed = 0, 0
    for p, _s in victims:
        try:
            shutil.rmtree(p) if p.is_dir() else p.unlink()
            removed += 1
        except Exception:  # noqa: BLE001
            failed += 1
    r = Result("ok" if not failed else "warn", "reclaimed %.1f MB" % (total / 1e6))
    r.rows("", [("removed", removed), ("failed", failed), ("older than", "%d days" % days)])
    if ctx.role == "standby":
        r.note("The primary's rsync --delete will re-create anything it still "
               "holds. Prune the primary if you want it gone from both.")
    return r


def repair_jobs(ctx, args):
    """Sweep ghost jobs and prune the terminated ledger."""
    days = _opt_int(args, "--older-than", 7)
    before = cmd_ops.job_list(ctx, [])
    ghosts = before.data.get("ghosts", 0)
    total = before.data.get("total", 0)
    if not _yes(args):
        r = Result("warn", "ledger: %d records, %d ghost" % (total, ghosts), exit_code=2)
        r.lines("would", [
            "sweep ghost jobs (pending, no pid, older than 10 minutes)",
            "delete terminated job records older than %d days" % days,
            "",
            "  sudo satom execute repair jobs --older-than %d --yes" % days,
        ])
        r.note("A ghost keeps the dock's toast open with a Stop button that "
               "cannot work — which teaches the operator that the dock lies.")
        return r
    code = ("from app import create_app\n"
            "from app.services import jobs\n"
            "a=create_app()\n"
            "with a.app_context():\n"
            "    swept=jobs.sweep_orphans(no_pid_stale_after_s=600)\n"
            "    pruned=jobs.prune(older_than_days=%d)\n"
            "    print('%%d %%d' %% (len(swept), pruned))\n" % days)
    rc, out, err = _app_call(ctx, code, timeout=300)
    if rc != 0:
        r = Result("bad", "sweep failed", exit_code=4)
        r.lines("error", (err or out).splitlines()[-10:])
        return r
    swept, pruned = (out.strip().split() + ["?", "?"])[:2]
    r = Result("ok", "job ledger repaired")
    r.rows("", [("ghosts swept", swept), ("records pruned", pruned),
                ("before", "%d records" % total)])
    return r


# -- accounts --------------------------------------------------------------
_PW_CODE = """
import json, sys
from app import create_app
from app.models import User
from app.extensions import db
arg = json.loads(sys.stdin.read())
app = create_app()
with app.app_context():
    u = User.query.filter_by(username=arg["user"]).first()
    if not u:
        print(json.dumps({"error": "no such user"}))
    else:
        if arg.get("password"):
            u.set_password(arg["password"])
        u.failed_logins = 0
        u.locked_until = None
        u.is_active = True
        db.session.commit()
        print(json.dumps({"ok": True, "role": u.role,
                          "auth_source": u.auth_source or "local"}))
"""


def _account_write(ctx, username, password=None):
    payload = json.dumps({"user": username, "password": password})
    rc, out, err = _app_stdin(ctx, _PW_CODE, payload, timeout=120)
    if rc != 0:
        return None, (err or out)
    try:
        return json.loads(out.strip().splitlines()[-1]), ""
    except Exception:  # noqa: BLE001
        return None, (out or err)


def admin_reset_password(ctx, args):
    """Set a local account's password, clear its lockout, re-activate it."""
    if not args:
        r = Result("bad", "usage: execute admin reset-password <username>", exit_code=2)
        r.lines("accounts", ["  satom get user list"])
        return r
    username = args[0]
    if os.isatty(0):
        pw1 = getpass.getpass("New password for %s: " % username)
        pw2 = getpass.getpass("Repeat: ")
        if pw1 != pw2:
            return Result("bad", "the two entries differ — nothing changed", exit_code=2)
        if len(pw1) < 12:
            return Result("bad", "refusing a password shorter than 12 characters",
                          exit_code=2)
        generated = False
    else:
        alphabet = string.ascii_letters + string.digits + "!@#%^*-_=+"
        pw1 = "".join(secrets.choice(alphabet) for _ in range(20))
        generated = True
    res, err = _account_write(ctx, username, pw1)
    if res is None:
        r = Result("bad", "could not update the account", exit_code=4)
        r.lines("error", err.splitlines()[-10:])
        return r
    if res.get("error"):
        return Result("bad", "%s: %s" % (username, res["error"]), exit_code=1)
    r = Result("ok", "password reset for %s" % username)
    r.rows("", [("role", res.get("role", "?")),
                ("auth source", res.get("auth_source", "local")),
                ("lockout", "cleared"), ("active", "yes")])
    if generated:
        r.lines("generated password (shown once)", [pw1])
        r.note("No TTY, so a password was generated. It is printed here and "
               "nowhere else — it never went through argv, which would have "
               "landed it in your shell history and in /proc.")
    if (res.get("auth_source") or "local") != "local":
        r.worst("warn")
        r.note("This account authenticates against the external IdP, so the "
               "local password may not be what the login form checks.")
    return r


def admin_unlock(ctx, args):
    """Clear a lockout without touching the password."""
    if not args:
        r = Result("bad", "usage: execute admin unlock <username>", exit_code=2)
        r.lines("accounts", ["  satom get user list"])
        return r
    res, err = _account_write(ctx, args[0], None)
    if res is None:
        r = Result("bad", "could not update the account", exit_code=4)
        r.lines("error", err.splitlines()[-10:])
        return r
    if res.get("error"):
        return Result("bad", "%s: %s" % (args[0], res["error"]), exit_code=1)
    r = Result("ok", "unlocked %s" % args[0])
    r.rows("", [("failed logins", "0"), ("locked until", "cleared"), ("active", "yes")])
    return r


# -- scheduled actions and devices ----------------------------------------
_ACTION_CODE = """
import json, sys
from app import create_app
from app.models import ScheduledAction
from app.extensions import db
from app.services import scheduled_actions as sa
arg = json.loads(sys.stdin.read())
app = create_app()
with app.app_context():
    row = ScheduledAction.query.get(arg["id"])
    if not row:
        print(json.dumps({"error": "no action with id %s" % arg["id"]}))
    elif arg["op"] in ("enable", "disable"):
        row.enabled = (arg["op"] == "enable")
        db.session.commit()
        print(json.dumps({"ok": True, "name": row.name, "enabled": row.enabled}))
    else:
        run = sa.execute_and_record(row, trigger="manual")
        print(json.dumps({"ok": True, "name": row.name,
                          "status": getattr(run, "status", "?"),
                          "summary": (getattr(run, "summary", "") or "")[:400]}))
"""


def _action_op(ctx, args, op, verb):
    if not args or not args[0].isdigit():
        r = Result("bad", "usage: execute scheduler %s <action-id>" % verb, exit_code=2)
        r.lines("ids", ["  satom get scheduler status"])
        return r
    rc, out, err = _app_stdin(ctx, _ACTION_CODE,
                              json.dumps({"id": int(args[0]), "op": op}), timeout=1800)
    if rc != 0:
        r = Result("bad", "action %s failed" % verb, exit_code=4)
        r.lines("error", (err or out).splitlines()[-12:])
        return r
    try:
        res = json.loads(out.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        r = Result("bad", "unexpected output", exit_code=4)
        r.lines("output", (out or err).splitlines()[-12:])
        return r
    if res.get("error"):
        return Result("bad", res["error"], exit_code=1)
    if op in ("enable", "disable"):
        return Result("ok", "%s: %s" % (verb, res.get("name", "?")))
    status = res.get("status", "?")
    r = Result("ok" if status in ("ok", "skipped") else "bad",
               "ran %s — %s" % (res.get("name", "?"), status))
    r.lines("summary", [res.get("summary", "") or "(no summary)"])
    r.note("This was a MANUAL run: parked devices are included on purpose, and "
           "it does not prove the scheduled path works. If manual passes and "
           "scheduled fails, the sidecar is on older code — 'diagnose code'.")
    return r


def scheduler_run(ctx, args):
    return _action_op(ctx, args, "run", "run")


def scheduler_enable(ctx, args):
    return _action_op(ctx, args, "enable", "enable")


def scheduler_disable(ctx, args):
    return _action_op(ctx, args, "disable", "disable")


_MAINT_CODE = """
import json, sys
from app import create_app
from app.models import Appliance
from app.extensions import db
arg = json.loads(sys.stdin.read())
app = create_app()
with app.app_context():
    row = Appliance.query.filter_by(name=arg["name"]).first()
    if not row:
        print(json.dumps({"error": "no appliance named %s" % arg["name"]}))
    else:
        row.maintenance = arg["on"]
        db.session.commit()
        print(json.dumps({"ok": True, "name": row.name, "maintenance": row.maintenance}))
"""


def maintenance(ctx, args):
    """Park or un-park an appliance."""
    if len(args) < 2 or args[1] not in ("on", "off"):
        r = Result("bad", "usage: execute maintenance <device> <on|off>", exit_code=2)
        r.lines("devices", ["  satom get device status"])
        return r
    rc, out, err = _app_stdin(ctx, _MAINT_CODE,
                              json.dumps({"name": args[0], "on": args[1] == "on"}))
    if rc != 0:
        r = Result("bad", "could not update the appliance", exit_code=4)
        r.lines("error", (err or out).splitlines()[-10:])
        return r
    try:
        res = json.loads(out.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        return Result("bad", "unexpected output from the app", exit_code=4)
    if res.get("error"):
        return Result("bad", res["error"], exit_code=1)
    on = res.get("maintenance")
    r = Result("ok", "%s: maintenance %s" % (res.get("name"), "ON" if on else "OFF"))
    r.lines("effect", [
        "AUTOMATIC runs skip this device and its health alerts are suppressed.",
        "A MANUAL run still reaches it — parking a box is usually the prelude",
        "to working on it.",
    ] if on else ["It is back in the hourly sweep and can alert again."])
    return r


# -- support bundle --------------------------------------------------------
def support_bundle(ctx, args):
    """Collect everything a diagnosis needs into one file.

    Written where the app tree is not: a support bundle that lands inside a
    directory being rsync'd to the peer, or inside git, is a support bundle
    that replicates. Mode 0600 because it contains journals and configuration.
    """
    from . import cmd_diagnose, cmd_get, cmd_show
    ts = time.strftime("%Y%m%d-%H%M%S")
    dest = Path("/var/tmp/satom-support-%s-%s.tar.gz" % (ctx.host, ts))
    probes = [
        ("system-status", cmd_get.system_status), ("health", cmd_get.system_health),
        ("performance", cmd_get.system_performance), ("interface", cmd_get.system_interface),
        ("node", cmd_get.node_status), ("database", cmd_get.database_status),
        ("certificate", cmd_get.certificate_status), ("disk", cmd_ops.system_disk),
        ("time", cmd_ops.system_time), ("timers", cmd_ops.timer_status),
        ("backups", cmd_ops.backup_status), ("scheduler-actions", cmd_ops.scheduler_status),
        ("devices", cmd_ops.device_status), ("monitors", cmd_ops.monitor_status),
        ("jobs", cmd_ops.job_list), ("git", cmd_ops.git_status),
        ("users", cmd_ops.user_list), ("alerts", cmd_ops.alerts_status),
        ("updates", cmd_ops.update_history), ("certificates", cmd_ops.certificate_list),
        ("diag-network", cmd_diagnose.network), ("diag-database", cmd_diagnose.database),
        ("diag-python", cmd_diagnose.python), ("diag-privilege", cmd_diagnose.privilege),
        ("diag-peer", cmd_diagnose.peer), ("diag-certificate", cmd_diagnose.certificate),
        ("diag-scheduler", cmd_checks.scheduler), ("diag-code", cmd_checks.code),
        ("diag-units", cmd_checks.units), ("diag-config", cmd_checks.config),
        ("diag-nginx", cmd_checks.nginx), ("diag-git", cmd_checks.git),
        ("diag-acme", cmd_checks.acme), ("diag-install", cmd_checks.install),
        ("show-config", cmd_show.config), ("show-units", cmd_show.units),
        ("show-version", cmd_show.version),
    ]
    tmp = Path(tempfile.mkdtemp(prefix="satom-support-"))
    collected, failed = 0, []
    try:
        from .render import render
        plain = type("P", (), {"json_mode": False, "quiet": True})()
        for name, fn in probes:
            buf = io.StringIO()
            try:
                with redirect_stdout(buf):
                    render(fn(ctx, []), plain)
                (tmp / ("%s.txt" % name)).write_text(buf.getvalue())
                collected += 1
            except Exception as exc:  # noqa: BLE001
                failed.append("%s: %s" % (name, exc))
        for alias in sorted(UNITS):
            (tmp / ("journal-%s.log" % alias)).write_text(ctx.journal(alias, 400))
        for cmd, out_name in (
                (["systemctl", "list-units", "--failed", "--no-pager"], "failed-units.txt"),
                (["systemctl", "list-timers", "--all", "--no-pager"], "timers.txt"),
                (["df", "-hP"], "df.txt"), (["free", "-m"], "free.txt"),
                (["ip", "-brief", "address"], "ip.txt"),
                (["ss", "-lntp"], "listening.txt"),
                (["nginx", "-T"], "nginx-full.txt"),
                (["uname", "-a"], "uname.txt")):
            rc, out, err = run(cmd, timeout=60)
            (tmp / out_name).write_text(out or err or "")
        rc, out, _ = run([str(ctx.app_dir / "venv" / "bin" / "pip"), "freeze"], timeout=120)
        (tmp / "pip-freeze.txt").write_text(out)
        rc, out, _ = run(["git", "-c", "safe.directory=%s" % ctx.app_dir,
                          "-C", str(ctx.app_dir), "log", "-30", "--format=%h %ci %s"])
        (tmp / "git-log.txt").write_text(out)
        units_dir = tmp / "units"
        units_dir.mkdir()
        for p in Path("/etc/systemd/system").glob("satom*"):
            try:
                if p.is_file():
                    shutil.copy2(p, units_dir / p.name)
                elif p.is_dir():
                    shutil.copytree(p, units_dir / p.name, dirs_exist_ok=True)
            except Exception:  # noqa: BLE001
                pass
        with tarfile.open(dest, "w:gz") as tar:
            tar.add(tmp, arcname="satom-support-%s-%s" % (ctx.host, ts))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    os.chmod(dest, 0o600)
    size = dest.stat().st_size
    r = Result("ok", "support bundle written")
    r.rows("", [("file", str(dest)),
                ("size", "%.1f MB" % (size / 1e6) if size >= 1e6
                 else "%.0f KB" % (size / 1e3)),
                ("sections", str(collected)), ("mode", "0600")])
    if failed:
        r.worst("warn")
        r.lines("sections that failed to collect", failed[:10])
    r.note("It contains journals, listening sockets and the nginx config — "
           "hostnames, IPs and account names included. .env is NOT in it, and "
           "'show config' redacts secrets, but read before you send it out.")
    r.lines("retrieve", ["  scp root@%s:%s ." % (ctx.host, dest)])
    return r


_THEME_RESET_CODE = """
import json
from app import create_app
from app.services import theme_service as ts
app = create_app()
with app.app_context():
    before = ts.active_theme()["name"]
    after = ts.reset_to_builtin()
print(json.dumps({"before": before, "after": after}))
"""


def reset_theme(ctx, args):
    """Activate the built-in theme.

    Exists for one situation: an operator saved a palette that made the console
    hard or impossible to read, and the page that would fix it is inside that
    console. Everything else about theming is a web concern; this is the way
    back when the web is the thing that broke.

    Built-in themes cannot be edited or deleted, so the target of this command
    is always a known-good palette.
    """
    if ctx.role == "standby":
        r = Result("bad", "refusing: this node is the standby", exit_code=1)
        r.note("Its Postgres is a read-only replica. Run this on the primary; "
               "streaming replication carries the change here within seconds.")
        return r
    rc, out, err = _app_stdin(ctx, _THEME_RESET_CODE, "", timeout=120)
    if rc != 0:
        r = Result("bad", "could not reach the theme registry", exit_code=4)
        r.lines("error", (err or out).splitlines()[-12:])
        return r
    try:
        res = json.loads(out.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        r = Result("bad", "unexpected output from the app", exit_code=4)
        r.lines("output", (out or err).splitlines()[-12:])
        return r
    if res["before"] == res["after"]:
        return Result("ok", "already on the built-in theme (%s)" % res["after"])
    r = Result("ok", "theme reset to %s" % res["after"])
    r.rows("theme", [("was", res["before"]), ("now", res["after"])],
           keys="dim")
    r.note("Workers pick this up within 15 seconds; no restart needed.")
    return r


_SEAL_CODE = (
    "import json, os\n"
    "from app import create_app\n"
    "from app.services import recovery_seal as rs\n"
    "a=create_app()\n"
    "with a.app_context():\n"
    "    h = rs.seal(os.environ['SATOM_SEAL_PASSPHRASE'], by=%r)\n"
    "    print(json.dumps({'header': h, 'state': rs.seal_state()}))\n"
)

_UNSEAL_CODE = (
    "import json, os\n"
    "from app import create_app\n"
    "from app.services import recovery_seal as rs\n"
    "a=create_app()\n"
    "with a.app_context():\n"
    "    print(json.dumps({'material': rs.unseal(os.environ['SATOM_SEAL_PASSPHRASE']),\n"
    "                      'state': rs.seal_state()}))\n"
)

#: Env var an installer or automation uses to supply the passphrase. Read from
#: the environment rather than an argument because a --passphrase flag lands in
#: the shell history, in ps output and in the sudo log -- three copies of the
#: one secret whose whole purpose is to have exactly one.
SEAL_ENV = "SATOM_SEAL_PASSPHRASE"


def seal_recovery(ctx, args):
    """Seal FERNET_KEY and the internal CA into an envelope only a passphrase
    opens, and put that envelope where every copy mechanism already goes.

    ``execute export recovery-key`` hands the operator the raw secrets and asks
    them to keep a copy somewhere safe. That works exactly as well as the
    operator's filing, which is why ``diagnose recovery`` so often reports the
    export has never happened.

    This is the durable half. The envelope lands under ``data/`` -- the one
    directory the HA datasync AND the backup bundle both carry -- so it reaches
    the peer within five minutes and rides off-box in every bundle from then on.
    That is only safe because it is sealed: whoever steals a bundle holds
    ciphertext, while the operator holding a passphrase and nothing else can
    rebuild the installation from ANY copy.

    The passphrase is never stored, never logged, and never sent anywhere. If
    it is lost the envelope is scrap -- which is the property that makes the
    envelope safe to replicate in the first place.
    """
    supplied = os.environ.get(SEAL_ENV) or ""
    if not _yes(args):
        r = Result("warn", "seal recovery material", exit_code=2)
        r.lines("would", [
            "wrap FERNET_KEY and the internal CA key in an encrypted envelope",
            "write it to data/recovery/seal.json (0600)",
            "replicate it to the peer via satom-ha-datasync (<=5 min)",
            "include it in every backup bundle from now on",
            "",
            ("use the passphrase from $%s" % SEAL_ENV) if supplied
            else "GENERATE a passphrase and print it ONCE",
            "",
            "  sudo satom execute seal recovery --yes",
        ])
        r.note("Re-run this after rotating FERNET_KEY or re-issuing the CA: "
               "'diagnose recovery' reports an envelope holding an old key as "
               "stale, because restoring from it would not open this node.")
        return r

    generated = ""
    passphrase = supplied
    if not passphrase:
        rc0, out0, err0 = _app_call(
            ctx, "from app.services import recovery_seal as rs\n"
                 "print(rs.generate_passphrase())\n", timeout=60)
        if rc0 != 0:
            r = Result("bad", "could not generate a passphrase", exit_code=4)
            r.lines("error", (err0 or out0).splitlines()[-8:])
            return r
        generated = passphrase = (out0 or "").strip().splitlines()[-1].strip()

    who = ""
    try:
        who = os.environ.get("SUDO_USER") or getpass.getuser()
    except Exception:  # noqa: BLE001
        who = "unknown"

    # Environment, never argv: see _SEAL_CODE. Scoped to this process so it
    # is inherited by the child and by nothing else.
    os.environ[SEAL_ENV] = passphrase
    try:
        rc, out, err = _app_call(ctx, _SEAL_CODE % who, timeout=180)
    finally:
        os.environ.pop(SEAL_ENV, None)
    if rc != 0:
        r = Result("bad", "could not seal the recovery material", exit_code=4)
        r.lines("error", (err or out).splitlines()[-12:])
        return r
    try:
        res = json.loads(out.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        r = Result("bad", "unexpected output from the app", exit_code=4)
        r.lines("output", (out or err).splitlines()[-12:])
        return r

    st = res.get("state") or {}
    r = Result("ok", "recovery material sealed (%s)"
               % ", ".join(st.get("kinds") or []))
    r.rows("envelope", [("path", st.get("path", "")),
                        ("sealed at", st.get("at", "")),
                        ("by", st.get("by", ""))], keys="dim")
    fps = sorted((st.get("fingerprints") or {}).items())
    if fps:
        r.rows("fingerprints", fps, keys="dim")
    if generated:
        r.lines("PASSPHRASE -- shown once, never stored, not recoverable", [
            "", "    " + generated, "",
            "Write it down NOW and keep it where you keep break-glass",
            "credentials -- NOT beside the backups. Without it every copy of",
            "this envelope is scrap, and that is exactly why the envelope is",
            "safe to replicate to the peer and push off-box.",
        ])
    else:
        r.note("Sealed with the passphrase from $%s." % SEAL_ENV)
    r.note("The peer picks the envelope up on its next datasync (<=5 min).")
    return r


def unseal_recovery(ctx, args):
    """Open the sealed envelope and print what it holds.

    The disaster-recovery path: a rebuilt node whose ``.env`` has the wrong
    FERNET_KEY restores a bundle full of columns nothing can read. The envelope
    in that same bundle holds the right key; this is how it comes back out.

    Prints. Does not write. Choosing where a secret lands stays the operator's
    decision -- a default destination is how an uncontrolled second copy gets
    made.
    """
    passphrase = os.environ.get(SEAL_ENV) or ""
    if not _yes(args):
        r = Result("warn", "unseal recovery material", exit_code=2)
        r.lines("would", [
            "open data/recovery/seal.json with the passphrase",
            "print FERNET_KEY and the internal CA key it holds",
            "",
            "  %s='<passphrase>' sudo -E satom execute unseal recovery --yes"
            % SEAL_ENV,
        ])
        r.note("Treat the output like a root password.")
        return r
    if not passphrase:
        try:
            passphrase = getpass.getpass("Seal passphrase: ")
        except Exception:  # noqa: BLE001
            passphrase = ""
    if not passphrase:
        r = Result("bad", "no passphrase supplied", exit_code=2)
        r.note("Set $%s, or run this on a terminal so it can prompt."
               % SEAL_ENV)
        return r

    os.environ[SEAL_ENV] = passphrase
    try:
        rc, out, err = _app_call(ctx, _UNSEAL_CODE, timeout=180)
    finally:
        os.environ.pop(SEAL_ENV, None)
    if rc != 0:
        r = Result("bad", "could not open the sealed envelope", exit_code=1)
        r.lines("error", (err or out).splitlines()[-8:])
        r.note("Wrong passphrase, or the envelope has been altered. These are "
               "reported the same way on purpose.")
        return r
    try:
        res = json.loads(out.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        r = Result("bad", "unexpected output from the app", exit_code=4)
        r.lines("output", (out or err).splitlines()[-12:])
        return r
    material = res.get("material") or {}
    r = Result("ok", "envelope opened (%s)" % ", ".join(sorted(material)))
    for kind in sorted(material):
        r.lines(kind, str(material[kind]).splitlines() or [""])
    r.note("Nothing was written. Put FERNET_KEY into .env and restart, or "
           "place the CA under pki/internal-ca/, as the situation needs.")
    return r


_EXPORT_CODE = (
    "import json\n"
    "from app import create_app\n"
    "from app.services import recovery\n"
    "a=create_app()\n"
    "with a.app_context():\n"
    "    mat = recovery.export_material()\n"
    "    recs = {k: recovery.record_escrow(k, by=%r) for k in mat}\n"
    "    print(json.dumps({'material': mat, 'recorded': recs,\n"
    "                      'fpr': recovery.current_fingerprints()}))\n"
)


def export_recovery_key(ctx, args):
    """Print the two secrets no backup carries, so somebody can hold a copy.

    FERNET_KEY opens every encrypted column in the database; the internal CA
    key is the sole issuer for replication mTLS. Both are deliberately absent
    from backup bundles -- a bundle is retained, mirrored to the peer and
    pushed off-box over SFTP, and one carrying the key that opens the SFTP
    password would turn every bundle into a total compromise.

    The cost of that decision is that a bundle restored onto a rebuilt node is
    a database of unreadable secrets unless somebody kept the key. This is how
    they keep it.

    Prints by default rather than writing a file: the fewest copies that can
    accomplish the job is one, and choosing where a secret lands is the
    operator's decision, not a default. ``--out PATH`` is available when the
    operator wants that second copy, and creates it 0600.
    """
    if not _yes(args):
        r = Result("warn", "recovery material export", exit_code=2)
        r.lines("would", [
            "print FERNET_KEY (opens every encrypted column in the database)",
            "print the internal CA private key, if this node holds it",
            "record the export in app_settings (fingerprint + time only)",
            "",
            "  sudo satom execute export recovery-key --yes",
        ])
        r.note("Treat the output like a root password. Store it where you "
               "store break-glass credentials, NOT beside the backups — the "
               "whole point is that it is not in the bundle.")
        return r
    dest = None
    if "--out" in args:
        try:
            dest = Path(args[args.index("--out") + 1])
        except IndexError:
            return Result("bad", "--out needs a path", exit_code=2)
    who = ""
    try:
        who = os.environ.get("SUDO_USER") or getpass.getuser()
    except Exception:  # noqa: BLE001
        who = "unknown"
    rc, out, err = _app_call(ctx, _EXPORT_CODE % who, timeout=120)
    if rc != 0:
        r = Result("bad", "could not read the recovery material", exit_code=4)
        r.lines("error", (err or out).splitlines()[-12:])
        return r
    try:
        res = json.loads(out.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        r = Result("bad", "unexpected output from the app", exit_code=4)
        r.lines("output", (out or err).splitlines()[-12:])
        return r
    material = res.get("material") or {}
    if not material:
        r = Result("bad", "this node holds no recovery material", exit_code=1)
        r.note("No FERNET_KEY in the environment and no internal CA key on "
               "disk. On a standby the CA key is absent BY DESIGN, but a "
               "missing FERNET_KEY means the app could not have started.")
        return r
    fpr = res.get("fpr") or {}
    blob = []
    if "fernet" in material:
        blob.append("FERNET_KEY=%s" % material["fernet"])
    if "ca" in material:
        blob.append(material["ca"].rstrip("\n"))
    text = "\n".join(blob) + "\n"

    if dest is not None:
        # Create 0600 BEFORE any bytes land: opening 0644 and chmod-ing after
        # leaves a window where the key is world-readable.
        fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        r = Result("ok", "recovery material written to %s" % dest)
        r.rows("fingerprints", [(k, v) for k, v in sorted(fpr.items()) if v],
               keys="dim")
        r.note("Mode 0600, owner root. This is now a SECOND uncontrolled copy "
               "— move it off this host and shred the original.")
        return r

    r = Result("ok", "recovery material (%d item(s))" % len(material))
    r.lines("material", text.splitlines())
    r.rows("fingerprints", [(k, v) for k, v in sorted(fpr.items()) if v],
           keys="dim")
    r.note("Store this where you store break-glass credentials, NOT beside "
           "the backups. Verify later with: satom diagnose recovery")
    return r
