"""'execute' — verbs that CHANGE STATE. Every one of these needs root.

Two rules hold this file together:

1. Anything the app already knows how to do is DELEGATED to the app, never
   reimplemented. Enqueuing a code update means calling
   ``self_update.request_update`` through the venv, not hand-writing the
   request JSON — a second writer of that schema is a schema that drifts.

2. Anything privileged that the app deliberately cannot do (rebuild a venv,
   write unit files) is done here, in the root process, and NEVER by widening
   the service account's sudoers.
"""
import json
import os
import shutil
import time
from pathlib import Path

from .context import RESTARTABLE, UNITS, run
from .render import Result

# Units whose templates live in deploy/ and are therefore re-copied by the
# self-update runner. Their User= must be pinned by a drop-in, because a plain
# edit is overwritten on the next update (that is how the standby silently
# reverted to User=root after the deprivilege).
DROPIN_UNITS = ("satom.service", "satom-scheduler.service", "satom-reconciler.service")


def _app_call(ctx, code, timeout=120):
    """Run a snippet inside the app's venv + app context. (rc, out, err)."""
    venv = ctx.app_dir / "venv" / "bin" / "python3"
    if not venv.exists():
        return 127, "", "venv missing at %s" % venv
    env = dict(os.environ)
    for k, v in ctx.env.items():
        env.setdefault(k, v)
    return run([str(venv), "-c", code], timeout=timeout, cwd=str(ctx.app_dir), env=env)


def _svc_arg(args, verb):
    if not args:
        r = Result("bad", "usage: execute %s <service>" % verb, exit_code=2)
        r.lines("restartable services", sorted(RESTARTABLE))
        return None, r
    alias = args[0]
    if alias not in RESTARTABLE:
        r = Result("bad", "refusing: %r is not operator-controllable" % alias, exit_code=2)
        r.lines("restartable services", sorted(RESTARTABLE))
        if alias in UNITS:
            r.note("'%s' exists but is excluded on purpose. 'updater' is the "
                   "privileged root runner and 'postgres' is shared state — "
                   "use systemctl directly and know why." % alias)
        return None, r
    return alias, None


def _systemctl(ctx, action, alias):
    unit = ctx.unit(alias)
    rc, out, err = run(["systemctl", action, unit], timeout=180)
    r = Result("ok" if rc == 0 else "bad", "%s %s" % (action, unit))
    if rc != 0:
        r.lines("error", (err or out).splitlines())
        r.lines("journal", ctx.journal(alias, 20).splitlines())
        return r
    # Do not trust 'systemctl restart' returning 0: gunicorn has reported an
    # active unit while its workers crash-looped. Wait for the real signal.
    if alias == "web":
        deadline = time.time() + 30
        code = 0
        while time.time() < deadline:
            code, _ = ctx.http("http://127.0.0.1:8000/healthz", timeout=3)
            if code == 200:
                break
            time.sleep(1)
        r.rows("verify", [("GET /healthz", code or "no answer within 30s")])
        if code != 200:
            r.status = "bad"
            r.lines("journal", ctx.journal(alias, 25).splitlines())
            r.note("The unit started but the app is not answering. Run "
                   "'satom diagnose python' — a module that fails to import "
                   "does not always stop the unit.")
            return r
    st = ctx.unit_state(alias)
    r.rows("state", [("unit", st["unit"]), ("active", "%s/%s" % (st["active"], st["sub"]))])
    return r


def restart(ctx, args):
    alias, err = _svc_arg(args, "restart")
    if err:
        return err
    res = _systemctl(ctx, "restart", alias)
    if alias in ("web",) and res.status == "ok":
        res.note("If you changed a scheduled-action spec or the probe registry, "
                 "restart 'scheduler' too — it runs its own copy of the code.")
    return res


def start(ctx, args):
    alias, err = _svc_arg(args, "start")
    return err or _systemctl(ctx, "start", alias)


def stop(ctx, args):
    alias, err = _svc_arg(args, "stop")
    return err or _systemctl(ctx, "stop", alias)


def reload_nginx(ctx, args):
    rc, out, err = run(["nginx", "-t"])
    if rc != 0:
        r = Result("bad", "nginx config is invalid — NOT reloading")
        r.lines("nginx -t", (err or out).splitlines())
        return r
    rc, out, err = run(["systemctl", "reload", "nginx"])
    r = Result("ok" if rc == 0 else "bad", "reload nginx")
    r.lines("nginx -t", (err or out or "syntax ok").splitlines())
    return r


# -- updates (delegated to the privileged queue) --------------------------
def update_code(ctx, args):
    target = args[0] if args else ""
    code = ("from app import create_app\n"
            "from app.services import self_update as su\n"
            "a=create_app()\n"
            "with a.app_context():\n"
            "    print(su.request_update(%r, 'cli'))\n" % target)
    rc, out, err = _app_call(ctx, code)
    if rc != 0:
        r = Result("bad", "could not enqueue the update", exit_code=4)
        r.lines("error", (err or out).splitlines()[-15:])
        r.note("Enqueuing goes through the app so the request schema cannot "
               "drift. If the app cannot import, fix that first: "
               "satom diagnose python")
        return r
    uid = out.strip().splitlines()[-1]
    r = Result("ok", "update queued: %s" % uid)
    r.lines("what happens now", [
        "The web worker only ENQUEUED. The privileged runner does the work:",
        "  satom-updater.path  ->  satom-updater.service  (root, oneshot)",
        "",
        "Follow it with:   satom execute update status %s" % uid,
        "Or watch:         satom get log updater 50",
    ])
    st = ctx.unit_state("updater")
    if st["enabled"] not in ("enabled", "enabled-runtime"):
        r.worst("bad")
        r.note("satom-updater.path is %s on this node. Enqueued updates will sit "
               "as 'queued' FOREVER. Enable it: "
               "systemctl enable --now satom-updater.path" % st["enabled"])
    r.set(id=uid)
    return r


def update_pip(ctx, args):
    if len(args) < 2:
        r = Result("bad", "usage: execute update pip <package> <version>", exit_code=2)
        r.lines("note", [
            "Curated allowlist only. There is deliberately NO 'pip install",
            "<anything>' — that would be arbitrary code execution as the",
            "service account. See 'show privilege'.",
        ])
        return r
    pkg, ver = args[0], args[1]
    code = ("from app import create_app\n"
            "from app.services import self_update as su\n"
            "a=create_app()\n"
            "with a.app_context():\n"
            "    print(su.request_pip_change(%r, %r, 'cli'))\n" % (pkg, ver))
    rc, out, err = _app_call(ctx, code)
    if rc != 0:
        r = Result("bad", "refused", exit_code=1)
        r.lines("error", (err or out).splitlines()[-8:])
        return r
    uid = out.strip().splitlines()[-1]
    r = Result("ok", "pip change queued: %s %s -> %s" % (pkg, "", ver))
    r.rows("", [("request", uid), ("node", "%s (venv is per-node)" % ctx.host)])
    r.note("This applies to THIS node only — the venv is not replicated. Run "
           "the same command on the peer to keep the pair in sync.")
    return r


def update_status(ctx, args):
    d = ctx.app_dir / "data" / "update-status"
    files = sorted(d.glob("*.json")) if d.exists() else []
    if args:
        files = [p for p in files if args[0] in p.name]
    if not files:
        return Result("info", "no update records found")
    p = files[-1]
    try:
        rec = json.loads(p.read_text())
    except Exception as exc:  # noqa: BLE001
        return Result("bad", "unreadable status file %s: %s" % (p, exc))
    r = Result("ok" if rec.get("state") in ("ok", "done", "success") else
               "warn" if rec.get("state") == "queued" else "bad",
               "update %s — %s" % (rec.get("id"), rec.get("state")))
    r.rows("", [(k, v) for k, v in rec.items() if not isinstance(v, (list, dict))])
    steps = rec.get("steps") or []
    r.lines("steps", ["%s %s %s" % ("ok " if s.get("ok") else "FAIL",
                                    s.get("name", ""), s.get("detail", "") or "")
                      for s in steps] or ["(none yet)"])
    if rec.get("state") == "queued" and not steps:
        st = ctx.unit_state("updater")
        if st["enabled"] not in ("enabled", "enabled-runtime"):
            r.status = "bad"
            r.note("Still 'queued' with no steps and satom-updater.path is %s. "
                   "That is the failure mode, not slowness." % st["enabled"])
    return r


def promote(ctx, args):
    if ctx.role != "standby":
        r = Result("bad", "refusing: this node is '%s', not a standby" % ctx.role,
                   exit_code=1)
        r.note("Promotion is only meaningful on the streaming replica.")
        return r
    if "--yes" not in args:
        r = Result("warn", "promote requires explicit confirmation", exit_code=2)
        r.lines("what this does", [
            "Promotes this standby's Postgres to read-write and makes this node",
            "the primary. The OLD primary will NOT be able to pull from the new",
            "one until you run --authorize-peer there: that is a known open item",
            "in the promote runbook, not a surprise.",
            "",
            "Re-run:  satom execute promote --yes",
        ])
        return r
    code = ("from app import create_app\n"
            "from app.services import self_update as su\n"
            "a=create_app()\n"
            "with a.app_context():\n"
            "    print(su.request_promote('cli') if hasattr(su,'request_promote') else '')\n")
    rc, out, err = _app_call(ctx, code)
    if rc != 0 or not out.strip():
        r = Result("warn", "could not enqueue via the app", exit_code=4)
        r.lines("fallback", ["Run the deployed script directly:",
                             "  /usr/local/sbin/satom-promote.sh"])
        r.lines("error", (err or out).splitlines()[-8:])
        return r
    return Result("ok", "promote queued: %s" % out.strip().splitlines()[-1])


# -- reinstall ------------------------------------------------------------
def reinstall_venv(ctx, args):
    req = ctx.app_dir / "requirements.txt"
    if not req.exists():
        return Result("bad", "requirements.txt missing at %s" % req)
    venv = ctx.app_dir / "venv"
    if "--yes" not in args:
        r = Result("warn", "reinstall venv requires explicit confirmation",
                   exit_code=2)
        r.rows("would rebuild", [
            ("venv", str(venv)),
            ("from", str(req)),
            ("node", "%s (%s)" % (ctx.host, ctx.role)),
        ])
        r.lines("what happens", [
            "1. save a pip freeze of the current venv under /root",
            "2. move the current venv aside (venv.old-<timestamp>)",
            "3. python3 -m venv + pip install -r requirements.txt",
            "",
            "This needs to reach the package index. On an isolated management",
            "network it will fail AFTER the old venv has been moved aside, and",
            "the node is then worse off than before — the offline bundle is",
            "the supported path there.",
            "",
            "Re-run:  sudo satom execute reinstall venv --yes",
        ])
        return r
    r = Result("ok", "reinstall venv")
    backup = None
    if venv.exists():
        rc, out, _ = run([str(venv / "bin" / "python3"), "-m", "pip", "freeze"], timeout=120)
        if rc == 0 and out:
            backup = Path("/root/satom-venv-freeze-%s.txt" % time.strftime("%Y%m%d-%H%M%S"))
            backup.write_text(out)
            r.rows("rollback point", [("pip freeze saved", str(backup))])
        moved = venv.with_name("venv.old-%s" % time.strftime("%Y%m%d-%H%M%S"))
        venv.rename(moved)
        r.rows("previous venv", [("moved to", str(moved))])
    rc, out, err = run(["python3", "-m", "venv", str(venv)], timeout=300)
    if rc != 0:
        r.status = "bad"
        r.lines("venv creation failed", (err or out).splitlines())
        return r
    rc, out, err = run([str(venv / "bin" / "pip"), "install", "-r", str(req)],
                       timeout=1800)
    r.lines("pip install -r requirements.txt", (out or err).splitlines()[-12:])
    if rc != 0:
        r.status = "bad"
        r.note("Install failed. The previous venv is still on disk (see above) — "
               "rename it back to recover, then investigate.")
        return r
    shutil.chown(str(venv), ctx.app_user, ctx.app_user)
    for p in venv.rglob("*"):
        try:
            shutil.chown(str(p), ctx.app_user, ctx.app_user)
        except Exception:  # noqa: BLE001
            pass
    r.rows("ownership", [("venv", "%s:%s" % (ctx.app_user, ctx.app_user))])
    r.note("Now restart the app:  satom execute restart web")
    return r


def reinstall_units(ctx, args):
    """Re-copy the unit templates AND re-assert the User= drop-ins.

    The drop-in is the whole point: self_update_runner re-copies deploy/<unit>
    on every code update, so a unit edited in place reverts to User=root. Only
    the drop-in survives.
    """
    src = ctx.app_dir / "deploy"
    dst = Path("/etc/systemd/system")
    r = Result("ok", "reinstall systemd units")
    copied = []
    for p in sorted(src.glob("satom*.service")) + sorted(src.glob("satom*.timer")) \
            + sorted(src.glob("satom*.path")):
        try:
            shutil.copy2(str(p), str(dst / p.name))
            os.chown(str(dst / p.name), 0, 0)
            os.chmod(str(dst / p.name), 0o644)
            copied.append(p.name)
        except Exception as exc:  # noqa: BLE001
            r.worst("bad")
            r.note("copy %s: %s" % (p.name, exc))
    r.lines("installed", copied or ["(none found)"])

    pinned = []
    if ctx.app_user != "root":
        for unit in DROPIN_UNITS:
            d = dst / (unit + ".d")
            d.mkdir(parents=True, exist_ok=True)
            (d / "10-app-user.conf").write_text(
                "# Written by 'satom execute reinstall units'.\n"
                "# The unit TEMPLATE in deploy/ is re-copied on every self-update,\n"
                "# so User= must be pinned here or it reverts to root.\n"
                "[Service]\nUser=%s\nGroup=%s\n" % (ctx.app_user, ctx.app_user))
            pinned.append(unit)
    r.lines("User=%s pinned via drop-in" % ctx.app_user, pinned or
            ["(skipped: the app tree is root-owned, so there is no service account "
             "to pin — self-healing, not a silent no-op)"])
    rc, out, err = run(["systemctl", "daemon-reload"])
    if rc != 0:
        r.status = "bad"
        r.lines("daemon-reload", (err or out).splitlines())
        return r
    r.rows("daemon-reload", [("result", "ok")])
    r.note("Units are on disk but not restarted. Restart what you changed, "
           "e.g.  satom execute restart web")
    return r


def reinstall_cli(ctx, args):
    """Refresh the root-owned copy of this CLI from the repo."""
    script = ctx.app_dir / "deploy" / "install-cli.sh"
    if not script.exists():
        return Result("bad", "missing %s" % script)
    rc, out, err = run(["bash", str(script)], timeout=120)
    r = Result("ok" if rc == 0 else "bad", "reinstall cli")
    r.lines("", (out or err).splitlines())
    r.note("Verify the privilege boundary afterwards: satom diagnose privilege")
    return r


def repair_permissions(ctx, args):
    """Give the app tree back to the service account.

    Running anything as root inside /opt/satom (pytest, a git command, a manual
    script) leaves root-owned files in .git/, data/jobs/ and reports/. The
    symptoms are indirect and slow: git publish keeps working because git
    renames refs, while some other write silently fails.
    """
    if ctx.app_user == "root":
        return Result("info", "app tree is root-owned; nothing to repair")
    r = Result("ok", "repair permissions")
    fixed = 0
    scanned = 0
    # docs/ and tests/ were missing from this list until 2026-08-02, and they are
    # exactly where running as root leaves debris: pytest writes tests/__pycache__,
    # and any doc edited or copied in as root stays root-owned. The command
    # reported "46 fixed" while leaving files behind in the two directories the
    # next `git commit` as the service account would touch.
    for sub in (".git", "data", "reports", "state", "app", "deploy", "pki", "site",
                "docs", "tests", "installers"):
        base = ctx.app_dir / sub
        if not base.exists():
            continue
        for p in [base] + list(base.rglob("*")):
            scanned += 1
            try:
                if p.stat().st_uid == 0:
                    shutil.chown(str(p), ctx.app_user, ctx.app_user)
                    fixed += 1
            except Exception:  # noqa: BLE001
                pass
    pyc = 0
    for p in ctx.app_dir.rglob("__pycache__"):
        # Checking only the DIRECTORY's owner missed the common case: the cache
        # directory already existed (service-owned) and root merely dropped a
        # new .pyc inside it. Sweep when the directory OR anything in it is
        # root-owned - a stale byte-cache is free to rebuild.
        try:
            rooted = p.stat().st_uid == 0 or any(
                c.stat().st_uid == 0 for c in p.iterdir())
        except Exception:  # noqa: BLE001
            continue
        if rooted:
            shutil.rmtree(p, ignore_errors=True)
            pyc += 1
    r.rows("", [("paths scanned", scanned),
                ("root-owned -> %s" % ctx.app_user, fixed),
                ("root-owned __pycache__ removed", pyc)])
    r.note(".env stays root:%s 0640 on purpose and is NOT touched." % ctx.app_user)
    return r


# -- one-shot operations --------------------------------------------------
def _flask(ctx, sub, extra=None, timeout=900):
    venv = ctx.app_dir / "venv" / "bin" / "flask"
    if not venv.exists():
        return Result("bad", "venv/bin/flask missing — run 'execute reinstall venv'",
                      exit_code=4)
    env = dict(os.environ)
    for k, v in ctx.env.items():
        env.setdefault(k, v)
    cmd = [str(venv), sub] + list(extra or [])
    rc, out, err = run(cmd, timeout=timeout, cwd=str(ctx.app_dir), env=env)
    r = Result("ok" if rc == 0 else "bad", "flask %s" % sub)
    r.lines("", (out or err).splitlines()[-40:])
    return r


def cert_renew(ctx, args):
    return _flask(ctx, "cert-renew")


def alerts_run(ctx, args):
    extra = ["--dry-run"] if "--dry-run" in args else []
    return _flask(ctx, "alerts-run", extra)


def preflight(ctx, args):
    return _flask(ctx, "preflight", ["--label", args[0]] if args else [])


def postflight(ctx, args):
    return _flask(ctx, "postflight")


def backup_db(ctx, args):
    """Create a system backup bundle, in the format the rest of the product
    understands.

    DELEGATED on purpose: the bundle is a tar.gz of db.dump + reports/ +
    manifest, and the System Backup page, the retention policy, the push to the
    external server and `restore_backup` all read exactly that. A bare pg_dump
    written here would be invisible to every one of them — a backup nothing can
    restore is not a backup.

    Pass --push to also upload it to the external backup server.
    """
    push = "--push" in args
    code = ("from app import create_app\n"
            "from app.services import system_backup as sb\n"
            "a=create_app()\n"
            "with a.app_context():\n"
            "    print(sb.create_backup(label='cli', publish_git=False, "
            "push_server=%s))\n" % bool(push))
    rc, out, err = _app_call(ctx, code, timeout=3600)
    r = Result("ok" if rc == 0 else "bad", "system backup bundle")
    r.lines("", (out or err).splitlines()[-10:])
    if rc != 0:
        return r
    if "'ok': False" in out:
        r.status = "bad"
        return r
    if not push:
        r.note("Local copy only. Add --push to send it to the external backup "
               "server as well — one rack holding both copies is one copy.")
    if ctx.role == "standby":
        r.note("You bundled the STANDBY. Deleting bundles here is pointless "
               "too: the primary's rsync --delete would resurrect them.")
    return r
