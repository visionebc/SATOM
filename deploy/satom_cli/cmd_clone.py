"""``execute clone export|import|release`` and ``get clone status``.

Copy one deploy's data into another (``app.services.deploy_clone``). The app
does the work; what the CLI adds is what a web request cannot: stopping the
writers around an import, taking the passphrase from a terminal instead of
argv, and verifying the node afterwards.
"""
import getpass
import json
import os
import shutil
import tarfile
import time
from pathlib import Path

from . import dbq
from .cmd_fix import _app_stdin, _yes
from .context import run
from .render import Result

PASSPHRASE_ENV = "SATOM_CLONE_PASSPHRASE"
EXPORT_USAGE = "execute clone export [--yes]"
FORMAT = "satom-clone/2"
IMPORT_USAGE = "execute clone import <bundle.tar.gz> [--yes]"
RELEASE_USAGE = "execute clone release [--yes]"

_EXPORT_CODE = """
import json, sys
from app import create_app
from app.services import deploy_clone as dc
arg = json.loads(sys.stdin.read())
app = create_app()
with app.app_context():
    try:
        print(json.dumps(dc.export_clone(by=arg["by"],
                                         passphrase=arg["passphrase"] or None)))
    except dc.CloneError as exc:
        print(json.dumps({"ok": False, "detail": str(exc)}))
"""

_IMPORT_CODE = """
import json, sys
from app import create_app
from app.services import deploy_clone as dc
arg = json.loads(sys.stdin.read())
app = create_app()
with app.app_context():
    try:
        print(json.dumps(dc.import_clone(arg["path"], arg["passphrase"], by="cli")))
    except dc.CloneError as exc:
        print(json.dumps({"ok": False, "detail": str(exc)}))
"""

_RELEASE_CODE = """
import json, sys
from app import create_app
from app.services import deploy_clone as dc
arg = json.loads(sys.stdin.read())
app = create_app()
with app.app_context():
    if not arg["apply"]:
        q = dc.quarantine_state()
        print(json.dumps({"ok": True, "held": q}))
    else:
        try:
            print(json.dumps(dc.release_quarantine(by="cli")))
        except dc.CloneError as exc:
            print(json.dumps({"ok": False, "detail": str(exc)}))
"""


def _last_json(out):
    for line in reversed((out or "").strip().splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            continue
    return None


def _refuse_standby(ctx, what):
    if ctx.role != "standby":
        return None
    r = Result("bad", "refusing: this node is the standby", exit_code=1)
    r.note("%s runs on the primary. The standby's data/ is a mirror that the "
           "next datasync overwrites, and its database is read-only." % what)
    return r


def _fmt_size(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.1f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024


# -- export ----------------------------------------------------------------
def export(ctx, args):
    """Write a clone bundle of this deploy's configuration. Read-only on the
    node."""
    refused = _refuse_standby(ctx, "An export")
    if refused:
        return refused
    if not _yes(args):
        r = Result("warn", "clone export requires confirmation", exit_code=2)
        r.lines("the bundle carries configuration only", [
            "appliances and their credentials, users, profiles, settings",
            "scheduled action definitions, templates, exceptions, probes",
            "Script Library scripts + schedules, integration hooks",
            "WAF artifacts, branding, the API library",
        ])
        r.lines("it does NOT carry", [
            "backups: the device vault and the system bundles",
            "config history (SoT store) and the live config tree",
            "the device cache: the first sync after release reads it again",
            "runs, logs, samples, incidents, notifications, firmware",
            "this node's FERNET_KEY or CA: every secret is re-encrypted under",
            "a one-time transfer key, sealed with a passphrase printed once",
            "HA role, node certificate, backup server: the target keeps its own",
            "queued script or hook requests",
        ])
        r.note("Re-run:  sudo satom %s --yes" % EXPORT_USAGE.replace(" [--yes]", ""))
        return r
    # The console chooses the passphrase and shows it before queueing the
    # export (the runner's result is a status file, which must never hold it);
    # it arrives here in the environment, never in argv.
    given = os.environ.get(PASSPHRASE_ENV) or ""
    rc, out, err = _app_stdin(ctx, _EXPORT_CODE,
                              json.dumps({"passphrase": given,
                                          "by": "console" if given else "cli"}),
                              timeout=3600)
    res = _last_json(out) if rc == 0 else None
    if not res or not res.get("ok"):
        r = Result("bad", "clone export failed", exit_code=1)
        r.lines("error", ((res or {}).get("detail") or err or out or "").splitlines()[-12:])
        return r
    rk = res.get("rekey") or {}
    r = Result("ok", "clone bundle written")
    r.rows("bundle", [
        ("file", res["path"]),
        ("size", _fmt_size(res.get("size"))),
        ("tables / rows", "%s / %s" % (res.get("tables"), res.get("rows"))),
        ("files", ", ".join("%s %s" % (k, v) for k, v in sorted((res.get("files") or {}).items()))),
        ("secrets re-encrypted", str(rk.get("rekeyed", 0))),
    ])
    if given:
        r.lines("passphrase", ["  the one supplied in $%s (not repeated here)" % PASSPHRASE_ENV])
    else:
        r.lines("passphrase (shown ONCE, stored nowhere)", ["  " + res["passphrase"]])
    if rk.get("vaulted"):
        r.worst("warn")
        r.note("%d secret(s) live in the external vault. The target reaches them "
               "through the same vault configuration, which travels with the "
               "bundle." % rk["vaulted"])
    if rk.get("foreign"):
        r.worst("warn")
        r.note("%d token-shaped value(s) this node's key cannot open were copied "
               "as they are: they were already unreadable here." % rk["foreign"])
    r.note("Copy the file to the target and run there:  sudo satom %s" % IMPORT_USAGE)
    r.set(path=res["path"], name=res.get("name"), size=res.get("size"), rekey=rk,
          tables=res.get("tables"), rows=res.get("rows"))
    return r


# -- import ----------------------------------------------------------------
def _manifest(path):
    with tarfile.open(path, "r:gz") as tar:
        try:
            member = tar.getmember("manifest.json")
        except KeyError:
            return None
        if not member.isfile():
            return None
        return json.loads(tar.extractfile(member).read().decode("utf-8"))


def import_(ctx, args):
    """Replace this deploy's configuration with a clone bundle's. Heavily
    gated."""
    refused = _refuse_standby(ctx, "An import")
    if refused:
        return refused
    plain = [a for a in args if not a.startswith("--")]
    if not plain:
        return Result("bad", "usage: satom " + IMPORT_USAGE, exit_code=2)
    src = Path(plain[0]).expanduser()
    if not src.is_file():
        return Result("bad", "no such file: %s" % src, exit_code=2)
    try:
        m = _manifest(src)
    except (tarfile.TarError, OSError, ValueError) as exc:
        return Result("bad", "not a readable clone bundle: %s" % exc, exit_code=2)
    if not m or m.get("format") != FORMAT:
        return Result("bad", "not a SATOM clone bundle (format %r)"
                      % ((m or {}).get("format")), exit_code=2)
    source = m.get("source") or {}
    tables = m.get("tables") or {}
    files = m.get("files") or {}
    if not _yes(args):
        r = Result("warn", "clone import requires explicit confirmation", exit_code=2)
        r.rows("bundle", [
            ("from", "%s (SATOM %s)" % (source.get("node", "?"), source.get("version", "?"))),
            ("created", m.get("created", "?")),
            ("tables / rows", "%d / %d" % (len(tables),
                                           sum(int(t.get("rows") or 0) for t in tables.values()))),
            ("files", ", ".join("%s %d" % (k, int(v.get("files") or 0))
                                for k, v in sorted(files.items()))),
            ("this node", "%s (%s)" % (ctx.host, ctx.role)),
        ])
        r.lines("what happens", [
            "1. check every table and file set against its checksum and this node's schema",
            "2. open the transfer key with the passphrase (asked, never in argv)",
            "3. take a safety bundle of the CURRENT database",
            "4. stop web, scheduler, reconciler",
            "5. replace the configuration; secrets are re-encrypted under THIS node's key",
            "6. empty this node's history, device cache and backup index",
            "   (they name appliances it will no longer have)",
            "7. this node's HA role, certificate, backup server, system bundles",
            "   and firmware are kept",
            "8. set the replaced files, the vault, the live config tree and the",
            "   SoT store aside under data/clone-prev-<time>/",
            "9. HOLD every schedule, alert e-mail, NetBox push and hook",
            "10. start the services again and verify /healthz",
        ])
        r.note("Accounts are replaced too: afterwards you log in with the "
               "SOURCE's users and passwords, and every open web session ends.")
        r.note("Nothing acts on appliances until:  sudo satom %s" % RELEASE_USAGE)
        r.note("Re-run:  sudo satom execute clone import %s --yes" % src)
        return r

    passphrase = os.environ.get(PASSPHRASE_ENV) or ""
    if not passphrase:
        try:
            passphrase = getpass.getpass("Clone passphrase: ")
        except Exception:  # noqa: BLE001
            passphrase = ""
    if not passphrase:
        r = Result("bad", "no passphrase supplied", exit_code=2)
        r.note("Set $%s, or run this on a terminal so it can prompt." % PASSPHRASE_ENV)
        return r

    # The app runs as the service account and must be able to read the file;
    # a copy in its own private directory, not a wider mode on the original.
    inbox = ctx.app_dir / "data" / "clone-imports"
    inbox.mkdir(mode=0o700, parents=True, exist_ok=True)
    dst = inbox / src.name
    if src.resolve() != dst.resolve():
        shutil.copyfile(src, dst)
    owner = (ctx.app_dir / "data").stat()
    for p in (inbox, dst):
        os.chown(p, owner.st_uid, owner.st_gid)
    os.chmod(dst, 0o600)

    r = Result("ok", "clone import %s" % src.name)
    steps, stopped = [], []
    for alias in ("web", "scheduler", "reconciler"):
        if ctx.unit_state(alias)["active"] == "active":
            run(["systemctl", "stop", ctx.unit(alias)], timeout=120)
            stopped.append(alias)
    steps.append(("stopped", ", ".join(stopped) or "(none were running)"))
    try:
        rc, out, err = _app_stdin(ctx, _IMPORT_CODE,
                                  json.dumps({"path": str(dst), "passphrase": passphrase}),
                                  timeout=7200)
    finally:
        passphrase = ""
    res = (_last_json(out) if rc == 0 else None) or {}
    ok = bool(res.get("ok"))
    if ok:
        rk = res.get("rekey") or {}
        steps.append(("rows", "%s in %s tables" % (res.get("rows"), res.get("tables"))))
        steps.append(("files", ", ".join(res.get("files") or []) or "(none)"))
        steps.append(("set aside", ", ".join(res.get("set_aside") or []) or "(none)"))
        steps.append(("tables emptied", str(res.get("emptied_tables", 0))))
        steps.append(("secrets re-encrypted", str(rk.get("rekeyed", 0))))
        steps.append(("safety bundle", res.get("safety") or "(none)"))
        steps.append(("previous files", res.get("previous_files") or "(none)"))
    else:
        steps.append(("import", (res.get("detail") or err or out or "FAILED to run")[-400:]))

    for alias in stopped:
        run(["systemctl", "start", ctx.unit(alias)], timeout=180)
    steps.append(("restarted", ", ".join(stopped) or "(none)"))
    code_ = 0
    deadline = time.time() + 60
    while time.time() < deadline:
        code_, _ = ctx.http("http://127.0.0.1:8000/healthz", timeout=4)
        if code_ == 200:
            break
        time.sleep(2)
    steps.append(("GET /healthz", str(code_ or "no answer within 60s")))
    r.rows("steps", steps)
    if not ok:
        r.status = "bad"
        r.note("Nothing was replaced if the error came before the database step; "
               "otherwise roll back with the safety bundle "
               "('satom execute restore db <bundle> --yes').")
        return r
    held = res.get("quarantine") or {}
    r.rows("held until release", [
        ("scheduled actions", str(held.get("actions", 0))),
        ("script schedules", str(held.get("script_schedules", 0))),
        ("hooks", str(held.get("hooks", 0))),
        ("settings", ", ".join(held.get("flags") or []) or "(none)"),
    ])
    if res.get("unreadable_secrets"):
        r.worst("bad")
        r.lines("secrets this node cannot open", res["unreadable_secrets"])
    if code_ != 200:
        r.worst("bad")
        r.note("The data was imported but the app is not answering: "
               "'satom diagnose python'.")
    r.note("Check the appliances and schedules, make sure the SOURCE is no "
           "longer acting on the same appliances, then:  sudo satom %s" % RELEASE_USAGE)
    try:
        dst.unlink()
    except OSError:
        pass
    return r


# -- release ---------------------------------------------------------------
def release(ctx, args):
    """Give back what an import held. Only what it held."""
    refused = _refuse_standby(ctx, "A release")
    if refused:
        return refused
    apply = _yes(args)
    rc, out, err = _app_stdin(ctx, _RELEASE_CODE, json.dumps({"apply": apply}),
                              timeout=300)
    res = (_last_json(out) if rc == 0 else None) or {}
    if not res.get("ok"):
        r = Result("bad", "clone release failed", exit_code=1)
        r.lines("error", (res.get("detail") or err or out or "").splitlines()[-12:])
        return r
    if not apply:
        held = res.get("held")
        if not held:
            return Result("ok", "nothing is held: no clone quarantine on this node")
        r = Result("warn", "release requires confirmation", exit_code=2)
        r.rows("held since %s (bundle %s)" % (held.get("at", "?"), held.get("bundle", "?")), [
            ("scheduled actions", str(len(held.get("actions") or []))),
            ("script schedules", str(len(held.get("script_schedules") or []))),
            ("hooks", str(len(held.get("hooks") or []))),
            ("settings", ", ".join(sorted(held.get("flags") or {})) or "(none)"),
        ])
        r.note("Schedules restart from now: the held period is not replayed.")
        r.note("Re-run:  sudo satom execute clone release --yes")
        return r
    r = Result("ok", "clone quarantine released")
    r.rows("re-enabled", [
        ("scheduled actions", str(res.get("actions", 0))),
        ("script schedules", str(res.get("script_schedules", 0))),
        ("hooks", str(res.get("hooks", 0))),
        ("settings", ", ".join(res.get("flags") or []) or "(none)"),
    ])
    return r


# -- status ----------------------------------------------------------------
def status(ctx, args):
    """Is this node holding a clone, and when was the last import. Read-only."""
    q, err = dbq.setting(ctx, "deployclone.quarantine")
    last, _ = dbq.setting(ctx, "deployclone.last_import")
    if q is None:
        r = Result("warn", "clone status unknown")
        r.lines("why", [err])
        return r
    r = Result("ok", "clone status")
    try:
        lastd = json.loads(last) if last else None
    except ValueError:
        lastd = None
    r.rows("last import", [
        ("at", (lastd or {}).get("at", "never")),
        ("bundle", (lastd or {}).get("bundle", "-")),
        ("from", ((lastd or {}).get("source") or {}).get("node", "-")),
        ("safety bundle", (lastd or {}).get("safety", "-") or "-"),
    ])
    if q:
        try:
            held = json.loads(q)
        except ValueError:
            held = {}
        r.worst("warn")
        r.rows("HELD (nothing acts on appliances)", [
            ("since", held.get("at", "?")),
            ("scheduled actions", str(len(held.get("actions") or []))),
            ("script schedules", str(len(held.get("script_schedules") or []))),
            ("hooks", str(len(held.get("hooks") or []))),
        ])
        r.note("Release with:  sudo satom %s" % RELEASE_USAGE)
    else:
        r.rows("quarantine", [("state", "none")])
    return r
