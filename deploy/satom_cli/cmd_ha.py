"""'ha' — can the standby fetch code from this primary, and the repair if it
cannot.   [SATOM-HA-LINK-CLI]

STDLIB ONLY (see context.py). The check and the repair are DELEGATED to the
app (``app/services/ha_link.py``), run as the service account: a second
implementation of either here is a second answer to the same question, and
the day they disagree is the day an operator trusts the wrong one. What this
module adds is what only a console can: the manual fallback when the app
itself cannot run, and waiting on the privileged runner with a visible clock.

The repair never runs systemctl from here either. It enqueues the same
allowlisted request the GUI button enqueues, so there is one audited path to
restarting systemd-logind, the root runner re-validates it (including its own
primary-only role check), and ``satom execute update status <id>`` reads its
record like any other.
"""
import json
import os
import time

from .context import run
from .render import EXIT_FAIL, EXIT_USAGE, Result

# One snippet per call, arguments on STDIN, never in argv (argv is world-
# readable in /proc and lands in shell history).
_CHECK_CODE = (
    "import json\n"
    "from app import create_app\n"
    "from app.services import ha_link\n"
    "a=create_app()\n"
    "with a.app_context():\n"
    "    print(json.dumps(ha_link.check(), default=str))\n"
)

_REPAIR_CODE = (
    "import json, sys\n"
    "args = json.loads(sys.stdin.read() or '{}')\n"
    "from app import create_app\n"
    "from app.services import ha_link\n"
    "from app.services.audit import log_action\n"
    "a=create_app()\n"
    "with a.app_context():\n"
    "    res = ha_link.request_repair(args['by'], origin='cli',\n"
    "                                 dry_run=not args.get('confirm'))\n"
    "    if args.get('confirm'):\n"
    "        b = res.get('before') or {}\n"
    "        if res.get('refused'):\n"
    "            log_action('ha.link.repair.refused', target=res.get('node') or '',\n"
    "                       extra={'reason': res['refused'][:200], 'by': args['by'],\n"
    "                              'role': b.get('role')})\n"
    "        else:\n"
    "            log_action('ha.link.repair', target=res.get('node') or '',\n"
    "                       extra={'request': res.get('uid'), 'by': args['by'],\n"
    "                              'unit': res.get('unit'), 'origin': 'cli',\n"
    "                              'verdict_before': b.get('verdict'),\n"
    "                              'problems_before': [p.get('code') for p in\n"
    "                                                  b.get('problems') or []]})\n"
    "    print(json.dumps(res, default=str))\n"
)

#: What to type when the app cannot even run the check. Kept here, in the
#: CLI, because that is the moment the web page is not available either.
MANUAL = (
    "loginctl list-sessions",
    "loginctl show-session <id> -p Name -p State -p Timestamp",
    "    (every login of the service account 'opening' for minutes = wedged)",
    "journalctl -u systemd-logind --since -2h | grep -i 'session scope'",
    "sudo systemctl restart systemd-logind      # the repair, by hand",
    "On the standby (read-only):  journalctl -u satom-reconciler -n 20",
    "    (decision=fetch-error / 'git fetch timed out' = cannot fetch from here)",
)

_STATUS_FOR = {"ok": "ok", "warning": "warn", "broken": "bad", "n/a": "info"}
WAIT_DEFAULT = 90


def _app_json(ctx, code, payload=None, timeout=90):
    """Run ``code`` in the app venv AS THE SERVICE ACCOUNT; parse its last line.

    As the service account and not as root: the app tree is writable by that
    account, so executing it as root is the escalation the launcher exists to
    avoid -- and the files the repair writes (the request in the runner's
    queue) must be owned by the account the web writes them as.
    """
    venv = ctx.app_dir / "venv" / "bin" / "python3"
    if not venv.exists():
        return None, "venv missing at %s" % venv
    env = dict(os.environ)
    for k, v in ctx.env.items():
        env.setdefault(k, v)
    env["HOME"] = str(ctx.app_dir)
    cmd = [str(venv), "-c", code]
    if os.geteuid() == 0 and ctx.app_user and ctx.app_user != "root":
        cmd = ["runuser", "-m", "-u", ctx.app_user, "--"] + cmd
    rc, out, err = run(cmd, timeout=timeout, cwd=str(ctx.app_dir), env=env,
                       input_=payload)
    if rc != 0:
        tail = (err or out or "exit %d" % rc).strip().splitlines()
        return None, (tail[-1] if tail else "exit %d" % rc)
    try:
        return json.loads((out or "").strip().splitlines()[-1]), ""
    except Exception as exc:  # noqa: BLE001
        return None, "unparseable output (%s)" % type(exc).__name__


def _cannot_run(title, err, ctx):
    r = Result("bad", title, exit_code=4)
    r.lines("error", [err])
    if not ctx.is_root and not ctx.env_readable:
        r.note("This account cannot read .env, so the app cannot start for it. "
               "Run it with sudo.")
    r.lines("check it by hand", list(MANUAL))
    return r


def _fmt_check(r, c, label=""):
    """Fold one check result into a Result (shared by check and repair).
    ``label`` heads the sections ("before" / "after" around a repair)."""
    pre = (label + ": ") if label else ""
    lg = c.get("logind") or {}
    sshd = c.get("sshd") or {}
    rows = [("node", "%s (%s, %s mode)" % (c.get("node"), c.get("role"),
                                            c.get("mode"))),
            ("verdict", c.get("verdict"))]
    if lg:
        if lg.get("responsive") is False:
            state = "NOT RESPONDING"
        elif lg.get("responsive") is None:
            state = "unknown"
        else:
            state = "%d session(s), %d opening, %d stuck (user %s)" % (
                lg.get("sessions") or 0, lg.get("opening") or 0,
                len(lg.get("stuck") or []), lg.get("user"))
        rows.append(("systemd-logind", state))
    if sshd:
        rows.append(("sshd", sshd.get("banner") if sshd.get("ok")
                     else "NOT ANSWERING: %s" % sshd.get("error")))
    r.rows(label, rows)
    if c.get("standby"):
        r.lines(pre + "standby, as it reports itself",
                [s.get("text") or "?" for s in c["standby"]])
    elif c.get("applicable"):
        r.lines(pre + "standby", ["no standby registered: nothing fetches from here"])
    probs = c.get("problems") or []
    if probs:
        r.lines(pre + "problems", ["%-22s %s" % (p.get("code"), p.get("text"))
                                   for p in probs])
    return r


def check(ctx, args):
    """Can the standby fetch code from this node? Read-only."""
    c, err = _app_json(ctx, _CHECK_CODE)
    if c is None:
        return _cannot_run("ha check could not run the app check", err, ctx)
    verdict = c.get("verdict") or "n/a"
    r = Result(_STATUS_FOR.get(verdict, "info"), "HA link on %s: %s"
               % (c.get("node"), verdict))
    _fmt_check(r, c)
    rep = c.get("repair") or {}
    if rep.get("refusal"):
        r.note(rep["refusal"])
    elif rep.get("recommended"):
        r.note("The login path on this node is wedged. Repair it with: "
               "sudo satom ha repair --yes")
    elif verdict == "broken":
        r.note("The repair restarts systemd-logind; the problems above do not "
               "point at it, so check them first ('satom show runbook ha-link').")
    r.set(check=c)
    return r


def _read_status(ctx, uid):
    p = ctx.app_dir / "data" / "update-status" / ("%s.json" % uid)
    try:
        return json.loads(p.read_text())
    except Exception:  # noqa: BLE001 -- not written yet / mid-rename
        return None


def repair(ctx, args):
    """Restart systemd-logind on this PRIMARY via the privileged runner.

    Without --yes: the plan and the current check, exit 2, nothing changes.
    """
    confirm = "--yes" in args
    wait = WAIT_DEFAULT
    if "--wait" in args:
        try:
            wait = max(0, int(args[args.index("--wait") + 1]))
        except (ValueError, IndexError):
            return Result("bad", "usage: ha repair [--yes] [--wait SECONDS]",
                          exit_code=EXIT_USAGE)
    by = "cli:%s" % (os.environ.get("SUDO_USER") or ctx.user)
    res, err = _app_json(ctx, _REPAIR_CODE,
                         payload=json.dumps({"by": by, "confirm": confirm}))
    if res is None:
        return _cannot_run("ha repair could not run the app", err, ctx)
    before = res.get("before") or {}
    if res.get("refused"):
        r = Result("bad", "refusing: %s" % res["refused"], exit_code=EXIT_FAIL)
        _fmt_check(r, before)
        return r
    if not confirm:
        r = Result("warn", "ha repair: preview only — nothing was changed",
                   exit_code=2)
        _fmt_check(r, before)
        r.lines("this repair", ["* " + t for t in res.get("does") or []])
        r.lines("it does not", ["* " + t for t in res.get("does_not") or []])
        r.note("Run it:  sudo satom ha repair --yes")
        r.set(before=before)
        return r

    uid = res.get("uid") or ""
    r = Result("ok", "ha repair %s on %s" % ("already queued" if
               res.get("already_queued") else "queued", res.get("node")))
    _fmt_check(r, before, "before")
    st = None
    deadline = time.time() + wait
    while True:
        st = _read_status(ctx, uid)
        if st and st.get("state") in ("success", "failed"):
            break
        if time.time() >= deadline:
            break
        time.sleep(2)
    if not st or st.get("state") not in ("success", "failed"):
        r.worst("warn")
        r.lines("runner", ["request %s is still %s after %ds"
                           % (uid, (st or {}).get("state") or "queued", wait),
                           "follow it:  satom execute update status %s" % uid,
                           "if it never leaves 'queued':  satom get service status updater"])
        r.set(uid=uid, before=before)
        return r
    r.lines("runner (%s)" % st.get("state"),
            ["%s %s %s" % ("ok  " if s.get("ok") else "FAIL", s.get("name", ""),
                           s.get("detail", "") or "")
             for s in st.get("steps") or []])
    if st.get("state") != "success":
        r.worst("bad")
    after, err = _app_json(ctx, _CHECK_CODE)
    if after is None:
        r.worst("warn")
        r.lines("after", ["the re-check could not run: %s" % err])
    else:
        _fmt_check(r, after, "after")
        if after.get("verdict") != "ok":
            r.worst("warn")
            r.note("The standby retries about once a minute. If it still shows "
                   "a fetch error from before the repair: satom ha check")
    r.set(uid=uid, before=before, after=after, runner=st.get("state"))
    return r
