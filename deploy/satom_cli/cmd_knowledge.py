"""Knowledge packs from the console (contract C7).

``satom show knowledge``            what is installed per lane, the mode, the feed
                                    and the last result (no network);
``satom execute knowledge fetch``   check the feed; ``--yes`` downloads the pack,
                                    ``--import --yes`` also imports it.

The work is the application's (``flask knowledge ...``, run AS the service
account like ``execute apipack import``): the feed is read with the same HTTPS
client as the system-upgrade feed, the download must match the feed's size and
sha256, and the import verifies the pack signature against the knowledge
lane's keys. This module only parses arguments and renders the JSON answer.
"""
import json
import os

from .context import run
from .render import Result

FETCH_USAGE = "execute knowledge fetch [--feed <https-url>] [--import] [--yes]"


def _flask_knowledge(ctx, extra, timeout=1800):
    """``flask knowledge <extra>`` as the service account. (rc, out, err)."""
    flask = ctx.app_dir / "venv" / "bin" / "flask"
    if not flask.exists():
        return 127, "", "venv/bin/flask missing — run 'execute reinstall venv'"
    env = dict(os.environ)
    for k, v in ctx.env.items():
        env.setdefault(k, v)
    env["FLASK_APP"] = "wsgi.py"
    env["HOME"] = str(ctx.app_dir)
    cmd = [str(flask), "knowledge"] + list(extra)
    if os.geteuid() == 0 and ctx.app_user and ctx.app_user != "root":
        cmd = ["runuser", "-m", "-u", ctx.app_user, "--"] + cmd
    return run(cmd, timeout=timeout, cwd=str(ctx.app_dir), env=env)


def _json_tail(out):
    start = (out or "").find("{")
    if start < 0:
        return None
    try:
        return json.loads(out[start:])
    except ValueError:
        return None


def _opt(args, flag):
    for i, a in enumerate(args):
        if a == flag:
            return args[i + 1] if i + 1 < len(args) else ""
        if a.startswith(flag + "="):
            return a.split("=", 1)[1]
    return None


def _lane_rows(installed):
    rows = []
    for lane in ("api_pack", "knowledge"):
        row = (installed or {}).get(lane)
        if not row:
            rows.append((lane, "nothing imported"))
            continue
        age = row.get("age_days")
        rows.append((lane, "%s  (%s, %s day(s) old%s)" % (
            row.get("pack"), row.get("date") or "?", "?" if age is None else age,
            ", STALE" if row.get("stale") else "")))
    return rows


def show_knowledge(ctx, args):
    """Installed knowledge per lane + mode + feed + last result. No network."""
    rc, out, err = _flask_knowledge(ctx, ["show"], timeout=120)
    doc = _json_tail(out)
    if doc is None:
        return Result("bad", "knowledge").lines("", ((err or out) or "no output")
                                                .splitlines()[-25:])
    fresh = doc.get("freshness") or {}
    r = Result("warn" if fresh.get("stale") else "ok", "knowledge packs")
    r.rows("installed", _lane_rows(doc.get("installed")))
    last = doc.get("last") or {}
    r.rows("feed", [("mode", str(doc.get("mode"))), ("url", str(doc.get("feed_url"))),
                    ("last check", "%s: %s (%s)" % (last.get("status") or "never",
                                                    last.get("message") or "-",
                                                    last.get("checked_at") or "-"))])
    if doc.get("refusal"):
        r.note(doc["refusal"])
    r.note("Fetch now:  satom execute knowledge fetch --import --yes")
    r.note("Air-gapped: download the pack elsewhere, upload it under Software "
           "Update -> API library packs, or 'satom execute apipack import <file> --yes'.")
    r.set(result=doc)
    return r


def fetch_knowledge(ctx, args):
    """Check the knowledge feed; ``--yes`` downloads, ``--import --yes`` imports."""
    feed = _opt(args, "--feed")
    if feed is not None and not feed.lower().startswith("https://"):
        return Result("bad", "knowledge fetch").lines("", [
            "--feed must be an https:// URL", "usage: satom " + FETCH_USAGE])
    yes = "--yes" in args
    do_import = "--import" in args
    if yes and ctx.role == "standby":
        return Result("bad", "knowledge fetch").lines("", [
            "this node is the STANDBY: its database is read-only.",
            "Fetch and import on the primary; the knowledge replicates here."])
    extra = ["fetch"]
    if feed:
        extra += ["--feed", feed]
    if yes:
        extra += ["--import"] if do_import else ["--download"]
    extra += ["--actor", os.environ.get("SUDO_USER") or "cli"]
    rc, out, err = _flask_knowledge(ctx, extra)
    res = _json_tail(out)
    if res is None:
        return Result("bad", "knowledge fetch").lines("", ((err or out) or "no output")
                                                      .splitlines()[-25:])
    status = res.get("status") or "?"
    verdict = {"imported": "ok", "current": "ok", "downloaded": "ok",
               "available": "warn", "standby": "bad"}.get(status, "bad")
    title = "knowledge fetch" + ("" if yes else " (dry run)")
    r = Result(verdict, title)
    r.rows("", [("feed", str(res.get("feed_url"))), ("status", status),
                ("pack", str(res.get("pack") or "-")),
                ("checked", str(res.get("checked_at")))])
    r.lines("result", [str(res.get("message") or "")])
    if not yes and status == "available":
        r.note("Re-run with --yes to download it, or --import --yes to download "
               "and import it.")
    r.set(result=res)
    return r
