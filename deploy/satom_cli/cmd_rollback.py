"""Rollback points from the console: list them, put one back.

Every OS package upgrade (Settings > General > Installed software) and every
Python package change (Installed software and the Libraries card) saves what
it replaces BEFORE it runs: the exact packages at their previous version, or
a full copy of the virtual environment. These commands put one back.

They are the break-glass path, so they depend on as little as possible: no
web application, no database, no network and NOT the venv (which may be the
very thing that is broken). They load the root-owned, signed copy of the
update runner with this Python and call the same restore the console's
Rollback button queues. The result is written as a status record, so the
console shows it once it is up again.
"""
from __future__ import annotations

import importlib.util
import os
import stat
from pathlib import Path

from .render import Result

RUNNER_LIB = Path("/usr/local/lib/satom-runner")
LIST_USAGE = "execute rollback list"
APPLY_USAGE = "execute rollback apply <point-id> [--yes]"


def _load_runner(ctx):
    """The ROOT-OWNED runner, never the app tree's copy: what root executes
    must come from the signed release (install-runner.sh puts it here)."""
    path = RUNNER_LIB / "self_update_runner.py"
    try:
        st = os.stat(path)
    except OSError:
        raise RuntimeError("the update runner is not installed at %s "
                           "(satom execute reinstall runner)" % path)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise RuntimeError("%s is not a root-owned file that only root can "
                           "write; refusing to run it as root" % path)
    os.environ.setdefault("FM_APP_DIR", str(ctx.app_dir))
    spec = importlib.util.spec_from_file_location("satom_runner_rollback", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _what(man):
    if man.get("kind") == "python":
        return "venv copy (%s)" % (man.get("label") or man.get("package") or "?")
    pk = man.get("packages") or {}
    return "%s: %s" % (man.get("label") or man.get("component") or "?", ", ".join(
        "%s %s → %s" % (n, v.get("from"), v.get("to")) for n, v in sorted(pk.items())))


def rollback_list(ctx, args):
    try:
        mod = _load_runner(ctx)
    except Exception as exc:  # noqa: BLE001
        return Result("bad", "rollback list").lines("", [str(exc)])
    pts = mod.rollback_points()
    if not pts:
        r = Result("info", "no rollback points on this node")
        r.note("A point is saved before every OS package upgrade and every Python "
               "package change, and kept until newer ones replace it.")
        return r
    r = Result("ok", "%d rollback point(s) on this node" % len(pts))
    r.rows("", [(p.get("id"), "%-9s %-8s %s  %s" % (
        p.get("state"), p.get("kind"), (p.get("created_at") or "")[:19], _what(p)))
        for p in pts], keys="plain")
    r.note("Put one back: satom execute rollback apply <point-id> --yes")
    r.set(points=pts)
    return r


def rollback_apply(ctx, args):
    ids = [a for a in args if not a.startswith("-")]
    if len(ids) != 1:
        return Result("bad", "usage: " + APPLY_USAGE, exit_code=2)
    point = ids[0]
    try:
        mod = _load_runner(ctx)
        d = mod._rb_point_dir(point)
        man = mod._rb_manifest(d)
    except Exception as exc:  # noqa: BLE001
        return Result("bad", "rollback %s" % point).lines("", [str(exc)])
    if "--yes" not in args:
        r = Result("warn", "dry run: rollback %s" % point)
        r.rows("", [("kind", man.get("kind")), ("state", man.get("state")),
                    ("saved", (man.get("created_at") or "")[:19]),
                    ("by", man.get("by")), ("restores", _what(man))])
        r.note("Python: the whole venv goes back to that moment and SATOM restarts. "
               "OS: those packages are reinstalled at the saved versions and the "
               "services they need are restarted and checked.")
        r.note("Apply it: satom execute rollback apply %s --yes" % point)
        return r
    ok, detail, uid = mod.rollback_apply(point)
    r = Result("ok" if ok else "bad", "rollback %s — %s" % (point, "done" if ok else "FAILED"))
    r.rows("", [("restores", _what(man)), ("result", detail), ("record", uid)])
    if not ok:
        r.note("The record has every step: satom execute update status %s" % uid)
    r.set(ok=ok, detail=detail, record=uid)
    return r
