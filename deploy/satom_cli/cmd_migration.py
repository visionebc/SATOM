"""``execute migration report`` — one appliance's configuration against a build.

DELEGATED, like every library verb: the report is the application's
(``flask apilib migration-report``, :mod:`app.services.migration_report`), run
as the service account. This module validates the arguments and renders the
answer. Read-only: nothing is written on the node or on the appliance.
"""
import re

from .cmd_apipack import _APPLIANCE_RE, _flask_apilib, _json_tail
from .render import Result

USAGE = "execute migration report <appliance-id|name> --target <build> [--backup <id>]"
_BUILD_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?$")
_TOP = 10


def _opt(args, flag):
    for i, a in enumerate(args):
        if a == flag and i + 1 < len(args):
            return args[i + 1]
        if a.startswith(flag + "="):
            return a.split("=", 1)[1]
    return ""


def _plain(args):
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a in ("--target", "--backup"):
            skip = True
            continue
        if a.startswith("--"):
            continue
        out.append(a)
    return out


def report(ctx, args):
    """Classify every configured object/field of the appliance's newest vault
    dump against the target build: block / translate / warn / info + verdict."""
    args = list(args)
    plain = _plain(args)
    target = _opt(args, "--target")
    backup = _opt(args, "--backup")
    if not plain or not target:
        return Result("info", "migration report").lines("", [
            "usage: satom " + USAGE, "",
            "Reads the appliance's newest show full-configuration dump from the",
            "backup vault and checks it against what the API library knows about",
            "the target build. Values never leave memory; nothing is changed."])
    appliance = plain[0]
    if not _APPLIANCE_RE.match(appliance):
        return Result("bad", "migration report", exit_code=2).lines(
            "", ["%r is not an appliance id or name" % appliance[:80]])
    if not _BUILD_RE.match(target):
        return Result("bad", "migration report", exit_code=2).lines(
            "", ["%r is not a firmware build (expected e.g. 8.0.6)" % target[:40]])
    extra = ["migration-report", appliance, "--target", target]
    if backup:
        if not backup.isdigit():
            return Result("bad", "migration report", exit_code=2).lines(
                "", ["--backup takes a vault backup id"])
        extra += ["--backup", backup]
    rc, out, err = _flask_apilib(ctx, extra, timeout=600)
    res = _json_tail(out)
    if rc != 0 or res is None:
        r = Result("bad", "migration report")
        r.lines("", ((err or out) or "no output").splitlines()[-25:])
        return r
    verdict = res.get("verdict") or "?"
    status = {"ready": "ok", "ready_with_warnings": "warn", "blocked": "bad"}.get(verdict, "info")
    r = Result(status, "migration report")
    s = res.get("summary") or {}
    lib = res.get("library") or {}
    comp = lib.get("target_completeness") or {}
    r.rows("move", [("appliance", str((res.get("appliance") or {}).get("name") or appliance)),
                    ("product", str(res.get("product") or "?")),
                    ("source", str(res.get("source") or "?")),
                    ("target", str(res.get("target") or "?")),
                    ("direction", str(res.get("direction") or "?")),
                    ("verdict", verdict),
                    ("reason", str(res.get("verdict_reason") or ""))])
    r.rows("findings", [(k, str(s.get(k, 0))) for k in ("block", "translate", "warn", "info")]
           + ([("target measured", "%s%%" % comp.get("pct"))] if comp else []))
    top = [x for x in res.get("rows") or [] if x.get("severity") in ("block", "warn")][:_TOP]
    if top:
        r.lines("top findings", ["%-5s %-24s %s %s" % (
            x.get("severity"), x.get("code"), x.get("object") or x.get("cli_path") or "-",
            ("." + x["field"]) if x.get("field") else "") for x in top])
    r.set(result=res)
    return r
