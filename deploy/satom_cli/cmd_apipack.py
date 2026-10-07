"""API library packs from the console (docs/api-library.md §11).

Software Update is the normal path; this is the same import for a node with no
browser, and the one the installer calls on a fresh node. The import itself is
the application's (``flask apilib pack import``): the signature is checked
against the update trust store, and items this node measured or already holds
are never touched. This module only finds the pack, stages it where the service
account can read it, and runs the import AS that account — run as root, the
release notes and field schemas it writes would be files the web worker can no
longer update (the same root-owned-file trap ``execute repair permissions``
exists for).
"""
import json
import os
import re
import shutil
from pathlib import Path

from .context import run
from .render import Result

PACK_RE = re.compile(r"^satom-apipack-[A-Za-z0-9._-]{1,64}\.tar\.gz$")
SECTIONS = ("library", "docs", "cli-coverage")
USAGE = ("execute apipack import <file.tar.gz|shipped> [--yes] "
         "[--product <p>[,<p>...]] [--section <s>[,<s>...]]")
HARVEST_USAGE = "execute apilib harvest <appliance-id|name> [--no-probe]"
_APPLIANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$")
COMPAT_USAGE = "execute apilib compat <product> <buildA> <buildB> [--json]"
CHANNELS_USAGE = "execute apilib channels <product> <build> [--json]"
PRODUCTS = ("fortiweb", "fortiadc", "fortiauthenticator", "fortianalyzer", "fortigate")
_BUILD_RE = re.compile(r"^[0-9][0-9A-Za-z._-]{0,31}$")


def _version_key(name):
    ver = name[len("satom-apipack-"):-len(".tar.gz")]
    return [int(x) if x.isdigit() else x for x in re.split(r"[.-]", ver)]


def _shipped_dir(ctx):
    return ctx.app_dir / "api-packs"


def _upload_dir(ctx):
    return ctx.app_dir / "data" / "apipack-uploads"


def _packs(d):
    if not d.is_dir():
        return []
    return sorted((p for p in d.glob("satom-apipack-*.tar.gz")
                   if p.is_file() and PACK_RE.match(p.name)),
                  key=lambda p: _version_key(p.name))


def shipped_pack(ctx):
    """The newest pack the release carries in api-packs/, or None."""
    packs = _packs(_shipped_dir(ctx))
    return packs[-1] if packs else None


def _chown_app(ctx, path):
    if ctx.app_user and ctx.app_user != "root":
        try:
            import pwd
            e = pwd.getpwnam(ctx.app_user)
            os.chown(path, e.pw_uid, e.pw_gid)
        except (KeyError, OSError):
            pass


def _opt_list(args, flag):
    out = []
    for i, a in enumerate(args):
        if a == flag and i + 1 < len(args):
            out += [x for x in args[i + 1].split(",") if x]
        elif a.startswith(flag + "="):
            out += [x for x in a.split("=", 1)[1].split(",") if x]
    return out


def _flask_pack(ctx, extra, timeout=1800):
    """``flask apilib pack <extra>`` as the service account. (rc, out, err)."""
    return _flask_apilib(ctx, ["pack"] + list(extra), timeout=timeout)


def _flask_apilib(ctx, extra, timeout=1800):
    """``flask apilib <extra>`` as the service account. (rc, out, err)."""
    flask = ctx.app_dir / "venv" / "bin" / "flask"
    if not flask.exists():
        return 127, "", "venv/bin/flask missing — run 'execute reinstall venv'"
    env = dict(os.environ)
    for k, v in ctx.env.items():
        env.setdefault(k, v)
    env["FLASK_APP"] = "wsgi.py"
    env["HOME"] = str(ctx.app_dir)
    cmd = [str(flask), "apilib"] + list(extra)
    if os.geteuid() == 0 and ctx.app_user and ctx.app_user != "root":
        # -m keeps the environment built above (.env, FLASK_APP, HOME); without
        # it runuser resets HOME to /root, which the service account cannot read.
        cmd = ["runuser", "-m", "-u", ctx.app_user, "--"] + cmd
    return run(cmd, timeout=timeout, cwd=str(ctx.app_dir), env=env)


def _json_tail(out):
    """The JSON document ``flask apilib pack import`` prints, or None."""
    start = (out or "").find("{")
    if start < 0:
        return None
    try:
        return json.loads(out[start:])
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------
def show_apipacks(ctx, args):
    """Packs on this node and what was imported from them. Reads files only."""
    r = Result("ok", "API library packs")
    rows = [(p.name, "shipped with this release (api-packs/)")
            for p in _packs(_shipped_dir(ctx))]
    rows += [(p.name, "uploaded (data/apipack-uploads/)") for p in _packs(_upload_dir(ctx))]
    if rows:
        r.rows("available", rows)
    else:
        r.status = "info"
        r.lines("available", ["no pack on this node"])
    log = ctx.app_dir / "data" / "apipacks" / "imports"
    hist = []
    for f in sorted(log.glob("*.json"), reverse=True)[:10] if log.is_dir() else []:
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        hist.append((f.name.split("-", 1)[0], "%s: %s imported, %s failed (%s)" % (
            rec.get("version"), rec.get("imported", 0), rec.get("errors", 0),
            rec.get("actor") or "?")))
    if hist:
        r.rows("recent imports", hist)
    r.note("Import: satom execute apipack import shipped        (dry run)")
    r.note("        satom execute apipack import shipped --yes")
    return r


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------
def import_apipack(ctx, args):
    """Import a signed API pack. Without --yes it only reports what would happen."""
    plain = []
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in ("--product", "--section"):
            skip = True
            continue
        if not a.startswith("--"):
            plain.append(a)
    if not plain:
        return Result("info", "apipack import").lines("", [
            "usage: satom " + USAGE, "",
            "'shipped' is the pack the installed release carries in api-packs/.",
            "The pack must be signed by a key in this node's trust store",
            "(satom show trust). Items this node measured itself are never replaced."])

    if ctx.role == "standby":
        return Result("bad", "apipack import").lines("", [
            "this node is the STANDBY: its database is read-only.",
            "Import on the primary; the library replicates here and the data sync",
            "copies the release notes and field schemas."])

    if plain[0] == "shipped":
        src = shipped_pack(ctx)
        if src is None:
            return Result("bad", "apipack import").lines("", [
                "this release carries no pack in %s" % _shipped_dir(ctx)])
    else:
        src = Path(plain[0]).expanduser()
        if not src.is_file():
            return Result("bad", "apipack import").lines("", ["%s is not a file" % src])
        if not PACK_RE.match(src.name):
            return Result("bad", "apipack import").lines("", [
                "%r is not an API pack name (satom-apipack-<version>.tar.gz)" % src.name])

    products = _opt_list(args, "--product")
    sections = _opt_list(args, "--section")
    bad = [s for s in sections if s not in SECTIONS]
    if bad:
        return Result("bad", "apipack import").lines("", [
            "unknown section(s): %s (valid: %s)" % (", ".join(bad), ", ".join(SECTIONS))])

    # The service account has to read the file. A pack in an operator's home
    # (0700) is copied to the staging area the web console also uses.
    path = src
    try:
        inside = src.resolve().is_relative_to(ctx.app_dir.resolve())
    except (AttributeError, OSError):
        inside = str(src.resolve()).startswith(str(ctx.app_dir.resolve()) + os.sep)
    if not inside:
        dest_dir = _upload_dir(ctx)
        dest_dir.mkdir(parents=True, exist_ok=True)
        _chown_app(ctx, dest_dir)
        path = dest_dir / src.name
        shutil.copy2(src, path)
        _chown_app(ctx, path)

    extra = ["import", str(path)]
    for p in products:
        extra += ["--product", p]
    for s in sections:
        extra += ["--section", s]
    dry = "--yes" not in args
    if dry:
        extra.append("--dry-run")
    rc, out, err = _flask_pack(ctx, extra)
    res = _json_tail(out)
    if res is None:
        r = Result("bad", "apipack import")
        r.lines("", ((err or out) or "no output").splitlines()[-25:])
        return r

    items = res.get("items") or []
    by_state = {}
    for it in items:
        by_state[it.get("state")] = by_state.get(it.get("state"), 0) + 1
    title = "apipack import%s" % (" (dry run)" if dry else "")
    r = Result("bad" if res.get("errors") else ("warn" if dry else "ok"), title)
    r.rows("pack", [("file", path.name), ("version", str(res.get("version"))),
                    ("signed by", str(res.get("signed_by")))])
    r.rows("items", [("selected", str(len(items))),
                     ("new", str(by_state.get("new", 0))),
                     ("already present", str(by_state.get("present", 0))),
                     ("measured locally", str(by_state.get("local", 0))),
                     ("imported", str(res.get("imported", 0))),
                     ("failed", str(res.get("errors", 0)))])
    failed = ["%s: %s" % (it.get("id"), it.get("error")) for it in items if it.get("error")]
    if failed:
        r.lines("failures", failed[:20])
    if dry:
        r.note("Re-run with --yes to import the %d new item(s)." % by_state.get("new", 0))
    r.set(result=res)
    return r


# ---------------------------------------------------------------------------
# execute apilib harvest
# ---------------------------------------------------------------------------
def harvest_schema(ctx, args):
    """Read one appliance's build through both channels into the API library:
    SSH ``tree`` + ``show full-configuration`` + a REST shape probe of what the
    library lacks. Read-only against the box; runs as the service account."""
    plain = [a for a in args if not a.startswith("--")]
    if not plain:
        return Result("info", "apilib harvest").lines("", [
            "usage: satom " + HARVEST_USAGE, "",
            "Reads the appliance's CLI schema (tree), its show full-configuration",
            "field names (hidden fields included) and probes the REST paths the",
            "library does not cover. Nothing is changed on the appliance."])
    target = plain[0]
    if not _APPLIANCE_RE.match(target):
        return Result("bad", "apilib harvest").lines("", ["%r is not an appliance id or name"
                                                          % target[:80]])
    if ctx.role == "standby":
        return Result("bad", "apilib harvest").lines("", [
            "this node is the STANDBY: its database is read-only. Harvest on the primary."])
    extra = ["schema-harvest", target]
    if "--no-probe" in args:
        extra.append("--no-probe")
    rc, out, err = _flask_apilib(ctx, extra, timeout=900)
    res = _json_tail(out)
    if res is None:
        r = Result("bad", "apilib harvest")
        r.lines("", ((err or out) or "no output").splitlines()[-25:])
        return r
    r = Result("ok" if res.get("ok") else "bad", "apilib harvest")
    r.rows("appliance", [("name", str(res.get("appliance"))),
                         ("product", str(res.get("product"))),
                         ("build", str(res.get("version")))])
    tree = res.get("tree") or {}
    full = res.get("full") or {}
    probe = res.get("probe") or {}
    ch = res.get("channels") or {}
    r.rows("evidence", [
        ("cli_tree", "#%s %s" % (tree.get("evidence_id"),
                                  "healthy" if tree.get("healthy") else
                                  "UNHEALTHY: %s" % tree.get("skip_reason"))),
        ("cli_full", "#%s %s (%s)" % (full.get("evidence_id"),
                                       "healthy" if full.get("healthy") else
                                       "UNHEALTHY: %s" % full.get("skip_reason"),
                                       full.get("source") or "-")),
        ("REST probe", "%s probed, %s GETs" % (probe.get("probed", 0), probe.get("spent", 0))
         if probe.get("probed") is not None else str(probe.get("skipped_reason") or "-"))])
    if ch:
        r.rows("channels", [(k, str(ch.get(k, 0))) for k in
                            ("both", "cli_only", "hidden", "rest_only", "unknown")]
               + [("complete", str(ch.get("complete")))])
    r.note(res.get("msg") or "")
    r.set(result=res)
    return r


# ---------------------------------------------------------------------------
# execute apilib compat / channels — read the library, change nothing
# ---------------------------------------------------------------------------
def _args_ok(title, plain, n, usage):
    if len(plain) < n:
        return Result("info", title).lines("", ["usage: satom " + usage])
    if plain[0] not in PRODUCTS:
        return Result("bad", title).lines("", ["%r is not a product (%s)"
                                               % (plain[0][:40], ", ".join(PRODUCTS))])
    bad = [b for b in plain[1:n] if not _BUILD_RE.match(b)]
    if bad:
        return Result("bad", title).lines("", ["%r is not a firmware build" % bad[0][:40]])
    return None


def apilib_compat(ctx, args):
    """Two builds of one product through both channels: objects and fields
    added / removed, option / type / range changes, rename candidates."""
    plain = [a for a in args if not a.startswith("--")]
    early = _args_ok("apilib compat", plain, 3, COMPAT_USAGE)
    if early:
        return early
    rc, out, err = _flask_apilib(ctx, ["compat"] + plain[:3], timeout=600)
    res = _json_tail(out)
    if res is None:
        r = Result("bad", "apilib compat")
        r.lines("", ((err or out) or "no output").splitlines()[-25:])
        return r
    r = Result("ok", "apilib compat %s %s -> %s" % (res["product"], res["base"], res["target"]))
    rest = (res.get("rest") or {}).get("totals") or {}
    r.rows("REST evidence", [
        ("measured", "%s: %s, %s: %s" % (res["base"], res["base_measured"],
                                         res["target"], res["target_measured"])),
        ("fields", "+%s / -%s, renamed %s, not comparable %s" % (
            rest.get("fields_added", 0), rest.get("fields_removed", 0),
            rest.get("fields_renamed", 0), rest.get("fields_unknown", 0)))])
    tree = res.get("tree")
    if tree is None:
        r.status = "warn"
        r.note("no CLI schema comparison: %s" % res.get("tree_reason"))
    else:
        t = tree.get("totals") or {}
        r.rows("CLI schema (tree)", [
            ("objects", "+%d / -%d" % (len(tree["endpoints_added"]),
                                       len(tree["endpoints_removed"]))),
            ("fields", "+%s / -%s" % (t.get("fields_added", 0), t.get("fields_removed", 0))),
            ("options changed", str(t.get("options_changed", 0))),
            ("retyped", str(t.get("retyped", 0))),
            ("ranges changed", str(t.get("ranges_changed", 0))),
            ("defaults changed", str(t.get("defaults_changed", 0))),
            ("field rename candidates", str(t.get("rename_candidates", 0))),
            ("object rename candidates", str(t.get("endpoint_rename_candidates", 0))),
            ("moves", str(t.get("field_moves", 0)))])
        if tree.get("endpoint_rename_candidates") or tree.get("rename_candidates"):
            r.lines("rename candidates (same CLI id; never applied)",
                    ["%s -> %s (id %s)" % (x["from"], x["to"], x["cli_id"])
                     for x in tree.get("endpoint_rename_candidates") or []]
                    + ["%s: %s -> %s (id %s)" % (x["endpoint"], x["from"], x["to"], x["cli_id"])
                       for x in tree.get("rename_candidates") or []][:40])
    r.set(result=res)
    return r


def apilib_channels(ctx, args):
    """One build: how many fields each channel serves, and which are CLI only."""
    plain = [a for a in args if not a.startswith("--")]
    early = _args_ok("apilib channels", plain, 2, CHANNELS_USAGE)
    if early:
        return early
    rc, out, err = _flask_apilib(ctx, ["channels"] + plain[:2], timeout=600)
    res = _json_tail(out)
    if res is None:
        r = Result("bad", "apilib channels")
        r.lines("", ((err or out) or "no output").splitlines()[-25:])
        return r
    s = res.get("summary") or {}
    r = Result("ok" if s.get("complete") else "warn",
               "apilib channels %s %s" % (res["product"], res["version"]))
    r.rows("fields", [(k, str(s.get(k, 0))) for k in
                      ("both", "cli_only", "hidden", "rest_only", "unknown", "meta",
                       "doc_conflicts")]
           + [("tree measured", str(s.get("tree_measured"))),
              ("REST measured", str(s.get("rest_measured"))),
              ("complete", str(s.get("complete")))])
    for k in ("cli_only", "hidden", "rest_only"):
        if res.get(k):
            r.lines(k.replace("_", " "), res[k][:40])
    r.set(result=res)
    return r
