"""API library packs from the console (docs/api-library.md §11).

Software Update is the normal path; this is the same import for a node with no
browser, and the one the installer calls on a fresh node. The import itself is
the application's (``flask apilib pack import``): a schema /2 pack is checked
against the keys of its lane (``deploy/pack-keys/<lane>/`` + ``/etc/satom/
pack-keys/<lane>/``), a legacy /1 pack against the update trust store, and
items this node measured itself are never touched. This module only finds the pack, stages it where the service
account can read it, and runs the import AS that account — run as root, the
release notes and field schemas it writes would be files the web worker can no
longer update (the same root-owned-file trap ``execute repair permissions``
exists for).
"""
import json
import os
import re
import shutil
import tarfile
from pathlib import Path

from .context import run
from .render import Result

PACK_RE = re.compile(r"^satom-apipack-[A-Za-z0-9._-]{1,64}\.tar\.gz$")
SECTIONS = ("library", "docs", "cli-coverage", "factory", "field-map", "baselines",
            "signature-meta")
USAGE = ("execute apipack import <file.tar.gz|shipped> [--yes] "
         "[--product <p>[,<p>...]] [--section <s>[,<s>...]]")
HARVEST_USAGE = "execute apilib harvest <appliance-id|name> [--no-probe]"
_APPLIANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$")
COMPAT_USAGE = "execute apilib compat <product> <buildA> <buildB> [--json]"
CHANNELS_USAGE = "execute apilib channels <product> <build> [--json]"
PRODUCTS = ("fortiweb", "fortiadc", "fortiauthenticator", "fortianalyzer", "fortigate")
_BUILD_RE = re.compile(r"^[0-9][0-9A-Za-z._-]{0,31}$")


#: Same series rule as app/services/api_pack.py (this CLI does not import the
#: app): a schema /2 pack's series is its ``lane`` (api_pack | knowledge); a
#: legacy /1 ``satom-apipack-kb-*`` is a knowledge pack built by
#: satom-harvester, any other /1 pack a release pack. Release packs and /2
#: api_packs are ONE lineage (3.0.0 supersedes 2.13.0). Every pack is
#: cumulative, so per lineage only the newest is imported: api_pack first,
#: then knowledge. The ``harvester`` lane is transport-only, never imported.
SERIES = ("release", "api_pack", "knowledge", "harvester")
LINEAGES = ("api_pack", "knowledge")
_LINEAGE = {"release": "api_pack", "api_pack": "api_pack", "knowledge": "knowledge"}
KB_LABEL = "knowledge pack (satom-harvester)"
LABELS = {"api_pack": "API pack (pinned to a SATOM release)", "knowledge": KB_LABEL,
          "harvester": "harvester transport pack (not importable)"}
_PEEK = {}


def _manifest(path):
    """The pack's manifest.json, UNVERIFIED (labels and ordering only: the
    import verifies the signature). ``{}`` when unreadable."""
    try:
        st = path.stat()
    except OSError:
        return {}
    key = (str(path), st.st_size, st.st_mtime)
    if key not in _PEEK:
        out = {}
        try:
            with tarfile.open(path, "r:gz") as tf:
                for m in tf:
                    parts = Path(m.name).parts
                    if len(parts) == 2 and parts[1] == "manifest.json" and m.isfile():
                        data = json.loads(tf.extractfile(m).read().decode("utf-8"))
                        out = data if isinstance(data, dict) else {}
                        break
        except (OSError, ValueError, tarfile.TarError, EOFError):
            out = {}
        _PEEK[key] = out
    return _PEEK[key]


def _series(name, path=None):
    m = _manifest(path) if path is not None else {}
    if m.get("schema") == "satom.api-pack/2" and isinstance(m.get("lane"), str) and m["lane"]:
        return m["lane"] if m["lane"] in SERIES else "harvester"
    return "knowledge" if name[len("satom-apipack-"):].startswith("kb-") else "release"


def _version_key(name):
    """Tagged parts, so ``kb-20261007.3`` and ``2.12.0`` never compare a word
    with a number (a plain list did: TypeError the day a kb pack shipped)."""
    ver = name[len("satom-apipack-"):-len(".tar.gz")]
    return tuple((0, int(x), "") if x.isdigit() else (1, 0, x)
                 for x in re.split(r"[.-]", ver))


def _snapshot(manifest):
    snap = manifest.get("snapshot") if isinstance(manifest.get("snapshot"), dict) else {}
    run_id = snap.get("run_id")
    return (str(manifest.get("content_fingerprint") or ""),
            run_id if isinstance(run_id, int) and not isinstance(run_id, bool) else None)


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


def shipped_packs(ctx):
    """The newest shipped pack of each lineage, in import order (api_pack,
    then knowledge). Older packs of a lineage are superseded: the newest
    carries everything they did."""
    newest = {}
    for p in _packs(_shipped_dir(ctx)):
        lin = _LINEAGE.get(_series(p.name, p))
        if lin:
            newest[lin] = p          # _packs() is ascending by version
    return [newest[s] for s in LINEAGES if s in newest]


def _full_imports(ctx):
    """Import-log records of full passes with no failed item — the same rule
    as api_pack.pending_shipped()."""
    out = []
    log = ctx.app_dir / "data" / "apipacks" / "imports"
    for f in log.glob("*.json") if log.is_dir() else []:
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(rec, dict) and not rec.get("errors") and not rec.get("partial") \
                and rec.get("pack"):
            out.append(rec)
    return out


def _imported_names(ctx):
    return {rec["pack"] for rec in _full_imports(ctx)}


def covered_by(path, imported):
    """An imported pack whose snapshot already carries ``path``'s (same
    content fingerprint, or a newer harvester run of either lane), or "".
    Importing a covered pack would only bring older content back."""
    fp, run_id = _snapshot(_manifest(path))
    for rec in imported:
        ofp, orun = _snapshot(rec)
        if fp and ofp == fp:
            return rec["pack"]
        if run_id is not None and orun is not None and orun >= run_id:
            return rec["pack"]
    return ""


def pending_packs(ctx):
    """Shipped packs this node has not imported yet and that no imported pack
    already covers, in import order."""
    full = _full_imports(ctx)
    done = {rec["pack"] for rec in full}
    return [p for p in shipped_packs(ctx) if p.name not in done and not covered_by(p, full)]


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
    current = {p.name for p in shipped_packs(ctx)}
    pending = {p.name for p in pending_packs(ctx)}
    full = _full_imports(ctx)
    done = {rec["pack"] for rec in full}

    def what(p):
        out = "shipped with this release (api-packs/)"
        series = _series(p.name, p)
        if series in LABELS:
            out += ", " + LABELS[series]
        if p.name not in current:
            out += ", superseded"
        elif p.name in pending:
            out += ", NOT IMPORTED YET"
        elif p.name not in done and covered_by(p, full):
            out += ", covered by %s" % covered_by(p, full)
        return out
    rows = [(p.name, what(p)) for p in _packs(_shipped_dir(ctx))]
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
        prov = rec.get("provenance") or "pack:%s:satom-apipack-%s" % (
            "knowledge" if str(rec.get("version") or "").startswith("kb-") else "api_pack",
            rec.get("version"))
        hist.append((f.name.split("-", 1)[0], "%s: %s imported, %s failed (%s) [%s]" % (
            rec.get("version"), rec.get("imported", 0), rec.get("errors", 0),
            rec.get("actor") or "?", prov)))
    if hist:
        r.rows("recent imports", hist)
    r.note("Import: satom execute apipack import shipped        (dry run)")
    r.note("        satom execute apipack import shipped --yes")
    return r


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------
def import_apipack(ctx, args):
    """Import a signed API pack. Without --yes it only reports what would happen.

    ``shipped`` imports every shipped pack this node has not imported yet: the
    newest release pack, then the newest knowledge pack (satom-harvester)."""
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
            "'shipped' imports every pack the installed release carries in api-packs/",
            "that this node has not imported yet: the newest API pack, then the",
            "newest knowledge pack (satom-harvester). A pack whose snapshot an",
            "imported pack already carries is skipped.",
            "A pack is verified with the keys of its lane (api_pack | knowledge);",
            "a legacy 2.x pack with the update trust store (satom show trust).",
            "Items this node measured itself are never replaced."])

    if ctx.role == "standby":
        return Result("bad", "apipack import").lines("", [
            "this node is the STANDBY: its database is read-only.",
            "Import on the primary; the library replicates here and the data sync",
            "copies the release notes and field schemas."])

    if plain[0] == "shipped":
        if not shipped_packs(ctx):
            return Result("bad", "apipack import").lines("", [
                "this release carries no pack in %s" % _shipped_dir(ctx)])
        srcs = pending_packs(ctx)
        if not srcs:
            full = _full_imports(ctx)
            return Result("ok", "apipack import").lines("", [
                "every shipped pack is already imported on this node:",
                *("  " + p.name + ("  (covered by %s)" % covered_by(p, full)
                                   if p.name not in _imported_names(ctx) else "")
                  for p in shipped_packs(ctx)),
                "To import one again: satom execute apipack import %s/<pack> --yes"
                % _shipped_dir(ctx)])
    else:
        src = Path(plain[0]).expanduser()
        if not src.is_file():
            return Result("bad", "apipack import").lines("", ["%s is not a file" % src])
        if not PACK_RE.match(src.name):
            return Result("bad", "apipack import").lines("", [
                "%r is not an API pack name (satom-apipack-<version>.tar.gz)" % src.name])
        srcs = [src]

    products = _opt_list(args, "--product")
    sections = _opt_list(args, "--section")
    bad = [s for s in sections if s not in SECTIONS]
    if bad:
        return Result("bad", "apipack import").lines("", [
            "unknown section(s): %s (valid: %s)" % (", ".join(bad), ", ".join(SECTIONS))])
    dry = "--yes" not in args
    results = [_import_file(ctx, src, products, sections, dry) for src in srcs]
    if len(results) == 1:
        return results[0]
    # Several packs: one report, the worst status wins, every pack's rows kept.
    rank = {"ok": 0, "info": 0, "warn": 1, "bad": 2}
    worst = max(results, key=lambda r: rank.get(r.status, 2))
    r = Result(worst.status, "apipack import%s: %d packs" % (" (dry run)" if dry else "",
                                                             len(results)))
    for one in results:
        res = one.data.get("result") or {}
        r.rows(one.data.get("pack", "?"), [
            ("version", str(res.get("version"))), ("signed by", str(res.get("signed_by"))),
            ("status", one.status),
            ("imported", str(res.get("imported", 0))), ("failed", str(res.get("errors", 0)))])
        for heading, (kind, body) in one.sections:
            if kind == "lines" and heading in ("failures", ""):
                r.lines("%s: %s" % (one.data.get("pack", "?"), heading or "error"),
                        list(body)[:20])
    if dry:
        r.note("Re-run with --yes to import them.")
    r.set(results=[one.data for one in results])
    return r


def _import_file(ctx, src, products, sections, dry):
    """``flask apilib pack import`` of ONE pack file, as a Result."""
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
    if dry:
        extra.append("--dry-run")
    rc, out, err = _flask_pack(ctx, extra)
    res = _json_tail(out)
    if res is None:
        r = Result("bad", "apipack import")
        r.lines("", ((err or out) or "no output").splitlines()[-25:])
        r.set(pack=path.name)
        return r

    items = res.get("items") or []
    by_state = {}
    for it in items:
        by_state[it.get("state")] = by_state.get(it.get("state"), 0) + 1
    title = "apipack import%s" % (" (dry run)" if dry else "")
    r = Result("bad" if res.get("errors") else ("warn" if dry else "ok"), title)
    series = _series(path.name, path)
    r.rows("pack", [("file", path.name),
                    ("version", str(res.get("version"))),
                    ("signed by", str(res.get("signed_by")))]
           + ([("schema", str(res["schema"]))] if res.get("schema") else [])
           + ([("provenance", str(res["provenance"]))] if res.get("provenance") else [])
           + ([("kind", LABELS[series])] if series in LABELS else []))
    r.rows("items", [("selected", str(len(items))),
                     ("new", str(by_state.get("new", 0))),
                     ("replaces an older pack copy", str(by_state.get("update", 0))),
                     ("already present", str(by_state.get("present", 0))),
                     ("measured locally", str(by_state.get("local", 0))),
                     ("rejected (malformed)", str(by_state.get("rejected", 0))),
                     ("unknown kind (skipped)", str(by_state.get("unknown", 0))),
                     ("imported", str(res.get("imported", 0))),
                     ("failed", str(res.get("errors", 0)))])
    failed = ["%s: %s" % (it.get("id"), it.get("error")) for it in items if it.get("error")]
    if failed:
        r.lines("failures", failed[:20])
    warnings = res.get("warnings") or []
    if warnings:
        r.worst("warn")
        r.lines("warnings", warnings[:20])
    if dry:
        r.note("Re-run with --yes to import the %d new and %d replacing item(s)."
               % (by_state.get("new", 0), by_state.get("update", 0)))
    r.set(result=res, pack=path.name)
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
