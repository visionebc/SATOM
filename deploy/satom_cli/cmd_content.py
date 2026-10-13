"""What SATOM holds ABOUT the devices: signature freshness, measured GUI
layouts, naming conventions. STDLIB ONLY (see context.py).

Every command here reads what the node already stored; none calls a device.
That is the same contract as ``get device config``: the moment the operator
reaches for these is often the moment the device, its credentials or the web
console are the thing that is broken.

* ``get signatures status`` reads the freshness state the daily
  ``signature_check`` writes (``app_settings``) and the newest snapshot of the
  local signature index. The verdict mirrors
  ``app/services/signature_freshness.assess`` — a device that reports it never
  downloaded an update is stale whatever its version says.
* ``show layouts`` reads the measured GUI templates under
  ``data/gui-templates/<product>/<page>/<version>-<build>.json`` (imported from
  knowledge packs) and says which managed device has a layout for its exact
  build.
* ``get device naming`` is DELEGATED: the analysis is the application's
  (``flask naming discover``, :mod:`app.services.naming_discovery`), run as the
  service account, so the console and the Discovery tab cannot disagree.
"""
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from . import dbq
from .context import run
from .render import Result

DEFAULT_SIG_MAX_DAYS = 7
GUI_DIR = "data/gui-templates"

# A build in a firmware string: FortiWeb ``7.6.8,build1128``, FortiGate
# ``v8.0.1,build0245``, FortiAnalyzer ``v7.6.7-build3737 260601``. FortiADC
# writes ``7.6.7 0676`` with no ``build`` word; a six-digit release date is not
# a build. Mirrors ``app/services/gui_store.build_of``.
_BUILD_RE = re.compile(r"build\s*0*(\d+)", re.I)
_ADC_FW_RE = re.compile(r"^\s*v?\d+\.\d+\.\d+\s+0*(\d{1,5})\s*$")
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_FILE_RE = re.compile(r"^(\d+\.\d+\.\d+)-(\d+)\.json$")


# -- signatures -------------------------------------------------------------
def _parse_ts(raw):
    try:
        at = datetime.fromisoformat(str(raw or ""))
    except ValueError:
        return None
    return at if at.tzinfo else at.replace(tzinfo=timezone.utc)


def assess_signature(entry, now, limit_days):
    """(status, age_days, reason). Same rules as signature_freshness.assess."""
    if entry.get("error"):
        return "unreadable", None, entry["error"]
    unlicensed = entry.get("licence_valid") is False
    lic = "; its FortiGuard licence is not valid" if unlicensed else ""
    if entry.get("never_updated"):
        return ("stale", None,
                "the device reports it never downloaded a signature update" + lic)
    since = _parse_ts(entry.get("device_last_update")) or _parse_ts(entry.get("last_change"))
    if since is None:
        return "unreadable", None, "no update time known"
    age = (now - since).days
    if (now - since).total_seconds() > limit_days * 86400:
        return ("stale", age, "signature DB %s is %d day(s) old (limit %d)%s"
                % (entry.get("version") or "?", age, limit_days, lic))
    return "ok", age, ""


def signatures_status(ctx, args):
    settings, err = dbq.query(ctx, dbq.SIGNATURE_SETTINGS)
    if settings is None:
        r = Result("warn", "signatures — unavailable", exit_code=4)
        r.rows("", [("reason", err)])
        return r
    kv = {k: v for k, v in ((s + ["", ""])[:2] for s in settings)}
    try:
        limit = max(1, min(365, int(float(kv.get("alerts.signature_max_days")
                                          or DEFAULT_SIG_MAX_DAYS))))
    except ValueError:
        limit = DEFAULT_SIG_MAX_DAYS
    try:
        state = json.loads(kv.get("signatures.db_state") or "{}")
    except ValueError:
        state = {}
    if not isinstance(state, dict):
        state = {}
    names = {}
    appl, _ = dbq.query(ctx, dbq.APPLIANCES)
    for a in appl or []:
        names[a[0]] = a[1]
    now = datetime.now(timezone.utc)

    r = Result("ok", "signature databases — %d device(s), limit %d day(s)"
               % (len(state), limit))
    rows, data = [], []
    for aid, entry in sorted(state.items(), key=lambda kv_: str(kv_[1].get("name", ""))):
        if not isinstance(entry, dict):
            continue
        status, age, reason = assess_signature(entry, now, limit)
        age_txt = "%dd" % age if age is not None else "-"
        rows.append(("%-3s %-14s" % (aid, entry.get("name") or names.get(aid, "?")),
                     "%-11s %-10s age=%-5s checked=%s via %s%s"
                     % (status, entry.get("version") or "?", age_txt,
                        (entry.get("checked_at") or "?")[:16].replace("T", " "),
                        entry.get("channel") or "?",
                        ("  <- " + reason) if reason else "")))
        data.append(dict(entry, appliance_id=aid, status=status, age_days=age,
                         reason=reason))
        if status != "ok":
            r.worst("warn")
    if rows:
        r.rows("FortiGuard signature DB per device", rows)
    else:
        r.worst("warn")
        r.lines("FortiGuard signature DB per device", [
            "nothing recorded — the daily 'signature_check' action has not run "
            "(see: satom get scheduler status)"])

    sources = []
    for k, v in sorted(kv.items()):
        if not k.startswith("signatures.source."):
            continue
        product = k.split(".", 2)[2]
        sid = v.strip()
        sources.append((product, "%s (#%s)" % (names.get(sid, "unknown appliance"), sid)
                        if sid else "none configured"))
    if not any(s[1] != "none configured" for s in sources):
        r.worst("warn")
        sources = sources or [("fortiweb", "none configured")]
        r.note("No signature source: the local index is never refreshed. Pick one "
               "under Fleet -> WAF -> Signatures (an alert finding says the same).")
    r.rows("signature source", sources)

    snaps, _ = dbq.query(ctx, dbq.SIGNATURE_SNAPSHOTS)
    idx = []
    for s in snaps or []:
        (product, dbv, src, count, added, removed, changed, base, taken) = (s + [""] * 9)[:9]
        idx.append((product, "DB %s from %s, %s signatures, taken %s%s"
                    % (dbv or "?", src or "?", count, taken,
                       " (baseline)" if dbq.bool_of(base)
                       else "  +%s -%s ~%s" % (added, removed, changed))))
        src_entry = next((e for e in state.values()
                          if isinstance(e, dict) and e.get("name") == src), None)
        if src_entry and src_entry.get("version") and src_entry["version"] != dbv:
            r.worst("warn")
            r.note("The %s index holds DB %s but its source %s now reports %s: the next "
                   "signature_check collects it (or: satom execute scheduler run <id>)."
                   % (product, dbv, src, src_entry["version"]))
    r.rows("local signature index", idx or [("", "empty — nothing collected yet")])
    r.note("State written by the daily 'signature_check' action; this command "
           "never contacts a device.")
    r.set(devices=data, limit_days=limit)
    return r


# -- measured GUI layouts ---------------------------------------------------
def build_of(firmware):
    fw = str(firmware or "")
    m = _BUILD_RE.search(fw) or _ADC_FW_RE.match(fw)
    return str(int(m.group(1))) if m else ""


def version_of(firmware):
    m = _VERSION_RE.search(str(firmware or ""))
    return ".".join(m.groups()) if m else ""


def match_layout(builds, firmware):
    """How close the node's layouts come to one device firmware.

    ``builds`` is a set of ``(version, build)``. Answers exact / same version /
    same train / other / none. The page picks the closest one itself
    (``gui_store.resolve``); this only tells the operator how close it is.
    """
    if not builds:
        return "none", ""
    ver, bld = version_of(firmware), build_of(firmware)
    if ver and bld and (ver, bld) in builds:
        return "exact", "%s-%s" % (ver, bld)
    same = sorted("%s-%s" % b for b in builds if b[0] == ver)
    if same:
        return "same version", ", ".join(same)
    train = ".".join(ver.split(".")[:2])
    near = sorted("%s-%s" % b for b in builds if train and b[0].startswith(train + "."))
    if near:
        return "same train", ", ".join(near)
    return "other build", ", ".join(sorted("%s-%s" % b for b in builds))


def _scan_layouts(root):
    """{product: {(version, build): counters}} — reads every template file."""
    out = {}
    for pdir in sorted(p for p in root.iterdir() if p.is_dir()):
        per = out.setdefault(pdir.name, {})
        for f in pdir.glob("*/*.json"):
            m = _FILE_RE.match(f.name)
            if not m:
                continue
            c = per.setdefault((m.group(1), m.group(2)),
                               {"pages": 0, "monitor": 0, "not_in_gui": 0,
                                "packs": set(), "built": ""})
            c["pages"] += 1
            try:
                doc = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if doc.get("gui_absent"):
                c["not_in_gui"] += 1
            elif doc.get("monitor"):
                c["monitor"] += 1
            imp = doc.get("_import") or {}
            if imp.get("provenance"):
                c["packs"].add(str(imp["provenance"]).rsplit(":", 1)[-1])
            c["built"] = max(c["built"], str(imp.get("built_at") or ""))
    return out


def _unreadable(ctx):
    r = Result("warn", "measured GUI layouts — unreadable as %s" % ctx.user, exit_code=4)
    r.lines("why", ["data/ is 0750 for the service account by design.",
                    "Re-run as root: sudo satom show layouts"])
    return r


def show_layouts(ctx, args):
    root = ctx.app_dir / GUI_DIR
    try:
        # is_dir() raises, not answers False, when data/ itself is closed to
        # this account: "none on this node" would then be a lie.
        present = root.is_dir()
    except PermissionError:
        return _unreadable(ctx)
    if not present:
        r = Result("info", "measured GUI layouts — none on this node")
        r.lines("why", [
            "No knowledge pack with GUI templates has been imported here.",
            "The device pages fall back to SATOM's own forms; nothing 404s.",
            "Import: satom execute knowledge fetch --import --yes",
        ])
        return r
    try:
        layouts = _scan_layouts(root)
    except PermissionError:
        return _unreadable(ctx)
    want = args[0] if args and not args[0].startswith("-") else ""
    r = Result("ok", "measured GUI layouts")
    for product, per in sorted(layouts.items()):
        if want and product != want:
            continue
        rows = []
        for (ver, bld), c in sorted(per.items()):
            rows.append(("%s build %s" % (ver, bld),
                         "%d pages (%d config, %d live monitor, %d not in GUI)  "
                         "pack %s  built %s"
                         % (c["pages"], c["pages"] - c["monitor"] - c["not_in_gui"],
                            c["monitor"], c["not_in_gui"],
                            ", ".join(sorted(c["packs"])) or "?", c["built"] or "?")))
        r.rows(product, rows or [("", "no template")])
    if want and want not in layouts:
        r.status = "bad"
        r.lines("unknown product", ["no layouts for %r; products here: %s"
                                    % (want, ", ".join(sorted(layouts)) or "none")])
        return r

    appl, err = dbq.query(ctx, dbq.APPLIANCES)
    if appl is None:
        r.note("Device match skipped: %s" % err)
    else:
        rows = []
        for a in appl:
            aid, name, kind, _host, _st, _m, _c, fw = (a + [""] * 8)[:8]
            if want and kind != want:
                continue
            builds = set(layouts.get(kind, {}))
            how, which = match_layout(builds, fw)
            ver, bld = version_of(fw), build_of(fw)
            runs = ("%s build %s" % (ver, bld) if ver and bld
                    else ver or "firmware unknown")
            rows.append(("%-3s %-14s %-18s" % (aid, name, kind),
                         "%-13s runs %-17s layout %s" % (how, runs, which or "-")))
        r.rows("devices", rows or [("", "no appliance registered")])
        r.note("exact = a layout measured on that build. Otherwise the page uses the "
               "closest one and says so; 'none' means SATOM's own forms.")
    r.set(layouts={p: {"%s-%s" % k: {kk: (sorted(vv) if isinstance(vv, set) else vv)
                                      for kk, vv in c.items()}
                       for k, c in per.items()} for p, per in layouts.items()})
    return r


# -- naming discovery (delegated) ------------------------------------------
NAMING_USAGE = "get device naming [<device> [--table <type>]] [--product <p>]"


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
        if a in ("--table", "--product"):
            skip = True
            continue
        if not a.startswith("--"):
            out.append(a)
    return out


def _flask_naming(ctx, extra, timeout=300):
    """``flask naming <extra>`` as the service account. (rc, out, err)."""
    return _flask_group(ctx, "naming", extra, timeout)


def _flask_group(ctx, group, extra, timeout=300):
    """``flask <group> <extra>`` as the service account. (rc, out, err)."""
    flask = ctx.app_dir / "venv" / "bin" / "flask"
    if not flask.exists():
        return 127, "", "venv/bin/flask missing — run 'execute reinstall venv'"
    env = dict(os.environ)
    for k, v in ctx.env.items():
        env.setdefault(k, v)
    env["FLASK_APP"] = "wsgi.py"
    env["HOME"] = str(ctx.app_dir)
    cmd = [str(flask), group] + list(extra)
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


def device_naming(ctx, args):
    if not ctx.is_root and ctx.user != ctx.app_user:
        r = Result("warn", "naming — needs the service account's read access", exit_code=4)
        r.lines("why", ["The configuration trees live under data/ (0750, %s)." % ctx.app_user,
                        "Re-run as root: sudo satom %s" % NAMING_USAGE])
        return r
    plain = _plain(args)
    table, product = _opt(args, "--table"), _opt(args, "--product")
    extra = ["discover"] + plain[:1]
    if table:
        extra += ["--table", table]
    if product and not plain:
        extra += ["--product", product]
    rc, out, err = _flask_naming(ctx, extra)
    doc = _json_tail(out)
    if doc is None:
        return Result("bad", "naming").lines("", ((err or out) or "no output")
                                             .splitlines()[-25:])
    if doc.get("error"):
        r = Result("bad", "naming — %s" % doc["error"], exit_code=1)
        r.lines("known", doc.get("appliances") or doc.get("tables")
                or doc.get("products") or [])
        return r
    if doc.get("mode") == "device":
        return _render_device(doc, table)
    return _render_fleet(doc)


def _render_device(doc, table):
    title = "naming — %s (%s)" % (doc["device"], doc["product"])
    if doc.get("missing"):
        r = Result("warn", title + ": no configuration tree", exit_code=1)
        r.lines("why", ["SATOM holds no _config.json for this device yet.",
                        "It appears after the next device sync (hourly), or now with",
                        "  satom execute scheduler run <device_sync id>"])
        return r
    r = Result("ok", title)
    r.rows("tree", [("generated", str(doc.get("generated_at") or "?")),
                    ("objects", "%s yours, %s factory (counted apart)"
                     % (doc.get("user_objects"), doc.get("factory_objects")))])
    rows = []
    for t in doc["tables"]:
        if t["status"] == "factory_only":
            continue
        main = t.get("main") or "-"
        extra = ""
        if t.get("scheme"):
            extra += "  scheme=%s (%s/%s)" % (t["scheme"], t.get("scheme_conform"), t["user"])
        if t["exceptions_total"]:
            extra += "  exceptions=%d" % t["exceptions_total"]
        rows.append(("%s / %s" % (t["section"], t["label"]),
                     "%-28s %s/%s%s" % (main, t["conform"], t["user"], extra)))
    r.rows("pattern per object type  (follows/total)", rows or [("", "no named object")])
    if table:
        for t in doc["tables"]:
            r.rows("%s (%s) — variants" % (t["label"], t["table"]),
                   [(v["pattern"], str(v["count"])) for v in t["variants"]] or [("", "-")])
            exc = [(e.get("name", "?"), e.get("reason", "")) for e in t["exceptions"]]
            if t["exceptions_total"] > len(exc):
                exc.append(("...", "%d more" % (t["exceptions_total"] - len(exc))))
            r.rows("%s — exceptions" % t["table"], exc or [("", "none")])
            if t.get("linked"):
                r.rows("%s — shares {name} with" % t["table"],
                       [(x["table"], "%s of %s" % (x["matched"], x["total"]))
                        for x in t["linked"]])
    else:
        r.note("Detail of one type: satom get device naming %s --table '<label or key>'"
               % doc["device"])
    r.note("Read from the stored configuration tree; the device is not contacted. "
           "Adopt or adapt a pattern into the scheme under Administrator -> Naming.")
    r.set(result=doc)
    return r


def _render_fleet(doc):
    r = Result("ok", "naming — fleet view")
    if not doc.get("products"):
        r.status = "info"
        r.lines("", ["no appliance registered"])
        return r
    for p in doc["products"]:
        rows = []
        for t in p["tables"]:
            verdict = ("one device only" if t["single"]
                       else "all agree" if t["agree"] else "devices differ")
            rows.append(("%s / %s" % (t["section"], t["label"]),
                         "%-28s %s%s" % (t["consensus"], verdict,
                                         "  scheme=%s" % t["scheme"] if t.get("scheme") else "")))
        head = "%s — %d device(s)" % (p["product"], len(p["devices"]))
        r.rows(head, rows or [("", "no named object")])
        if p.get("missing"):
            r.note("%s: no configuration tree yet for %s"
                   % (p["product"], ", ".join(p["missing"])))
    r.note("One device: satom get device naming <device>")
    r.set(result=doc)
    return r


# -- "Not in GUI, but in CLI" (delegated) ----------------------------------
NIG_USAGE = "get device not-in-gui <device> [--endpoint <key|cli path>]"

#: Field names listed per object before "... N more"; --endpoint lists them all.
_NIG_FIELDS = 12


def _names(fields, full):
    keys = [f["key"] if isinstance(f, dict) else f for f in fields]
    shown = keys if full else keys[:_NIG_FIELDS]
    more = len(keys) - len(shown)
    return ", ".join(shown) + (" ... %d more" % more if more else "")


def device_not_in_gui(ctx, args):
    if not ctx.is_root and ctx.user != ctx.app_user:
        r = Result("warn", "not in GUI — needs the service account's read access", exit_code=4)
        r.lines("why", ["The API library and the GUI layouts live under data/ (0750, %s)."
                        % ctx.app_user, "Re-run as root: sudo satom %s" % NIG_USAGE])
        return r
    plain = [a for a in args if not a.startswith("--")
             and a != _opt(args, "--endpoint")]
    if not plain:
        return Result("bad", "usage: satom %s" % NIG_USAGE, exit_code=2)
    endpoint = _opt(args, "--endpoint")
    extra = ["inventory", plain[0]] + (["--endpoint", endpoint] if endpoint else [])
    rc, out, err = _flask_group(ctx, "not-in-gui", extra)
    doc = _json_tail(out)
    if doc is None:
        return Result("bad", "not in GUI").lines("", ((err or out) or "no output")
                                                 .splitlines()[-25:])
    if doc.get("error"):
        r = Result("bad", "not in GUI — %s" % doc["error"], exit_code=1)
        r.lines("known", doc.get("appliances") or doc.get("endpoints") or [])
        return r
    full = bool(endpoint)
    r = Result("ok", "Not in GUI, but in CLI — %s (%s %s)"
               % (doc["device"], doc["product"], doc.get("version") or "build unknown"))
    if not doc.get("version"):
        r.status = "warn"
    if doc.get("note"):
        r.note(doc["note"])
    if doc["objects"]:
        r.rows("objects only the CLI serves (written over SSH)",
               [(o["cli_path"] or o["endpoint"], _names(o["fields"], full) or "-")
                for o in doc["objects"]])
    if doc["fields"]:
        r.rows("CLI-only fields of REST objects (written over SSH)",
               [(o["cli_path"] or o["endpoint"], _names(o["fields"], full))
                for o in doc["fields"]])
    pages = [p for p in doc["layout_pages"] if p["rest_not_in_gui"]]
    if pages:
        r.rows("REST fields the Fortinet GUI does not show (written over REST)",
               [(p["endpoint"], "%d: %s" % (len(p["rest_not_in_gui"]),
                                            _names(p["rest_not_in_gui"], full)))
                for p in pages])
    if len(pages) < len(doc["layout_pages"]):
        r.note("%d measured GUI page(s) show every REST field of their object."
               % (len(doc["layout_pages"]) - len(pages)))
    if doc["absent"]:
        r.rows("objects the device's GUI does not draw",
               [("%s / %s" % (o["group"], o["label"]) if o["group"] else o["label"],
                 "%s%s" % (o["endpoint"], "" if o["page"] else "  (no GUI page)"))
                for o in doc["absent"]])
    if not (doc["objects"] or doc["fields"] or pages or doc["absent"]):
        r.lines("", ["nothing outside the GUI is known for this build"])
    if not full:
        r.note("All fields of one object: satom get device not-in-gui %s --endpoint <key>"
               % doc["device"])
    r.note("From the API library and the measured GUI layouts; the device is not "
           "contacted. Current values and the editor: %s" % doc["page"])
    r.set(result=doc)
    return r
