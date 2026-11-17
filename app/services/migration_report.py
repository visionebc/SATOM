"""Migration report: will THIS appliance's configuration survive a move to build X?

The device's real state is its full CLI configuration (``show full-configuration``
prints every field of every object that exists, defaults included); REST is the
operating channel, not the inventory. So the report reads the appliance's newest
dump from the backup vault (the same reader :mod:`cli_coverage` uses), parses it
with :func:`cli_schema.parse_show_full_values` (``rows=True``) and checks every
configured object and field against what the API library knows about the TARGET
build: its ``tree`` schema (fields, enum options, types, ranges), the CLI half of
:func:`api_library.compare` (removed/added objects and fields, option and type
changes, rename candidates by CLI attribute id), :func:`api_library.channels_at`
(is the field there at all, how complete is the build) and the operator's field
maps (``ApiLibFieldMap``, the only authority for a rename).

VALUES STAY IN MEMORY. A report row names objects, fields, counts of affected
rows and library facts (option lists, defaults, ranges, types); it never carries
a configuration value, so the JSON and CSV exports carry none either. Nothing
is stored.

Severities:

* ``block``     — the move would lose or reject configuration: an object or
  field removed in the target while the device holds a non-default value (any
  value when the default is unknown), an enum value the target no longer
  accepts, a value outside the target's range, a type change the value does
  not satisfy.
* ``translate`` — a rename an operator field map covers (from -> to).
* ``warn``      — cannot be guaranteed: a rename CANDIDATE (same CLI attribute
  id, no field map), a default that changed under a field the device leaves at
  the default (behaviour changes without touching anything; only when both
  defaults are known), a device object/field the target build has no evidence
  for, a target build that is not completely measured.
* ``info``      — new objects/fields in the target (with their default when
  known), removed fields the device does not use.

Verdict: ``blocked`` (any block), ``ready_with_warnings`` (any warn),
``ready``, or ``cannot_assess`` (no usable dump, unknown source build, target
schema not measured). ``source == target`` is ``ready`` with nothing to do;
``target < source`` runs the same checks, labelled ``downgrade``.

:func:`classify` is pure: same dump + same library view -> same report, rows
sorted. :func:`library_view` is the only part that reads the database.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re

from . import cli_schema
from . import firmware_versions as fv

SCHEMA = "satom.migration-report/1"

SEV_BLOCK = "block"
SEV_TRANSLATE = "translate"
SEV_WARN = "warn"
SEV_INFO = "info"
SEVERITIES = (SEV_BLOCK, SEV_TRANSLATE, SEV_WARN, SEV_INFO)
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

V_READY = "ready"
V_WARN = "ready_with_warnings"
V_BLOCKED = "blocked"
V_CANNOT = "cannot_assess"
VERDICTS = (V_READY, V_WARN, V_BLOCKED, V_CANNOT)

DIR_UPGRADE = "upgrade"
DIR_DOWNGRADE = "downgrade"
DIR_NONE = "none"
DIR_UNKNOWN = "unknown"

CSV_COLUMNS = ("severity", "code", "object", "cli_path", "field", "rows", "message",
               "detail")

_TOKEN = re.compile(r'"([^"]*)"|(\S+)')
_INT = re.compile(r"^[+-]?\d+$")


# ---------------------------------------------------------------------------
# small pure helpers
# ---------------------------------------------------------------------------

def direction(source, target) -> str:
    c = fv.compare(source, target)
    if c is None:
        return DIR_UNKNOWN
    return {1: DIR_DOWNGRADE, -1: DIR_UPGRADE, 0: DIR_NONE}[c]


def _tokens(value) -> list:
    return [a if a else b for a, b in _TOKEN.findall(str(value or ""))]


def _norm(value) -> str:
    v = str(value if value is not None else "").strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"' and v.count('"') == 2:
        v = v[1:-1]
    return v


def _cli_type(spec) -> str:
    spec = spec or {}
    return ((spec.get("attrs") or {}).get("cli_type") or spec.get("type") or "").strip()


def _satisfies(spec: dict, value) -> bool | None:
    """Does ``value`` fit the field described by ``spec``? None = cannot tell."""
    t = _cli_type(spec).strip("<>").lower()
    toks = _tokens(value)
    if not toks:
        return True
    opts = spec.get("options") or []
    if t == "option" or (spec.get("type") == "option"):
        return all(x in opts for x in toks) if opts else None
    if t in ("integer", "int", "no.", "number"):
        return all(_INT.match(x) for x in toks)
    if t in ("unsigned_integer", "uint"):
        return all(_INT.match(x) and int(x) >= 0 for x in toks)
    if t in ("string", "str", "passwd", "password", "file", "datasource"):
        return True
    if t in ("class_ip", "ip", "ipv4", "ipv6", "ipv4-address", "ipv6-address"):
        try:
            for x in toks:
                ipaddress.ip_address(x)
            return True
        except ValueError:
            return False
    if t in ("ip&netmask", "ipmask", "ipv4-classnet", "ipv6-prefix"):
        try:
            if len(toks) == 2 and "/" not in toks[0]:
                ipaddress.ip_network("%s/%s" % (toks[0], toks[1]), strict=False)
            else:
                for x in toks:
                    ipaddress.ip_network(x, strict=False)
            return True
        except ValueError:
            return False
    return None


def _row(sev, code, key, cli_path, field, rows, message, detail=None) -> dict:
    return {"severity": sev, "code": code, "object": key or "", "cli_path": cli_path or "",
            "field": field or "", "rows": int(rows or 0), "message": message,
            "detail": detail or {}}


def _sort_rows(rows: list) -> list:
    return sorted(rows, key=lambda r: (_SEV_RANK[r["severity"]], r["object"], r["field"],
                                       r["code"], r["cli_path"]))


def _counts(rows: list) -> dict:
    out = {s: 0 for s in SEVERITIES}
    for r in rows:
        out[r["severity"]] += 1
    return out


def _verdict(counts: dict) -> str:
    if counts.get(SEV_BLOCK):
        return V_BLOCKED
    if counts.get(SEV_WARN):
        return V_WARN
    return V_READY


# ---------------------------------------------------------------------------
# the library side (the only database reads)
# ---------------------------------------------------------------------------

def _tree_objects(product: str, version: str, specs: dict | None = None) -> dict:
    """``{key: {cli_path, kind, mkey, parent, cli_id}}`` from the build's
    healthy ``cli_tree`` evidence summaries (``summary.objects``), completed by
    the endpoint facts' own ``attrs`` when they carry a ``cli_path``."""
    from . import api_library as lib
    b = lib._build_row(product, version) if version else None
    out: dict = {}
    if b is None:
        return out
    for summ in lib._cli_evidence(b.id).get(lib.SOURCE_CLI_TREE, []):
        for key, meta in (summ.get("objects") or {}).items():
            if isinstance(meta, dict):
                out.setdefault(key, dict(meta))
    for key, spec in (specs or {}).items():
        attrs = (spec or {}).get("attrs") or {}
        if attrs.get("cli_path") and key not in out:
            out[key] = dict(attrs)
    return out


def _vendor_defaults(product: str, version: str) -> dict:
    """``{key: {field: default}}`` from vendor documentation covering the build."""
    from . import api_library as lib
    out: dict = {}
    if not version:
        return out
    for name, by_src in lib._vendor_state(product, lib.version_key(version), None,
                                          True).items():
        rec = by_src.get(lib.SOURCE_VENDOR) or {}
        if rec.get("verdict") != lib.VERDICT_OK or not rec.get("fields"):
            continue
        key = lib.urn_key(rec.get("urn") or name)
        for fname, spec in rec["fields"].items():
            d = (spec or {}).get("default")
            if d is not None and d != "":
                out.setdefault(key, {}).setdefault(fname, str(d))
    return out


def _completeness(ch: dict) -> dict:
    s = (ch or {}).get("summary") or {}
    total = int(s.get("fields") or 0)
    unknown = int(s.get("unknown") or 0)
    pct = round(100.0 * (total - unknown) / total, 1) if total else 0.0
    return {"pct": pct, "complete": bool(s.get("complete")), "fields": total,
            "unknown": unknown, "tree_measured": bool(s.get("tree_measured")),
            "rest_measured": bool(s.get("rest_measured"))}


def library_view(product: str, source, target) -> dict:
    """Everything :func:`classify` needs from the library, as plain data.

    Memoise it per ``(product, source, target)``: it does not depend on the
    appliance, only on the two builds.
    """
    from . import api_library as lib
    src, tgt = fv.normalize(source), fv.normalize(target)
    ms, specs_s = lib._tree_specs(product, src)
    mt, specs_t = lib._tree_specs(product, tgt)
    diff = lib._cli_compare(product, src, tgt) if (ms or mt) else {}
    ch = lib.channels_at(product, tgt) if mt else {}
    present_t: dict = {}
    for key, ep in ((ch or {}).get("endpoints") or {}).items():
        present_t[key] = sorted(f for f, rec in (ep.get("fields") or {}).items()
                                if rec.get("cli") == "yes" or rec.get("rest") == "yes")
    keys = sorted(set(specs_s) | set(specs_t))
    renames = {k: [[o, n, note] for o, n, note in v]
               for k, v in lib._renames(product, keys, src, tgt).items()}
    return {
        "product": product, "source": src, "target": tgt,
        "source_tree": bool(ms), "target_tree": bool(mt),
        "specs_source": specs_s, "specs_target": specs_t,
        "objects_source": _tree_objects(product, src, specs_s),
        "objects_target": _tree_objects(product, tgt, specs_t),
        "tree_diff": (diff or {}).get("tree") or {},
        "tree_reason": (diff or {}).get("tree_reason") or "",
        "present_target": present_t,
        "renames": renames,
        "vendor_defaults_source": _vendor_defaults(product, src),
        "vendor_defaults_target": _vendor_defaults(product, tgt),
        "completeness": _completeness(ch),
    }


# ---------------------------------------------------------------------------
# the pure classifier
# ---------------------------------------------------------------------------

def _default(view: dict, side: str, key: str, field: str):
    spec = (((view.get("specs_" + side) or {}).get(key) or {}).get("fields") or {}).get(field)
    d = (spec or {}).get("default")
    if d is not None:
        return _norm(d)
    d = ((view.get("vendor_defaults_" + side) or {}).get(key) or {}).get(field)
    return _norm(d) if d is not None else None


def _path_index(view: dict) -> dict:
    """``{cli_path: key}`` from both builds' tree summaries (source first)."""
    idx: dict = {}
    for side in ("objects_target", "objects_source"):
        for key, meta in (view.get(side) or {}).items():
            p = (meta or {}).get("cli_path")
            if p:
                idx[p] = key
    return idx


def _resolve(product: str, path: str, idx: dict, chains: dict):
    """``(key, rel_words)`` for a dump path: the tree's own mapping, else the
    product rule over the dump's ``config`` segments, else the nearest mapped
    ancestor with the rest as a nested field (FortiOS)."""
    if path in idx:
        return idx[path], []
    chain = chains.get(path)
    if chain:
        key = cli_schema.rest_path(product, path, chain)
        if key:
            return key, []
    words = path.split()
    for i in range(len(words) - 1, 0, -1):
        head = " ".join(words[:i])
        if head in idx:
            return idx[head], words[i:]
    return None, words


def _object_renames(view: dict) -> dict:
    """``{removed_key: added_key}`` — same object CLI id on both builds."""
    diff = view.get("tree_diff") or {}
    os_, ot = view.get("objects_source") or {}, view.get("objects_target") or {}
    added = {(ot.get(k) or {}).get("cli_id"): k for k in diff.get("endpoints_added") or []
             if (ot.get(k) or {}).get("cli_id")}
    out = {}
    for k in diff.get("endpoints_removed") or []:
        cid = (os_.get(k) or {}).get("cli_id")
        if cid and cid in added:
            out[k] = added[cid]
    for c in diff.get("endpoint_rename_candidates") or []:
        out.setdefault(c["from"], c["to"])
    return out


def _removed_field_rows(view, key, cli_path, field, vals, is_object=False) -> tuple:
    """(severity, rows_affected, reason) for a field that will not exist."""
    nonempty = [v for v in vals if v not in ("", None)]
    if not nonempty:
        return SEV_INFO, 0, "the device does not set it"
    bdef = _default(view, "source", key, field)
    if bdef is not None:
        nd = [v for v in nonempty if _norm(v) != bdef]
        if not nd:
            return SEV_INFO, 0, "the device keeps the default"
        return SEV_BLOCK, len(nd), "the device sets a non-default value"
    return SEV_BLOCK, len(nonempty), "the device sets a value and the default is unknown"


def classify(view: dict, device_rows: dict, chains: dict | None = None) -> list:
    """Every finding for one device dump against one library view. Pure.

    ``device_rows`` = :func:`cli_schema.parse_show_full_values` ``(rows=True)``;
    ``chains`` = ``{cli_path: kind_chain}`` of the dump's blocks (fallback key
    derivation for objects neither tree lists).
    """
    product = view["product"]
    chains = chains or {}
    specs_s, specs_t = view.get("specs_source") or {}, view.get("specs_target") or {}
    present_t = {k: set(v) for k, v in (view.get("present_target") or {}).items()}
    diff = view.get("tree_diff") or {}
    per = diff.get("endpoints") or {}
    ms = bool(view.get("source_tree"))
    idx = _path_index(view)
    obj_ren = _object_renames(view)
    kinds_s = {k: (m or {}).get("kind") for k, m in (view.get("objects_source") or {}).items()}
    out: list = []
    seen_keys: set = set()

    def t_fields(key):
        return (specs_t.get(key) or {}).get("fields") or {}

    def s_fields(key):
        return (specs_s.get(key) or {}).get("fields") or {}

    for path in sorted(device_rows):
        rows = [r for r in device_rows[path] if isinstance(r, dict)]
        if not rows:
            continue
        key, rel = _resolve(product, path, idx, chains)
        if key is None:
            out.append(_row(SEV_WARN, "no_target_evidence", "", path, "", len(rows),
                            "No REST path or schema object maps this configuration "
                            "block: it cannot be guaranteed on the target build."))
            continue
        if rel:
            # FortiOS: a nested table is a field of its top-level object.
            if rel[0] in t_fields(key) or rel[0] in present_t.get(key, ()):
                continue
            sev = SEV_BLOCK if rel[0] in s_fields(key) else SEV_WARN
            out.append(_row(sev, "field_removed" if sev == SEV_BLOCK else "no_target_evidence",
                            key, path, rel[0], len(rows),
                            "Nested object '%s' is not in the target build's schema." % rel[0]
                            if sev == SEV_BLOCK else
                            "Nested object '%s' has no evidence on the target build: it "
                            "cannot be guaranteed." % rel[0]))
            continue
        seen_keys.add(key)
        fields = sorted({f for r in rows for f in r})
        in_target = key in specs_t or key in present_t
        if not in_target:
            if key in obj_ren:
                out.append(_row(SEV_WARN, "object_rename_candidate", key, path, "", len(rows),
                                "Candidate rename: '%s' -> '%s' (same CLI attribute id). "
                                "Confirm with a field map." % (key, obj_ren[key]),
                                {"to": obj_ren[key]}))
                continue
            if key in specs_s or not ms:
                kind = kinds_s.get(key) or ""
                if kind == cli_schema.KIND_TABLE:
                    out.append(_row(SEV_BLOCK, "object_removed", key, path, "", len(rows),
                                    "Object removed in the target build; the device has "
                                    "%d row(s) in it." % len(rows), {"kind": kind}))
                    continue
                worst, affected = SEV_INFO, 0
                for f in fields:
                    sev, n, _why = _removed_field_rows(view, key, path, f,
                                                       [r.get(f) for r in rows if f in r])
                    if sev == SEV_BLOCK:
                        worst, affected = SEV_BLOCK, affected + n
                if worst == SEV_BLOCK:
                    out.append(_row(SEV_BLOCK, "object_removed", key, path, "", affected,
                                    "Object removed in the target build and the device "
                                    "sets values in it.", {"kind": kind or "object"}))
                else:
                    out.append(_row(SEV_INFO, "object_removed_unused", key, path, "", 0,
                                    "Object removed in the target build; the device keeps "
                                    "it at its defaults.", {"kind": kind or "object"}))
                continue
            out.append(_row(SEV_WARN, "no_target_evidence", key, path, "", len(rows),
                            "The source build's schema does not list this object either "
                            "(hidden or unmapped): it cannot be guaranteed on the target."))
            continue

        tf, sf = t_fields(key), s_fields(key)
        pd = per.get(key) or {}
        retyped = {r["field"]: r for r in pd.get("retyped") or []}
        cands = {c["from"]: c for c in pd.get("rename_candidates") or []}
        mapped = {o: n for o, n, _note in (view.get("renames") or {}).get(key) or []}
        # A rename's new name is not a "new field", whether or not this device
        # prints the old one.
        rename_targets = {c["to"] for c in cands.values()} | set(mapped.values())
        for f in fields:
            vals = [r.get(f) for r in rows if f in r]
            nonempty = [v for v in vals if v not in ("", None)]
            tspec, sspec = tf.get(f), sf.get(f)
            present = tspec is not None or f in present_t.get(key, ())
            if not present:
                new = mapped.get(f)
                if new and (new in tf or new in present_t.get(key, ())):
                    rename_targets.add(new)
                    out.append(_row(SEV_TRANSLATE, "rename_mapped", key, path, f, len(nonempty),
                                    "Renamed by a field map: '%s' -> '%s'." % (f, new),
                                    {"from": f, "to": new}))
                    continue
                c = cands.get(f)
                if c is not None:
                    rename_targets.add(c["to"])
                    # Nothing set = nothing to carry over: worth knowing, not a risk.
                    sev = SEV_WARN if nonempty else SEV_INFO
                    out.append(_row(sev, "rename_candidate", key, path, f, len(nonempty),
                                    "Candidate rename: '%s' -> '%s' (same CLI attribute id %s). "
                                    "Confirm with a field map.%s"
                                    % (f, c["to"], c.get("cli_id"),
                                       "" if nonempty else " The device does not set it."),
                                    {"from": f, "to": c["to"], "cli_id": c.get("cli_id")}))
                    continue
                if sspec is not None or not ms:
                    sev, n, why = _removed_field_rows(view, key, path, f, vals)
                    out.append(_row(sev, "field_removed" if sev == SEV_BLOCK
                                    else "field_removed_unused", key, path, f, n,
                                    "Field removed in the target build; %s." % why))
                    continue
                out.append(_row(SEV_WARN, "no_target_evidence", key, path, f, len(nonempty),
                                "Field not listed by the source build's schema (hidden) and "
                                "no evidence on the target: it cannot be guaranteed."))
                continue
            if tspec is not None and nonempty:
                topts = list(tspec.get("options") or [])
                sopts = set((sspec or {}).get("options") or [])
                if topts and (sopts or not ms):
                    removed_opts, bad_rows = set(), 0
                    for v in nonempty:
                        bad = [x for x in _tokens(v) if x not in topts]
                        hit = [x for x in bad if x in sopts] if sopts else bad
                        if hit:
                            bad_rows += 1
                            # Only option names the source schema lists are
                            # echoed: they are library vocabulary, not values.
                            removed_opts.update(x for x in hit if x in sopts)
                    if bad_rows:
                        out.append(_row(SEV_BLOCK, "option_invalid", key, path, f, bad_rows,
                                        "Enum value no longer valid in the target build.",
                                        {"removed_options": sorted(removed_opts),
                                         "target_options": topts}))
                rng = (tspec.get("attrs") or {}).get("range")
                if rng and len(rng) == 2:
                    lo, hi = int(rng[0]), int(rng[1])
                    out_n = sum(1 for v in nonempty
                                if _INT.match(_norm(v)) and not lo <= int(_norm(v)) <= hi)
                    if out_n:
                        out.append(_row(SEV_BLOCK, "value_out_of_range", key, path, f, out_n,
                                        "Value outside the target range [%d, %d]." % (lo, hi),
                                        {"range": [lo, hi]}))
                rt = retyped.get(f)
                if rt is not None:
                    verdicts = [_satisfies(tspec, v) for v in nonempty]
                    bad_n = sum(1 for x in verdicts if x is False)
                    unk_n = sum(1 for x in verdicts if x is None)
                    det = {"from": rt.get("from"), "to": rt.get("to")}
                    if bad_n:
                        out.append(_row(SEV_BLOCK, "type_changed", key, path, f, bad_n,
                                        "Type changed %s -> %s and the value does not satisfy "
                                        "the new type." % (det["from"], det["to"]), det))
                    elif unk_n:
                        out.append(_row(SEV_WARN, "type_changed", key, path, f, unk_n,
                                        "Type changed %s -> %s; the value cannot be verified "
                                        "against the new type." % (det["from"], det["to"]), det))
                    else:
                        out.append(_row(SEV_INFO, "type_changed", key, path, f, 0,
                                        "Type changed %s -> %s; the value satisfies the new "
                                        "type." % (det["from"], det["to"]), det))
            bdef, tdef = _default(view, "source", key, f), _default(view, "target", key, f)
            if bdef is not None and tdef is not None and bdef != tdef:
                at_default = sum(1 for v in vals if _norm(v) == bdef)
                if at_default:
                    out.append(_row(SEV_WARN, "default_changed", key, path, f, at_default,
                                    "Default changed and the device does not set this field "
                                    "explicitly: its behaviour changes.",
                                    {"source_default": bdef, "target_default": tdef}))
        for f in pd.get("added") or []:
            if f in rename_targets:
                continue
            d = _default(view, "target", key, f)
            out.append(_row(SEV_INFO, "field_added", key, path, f, 0,
                            "New field in the target build" +
                            (" (default '%s')." % d if d is not None else
                             " (default unknown)."),
                            {"default": d} if d is not None else {}))
    rename_to = set(obj_ren.values())
    for k in diff.get("endpoints_added") or []:
        if k in rename_to:
            continue
        meta = (view.get("objects_target") or {}).get(k) or {}
        out.append(_row(SEV_INFO, "object_added", k, meta.get("cli_path") or "", "", 0,
                        "New object in the target build."))
    return _sort_rows(out)


# ---------------------------------------------------------------------------
# the report
# ---------------------------------------------------------------------------

def _objects(rows: list, device_rows: dict) -> list:
    by: dict = {}
    for r in rows:
        k = r["object"] or r["cli_path"]
        o = by.setdefault(k, {"object": r["object"], "cli_path": r["cli_path"],
                              "rows": len(device_rows.get(r["cli_path"]) or []),
                              **{s: 0 for s in SEVERITIES}})
        o[r["severity"]] += 1
    return sorted(by.values(), key=lambda o: (
        [-o[s] for s in SEVERITIES[:3]], o["object"], o["cli_path"]))


def _empty(product, source, target, verdict, reason, **extra) -> dict:
    rows = extra.pop("rows", [])
    counts = _counts(rows)
    return {"schema": SCHEMA, "product": product, "source": fv.normalize(source) or "",
            "target": fv.normalize(target) or "",
            "direction": direction(source, target) if source and target else DIR_UNKNOWN,
            "verdict": verdict, "verdict_reason": reason, "summary": counts,
            "rows": rows, "objects": [], "library": None, "appliance": None, "dump": None,
            **extra}


def build(product: str, source, target, text: str, *, view: dict | None = None,
          appliance: dict | None = None, dump: dict | None = None) -> dict:
    """The report for a dump ``text`` captured on ``source``, moving to ``target``.

    ``view`` may be passed in (memoised by the caller); otherwise it is read.
    """
    src, tgt = fv.normalize(source), fv.normalize(target)
    base = {"appliance": appliance, "dump": dump}
    if not product:
        return _empty(product, src, tgt, V_CANNOT, "the product is unknown", **base)
    if not tgt:
        return _empty(product, src, tgt, V_CANNOT, "no target build given", **base)
    if not src:
        return _empty(product, src, tgt, V_CANNOT,
                      "the source build is unknown (no firmware recorded on the dump "
                      "or the appliance)", **base)
    if direction(src, tgt) == DIR_NONE:
        rows = [_row(SEV_INFO, "same_build", "", "", "", 0,
                     "Source and target are the same build: nothing to migrate.")]
        return _empty(product, src, tgt, V_READY, "same build: nothing to migrate",
                      rows=rows, **base)
    if not (text or "").strip():
        return _empty(product, src, tgt, V_CANNOT,
                      "no usable show full-configuration dump for this appliance", **base)
    view = view if view is not None else library_view(product, src, tgt)
    lib_meta = {"source_tree": view["source_tree"], "target_tree": view["target_tree"],
                "target_completeness": view["completeness"],
                "diff_totals": (view.get("tree_diff") or {}).get("totals") or {},
                "tree_reason": view.get("tree_reason") or ""}
    if not view["target_tree"]:
        return _empty(product, src, tgt, V_CANNOT,
                      "the target build %s has no CLI schema (cli_tree) in the API library"
                      % tgt, library=lib_meta, **base)
    device_rows = cli_schema.parse_show_full_values(text, rows=True)
    chains = {}
    for blk in cli_schema._full_blocks(text).values():
        chains[blk.path] = cli_schema._full_kind_chain(blk)
    rows = classify(view, device_rows, chains)
    gui = _gui_block(product, source, target, rows)
    comp = view["completeness"]
    if not comp["complete"]:
        rows.append(_row(SEV_WARN, "target_incomplete", "", "", "", 0,
                         "The target build %s is %.1f%% measured (%d of %d fields have an "
                         "unknown channel): what is not measured cannot be guaranteed."
                         % (tgt, comp["pct"], comp["unknown"], comp["fields"]),
                         {"completeness_pct": comp["pct"]}))
    if not view["source_tree"]:
        rows.append(_row(SEV_WARN, "source_unmeasured", "", "", "", 0,
                         "The source build %s has no CLI schema in the API library: rename "
                         "candidates and default changes cannot be detected." % src))
    rows = _sort_rows(rows)
    counts = _counts(rows)
    verdict = _verdict(counts)
    reason = {V_BLOCKED: "%d blocking finding(s)" % counts[SEV_BLOCK],
              V_WARN: "%d warning(s), nothing blocking" % counts[SEV_WARN],
              V_READY: "nothing blocking, nothing to warn about"}[verdict]
    return {"schema": SCHEMA, "product": product, "source": src, "target": tgt,
            "direction": direction(src, tgt), "verdict": verdict, "verdict_reason": reason,
            "summary": dict(counts, objects=len(device_rows),
                            fields=sum(len({f for r in rs for f in r})
                                       for rs in device_rows.values())),
            "rows": rows, "objects": _objects(rows, device_rows), "library": lib_meta,
            "gui": gui, **base}


#: GUI layout changes (gui_diff): a field the target's GUI no longer shows is a
#: warning (the operator loses it on screen); every other change is info.
_GUI_SEV = {"removed": SEV_WARN, "dialog_removed": SEV_WARN}


def _gui_block(product: str, source, target, rows: list) -> dict:
    """The "GUI layout" block between the two builds' resolved templates; each
    change also becomes a ``gui_<kind>`` row. Never fails the report."""
    try:
        from . import gui_diff
        gui = gui_diff.between(product, source, target)
    except Exception:  # noqa: BLE001
        return {"pages": [], "error": "GUI layouts could not be compared"}
    for p in gui["pages"]:
        for c in p["changes"]:
            frm = c["from"] if not isinstance(c["from"], (dict, list)) else "…"
            to = c["to"] if not isinstance(c["to"], (dict, list)) else "…"
            rows.append(_row(_GUI_SEV.get(c["kind"], SEV_INFO), "gui_" + c["kind"],
                             "GUI %s / %s" % (p["page"], c["dialog"]), "", c["field"], 0,
                             "FortiWeb GUI %s → %s: %s %s (%s → %s)"
                             % (p["source"].get("version"), p["target"].get("version"),
                                c["kind"].replace("_", " "), c["field"] or c["dialog"],
                                frm, to)))
    # A page whose layout was not measured on one of the builds carries its
    # note in the block (report["gui"]), not as a finding row.
    return gui


# ---------------------------------------------------------------------------
# the vault (an appliance's newest dump)
# ---------------------------------------------------------------------------

def dumps_for(appliance_id: int, index: list | None = None) -> list:
    """The vault rows of one appliance, newest first (usable or not)."""
    from . import cli_coverage
    idx = index if index is not None else cli_coverage.evidence_index()
    return [r for r in idx if r.get("appliance_id") == appliance_id]


def for_appliance(appliance, target, *, backup_id: int | None = None,
                  views: dict | None = None, index: list | None = None) -> dict:
    """The report for ``appliance``'s newest usable vault dump (or ``backup_id``).

    ``views`` memoises :func:`library_view` per ``(product, source, target)``
    across calls; ``index`` is a pre-read :func:`cli_coverage.evidence_index`.
    """
    from . import cli_coverage
    product = getattr(appliance, "kind", "") or ""
    ident = {"id": getattr(appliance, "id", None), "name": getattr(appliance, "name", "")}
    recs = dumps_for(ident["id"], index)
    usable = [r for r in recs if r.get("usable") and r.get("product") == product]
    chosen = None
    if backup_id:
        chosen = next((r for r in usable if r["backup_id"] == backup_id), None)
    elif usable:
        chosen = usable[0]
    text, rec = ("", {})
    if chosen is not None:
        text, rec = cli_coverage.read_dump(chosen["backup_id"])
    dump = None
    if chosen is not None:
        dump = {"backup_id": chosen["backup_id"], "created_at": chosen.get("created_at", ""),
                "firmware": chosen.get("firmware", ""), "version": chosen.get("version", ""),
                "usable": bool(text), "reason": (rec or {}).get("reason", "")}
    source = (chosen or {}).get("version") or fv.normalize(
        getattr(appliance, "fw_version", "") or getattr(appliance, "firmware", "") or "")
    src, tgt = fv.normalize(source), fv.normalize(target)
    view = None
    if text and src and tgt and direction(src, tgt) != DIR_NONE:
        k = (product, src, tgt)
        if views is not None and k in views:
            view = views[k]
        else:
            view = library_view(product, src, tgt)
            if views is not None:
                views[k] = view
    rep = build(product, src, tgt, text, view=view, appliance=ident, dump=dump)
    if chosen is None and rep["verdict"] == V_CANNOT and src and tgt and \
            direction(src, tgt) != DIR_NONE:
        why = next((r.get("reason") for r in recs if r.get("reason")), "")
        rep["verdict_reason"] = ("no usable show full-configuration dump in the backup "
                                 "vault for this appliance" + (" (%s)" % why if why else "")
                                 + ": take a configuration backup first")
    return rep


def target_builds(product: str) -> list:
    """Builds the library holds a CLI schema for: the targets a report can check."""
    from . import api_library as lib
    return [b["version"] for b in lib.builds(product)
            if b.get("cli_measured") and not b.get("line_only")]


# ---------------------------------------------------------------------------
# exports (no values: every cell is a name, a count or a library fact)
# ---------------------------------------------------------------------------

def to_json(rep: dict) -> str:
    return json.dumps(rep, indent=1, sort_keys=True, default=str)


def to_csv(rep: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["# %s %s %s -> %s (%s): %s" % (
        rep.get("product", ""), (rep.get("appliance") or {}).get("name", "") or "-",
        rep.get("source", ""), rep.get("target", ""), rep.get("direction", ""),
        rep.get("verdict", ""))])
    w.writerow(CSV_COLUMNS)
    for r in rep.get("rows") or []:
        w.writerow([r["severity"], r["code"], r["object"], r["cli_path"], r["field"],
                    r["rows"], r["message"],
                    json.dumps(r.get("detail") or {}, sort_keys=True)])
    return buf.getvalue()


def summary(rep: dict) -> dict:
    """The small badge-sized reading (upgrade flow pre-check)."""
    s = rep.get("summary") or {}
    return {"verdict": rep.get("verdict"), "reason": rep.get("verdict_reason", ""),
            "source": rep.get("source", ""), "target": rep.get("target", ""),
            "direction": rep.get("direction", ""),
            "block": s.get(SEV_BLOCK, 0), "warn": s.get(SEV_WARN, 0),
            "translate": s.get(SEV_TRANSLATE, 0), "info": s.get(SEV_INFO, 0)}


__all__ = ["SCHEMA", "SEVERITIES", "VERDICTS", "direction", "library_view", "classify",
           "build", "for_appliance", "dumps_for", "target_builds", "to_json", "to_csv",
           "summary"]
