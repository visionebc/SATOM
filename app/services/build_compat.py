"""Will this payload fit each target build — field by field, by both channels?

The fleet runs many firmware builds, and two builds speaking the SAME REST API
version still differ in fields: the key is always the exact build. This module
answers the operator's question before a write: "you can do this, but on 7.4.x
``lb-algo`` and ``health`` do not exist: they will be skipped on 3 appliances".

It reads only the API library (``services.api_library``), both channels:

* REST evidence (sweep / schema / vendor documentation) and the CLI schema
  (``cli_tree``) plus ``show full-configuration`` names (``cli_full``), joined by
  :func:`api_library.channels_at`;
* the tree's option lists and ``<lo-hi>`` ranges (:func:`api_library._tree_specs`);
* renames: operator-authored (``ApiLibFieldMap``) and CLI-id candidates (same
  attribute id under another name, or moved to another object, on that build).

Per target build each payload field gets ONE finding kind:

``missing``         exists on neither channel of that build -> ``skip`` (a cmdb
                    write answers 200 and drops it; SATOM strips it and says so);
``cli_only``        only the CLI has it (``hidden`` included) -> ``cli``: the REST
                    writer cannot set it, the CLI writer can;
``enum_invalid``    the value is not an option of that build -> ``block``;
``range_invalid``   the value is outside the build's ``<lo-hi>`` -> ``block``;
``unknown``         no evidence for that build -> ``warn`` "cannot be guaranteed",
                    never ok;
``endpoint_absent`` the build has no such object at all -> ``block``.

``rest_unverified`` is not a finding: the field is in the build's CLI schema and
REST was never measured there (an empty table, a build with no sweep). FortiWeb
REST mirrors the tree on every served object (lab 2026-10-07), so it is listed
as such, not as a risk.

Pure over the library; one view per (product, build), cached and invalidated
when the product's evidence or rename maps change.
"""
from __future__ import annotations

import threading
from typing import Any, Iterable

from . import firmware_versions as fv

F_MISSING = "missing"
F_CLI_ONLY = "cli_only"
F_ENUM = "enum_invalid"
F_RANGE = "range_invalid"
F_UNKNOWN = "unknown"
F_ENDPOINT_ABSENT = "endpoint_absent"
FINDINGS = (F_ENDPOINT_ABSENT, F_ENUM, F_RANGE, F_MISSING, F_CLI_ONLY, F_UNKNOWN)

ACTION_SKIP = "skip"
ACTION_CLI = "cli"
ACTION_BLOCK = "block"
ACTION_WARN = "warn"
#: What each finding does to the write. Explicit per finding, never implied:
#: invalid values and absent objects block the device; a missing field is
#: skipped (stripped) with a warning; a CLI-only field needs the CLI writer;
#: an unknown build is a warning that the result cannot be guaranteed.
ACTION_FOR = {
    F_ENDPOINT_ABSENT: ACTION_BLOCK, F_ENUM: ACTION_BLOCK, F_RANGE: ACTION_BLOCK,
    F_MISSING: ACTION_SKIP, F_CLI_ONLY: ACTION_CLI, F_UNKNOWN: ACTION_WARN,
}
LEVEL_FOR_ACTION = {ACTION_BLOCK: "block", ACTION_SKIP: "warn", ACTION_CLI: "warn",
                    ACTION_WARN: "warn"}
_LEVEL_RANK = {"ok": 0, "warn": 1, "block": 2}

_CACHE: dict = {}
_CACHE_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# the per-build view (cached)
# ---------------------------------------------------------------------------

def _fingerprint(product: str) -> tuple:
    """Changes whenever evidence or an operator rename of ``product`` changes."""
    from sqlalchemy import func, select
    from ..extensions import db
    from ..models_apilib import ApiLibEvidence, ApiLibFieldMap
    ev = db.session.execute(select(func.count(ApiLibEvidence.id), func.max(ApiLibEvidence.id))
                            .where(ApiLibEvidence.product == product)).one()
    fm = db.session.execute(select(func.count(ApiLibFieldMap.id), func.max(ApiLibFieldMap.id),
                                   func.max(ApiLibFieldMap.retired_at))
                            .where(ApiLibFieldMap.product == product)).one()
    return tuple(ev) + tuple(str(x) for x in fm)


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def build_view(product: str, version) -> dict:
    """Everything SATOM knows about one build, both channels, ready to check.

    ``{"version", "known", "tree_measured", "rest_measured", "path_rule",
    "endpoints": {key: {"present": "yes|no|unknown", "rest_names", "channel",
    "fields": {name: {"channel", "rest", "cli", "options", "range", "type",
    "cli_id"}}, "rest_fields_known", "cli_id"}}, "aliases": {name: key},
    "by_cli_id": {cli_id: (key, field|None)}}``. Cached per (product, build).
    """
    v = fv.normalize(version) or str(version or "")
    fp = _fingerprint(product)
    ck = (product, v)
    with _CACHE_LOCK:
        hit = _CACHE.get(ck)
        if hit is not None and hit[0] == fp:
            return hit[1]
    view = _compute_view(product, v)
    with _CACHE_LOCK:
        _CACHE[ck] = (fp, view)
    return view


def _compute_view(product: str, v: str) -> dict:
    from . import api_library as lib
    from . import cli_schema
    out = {"product": product, "version": v, "known": False, "tree_measured": False,
           "rest_measured": False, "endpoints": {}, "aliases": {}, "by_cli_id": {},
           "path_rule": cli_schema.PATH_RULE_STATUS.get(product, "none")}
    if not v:
        return out
    ch = lib.channels_at(product, v)
    s = ch["summary"]
    out["tree_measured"] = bool(s.get("tree_measured"))
    out["rest_measured"] = bool(s.get("rest_measured"))
    _m, specs = lib._tree_specs(product, v)
    out["known"] = bool(ch["endpoints"]) or out["tree_measured"] or out["rest_measured"]
    for key, ep in ch["endpoints"].items():
        tree = specs.get(key) or {}
        tfields = tree.get("fields") or {}
        cli_has = bool(ep.get("cli_tree") or ep.get("cli_full"))
        if ep.get("rest_verdict") == lib.VERDICT_OK or cli_has:
            present = "yes"
        elif ep.get("rest_verdict") == lib.VERDICT_ABSENT:
            present = "no"
        else:
            present = "unknown"
        fields = {}
        for name, f in ep["fields"].items():
            spec = tfields.get(name) or {}
            attrs = {**(spec.get("attrs") or {}), **(f.get("attrs") or {})}
            fields[name] = {"channel": f["channel"], "rest": f["rest"], "cli": f["cli"],
                            "options": list(spec.get("options") or []),
                            "range": attrs.get("range"),
                            "type": attrs.get("cli_type") or spec.get("type") or "",
                            "cli_id": attrs.get("cli_id"),
                            "doc_conflict": bool(f.get("doc_conflict"))}
            if attrs.get("cli_id") is not None:
                out["by_cli_id"].setdefault(attrs["cli_id"], (key, name))
        cid = (ep.get("attrs") or {}).get("cli_id")
        if cid:
            out["by_cli_id"][cid] = (key, None)
        out["endpoints"][key] = {
            "present": present, "channel": ep["channel"], "rest_names": ep["rest_names"],
            "rest_fields_known": bool(ep.get("rest_fields_known")), "cli_has": cli_has,
            # Only the vendor documentation speaks for REST here: a claim.
            "vendor_only": set(ep.get("rest_sources") or []) == {lib.SOURCE_VENDOR},
            "cli_id": cid, "fields": fields}
        for n in ep["rest_names"]:
            out["aliases"][n] = key
    return out


# ---------------------------------------------------------------------------
# endpoint names
# ---------------------------------------------------------------------------

def key_for(product: str, endpoint: str, view: dict | None = None) -> str:
    """A registry name, REST path or URN -> the library's channel key."""
    from . import api_library as lib
    ep = str(endpoint or "").strip()
    if not ep:
        return ""
    if view is not None and ep in view.get("aliases", {}):
        return view["aliases"][ep]
    if "/" in ep:
        return lib.urn_key(ep)
    try:
        from ..registry.loader import registry_for
        urn = (registry_for(product, "") or {}).get(ep)
    except Exception:  # noqa: BLE001 — no registry: the name is the key
        urn = None
    return lib.urn_key(urn) if urn else ep


# ---------------------------------------------------------------------------
# one object against one build
# ---------------------------------------------------------------------------

def _value_tokens(value) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(x) for x in value]
    if isinstance(value, bool):
        return ["enable" if value else "disable"]
    return str(value).split() if str(value).strip() else []


def _check_value(f: dict, value) -> tuple[str, dict] | None:
    """``(kind, detail)`` when ``value`` does not fit the build's spec of the field."""
    if value is None or isinstance(value, (dict,)):
        return None
    opts = [str(o) for o in f.get("options") or []]
    if opts:
        raw = str(value).strip() if not isinstance(value, (list, tuple)) else ""
        if raw and raw in opts:
            return None
        bad = [t for t in _value_tokens(value) if t not in opts]
        if bad:
            return F_ENUM, {"value": value, "invalid": bad, "allowed": opts}
        return None
    rng = f.get("range")
    if rng and len(rng) == 2:
        try:
            n = int(str(value).strip())
        except (TypeError, ValueError):
            return F_RANGE, {"value": value, "range": list(rng),
                             "why": "not an integer"}
        if not (int(rng[0]) <= n <= int(rng[1])):
            return F_RANGE, {"value": value, "range": list(rng)}
    return None


def _known_cli_ids(product: str, key: str, names) -> dict:
    """``{field: cli_id}`` for ``key``'s fields on ANY build of ``product``."""
    from sqlalchemy import select
    from ..extensions import db
    from ..models_apilib import ApiLibEndpoint, ApiLibField, ApiLibFieldFact
    names = sorted(set(names))
    if not names:
        return {}
    out: dict = {}
    rows = db.session.execute(
        select(ApiLibField.name, ApiLibFieldFact.attrs)
        .join(ApiLibEndpoint, ApiLibEndpoint.id == ApiLibField.endpoint_id)
        .join(ApiLibFieldFact, ApiLibFieldFact.field_id == ApiLibField.id)
        .where(ApiLibEndpoint.product == product, ApiLibEndpoint.name == key,
               ApiLibField.name.in_(names), ApiLibFieldFact.attrs.isnot(None)))
    for name, attrs in rows:
        cid = (attrs or {}).get("cli_id")
        if cid is not None:
            out.setdefault(name, cid)
    return out


def _mapped_renames(product: str, key: str, names: list, view: dict) -> dict:
    """``{field: [hint]}`` from operator rename maps whose other side exists here."""
    from ..models_apilib import ApiLibFieldMap
    ep = view["endpoints"].get(key) or {}
    here = set(ep.get("fields") or {})
    eps = sorted({key, *(ep.get("rest_names") or [])})
    out: dict = {}
    if not names:
        return out
    for m in ApiLibFieldMap.query.filter(ApiLibFieldMap.product == product,
                                         ApiLibFieldMap.endpoint.in_(eps),
                                         ApiLibFieldMap.retired_at.is_(None)).all():
        if m.from_field in names and m.to_field in here:
            out.setdefault(m.from_field, []).append(
                {"source": "field_map", "to": m.to_field, "note": m.note or "",
                 "text": "renamed to `%s` (%s → %s)" % (m.to_field, m.from_version or "?",
                                                        m.to_version or "?")})
        elif m.to_field in names and m.from_field in here:
            out.setdefault(m.to_field, []).append(
                {"source": "field_map", "to": m.from_field, "note": m.note or "",
                 "text": "called `%s` on this build (renamed %s → %s)"
                         % (m.from_field, m.from_version or "?", m.to_version or "?")})
    return out


def _id_hints(product: str, key: str, names: list, view: dict) -> dict:
    """``{field: [hint]}`` from the CLI attribute id: same id, another name or
    another object on this build (candidates, never applied)."""
    if not names:
        return {}
    ids = _known_cli_ids(product, key, names)
    out: dict = {}
    for name, cid in ids.items():
        where = view["by_cli_id"].get(cid)
        if not where:
            continue
        k2, f2 = where
        if k2 == key and f2 and f2 != name:
            out.setdefault(name, []).append(
                {"source": "cli_id", "to": f2, "cli_id": cid,
                 "text": "same CLI attribute id %s is `%s` on this build" % (cid, f2)})
        elif k2 != key:
            out.setdefault(name, []).append(
                {"source": "cli_id", "to": "%s%s" % (k2, ("." + f2) if f2 else ""),
                 "cli_id": cid,
                 "text": "CLI attribute id %s moved to `%s`%s on this build"
                         % (cid, k2, (" (field `%s`)" % f2) if f2 else " (now an object)")})
    return out


def _object_hints(product: str, key: str, view: dict) -> list:
    """The object's CLI id on any other build, found under another path here."""
    from sqlalchemy import select
    from ..extensions import db
    from ..models_apilib import ApiLibEvidence
    from . import api_library as lib
    cid = None
    for (summ,) in db.session.execute(select(ApiLibEvidence.summary).where(
            ApiLibEvidence.product == product, ApiLibEvidence.source == lib.SOURCE_CLI_TREE,
            ApiLibEvidence.healthy.is_(True))):
        meta = ((summ or {}).get("objects") or {}).get(key) or {}
        if meta.get("cli_id"):
            cid = meta["cli_id"]
            break
    where = view["by_cli_id"].get(cid) if cid else None
    if not where or where[0] == key:
        return []
    k2, f2 = where
    return [{"source": "cli_id", "to": k2 if f2 is None else "%s.%s" % (k2, f2),
             "cli_id": cid,
             "text": "same CLI object id %s is `%s` on this build" % (
                 cid, k2 if f2 is None else "%s.%s" % (k2, f2))}]


def _payload(fields) -> tuple[list, dict]:
    """``(names, values)``: ``fields`` is a list of names or a ``{name: value}``."""
    if isinstance(fields, dict):
        return sorted(str(k) for k in fields), {str(k): v for k, v in fields.items()}
    return sorted({str(f) for f in fields or []}), {}


def check_object(product: str, version, endpoint: str, fields) -> dict:
    """One object payload against one build. Pure over the library.

    ``fields``: names, or ``{name: value}`` to also check options and ranges.
    Returns ``{"version", "known", "key", "endpoint": "present|absent|unknown",
    "findings": [...], "ok": [...], "rest_unverified": [...], "skip": [...],
    "level": "ok|warn|block", "blocking": bool}``.
    """
    from . import api_library as lib
    from . import version_compat as vc
    view = build_view(product, version)
    names, values = _payload(fields)
    authored, ignored = vc.split_fields(names)
    key = key_for(product, endpoint, view)
    out: dict[str, Any] = {
        "product": product, "version": view["version"], "known": view["known"],
        "endpoint": endpoint, "key": key, "present": "unknown",
        "tree_measured": view["tree_measured"], "rest_measured": view["rest_measured"],
        "findings": [], "ok": [], "rest_unverified": [], "ignored": ignored,
        "skip": [], "level": "ok", "blocking": False}

    def _add(field, kind, action=None, **detail):
        out["findings"].append({"field": field, "kind": kind,
                                "action": action or ACTION_FOR[kind], **detail})

    if not view["known"]:
        for f in authored:
            _add(f, F_UNKNOWN, why="build not measured")
        return _finish(out)
    ep = view["endpoints"].get(key)
    if ep is None:
        absent = view["tree_measured"] and view["path_rule"] == "verified"
        out["present"] = "no" if absent else "unknown"
        if absent:
            _add("", F_ENDPOINT_ABSENT, why="not in the CLI schema of this build",
                 **({"hints": h} if (h := _object_hints(product, key, view)) else {}))
        else:
            for f in authored:
                _add(f, F_UNKNOWN, why="object never measured on this build")
        return _finish(out)
    out["present"] = ep["present"]
    if ep["present"] == "no":
        if ep["vendor_only"]:
            # A vendor table saying "not served" is a claim about the
            # appliance, graded like one (version_compat's rule): warn.
            _add("", F_ENDPOINT_ABSENT, action=ACTION_WARN, claim="vendor",
                 why="outside the range the vendor documents for this build")
        else:
            _add("", F_ENDPOINT_ABSENT, why="the appliance rejected the URN")
        return _finish(out)
    unresolved = []
    for f in authored:
        spec = ep["fields"].get(f)
        if spec is None:
            if lib.is_rest_meta(product, f, tree_measured=view["tree_measured"]):
                out["ignored"].append(f)
            elif ep["cli_has"] and view["tree_measured"]:
                unresolved.append(f)
                _add(f, F_MISSING, why="not in the CLI schema of this build"
                     + ("; REST never served it" if ep["rest_fields_known"] else ""))
            elif ep["rest_fields_known"]:
                unresolved.append(f)
                _add(f, F_MISSING, why="REST measured the object's fields; not among them")
            else:
                _add(f, F_UNKNOWN, why="the object's fields were never measured on this build")
            continue
        chn = spec["channel"]
        if chn == lib.CH_META:
            out["ignored"].append(f)
            continue
        if chn in (lib.CH_CLI_ONLY, lib.CH_HIDDEN):
            _add(f, F_CLI_ONLY, hidden=chn == lib.CH_HIDDEN,
                 why="the CLI has it, REST does not serve it")
        elif chn == lib.CH_UNKNOWN and spec["cli"] == "no":
            unresolved.append(f)
            _add(f, F_MISSING, why="not in the CLI schema of this build"
                 + ("; only the vendor documentation names it" if spec["doc_conflict"]
                    else ""))
            continue
        elif chn == lib.CH_UNKNOWN and spec["cli"] != "yes":
            _add(f, F_UNKNOWN, why="no channel measured it on this build")
            continue
        elif chn == lib.CH_UNKNOWN:
            out["rest_unverified"].append(f)
        else:
            out["ok"].append(f)
        if f in values:
            bad = _check_value(spec, values[f])
            if bad:
                _add(f, bad[0], **bad[1])
    if unresolved:
        hints = _mapped_renames(product, key, unresolved, view)
        for f, hs in _id_hints(product, key, unresolved, view).items():
            hints.setdefault(f, []).extend(hs)
        for item in out["findings"]:
            if item["field"] in hints:
                item["hints"] = hints[item["field"]]
    return _finish(out)


def _finish(out: dict) -> dict:
    level = "ok"
    for item in out["findings"]:
        lv = LEVEL_FOR_ACTION[item["action"]]
        if _LEVEL_RANK[lv] > _LEVEL_RANK[level]:
            level = lv
    out["level"] = level
    out["blocking"] = level == "block"
    out["skip"] = sorted({i["field"] for i in out["findings"]
                          if i["action"] == ACTION_SKIP and i["field"]})
    out["by_kind"] = {k: sorted({i["field"] for i in out["findings"]
                                 if i["kind"] == k and i["field"]}) for k in FINDINGS}
    out["ignored"] = sorted(set(out["ignored"]))
    return out


# ---------------------------------------------------------------------------
# many objects x many targets
# ---------------------------------------------------------------------------

def _target_build(target, product: str) -> tuple[str, dict]:
    """``(version, device)`` for an appliance or a build string."""
    if isinstance(target, str):
        return fv.normalize(target) or target, {}
    from . import version_compat as vc
    v = vc._resolved(target).get("version") or ""
    return v, {"appliance_id": getattr(target, "id", None),
               "appliance": getattr(target, "name", "") or ""}


def _fmt_fields(names, limit=6) -> str:
    """Backquoted names joined "a, b and c"; past ``limit``: the first ones + a count."""
    q = ["`%s`" % n for n in names]
    if len(q) > limit:
        return ", ".join(q[:limit]) + " (+%d more)" % (len(q) - limit)
    return q[0] if len(q) == 1 else ", ".join(q[:-1]) + " and " + q[-1]


def _n_targets(n: int, devices: bool) -> str:
    if not devices:
        return "that build"
    return "%d appliance%s" % (n, "" if n == 1 else "s")


def check(product: str, targets: Iterable, objects) -> dict:
    """``objects`` = ``[(endpoint, fields)]`` (fields: names or ``{name: value}``)
    against every target (appliances and/or build strings).

    One :func:`check_object` per (distinct build, object). Returns per build and
    per device the findings, the fields to strip per device (``skips``), the
    operator messages, and whether anything blocks.
    """
    objs = []
    merged: dict = {}
    for endpoint, fields in objects or []:
        if not endpoint:
            continue
        names, values = _payload(fields)
        rec = merged.setdefault(str(endpoint), ({}, set()))
        rec[1].update(names)
        rec[0].update(values)
    for endpoint, (values, names) in sorted(merged.items()):
        objs.append((endpoint, {n: values.get(n) for n in sorted(names)}
                     if values else sorted(names)))
    by_build: dict = {}
    devices = []
    for t in targets or []:
        v, dev = _target_build(t, product)
        b = by_build.setdefault(v, {"version": v, "devices": [], "objects": []})
        if dev:
            b["devices"].append(dev)
            devices.append({**dev, "version": v})
    for v, b in by_build.items():
        if not v:
            b["objects"] = []
            b["level"] = "warn"
            b["known"] = False
            continue
        b["objects"] = [check_object(product, v, ep, flds) for ep, flds in objs]
        b["known"] = any(o["known"] for o in b["objects"]) if b["objects"] else \
            build_view(product, v)["known"]
        b["level"] = max((o["level"] for o in b["objects"]), key=_LEVEL_RANK.get,
                         default="ok")
    messages, blocks = [], []
    has_devices = bool(devices)
    for v, b in sorted(by_build.items(), key=lambda kv: fv.sort_key(kv[0] or "0")):
        n = len(b["devices"]) or 1
        who = _n_targets(n, has_devices)
        if not v:
            messages.append({"level": "warn", "build": "",
                             "text": "%s report%s no firmware — cannot be guaranteed"
                                     % (who, "s" if n == 1 and has_devices else "")})
            continue
        unknown_objs = [o for o in b["objects"] if not o["known"]]
        if unknown_objs or not b["known"]:
            messages.append({"level": "warn", "build": v,
                             "text": "not measured on %s — cannot be guaranteed (%s)"
                                     % (v, who)})
            continue
        for o in b["objects"]:
            label = o["key"] or o["endpoint"]
            bk = o["by_kind"]
            gone = [i for i in o["findings"] if i["kind"] == F_ENDPOINT_ABSENT]
            if gone and gone[0]["action"] == ACTION_BLOCK:
                t = "%s does not exist on %s: blocked on %s%s" % (
                    label, v, who, (" (%s)" % gone[0]["hints"][0]["text"])
                    if gone[0].get("hints") else "")
                messages.append({"level": "block", "build": v, "text": t})
                blocks.append(t)
            elif gone:
                messages.append({"level": "warn", "build": v, "text":
                                 "the vendor documentation says %s does not exist on %s "
                                 "— not measured, cannot be guaranteed (%s)"
                                 % (label, v, who)})
            if bk[F_MISSING]:
                hint = "; ".join("`%s`: %s" % (i["field"], i["hints"][0]["text"])
                                 for i in o["findings"]
                                 if i["kind"] == F_MISSING and i.get("hints"))
                messages.append({"level": "warn", "build": v, "text":
                                 "Applies, but on %s %s %s not exist in %s: %s will be "
                                 "skipped on %s%s" % (
                                     v, _fmt_fields(bk[F_MISSING]),
                                     "does" if len(bk[F_MISSING]) == 1 else "do", label,
                                     "it" if len(bk[F_MISSING]) == 1 else "they", who,
                                     (" (" + hint + ")") if hint else "")})
            if bk[F_CLI_ONLY]:
                messages.append({"level": "warn", "build": v, "text":
                                 "on %s %s in %s exist only in the CLI: the REST write "
                                 "will not set %s on %s (needs the CLI writer)" % (
                                     v, _fmt_fields(bk[F_CLI_ONLY]), label,
                                     "it" if len(bk[F_CLI_ONLY]) == 1 else "them", who)})
            for i in o["findings"]:
                if i["kind"] == F_ENUM:
                    t = ("on %s `%s` = %r is not valid in %s (allowed: %s): blocked on %s"
                         % (v, i["field"], i.get("value"), label,
                            ", ".join(i.get("allowed") or [])[:200], who))
                    messages.append({"level": "block", "build": v, "text": t})
                    blocks.append(t)
                elif i["kind"] == F_RANGE:
                    t = ("on %s `%s` = %r is out of range %s in %s: blocked on %s"
                         % (v, i["field"], i.get("value"), i.get("range"), label, who))
                    messages.append({"level": "block", "build": v, "text": t})
                    blocks.append(t)
            if bk[F_UNKNOWN]:
                messages.append({"level": "warn", "build": v, "text":
                                 "on %s %s in %s were never measured — cannot be "
                                 "guaranteed (%s)" % (v, _fmt_fields(bk[F_UNKNOWN]),
                                                      label, who)})
    for d in devices:
        b = by_build.get(d["version"]) or {}
        d["level"] = b.get("level", "warn")
        d["blocking"] = d["level"] == "block"
        d["skips"] = {o["endpoint"]: o["skip"] for o in b.get("objects") or [] if o["skip"]}
        d["findings"] = [{**i, "endpoint": o["endpoint"]} for o in b.get("objects") or []
                         for i in o["findings"]]
    level = max((b.get("level", "warn") for b in by_build.values()), key=_LEVEL_RANK.get,
                default="ok")
    return {"product": product, "builds": by_build, "devices": devices,
            "messages": messages, "blocks": blocks, "level": level,
            "blocking": level == "block",
            "skips": {d["appliance_id"]: d["skips"] for d in devices
                      if d.get("appliance_id") is not None and d["skips"]}}


def strip_skipped(items: list[dict], skips: dict, product: str = "fortiweb",
                  version: str = "") -> tuple[list[dict], list[dict]]:
    """``(items', skipped)`` — push items with the ``skip`` fields removed.

    ``skips`` = ``{endpoint: [field]}`` as :func:`check` reports it for one
    device. A node's payload may sit in ``data`` or in the cmdb envelope
    ``data.data``; both are handled. Nothing else is touched.
    """
    if not skips:
        return items, []
    by_key = {key_for(product, ep): set(fs) for ep, fs in skips.items()}
    by_key.update({ep: set(fs) for ep, fs in skips.items()})
    out, skipped = [], []
    for it in items:
        ep = it.get("endpoint") or ""
        drop = by_key.get(ep) or by_key.get(key_for(product, ep)) or set()
        if not drop:
            out.append(it)
            continue
        data = dict(it.get("data") or {})
        inner = data.get("data") if isinstance(data.get("data"), dict) else None
        target = dict(inner) if inner is not None else data
        gone = sorted(f for f in drop if f in target)
        for f in gone:
            target.pop(f, None)
        if inner is not None:
            data["data"] = target
        else:
            data = target
        if gone:
            skipped.append({"endpoint": ep, "mkey": it.get("mkey"), "fields": gone})
        out.append({**it, "data": data})
    return out, skipped


__all__ = ["F_MISSING", "F_CLI_ONLY", "F_ENUM", "F_RANGE", "F_UNKNOWN",
           "F_ENDPOINT_ABSENT", "FINDINGS", "ACTION_FOR", "build_view", "key_for",
           "check_object", "check", "strip_skipped", "clear_cache"]
