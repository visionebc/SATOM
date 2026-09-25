"""The API library: versioned, append-only knowledge of what each build serves.

Design contract: ``docs/api-library.md``. This module is the ONLY writer of the
``api_lib_*`` tables (:func:`ingest`) and the one place their contents are
turned back into answers (the query half below).

Why it replaces ``data/api_matrix/*.json`` rather than feeding it: that file
was derived and rewritten wholesale on every rebuild, and ``build`` filtered
its evidence through the live appliance table. Deleting an appliance therefore
deleted the proof of what its firmware served — the 8.0.3 FortiADC evidence
went that way. Here a harvest is stored once, device identity is copied into
the evidence row, and no code path filters by the live table or deletes a row.

The rules carried over from ``api_matrix`` (each one a way to quietly lie):

1. ``fields=None`` (blind) is not ``fields={}`` (measured, none). Only the
   second sets ``fields_known``.
2. A build with no evidence is ``unmeasured``, never "compatible".
3. "Removed" requires BOTH builds to have measured the thing.
4. Vendor data (``vendor_doc``) is a claim, not a measurement. It never
   outranks a real box, and an open vendor range stops at the newest build the
   vendor's tooling knew about — a later build is ``unmeasured``, not ``ok``.

Performance shape: every query here answers one build with a handful of SQL
statements (no per-endpoint or per-field loops), and ingest uses bulk inserts
with bulk lookups, because a FortiGate vendor document is ~720 endpoints and
tens of thousands of fields.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
from datetime import datetime

from sqlalchemy import func, insert, or_, select, update
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models_apilib import (ApiLibBuild, ApiLibEndpoint, ApiLibEndpointFact,
                             ApiLibEvidence, ApiLibField, ApiLibFieldFact,
                             ApiLibFieldMap, ApiLibSpan)
from . import firmware_versions as fv

# ---------------------------------------------------------------------------
# vocabulary
# ---------------------------------------------------------------------------

PRODUCTS = ("fortiweb", "fortiadc", "fortiauthenticator", "fortianalyzer", "fortigate")
#: SATOM does not manage these; the library only holds their API catalogue.
CATALOG_ONLY_PRODUCTS = ("fortigate",)

SOURCE_SWEEP = "sweep"
SOURCE_SCHEMA = "schema"
SOURCE_VENDOR = "vendor_doc"
SOURCE_MANUAL = "manual"
SOURCE_LEGACY = "legacy_matrix"
SOURCES = (SOURCE_SWEEP, SOURCE_SCHEMA, SOURCE_VENDOR, SOURCE_MANUAL, SOURCE_LEGACY)
#: Which source speaks first when two describe the same thing. A sweep of a
#: real box outranks everything; vendor data is last by rule 4.
SOURCE_PRIORITY = (SOURCE_SWEEP, SOURCE_SCHEMA, SOURCE_MANUAL, SOURCE_LEGACY, SOURCE_VENDOR)

VERDICT_OK = "ok"
VERDICT_ABSENT = "absent"
VERDICT_ERROR = "error"
_VERDICT_RANK = {VERDICT_OK: 3, VERDICT_ABSENT: 2, VERDICT_ERROR: 1}

ORIGIN_EVIDENCE = "evidence"
ORIGIN_VENDOR = "vendor"
ORIGIN_DECLARED = "declared"
_ORIGIN_RANK = {ORIGIN_DECLARED: 1, ORIGIN_VENDOR: 2, ORIGIN_EVIDENCE: 3}

# Same threshold and same reason as ``api_matrix``/``registry_reconcile``: a
# ledger that is mostly errors is evidence about the appliance (fortiweb08
# answered -20010 to 283 of 321 reads), not about the catalogue.
MAX_ERROR_RATIO = 0.25

_CHUNK = 500


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def version_key(version) -> str:
    """``"8.0.5"`` -> ``"00008.00000.00005"``; ``"8.0"`` -> ``"00008.00000"``.

    A string, so a vendor range resolves with ``from_key <= key <= to_key`` in
    SQL. Ordering matches :func:`firmware_versions.sort_key`: numeric per
    component (``8.0.10`` after ``8.0.9``), and a line-only key is a strict
    prefix of every patch of its line, so it sorts first — the same "weakest
    claim reads first" rule.
    """
    v = fv.normalize(version)
    if not v:
        return ""
    return ".".join("%05d" % int(p) for p in v.split("."))


def _now() -> datetime:
    return datetime.utcnow().replace(microsecond=0)


def _parse_ts(value) -> datetime | None:
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    s = str(value or "").strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None) - dt.utcoffset()
    return dt


def _iso(dt) -> str:
    return dt.isoformat(timespec="seconds") if dt else ""


def _chunks(seq, n=_CHUNK):
    seq = list(seq)
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _canonical(doc: dict) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)


def _witness_key(device) -> dict | None:
    """WHO measured, reduced to the identity that does not drift.

    The appliance id when there is one (a live row and a snapshot of a
    deleted box agree on it), else the device name; ``None`` for vendor or
    manual evidence that no device produced.
    """
    if not isinstance(device, dict):
        return None
    if isinstance(device.get("appliance_id"), int):
        return {"appliance_id": device["appliance_id"]}
    name = str(device.get("name") or "")
    return {"name": name} if name else None


def content_hash(doc: dict) -> str:
    """sha256 of the MEASUREMENT and of who measured it — nothing else.

    Covered: product, source, scope (without its build token), endpoints,
    health, summary, and :func:`_witness_key`. Left out: ``captured_at``
    (re-harvesting identical content is a confirmation, not new evidence),
    ``origin_ref`` and the device DECORATION (serial, model, hw type, raw
    firmware string, display name, build token). The decoration depends on
    which path read the snapshot: a live sweep copies it from the appliance
    row, a backfill of the same by-version file reconstructs it from the
    snapshot. Hashing it filed one measurement twice.

    Why the hash and not a backfill-side dedupe on the raw snapshot: this
    keeps ONE definition of "same evidence" for every path and every order
    (a backfill can also run before the live ingest), with no blob to
    decompress per candidate row. The witness stays IN the hash so two
    different boxes that return identical content on one build remain two
    evidence rows and two witnesses.
    """
    scope = {k: v for k, v in (doc.get("scope") or {}).items() if k != "build"}
    body = {"product": doc.get("product"), "source": doc.get("source"), "scope": scope,
            "endpoints": doc.get("endpoints") or {},
            "healthy": bool(doc.get("healthy", True)),
            "skip_reason": doc.get("skip_reason") or "",
            "summary": doc.get("summary") or {},
            "witness": _witness_key(doc.get("device"))}
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


def _gz(raw, doc: dict) -> bytes:
    if raw is None:
        data = _canonical(doc).encode("utf-8")
    elif isinstance(raw, (bytes, bytearray)):
        data = bytes(raw)
        if data[:2] == b"\x1f\x8b":
            return data
    elif isinstance(raw, str):
        data = raw.encode("utf-8")
    else:
        data = _canonical(raw).encode("utf-8")
    return gzip.compress(data, compresslevel=6)


def _best_verdict(verdicts) -> str | None:
    best = None
    for v in verdicts:
        if v and _VERDICT_RANK.get(v, 0) > _VERDICT_RANK.get(best, 0):
            best = v
    return best


def _build_token(raw) -> str:
    m = re.search(r"build\s*(\d+)", str(raw or ""), re.I)
    return "build%s" % m.group(1) if m else ""


def _build_dict(b: ApiLibBuild | None) -> dict | None:
    if b is None:
        return None
    return {"id": b.id, "product": b.product, "version": b.version,
            "build": b.build or "", "line": b.line, "line_only": bool(b.line_only),
            "sort_key": b.sort_key, "origin": b.origin,
            "first_seen": _iso(b.first_seen), "last_seen": _iso(b.last_seen)}


def _build_row(product: str, version) -> ApiLibBuild | None:
    v = fv.normalize(version)
    if not v:
        return None
    return ApiLibBuild.query.filter_by(product=product, version=v).first()


# ---------------------------------------------------------------------------
# ingest — the only writer
# ---------------------------------------------------------------------------

def _validate(doc: dict) -> None:
    if not isinstance(doc, dict):
        raise ValueError("evidence document must be a dict")
    if not doc.get("product"):
        raise ValueError("evidence document has no product")
    if doc.get("source") not in SOURCES:
        raise ValueError("unknown evidence source %r (expected one of %s)"
                         % (doc.get("source"), ", ".join(SOURCES)))
    scope = doc.get("scope") or {}
    if scope.get("kind", "build") not in ("build", "line", "spans"):
        raise ValueError("unknown scope kind %r" % scope.get("kind"))
    if not isinstance(doc.get("endpoints") or {}, dict):
        raise ValueError("endpoints must be a dict")


def ingest(doc: dict, raw=None) -> dict:
    """Store one evidence document. Idempotent on content.

    Returns ``{"evidence_id", "created", "facts": {...counts}}``. Identical
    content (same hash) only bumps ``last_confirmed_at``/``confirmations``.
    Unhealthy evidence is stored — the record of a failed harvest is evidence
    too — but never folded into facts.
    """
    _validate(doc)
    sha = content_hash(doc)
    try:
        return _ingest(doc, raw, sha)
    except IntegrityError:
        # A concurrent writer inserted the same evidence or the same endpoint
        # between our lookup and our insert. The second pass finds its rows.
        db.session.rollback()
        return _ingest(doc, raw, sha)


def _ensure_builds(product: str, wanted: dict) -> dict:
    """``{version: ApiLibBuild}`` for ``{version: {"origin","build","seen"}}``."""
    if not wanted:
        return {}
    rows = {}
    for chunk in _chunks(wanted):
        for b in ApiLibBuild.query.filter(ApiLibBuild.product == product,
                                          ApiLibBuild.version.in_(chunk)).all():
            rows[b.version] = b
    for v, meta in wanted.items():
        seen = meta.get("seen") or _now()
        b = rows.get(v)
        if b is None:
            b = ApiLibBuild(product=product, version=v, build=meta.get("build") or "",
                            line=fv.line_of(v), line_only=fv.is_line_only(v),
                            sort_key=version_key(v), origin=meta["origin"],
                            first_seen=seen, last_seen=seen)
            db.session.add(b)
            rows[v] = b
            continue
        if _ORIGIN_RANK.get(meta["origin"], 0) > _ORIGIN_RANK.get(b.origin, 0):
            b.origin = meta["origin"]
        if meta.get("build") and not b.build:
            b.build = meta["build"]
        if b.first_seen is None or seen < b.first_seen:
            b.first_seen = seen
        if b.last_seen is None or seen > b.last_seen:
            b.last_seen = seen
    db.session.flush()
    return rows


def _ensure_endpoints(product: str, names, seen: datetime) -> dict:
    """``{name: endpoint_id}``, inserting missing rows in bulk."""
    names = sorted(set(names))
    ids: dict = {}

    def _load(batch):
        for chunk in _chunks(batch):
            for eid, name in db.session.execute(
                    select(ApiLibEndpoint.id, ApiLibEndpoint.name).where(
                        ApiLibEndpoint.product == product,
                        ApiLibEndpoint.name.in_(chunk))):
                ids[name] = eid

    _load(names)
    missing = [n for n in names if n not in ids]
    if missing:
        db.session.execute(insert(ApiLibEndpoint), [
            {"product": product, "name": n, "first_seen": seen, "last_seen": seen}
            for n in missing])
        _load(missing)
    _touch(ApiLibEndpoint, [ids[n] for n in names if n in ids], seen)
    return ids


def _ensure_fields(pairs, seen: datetime) -> dict:
    """``{(endpoint_id, name): field_id}`` for ``[(endpoint_id, name), ...]``."""
    pairs = sorted(set(pairs))
    ids: dict = {}
    by_ep: dict = {}
    for eid, name in pairs:
        by_ep.setdefault(eid, set()).add(name)

    def _load(ep_ids):
        for chunk in _chunks(ep_ids):
            for fid, eid, name in db.session.execute(
                    select(ApiLibField.id, ApiLibField.endpoint_id, ApiLibField.name)
                    .where(ApiLibField.endpoint_id.in_(chunk))):
                if name in by_ep.get(eid, ()):
                    ids[(eid, name)] = fid

    _load(sorted(by_ep))
    missing = [p for p in pairs if p not in ids]
    if missing:
        for chunk in _chunks(missing, 5000):
            db.session.execute(insert(ApiLibField), [
                {"endpoint_id": eid, "name": n, "first_seen": seen, "last_seen": seen}
                for eid, n in chunk])
        _load(sorted({eid for eid, _ in missing}))
    _touch(ApiLibField, list(ids.values()), seen)
    return ids


def _touch(model, row_ids, seen: datetime) -> None:
    """Widen first_seen/last_seen of many rows with two bulk statements."""
    for chunk in _chunks(row_ids):
        db.session.execute(update(model).where(model.id.in_(chunk), model.last_seen < seen)
                           .values(last_seen=seen).execution_options(synchronize_session=False))
        db.session.execute(update(model).where(model.id.in_(chunk), model.first_seen > seen)
                           .values(first_seen=seen).execution_options(synchronize_session=False))


def _scope_versions(doc: dict) -> tuple[str, list]:
    """``(kind, [normalized versions])`` the scope names."""
    scope = doc.get("scope") or {}
    kind = scope.get("kind") or "build"
    if kind == "spans":
        out = {fv.normalize(v) for v in scope.get("versions") or []}
        return kind, sorted((v for v in out if v), key=fv.sort_key)
    v = fv.normalize(scope.get("line") if kind == "line" else scope.get("version"))
    return kind, [v] if v else []


def _span_bounds(doc: dict, sample: list) -> tuple[str, str]:
    """``(min_version, max_version)`` a spans document has an opinion about.

    The max is the cap for open-ended spans (rule 4). It is the newest version
    named ANYWHERE in the document — sample list, any span edge, or the
    adapter's own ``summary.max_version`` — because the collection "knows" a
    build as soon as any range mentions it.
    """
    seen = set(sample)
    for info in (doc.get("endpoints") or {}).values():
        for lo, hi in (info.get("spans") or []):
            seen.update(x for x in (fv.normalize(lo), fv.normalize(hi)) if x)
        for f in (info.get("fields") or {}).values():
            for lo, hi in (f.get("spans") or []) if isinstance(f, dict) else []:
                seen.update(x for x in (fv.normalize(lo), fv.normalize(hi)) if x)
    summ = doc.get("summary") or {}
    for k in ("min_version", "max_version"):
        v = fv.normalize(summ.get(k))
        if v:
            seen.add(v)
    full = [v for v in seen if not fv.is_line_only(v)]
    if not full:
        return "", ""
    full.sort(key=fv.sort_key)
    return full[0], full[-1]


def _ingest(doc: dict, raw, sha: str) -> dict:
    product, source = doc["product"], doc["source"]
    now = _now()
    ev = ApiLibEvidence.query.filter_by(product=product, source=source, sha256=sha).first()
    if ev is not None:
        ev.last_confirmed_at = now
        ev.confirmations = (ev.confirmations or 0) + 1
        _fill_identity(ev, doc)
        db.session.commit()
        return {"evidence_id": ev.id, "created": False, "facts": {}}

    kind, versions = _scope_versions(doc)
    captured = _parse_ts(doc.get("captured_at")) or now
    device = doc.get("device") or {}
    endpoints = doc.get("endpoints") or {}
    healthy = bool(doc.get("healthy", True))
    scope = doc.get("scope") or {}

    summary = dict(doc.get("summary") or {})
    summary.update({
        "endpoints": len(endpoints),
        "fields": sum(len(e.get("fields") or {}) for e in endpoints.values()
                      if isinstance(e, dict)),
        "verdicts": {v: sum(1 for e in endpoints.values()
                            if isinstance(e, dict) and e.get("verdict") == v)
                     for v in (VERDICT_OK, VERDICT_ABSENT, VERDICT_ERROR)},
    })

    build = None
    builds_for_scope: dict = {}
    if kind == "spans":
        lo, hi = _span_bounds(doc, versions)
        summary.update({"min_version": lo, "max_version": hi,
                        "min_key": version_key(lo), "max_key": version_key(hi)})
        if healthy:
            builds_for_scope = _ensure_builds(product, {
                v: {"origin": ORIGIN_VENDOR, "seen": captured} for v in versions})
    elif versions:
        v = versions[0]
        token = scope.get("build") or ""
        if not token and fv.normalize(device.get("firmware_raw")) == v:
            token = _build_token(device.get("firmware_raw"))
        builds_for_scope = _ensure_builds(product, {
            v: {"origin": ORIGIN_EVIDENCE, "build": token, "seen": captured}})
        build = builds_for_scope[v]

    ev = ApiLibEvidence(
        product=product, source=source, build_id=build.id if build else None,
        scope_kind=kind,
        appliance_id=device.get("appliance_id") if isinstance(device.get("appliance_id"), int) else None,
        device_name=str(device.get("name") or "")[:128],
        device_serial=str(device.get("serial") or "")[:64],
        device_model=str(device.get("model") or "")[:128],
        device_hw_type=str(device.get("hw_type") or "")[:16],
        firmware_raw=str(device.get("firmware_raw") or "")[:128],
        origin_ref=str(doc.get("origin_ref") or "")[:255],
        captured_at=captured, ingested_at=now, last_confirmed_at=now,
        confirmations=1, sha256=sha, healthy=healthy,
        skip_reason=str(doc.get("skip_reason") or "")[:500],
        summary=summary, raw_gz=_gz(raw, doc))
    db.session.add(ev)
    db.session.flush()

    facts: dict = {}
    if healthy and endpoints:
        if kind == "spans":
            facts = _fold_spans(product, source, ev, endpoints, summary, captured)
        elif build is not None:
            facts = _fold_point(product, source, build, ev, device, endpoints, captured)
    db.session.commit()
    return {"evidence_id": ev.id, "created": True, "facts": facts}


def _fill_identity(ev: ApiLibEvidence, doc: dict) -> None:
    """Fill BLANK device decoration from a confirming document; never overwrite.

    Decoration is not in the hash, so whichever path ingested first owns the
    row. A backfill that ran before the live sweep would otherwise leave the
    evidence without the serial/model and its build without the token the
    appliance row knows. The measurement itself is untouched.
    """
    device = doc.get("device") or {}
    if not isinstance(device, dict):
        return
    placeholder = "appliance #%s" % ev.appliance_id
    if device.get("name") and ev.device_name in ("", placeholder):
        ev.device_name = str(device["name"])[:128]
    for col, key, size in (("device_serial", "serial", 64), ("device_model", "model", 128),
                           ("device_hw_type", "hw_type", 16),
                           ("firmware_raw", "firmware_raw", 128)):
        if not getattr(ev, col) and device.get(key):
            setattr(ev, col, str(device[key])[:size])
    token = (doc.get("scope") or {}).get("build")
    if token and ev.build_id is not None:
        b = db.session.get(ApiLibBuild, ev.build_id)
        if b is not None and not b.build:
            b.build = token


def _fold_point(product, source, build, ev, device, endpoints, seen) -> dict:
    """Fold build/line-scoped evidence into facts keyed (thing, build, source).

    Bounded by construction: a second sweep of the same build UPDATES the same
    fact rows, so the fact count tracks distinct builds, not harvests.
    """
    ep_ids = _ensure_endpoints(product, endpoints.keys(), seen)
    device_name = str(device.get("name") or "")
    hw = str(device.get("hw_type") or "")
    platform = hw if hw and hw != "unknown" else str(device.get("model") or "")

    existing = {}
    for chunk in _chunks(ep_ids.values()):
        for f in ApiLibEndpointFact.query.filter(
                ApiLibEndpointFact.build_id == build.id,
                ApiLibEndpointFact.source == source,
                ApiLibEndpointFact.endpoint_id.in_(chunk)).all():
            existing[f.endpoint_id] = f

    new_rows, updated = [], 0
    for name, info in endpoints.items():
        info = info if isinstance(info, dict) else {}
        eid = ep_ids[name]
        verdict = info.get("verdict") or VERDICT_ERROR
        known = info.get("fields") is not None and verdict == VERDICT_OK
        wits = sorted({w for w in ([device_name] + list(info.get("witnesses") or [])) if w})
        f = existing.get(eid)
        if f is None:
            new_rows.append({
                "endpoint_id": eid, "build_id": build.id, "source": source,
                "urn": str(info.get("urn") or "")[:255],
                "section": str(info.get("section") or "")[:128],
                "verdict": verdict, "fields_known": known, "witnesses": wits,
                "first_evidence_id": ev.id, "last_evidence_id": ev.id,
                "first_seen": seen, "last_seen": seen})
            continue
        # Verdict merge WITHIN one build: ok from any healthy witness wins,
        # then absent, then error.
        f.verdict = _best_verdict([f.verdict, verdict])
        f.fields_known = bool(f.fields_known or known)
        f.witnesses = sorted(set(f.witnesses or []) | set(wits))
        if not f.urn and info.get("urn"):
            f.urn = str(info["urn"])[:255]
        if not f.section and info.get("section"):
            f.section = str(info["section"])[:128]
        f.last_evidence_id = ev.id
        f.first_seen = min(f.first_seen or seen, seen)
        f.last_seen = max(f.last_seen or seen, seen)
        updated += 1
    if new_rows:
        db.session.execute(insert(ApiLibEndpointFact), new_rows)

    # --- fields: only endpoints that REVEALED them (rule 1) ----------------
    pairs, specs = [], {}
    for name, info in endpoints.items():
        fields = info.get("fields") if isinstance(info, dict) else None
        if not isinstance(fields, dict) or (info.get("verdict") or VERDICT_ERROR) != VERDICT_OK:
            continue
        for fname, spec in fields.items():
            key = (ep_ids[name], str(fname))
            pairs.append(key)
            specs[key] = spec if isinstance(spec, dict) else {}
    field_ids = _ensure_fields(pairs, seen) if pairs else {}

    fexisting = {}
    for chunk in _chunks(field_ids.values()):
        for ff in ApiLibFieldFact.query.filter(
                ApiLibFieldFact.build_id == build.id,
                ApiLibFieldFact.source == source,
                ApiLibFieldFact.field_id.in_(chunk)).all():
            fexisting[ff.field_id] = ff

    fnew, fupdated = [], 0
    for key, fid in field_ids.items():
        spec = specs.get(key) or {}
        attrs = {k: spec.get(k) for k in ("type", "options", "default", "required", "children")}
        if attrs["type"] is not None:
            attrs["type"] = str(attrs["type"])[:32]
        ff = fexisting.get(fid)
        if ff is None:
            fnew.append({"field_id": fid, "build_id": build.id, "source": source,
                         **attrs, "platforms": [platform] if platform else [],
                         "first_evidence_id": ev.id, "last_evidence_id": ev.id,
                         "first_seen": seen, "last_seen": seen})
            continue
        # Newest non-empty description wins; platforms accumulate.
        for k, v in attrs.items():
            if v is not None:
                setattr(ff, k, v)
        if platform and platform not in (ff.platforms or []):
            ff.platforms = sorted(set(ff.platforms or []) | {platform})
        ff.last_evidence_id = ev.id
        ff.first_seen = min(ff.first_seen or seen, seen)
        ff.last_seen = max(ff.last_seen or seen, seen)
        fupdated += 1
    for chunk in _chunks(fnew, 5000):
        db.session.execute(insert(ApiLibFieldFact), chunk)
    db.session.flush()
    return {"endpoint_facts_created": len(new_rows), "endpoint_facts_updated": updated,
            "field_facts_created": len(fnew), "field_facts_updated": fupdated}


def _fold_spans(product, source, ev, endpoints, summary, seen) -> dict:
    """Store vendor ranges once. They are resolved per build at query time."""
    ep_ids = _ensure_endpoints(product, endpoints.keys(), seen)
    floor = summary.get("min_version") or ""
    pairs = []
    for name, info in endpoints.items():
        for fname in (info.get("fields") or {}) if isinstance(info, dict) else {}:
            pairs.append((ep_ids[name], str(fname)))
    field_ids = _ensure_fields(pairs, seen) if pairs else {}

    def _rows(eid, fid, spans, attrs):
        for pair in spans:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                continue
            lo, hi = fv.normalize(pair[0]), fv.normalize(pair[1])
            if not lo:
                continue
            yield {"endpoint_id": eid, "field_id": fid, "evidence_id": ev.id,
                   "source": source, "from_key": version_key(lo),
                   "to_key": version_key(hi) or None,
                   "from_version": lo, "to_version": hi or "", "attrs": attrs}

    rows = []
    for name, info in endpoints.items():
        info = info if isinstance(info, dict) else {}
        eid = ep_ids[name]
        # An endpoint with no ranges is valid across everything the document
        # covers — still capped at max_version when read.
        spans = info.get("spans") or ([[floor, ""]] if floor else [])
        fields = info.get("fields")
        rows.extend(_rows(eid, None, spans, {
            "urn": info.get("urn") or "", "section": info.get("section") or "",
            "fields_known": fields is not None}))
        for fname, spec in (fields or {}).items():
            spec = spec if isinstance(spec, dict) else {}
            attrs = {k: spec[k] for k in ("type", "options", "default", "required", "children")
                     if spec.get(k) is not None}
            rows.extend(_rows(eid, field_ids[(eid, str(fname))],
                              spec.get("spans") or spans, attrs))
    for chunk in _chunks(rows, 5000):
        db.session.execute(insert(ApiLibSpan), chunk)
    db.session.flush()
    return {"spans_created": len(rows), "endpoints": len(ep_ids), "fields": len(field_ids)}


# ---------------------------------------------------------------------------
# adapters — produce evidence documents, never write
# ---------------------------------------------------------------------------

def _json_type(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "dict"
    return type(value).__name__


def _fields_from_rows(rows) -> dict | None:
    """The field set a sweep's rows reveal, or None when they reveal nothing.

    Only a row WITH keys creates a field set (rule 1): an empty collection
    tells you the endpoint exists and nothing about its fields.
    """
    out: dict = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        for k, v in row.items():
            rec = out.setdefault(str(k), {"type": "null"})
            t = _json_type(v)
            if t != "null" and rec["type"] != t:
                rec["type"] = t if rec["type"] == "null" else "mixed"
            if isinstance(v, list) and any(isinstance(x, dict) for x in v):
                kids = set(rec.get("children") or [])
                for x in v:
                    if isinstance(x, dict):
                        kids.update(str(c) for c in x)
                rec["children"] = sorted(kids)
    for rec in out.values():
        if rec["type"] == "null":
            rec["type"] = None
    return out or None


def evidence_from_sweep(product: str, snapshot: dict, device: dict | None,
                        origin_ref: str) -> dict:
    """A rediscovery snapshot -> evidence document.

    The version comes from the SNAPSHOT, never from the appliance row: the row
    may have been upgraded since, and filing old evidence under the new
    version is the error the by-version archive exists to prevent.
    """
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    device = dict(device or {})
    raw_fw = str(snapshot.get("firmware") or "")
    version = fv.normalize(raw_fw)
    dev_raw = str(device.get("firmware_raw") or "")
    token = _build_token(dev_raw) if fv.normalize(dev_raw) == version else ""
    token = token or _build_token(raw_fw)
    device.setdefault("firmware_raw", raw_fw)
    if fv.normalize(device.get("firmware_raw")) != version:
        device["firmware_raw"] = raw_fw

    # Always POINT evidence, even when the box reported only "8.0": one box
    # was asked once, so this is a measurement of one (patch-unknown) build,
    # not a claim about every 8.0.x. ``matrix_doc`` gives it its own
    # version-axis entry; only line-harvested stores (schema dirs, legacy
    # matrices) stay line-scoped.
    scope = {"kind": "build", "version": version, "build": token}

    ledger = snapshot.get("endpoint_status") or {}
    rows_by_ep: dict = {}
    for _section, eps in (snapshot.get("sections") or {}).items():
        if isinstance(eps, dict):
            for ep_name, rows in eps.items():
                if isinstance(rows, list):
                    rows_by_ep.setdefault(ep_name, []).extend(rows)

    endpoints: dict = {}
    for ep_name, info in ledger.items():
        info = info if isinstance(info, dict) else {}
        verdict = info.get("verdict") or VERDICT_ERROR
        endpoints[ep_name] = {
            "urn": info.get("urn") or "", "section": info.get("section") or "",
            "verdict": verdict, "rows": info.get("rows"),
            "fields": _fields_from_rows(rows_by_ep.get(ep_name)) if verdict == VERDICT_OK else None,
        }

    errs = sum(1 for e in endpoints.values() if e["verdict"] == VERDICT_ERROR)
    healthy, reason = True, ""
    if not version:
        healthy, reason = False, ("snapshot records no firmware version; it cannot be "
                                  "filed under a build")
    elif not ledger:
        healthy, reason = False, "pre-ledger snapshot (no per-endpoint verdicts)"
    elif errs / max(len(ledger), 1) > MAX_ERROR_RATIO:
        healthy, reason = False, ("%d/%d endpoints errored; the device is unhealthy, "
                                  "not the catalog" % (errs, len(ledger)))

    return {
        "product": product, "source": SOURCE_SWEEP,
        "captured_at": str(snapshot.get("generated_at") or "")[:19],
        "origin_ref": origin_ref, "device": device or None, "scope": scope,
        "healthy": healthy, "skip_reason": reason, "endpoints": endpoints,
    }


_SCHEMA_WITNESS_RE = re.compile(r"^[a-z_]+:([^@]+)@", re.I)


def evidence_from_schema_dir(product: str, line: str, path: str) -> dict:
    """``data/field_schemas/<product>/<line>/`` -> evidence document.

    The files were harvested per LINE from several boxes over time, so the
    scope is the line unless ``line`` names a full build. Per-object metadata
    (object name, harvest source) goes into ``summary.objects`` so
    :func:`matrix_doc` can rebuild the ``objects`` section of the old shape.
    """
    v = fv.normalize(line)
    scope = ({"kind": "line", "line": v} if fv.is_line_only(v)
             else {"kind": "build", "version": v, "build": ""})
    endpoints, objects, stamps = {}, {}, []
    coverage = {}
    for fname in sorted(os.listdir(path)) if os.path.isdir(path) else []:
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(path, fname)) as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            continue
        if fname == "_coverage.json" and isinstance(doc, dict):
            coverage = {k: doc.get(k) for k in ("appliance", "device_firmware",
                                               "harvested_at", "covered", "catalog_size")}
            if doc.get("harvested_at"):
                stamps.append(str(doc["harvested_at"])[:19])
            continue
        if fname.startswith("_") or not isinstance(doc, dict) or "object" not in doc:
            continue
        name = doc.get("endpoint") or doc["object"]
        fields = {}
        for f in doc.get("fields") or []:
            if isinstance(f, dict) and f.get("name"):
                fields[str(f["name"])] = {
                    "type": f.get("type") or None,
                    "options": f.get("options") or None,
                    "default": f.get("default"),
                    "required": bool(f["required"]) if "required" in f else None,
                }
        src = str(doc.get("source") or "")
        m = _SCHEMA_WITNESS_RE.match(src)
        endpoints[name] = {"urn": "", "section": "", "verdict": VERDICT_OK, "rows": None,
                           "fields": fields or None,
                           "witnesses": [m.group(1)] if m else []}
        objects[name] = {"object": doc["object"], "source": src,
                         "device_firmware": str(doc.get("device_firmware") or ""),
                         "generated_at": str(doc.get("generated_at") or "")[:19]}
        if doc.get("generated_at"):
            stamps.append(str(doc["generated_at"])[:19])
    return {
        "product": product, "source": SOURCE_SCHEMA,
        "captured_at": max(stamps) if stamps else "",
        "origin_ref": "field_schemas:%s/%s" % (product, line),
        "device": None, "scope": scope, "healthy": bool(endpoints),
        "skip_reason": "" if endpoints else "no object schemas in the directory",
        "endpoints": endpoints,
        "summary": {"objects": objects, "coverage": coverage},
    }


def _legacy_endpoints(scope_doc: dict) -> dict:
    eps: dict = {}
    for name, rec in (scope_doc.get("endpoints") or {}).items():
        if not isinstance(rec, dict):
            continue
        fields = rec.get("fields")
        eps[name] = {"urn": rec.get("urn") or "", "section": rec.get("section") or "",
                     "verdict": rec.get("verdict") or VERDICT_ERROR, "rows": None,
                     "fields": {str(f): {} for f in fields} if fields else None,
                     "witnesses": sorted(rec.get("devices") or [])}
    for obj, rec in (scope_doc.get("objects") or {}).items():
        if not isinstance(rec, dict):
            continue
        name = rec.get("endpoint") or obj
        fields = rec.get("fields")
        ep = eps.setdefault(name, {"urn": "", "section": "", "verdict": VERDICT_OK,
                                   "rows": None, "fields": None, "witnesses": []})
        if fields and ep.get("verdict") == VERDICT_OK:
            ep["fields"] = {**(ep.get("fields") or {}), **{str(f): {} for f in fields}}
    return eps


def evidence_from_legacy_matrix(product: str, matrix_doc: dict) -> list:
    """A frozen ``data/api_matrix/<product>.json`` -> evidence documents.

    One document per line (and per version, if the file has that axis). The
    file itself is the only surviving record for a product whose witnesses
    were deleted, so it is imported as what it is — ``legacy_matrix``, at the
    granularity it was recorded — rather than re-derived.
    """
    matrix_doc = matrix_doc if isinstance(matrix_doc, dict) else {}
    built_at = str(matrix_doc.get("built_at") or "")
    ref = "api_matrix:%s.json@%s" % (product, built_at)
    witnesses = [{k: w.get(k) for k in ("id", "name", "firmware", "line", "version") if k in w}
                 for w in matrix_doc.get("witnesses") or [] if isinstance(w, dict)]
    out = []
    axes = [("line", k, d) for k, d in (matrix_doc.get("lines") or {}).items()]
    axes += [("build", k, d) for k, d in (matrix_doc.get("versions") or {}).items()]
    for kind, key, scope_doc in sorted(axes, key=lambda t: (t[0], fv.sort_key(t[1]))):
        v = fv.normalize(key)
        if not v or not isinstance(scope_doc, dict):
            continue
        eps = _legacy_endpoints(scope_doc)
        if not eps:
            continue
        if fv.is_line_only(v):
            scope = {"kind": "line", "line": v}
        else:
            scope = {"kind": "build", "version": v, "build": ""}
        out.append({
            "product": product, "source": SOURCE_LEGACY, "captured_at": built_at[:19],
            "origin_ref": ref, "device": None, "scope": scope, "healthy": True,
            "skip_reason": "", "endpoints": eps,
            "summary": {"witnesses": witnesses, "axis": kind, "key": key},
        })
    return out


# ---------------------------------------------------------------------------
# backfill — every on-disk store, including deleted appliances
# ---------------------------------------------------------------------------

def _read_json_file(path: str):
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        return json.loads(data.decode("utf-8")), data
    except (OSError, ValueError):
        return None, None


def _product_for_snapshot(aid: int, snap: dict) -> str:
    """Which product a snapshot measured. Snapshots do not record it.

    Tables first (the live row, then ``device_identity`` which outlives
    de-registration), then the shape of the evidence itself — needed for
    appliances that are gone from both, which is precisely the evidence this
    backfill exists to save.
    """
    try:
        from ..models import Appliance
        ap = db.session.get(Appliance, aid)
        if ap is not None and ap.kind in PRODUCTS:
            return ap.kind
    except Exception:  # noqa: BLE001 — a lookup miss must not stop a backfill
        db.session.rollback()
    try:
        from ..models_identity import DeviceIdentity
        ident = DeviceIdentity.query.filter_by(appliance_id=aid).first()
        if ident is not None and ident.product in PRODUCTS:
            return ident.product
    except Exception:  # noqa: BLE001
        db.session.rollback()
    urns = [str((v or {}).get("urn") or "") for v in (snap.get("endpoint_status") or {}).values()
            if isinstance(v, dict)]
    if urns:
        if any(u.startswith("/api/v2.") for u in urns):
            return "fortiweb"
        if all(u.startswith("/api/") for u in urns if u):
            return "fortiadc"
    for eps in (snap.get("sections") or {}).values():
        for rows in (eps or {}).values() if isinstance(eps, dict) else []:
            for row in rows if isinstance(rows, list) else []:
                if isinstance(row, dict):
                    if "q_type" in row or "can_view" in row:
                        return "fortiweb"
                    if "mkey" in row:
                        return "fortiadc"
    name = str(snap.get("device") or "").lower()
    if "adc" in name:
        return "fortiadc"
    if name.startswith(("fw", "fortiweb")):
        return "fortiweb"
    return ""


def _device_for_snapshot(aid: int, snap: dict, devdir: str) -> dict:
    """Device identity as recorded at the time of THIS snapshot.

    Model and hw type come from ``_inventory_applied.json`` only when it was
    written from this same snapshot (same ``generated_at``): the model string
    embeds the running version, so borrowing it from a later inventory would
    stamp old evidence with the new firmware.
    """
    dev = {"appliance_id": aid,
           "name": str(snap.get("device") or "") or "appliance #%d" % aid,
           "serial": "", "model": "", "hw_type": "",
           "firmware_raw": str(snap.get("firmware") or "")}
    inv, _ = _read_json_file(os.path.join(devdir, "_inventory_applied.json"))
    if isinstance(inv, dict) and inv.get("generated_at") and \
            inv.get("generated_at") == snap.get("generated_at"):
        res = inv.get("result") or {}
        dev["model"] = str(res.get("model") or "")
        dev["hw_type"] = str(res.get("hw_type") or "")
    try:
        from ..models_identity import DeviceIdentity
        ident = DeviceIdentity.query.filter_by(appliance_id=aid).first()
        if ident is not None and ident.serial:
            dev["serial"] = ident.serial
    except Exception:  # noqa: BLE001
        db.session.rollback()
    return dev


def _rediscovery_docs(root: str):
    """Yield ``(doc, raw_bytes)`` for every snapshot under ``rediscovery/``.

    ``by-version/<v>.json`` is authoritative; ``_config.json`` is a fallback
    for a version the archive does not hold (never a merge — the archive entry
    is that version's own file). Deleted appliances are read like any other.
    """
    if not os.path.isdir(root):
        return
    for entry in sorted(os.listdir(root), key=lambda e: (not e.isdigit(), int(e) if e.isdigit() else 0, e)):
        if not entry.isdigit():
            continue
        aid = int(entry)
        devdir = os.path.join(root, entry)
        snaps = []
        archived = set()
        vdir = os.path.join(devdir, "by-version")
        if os.path.isdir(vdir):
            for fname in sorted(os.listdir(vdir)):
                if fname.endswith(".json"):
                    snap, raw = _read_json_file(os.path.join(vdir, fname))
                    if isinstance(snap, dict):
                        snaps.append((snap, raw))
                        archived.add(fv.normalize(snap.get("firmware")) or fname[:-5])
        latest, raw = _read_json_file(os.path.join(devdir, "_config.json"))
        if isinstance(latest, dict):
            v = fv.normalize(latest.get("firmware"))
            if not v or v not in archived:
                snaps.append((latest, raw))
        for snap, raw in snaps:
            product = _product_for_snapshot(aid, snap)
            yield aid, devdir, snap, raw, product


def backfill(data_root: str, products=None) -> dict:
    """Ingest every on-disk evidence store under ``data_root``. Idempotent.

    Reads ``rediscovery/*/by-version/*.json`` + ``_config.json`` (deleted
    appliances included), ``field_schemas/<product>/<line>/`` (``_default``
    excluded: it is a fallback, not a firmware), and pre-version-axis matrices
    in ``api_matrix/`` (a modern matrix is derived from the snapshots already
    read, so importing it would only duplicate them).
    """
    wanted = set(products) if products else None
    out = {"documents": 0, "created": 0, "confirmed": 0, "skipped": [], "by_product": {}}

    def _take(doc, raw, label):
        if wanted and doc["product"] not in wanted:
            return
        res = ingest(doc, raw=raw)
        out["documents"] += 1
        out["created" if res["created"] else "confirmed"] += 1
        bp = out["by_product"].setdefault(doc["product"], {"documents": 0, "created": 0,
                                                           "unhealthy": 0})
        bp["documents"] += 1
        bp["created"] += int(res["created"])
        bp["unhealthy"] += int(not doc.get("healthy", True))

    # 1. sweeps
    for aid, devdir, snap, raw, product in _rediscovery_docs(os.path.join(data_root, "rediscovery")):
        if not product:
            out["skipped"].append({"appliance_id": aid, "device": snap.get("device") or "",
                                   "reason": "cannot tell which product it measured"})
            continue
        version = fv.normalize(snap.get("firmware"))
        device = _device_for_snapshot(aid, snap, devdir)
        ref = "rediscovery:%d@%s" % (aid, version or "unversioned")
        _take(evidence_from_sweep(product, snap, device, ref), raw, ref)

    # 2. harvested field schemas
    base = os.path.join(data_root, "field_schemas")
    for product in sorted(os.listdir(base)) if os.path.isdir(base) else []:
        pdir = os.path.join(base, product)
        for line in sorted(os.listdir(pdir)) if os.path.isdir(pdir) else []:
            path = os.path.join(pdir, line)
            if line.startswith("_") or not os.path.isdir(path) or not fv.normalize(line):
                continue
            doc = evidence_from_schema_dir(product, line, path)
            if doc["endpoints"]:
                _take(doc, None, doc["origin_ref"])

    # 3. frozen line-only matrices
    mdir = os.path.join(data_root, "api_matrix")
    for fname in sorted(os.listdir(mdir)) if os.path.isdir(mdir) else []:
        if not fname.endswith(".json"):
            continue
        mdoc, raw = _read_json_file(os.path.join(mdir, fname))
        if not isinstance(mdoc, dict) or "versions" in mdoc or not mdoc.get("lines"):
            continue
        product = mdoc.get("product") or fname[:-5]
        for doc in evidence_from_legacy_matrix(product, mdoc):
            _take(doc, raw, doc["origin_ref"])
    return out


# ---------------------------------------------------------------------------
# query internals — state of one build, in a few SQL statements
# ---------------------------------------------------------------------------

def _vendor_evidence(product: str) -> list:
    """``[(evidence_id, summary)]`` of healthy vendor documents for a product."""
    return [(eid, summ or {}) for eid, summ in db.session.execute(
        select(ApiLibEvidence.id, ApiLibEvidence.summary).where(
            ApiLibEvidence.product == product,
            ApiLibEvidence.source == SOURCE_VENDOR,
            ApiLibEvidence.healthy.is_(True)))]


def _vendor_candidates(product: str, key: str, vendor=None) -> list:
    """Vendor evidence ids that speak for the build at ``key``.

    A document speaks for a build only inside its own ``[min, max]``: the max
    is the cap on every open-ended range in it (rule 4). When several
    documents cover the build, the ones that know the newest firmware win —
    a newer collection supersedes an older one's opinion — while sibling
    documents of the same collection (same max) are read together.
    """
    if not key or key.count(".") < 2:
        return []   # a line-only build is not a point a range can contain
    cands = [(eid, s) for eid, s in (vendor if vendor is not None else _vendor_evidence(product))
             if s.get("min_key") and s.get("max_key")
             and s["min_key"] <= key <= s["max_key"]]
    if not cands:
        return []
    top = max(s["max_key"] for _, s in cands)
    return [eid for eid, s in cands if s["max_key"] == top]


def _point_state(build_ids, endpoint=None, with_fields=True) -> dict:
    """``{build_id: {endpoint: {source: rec}}}`` from folded facts."""
    out: dict = {}
    build_ids = list(build_ids)
    if not build_ids:
        return out
    for chunk in _chunks(build_ids):
        q = (select(ApiLibEndpointFact, ApiLibEndpoint.name)
             .join(ApiLibEndpoint, ApiLibEndpoint.id == ApiLibEndpointFact.endpoint_id)
             .where(ApiLibEndpointFact.build_id.in_(chunk)))
        if endpoint is not None:
            q = q.where(ApiLibEndpoint.name == endpoint)
        for f, name in db.session.execute(q):
            out.setdefault(f.build_id, {}).setdefault(name, {})[f.source] = {
                "verdict": f.verdict, "urn": f.urn or "", "section": f.section or "",
                "fields_known": bool(f.fields_known), "witnesses": list(f.witnesses or []),
                "first_seen": f.first_seen, "last_seen": f.last_seen,
                "evidence_ids": sorted({f.first_evidence_id, f.last_evidence_id} - {None}),
                "fields": {} if f.fields_known else None,
            }
    if not with_fields:
        return out
    for chunk in _chunks(build_ids):
        q = (select(ApiLibFieldFact, ApiLibField.name, ApiLibEndpoint.name)
             .join(ApiLibField, ApiLibField.id == ApiLibFieldFact.field_id)
             .join(ApiLibEndpoint, ApiLibEndpoint.id == ApiLibField.endpoint_id)
             .where(ApiLibFieldFact.build_id.in_(chunk)))
        if endpoint is not None:
            q = q.where(ApiLibEndpoint.name == endpoint)
        for ff, fname, ename in db.session.execute(q):
            rec = out.get(ff.build_id, {}).get(ename, {}).get(ff.source)
            if rec is None or rec["fields"] is None:
                continue
            rec["fields"][fname] = {
                "type": ff.type, "options": ff.options, "default": ff.default,
                "required": ff.required, "children": ff.children,
                "platforms": list(ff.platforms or []),
            }
    return out


def _vendor_state(product: str, key: str, endpoint=None, with_fields=True,
                  vendor=None) -> dict:
    """``{endpoint: {"vendor_doc": rec}}`` — vendor ranges resolved at ``key``."""
    cands = _vendor_candidates(product, key, vendor)
    if not cands:
        return {}
    out: dict = {}
    q = (select(ApiLibSpan.endpoint_id, ApiLibEndpoint.name, ApiLibSpan.from_key,
                ApiLibSpan.to_key, ApiLibSpan.attrs, ApiLibSpan.evidence_id)
         .join(ApiLibEndpoint, ApiLibEndpoint.id == ApiLibSpan.endpoint_id)
         .where(ApiLibSpan.evidence_id.in_(cands), ApiLibSpan.field_id.is_(None)))
    if endpoint is not None:
        q = q.where(ApiLibEndpoint.name == endpoint)
    ep_ids = {}
    for eid, name, lo, hi, attrs, evid in db.session.execute(q):
        attrs = attrs or {}
        covered = lo <= key and (hi is None or key <= hi)
        rec = out.setdefault(name, {SOURCE_VENDOR: {
            "verdict": VERDICT_ABSENT, "urn": attrs.get("urn") or "",
            "section": attrs.get("section") or "", "fields_known": False,
            "witnesses": [], "first_seen": None, "last_seen": None,
            "evidence_ids": [], "fields": None}})[SOURCE_VENDOR]
        if evid not in rec["evidence_ids"]:
            rec["evidence_ids"].append(evid)
        if covered:
            rec["verdict"] = VERDICT_OK
            if attrs.get("fields_known"):
                rec["fields_known"] = True
                rec["fields"] = rec["fields"] or {}
        ep_ids[eid] = name
    if not with_fields or not ep_ids:
        return out
    q = (select(ApiLibSpan.endpoint_id, ApiLibField.name, ApiLibSpan.attrs)
         .join(ApiLibField, ApiLibField.id == ApiLibSpan.field_id)
         .where(ApiLibSpan.evidence_id.in_(cands), ApiLibSpan.field_id.isnot(None),
                ApiLibSpan.from_key <= key,
                or_(ApiLibSpan.to_key.is_(None), ApiLibSpan.to_key >= key)))
    if endpoint is not None:
        q = q.where(ApiLibSpan.endpoint_id.in_(list(ep_ids)))
    for eid, fname, attrs in db.session.execute(q):
        rec = out.get(ep_ids.get(eid), {}).get(SOURCE_VENDOR)
        if rec is None or rec["verdict"] != VERDICT_OK or rec["fields"] is None:
            continue
        a = attrs or {}
        rec["fields"][fname] = {"type": a.get("type"), "options": a.get("options"),
                                "default": a.get("default"), "required": a.get("required"),
                                "children": a.get("children"), "platforms": []}
    return out


def _state(product: str, version, endpoint=None, with_fields=True) -> tuple:
    """``(build_row, {endpoint: {source: rec}})`` for one version string."""
    v = fv.normalize(version)
    b = _build_row(product, v) if v else None
    state: dict = {}
    if b is not None:
        state = _point_state([b.id], endpoint, with_fields).get(b.id, {})
    for name, by_src in _vendor_state(product, version_key(v), endpoint, with_fields).items():
        state.setdefault(name, {}).update(by_src)
    return b, state


def _pool(by_src: dict) -> dict:
    """The sources that decide: measured ones if any, else vendor (rule 4)."""
    measured = {s: r for s, r in by_src.items() if s != SOURCE_VENDOR}
    return measured or by_src


def _ordered_sources(sources) -> list:
    return sorted(sources, key=lambda s: (SOURCE_PRIORITY.index(s)
                                          if s in SOURCE_PRIORITY else 99, s))


# ---------------------------------------------------------------------------
# query API
# ---------------------------------------------------------------------------

def products() -> list:
    """One summary row per product the library knows about."""
    ev_counts: dict = {}
    for product, source, n in db.session.execute(
            select(ApiLibEvidence.product, ApiLibEvidence.source, func.count())
            .group_by(ApiLibEvidence.product, ApiLibEvidence.source)):
        ev_counts.setdefault(product, {})[source] = n
    b_counts = dict(db.session.execute(
        select(ApiLibBuild.product, func.count()).group_by(ApiLibBuild.product)).all())
    e_counts = dict(db.session.execute(
        select(ApiLibEndpoint.product, func.count()).group_by(ApiLibEndpoint.product)).all())
    names = list(PRODUCTS) + sorted(set(ev_counts) - set(PRODUCTS))
    return [{"product": p, "catalog_only": p in CATALOG_ONLY_PRODUCTS,
             "builds": b_counts.get(p, 0), "endpoints": e_counts.get(p, 0),
             "evidence": sum((ev_counts.get(p) or {}).values()),
             "sources": _ordered_sources(ev_counts.get(p) or {}),
             "evidence_by_source": dict(ev_counts.get(p) or {})}
            for p in names]


def _fleet(product: str) -> dict:
    """``{appliance_id: {...}}`` of LIVE boxes — used for ``in_fleet`` only."""
    try:
        from . import api_matrix
        return api_matrix._live_appliances(product)
    except Exception:  # noqa: BLE001 — no appliance table for this product
        db.session.rollback()
        return {}


def builds(product: str) -> list:
    """Every version the library knows for ``product``, measured or not.

    Evidence and vendor builds come from ``api_lib_build``. Declared versions
    (``firmware_version_decls``, uploaded images) and versions a live box runs
    are merged on read and never written: a query that inserts rows would turn
    typing a version number into evidence.
    """
    rows = {b.version: b for b in ApiLibBuild.query.filter_by(product=product).all()}
    by_id = {b.id: b for b in rows.values()}

    ev_count: dict = {}
    ev_sources: dict = {}
    for bid, source, n in db.session.execute(
            select(ApiLibEvidence.build_id, ApiLibEvidence.source, func.count())
            .where(ApiLibEvidence.product == product, ApiLibEvidence.build_id.isnot(None))
            .group_by(ApiLibEvidence.build_id, ApiLibEvidence.source)):
        ev_count[bid] = ev_count.get(bid, 0) + n
        ev_sources.setdefault(bid, set()).add(source)
    point_measured = {bid for (bid,) in db.session.execute(
        select(ApiLibEndpointFact.build_id).distinct()
        .where(ApiLibEndpointFact.build_id.in_(list(by_id) or [-1])))}
    vendor = _vendor_evidence(product)

    try:
        catalog = fv.catalog(product)
    except Exception:  # noqa: BLE001 — authored declarations are optional here
        db.session.rollback()
        catalog = {}
    fleet_versions = {w["version"] for w in _fleet(product).values() if w.get("version")}

    out = []
    for v in sorted(set(rows) | set(catalog) | fleet_versions, key=fv.sort_key):
        b = rows.get(v)
        meta = catalog.get(v) or {}
        declared_sources = [s for s in meta.get("sources") or [] if s != fv.SOURCE_EVIDENCE]
        key = b.sort_key if b else version_key(v)
        vendor_cov = bool(_vendor_candidates(product, key, vendor))
        point = b is not None and b.id in point_measured
        sources = set(ev_sources.get(b.id, set())) if b else set()
        if vendor_cov:
            sources.add(SOURCE_VENDOR)
        out.append({
            "product": product, "version": v, "build": (b.build if b else "") or "",
            "line": fv.line_of(v), "line_only": fv.is_line_only(v), "sort_key": key,
            "origin": b.origin if b else ORIGIN_DECLARED,
            "sources": _ordered_sources(sources),
            "declared_sources": declared_sources,
            "declared": bool(declared_sources),
            "evidence": ev_count.get(b.id, 0) if b else 0,
            "measured": point or vendor_cov,
            "vendor_only": vendor_cov and not point,
            "in_fleet": v in fleet_versions,
            "first_seen": _iso(b.first_seen) if b else "",
            "last_seen": _iso(b.last_seen) if b else "",
        })
    return out


def _endpoint_summary(name: str, by_src: dict) -> dict:
    pool = _pool(by_src)
    first = [r["first_seen"] for r in by_src.values() if r.get("first_seen")]
    last = [r["last_seen"] for r in by_src.values() if r.get("last_seen")]
    lead = next(by_src[s] for s in _ordered_sources(by_src))
    return {
        "endpoint": name,
        "urn": lead["urn"] or next((r["urn"] for r in by_src.values() if r["urn"]), ""),
        "section": lead["section"] or next((r["section"] for r in by_src.values()
                                            if r["section"]), ""),
        "verdict": _best_verdict(r["verdict"] for r in pool.values()),
        "fields_known": any(r["fields_known"] and r["verdict"] == VERDICT_OK
                            for r in pool.values()),
        "sources": _ordered_sources(by_src),
        "by_source": {s: by_src[s]["verdict"] for s in _ordered_sources(by_src)},
        "vendor_only": set(by_src) == {SOURCE_VENDOR},
        "witnesses": sorted({w for r in by_src.values() for w in r["witnesses"]}),
        "first_seen": _iso(min(first)) if first else "",
        "last_seen": _iso(max(last)) if last else "",
    }


def endpoints_at(product: str, version) -> dict:
    """``{endpoint: summary}`` for one build, vendor range coverage included.

    Empty for an unmeasured build — the caller must read that as "unknown",
    which is why nothing here fills gaps from the line or a neighbour build.
    """
    _b, state = _state(product, version, with_fields=False)
    return {name: _endpoint_summary(name, by_src) for name, by_src in sorted(state.items())}


def fields_at(product: str, endpoint: str, version) -> dict:
    """Fields ``endpoint`` serves on ``version``, with an honest status.

    ``measured`` (fields known), ``blind`` (the endpoint answered, no row
    revealed its fields), ``absent`` (measured and not served) or
    ``unmeasured`` (nobody asked this build). Measured sources decide; vendor
    fields are used only when no measured source speaks for the endpoint.
    """
    b, state = _state(product, version, endpoint=endpoint, with_fields=True)
    by_src = state.get(endpoint) or {}
    base = {"product": product, "endpoint": endpoint, "version": fv.normalize(version),
            "build": _build_dict(b), "fields": {}, "provenance": []}
    for s in _ordered_sources(by_src):
        r = by_src[s]
        base["provenance"].append({
            "source": s, "verdict": r["verdict"], "fields_known": r["fields_known"],
            "field_count": len(r["fields"] or {}), "witnesses": r["witnesses"],
            "evidence_ids": r["evidence_ids"], "first_seen": _iso(r["first_seen"]),
            "last_seen": _iso(r["last_seen"])})
    if not by_src:
        return {**base, "status": "unmeasured"}
    pool = _pool(by_src)
    verdict = _best_verdict(r["verdict"] for r in pool.values())
    if verdict == VERDICT_ABSENT:
        return {**base, "status": "absent"}
    if verdict != VERDICT_OK:
        # Only errors: the build was asked and did not answer. Not a "no".
        return {**base, "status": "unmeasured"}
    knowing = [s for s in _ordered_sources(pool)
               if pool[s]["verdict"] == VERDICT_OK and pool[s]["fields_known"]]
    if not knowing:
        return {**base, "status": "blind"}
    fields: dict = {}
    for s in knowing:
        for fname, spec in (pool[s]["fields"] or {}).items():
            rec = fields.setdefault(fname, {**spec, "sources": []})
            rec["sources"].append(s)
            for k, v in spec.items():
                if rec.get(k) in (None, []) and v not in (None, []):
                    rec[k] = v
    for p in base["provenance"]:
        p["used"] = p["source"] in knowing
    return {**base, "status": "measured", "fields": dict(sorted(fields.items()))}


def _renames(product: str, names, base: str, target: str) -> dict:
    """``{endpoint: [(old, new, note)]}`` applicable to a base->target move."""
    names = list(names)
    if not names:
        return {}
    kb, kt = version_key(base), version_key(target)
    out: dict = {}
    for chunk in _chunks(names):
        for m in ApiLibFieldMap.query.filter(ApiLibFieldMap.product == product,
                                             ApiLibFieldMap.endpoint.in_(chunk),
                                             ApiLibFieldMap.retired_at.is_(None)).all():
            fk = version_key(m.from_version) or None
            tk = version_key(m.to_version) or None
            if kb <= kt and (fk is None or kb <= fk) and (tk is None or kt >= tk):
                out.setdefault(m.endpoint, []).append((m.from_field, m.to_field, m.note or ""))
            elif kt < kb and (fk is None or kt <= fk) and (tk is None or kb >= tk):
                # Comparing backwards across the rename: new name -> old name.
                out.setdefault(m.endpoint, []).append((m.to_field, m.from_field, m.note or ""))
    return out


def compare(product: str, base, target, endpoint=None) -> dict:
    """What changes moving from ``base`` to ``target``.

    Endpoints: ``added``/``removed`` need a measured answer on BOTH sides
    (rule 3); anything else is ``unknown``. Fields are compared only between
    the SAME kind of evidence (sweep<->sweep, schema<->schema, vendor<->vendor):
    a sweep field set carries wire noise a harvested schema strips, and mixing
    them produced 56 phantom removals in the file-based matrix.
    Operator-authored renames (``api_lib_field_map``) turn a lost+added pair
    into one ``renamed`` entry.
    """
    bb, sa_ = _state(product, base, endpoint=endpoint, with_fields=True)
    tb, sb_ = _state(product, target, endpoint=endpoint, with_fields=True)
    added, removed, unknown = [], [], []
    per_ep: dict = {}
    both_ok = []
    for name in sorted(set(sa_) | set(sb_)):
        a, b = sa_.get(name) or {}, sb_.get(name) or {}
        va = _best_verdict(r["verdict"] for r in _pool(a).values()) if a else None
        vb = _best_verdict(r["verdict"] for r in _pool(b).values()) if b else None
        urn = next((r["urn"] for r in list(b.values()) + list(a.values()) if r["urn"]), "")
        if va == VERDICT_OK and vb == VERDICT_OK:
            both_ok.append(name)
        elif va == VERDICT_ABSENT and vb == VERDICT_OK:
            added.append({"endpoint": name, "urn": urn, "sources": _ordered_sources(b)})
        elif va == VERDICT_OK and vb == VERDICT_ABSENT:
            removed.append({"endpoint": name, "urn": urn, "sources": _ordered_sources(a)})
        elif VERDICT_OK in (va, vb):
            unknown.append({"endpoint": name, "urn": urn,
                            "known_on": "base" if va == VERDICT_OK else "target",
                            "base_verdict": va, "target_verdict": vb})

    renames = _renames(product, both_ok, str(base), str(target))
    totals = {"fields_added": 0, "fields_removed": 0, "fields_retyped": 0,
              "fields_renamed": 0, "fields_unknown": 0}
    for name in both_ok:
        a, b = sa_[name], sb_[name]
        ka = {s for s, r in a.items() if r["verdict"] == VERDICT_OK and r["fields_known"]}
        kb = {s for s, r in b.items() if r["verdict"] == VERDICT_OK and r["fields_known"]}
        shared = _ordered_sources(ka & kb)
        if not shared:
            reason = ("fields known on neither side" if not ka and not kb else
                      "fields known on one side only" if not (ka and kb) else
                      "fields known from different kinds of evidence")
            per_ep[name] = {"unknown": True, "reason": reason,
                            "base_sources": _ordered_sources(ka),
                            "target_sources": _ordered_sources(kb)}
            totals["fields_unknown"] += 1
            continue
        src = shared[0]
        fa, fb = a[src]["fields"] or {}, b[src]["fields"] or {}
        f_added = sorted(set(fb) - set(fa))
        f_removed = sorted(set(fa) - set(fb))
        retyped = [{"field": f, "from": fa[f].get("type"), "to": fb[f].get("type")}
                   for f in sorted(set(fa) & set(fb))
                   if fa[f].get("type") and fb[f].get("type")
                   and fa[f].get("type") != fb[f].get("type")]
        renamed = []
        for old, new, note in renames.get(name, []):
            if old in f_removed and new in f_added:
                f_removed.remove(old)
                f_added.remove(new)
                renamed.append({"from": old, "to": new, "note": note})
        if f_added or f_removed or retyped or renamed:
            per_ep[name] = {"unknown": False, "source": src, "added": f_added,
                            "removed": f_removed, "retyped": retyped, "renamed": renamed}
            totals["fields_added"] += len(f_added)
            totals["fields_removed"] += len(f_removed)
            totals["fields_retyped"] += len(retyped)
            totals["fields_renamed"] += len(renamed)
    return {
        "product": product, "base": fv.normalize(base), "target": fv.normalize(target),
        "base_build": _build_dict(bb), "target_build": _build_dict(tb),
        "base_measured": bool(sa_), "target_measured": bool(sb_),
        "endpoints_added": added, "endpoints_removed": removed,
        "endpoints_unknown": unknown, "endpoints": per_ep, "totals": totals,
    }


def field_history(product: str, endpoint: str, field: str) -> dict:
    """Where ``endpoint.field`` was seen: builds, first/last, sources."""
    out = {"product": product, "endpoint": endpoint, "field": field, "known": False,
           "builds": [], "vendor_spans": [], "first_build": "", "last_build": "",
           "sources": []}
    ep = ApiLibEndpoint.query.filter_by(product=product, name=endpoint).first()
    f = ApiLibField.query.filter_by(endpoint_id=ep.id, name=field).first() if ep else None
    if f is None:
        return out
    out["known"] = True
    seen: dict = {}
    sources = set()
    for ff, version, key in db.session.execute(
            select(ApiLibFieldFact, ApiLibBuild.version, ApiLibBuild.sort_key)
            .join(ApiLibBuild, ApiLibBuild.id == ApiLibFieldFact.build_id)
            .where(ApiLibFieldFact.field_id == f.id)):
        out["builds"].append({"version": version, "source": ff.source, "type": ff.type,
                              "first_seen": _iso(ff.first_seen),
                              "last_seen": _iso(ff.last_seen)})
        seen[key] = version
        sources.add(ff.source)
    spans = db.session.execute(
        select(ApiLibSpan.from_version, ApiLibSpan.to_version, ApiLibSpan.from_key,
               ApiLibSpan.to_key, ApiLibEvidence.summary, ApiLibEvidence.origin_ref)
        .join(ApiLibEvidence, ApiLibEvidence.id == ApiLibSpan.evidence_id)
        .where(ApiLibSpan.field_id == f.id)).all()
    if spans:
        sources.add(SOURCE_VENDOR)
        vbuilds = db.session.execute(
            select(ApiLibBuild.version, ApiLibBuild.sort_key)
            .where(ApiLibBuild.product == product, ApiLibBuild.line_only.is_(False))).all()
        for lo_v, hi_v, lo, hi, summ, ref in spans:
            cap = (summ or {}).get("max_key") or ""
            end = hi or cap
            out["vendor_spans"].append({"from": lo_v, "to": hi_v,
                                        "to_capped": hi_v or (summ or {}).get("max_version") or "",
                                        "origin_ref": ref})
            for version, key in vbuilds:
                if lo <= key <= end:
                    seen.setdefault(key, version)
    out["builds"].sort(key=lambda r: (fv.sort_key(r["version"]), r["source"]))
    if seen:
        keys = sorted(seen)
        out["first_build"], out["last_build"] = seen[keys[0]], seen[keys[-1]]
    out["sources"] = _ordered_sources(sources)
    return out


def resolve_appliance(appliance) -> dict:
    """Which build ``appliance`` runs and what the library knows about it."""
    product = getattr(appliance, "kind", "") or ""
    raw = getattr(appliance, "fw_version", "") or getattr(appliance, "firmware", "") or ""
    v = fv.normalize(raw)
    out = {"appliance": getattr(appliance, "name", ""), "product": product,
           "firmware_raw": str(raw), "version": v, "line": fv.line_of(v),
           "build": None, "status": "unknown_firmware"}
    if not v:
        return out
    b = _build_row(product, v)
    point = False
    if b is not None:
        point = db.session.execute(select(ApiLibEndpointFact.id).where(
            ApiLibEndpointFact.build_id == b.id).limit(1)).first() is not None
    vendor = bool(_vendor_candidates(product, version_key(v)))
    status = "measured" if point else "vendor_only" if vendor else "unmeasured"
    return {**out, "build": _build_dict(b), "status": status}


# ---------------------------------------------------------------------------
# matrix_doc — the api_matrix.build() shape, served from the library
# ---------------------------------------------------------------------------

_MATRIX_ORIGIN = {SOURCE_SWEEP: "sweep", SOURCE_SCHEMA: "schema", SOURCE_MANUAL: "manual",
                  SOURCE_LEGACY: "legacy_matrix", SOURCE_VENDOR: "vendor_doc"}


def _matrix_ep(name: str, by_src: dict) -> dict:
    pool = _pool(by_src)
    names = set()
    for r in pool.values():
        if r["verdict"] == VERDICT_OK and r["fields"]:
            names |= set(r["fields"])
    last = [r["last_seen"] for r in by_src.values() if r.get("last_seen")]
    lead = _ordered_sources(pool)[0]
    return {
        "endpoint": name,
        "urn": next((by_src[s]["urn"] for s in _ordered_sources(by_src) if by_src[s]["urn"]), ""),
        "section": next((by_src[s]["section"] for s in _ordered_sources(by_src)
                         if by_src[s]["section"]), ""),
        "verdict": _best_verdict(r["verdict"] for r in pool.values()),
        # Rule 1: an empty set is reported as None, exactly like api_matrix.
        "fields": sorted(names) if names else None,
        "origin": _MATRIX_ORIGIN.get(lead, lead),
        "devices": sorted({w for r in by_src.values() for w in r["witnesses"]}),
        "measured_at": _iso(max(last)) if last else "",
    }


def _matrix_obj(name: str, rec: dict, meta: dict) -> dict:
    fields = sorted(rec["fields"]) if rec.get("fields") else None
    return {"endpoint": name, "object": meta.get("object") or name,
            "fields": fields, "origin": "schema", "source": meta.get("source") or "",
            "device_firmware": meta.get("device_firmware") or "",
            "measured_at": meta.get("generated_at") or _iso(rec.get("last_seen"))}


def _counts(eps: dict, objects: dict) -> dict:
    ok = sum(1 for r in eps.values() if r["verdict"] == VERDICT_OK)
    absent = sum(1 for r in eps.values() if r["verdict"] == VERDICT_ABSENT)
    return {"swept": len(eps), "ok": ok, "absent": absent, "error": len(eps) - ok - absent,
            "endpoints_with_fields": sum(1 for r in eps.values() if r["fields"]),
            "schema_objects": len(objects),
            "schema_fields": sum(len(r["fields"] or []) for r in objects.values())}


def _witnesses(product: str, live: dict) -> list:
    """Live boxes plus every other device that left evidence.

    A retired or deleted device's evidence is kept, and so is its name here:
    a claim on the page must be traceable to the box that produced it.
    """
    try:
        from ..models import Appliance
        existing = {aid for (aid,) in db.session.execute(select(Appliance.id))}
    except Exception:  # noqa: BLE001
        db.session.rollback()
        existing = set()
    out = {aid: {"id": aid, **w, "live": True, "retired": False} for aid, w in live.items()}
    latest: dict = {}
    for aid, name, fw_raw, at in db.session.execute(
            select(ApiLibEvidence.appliance_id, ApiLibEvidence.device_name,
                   ApiLibEvidence.firmware_raw, ApiLibEvidence.captured_at)
            .where(ApiLibEvidence.product == product,
                   ApiLibEvidence.appliance_id.isnot(None))):
        if aid in out:
            continue
        cur = latest.get(aid)
        if cur is None or (at or datetime.min) >= (cur[2] or datetime.min):
            latest[aid] = (name, fw_raw, at)
    for aid, (name, fw_raw, _at) in latest.items():
        out[aid] = {"id": aid, "name": name or "appliance #%d" % aid,
                    "firmware": fw_raw or "", "version": fv.normalize(fw_raw),
                    "line": fv.line_of(fw_raw), "live": False,
                    "retired": aid not in existing}
    return [out[k] for k in sorted(out)]


def matrix_doc(product: str, versions=None) -> dict:
    """The document ``api_matrix.build(product)`` returns, built from the DB.

    Same keys at every level so existing consumers (diff, preflight, the
    versions page) keep working. Two deliberate differences, both the point of
    the library: evidence is NOT filtered by the live appliance table (a
    retired device's evidence stays and it is listed in ``witnesses`` with
    ``retired: True``), and vendor range coverage appears as endpoints with
    ``origin: vendor_doc`` for products that have it.

    Which builds get a ``versions`` entry is decided by the evidence SCOPE,
    not by the version string: a build with point evidence (``scope_kind ==
    "build"``, e.g. a sweep whose box reported only ``8.0``) is its own
    entry, marked ``line_only``, so ``resolve_scope("8.0")`` answers from
    that snapshot and not from the merge of every 8.0.x. Line-scoped evidence
    (schema dirs, ``legacy_matrix``) names no build: it only joins the rollup
    and reaches builds as ``granularity: "line"`` objects.
    """
    from . import api_matrix

    wanted = {fv.normalize(v) for v in versions or [] if fv.normalize(v)} or None
    live = _fleet(product)
    fleet_versions = sorted({w["version"] for w in live.values() if w.get("version")},
                            key=fv.sort_key)
    fleet_lines = sorted({w["line"] for w in live.values() if w.get("line")})

    all_builds = {b.id: b for b in ApiLibBuild.query.filter_by(product=product).all()}
    point = _point_state(all_builds.keys(), with_fields=True)
    vendor = _vendor_evidence(product)

    # Per-object metadata of schema evidence (object name, harvest source),
    # newest evidence last so it wins.
    obj_meta: dict = {}
    for bid, summ in db.session.execute(
            select(ApiLibEvidence.build_id, ApiLibEvidence.summary)
            .where(ApiLibEvidence.product == product, ApiLibEvidence.source == SOURCE_SCHEMA,
                   ApiLibEvidence.healthy.is_(True))
            .order_by(ApiLibEvidence.id)):
        obj_meta.setdefault(bid, {}).update((summ or {}).get("objects") or {})

    notes = []
    for name, ref, reason, bid in db.session.execute(
            select(ApiLibEvidence.device_name, ApiLibEvidence.origin_ref,
                   ApiLibEvidence.skip_reason, ApiLibEvidence.build_id)
            .where(ApiLibEvidence.product == product, ApiLibEvidence.healthy.is_(False))
            .order_by(ApiLibEvidence.id)):
        b = all_builds.get(bid)
        notes.append({"device": name or ref, "version": b.version if b else "",
                      "skipped": reason or "unhealthy evidence"})

    line_builds = {b.version: b for b in all_builds.values() if b.line_only}

    # (build_id, source) pairs backed by healthy POINT evidence. Facts are
    # keyed (thing, build, source), so the source is what tells a line-only
    # build's sweep facts apart from the schema/legacy facts filed on the
    # same "8.0" row at line granularity.
    point_src = {(bid, src) for bid, src in db.session.execute(
        select(ApiLibEvidence.build_id, ApiLibEvidence.source).distinct()
        .where(ApiLibEvidence.product == product, ApiLibEvidence.scope_kind == "build",
               ApiLibEvidence.healthy.is_(True), ApiLibEvidence.build_id.isnot(None)))}

    def _facts(bid, point_scoped: bool) -> dict:
        """``{endpoint: {source: rec}}`` of one build, point OR line part."""
        out = {}
        for name, by_src in (point.get(bid) or {}).items():
            d = {s: r for s, r in by_src.items() if ((bid, s) in point_src) == point_scoped}
            if d:
                out[name] = d
        return out

    def _objects(bid, facts, granularity=None, line=None) -> dict:
        objs = {}
        for name, by_src in facts.items():
            rec = by_src.get(SOURCE_SCHEMA)
            if rec is None:
                continue
            meta = (obj_meta.get(bid) or {}).get(name) or {}
            o = _matrix_obj(name, rec, meta)
            if granularity:
                o = dict(o, granularity=granularity, line=line)
            objs[o["object"]] = o
        return objs

    # --- the atomic axis ---------------------------------------------------
    out_versions: dict = {}
    for b in sorted(all_builds.values(), key=lambda x: x.sort_key):
        if wanted and b.version not in wanted:
            continue
        own = _facts(b.id, point_scoped=True)
        by_ep = {n: {s: r for s, r in d.items() if s != SOURCE_SCHEMA}
                 for n, d in own.items()}
        for n, d in _vendor_state(product, b.sort_key, None, True, vendor).items():
            by_ep.setdefault(n, {}).update(d)
        eps = {n: _matrix_ep(n, d) for n, d in sorted(by_ep.items()) if d}
        objects = _objects(b.id, own, "build", b.line)
        # A line-only build with nothing but line-scoped evidence stops here:
        # it stays a line, exactly as before.
        if not eps and not objects:
            continue
        lb = line_builds.get(b.line)
        if lb is not None:
            for k, o in _objects(lb.id, _facts(lb.id, point_scoped=False),
                                 "line", b.line).items():
                objects.setdefault(k, o)
        out_versions[b.version] = {
            "version": b.version, "line": b.line, "line_only": bool(b.line_only),
            "sources": [fv.SOURCE_EVIDENCE], "manual": False, "declared": False,
            "in_fleet": b.version in fleet_versions,
            "measured": bool(eps),
            "devices": sorted({d for r in eps.values() for d in r["devices"]}),
            "endpoints": eps, "objects": objects, "counts": _counts(eps, objects),
        }

    # --- the rollup --------------------------------------------------------
    lines_with_facts = {v for v, b in line_builds.items() if _facts(b.id, point_scoped=False)}
    if wanted:
        lines_with_facts = {ln for ln in lines_with_facts
                            if ln in wanted or any(fv.line_of(w) == ln for w in wanted)}
    all_lines = sorted({v["line"] for v in out_versions.values()} | lines_with_facts,
                       key=fv.sort_key)
    out_lines: dict = {}
    for line in all_lines:
        members = sorted([v for v in out_versions if fv.line_of(v) == line], key=fv.sort_key)
        measured_members = [v for v in members if out_versions[v]["measured"]]
        eps: dict = {}
        for version in measured_members:
            # A line-only member (a box that reported only "8.0") joins the
            # merge but names no build, so it cannot be listed as a build
            # that attested or stayed silent — partials stay a build-level fact.
            pinned = not out_versions[version]["line_only"]
            for name, rec in out_versions[version]["endpoints"].items():
                agg = eps.setdefault(name, {
                    "endpoint": name, "urn": rec.get("urn") or "",
                    "section": rec.get("section") or "", "verdict": None, "fields": None,
                    "origin": rec.get("origin") or "sweep", "devices": [],
                    "measured_at": rec.get("measured_at") or "",
                    "attested_on": [], "silent_on": []})
                for d in rec["devices"]:
                    if d not in agg["devices"]:
                        agg["devices"].append(d)
                if (rec.get("measured_at") or "") > (agg["measured_at"] or ""):
                    agg["measured_at"] = rec.get("measured_at") or ""
                if rec["verdict"] == VERDICT_OK:
                    agg["verdict"] = VERDICT_OK
                    if pinned:
                        agg["attested_on"].append(version)
                else:
                    if pinned:
                        agg["silent_on"].append(version)
                    if rec["verdict"] == VERDICT_ABSENT and agg["verdict"] != VERDICT_OK:
                        agg["verdict"] = VERDICT_ABSENT
                    elif agg["verdict"] is None:
                        agg["verdict"] = VERDICT_ERROR
                if rec.get("fields"):
                    agg["fields"] = sorted(set(agg["fields"] or []) | set(rec["fields"]))

        # Line-scoped endpoint evidence (a frozen line-only matrix) joins the
        # rollup it was recorded for. It names no build, so it never adds to
        # ``attested_on`` — it cannot say which build served the endpoint.
        lb = line_builds.get(line)
        line_facts = _facts(lb.id, point_scoped=False) if lb is not None else {}
        if lb is not None:
            for name, by_src in line_facts.items():
                d = {s: r for s, r in by_src.items() if s != SOURCE_SCHEMA}
                if not d:
                    continue
                rec = _matrix_ep(name, d)
                agg = eps.get(name)
                if agg is None:
                    eps[name] = dict(rec, attested_on=[], silent_on=[])
                    continue
                agg["verdict"] = _best_verdict([agg["verdict"], rec["verdict"]])
                if rec["fields"]:
                    agg["fields"] = sorted(set(agg["fields"] or []) | set(rec["fields"]))
                agg["devices"] = sorted(set(agg["devices"]) | set(rec["devices"]))

        partial = [{"endpoint": name, "attested_on": r["attested_on"],
                    "silent_on": r["silent_on"], "urn": r.get("urn", "")}
                   for name, r in sorted(eps.items()) if r["attested_on"] and r["silent_on"]]
        objects = _objects(lb.id, line_facts) if lb is not None else {}
        counts = _counts(eps, objects)
        counts.update(versions=len(members), measured_versions=len(measured_members),
                      partial=len(partial))
        out_lines[line] = {
            "line": line, "in_fleet": line in fleet_lines, "versions": members,
            "measured_versions": measured_members, "declared_versions": [],
            "heterogeneous": len(measured_members) > 1,
            "measured": bool(eps) or bool(objects),
            "devices": sorted({d for r in eps.values() for d in r["devices"]}),
            "endpoints": eps, "objects": objects, "partial_endpoints": partial,
            "counts": counts,
        }

    return {
        "product": product,
        "built_at": _iso(_now()),
        "sweepable": product in api_matrix.SWEPT_PRODUCTS,
        "fleet_lines": fleet_lines,
        "fleet_versions": fleet_versions,
        "witnesses": _witnesses(product, live),
        "notes": notes,
        "versions": out_versions,
        "lines": out_lines,
    }


__all__ = [
    "PRODUCTS", "CATALOG_ONLY_PRODUCTS", "SOURCES", "MAX_ERROR_RATIO",
    "version_key", "content_hash", "ingest",
    "evidence_from_sweep", "evidence_from_schema_dir", "evidence_from_legacy_matrix",
    "backfill", "products", "builds", "endpoints_at", "fields_at", "compare",
    "field_history", "resolve_appliance", "matrix_doc",
]
