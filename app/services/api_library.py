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
#: The CLI channel. ``cli_tree`` is the schema the appliance's ``tree`` command
#: prints (objects, fields, types, options, CLI ids); ``cli_full`` is the field
#: NAMES ``show full-configuration`` reveals per object, hidden fields included.
#: Keyed by the canonical REST path without prefix (:func:`urn_key`), never by
#: a registry name. Never values (pack rule 1), except ``default`` on lab
#: evidence (``summary.lab``).
SOURCE_CLI_TREE = "cli_tree"
SOURCE_CLI_FULL = "cli_full"
CLI_SOURCES = (SOURCE_CLI_TREE, SOURCE_CLI_FULL)
SOURCES = (SOURCE_SWEEP, SOURCE_SCHEMA, SOURCE_VENDOR, SOURCE_MANUAL, SOURCE_LEGACY,
           SOURCE_CLI_TREE, SOURCE_CLI_FULL)
#: The REST channel: everything a REST answer (or a claim about one) produced.
#: Every REST reader below (``endpoints_at``, ``fields_at``, the REST half of
#: ``compare``, ``matrix_doc``, ``builds().measured``) reads ONLY these. A CLI
#: object is not a REST endpoint: folding ``cli_tree`` into those answers
#: would let a baseline promotion register every CLI path as a served URN.
REST_SOURCES = tuple(s for s in SOURCES if s not in CLI_SOURCES)
#: Which source speaks first when two describe the same thing. A sweep of a
#: real box outranks everything; vendor data is last by rule 4. The CLI sources
#: are measurements of a real box too, so they come right after sweep/schema.
SOURCE_PRIORITY = (SOURCE_SWEEP, SOURCE_SCHEMA, SOURCE_CLI_TREE, SOURCE_CLI_FULL,
                   SOURCE_MANUAL, SOURCE_LEGACY, SOURCE_VENDOR)

#: Keys a field's ``attrs`` may carry (contract §3 of the 2.13 brief).
FIELD_ATTR_KEYS = ("cli_id", "hidden", "range", "help", "cli_type", "datasource",
                   "lab_default")

#: Channel classification of one field on one build (:func:`channels_at`).
CH_BOTH = "both"
CH_CLI_ONLY = "cli_only"
CH_HIDDEN = "hidden"
CH_REST_ONLY = "rest_only"
CH_UNKNOWN = "unknown"
#: REST bookkeeping a row carries that is not configuration (:data:`REST_META`).
#: Reported so nothing is hidden, never counted toward completeness.
CH_META = "meta"
CHANNELS = (CH_BOTH, CH_CLI_ONLY, CH_HIDDEN, CH_REST_ONLY, CH_UNKNOWN, CH_META)
#: The only reasons an endpoint may be left out of "complete". Named, so an
#: exception is a statement somebody made, not a hole nobody looked at.
EXCEPTION_REASONS = {
    "licence": "the object cannot be read or filled without a licence the lab box lacks",
    "status-object": "a runtime status object: it has no configuration rows to reveal fields",
}

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


_URN_VERSION_RE = re.compile(r"^v\d+(?:\.\d+)?/")


def urn_key(urn) -> str:
    """The canonical REST path of a URN, without prefix, query or slashes.

    ``/api/v2.0/cmdb/system/ntp/ntpserver?mkey=x`` -> ``system/ntp/ntpserver``;
    ``/api/v2/cmdb/firewall/policy`` -> ``firewall/policy``;
    ``/api/load_balance_virtual_server`` -> ``load_balance_virtual_server``.
    An already-normalised key is returned unchanged. This is the ONE join
    between the REST channel (sweep evidence keyed by registry names, carrying
    a URN) and the CLI channel (keyed by this path).
    """
    u = str(urn or "").strip().split("#", 1)[0].split("?", 1)[0].strip("/")
    if u.startswith("api/"):
        u = u[4:]
        u = _URN_VERSION_RE.sub("", u, count=1)
        if u.startswith("cmdb/"):
            u = u[5:]
    return u.strip("/")


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
    if doc.get("source") in CLI_SOURCES:
        _validate_cli(doc)


#: What a ``cli_full`` field spec may hold. Names (the key) and channel
#: metadata — never a value read off a configuration.
_CLI_FULL_SPEC_KEYS = frozenset({"attrs", "type"})


def _validate_cli(doc: dict) -> None:
    """Contract rules of the CLI sources, enforced at the only writer.

    * one box, one build: a CLI dump is never line- or range-scoped;
    * the endpoint key IS the canonical REST path (``urn_key``), so the join to
      the REST channel needs no registry and cannot drift;
    * ``cli_full`` carries field NAMES only. A ``default`` is accepted only on
      lab evidence (``summary.lab``: a fresh lab row's value is the default);
      anything else that looks like a value is refused, because a value from a
      production box is configuration and pack rule 1 forbids shipping it.
    """
    source = doc["source"]
    scope = doc.get("scope") or {}
    if scope.get("kind", "build") != "build":
        raise ValueError("%s evidence must be build-scoped (one box, one build)" % source)
    lab = bool((doc.get("summary") or {}).get("lab"))
    for key, info in (doc.get("endpoints") or {}).items():
        k = str(key or "")
        if not k or k != urn_key(k):
            raise ValueError("%s endpoint key %r is not a canonical REST path" % (source, key))
        info = info if isinstance(info, dict) else {}
        if info.get("urn") and urn_key(info["urn"]) != k:
            raise ValueError("%s endpoint %r carries urn %r of another path"
                             % (source, key, info["urn"]))
        if source != SOURCE_CLI_FULL:
            continue
        for fname, spec in (info.get("fields") or {}).items():
            spec = spec if isinstance(spec, dict) else {}
            extra = set(spec) - _CLI_FULL_SPEC_KEYS - ({"default"} if lab else set())
            if extra:
                raise ValueError("cli_full field %s.%s carries %s: cli_full holds names, "
                                 "never values" % (k, fname, ", ".join(sorted(extra))))
            attrs = spec.get("attrs") or {}
            if not isinstance(attrs, dict) or (attrs.get("lab_default") and not lab):
                raise ValueError("cli_full field %s.%s: lab_default needs summary.lab"
                                 % (k, fname))


def _clean_attrs(attrs) -> dict | None:
    """A JSON-safe copy of an ``attrs`` dict, or None when there is nothing."""
    if not isinstance(attrs, dict) or not attrs:
        return None
    out = {}
    for k, v in attrs.items():
        if v is None:
            continue
        if isinstance(v, tuple):
            v = list(v)
        out[str(k)] = v
    return out or None


def _merge_attrs(old, new) -> dict | None:
    """Newest non-empty description wins per key, like the other fact columns."""
    new = _clean_attrs(new)
    if not new:
        return old
    merged = dict(old or {})
    merged.update(new)
    return merged


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
        ep_attrs = _clean_attrs(info.get("attrs"))
        f = existing.get(eid)
        if f is None:
            new_rows.append({
                "endpoint_id": eid, "build_id": build.id, "source": source,
                "urn": str(info.get("urn") or "")[:255],
                "section": str(info.get("section") or "")[:128],
                "verdict": verdict, "fields_known": known, "witnesses": wits,
                "attrs": ep_attrs,
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
        if ep_attrs:
            f.attrs = _merge_attrs(f.attrs, ep_attrs)
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
        # Channel metadata (cli_id, hidden, range, ...) rides in its own column.
        extra = _clean_attrs(spec.get("attrs"))
        ff = fexisting.get(fid)
        if ff is None:
            fnew.append({"field_id": fid, "build_id": build.id, "source": source,
                         **attrs, "attrs": extra,
                         "platforms": [platform] if platform else [],
                         "first_evidence_id": ev.id, "last_evidence_id": ev.id,
                         "first_seen": seen, "last_seen": seen})
            continue
        # Newest non-empty description wins; platforms accumulate.
        for k, v in attrs.items():
            if v is not None:
                setattr(ff, k, v)
        if extra:
            ff.attrs = _merge_attrs(ff.attrs, extra)
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


def _point_state(build_ids, endpoint=None, with_fields=True, sources=None) -> dict:
    """``{build_id: {endpoint: {source: rec}}}`` from folded facts.

    ``sources`` defaults to the REST channel (:data:`REST_SOURCES`): every
    pre-existing reader answers a REST question, and a CLI object is not a REST
    endpoint. :func:`channels_at` asks for both channels explicitly.
    """
    out: dict = {}
    build_ids = list(build_ids)
    if not build_ids:
        return out
    sources = tuple(REST_SOURCES if sources is None else sources)
    for chunk in _chunks(build_ids):
        q = (select(ApiLibEndpointFact, ApiLibEndpoint.name)
             .join(ApiLibEndpoint, ApiLibEndpoint.id == ApiLibEndpointFact.endpoint_id)
             .where(ApiLibEndpointFact.build_id.in_(chunk),
                    ApiLibEndpointFact.source.in_(sources)))
        if endpoint is not None:
            q = q.where(ApiLibEndpoint.name == endpoint)
        for f, name in db.session.execute(q):
            out.setdefault(f.build_id, {}).setdefault(name, {})[f.source] = {
                "verdict": f.verdict, "urn": f.urn or "", "section": f.section or "",
                "fields_known": bool(f.fields_known), "witnesses": list(f.witnesses or []),
                "first_seen": f.first_seen, "last_seen": f.last_seen,
                "evidence_ids": sorted({f.first_evidence_id, f.last_evidence_id} - {None}),
                "attrs": dict(f.attrs or {}),
                "fields": {} if f.fields_known else None,
            }
    if not with_fields:
        return out
    for chunk in _chunks(build_ids):
        q = (select(ApiLibFieldFact, ApiLibField.name, ApiLibEndpoint.name)
             .join(ApiLibField, ApiLibField.id == ApiLibFieldFact.field_id)
             .join(ApiLibEndpoint, ApiLibEndpoint.id == ApiLibField.endpoint_id)
             .where(ApiLibFieldFact.build_id.in_(chunk),
                    ApiLibFieldFact.source.in_(sources)))
        if endpoint is not None:
            q = q.where(ApiLibEndpoint.name == endpoint)
        for ff, fname, ename in db.session.execute(q):
            rec = out.get(ff.build_id, {}).get(ename, {}).get(ff.source)
            if rec is None or rec["fields"] is None:
                continue
            spec = {
                "type": ff.type, "options": ff.options, "default": ff.default,
                "required": ff.required, "children": ff.children,
                "platforms": list(ff.platforms or []),
            }
            if ff.attrs:
                spec["attrs"] = dict(ff.attrs)
            if ff.source in CLI_SOURCES:
                spec["evidence_ids"] = sorted({ff.first_evidence_id, ff.last_evidence_id}
                                              - {None})
            rec["fields"][fname] = spec
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
    point_measured, cli_measured = set(), set()
    for bid, source in db.session.execute(
            select(ApiLibEndpointFact.build_id, ApiLibEndpointFact.source).distinct()
            .where(ApiLibEndpointFact.build_id.in_(list(by_id) or [-1]))):
        # "measured" stays a REST statement: a build known only from its CLI
        # schema has not been asked what its REST API serves.
        (cli_measured if source in CLI_SOURCES else point_measured).add(bid)
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
            "cli_measured": b is not None and b.id in cli_measured,
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
        # The CLI channel, reported beside the REST answer above and never
        # mixed into it (fields compare only within one kind of evidence).
        "channels": _cli_compare(product, base, target, endpoint, rows=(bb, tb)),
    }


def _channel_twins(product: str, ep) -> list:
    """Endpoint rows that describe the SAME REST path as ``ep`` on the other
    channel: a registry name (REST) and its ``urn_key`` (CLI) are two rows."""
    keys = {urn_key(u) for (u,) in db.session.execute(
        select(ApiLibEndpointFact.urn).distinct().where(
            ApiLibEndpointFact.endpoint_id == ep.id)) if u}
    if "/" in ep.name or ep.name == urn_key(ep.name):
        keys.add(urn_key(ep.name))
    keys.discard("")
    if not keys:
        return []
    twins = {e.id: e for e in ApiLibEndpoint.query.filter(
        ApiLibEndpoint.product == product, ApiLibEndpoint.name.in_(sorted(keys))).all()}
    # REST rows named by the registry whose URN maps onto one of the keys.
    for eid, urn in db.session.execute(
            select(ApiLibEndpointFact.endpoint_id, ApiLibEndpointFact.urn).distinct()
            .join(ApiLibEndpoint, ApiLibEndpoint.id == ApiLibEndpointFact.endpoint_id)
            .where(ApiLibEndpoint.product == product, ApiLibEndpointFact.urn != "")):
        if eid not in twins and urn_key(urn) in keys:
            twins[eid] = db.session.get(ApiLibEndpoint, eid)
    twins.pop(ep.id, None)
    return [t for t in twins.values() if t is not None]


def field_history(product: str, endpoint: str, field: str) -> dict:
    """Where ``endpoint.field`` was seen: builds, first/last, sources.

    Both channels: ``endpoint`` may be a registry name or a REST path, and the
    facts of its twin on the other channel (same :func:`urn_key`) are read too.
    Each build row says which channel saw it (``rest`` / ``cli``) and carries
    the fact's ``attrs`` (CLI id, hidden, range ...).
    """
    out = {"product": product, "endpoint": endpoint, "field": field, "known": False,
           "builds": [], "vendor_spans": [], "first_build": "", "last_build": "",
           "sources": [], "channels": []}
    ep = ApiLibEndpoint.query.filter_by(product=product, name=endpoint).first()
    eps = ([ep] + _channel_twins(product, ep)) if ep is not None else []
    if ep is None and endpoint:
        # A REST path whose CLI row is named by it, or whose REST row is not.
        ep = ApiLibEndpoint.query.filter_by(product=product, name=urn_key(endpoint)).first()
        eps = ([ep] + _channel_twins(product, ep)) if ep is not None else []
    fids = []
    for e in eps:
        fr = ApiLibField.query.filter_by(endpoint_id=e.id, name=field).first()
        if fr is not None:
            fids.append(fr)
    f = next((x for x in fids if ep is not None and x.endpoint_id == ep.id), None) \
        or (fids[0] if fids else None)
    if f is None:
        return out
    out["known"] = True
    seen: dict = {}
    sources = set()
    channels = set()
    for ff, version, key in db.session.execute(
            select(ApiLibFieldFact, ApiLibBuild.version, ApiLibBuild.sort_key)
            .join(ApiLibBuild, ApiLibBuild.id == ApiLibFieldFact.build_id)
            .where(ApiLibFieldFact.field_id.in_([x.id for x in fids]))):
        channel = "cli" if ff.source in CLI_SOURCES else "rest"
        out["builds"].append({"version": version, "source": ff.source, "type": ff.type,
                              "channel": channel, "attrs": dict(ff.attrs or {}),
                              "first_seen": _iso(ff.first_seen),
                              "last_seen": _iso(ff.last_seen)})
        seen[key] = version
        sources.add(ff.source)
        channels.add(channel)
    spans = db.session.execute(
        select(ApiLibSpan.from_version, ApiLibSpan.to_version, ApiLibSpan.from_key,
               ApiLibSpan.to_key, ApiLibEvidence.summary, ApiLibEvidence.origin_ref)
        .join(ApiLibEvidence, ApiLibEvidence.id == ApiLibSpan.evidence_id)
        .where(ApiLibSpan.field_id.in_([x.id for x in fids]))).all()
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
    out["channels"] = sorted(channels | ({"rest"} if spans else set()))
    return out


# ---------------------------------------------------------------------------
# channels — the same build seen through REST and through the CLI
# ---------------------------------------------------------------------------

#: REST bookkeeping per product: keys a REST row carries that are not fields of
#: the object. :func:`channels_at` reports them as ``meta`` (never ``rest_only``,
#: never counted toward completeness).
#:
#: FortiWeb, measured 2026-10-07 (harvester pack kb-20261007: sweep of
#: fortiweb17 7.6.8 build1128 against the ``tree`` of the same build). Before
#: this rule ``channels_at`` reported 276 ``rest_only`` on 7.6.8: 107 ``id`` on
#: tables whose tree has no ``id``, 45 ``_id`` + 45 ``seq`` on subtables, 9
#: ``<NO.>``/``<No.>`` on sequence subtables (the tree types their real mkey
#: ``id`` as ``<NO.>``), and 70 vendor-doc names (see ``doc_conflict``). The
#: same rows carry ``q_type``/``q_ref``/``q_ref_string``, ``can_view``/
#: ``can_clone``, ``sz_<child>`` counters, ``<field>_val`` select companions and
#: ``sub_table_id``/``sub_table_action``; the lab found every OTHER REST key of
#: a served object in that build's tree (rest_only = 0 on 7.6.8 and 8.0.6).
#:
#: ``exact`` names compare case-insensitively. A name the build's CLI lists for
#: that object is a REAL field and never meta: 199 tables of 7.6.8 have the mkey
#: ``id`` (``<No.>`` sequence tables included). ``ambiguous`` names are real on
#: some objects, so without a measured tree they are not called meta at all.
#:
#: FortiGate / FortiADC / FortiAuthenticator / FortiAnalyzer: no REST row was
#: measured next to a tree yet (fgt02 cmdb answers 401 without a licence), so
#: no rule — a guess here would hide real fields.
REST_META = {
    "fortiweb": {
        "exact": frozenset({"id", "_id", "seq", "<no.>", "sub_table_id",
                            "sub_table_action"}),
        "pattern": re.compile(r"^(?:q_|sz_|can_)|_val$"),
        "ambiguous": frozenset({"id"}),
    },
}


def is_rest_meta(product: str, name: str, *, cli_lists: bool = False,
                 tree_measured: bool = True) -> bool:
    """Is ``name`` REST bookkeeping on ``product`` (see :data:`REST_META`)?

    ``cli_lists``: the build's CLI lists ``name`` for this object — then it is a
    real field whatever it looks like. ``tree_measured``: the build's ``tree``
    was read; without it an ``ambiguous`` name (``id``) cannot be told apart.
    """
    rule = REST_META.get(product)
    if rule is None or cli_lists:
        return False
    n = str(name or "")
    hit = n.lower() in rule["exact"] or bool(rule["pattern"].search(n))
    if hit and not tree_measured and n.lower() in rule["ambiguous"]:
        return False
    return hit


_YES, _NO, _UNK = "yes", "no", "unknown"


def _cli_evidence(build_id) -> dict:
    """``{source: [summary, ...]}`` of HEALTHY CLI and sweep evidence on a build.

    A ``cli_tree`` row on the build is what lets the CLI side say "no": the
    tree prints the whole schema, so a field it does not print is not there.
    Summaries also carry named completeness exceptions (``summary.exceptions``).
    """
    out: dict = {}
    if build_id is None:
        return out
    for source, summ in db.session.execute(
            select(ApiLibEvidence.source, ApiLibEvidence.summary).where(
                ApiLibEvidence.build_id == build_id,
                ApiLibEvidence.healthy.is_(True),
                ApiLibEvidence.scope_kind == "build")):
        out.setdefault(source, []).append(summ or {})
    return out


def _cli_objects(evidence: dict) -> dict:
    """``{key: {cli_path, kind, mkey, parent, cli_id}}`` from the build's CLI
    evidence summaries (contract: ``summary.objects``), ``cli_tree`` first.

    A pack may carry the object metadata ONLY there (the harvester's endpoints
    have no ``attrs``): reading it is what gives an object its ``cli_id`` and
    its mkey, which the rename candidates and the meta rule need.
    """
    out: dict = {}
    for source in (SOURCE_CLI_FULL, SOURCE_CLI_TREE):     # tree last = tree wins
        for summ in evidence.get(source) or []:
            for key, meta in ((summ or {}).get("objects") or {}).items():
                if isinstance(meta, dict):
                    out.setdefault(key, {}).update(
                        {k: v for k, v in meta.items() if v is not None})
    return out


def _with_object_meta(rec, meta):
    """``rec`` (a point-state record) whose ``attrs`` are completed from the
    evidence summary's object metadata; the fact's own attrs win per key."""
    if rec is None or not meta:
        return rec
    return {**rec, "attrs": {**meta, **(rec.get("attrs") or {})}}


def _resolve_key(endpoint, rest_names: dict) -> str:
    """An endpoint argument (registry name or REST path) -> channel key."""
    if not endpoint:
        return ""
    for key, names in rest_names.items():
        if endpoint in names:
            return key
    return urn_key(endpoint)


def _channel_view(product: str, version) -> dict:
    """Both channels of one build, joined on :func:`urn_key`.

    ``{"build", "keys": {key: {"rest": {...}, "tree": rec|None, "full": rec|None,
    "rest_names": [...]}}, "tree_measured", "evidence", "unjoined"}``.
    """
    v = fv.normalize(version)
    b = _build_row(product, v) if v else None
    point = _point_state([b.id], with_fields=True, sources=SOURCES).get(b.id, {}) if b else {}
    vendor = _vendor_state(product, version_key(v), None, True) if v else {}
    evidence = _cli_evidence(b.id if b else None)
    objects = _cli_objects(evidence)

    cli_keys = {name for name, by_src in point.items()
                if any(s in CLI_SOURCES for s in by_src)}
    keys: dict = {}
    unjoined = []

    def _slot(key):
        return keys.setdefault(key, {"rest": None, "tree": None, "full": None,
                                     "rest_names": []})

    rest_names = set(point) | set(vendor)
    for name in sorted(rest_names):
        by_src = {s: r for s, r in (point.get(name) or {}).items() if s in REST_SOURCES}
        by_src.update(vendor.get(name) or {})
        if not by_src:
            continue
        pool = _pool(by_src)
        urn = next((by_src[s]["urn"] for s in _ordered_sources(by_src) if by_src[s]["urn"]), "")
        key = urn_key(urn) if urn else (name if name in cli_keys else "")
        if not key:
            unjoined.append(name)
            continue
        verdict = _best_verdict(r["verdict"] for r in pool.values())
        knowing = [s for s in _ordered_sources(pool)
                   if pool[s]["verdict"] == VERDICT_OK and pool[s]["fields_known"]]
        fields = None
        if knowing:
            fields = {}
            for s in knowing:
                for fname in pool[s]["fields"] or {}:
                    fields.setdefault(fname, set()).add(s)
        ev_ids = sorted({i for r in pool.values() for i in r["evidence_ids"]})
        slot = _slot(key)
        slot["rest_names"].append(name)
        cur = slot["rest"]
        if cur is None:
            slot["rest"] = {"verdict": verdict, "fields": fields, "urn": urn,
                            "sources": _ordered_sources(pool), "evidence_ids": ev_ids}
        else:
            # Two registry names for one path (aliases): read together.
            cur["verdict"] = _best_verdict([cur["verdict"], verdict])
            if fields is not None:
                merged = dict(cur["fields"] or {})
                for f, srcs in fields.items():
                    merged.setdefault(f, set()).update(srcs)
                cur["fields"] = merged
            cur["sources"] = _ordered_sources(set(cur["sources"]) | set(pool))
            cur["evidence_ids"] = sorted(set(cur["evidence_ids"]) | set(ev_ids))
    for name in sorted(cli_keys):
        by_src = point.get(name) or {}
        slot = _slot(name)
        slot["tree"] = _with_object_meta(by_src.get(SOURCE_CLI_TREE), objects.get(name))
        slot["full"] = _with_object_meta(by_src.get(SOURCE_CLI_FULL), objects.get(name))
    return {"build": b, "version": v, "keys": keys, "evidence": evidence,
            "tree_measured": bool(evidence.get(SOURCE_CLI_TREE)),
            "rest_measured": any(s in evidence for s in (SOURCE_SWEEP, SOURCE_SCHEMA,
                                                         SOURCE_MANUAL, SOURCE_LEGACY)),
            "unjoined": unjoined}


def _rest_status(rest, fname) -> str:
    if rest is None:
        return _UNK
    if rest["verdict"] == VERDICT_ABSENT:
        return _NO
    if rest["verdict"] != VERDICT_OK or rest["fields"] is None:
        return _UNK            # blind or only errors: the build was not shown
    return _YES if fname in rest["fields"] else _NO


def _classify(rest_st: str, cli_st: str, hidden: bool) -> str:
    if rest_st == _YES and cli_st == _YES:
        return CH_BOTH
    if cli_st == _YES and rest_st == _NO:
        return CH_HIDDEN if hidden else CH_CLI_ONLY
    if rest_st == _YES and cli_st == _NO:
        return CH_REST_ONLY
    return CH_UNKNOWN


def _exceptions_of(view: dict, extra) -> tuple[dict, list]:
    """``({key: reason}, rejected)`` — named exceptions from the evidence
    summaries of the build plus the caller's. Only :data:`EXCEPTION_REASONS`."""
    wanted: dict = {}
    for summaries in view["evidence"].values():
        for summ in summaries:
            for k, why in (summ.get("exceptions") or {}).items():
                wanted.setdefault(urn_key(k), why)
    for k, why in (extra or {}).items():
        wanted[urn_key(k)] = why
    ok, rejected = {}, []
    for k, why in wanted.items():
        if why in EXCEPTION_REASONS:
            ok[k] = why
        else:
            rejected.append({"endpoint": k, "reason": why})
    return ok, rejected


def channels_at(product: str, version, endpoint=None, exceptions=None) -> dict:
    """Per field of one build: is it served by REST, by the CLI, by both?

    Derived on every call, never stored. Each field gets a ``channel``:

    * ``both``       — REST revealed it and the CLI has it;
    * ``cli_only``   — the CLI has it (``tree``) and REST, which revealed the
      endpoint's fields or measured it absent, does not;
    * ``hidden``     — like ``cli_only``, but only ``show full-configuration``
      prints it: the build's ``tree`` does not list it;
    * ``rest_only``  — REST revealed it and the build's ``tree`` does not list it;
    * ``unknown``    — one of the two channels never answered for it on THIS
      build (no tree, a blind endpoint, an unmeasured build). Never a "no".
      A name only the vendor documentation gives REST, on a build whose
      measured ``tree`` does not list it, is ``unknown`` with
      ``doc_conflict: True``: documentation is not a REST measurement, and a
      measured "no" from the CLI beats it (local measurement wins);
    * ``meta``       — REST bookkeeping (:data:`REST_META`: ``_id``, ``seq``,
      ``q_type`` ...), reported and never counted toward completeness. A name
      the build's CLI lists for the object (a table whose mkey is ``id``) is a
      real field, never meta.

    Every field carries ``rest`` / ``cli`` (``yes|no|unknown``) and the evidence
    ids behind it. ``summary.complete`` is True when nothing is ``unknown``
    outside the named exceptions (:data:`EXCEPTION_REASONS`): from evidence
    summaries (``summary.exceptions``) or ``exceptions={key: reason}``.

    ``endpoint`` filters to one REST path or one registry name.
    """
    view = _channel_view(product, version)
    excepted, rejected = _exceptions_of(view, exceptions)
    rest_names = {k: s["rest_names"] for k, s in view["keys"].items()}
    only = _resolve_key(endpoint, rest_names) if endpoint else ""
    tree_measured = view["tree_measured"]

    out_eps: dict = {}
    counts = {c: 0 for c in CHANNELS}
    excepted_unknown = doc_conflicts = 0
    exc_report: dict = {}
    for key in sorted(view["keys"]):
        if only and key != only:
            continue
        slot = view["keys"][key]
        rest, tree, full = slot["rest"], slot["tree"], slot["full"]
        tree_fields = (tree or {}).get("fields") or {}
        full_fields = (full or {}).get("fields") or {}
        rest_fields = (rest or {}).get("fields") or {}
        names = set(rest_fields) | set(tree_fields) | set(full_fields)
        fields = {}
        mkey = ((tree or {}).get("attrs") or {}).get("mkey") or ""
        doc_only = rest is not None and set(rest.get("sources") or []) <= {SOURCE_VENDOR}
        for fname in sorted(names):
            in_tree, in_full = fname in tree_fields, fname in full_fields
            r_st = _rest_status(rest, fname)
            r_srcs = sorted(rest_fields.get(fname) or ())
            if in_tree or in_full:
                c_st = _YES
            elif tree_measured:
                c_st = _NO
            else:
                c_st = _UNK
            attrs = dict((tree_fields.get(fname) or {}).get("attrs") or {})
            attrs.update((full_fields.get(fname) or {}).get("attrs") or {})
            hidden = bool(in_full and ((tree_measured and not in_tree) or attrs.get("hidden")))
            if hidden:
                attrs["hidden"] = True
            ch = _classify(r_st, c_st, hidden)
            conflict = False
            if r_st == _YES and is_rest_meta(product, fname,
                                             cli_lists=in_tree or in_full or fname == mkey,
                                             tree_measured=tree_measured):
                ch = CH_META
            elif r_st == _YES and c_st == _NO and set(r_srcs) <= {SOURCE_VENDOR}:
                # Documented for REST, never measured there, absent from a
                # measured tree: not "REST only", an open contradiction.
                r_st, ch, conflict = _UNK, CH_UNKNOWN, True
                doc_conflicts += 1
            ev = set()
            if r_st != _UNK and rest is not None:
                ev.update(rest["evidence_ids"])
            for spec in (tree_fields.get(fname), full_fields.get(fname)):
                ev.update((spec or {}).get("evidence_ids") or [])
            fields[fname] = {"channel": ch, "rest": r_st, "cli": c_st, "hidden": hidden,
                             "in_tree": in_tree, "in_full": in_full,
                             "rest_sources": r_srcs, "doc_conflict": conflict,
                             "attrs": attrs, "evidence_ids": sorted(ev)}
            if key in excepted and ch == CH_UNKNOWN:
                excepted_unknown += 1
                exc_report.setdefault(key, 0)
                exc_report[key] += 1
            else:
                counts[ch] += 1
        r_verdict = rest["verdict"] if rest else None
        cli_has = tree is not None or full is not None
        if r_verdict == VERDICT_OK and cli_has:
            ep_ch = CH_BOTH
        elif r_verdict == VERDICT_ABSENT and cli_has:
            ep_ch = CH_CLI_ONLY
        elif r_verdict == VERDICT_OK and tree_measured and not cli_has and not doc_only:
            ep_ch = CH_REST_ONLY
        else:
            ep_ch = CH_UNKNOWN
        ep_conflict = bool(r_verdict == VERDICT_OK and tree_measured and not cli_has
                           and doc_only)
        ep_attrs = dict((tree or {}).get("attrs") or {})
        ep_attrs.update((full or {}).get("attrs") or {})
        out_eps[key] = {
            "endpoint": key, "channel": ep_ch,
            "urn": (rest or {}).get("urn") or "", "rest_names": sorted(slot["rest_names"]),
            "rest_verdict": r_verdict, "rest_fields_known": bool(rest and rest["fields"] is not None),
            "rest_sources": (rest or {}).get("sources") or [],
            "cli_tree": tree is not None, "cli_full": full is not None,
            "attrs": ep_attrs, "exception": excepted.get(key, ""),
            "doc_conflict": ep_conflict,
            "fields": fields,
        }
    total = sum(n for c, n in counts.items() if c != CH_META)
    summary = dict(counts)
    summary.update({
        "fields": total, "endpoints": len(out_eps),
        "excepted_unknown": excepted_unknown, "doc_conflicts": doc_conflicts,
        "exceptions": [{"endpoint": k, "reason": excepted[k],
                        "why": EXCEPTION_REASONS[excepted[k]], "unknown": n}
                       for k, n in sorted(exc_report.items())],
        "rejected_exceptions": rejected,
        "tree_measured": tree_measured, "rest_measured": view["rest_measured"],
        "unjoined_rest": len(view["unjoined"]),
        # Complete = both channels measured and nothing left unknown outside
        # a named exception. An empty build is not complete: nothing was asked.
        "complete": bool(total and counts[CH_UNKNOWN] == 0
                         and tree_measured and view["rest_measured"]),
    })
    return {"product": product, "version": view["version"],
            "build": _build_dict(view["build"]), "endpoints": out_eps,
            "summary": summary}


def _tree_specs(product: str, version, only: str = "") -> tuple[bool, dict]:
    """``(measured, {key: {"attrs", "fields": {name: spec}}})`` from cli_tree,
    with lab defaults (cli_full on lab evidence) folded in as ``default``."""
    v = fv.normalize(version)
    b = _build_row(product, v) if v else None
    if b is None:
        return False, {}
    st = _point_state([b.id], only or None, True,
                      sources=(SOURCE_CLI_TREE, SOURCE_CLI_FULL)).get(b.id, {})
    evidence = _cli_evidence(b.id)
    measured = bool(evidence.get(SOURCE_CLI_TREE))
    objects = _cli_objects(evidence)
    out: dict = {}
    for key, by_src in st.items():
        tree = _with_object_meta(by_src.get(SOURCE_CLI_TREE), objects.get(key))
        if tree is None:
            continue
        fields = {k: dict(s) for k, s in (tree.get("fields") or {}).items()}
        full = by_src.get(SOURCE_CLI_FULL) or {}
        for fname, spec in (full.get("fields") or {}).items():
            if fname in fields and (spec.get("attrs") or {}).get("lab_default") \
                    and spec.get("default") is not None:
                fields[fname]["default"] = spec["default"]
        out[key] = {"attrs": tree.get("attrs") or {}, "fields": fields}
    return measured, out


def _has_cli(b) -> bool:
    """Any healthy CLI evidence on build row ``b`` (None: no row, no evidence)."""
    if b is None:
        return False
    return db.session.execute(select(ApiLibEvidence.id).where(
        ApiLibEvidence.build_id == b.id, ApiLibEvidence.source.in_(CLI_SOURCES),
        ApiLibEvidence.healthy.is_(True)).limit(1)).first() is not None


def _cli_compare(product: str, base, target, endpoint=None, rows=None) -> dict:
    """The CLI half of :func:`compare`: channel moves + like-for-like ``tree``.

    Rename CANDIDATES (same CLI attribute id, different name) are reported and
    never applied: ``api_lib_field_map`` stays the only authority for a rename.
    """
    rb, rt = rows if rows is not None else (_build_row(product, base),
                                             _build_row(product, target))
    if not (_has_cli(rb) or _has_cli(rt)):
        # No CLI evidence on either build: every channel would read unknown.
        return {"base_tree": False, "target_tree": False, "channel_moves": [],
                "channel_unknown": 0, "tree": None,
                "tree_reason": "no CLI evidence on %s or %s"
                               % (fv.normalize(base), fv.normalize(target))}
    ca = channels_at(product, base, endpoint)
    cb = channels_at(product, target, endpoint)
    moves = []
    unknown = 0

    def _side(view, ep, f):
        """The channel label of ``f`` on one side, ``absent`` when BOTH channels
        of that side measured it missing, ``unknown`` when either did not ask."""
        if ep is not None and f in ep["fields"]:
            return ep["fields"][f]["channel"]
        if ep is None:
            r_st = _UNK          # REST never asked this build about the path
        elif ep["rest_verdict"] == VERDICT_ABSENT:
            r_st = _NO
        elif ep["rest_verdict"] == VERDICT_OK and ep["rest_fields_known"]:
            r_st = _NO
        else:
            r_st = _UNK
        c_st = _NO if view["summary"]["tree_measured"] else _UNK
        return "absent" if (r_st, c_st) == (_NO, _NO) else _classify(r_st, c_st, False)

    for key in sorted(set(ca["endpoints"]) | set(cb["endpoints"])):
        ea, eb = ca["endpoints"].get(key), cb["endpoints"].get(key)
        names = set((ea or {}).get("fields") or {}) | set((eb or {}).get("fields") or {})
        for f in sorted(names):
            a, b = _side(ca, ea, f), _side(cb, eb, f)
            if a == b:
                continue
            if CH_UNKNOWN in (a, b):
                unknown += 1
                continue
            moves.append({"endpoint": key, "field": f, "base": a, "target": b})

    ma, ta = _tree_specs(product, base)
    mb, tb = _tree_specs(product, target)
    only = _resolve_key(endpoint, {k: e["rest_names"] for k, e in
                                   list(ca["endpoints"].items()) + list(cb["endpoints"].items())}
                        ) if endpoint else ""
    if only:
        ta = {k: v for k, v in ta.items() if k == only}
        tb = {k: v for k, v in tb.items() if k == only}
    out = {"base_tree": ma, "target_tree": mb, "channel_moves": moves,
           "channel_unknown": unknown, "tree": None}
    if not (ma and mb):
        out["tree_reason"] = ("no cli_tree evidence on %s" % " and ".join(
            x for x, m in ((fv.normalize(base), ma), (fv.normalize(target), mb)) if not m))
    else:
        renames = _renames(product, sorted(set(ta) & set(tb)), str(base), str(target))
        ep_added = sorted(set(tb) - set(ta))
        ep_removed = sorted(set(ta) - set(tb))
        ep_renames = []
        ids_b = {tb[k]["attrs"].get("cli_id"): k for k in ep_added
                 if tb[k]["attrs"].get("cli_id") is not None}
        for k in ep_removed:
            cid = ta[k]["attrs"].get("cli_id")
            if cid is not None and cid in ids_b:
                ep_renames.append({"from": k, "to": ids_b[cid], "cli_id": cid})
        per: dict = {}
        totals = {"fields_added": 0, "fields_removed": 0, "options_changed": 0,
                  "retyped": 0, "ranges_changed": 0, "defaults_changed": 0,
                  "rename_candidates": 0}
        removed_ids: dict = {}     # cli_id -> (key, field) gone from its object
        added_ids: dict = {}       # cli_id -> (key, field) new in its object
        for key in sorted(set(ta) & set(tb)):
            fa, fb = ta[key]["fields"], tb[key]["fields"]
            added, removed = sorted(set(fb) - set(fa)), sorted(set(fa) - set(fb))
            options, retyped, ranges, defaults = [], [], [], []
            for f in sorted(set(fa) & set(fb)):
                sa, sb = fa[f], fb[f]
                oa, ob = set(sa.get("options") or []), set(sb.get("options") or [])
                if oa != ob and (oa or ob):
                    options.append({"field": f, "added": sorted(ob - oa),
                                    "removed": sorted(oa - ob)})
                ty_a = (sa.get("attrs") or {}).get("cli_type") or sa.get("type")
                ty_b = (sb.get("attrs") or {}).get("cli_type") or sb.get("type")
                if ty_a and ty_b and ty_a != ty_b:
                    retyped.append({"field": f, "from": ty_a, "to": ty_b})
                ra, rb = (sa.get("attrs") or {}).get("range"), (sb.get("attrs") or {}).get("range")
                if ra is not None and rb is not None and list(ra) != list(rb):
                    ranges.append({"field": f, "from": list(ra), "to": list(rb)})
                da, db_ = sa.get("default"), sb.get("default")
                if da is not None and db_ is not None and da != db_:
                    defaults.append({"field": f, "from": da, "to": db_})
            mapped = {(o, n) for o, n, _note in renames.get(key, [])}
            cands = []
            ids_added = {(fb[f].get("attrs") or {}).get("cli_id"): f for f in added
                         if (fb[f].get("attrs") or {}).get("cli_id") is not None}
            for f in removed:
                cid = (fa[f].get("attrs") or {}).get("cli_id")
                if cid is not None and cid in ids_added:
                    cands.append({"from": f, "to": ids_added[cid], "cli_id": cid,
                                  "mapped": (f, ids_added[cid]) in mapped})
            for f in removed:
                cid = (fa[f].get("attrs") or {}).get("cli_id")
                if cid is not None and cid not in ids_added:
                    removed_ids.setdefault(cid, (key, f))
            taken = {c["to"] for c in cands}
            for f in added:
                cid = (fb[f].get("attrs") or {}).get("cli_id")
                if cid is not None and f not in taken:
                    added_ids.setdefault(cid, (key, f))
            if added or removed or options or retyped or ranges or defaults or cands:
                per[key] = {"added": added, "removed": removed, "options": options,
                            "retyped": retyped, "ranges": ranges, "defaults": defaults,
                            "rename_candidates": cands}
                totals["fields_added"] += len(added)
                totals["fields_removed"] += len(removed)
                totals["options_changed"] += len(options)
                totals["retyped"] += len(retyped)
                totals["ranges_changed"] += len(ranges)
                totals["defaults_changed"] += len(defaults)
                totals["rename_candidates"] += len(cands)
        moves = _field_moves(ta, tb, ep_added, ep_removed, ep_renames,
                             removed_ids, added_ids)
        totals["endpoint_rename_candidates"] = len(ep_renames)
        totals["field_moves"] = len(moves)
        out["tree"] = {"endpoints_added": ep_added, "endpoints_removed": ep_removed,
                       "endpoint_rename_candidates": ep_renames,
                       "field_moves": moves,
                       "endpoints": per, "totals": totals}
    return out


def _field_moves(ta, tb, ep_added, ep_removed, ep_renames, removed_ids, added_ids) -> list:
    """Attributes whose CLI id left one object and reappears in ANOTHER.

    Two shapes, both measured on 7.6.8 -> 8.0.6 (lab compare_7.6.8_8.0.6.md):
    a renamed object takes its fields along (``allow-source-ip`` ->
    ``source-ip-list``, 9785/9786), and a field becomes an object or a field of
    a new subtable (``client-side-protection-policy url-type`` 6991 -> the
    table ``page-list``; ``url-pattern`` 6992 -> ``page-list.id``). Candidates,
    never applied: the CLI id is evidence, not an operator's rename.
    """
    gone = dict(removed_ids)
    for k in ep_removed:                      # fields of objects that went away
        for f, spec in ta[k]["fields"].items():
            cid = (spec.get("attrs") or {}).get("cli_id")
            if cid is not None:
                gone.setdefault(cid, (k, f))
    new = dict(added_ids)
    for k in ep_added:                        # fields and ids of new objects
        cid = tb[k]["attrs"].get("cli_id")
        if cid is not None:
            new.setdefault(cid, (k, None))
        for f, spec in tb[k]["fields"].items():
            fid = (spec.get("attrs") or {}).get("cli_id")
            if fid is not None:
                new.setdefault(fid, (k, f))
    renamed_eps = {(r["from"], r["to"]) for r in ep_renames}
    moves = []
    for cid in sorted(set(gone) & set(new)):
        (fk, ff), (tk, tf) = gone[cid], new[cid]
        if fk == tk:
            continue                          # same object: a field rename candidate
        moves.append({"from_endpoint": fk, "from_field": ff, "to_endpoint": tk,
                      "to_field": tf, "cli_id": cid,
                      "with_object": (fk, tk) in renamed_eps,
                      "becomes": "object" if tf is None else "field"})
    return moves


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
            ApiLibEndpointFact.build_id == b.id,
            ApiLibEndpointFact.source.in_(REST_SOURCES)).limit(1)).first() is not None
    vendor = bool(_vendor_candidates(product, version_key(v)))
    status = "measured" if point else "vendor_only" if vendor else "unmeasured"
    return {**out, "build": _build_dict(b), "status": status}


# ---------------------------------------------------------------------------
# matrix_doc — the api_matrix.build() shape, served from the library
# ---------------------------------------------------------------------------

_MATRIX_ORIGIN = {SOURCE_SWEEP: "sweep", SOURCE_SCHEMA: "schema", SOURCE_MANUAL: "manual",
                  SOURCE_LEGACY: "legacy_matrix", SOURCE_VENDOR: "vendor_doc",
                  SOURCE_CLI_TREE: "cli_tree", SOURCE_CLI_FULL: "cli_full"}


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

    # CLI-channel object counts per build. Reported beside the REST answer,
    # never merged into ``endpoints``: a CLI object is not a served URN.
    cli_counts: dict = {}
    for bid, source, n in db.session.execute(
            select(ApiLibEndpointFact.build_id, ApiLibEndpointFact.source, func.count())
            .where(ApiLibEndpointFact.build_id.in_(list(all_builds) or [-1]),
                   ApiLibEndpointFact.source.in_(CLI_SOURCES))
            .group_by(ApiLibEndpointFact.build_id, ApiLibEndpointFact.source)):
        cli_counts.setdefault(bid, {})[source] = n

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
            "cli": dict(cli_counts.get(b.id) or {}),
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
    "CLI_SOURCES", "REST_SOURCES", "SOURCE_CLI_TREE", "SOURCE_CLI_FULL",
    "CHANNELS", "EXCEPTION_REASONS", "FIELD_ATTR_KEYS", "urn_key", "channels_at",
    "version_key", "content_hash", "ingest",
    "evidence_from_sweep", "evidence_from_schema_dir", "evidence_from_legacy_matrix",
    "backfill", "products", "builds", "endpoints_at", "fields_at", "compare",
    "field_history", "resolve_appliance", "matrix_doc",
]
