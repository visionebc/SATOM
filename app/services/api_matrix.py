"""Firmware-keyed API matrix: what each firmware BUILD actually serves.

The problem this exists for: FortiWeb 7.6 and 8.0 speak the **same API
version** (``v2.0``). The registry's ``api_version`` axis therefore cannot
express the difference between them — and the difference is real: measured on
this fleet's own artifacts, ``admin`` has 40 fields on 7.6 and **42** on 8.0,
``global`` 60 vs **63**, ``ntp`` 3 vs **4**. Code that builds a payload from
one build and writes it to a box running another is the failure this module
is here to make visible BEFORE the write, not after the device rejects it.

The unit of knowledge is the **(product, firmware version, endpoint)** triple,
and the value is the set of field names that build was observed to serve. The
``major.minor`` line survives as a rollup that always declares which builds it
merged (``versions``, ``heterogeneous``, per endpoint ``attested_on`` /
``silent_on``).

Where the evidence lives
------------------------
In the database, in the append-only ``api_lib_*`` tables owned by
:mod:`app.services.api_library` (contract: ``docs/api-library.md``). Every
sweep snapshot, harvested field schema, vendor range and frozen legacy matrix
is stored there ONCE by ``api_library.ingest``; :func:`build` and :func:`load`
ask ``api_library.matrix_doc`` for the same document shape this module always
returned, so its consumers (``diff``, ``preflight``, ``version_compat``,
``absence_record``, ``cli_coverage``, the versions and structure pages) did
not have to change.

Why a table and not the file it used to be: the file was DERIVED and rewritten
wholesale on every rebuild, and the rebuild filtered its evidence through the
live appliance table. Deleting or retiring an appliance therefore deleted the
proof of what its firmware served — that is how the 8.0.3 build disappeared —
and a test run once overwrote the production matrix with an empty one. An
evidence row is never deleted and carries the device identity it was measured
on, so a retired device keeps its evidence and is listed in ``witnesses`` as
``retired`` instead of silently dropping out.

``rebuild`` still writes ``data/api_matrix/<product>.json``, as an EXPORT
only: the stdlib CLI (``deploy/satom_cli/cmd_apiver.py``) reads it on a node
whose venv or database is down. Nothing in the app reads it back.

Three rules the whole module is shaped around, each one a way this could
quietly lie instead of loudly not-knowing:

1. **``fields=None`` is not ``fields=[]``.** An endpoint that answered ``ok``
   with zero rows tells you the endpoint EXISTS and tells you NOTHING about
   its fields. Folding that into an empty set would make a build look like it
   "lost" every field of an empty collection — the diff against a populated
   build would invent dozens of removals that never happened.
2. **A build with no evidence is ``unmeasured``, never ``compatible``.** The
   preflight's default answer is "I don't know", because the caller's next
   action is a write to a real appliance.
3. **"Absent on the other build" requires the other build to have been
   measured.** Present-here/unknown-there is reported as unknown, never as
   removed.
"""
from __future__ import annotations

import json
import os
import re
import tempfile

from . import api_library as _lib

# ---------------------------------------------------------------------------
# paths — the EXPORT file, and the schema tree ``diff`` reads coverage from
# ---------------------------------------------------------------------------

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCHEMA_ROOT = os.path.join(_ROOT, "data", "field_schemas")

#: The in-tree location, kept as its own name so documentation guards can
#: assert where the export lives WITHOUT reading whatever a test run
#: redirected it to.
MATRIX_ROOT_DEFAULT = os.path.join(_ROOT, "data", "api_matrix")

# Redirected by env, resolved at IMPORT so the monkeypatch-the-constant tests
# keep working. The file is only an export now, but it is still the one the
# offline CLI trusts: a test run that wrote its fixture into the production
# path would have that CLI answer from fixtures (2026-09-15: a test sweep left
# ``swept: 0, devices: []`` where 326 endpoints had been).
MATRIX_ROOT = os.environ.get("SATOM_API_MATRIX_DIR") or MATRIX_ROOT_DEFAULT

# ---------------------------------------------------------------------------
# products — from the library, so a product the library learns is one list
# ---------------------------------------------------------------------------

PRODUCTS = _lib.PRODUCTS
CATALOG_ONLY_PRODUCTS = _lib.CATALOG_ONLY_PRODUCTS

# Kind string on ``Appliance`` per product key. Catalog-only products have no
# appliance rows (SATOM does not manage FortiGates), so they have no kind.
_KIND_FOR = {p: p for p in PRODUCTS if p not in CATALOG_ONLY_PRODUCTS}

# Products the rediscovery sweep walks (``rediscovery.plan_for`` has a plan
# for exactly these). FAZ and FAC are described by schema or vendor evidence
# only — stated here rather than discovered as an empty page.
SWEPT_PRODUCTS = tuple(p for p in _KIND_FOR if p in ("fortiweb", "fortiadc"))

# Same threshold as the library's healthy-evidence gate, re-exported so the
# docs guards and the page quote one number.
MAX_ERROR_RATIO = _lib.MAX_ERROR_RATIO

VERDICT_OK = _lib.VERDICT_OK
VERDICT_ABSENT = _lib.VERDICT_ABSENT
VERDICT_ERROR = _lib.VERDICT_ERROR


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def firmware_line(version: str | None) -> str:
    """``"7.6.8 build1128"`` → ``"7.6"``. Empty string when there is no version.

    Truncating to major.minor is what makes a rollup possible: a patch release
    is not a new line, and keying the rollup by the full string would give
    every build its own column of one-device evidence that never accumulates.
    """
    if not version:
        return ""
    m = re.search(r"(\d+)\.(\d+)", str(version))
    return f"{m.group(1)}.{m.group(2)}" if m else ""


def firmware_version(version: str | None) -> str:
    """``"8.0.3,build0123"`` → ``"8.0.3"``. The ATOMIC evidence key.

    Delegates to :func:`app.services.firmware_versions.normalize` so the app
    has exactly one definition of what a version string means. Two definitions
    is how ``8.0`` and ``8.0.0`` would end up as separate columns describing
    the same evidence.
    """
    from . import firmware_versions as fv
    return fv.normalize(version)


def resolve_scope(matrix: dict, scope: str) -> tuple:
    """``(doc, kind)`` for a version or line key. ``kind`` is the honest label.

    It NEVER falls back from one kind to the other. A caller that asked about
    ``8.0.3`` and silently got the ``8.0`` rollup is the bug this module spent
    a round removing: the rollup merges builds, and merging is what produced
    *"compatible"* for an endpoint the asking box does not serve.
    """
    if not scope:
        return None, None
    versions = matrix.get("versions") or {}
    lines = matrix.get("lines") or {}
    if scope in versions:
        return versions[scope], "version"
    if scope in lines:
        return lines[scope], "line"
    return None, None


def _write_json_atomic(path: str, payload) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(payload, fh, indent=1, sort_keys=True)
        # mkstemp hands back 0600. Every other artifact under data/ is 0644
        # and this one holds no secret — it is an export of endpoint names and
        # field names. A stated mode, not an inherited one, so a mode audit
        # does not turn up one odd file with no reason.
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def matrix_path(product: str) -> str:
    return os.path.join(MATRIX_ROOT, f"{product}.json")


# ---------------------------------------------------------------------------
# the live fleet — ``in_fleet`` and witness liveness, never an evidence filter
# ---------------------------------------------------------------------------

def _live_appliances(product: str) -> dict:
    """``{appliance_id: {"name","firmware","version","line"}}`` for live boxes.

    Used to say which builds the fleet runs TODAY (``in_fleet``) and which
    witnesses can still be re-probed. It no longer filters evidence: a box in
    maintenance, on a ``*.invalid`` host or deleted outright still measured
    what it measured, and the library keeps that evidence under the device
    identity recorded at the time.
    """
    from ..models import Appliance
    from . import firmware_versions as fv

    kind = _KIND_FOR.get(product)
    if not kind:
        return {}
    out: dict = {}
    for ap in Appliance.query.filter_by(kind=kind).all():
        if getattr(ap, "maintenance", False):
            continue
        if str(getattr(ap, "host", "") or "").endswith(".invalid"):
            continue
        raw = getattr(ap, "fw_version", "") or ap.firmware
        out[ap.id] = {"name": ap.name, "firmware": ap.firmware or "",
                      "version": fv.normalize(raw),
                      "line": firmware_line(raw)}
    return out


# ---------------------------------------------------------------------------
# build / load — read from the library; rebuild — the export
# ---------------------------------------------------------------------------

def _library_doc(product: str, versions=None) -> dict:
    """The one call into the library, so there is one place to read it from."""
    return _lib.matrix_doc(product, versions=versions)


def build(product: str, versions=None) -> dict:
    """The matrix for one product, from the API library. Writes nothing.

    Two axes come out of here and they are not the same kind of thing:

    * ``versions`` — the ATOMIC evidence, one bucket per full firmware version
      (``8.0.3``). Nothing is merged across builds.
    * ``lines`` — the ``major.minor`` ROLLUP, which always declares the
      ``versions`` it is made of, ``heterogeneous``, and per endpoint
      ``attested_on`` / ``silent_on``, so "8.0 serves this" can never be read
      as "every 8.0.x serves this".

    ``versions`` limits the version axis (and the rollups of their lines) to
    the builds named. Pass it for vendor-heavy products: the FortiGate
    catalogue is ~720 endpoints per build across dozens of builds, and the
    whole document is never what a page needs.

    Declarations are NOT baked in: they are authored rows, and
    ``firmware_versions.overlay`` merges them on read.
    """
    return _library_doc(product, versions=versions)


def load(product: str, versions=None) -> dict | None:
    """The matrix for ``product`` — ``None`` only when the library cannot answer.

    Never reads the export file. A cold or broken database answers ``None``
    rather than a stale file, because a stale file is exactly the store whose
    silent drift this replaced; callers already treat ``None`` as "no evidence".
    """
    try:
        return build(product, versions=versions)
    except Exception:  # noqa: BLE001 — a page must not 500 on a cold store
        from ..extensions import db
        db.session.rollback()
        return None


def rebuild(product: str) -> dict:
    """Write the export file from the library. Returns the matrix.

    An export, not a derivation: no evidence is read from disk and nothing is
    filtered, so running it can no longer lose a retired device's evidence.
    """
    matrix = build(product)
    _write_json_atomic(matrix_path(product), matrix)
    return matrix


def _scope_versions(product: str, scopes) -> list:
    """Every build an answer about ``scopes`` can depend on.

    Each named build, plus every build of its line: a line rollup is made of
    them, and a version-scoped ``preflight`` that finds no evidence of its own
    reports the line's answer beside its refusal.
    """
    from sqlalchemy import select

    from ..extensions import db
    from ..models_apilib import ApiLibBuild
    from . import firmware_versions as fv

    named = {fv.normalize(s) for s in scopes if fv.normalize(s)}
    lines = {fv.line_of(s) for s in named if fv.line_of(s)}
    if not lines:
        return sorted(named)
    same_line = {v for (v,) in db.session.execute(
        select(ApiLibBuild.version).where(ApiLibBuild.product == product,
                                          ApiLibBuild.line.in_(sorted(lines))))}
    return sorted(named | same_line, key=fv.sort_key)


def _load_for(product: str, *scopes) -> dict:
    """The matrix restricted to what an answer about ``scopes`` reads.

    Equivalent to the whole document for those scopes (see
    :func:`_scope_versions`), and it keeps a single preflight against a
    catalogue the size of FortiGate's from resolving every build it holds.
    """
    empty = {"lines": {}, "versions": {}}
    try:
        wanted = _scope_versions(product, scopes)
    except Exception:  # noqa: BLE001 — same contract as ``load``
        from ..extensions import db
        db.session.rollback()
        return empty
    if not wanted:
        # Nothing nameable was asked about. ``matrix_doc(versions=[])`` would
        # mean "every build", which is the opposite of what was asked.
        return empty
    return load(product, versions=wanted) or empty


# ---------------------------------------------------------------------------
# diff — the answer to "what does 8.0 add?"
# ---------------------------------------------------------------------------

#: ``bucket -> (label, is-it-a-change)``. It lives here, next to the code that
#: fills the buckets, because the CSV export, the PDF and now the row
#: cross-reference all name them — and three authors of one vocabulary is how a
#: label drifts out of step with the rule it describes.
#:
#: ``is a change`` is "yes" for exactly the three buckets where BOTH builds were
#: measured. The other three are gaps in the evidence; counted as changes they
#: become removals nobody ever measured.
BUCKET_LABEL = {
    "endpoints_added": ("endpoint added", "yes"),
    "endpoints_removed": ("endpoint gone", "yes"),
    "fields_changed": ("field delta", "yes"),
    "endpoints_unknown": ("endpoint measured on one side only", "no"),
    "fields_unknown": ("fields known on one side only", "no"),
    "fields_incomparable": ("incomparable", "no"),
}

ALL_BUCKETS = tuple(BUCKET_LABEL)

#: Order in which same-kind field deltas are reported for one key.
_ORIGIN_ORDER = ("schema", "sweep", "legacy_matrix", "manual", "vendor_doc")


def diff(product: str, base_line: str, target_line: str, matrix: dict | None = None) -> dict:
    """What ``target_line`` adds/removes relative to ``base_line``.

    Both arguments may name a full version (``8.0.3``) or a line (``8.0``);
    :func:`resolve_scope` decides which, and the answer reports ``base_kind`` /
    ``target_kind`` so a reader is never left guessing whether a difference was
    measured between two builds or between two merged rollups.

    Every bucket here is separated by WHY, because "8.0 has a field 7.6 does
    not" and "nobody ever measured that endpoint on 7.6" look identical in a
    naive set difference and mean opposite things to whoever is about to write
    a payload.
    """
    matrix = matrix or _load_for(product, base_line, target_line)
    a, a_kind = resolve_scope(matrix, base_line)
    b, b_kind = resolve_scope(matrix, target_line)
    a = a or {}
    b = b or {}
    a_eps, b_eps = a.get("endpoints") or {}, b.get("endpoints") or {}
    a_obj, b_obj = a.get("objects") or {}, b.get("objects") or {}

    def _served(rec):
        return bool(rec) and rec.get("verdict") == VERDICT_OK

    def _urn(key):
        """The REST path for a key, or ``""`` when the key is not an endpoint.

        The comparison renders ONE table since 2026-09-16, so a field-delta row
        now sits beside an endpoint row and offers the same Test button. That
        button needs a URN and only ENDPOINT evidence carries one: a key that
        reached this function from the harvested OBJECT schemas has no REST
        path of its own. It gets an empty string, which renders no button at
        all — fabricating a plausible path would put a control on the page that
        cannot work and, worse, would assert that the path exists.

        The target side is asked first: it is the build being written to.
        """
        for src in (b_eps, a_eps):
            rec = src.get(key)
            if rec and rec.get("urn"):
                return rec["urn"]
        return ""

    def _origin(*recs):
        """The evidence kind a record was BUILT with, never one inferred here.

        The comparison grows an *Evidence* column on 2026-09-16 and it has to
        answer for endpoint rows too, not only for field rows. The template
        must not be the one to decide: hardcoding ``sweep`` in its endpoint
        loops would print a kind for a record that never carried one, which is
        the same class of fabrication as inventing a URN for a schema object.
        Every endpoint record gets ``origin`` at build time (``"sweep"``) and
        every object record gets ``"schema"``; a record from an older matrix
        that carries neither yields ``""`` and the page says so rather than
        guessing.
        """
        for rec in recs:
            if rec and rec.get("origin"):
                return rec["origin"]
        return ""

    endpoints_added, endpoints_removed, endpoints_unknown = [], [], []
    for name in sorted(set(a_eps) | set(b_eps)):
        ra, rb = a_eps.get(name), b_eps.get(name)
        if ra is None or rb is None:
            # RULE 3: not measured on one side is UNKNOWN, not a change.
            endpoints_unknown.append({"endpoint": name, "urn": _urn(name),
                                      "origin": _origin(ra, rb),
                                      "measured_on": base_line if ra else target_line})
            continue
        if _served(rb) and not _served(ra) and ra.get("verdict") == VERDICT_ABSENT:
            endpoints_added.append({"endpoint": name, "urn": rb.get("urn", ""),
                                    "origin": _origin(rb, ra),
                                    "attested_on": rb.get("attested_on") or [],
                                    "silent_on": rb.get("silent_on") or []})
        elif _served(ra) and not _served(rb) and rb.get("verdict") == VERDICT_ABSENT:
            endpoints_removed.append({"endpoint": name, "urn": ra.get("urn", ""),
                                      "origin": _origin(ra, rb),
                                      "attested_on": ra.get("attested_on") or [],
                                      "silent_on": ra.get("silent_on") or []})

    # --- field deltas, compared ONLY within one kind of evidence ------------
    fields_changed, fields_unknown, fields_incomparable = [], [], []

    def _field_map(line_doc):
        """``{key: {origin: fields}}`` — the two evidence kinds kept APART.

        Merging them was the first version of this function and it was wrong
        in a way that only real data showed: a sweep field set is the raw dict
        FortiWeb puts on the wire, which carries the ``_val`` companion of
        every enum, plus ``sz_``/``q_`` internals; the harvested schema
        deliberately strips exactly those (``fortiweb_field_schema._NOISE_*``)
        because they are not operator-settable fields. Comparing one against
        the other reported **56 removed fields** for 7.6 → 8.0 that are
        nothing but that filter — a page whose headline number is noise is a
        page the operator learns to ignore.

        So a delta is only ever computed between two sets of the SAME kind.
        A key known by different kinds on the two sides is *incomparable*, and
        says so. Endpoint evidence is keyed by the origin the library recorded
        (``sweep``, ``vendor_doc``, ``legacy_matrix``) rather than assumed to be
        a sweep: a vendor claim labelled ``sweep`` would present the vendor's
        tooling as a measurement of a real box.
        """
        out: dict = {}
        for obj, rec in (line_doc.get("objects") or {}).items():
            if rec.get("fields"):
                out.setdefault(obj, {})["schema"] = set(rec["fields"])
        for name, rec in (line_doc.get("endpoints") or {}).items():
            if rec.get("fields"):
                out.setdefault(name, {})[rec.get("origin") or "sweep"] = set(rec["fields"])
        return out

    fa, fb = _field_map(a), _field_map(b)
    for key in sorted(set(fa) | set(fb)):
        ia, ib = fa.get(key) or {}, fb.get(key) or {}
        shared = sorted(set(ia) & set(ib),
                        key=lambda o: (_ORIGIN_ORDER.index(o) if o in _ORIGIN_ORDER else 99, o))
        if not shared:
            if ia and ib:
                fields_incomparable.append({
                    "key": key, "urn": _urn(key),
                    "base_origin": sorted(ia)[0], "target_origin": sorted(ib)[0],
                    "base_count": len(next(iter(ia.values()))),
                    "target_count": len(next(iter(ib.values()))),
                })
            else:
                side = ia or ib
                fields_unknown.append({
                    "key": key, "urn": _urn(key),
                    "known_on": base_line if ia else target_line,
                    "origin": sorted(side)[0], "count": len(next(iter(side.values()))),
                })
            continue
        for origin in shared:
            added = sorted(ib[origin] - ia[origin])
            removed = sorted(ia[origin] - ib[origin])
            if added or removed:
                fields_changed.append({
                    "key": key, "urn": _urn(key), "origin": origin,
                    "added": added, "removed": removed,
                    "base_count": len(ia[origin]), "target_count": len(ib[origin]),
                })

    buckets = {
        "endpoints_added": endpoints_added,
        "endpoints_removed": endpoints_removed,
        "endpoints_unknown": endpoints_unknown,
        "fields_changed": fields_changed,
        "fields_unknown": fields_unknown,
        "fields_incomparable": fields_incomparable,
    }

    # --- rows that describe the SAME NAME ----------------------------------
    # ``user_group`` appears TWICE in the live matrix: once as endpoint
    # evidence (a sweep asked the box and it answered ``absent``) and once as
    # object evidence (a harvested schema, present on 7.6 and not on 8.0).
    # Nothing tied the two rows together, so an operator who had just run a
    # sweep read the schema row's "not measured on 8.0.5" as the sweep having
    # failed (reported 2026-09-17). Both rows were correct; what was missing is
    # that each says the other exists.
    #
    # Computed HERE and never in the template: the page renders one loop per
    # bucket, and a cross-reference assembled inside a loop can only see its
    # own bucket's rows — which is precisely the blindness being fixed.
    #
    # It does NOT merge them. The two are different kinds of evidence and
    # merging them is what produced the 56 phantom removals; the link is a
    # pointer, and the ``origin`` it carries is the reason the rows are apart.
    by_key: dict = {}
    for bucket, rows in buckets.items():
        for row in rows:
            by_key.setdefault(row.get("endpoint") or row.get("key") or "", []).append(
                (bucket, row))
    for name, entries in by_key.items():
        if len(entries) < 2:
            continue
        for bucket, row in entries:
            row["siblings"] = [
                {"bucket": b, "label": BUCKET_LABEL[b][0],
                 "origin": r.get("origin") or "",
                 "is_change": BUCKET_LABEL[b][1] == "yes"}
                for b, r in entries if r is not row]

    # --- why a side has no schema ------------------------------------------
    # A ``fields_unknown`` row whose evidence is ``schema`` says "not measured
    # on 8.0.5" and that is literally true — but the reason lives in the
    # harvest, which until now printed it to a terminal and discarded it. The
    # reason is READ from the recorded coverage; it is never inferred from the
    # absence itself, because "no schema" and "no schema BECAUSE the reference
    # box has that table empty" are the difference between a defect and a
    # property of the estate.
    from . import field_catalog as _fc
    base_ln, target_ln = firmware_line(base_line), firmware_line(target_line)
    for row in fields_unknown:
        missing_line = target_ln if row.get("known_on") == base_line else base_ln
        missing_scope = target_line if row.get("known_on") == base_line else base_line
        # The recorded harvest reason exists for SCHEMA evidence only -- it is
        # the harvest's own log. A sweep keeps no such record, and lending it
        # the harvest's sentence would explain one absence with the cause of
        # another.
        if row.get("origin") == "schema":
            gap = _fc.coverage_gap(product, missing_line, row.get("key") or "",
                                   root=SCHEMA_ROOT)
            if gap:
                row["gap_reason"] = gap
                row["gap_reason"]["scope"] = missing_scope

        # --- and what the SWEEP already answered about that same side -------
        # Reported 2026-09-17: an operator ran a sweep against the 8.0.5 box
        # and the cell still read "not measured on 8.0.5", so they concluded
        # the sweep had failed. It had not. The sweep asked, and the box
        # REJECTED the URN — a measured no. The cell was true about SCHEMA
        # evidence and silent about the answer the operator had just paid for.
        #
        # This is not a merge: no field set crosses the origin boundary (that
        # is what produced the 56 phantom removals). Only the EXISTENCE verdict
        # the sweep recorded for the same key on the same line is surfaced, so
        # a blank cell can distinguish the two states it used to spell the same
        # way — "nobody asked this build" from "this build was asked and said
        # no". A key with no endpoint record on the missing side keeps the
        # unqualified phrase, because for that key nobody really did ask.
        # Applies to BOTH kinds of evidence. The first cut of this guarded on
        # schema rows only and left five rows saying "not measured on 8.0.5"
        # for endpoints the 8.0.5 sweep had answered ``ok`` about -- the very
        # sentence being fixed, in the commoner half of the page.
        missing_doc = b if row.get("known_on") == base_line else a
        ep = (missing_doc.get("endpoints") or {}).get(row.get("key") or "")
        if ep and ep.get("verdict"):
            row["measured"] = {
                "verdict": ep.get("verdict"),
                "measured_at": ep.get("measured_at") or "",
                "devices": list(ep.get("devices") or []),
                "urn": ep.get("urn") or "",
                "scope": missing_scope,
            }

    # What the harvest of each compared line actually managed. A side whose
    # catalog was never harvested reports ``harvested: False`` — not "complete".
    schema_coverage = {
        "base": dict(_fc.coverage_summary(product, base_ln, root=SCHEMA_ROOT),
                     scope=base_line),
        "target": dict(_fc.coverage_summary(product, target_ln, root=SCHEMA_ROOT),
                       scope=target_line),
    }

    # A delta computed between two ROLLUPS carries every build each rollup
    # merged. Without it "8.0 adds X" is unfalsifiable: the reader cannot tell
    # whether X was seen on one build or on all of them.
    return {
        "schema_coverage": schema_coverage,
        "product": product, "base": base_line, "target": target_line,
        "base_kind": a_kind, "target_kind": b_kind,
        "base_known": bool(a), "target_known": bool(b),
        "base_versions": a.get("measured_versions") or ([base_line] if a_kind == "version" else []),
        "target_versions": b.get("measured_versions") or ([target_line] if b_kind == "version" else []),
        "base_heterogeneous": bool(a.get("heterogeneous")),
        "target_heterogeneous": bool(b.get("heterogeneous")),
        "endpoints_added": endpoints_added,
        "endpoints_removed": endpoints_removed,
        "endpoints_unknown": endpoints_unknown,
        "fields_changed": fields_changed,
        "fields_unknown": fields_unknown,
        "fields_incomparable": fields_incomparable,
        "totals": {
            "fields_added": sum(len(c["added"]) for c in fields_changed),
            "fields_removed": sum(len(c["removed"]) for c in fields_changed),
        },
    }


# ---------------------------------------------------------------------------
# preflight — the point of all of the above
# ---------------------------------------------------------------------------

STATUS_OK = "ok"
STATUS_UNMEASURED = "unmeasured"
STATUS_ABSENT = "absent"
STATUS_FIELDS_UNKNOWN = "fields_unknown"
STATUS_UNKNOWN_FIELDS = "unknown_fields"
#: The caller asked about a BUILD nobody measured. Deliberately not folded into
#: ``unmeasured``: that word also covers "this product has no evidence at all",
#: and the two demand different next actions — one needs any sweep, the other
#: needs a sweep of THAT build while its siblings already have one.
STATUS_VERSION_UNMEASURED = "version_unmeasured"


def known_fields(doc: dict, key: str) -> tuple[set, list]:
    """Field evidence for ``key`` inside an ALREADY-RESOLVED scope document.

    The single author of "which fields does this scope serve". ``_answer``
    reads it to decide ``unknown``; ``version_compat`` reads it to decide which
    fields are NEW at a destination. Two readers, one rule — a second copy of
    this union is how the two surfaces would start disagreeing about the same
    appliance.

    Returns ``(fields, origins)``. An EMPTY set with empty origins means nobody
    measured them, which is not the same as "it has none": the caller must keep
    those apart (``STATUS_FIELDS_UNKNOWN`` is the verdict for it).
    """
    known: set = set()
    origins: list = []
    obj = (doc.get("objects") or {}).get(key)
    ep = (doc.get("endpoints") or {}).get(key)
    if obj and obj.get("fields"):
        known |= set(obj["fields"])
        origins.append("schema")
    if ep and ep.get("fields"):
        known |= set(ep["fields"])
        origins.append("sweep")
    return known, origins


def _answer(doc: dict, kind: str, scope: str, key: str, keys: list) -> dict:
    """The verdict for one already-resolved scope. Never resolves anything."""
    base = {"status": None, "line": scope, "scope": scope, "scope_kind": kind,
            "key": key, "unknown": [], "known": []}
    if kind == "line":
        base["rollup"] = True
        base["rollup_versions"] = doc.get("measured_versions") or []
        base["heterogeneous"] = bool(doc.get("heterogeneous"))

    ep = (doc.get("endpoints") or {}).get(key)
    obj = (doc.get("objects") or {}).get(key)
    if ep is None and obj is None:
        return {**base, "status": STATUS_UNMEASURED,
                "reason": "%r was never measured on %s" % (key, scope)}

    if ep is not None:
        # A rollup answer that rests on SOME of its builds says which. The
        # caller is about to write to one specific box, and "the line serves
        # it" is not the same claim as "the build you are writing to serves
        # it" — folding them is the false positive this module was rebuilt to
        # remove.
        if ep.get("attested_on") is not None:
            base["attested_on"] = ep.get("attested_on") or []
            base["silent_on"] = ep.get("silent_on") or []
            base["partial"] = bool(base["attested_on"] and base["silent_on"])

    if ep is not None and ep.get("verdict") == VERDICT_ABSENT and not (obj and obj.get("fields")):
        return {**base, "status": STATUS_ABSENT, "unknown": keys,
                "reason": "%r is not served by %s (the appliance rejected the "
                          "URN)" % (key, scope)}

    known, origins = known_fields(doc, key)
    line_granular = []
    # Field schemas are harvested per LINE, so on a VERSION scope they are the
    # weaker claim. Labelled rather than dropped: dropping would make every
    # build look field-blind, and silence would make a line-granular fact read
    # as a build-granular one.
    if ("schema" in origins and kind == "version"
            and (obj or {}).get("granularity") == "line"):
        line_granular.append("schema")
    if not known:
        return {**base, "status": STATUS_FIELDS_UNKNOWN, "origins": origins,
                "reason": "%r exists on %s but no evidence records its fields "
                          "(the endpoint answered with an empty collection)"
                          % (key, scope)}

    unknown = [k for k in keys if k not in known]
    return {
        **base,
        "status": STATUS_UNKNOWN_FIELDS if unknown else STATUS_OK,
        "origins": origins, "line_granular_origins": line_granular,
        "unknown": unknown, "known": [k for k in keys if k in known],
        "reason": ("%d field(s) not present on %s: %s"
                   % (len(unknown), scope, ", ".join(unknown))) if unknown else "",
    }


def preflight(product: str, line: str, key: str, keys,
              matrix: dict | None = None) -> dict:
    """Would a payload of ``keys`` for ``key`` be understood on ``line``?

    ``line`` may name a full firmware version (``8.0.3``) or a line (``8.0``).
    ``key`` is an endpoint name (sweep evidence) or a provisioning object name
    (schema evidence) — the two namespaces overlap and both are consulted.

    RULE 2: the answer is never a bare boolean. ``unmeasured`` and ``ok`` are
    different answers and the caller must be able to tell them apart, because
    one of them means "go ahead" and the other means "you are about to write
    to a device on the basis of nothing".

    RULE 4, added this round: **a version with no evidence is never answered
    from its line.** ``8.0.5`` is not ``8.0.3``, the fleet holds both, and the
    old code merged them — so an endpoint measured only on 8.0.3 came back
    ``ok`` for a 8.0.5 box. The new answer is ``version_unmeasured``, and it
    **carries the line-granular answer beside it, labelled**, rather than
    withholding it: a refusal that hides what IS known is how a correct guard
    gets routed around.
    """
    from . import firmware_versions as fv

    keys = sorted({str(k) for k in (keys or [])})
    matrix = matrix or _load_for(product, line)
    doc, kind = resolve_scope(matrix, line)

    if doc is not None:
        return _answer(doc, kind, line, key, keys)

    if line and not fv.is_line_only(line):
        parent = fv.line_of(line)
        ldoc = (matrix.get("lines") or {}).get(parent)
        if ldoc:
            siblings = ldoc.get("measured_versions") or []
            return {
                "status": STATUS_VERSION_UNMEASURED, "line": line, "scope": line,
                "scope_kind": "version", "key": key, "unknown": [], "known": [],
                "measured_siblings": siblings, "rollup_line": parent,
                "line_answer": _answer(ldoc, "line", parent, key, keys),
                "reason": "%s has no evidence of its own. The %s line was "
                          "measured on %s — what those builds serve is not "
                          "proof about this one. The line-granular answer is "
                          "reported beside this one, labelled."
                          % (line, parent, ", ".join(siblings) or "nothing"),
            }

    return {"status": STATUS_UNMEASURED, "line": line, "scope": line,
            "scope_kind": None, "key": key, "unknown": [], "known": [],
            "reason": "no evidence for %s %s — sweep an appliance on "
                      "that version, or harvest its field schemas, before "
                      "trusting a payload built for another one"
                      % (product, line or "?")}


def preflight_for_appliance(appliance, key: str, keys) -> dict:
    """``preflight`` scoped to the appliance's EXACT running firmware.

    The full version, not the line. This is the call site the false positive
    came out of: the box reports ``8.0.3``, the line rollup held evidence from
    ``8.0.5``, and the merge answered ``ok``.
    """
    from . import firmware_versions as fv

    product = _KIND_FOR.get(getattr(appliance, "kind", ""), getattr(appliance, "kind", ""))
    raw = (getattr(appliance, "fw_version", "") or
           getattr(appliance, "firmware", ""))
    version = fv.normalize(raw)
    if not version:
        return {"status": STATUS_UNMEASURED, "line": "", "scope": "",
                "scope_kind": None, "key": key, "unknown": [], "known": [],
                "reason": "%s has no known firmware — SATOM cannot tell which "
                          "API surface it serves" % getattr(appliance, "name", "?")}
    return preflight(product, version, key, keys)


__all__ = [
    "firmware_line", "firmware_version", "resolve_scope", "build", "rebuild",
    "load", "diff", "preflight", "preflight_for_appliance", "matrix_path",
    "MATRIX_ROOT", "MATRIX_ROOT_DEFAULT", "PRODUCTS", "CATALOG_ONLY_PRODUCTS",
    "SWEPT_PRODUCTS", "STATUS_OK", "STATUS_UNMEASURED", "STATUS_ABSENT",
    "STATUS_FIELDS_UNKNOWN", "STATUS_UNKNOWN_FIELDS",
    "STATUS_VERSION_UNMEASURED", "known_fields",
]
