"""Declared firmware versions — the axis the API evidence is indexed by.

Why this module exists, in one measured sentence: on 2026-09-15 the fleet held
snapshots recording **8.0.3** (``fortiweb16``, ``fortiweb17``) and **8.0.5**
(appliance 34), ``api_matrix`` folded all three into the line ``8.0``, and its
merge rule is *"OK from ANY healthy witness on the line wins"* — so an endpoint
served only by 8.0.5 was attributed to 8.0, and ``preflight`` answered
**compatible** for a box running 8.0.3 about something that box does not have.
A false positive in the only question the module exists to answer.

So the unit of evidence becomes the **full version** (``8.0.3``) and the
**line** (``8.0``) survives as a declared rollup — the aggregation argument in
``api_matrix``'s docstring is still right *for aggregating*; what was wrong was
aggregating in silence.

Three rules this module is shaped around:

1. **A version with no patch component is not the patch ``.0``.** ``"8.0"``
   normalises to ``"8.0"``, never to ``"8.0.0"``: it means *"we know the line
   and not the patch"*, which is a third thing, and minting ``8.0.0`` would
   invent a build nobody runs and then attribute evidence to it.
2. **Declared is not measured.** A version can be known to exist (somebody
   uploaded its image, or an operator declared it) with zero evidence behind
   it. That renders ``declared · unmeasured`` — never as a measured line that
   happens to be empty, which is what an operator reads as "no differences".
3. **Derived declarations are derived, never stored.** Versions that come from
   a ``FirmwareImage`` row or from an appliance's running firmware are computed
   on read, so they cannot drift from their source and no upload path can
   "forget" to register one. The table here holds **only** what an operator
   authored by hand, which is the only thing that has nowhere else to live.
"""
from __future__ import annotations

import re
from datetime import datetime

#: Where a declaration came from. Kept as separate strings rather than a
#: boolean because "somebody uploaded the image", "an operator typed it" and
#: "a box in the fleet is running it" justify very different next actions.
SOURCE_UPLOAD = "upload"
SOURCE_MANUAL = "manual"
SOURCE_FLEET = "fleet"
SOURCE_EVIDENCE = "evidence"

SOURCE_LABEL = {
    SOURCE_UPLOAD: "firmware image uploaded",
    SOURCE_MANUAL: "declared by an operator",
    SOURCE_FLEET: "an appliance is running it",
    SOURCE_EVIDENCE: "evidence on disk",
}

_VER_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def normalize(version) -> str:
    """``"7.6.8,build1128(GA.M)"`` → ``"7.6.8"``; ``"8.0"`` → ``"8.0"``.

    RULE 1 lives here. The patch group is optional and its absence is carried
    through as absence — the return is two components, not three with a zero
    invented for the third.
    """
    if not version:
        return ""
    m = _VER_RE.search(str(version))
    if not m:
        return ""
    if m.group(3) is None:
        return "%s.%s" % (m.group(1), m.group(2))
    return "%s.%s.%s" % (m.group(1), m.group(2), m.group(3))


def line_of(version) -> str:
    """The ``major.minor`` rollup key for a version string."""
    v = normalize(version)
    if not v:
        return ""
    a, b = v.split(".")[:2]
    return "%s.%s" % (a, b)


def is_line_only(version) -> bool:
    """True when the string pins a line but not a patch (``"8.0"``).

    Callers need this to avoid reporting *"measured on 8.0"* as if it named a
    build: it is evidence whose patch level was never recorded, and that is a
    weaker claim than evidence from a known build.
    """
    v = normalize(version)
    return bool(v) and v.count(".") == 1


def sort_key(version: str):
    """Numeric ordering, so ``8.0.10`` sorts after ``8.0.9``.

    A line-only string sorts BEFORE every patch of its line: ``8.0`` is the
    weakest thing anyone can say about 8.0.x, so it reads first.
    """
    parts = [int(p) for p in (normalize(version) or "0").split(".") if p.isdigit()]
    while len(parts) < 3:
        parts.append(-1)
    return tuple(parts[:3])


def compare(a, b):
    """``1`` if ``a`` is newer than ``b``, ``-1`` older, ``0`` the same build,
    and **None when the pair cannot be decided**.

    ``None`` is an answer, not a failure, and it is why this exists beside
    :func:`sort_key` instead of being spelled ``sort_key(a) > sort_key(b)``.
    Sorting has to be total, so a line-only string is placed before every
    patch of its line and ``8.0`` sorts under ``8.0.3``. Read as an UPGRADE
    question that ordering is a LIE: ``8.0`` means *"the 8.0 line, patch
    unrecorded"* (RULE 1), and against a box on ``8.0.3`` it could turn out to
    be ``8.0.0`` — a downgrade — or ``8.0.9``. A caller that HIDES
    destinations has to be able to tell *provably not newer* from *unknown*,
    because only the first is safe to hide.

    Across different lines the line decides and no patch is needed: ``8.0`` is
    newer than every ``7.6.x`` whatever its patch turns out to be.

    Nothing here compares across PRODUCTS. FortiAuthenticator 8.0.3 and
    FortiWeb 8.0.5 are two vendors' counters that happen to share digits.
    Keeping products apart is the caller's job and it is deliberately not
    defaulted here, because a default would be silent.
    """
    va, vb = normalize(a), normalize(b)
    if not va or not vb:
        return None
    la, lb = line_of(va), line_of(vb)
    if la != lb:
        ka = tuple(int(p) for p in la.split("."))
        kb = tuple(int(p) for p in lb.split("."))
        return 1 if ka > kb else -1
    oa, ob = is_line_only(va), is_line_only(vb)
    if oa and ob:
        return 0
    if oa or ob:
        return None
    pa, pb = int(va.split(".")[2]), int(vb.split(".")[2])
    return (pa > pb) - (pa < pb)


# ---------------------------------------------------------------------------
# the manual table (authored declarations only — see RULE 3)
# ---------------------------------------------------------------------------

def manual(product: str) -> dict:
    """``{version: row}`` of operator-declared versions for one product."""
    from ..models_firmware import FirmwareVersionDecl

    out: dict = {}
    for row in FirmwareVersionDecl.query.filter_by(product=product).all():
        v = normalize(row.version)
        if v:
            out[v] = row
    return out


def declare(product: str, version: str, note: str = "", by: str = "") -> tuple:
    """Author a version declaration. ``(ok, message, version)``.

    Idempotent on ``(product, version)``: re-declaring updates the note rather
    than raising, because the operator's intent in both cases is "this version
    should be on the page".
    """
    from ..extensions import db
    from ..models_firmware import FirmwareVersionDecl

    v = normalize(version)
    if not v:
        return False, ("%r does not contain a firmware version — expected "
                       "something like 8.0.3" % (version or "")), ""
    row = FirmwareVersionDecl.query.filter_by(product=product, version=v).first()
    if row is None:
        row = FirmwareVersionDecl(product=product, version=v,
                                  declared_by=by or "", note=(note or "")[:500])
        db.session.add(row)
        created = True
    else:
        row.note = (note or "")[:500]
        row.declared_by = by or row.declared_by
        created = False
    db.session.commit()
    return True, ("%s declared." % v if created else "%s updated." % v), v


def forget(product: str, version: str) -> tuple:
    """Drop an operator declaration. ``(ok, message)``.

    Only ever removes the AUTHORED row. A version that is also derived (an
    image is in the vault, or a box runs it) stays on the page afterwards, and
    it should: forgetting a note cannot unmake a fact.
    """
    from ..extensions import db
    from ..models_firmware import FirmwareVersionDecl

    v = normalize(version)
    row = FirmwareVersionDecl.query.filter_by(product=product, version=v).first()
    if row is None:
        return False, "%s was not declared by hand — nothing to forget." % (v or version)
    db.session.delete(row)
    db.session.commit()
    return True, "%s is no longer declared by hand." % v


# ---------------------------------------------------------------------------
# the merged view
# ---------------------------------------------------------------------------

def _image_versions(product: str) -> dict:
    """``{version: [filename, ...]}`` from the firmware vault.

    Derived from the ``FirmwareImage`` table on every read (RULE 3). There are
    TWO code paths that create those rows — the plain ``upload`` view and the
    chunked ``assemble_upload`` — and hooking both would be one refactor away
    from a version that silently never gets declared. Querying the table has
    one call site and cannot drift.
    """
    from ..models_firmware import FirmwareImage

    out: dict = {}
    for row in FirmwareImage.query.filter_by(product=product).all():
        v = normalize(row.version)
        if v:
            out.setdefault(v, []).append(row.filename or "")
    return out


def _fleet_versions(product: str) -> dict:
    """``{version: [appliance name, ...]}`` for boxes of this product."""
    from ..models import Appliance
    from . import api_matrix

    kind = api_matrix._KIND_FOR.get(product, product)
    out: dict = {}
    for ap in Appliance.query.filter_by(kind=kind).all():
        if getattr(ap, "maintenance", False):
            continue
        if str(getattr(ap, "host", "") or "").endswith(".invalid"):
            continue
        v = normalize(getattr(ap, "fw_version", "") or ap.firmware)
        if v:
            out.setdefault(v, []).append(ap.name)
    return out


def catalog(product: str, measured: dict | None = None) -> dict:
    """Every version SATOM knows of for ``product``, merged from all sources.

    ``measured`` is ``{version: True}`` (or any mapping keyed by version) from
    the evidence store; a version present there gains ``SOURCE_EVIDENCE`` and
    ``measured=True``. RULE 2 is the return value's whole shape: ``declared``
    and ``measured`` are separate booleans and a row can be the first without
    the second.
    """
    images = _image_versions(product)
    fleet = _fleet_versions(product)
    hand = manual(product)
    seen = set(images) | set(fleet) | set(hand) | set(measured or {})

    out: dict = {}
    for v in sorted(seen, key=sort_key):
        sources, detail = [], {}
        if v in images:
            sources.append(SOURCE_UPLOAD)
            detail["images"] = sorted(images[v])
        if v in fleet:
            sources.append(SOURCE_FLEET)
            detail["appliances"] = sorted(fleet[v])
        if v in hand:
            sources.append(SOURCE_MANUAL)
            detail["note"] = hand[v].note or ""
            detail["declared_by"] = hand[v].declared_by or ""
        if measured and v in measured:
            sources.append(SOURCE_EVIDENCE)
        out[v] = {
            "version": v,
            "line": line_of(v),
            "line_only": is_line_only(v),
            "sources": sources,
            "manual": v in hand,
            "declared": bool(set(sources) - {SOURCE_EVIDENCE}),
            "measured": bool(measured and v in measured),
            **detail,
        }
    return out


def _empty_line(line: str) -> dict:
    """A rollup row for a line nothing has measured. Explicitly empty.

    Every count is zero AND ``measured`` is False, because those two say
    different things: zero endpoints with ``measured=True`` reads as "we asked
    and there is nothing there", which is the opposite of "nobody ever asked".
    """
    return {
        "line": line, "in_fleet": False, "versions": [], "measured_versions": [],
        "declared_versions": [], "heterogeneous": False, "measured": False,
        "devices": [], "endpoints": {}, "objects": {}, "partial_endpoints": [],
        "counts": {"swept": 0, "ok": 0, "absent": 0, "error": 0,
                   "endpoints_with_fields": 0, "schema_objects": 0,
                   "schema_fields": 0, "versions": 0, "measured_versions": 0,
                   "partial": 0},
    }


def overlay(product: str, matrix: dict) -> dict:
    """``matrix`` plus every DECLARED version, merged at read time.

    Declarations are authored data in Postgres; the matrix is derived evidence
    in a file. They are merged here, on read, for two reasons that are both
    failures avoided:

    * A declaration made through the form would otherwise be invisible until
      somebody pressed **Rebuild** — an action that appears to do nothing is an
      action operators stop trusting.
    * The alternative (declaring triggers a rebuild) is worse: ``build``
      filters witnesses through the live appliance table, so on a product whose
      witnesses have been deleted a rebuild DESTROYS its evidence. Typing a
      version number must not be able to do that.

    A declared version never gains measurements it does not have: it arrives
    with ``measured=False`` and empty counts, which the page renders as
    ``declared · unmeasured``.
    """
    matrix = dict(matrix)
    versions = dict(matrix.get("versions") or {})
    lines = {k: dict(v) for k, v in (matrix.get("lines") or {}).items()}

    known = catalog(product, measured=versions)
    for v, meta in known.items():
        if v in versions:
            # Already measured — only the authored metadata is merged in, never
            # the counts. Sources are re-derived so a version that gained an
            # uploaded image shows it without a rebuild.
            versions[v] = {**versions[v], "sources": meta["sources"],
                           "manual": meta["manual"], "declared": meta["declared"],
                           "note": meta.get("note", versions[v].get("note", "")),
                           "declared_by": meta.get("declared_by", "")}
            continue
        versions[v] = {**meta, "in_fleet": SOURCE_FLEET in meta["sources"],
                       "measured": False, "devices": [], "endpoints": {},
                       "objects": {},
                       "counts": {"swept": 0, "ok": 0, "absent": 0, "error": 0,
                                  "endpoints_with_fields": 0,
                                  "schema_objects": 0, "schema_fields": 0}}
        ln = lines.setdefault(meta["line"], _empty_line(meta["line"]))
        ln["versions"] = sorted(set(ln.get("versions") or []) | {v}, key=sort_key)
        ln["declared_versions"] = sorted(
            set(ln.get("declared_versions") or []) | {v}, key=sort_key)
        ln.setdefault("counts", {})["versions"] = len(ln["versions"])

    matrix["versions"] = versions
    matrix["lines"] = lines
    return matrix


def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


__all__ = [
    "normalize", "line_of", "is_line_only", "sort_key",
    "manual", "declare", "forget", "catalog", "overlay",
    "SOURCE_UPLOAD", "SOURCE_MANUAL", "SOURCE_FLEET", "SOURCE_EVIDENCE",
    "SOURCE_LABEL",
]
