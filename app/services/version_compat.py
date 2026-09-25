"""Does a configuration authored for one firmware fit the API of another?

One engine, two surfaces. The clone/migrate pre-flight asks it about the
**destination appliance's exact running build**; the upgrade flow asks it about
the **version a box is about to be flashed to**. Both questions are the same
question — *would this payload survive the write?* — and giving them one author
is the point: two copies would start disagreeing about the same appliance, and
the disagreement would surface as a green light on one page and a warning on
the other.

The evidence comes from the API library (``services.api_library``,
``docs/api-library.md``): ``fields_at`` says what one build serves for one
endpoint, ``compare`` says what changed between two builds (same kind of
evidence on both sides, operator-authored renames honoured), and
``resolve_appliance`` pins an appliance to its exact build. Every answer carries
its **provenance** — which kind of evidence spoke (``sweep``, ``schema``,
``vendor_doc`` …) — so a page can tell "a box was measured" from "the vendor's
tooling claims".

Three facts this module is shaped around, all measured rather than assumed:

1. **FortiWeb has no schema endpoint.** ``?action=schema|default|meta|describe``,
   ``?datasource=1``, ``?with_meta=1``, ``?meta=1`` all answer 200 with the
   ordinary row list (measured 2026-09-18): an unknown parameter is *ignored*,
   not rejected, so a schema probe looks exactly like a probe that worked and
   found nothing. The fields of a version are therefore knowable ONLY from
   evidence harvested off a box running it.
2. **An empty collection reveals nothing.** A build whose ``server_policy``
   collection has no rows records no fields for it. That is ``BLIND`` here, and
   it is deliberately not ``OK``: "nothing contradicted the payload" is a
   different claim from "the build serves these fields".
3. **A silent drop is the failure mode.** A cmdb POST carrying a field the
   destination does not understand answers **200 and discards it**. Nothing
   fails, and the copy looks complete in the destination GUI. That is why the
   verdict is never a bare boolean and why absence of evidence never renders
   green.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from . import api_matrix as am
from . import firmware_versions as fv

# ---------------------------------------------------------------------------
# verdicts
# ---------------------------------------------------------------------------

#: Source and target are the same build. Not a flavour of ``OK``: nothing was
#: compared, and an operator reading "compatible" deserves to know whether that
#: came from evidence or from the two versions being the same string.
STATE_SAME = "same"
STATE_OK = "ok"
#: Fields the payload carries that the target build has no evidence for. The
#: 200-and-discard case — the only one that silently corrupts a copy.
STATE_DROPPED = "dropped"
#: The target build does not serve the endpoint at all (it rejected the URN).
STATE_ABSENT = "absent"
#: The target serves the endpoint but nobody measured its fields.
STATE_BLIND = "blind"
#: No evidence for that build at all (covers ``version_unmeasured``).
STATE_UNMEASURED = "unmeasured"

STATE_LABEL = {
    STATE_SAME: "same API surface",
    STATE_OK: "every field is served",
    STATE_DROPPED: "fields would be discarded",
    STATE_ABSENT: "endpoint not served",
    STATE_BLIND: "fields never measured",
    STATE_UNMEASURED: "no evidence for that build",
}

#: Worst-first. ``UNMEASURED`` outranks ``BLIND`` because they are two
#: different ignorances: blind still proves the object can exist on that build,
#: unmeasured proves nothing at all, so it is the weaker footing to write from.
SEVERITY = (STATE_ABSENT, STATE_DROPPED, STATE_UNMEASURED, STATE_BLIND,
            STATE_OK, STATE_SAME)

#: The pre-flight LEVEL each verdict maps to, so both surfaces colour the same
#: fact the same way. ``dropped`` is a warn and not a block on purpose: the
#: evidence is a field census, not a contract, and a hard block built on a
#: census would stop legitimate clones the day a sweep runs thin. ``absent`` IS
#: a block — the endpoint answering "I do not serve this URN" is the appliance
#: itself talking, not an inference about it.
LEVEL_FOR = {
    STATE_SAME: "ok", STATE_OK: "ok", STATE_BLIND: "warn",
    STATE_UNMEASURED: "warn", STATE_DROPPED: "warn", STATE_ABSENT: "block",
}
_LEVEL_RANK = {"ok": 0, "warn": 1, "block": 2}

#: Where the deciding evidence came from. ``vendor`` = only the vendor's
#: tooling (Ansible ``v_range`` data) speaks for the target build: a claim, not
#: a measurement, and labelled so on every surface.
CLAIM_MEASURED = "measured"
CLAIM_VENDOR = "vendor"
CLAIM_NONE = "none"
_VENDOR_SOURCE = "vendor_doc"

#: Transport echoes, not authored configuration. Stripped before comparing so a
#: report does not list ``http2`` and ``http2_val`` as two separate losses and
#: double every number an operator reads. Named explicitly (never a regex over
#: everything) and **reported back** in ``ignored`` — a wrong call here has to
#: be visible on the page rather than silently shrink the diff.
META_FIELDS = frozenset({"q_type", "q_ref", "q_ref_string", "can_clone",
                         "can_view"})

#: ``sz_<table>`` is the per-object sub-table census counter (measured
#: 2026-09-18); it is emitted by the appliance, never authored.
META_PREFIXES = ("sz_",)


def split_fields(fields) -> tuple[list, list]:
    """``(authored, ignored)`` — transport echoes peeled off the field list.

    ``X_val`` is dropped only when ``X`` is present beside it. An ORPHAN
    ``_val`` is kept: it would be a field whose base name this evidence never
    saw, and inventing a rule that swallows it would hide exactly the kind of
    surprise this module exists to surface.
    """
    names = {str(f) for f in (fields or [])}
    authored, ignored = [], []
    for f in sorted(names):
        if f in META_FIELDS or f.startswith(META_PREFIXES):
            ignored.append(f)
        elif f.endswith("_val") and f[:-4] in names:
            ignored.append(f)
        else:
            authored.append(f)
    return authored, ignored


def payload_fields(payload) -> tuple[list, list]:
    """``(authored, ignored)`` for one object payload as the appliance returns it."""
    if not isinstance(payload, dict):
        return [], []
    return split_fields(payload.keys())


def _claim(prov) -> str:
    """``measured`` / ``vendor`` / ``none`` for one ``fields_at`` provenance list.

    The library's own rule decides which sources are USED (measured ones if
    any, vendor only when nothing measured speaks); this only names the result.
    """
    prov = prov or []
    used = [p.get("source") for p in prov if p.get("used")]
    pool = used or [p.get("source") for p in prov]
    if not pool:
        return CLAIM_NONE
    measured = [s for s in pool if s != _VENDOR_SOURCE]
    return CLAIM_MEASURED if measured else CLAIM_VENDOR


def _spec(rec: dict | None, claim: str) -> dict:
    """The part of a library field record a form needs, plus where it came from."""
    rec = rec or {}
    return {"type": rec.get("type"), "options": list(rec.get("options") or []),
            "default": rec.get("default"), "required": rec.get("required"),
            "children": list(rec.get("children") or []),
            "sources": list(rec.get("sources") or []),
            "claim": (CLAIM_VENDOR if (rec.get("sources") or []) == [_VENDOR_SOURCE]
                      else claim)}


# ---------------------------------------------------------------------------
# evidence readers — the library (default) and a hand-built matrix (legacy)
# ---------------------------------------------------------------------------

class _LibraryEvidence:
    """Reads ``api_library``. One instance per question, results cached.

    Every read is wrapped: a library that cannot be read (no app context, table
    missing, database down) answers ``unmeasured`` with the error as the reason,
    never ``ok`` — unknown is never compatible.
    """

    kind = "library"

    def __init__(self, product: str):
        self.product = product
        self._fields: dict = {}
        self._compare: dict = {}
        self._renames: dict = {}
        self.error = ""

    def _guard(self, fn, default):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 — reported, never raised
            try:
                from ..extensions import db
                db.session.rollback()
            except Exception:  # noqa: BLE001
                pass
            self.error = "%s: %s" % (type(exc).__name__, exc)
            return default

    def fields(self, key: str, version: str) -> dict:
        ck = (key, version)
        if ck not in self._fields:
            from . import api_library as lib

            def _read():
                r = lib.fields_at(self.product, key, version)
                out = {"status": r.get("status") or "unmeasured",
                       "fields": r.get("fields") or {},
                       "provenance": r.get("provenance") or [],
                       "build": r.get("build")}
                if (out["status"] == "unmeasured" and version
                        and not fv.is_line_only(version)):
                    line = fv.line_of(version)
                    lr = lib.fields_at(self.product, key, line)
                    if lr.get("status") != "unmeasured":
                        out["line_hint"] = {
                            "line": line, "status": lr.get("status"),
                            "field_count": len(lr.get("fields") or {}),
                            "claim": _claim(lr.get("provenance"))}
                return out

            self._fields[ck] = self._guard(_read, {
                "status": "unmeasured", "fields": {}, "provenance": [],
                "build": None, "error": True})
        return self._fields[ck]

    def gains(self, key: str, source: str, target: str) -> dict:
        """``{"state": "measured"|"unknown", "added": [...], "renamed": [...]}``."""
        ck = (key, source, target)
        if ck not in self._compare:
            from . import api_library as lib

            def _read():
                cmp_ = lib.compare(self.product, source, target, endpoint=key)
                ep = (cmp_.get("endpoints") or {}).get(key)
                if ep is None:
                    return {"state": "measured", "added": [], "renamed": [],
                            "source": ""}
                if ep.get("unknown"):
                    return {"state": "unknown", "added": [], "renamed": [],
                            "reason": ep.get("reason") or ""}
                return {"state": "measured", "added": list(ep.get("added") or []),
                        "renamed": list(ep.get("renamed") or []),
                        "source": ep.get("source") or ""}

            self._compare[ck] = self._guard(_read, {
                "state": "unknown", "added": [], "renamed": [],
                "reason": "the API library could not be read"})
        return self._compare[ck]

    def renames(self, key: str, source: str, target: str) -> list:
        """``[(old, new, note)]`` operator-authored renames for source -> target."""
        if not (source and target):
            return []
        ck = (key, source, target)
        if ck not in self._renames:
            from . import api_library as lib
            self._renames[ck] = self._guard(
                lambda: list(lib._renames(self.product, [key], source, target)
                             .get(key, [])), [])
        return self._renames[ck]


class _MatrixEvidence:
    """A hand-built ``api_matrix`` document, read with the matrix's own rules.

    Kept for callers that already hold a matrix document (and the guards that
    state their evidence inline). It knows nothing about renames or vendor
    claims — the file format never carried either.
    """

    kind = "matrix"
    error = ""

    def __init__(self, matrix: dict):
        self.matrix = matrix or {"lines": {}, "versions": {}}

    def _doc(self, version):
        doc, _kind = am.resolve_scope(self.matrix, version)
        return doc

    def fields(self, key: str, version: str) -> dict:
        doc = self._doc(version)
        empty = {"status": "unmeasured", "fields": {}, "provenance": [], "build": None}
        if doc is None:
            return empty
        ep = (doc.get("endpoints") or {}).get(key)
        obj = (doc.get("objects") or {}).get(key)
        if ep is None and obj is None:
            return empty
        if (ep is not None and ep.get("verdict") == am.VERDICT_ABSENT
                and not (obj and obj.get("fields"))):
            return {**empty, "status": "absent",
                    "provenance": [{"source": "sweep", "used": True}]}
        known, origins = am.known_fields(doc, key)
        prov = [{"source": o, "used": True} for o in origins]
        if not known:
            return {**empty, "status": "blind", "provenance": prov}
        return {**empty, "status": "measured", "provenance": prov,
                "fields": {f: {"sources": list(origins)} for f in sorted(known)}}

    def gains(self, key: str, source: str, target: str) -> dict:
        tdoc, sdoc = self._doc(target), self._doc(source)
        tknown, _ = am.known_fields(tdoc, key) if tdoc else (set(), [])
        sknown, _ = am.known_fields(sdoc, key) if sdoc else (set(), [])
        return {"state": "measured", "added": sorted(tknown - sknown), "renamed": []}

    def renames(self, key: str, source: str, target: str) -> list:
        return []


def _reader(product: str, matrix):
    return _MatrixEvidence(matrix) if matrix is not None else _LibraryEvidence(product)


# ---------------------------------------------------------------------------
# the engine
# ---------------------------------------------------------------------------

def compare_object(product: str, target_version: str, key: str, fields,
                   *, source_version: str = "", matrix: dict | None = None,
                   reader=None) -> dict:
    """Would a payload of ``fields`` for ``key`` survive a write to ``target_version``?

    ``source_version`` is optional and buys two things: ``new_fields``, the
    fields the target serves that the source never did, and the operator's
    renames (``api_lib_field_map``). Without it the gains are
    **indeterminate, not empty** — and say so, because an empty list rendered
    beside a populated one reads as "this object gained nothing".

    A mapped rename is reported in ``renamed`` (``{"from", "to", "note"}``) and
    NOT as a dropped field plus a new one. The rename does not make the write
    carry the value: a payload that still says ``from`` is discarded by a
    build that only knows ``to``. Each surface grades that itself — an upgrade
    converts the configuration, a clone does not.
    """
    ev = reader if reader is not None else _reader(product, matrix)
    target_version = fv.normalize(target_version) or (target_version or "")
    source_version = fv.normalize(source_version) or (source_version or "")

    authored, ignored = split_fields(fields)
    out: dict[str, Any] = {
        "key": key, "product": product,
        "source_version": source_version, "target_version": target_version,
        "fields": authored, "ignored": ignored,
        "dropped": [], "renamed": [], "new_fields": [], "new_field_specs": {},
        "new_fields_state": "unmeasured", "new_fields_reason": "",
        "level": "warn", "claim": CLAIM_NONE, "evidence": ev.kind,
        "provenance": {"target": [], "source": []},
    }

    if source_version and target_version and source_version == target_version:
        return {**out, "state": STATE_SAME, "level": LEVEL_FOR[STATE_SAME],
                "target": None,
                "reason": "source and destination both run %s — the payload was "
                          "authored against the API it is being written to"
                          % target_version,
                "new_fields_state": "same",
                "new_fields_reason": "same build: an upgrade adds nothing"}

    tgt = ev.fields(key, target_version) if target_version else {
        "status": "unmeasured", "fields": {}, "provenance": []}
    claim = _claim(tgt.get("provenance"))
    out["claim"] = claim
    out["provenance"]["target"] = tgt.get("provenance") or []
    out["target"] = {"status": tgt.get("status"), "build": tgt.get("build")}
    if tgt.get("line_hint"):
        out["line_hint"] = tgt["line_hint"]
    status = tgt.get("status")
    tfields = tgt.get("fields") or {}
    vendor_tail = (" (vendor documentation claims this; no box running %s was "
                   "measured)" % target_version) if claim == CLAIM_VENDOR else ""

    if status == "absent":
        out.update(state=STATE_ABSENT,
                   reason="%r is not served by %s (the appliance rejected the "
                          "URN)" % (key, target_version) if claim != CLAIM_VENDOR
                   else "%r is outside the range the vendor documents for %s%s"
                        % (key, target_version, vendor_tail))
    elif status == "blind":
        out.update(state=STATE_BLIND,
                   reason="%r exists on %s but no evidence records its fields "
                          "(the endpoint answered with an empty collection)"
                          % (key, target_version))
    elif status == "measured":
        missing = [f for f in authored if f not in tfields]
        renames = {old: (new, note) for old, new, note
                   in ev.renames(key, source_version, target_version)}
        dropped = []
        for f in missing:
            new, note = renames.get(f, (None, ""))
            if new and new in tfields:
                out["renamed"].append({"from": f, "to": new, "note": note})
            else:
                dropped.append(f)
        out["dropped"] = dropped
        if dropped:
            out.update(state=STATE_DROPPED,
                       reason="%d field(s) have no evidence on %s — a cmdb write "
                              "answers 200 and discards them, so the copy would "
                              "look complete and not be%s"
                              % (len(dropped), target_version, vendor_tail))
        else:
            out.update(state=STATE_OK,
                       reason="all %d authored field(s) are served by %s%s%s"
                              % (len(authored), target_version,
                                 ("; %d under a new name (%s)" % (
                                     len(out["renamed"]),
                                     ", ".join("%s → %s" % (r["from"], r["to"])
                                               for r in out["renamed"])))
                                 if out["renamed"] else "", vendor_tail))
    else:  # unmeasured
        hint = out.get("line_hint")
        err = getattr(ev, "error", "") if tgt.get("error") else ""
        out.update(state=STATE_UNMEASURED,
                   reason=("the API library could not be read (%s)" % err) if err else
                   ("no evidence for %s %s — sweep an appliance on that build, "
                    "or harvest its field schemas, before trusting a payload "
                    "built for another one%s"
                    % (product, target_version or "?",
                       (". The %s line holds %s evidence for %r — what other "
                        "builds serve is not proof about this one"
                        % (hint["line"], hint["status"], key)) if hint else "")))

    out["level"] = LEVEL_FOR[out["state"]]
    if out["state"] == STATE_ABSENT and claim == CLAIM_VENDOR:
        # Only the appliance saying "I do not serve this URN" blocks. A vendor
        # table saying so is a claim about the appliance, graded like one.
        out["level"] = "warn"

    # --- what the target gained -------------------------------------------
    for r in out["renamed"]:
        if r["to"] not in authored:
            out["new_field_specs"][r["to"]] = {**_spec(tfields.get(r["to"]), claim),
                                              "renamed_from": r["from"]}
    if not source_version:
        out["new_fields_reason"] = ("no source build given — SATOM cannot say "
                                    "which fields are NEW rather than merely present")
        return out
    if status != "measured":
        out["new_fields_reason"] = ("%s records no fields for %r, so its gains "
                                    "over %s are unknown"
                                    % (target_version, key, source_version))
        return out
    src = ev.fields(key, source_version)
    out["provenance"]["source"] = src.get("provenance") or []
    if src.get("status") != "measured":
        out["new_fields_reason"] = ("%s records no fields for %r, so there is "
                                    "no baseline to call anything new"
                                    % (source_version, key))
        return out
    g = ev.gains(key, source_version, target_version)
    if g.get("state") != "measured":
        out["new_fields_reason"] = ("the gains of %s over %s for %r are unknown: %s"
                                    % (target_version, source_version, key,
                                       g.get("reason") or "no comparable evidence"))
        return out
    # A mapped rename's target is not a gain: ``api_library.compare`` already
    # took it out of ``added`` when it turned lost+added into ``renamed``.
    gained, _ = split_fields(g.get("added") or [])
    have = set(authored)
    out["new_fields"] = [f for f in gained if f not in have]
    out["new_fields_present"] = [f for f in gained if f in have]
    for f in out["new_fields"]:
        out["new_field_specs"][f] = _spec(tfields.get(f), claim)
    out["new_fields_state"] = "measured"
    out["new_fields_origins"] = {
        "target": [p.get("source") for p in out["provenance"]["target"] if p.get("used")],
        "source": [p.get("source") for p in out["provenance"]["source"] if p.get("used")],
        "compared": g.get("source") or ""}
    out["new_fields_reason"] = (
        "%d field(s) exist on %s and not on %s"
        % (len(gained), target_version, source_version))
    return out


def worst(states) -> str:
    """The rollup verdict for a set of per-object verdicts (worst wins)."""
    seen = {s for s in states if s}
    for s in SEVERITY:
        if s in seen:
            return s
    return STATE_SAME


def _worst_level(levels) -> str:
    best = "ok"
    for lv in levels:
        if _LEVEL_RANK.get(lv, 1) > _LEVEL_RANK[best]:
            best = lv if lv in _LEVEL_RANK else "warn"
    return best


def compare_many(product: str, target_version: str, objects,
                 *, source_version: str = "", matrix: dict | None = None) -> dict:
    """``objects`` is an iterable of ``(key, fields)``. One evidence reader for all.

    Rows for the SAME key are merged before asking: a plan routinely carries a
    dozen rows of one sub-table, and asking once per row would multiply the
    same verdict across the page while hiding that a field seen on row 7 and
    not on row 1 still has to be checked.
    """
    ev = _reader(product, matrix)
    merged: dict[str, set] = {}
    for key, fields in objects or []:
        if not key:
            continue
        merged.setdefault(str(key), set()).update(str(f) for f in (fields or []))

    rows = [compare_object(product, target_version, k, sorted(v),
                           source_version=source_version, reader=ev)
            for k, v in sorted(merged.items())]
    counts: dict[str, int] = {}
    claims: dict[str, int] = {}
    for r in rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
        claims[r["claim"]] = claims.get(r["claim"], 0) + 1
    state = worst(r["state"] for r in rows) if rows else STATE_SAME
    return {
        "product": product,
        "source_version": fv.normalize(source_version) or (source_version or ""),
        "target_version": fv.normalize(target_version) or (target_version or ""),
        "rows": rows, "counts": counts, "claims": claims,
        "evidence": ev.kind,
        "state": state,
        # Worst ROW level, not LEVEL_FOR[worst state]: a vendor-claimed absence
        # is an ``absent`` row graded warn, and the rollup must not re-promote
        # it to the block only the appliance itself can justify.
        "level": _worst_level(r["level"] for r in rows) if rows else LEVEL_FOR[STATE_SAME],
        "dropped_total": sum(len(r["dropped"]) for r in rows),
        "renamed_total": sum(len(r["renamed"]) for r in rows),
        #: Objects the target build does not serve AT ALL. Counted apart from
        #: ``dropped_total`` on purpose: "4 fields of this object are discarded"
        #: and "this object cannot exist there" are different facts with
        #: different fixes, and folding the second into the first would have
        #: rendered it as *zero fields lost* — invisible in every summary.
        "absent_total": sum(1 for r in rows if r["state"] == STATE_ABSENT),
        "absent_keys": [r["key"] for r in rows if r["state"] == STATE_ABSENT],
        "new_total": sum(len(r["new_fields"]) for r in rows),
        #: Objects whose gains could not be computed. Reported as a NUMBER and
        #: not folded into ``new_total`` — "0 new fields" and "0 new fields
        #: that we were able to look for" are different sentences.
        #: ``same`` is NOT an ignorance. When source and destination run the
        #: same build there is no upgrade, so "this object gained nothing" is
        #: a measured fact — counting it here printed "gains unknown for 14
        #: object(s)" underneath "same API surface", which reads as a hole in
        #: the evidence where there is none.
        "new_unmeasured": sum(1 for r in rows
                              if r["new_fields_state"] not in ("measured", "same")),
    }


def cached_config_fields(appliance_id: int, *, session=None) -> tuple[list, int]:
    """``([(logical, fields)], rows)`` from the appliance's HARVESTED config.

    The upgrade question is not "what could this build serve" but "what does
    THIS BOX actually have set", and the answer to that is the cache the
    harvest already wrote — no extra device reads, and it works on a box that
    is mid-window and unreachable.

    ``rows == 0`` means the appliance was never harvested. The caller must not
    render that as "nothing would be lost": it is the difference between a
    measured empty answer and no measurement, and this function reports the
    count precisely so the two stay apart.
    """
    from ..models_cache import DeviceObject
    from ..extensions import db

    sess = session or db.session
    rows = (sess.query(DeviceObject.logical_name, DeviceObject.payload)
            .filter(DeviceObject.appliance_id == appliance_id).all())
    merged: dict[str, set] = {}
    for logical, payload in rows:
        if not logical or not isinstance(payload, dict):
            continue
        merged.setdefault(str(logical), set()).update(str(k) for k in payload)
    return sorted((k, sorted(v)) for k, v in merged.items()), len(rows)


def _version_of(appliance) -> str:
    return fv.normalize(getattr(appliance, "fw_version", "")
                        or getattr(appliance, "firmware", "") or "")


def _product_of(appliance) -> str:
    kind = getattr(appliance, "kind", "") or ""
    return am._KIND_FOR.get(kind, kind)


def _resolved(appliance) -> dict:
    """``api_library.resolve_appliance`` — the exact build, and what is known of it.

    Falls back to the firmware string alone when the library cannot be read:
    the version is still the right question to ask, the library's opinion of
    it is what is missing, and the comparison says so itself.
    """
    if appliance is None:
        return {"version": "", "status": "unknown_firmware"}
    try:
        from . import api_library as lib
        r = lib.resolve_appliance(appliance)
        return {"version": r.get("version") or "", "status": r.get("status") or "",
                "build": r.get("build")}
    except Exception:  # noqa: BLE001 — degrade to the firmware string
        try:
            from ..extensions import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        v = _version_of(appliance)
        return {"version": v, "status": "unmeasured" if v else "unknown_firmware"}


def for_clone(source_appl, dest_appl, objects) -> dict:
    """Surface A: the payload is about to be written to ``dest_appl`` AS IT RUNS NOW.

    The destination's exact build, never its line: the line rollup answering
    for a build it does not cover is the false positive ``api_matrix`` was
    rebuilt to remove.
    """
    dest = dest_appl if dest_appl is not None else source_appl
    dres, sres = _resolved(dest), _resolved(source_appl)
    target = dres["version"]
    if not target:
        return {"state": STATE_UNMEASURED, "level": LEVEL_FOR[STATE_UNMEASURED],
                "rows": [], "counts": {}, "claims": {}, "dropped_total": 0,
                "renamed_total": 0, "new_total": 0,
                "absent_total": 0, "absent_keys": [],
                "new_unmeasured": 0, "product": _product_of(dest),
                "source_version": sres["version"], "target_version": "",
                "target_status": dres["status"], "source_status": sres["status"],
                "reason": "%s reports no firmware — SATOM cannot tell which API "
                          "surface it serves" % (getattr(dest, "name", "?"))}
    rep = compare_many(_product_of(dest), target, objects,
                       source_version=sres["version"])
    rep["target_status"], rep["source_status"] = dres["status"], sres["status"]
    return rep


def for_upgrade(appliance, target_version: str, objects) -> dict:
    """Surface B: the box keeps its config and the API underneath it changes.

    Offline by construction: ``objects`` is the harvested cache and the
    evidence is the library, so a box mid-window and unreachable still gets
    its answer.
    """
    sres = _resolved(appliance)
    rep = compare_many(_product_of(appliance), target_version, objects,
                       source_version=sres["version"])
    rep["source_status"] = sres["status"]
    return rep


# ---------------------------------------------------------------------------
# "offer the destination's new fields" — what may be ADDED to a copy
# ---------------------------------------------------------------------------

#: Hard caps on what an operator may add in one run. The values are written
#: verbatim into a firewall's configuration.
MAX_VALUE_LEN = 1024
_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,160}$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_INT_TYPES = {"int", "integer", "number"}
_FLOAT_TYPES = {"float", "double"}
_BOOL_TYPES = {"bool", "boolean"}
_LIST_TYPES = {"list", "multi", "multiselect"}
_STRUCT_TYPES = {"dict", "table", "mixed", "object"}
_IP_TYPES = {"ip", "ipv4", "ipv6", "ip-address"}


def offer(product: str, source_version: str, target_version: str, key: str,
          *, reader=None) -> dict:
    """``{field: spec}`` the operator may SET on ``key`` when writing to ``target_version``.

    Exactly the fields the target build is measured (or vendor-claimed) to
    serve that the source build does not, plus the target name of every mapped
    rename. Independent of any payload: the payload check ("the object does not
    already carry it") happens where the payload is, at merge time. Empty when
    either build's fields are unknown — a field nobody knows the destination
    serves is never offered.
    """
    ev = reader if reader is not None else _reader(product, None)
    s = fv.normalize(source_version) or ""
    t = fv.normalize(target_version) or ""
    if not (s and t) or s == t:
        return {}
    tgt = ev.fields(key, t)
    if tgt.get("status") != "measured":
        return {}
    tfields = tgt.get("fields") or {}
    claim = _claim(tgt.get("provenance"))
    out: dict = {}
    for old, new, _note in ev.renames(key, s, t):
        if new in tfields:
            out[new] = {**_spec(tfields.get(new), claim), "renamed_from": old}
    src = ev.fields(key, s)
    if src.get("status") != "measured":
        return out
    g = ev.gains(key, s, t)
    if g.get("state") != "measured":
        return out
    gained, _ = split_fields(g.get("added") or [])
    for f in gained:
        if f in tfields and f not in out:
            out[f] = _spec(tfields.get(f), claim)
    return out


def _coerce(field: str, spec: dict, raw) -> tuple[Any, str]:
    """``(value, error)`` for one operator value against one library spec."""
    if isinstance(raw, bool):
        raw = "true" if raw else "false"
    if isinstance(raw, (int, float)):
        raw = str(raw)
    if not isinstance(raw, str):
        return None, "%s: a value must be text, got %s" % (field, type(raw).__name__)
    val = raw.strip()
    if len(val) > MAX_VALUE_LEN:
        return None, "%s: value longer than %d characters" % (field, MAX_VALUE_LEN)
    if _CTRL_RE.search(val):
        return None, "%s: value contains control characters" % field
    typ = str(spec.get("type") or "").lower()
    opts = [str(o) for o in (spec.get("options") or []) if o is not None and str(o) != ""]
    if spec.get("children") or typ in _STRUCT_TYPES:
        return None, ("%s: a structured/sub-table field (%s) cannot be set here — "
                      "set it on the destination after the copy" % (field, typ or "table"))
    if opts:
        tokens = val.split() if typ in _LIST_TYPES else [val]
        if typ not in _LIST_TYPES and len(val.split()) > 1 and val not in opts:
            return None, "%s: %r is not one of %s" % (field, val, ", ".join(opts[:20]))
        bad = [t for t in tokens if t not in opts]
        if bad or not tokens:
            return None, "%s: %r is not one of %s" % (field, " ".join(bad) or val,
                                                     ", ".join(opts[:20]))
        return " ".join(tokens), ""
    if typ in _INT_TYPES:
        if not re.fullmatch(r"-?\d{1,18}", val):
            return None, "%s: %r is not an integer" % (field, val)
        return int(val), ""
    if typ in _FLOAT_TYPES:
        try:
            return float(val), ""
        except ValueError:
            return None, "%s: %r is not a number" % (field, val)
    if typ in _BOOL_TYPES:
        low = val.lower()
        if low in ("enable", "disable"):
            return low, ""
        if low in ("true", "false"):
            return low == "true", ""
        return None, "%s: %r is not enable/disable" % (field, val)
    if typ in _IP_TYPES:
        cand = val.replace(" ", "/") if val.count(" ") == 1 else val
        try:
            ipaddress.ip_interface(cand)
        except ValueError:
            return None, "%s: %r is not an IP address" % (field, val)
        return val, ""
    if typ in _LIST_TYPES:
        return None, ("%s: a list field with no documented options cannot be set "
                      "here — set it on the destination after the copy" % field)
    return val, ""


def validate_new_values(product: str, source_version: str, target_version: str,
                        values, *, reader=None) -> tuple[dict, list]:
    """``(clean, errors)`` for ``{key: {field: value}}`` the operator filled in.

    Server-side and authoritative: the form's offer is a hint, this is the
    rule. A field is accepted only if :func:`offer` names it for that key —
    i.e. the destination build is KNOWN to serve it and the source build does
    not — and its value fits the library's type/options. Empty values are
    "not opted in" and simply absent from ``clean``. Any error refuses the lot:
    half an operator's choices applied is a run nobody asked for.
    """
    clean: dict = {}
    errors: list = []
    if not values:
        return clean, errors
    if not isinstance(values, dict):
        return {}, ["new field values must be an object of {object: {field: value}}"]
    ev = reader if reader is not None else _reader(product, None)
    for key, fields in values.items():
        key = str(key or "")
        if not _NAME_RE.match(key) or not isinstance(fields, dict):
            errors.append("%r is not an object name with a field map" % key)
            continue
        filled = {str(f): v for f, v in fields.items()
                  if v is not None and not (isinstance(v, str) and not v.strip())}
        if not filled:
            continue
        offered = offer(product, source_version, target_version, key, reader=ev)
        for f, raw in sorted(filled.items()):
            if not _NAME_RE.match(f):
                errors.append("%s: %r is not a field name" % (key, f))
                continue
            spec = offered.get(f)
            if spec is None:
                errors.append(
                    "%s.%s: not offered — %s is not known to serve it as a field "
                    "%s lacks, so it is never sent"
                    % (key, f, fv.normalize(target_version) or "the destination",
                       fv.normalize(source_version) or "the source"))
                continue
            val, err = _coerce("%s.%s" % (key, f), spec, raw)
            if err:
                errors.append(err)
                continue
            clean.setdefault(key, {})[f] = val
    if errors:
        return {}, errors
    return clean, errors


def validate_for_clone(source_appl, dest_appl, values) -> tuple[dict, list]:
    """:func:`validate_new_values` for a clone from ``source_appl`` to ``dest_appl``.

    Both builds resolved the way :func:`for_clone` resolves them, so the offer
    the checklist showed and the rule the apply enforces read the same builds.
    """
    if not values:
        return {}, []
    dest = dest_appl if dest_appl is not None else source_appl
    return validate_new_values(_product_of(dest), _resolved(source_appl)["version"],
                               _resolved(dest)["version"], values)


def merge_new_values(items, values) -> dict:
    """Merge the operator's validated values into the plan's CREATE objects.

    Only ``kind == "object"`` items with ``status == "create"``: an object the
    destination already owns is not written by the clone, and writing a new
    field into it would edit live configuration the operator never saw. A
    field the object's payload already carries is REFUSED (``RuntimeError``):
    the offer never listed it, so the value came from a stale form, and
    overwriting the source's own value with it would change what is copied.

    Returns ``{"applied": [{key, mkey, field}], "not_applied": [{key, field,
    reason}]}``; every value lands somewhere in that report.
    """
    report = {"applied": [], "not_applied": []}
    if not values:
        return report
    by_key: dict = {}
    for it in items or []:
        if getattr(it, "kind", "") == "object" and getattr(it, "status", "") == "create" \
                and getattr(it, "logical", None) in values:
            by_key.setdefault(it.logical, []).append(it)
    for key, fields in values.items():
        targets = by_key.get(key) or []
        if not targets:
            for f in sorted(fields):
                report["not_applied"].append({
                    "key": key, "field": f,
                    "reason": "this run creates no %s — the destination already "
                              "has it, and an existing object is not edited" % key})
            continue
        for it in targets:
            payload = dict(it.payload or {})
            clash = sorted(f for f in fields if f in payload)
            if clash:
                raise RuntimeError(
                    "%s %r already carries %s — a new-field value never overwrites "
                    "what the source copies (re-run the checklist)"
                    % (key, it.mkey, ", ".join(clash)))
            it.payload = {**payload, **fields}
            for f in sorted(fields):
                report["applied"].append({"key": key, "mkey": it.mkey, "field": f})
    return report


__all__ = [
    "STATE_SAME", "STATE_OK", "STATE_DROPPED", "STATE_ABSENT", "STATE_BLIND",
    "STATE_UNMEASURED", "STATE_LABEL", "SEVERITY", "LEVEL_FOR", "META_FIELDS",
    "META_PREFIXES", "CLAIM_MEASURED", "CLAIM_VENDOR", "CLAIM_NONE",
    "split_fields", "payload_fields", "compare_object",
    "compare_many", "worst", "for_clone", "for_upgrade",
    "cached_config_fields", "offer", "validate_new_values", "validate_for_clone",
    "merge_new_values",
]
