"""Does a configuration authored for one firmware fit the API of another?

One engine, two surfaces. The clone/migrate pre-flight asks it about the
**destination appliance's exact running build**; the upgrade flow asks it about
the **version a box is about to be flashed to**. Both questions are the same
question — *would this payload survive the write?* — and giving them one author
is the point: two copies would start disagreeing about the same appliance, and
the disagreement would surface as a green light on one page and a warning on
the other.

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


def _scope_doc(matrix: dict, scope: str):
    doc, _kind = am.resolve_scope(matrix or {}, scope)
    return doc


def compare_object(product: str, target_version: str, key: str, fields,
                   *, source_version: str = "", matrix: dict | None = None) -> dict:
    """Would a payload of ``fields`` for ``key`` survive a write to ``target_version``?

    ``source_version`` is optional and buys exactly one thing: ``new_fields``,
    the fields the target serves that the source never did. Without it that
    list is **indeterminate, not empty** — and says so, because an empty list
    rendered beside a populated one reads as "this object gained nothing".
    """
    matrix = matrix if matrix is not None else (am.load(product) or {"lines": {}, "versions": {}})
    target_version = fv.normalize(target_version) or (target_version or "")
    source_version = fv.normalize(source_version) or (source_version or "")

    authored, ignored = split_fields(fields)
    out: dict[str, Any] = {
        "key": key, "product": product,
        "source_version": source_version, "target_version": target_version,
        "fields": authored, "ignored": ignored,
        "dropped": [], "new_fields": [], "new_fields_state": "unmeasured",
        "new_fields_reason": "", "level": "warn",
    }

    if source_version and target_version and source_version == target_version:
        return {**out, "state": STATE_SAME, "level": LEVEL_FOR[STATE_SAME],
                "target": None,
                "reason": "source and destination both run %s — the payload was "
                          "authored against the API it is being written to"
                          % target_version,
                "new_fields_state": "same",
                "new_fields_reason": "same build: an upgrade adds nothing"}

    pf = am.preflight(product, target_version, key, authored, matrix=matrix)
    out["target"] = pf
    st = pf.get("status")

    if st == am.STATUS_ABSENT:
        out.update(state=STATE_ABSENT, reason=pf.get("reason", ""))
    elif st == am.STATUS_UNKNOWN_FIELDS:
        out.update(state=STATE_DROPPED, dropped=list(pf.get("unknown") or []),
                   reason="%d field(s) have no evidence on %s — a cmdb write "
                          "answers 200 and discards them, so the copy would "
                          "look complete and not be"
                          % (len(pf.get("unknown") or []), target_version))
    elif st == am.STATUS_OK:
        out.update(state=STATE_OK,
                   reason="all %d authored field(s) are served by %s"
                          % (len(authored), target_version))
    elif st == am.STATUS_FIELDS_UNKNOWN:
        out.update(state=STATE_BLIND, reason=pf.get("reason", ""))
    else:  # unmeasured / version_unmeasured
        out.update(state=STATE_UNMEASURED, reason=pf.get("reason", ""))

    out["level"] = LEVEL_FOR[out["state"]]

    # --- what the target gained -------------------------------------------
    tdoc = _scope_doc(matrix, target_version)
    sdoc = _scope_doc(matrix, source_version) if source_version else None
    tknown, torigins = am.known_fields(tdoc, key) if tdoc else (set(), [])
    sknown, sorigins = am.known_fields(sdoc, key) if sdoc else (set(), [])
    if not source_version:
        out["new_fields_reason"] = ("no source build given — SATOM cannot say "
                                    "which fields are NEW rather than merely present")
    elif not tknown:
        out["new_fields_reason"] = ("%s records no fields for %r, so its gains "
                                    "over %s are unknown"
                                    % (target_version, key, source_version))
    elif not sknown:
        out["new_fields_reason"] = ("%s records no fields for %r, so there is "
                                    "no baseline to call anything new"
                                    % (source_version, key))
    else:
        gained, _ = split_fields(tknown - sknown)
        have = set(authored)
        out["new_fields"] = [f for f in gained if f not in have]
        out["new_fields_present"] = [f for f in gained if f in have]
        out["new_fields_state"] = "measured"
        out["new_fields_origins"] = {"target": torigins, "source": sorigins}
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


def compare_many(product: str, target_version: str, objects,
                 *, source_version: str = "", matrix: dict | None = None) -> dict:
    """``objects`` is an iterable of ``(key, fields)``. One matrix read for all.

    Rows for the SAME key are merged before asking: a plan routinely carries a
    dozen rows of one sub-table, and asking once per row would multiply the
    same verdict across the page while hiding that a field seen on row 7 and
    not on row 1 still has to be checked.
    """
    matrix = matrix if matrix is not None else (am.load(product) or {"lines": {}, "versions": {}})
    merged: dict[str, set] = {}
    for key, fields in objects or []:
        if not key:
            continue
        merged.setdefault(str(key), set()).update(str(f) for f in (fields or []))

    rows = [compare_object(product, target_version, k, sorted(v),
                           source_version=source_version, matrix=matrix)
            for k, v in sorted(merged.items())]
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    state = worst(r["state"] for r in rows) if rows else STATE_SAME
    return {
        "product": product, "source_version": source_version,
        "target_version": target_version, "rows": rows, "counts": counts,
        "state": state, "level": LEVEL_FOR[state],
        "dropped_total": sum(len(r["dropped"]) for r in rows),
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


def for_clone(source_appl, dest_appl, objects) -> dict:
    """Surface A: the payload is about to be written to ``dest_appl`` AS IT RUNS NOW.

    The destination's exact build, never its line: the line rollup answering
    for a build it does not cover is the false positive ``api_matrix`` was
    rebuilt to remove.
    """
    dest = dest_appl if dest_appl is not None else source_appl
    target = _version_of(dest)
    if not target:
        return {"state": STATE_UNMEASURED, "level": LEVEL_FOR[STATE_UNMEASURED],
                "rows": [], "counts": {}, "dropped_total": 0, "new_total": 0,
                "absent_total": 0, "absent_keys": [],
                "new_unmeasured": 0, "product": _product_of(dest),
                "source_version": _version_of(source_appl), "target_version": "",
                "reason": "%s reports no firmware — SATOM cannot tell which API "
                          "surface it serves" % (getattr(dest, "name", "?"))}
    return compare_many(_product_of(dest), target, objects,
                        source_version=_version_of(source_appl))


def for_upgrade(appliance, target_version: str, objects) -> dict:
    """Surface B: the box keeps its config and the API underneath it changes."""
    return compare_many(_product_of(appliance), target_version, objects,
                        source_version=_version_of(appliance))


__all__ = [
    "STATE_SAME", "STATE_OK", "STATE_DROPPED", "STATE_ABSENT", "STATE_BLIND",
    "STATE_UNMEASURED", "STATE_LABEL", "SEVERITY", "LEVEL_FOR", "META_FIELDS",
    "META_PREFIXES", "split_fields", "payload_fields", "compare_object",
    "compare_many", "worst", "for_clone", "for_upgrade",
    "cached_config_fields",
]
