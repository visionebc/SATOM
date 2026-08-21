"""New, compare and decide — the third Web Protection Profile policy.

The first two are non-interactive: copy the subtree, or leave an existing
profile strictly alone. This is the one that EDITS A LIVE PROFILE ON PURPOSE,
so nothing here is ever pre-ticked and the pre-flight says WARN, never ok.

WHAT THE PLANNER ALREADY DID, AND WHAT IT DID NOT
    Sub-table rows were already compared: ``create`` = missing at the
    destination, ``update`` = same key, different content, ``exists`` = equal.
    What was NOT compared is the profile OBJECT ITSELF — an existing one is
    classified ``exists`` and never asked another question, so a profile whose
    ~40 lists all match but whose own switches differ reads as identical and is
    not.

⚠ THE SLICE IS BACKWARDS, AND THAT IS THE WHOLE FUNCTION
    The plan is POST-ORDER: every referenced object is emitted BEFORE the object
    that names it, because a clone must create a dependency first. Measured on a
    real plan (fortiweb12 -> fortiweb13, ``pol-root-shop``):

        Web Protection Profile   #125  depth 1
        root Server Policy       #126  depth 0
        walking BACK while depth > 1   -> 111 items
        scanning FORWARD from #125     ->   1 item

    A forward scan is what the standalone shipped for four releases. It does not
    fail — it SUB-REPORTS, and sub-reporting reads exactly like agreement: the
    comparison offered the profile's own fields and nothing else, and declining
    everything declined almost nothing.

    The bound is DEPTH, not a position guess: in post-order a node's descendants
    are exactly the contiguous run before it that is deeper than it. The item
    before the run here is a Replacement Message Group at the same depth — a
    sibling, correctly excluded.

WHY THE DECISION TRAVELS IN ``opts`` AND NOT IN A PERSISTED PLAN
    The pre-flight already runs synchronously inside the request. So the phases
    are: analyse (in-request, read-only) -> the operator answers -> apply. The
    apply RE-PLANS, which means a decision cannot be an index into a list that
    no longer exists. Every offer is addressed by a stable KEY built from what
    identifies it on the appliance, and a re-plan that offers something the
    decision set does not cover REFUSES rather than guessing.

    Refusing is the only honest end. "Never shown, so skip it" writes nothing
    the operator saw and calls the run green; "never shown, so take it" writes
    something the operator never saw at all.
"""
from __future__ import annotations

from typing import Iterable

from .fortiweb_ops import sanitize_payload as clean_for_write


def item_key(it) -> str:
    """A stable identity for one plan item, across two plans of the same pair.

    Built from what identifies the thing ON THE APPLIANCE — collection, key,
    parent and kind — never from its position. An index would be silently wrong
    the first time the source gained a row between analyse and apply, and the
    operator would have ticked one change and applied another.
    """
    return "|".join((str(getattr(it, "urn", "")),
                     str(getattr(it, "mkey", "")),
                     str(getattr(it, "parent_mkey", "")),
                     str(getattr(it, "kind", ""))))


def wpp_subtree(items: list, wpp=None) -> list:
    """The profile object and everything under it, ending AT the profile.

    Walks BACKWARDS from the profile while the depth is greater than its own —
    see the module docstring for the measurement that makes this the only
    correct direction.
    """
    from .clone import _WPP_URNS

    if wpp is None:
        wpp = next((it for it in items
                    if it.urn in _WPP_URNS and it.kind == "object"), None)
    if wpp is None:
        return []
    try:
        idx = items.index(wpp)
    except ValueError:
        return []
    j = idx - 1
    while j >= 0 and items[j].depth > wpp.depth:
        j -= 1
    return items[j + 1: idx + 1]


def object_field_diff(src_payload: dict, dst_row: dict) -> list:
    """``[(field, destination value, source value)]`` for a profile object.

    Both sides go through the WRITE sanitizer first, so read-only and volatile
    keys are gone before anything is called a difference. Only fields the SOURCE
    carries are compared: a destination object legitimately holds defaults the
    source never named, and reporting those would bury the one line that matters
    under twenty that do not.
    """
    a = clean_for_write(dict(src_payload or {}))
    b = clean_for_write(dict(dst_row or {}))
    out = []
    for f in sorted(a):
        if f in ("name", "id", "_id"):
            continue
        sv, dv = a.get(f), b.get(f)
        if str(sv or "") != str(dv or ""):
            out.append((f, dv, sv))
    return out


def offers(items: list, dst_reader) -> list:
    """Every change this run would make INSIDE an existing destination profile.

    Returns ``[{key, kind, label, action, detail, fields}]`` — ``kind`` is
    ``object`` for the profile's own fields and ``subrow`` for a row.

    Empty when the profile is not already at the destination: there is nothing
    to compare and nothing to decide, and offering "create the whole thing"
    as a checklist would make a routine copy look like a merge.
    """
    from .clone import _WPP_URNS

    wpp = next((it for it in items
                if it.urn in _WPP_URNS and it.kind == "object"), None)
    if wpp is None or wpp.status != "exists":
        return []
    out: list = []
    dst_row = {}
    try:
        rows = dst_reader.get_raw(wpp.urn, wpp.mkey)
        dst_row = rows[0] if rows else {}
    except Exception:  # noqa: BLE001
        dst_row = {}
    fields = object_field_diff(wpp.payload, dst_row)
    if fields:
        out.append({
            "key": item_key(wpp), "kind": "object", "label": wpp.label,
            "action": "retune", "urn": wpp.urn, "mkey": wpp.mkey,
            "detail": "; ".join("%s: %s -> %s"
                                % (f, d or "(blank)", s or "(blank)")
                                for f, d, s in fields[:6]),
            "fields": [{"field": f, "destination": d, "source": s}
                       for f, d, s in fields],
        })
    for it in wpp_subtree(items, wpp):
        if it is wpp or it.status not in ("create", "update"):
            continue
        out.append({
            "key": item_key(it), "kind": it.kind, "label": it.label,
            "action": "add" if it.status == "create" else "change",
            "urn": it.urn, "mkey": it.mkey, "parent": it.parent_mkey,
            "detail": it.note or "", "fields": [],
        })
    return out


def object_update_payload(src_payload: dict, dst_row: dict) -> dict:
    """The MINIMAL EDIT: the destination object with the source's non-empty
    fields laid over it.

    A bare source payload would blank every destination field the source never
    named. And a blank in the SOURCE means "this appliance does not use this
    field", not "erase whatever the other one has" — the distinction is the
    reason this is a merge and not a replacement.

    The NAME comes from the destination and is never overwritten: it is what the
    URL addresses, and a body renaming the object mid-PUT is a different
    operation wearing this one's name.
    """
    dst = clean_for_write(dict(dst_row or {}))
    src = clean_for_write(dict(src_payload or {}))
    # ``out`` STARTS as the destination row, so the destination's own name and
    # id are already in it, and the loop below skips those keys. Restoring them
    # afterwards would be a second safeguard over the same hole — and with an
    # unreadable destination it would restore nothing either.
    out = dict(dst)
    for f, v in src.items():
        if f in ("name", "id", "_id"):
            continue
        if v in (None, ""):
            continue
        out[f] = v
    return out


class StaleDecision(RuntimeError):
    """The re-planned run offers something the decision set never covered."""


def apply_decisions(items: list, accepted: Iterable[str],
                    shown: Iterable[str]) -> dict:
    """Keep the accepted offers, DROP the rest, refuse anything never shown.

    ``accepted`` and ``shown`` both come from the operator's answer. The
    distinction is the point:

      * shown and ticked   -> kept
      * shown and unticked -> REMOVED FROM THE PLAN, not skipped. An item left
        in saying ``create`` describes a write that will not happen, and every
        counter, report and verification reads the plan.
      * never shown        -> :class:`StaleDecision`. The source changed between
        analyse and apply, so the answer no longer covers the run.

    The one exception: a profile OBJECT whose fields were declined is degraded
    to ``exists`` and KEPT. The rows beneath it are addressed through it, so
    removing it would take them with it.
    """
    from .clone import _WPP_URNS

    accepted, shown = set(accepted or ()), set(shown or ())
    wpp = next((it for it in items
                if it.urn in _WPP_URNS and it.kind == "object"), None)
    if wpp is None or wpp.status != "exists":
        return {"kept": 0, "dropped": 0, "retuned": False}
    block = wpp_subtree(items, wpp)
    unknown = [it for it in block
               if it is not wpp and it.status in ("create", "update")
               and item_key(it) not in shown]
    if unknown:
        raise StaleDecision(
            "the plan now offers %d change(s) this decision never covered "
            "(%s%s) — re-run the comparison before applying"
            % (len(unknown),
               ", ".join(u.label for u in unknown[:4]),
               "…" if len(unknown) > 4 else ""))
    kept = dropped = 0
    keep: list = []
    for it in items:
        # NOT also `or it is wpp`: at this point the profile object is still
        # ``exists``, so the status branch below already keeps it, and its own
        # status is only rewritten AFTER this loop. A second guard for the same
        # case would make neither of them demonstrable.
        if it not in block or it.status not in ("create", "update"):
            keep.append(it)
            continue
        if item_key(it) in accepted:
            kept += 1
            keep.append(it)
        else:
            dropped += 1
    retuned = item_key(wpp) in accepted
    if retuned:
        wpp.status = "obj-update"
        wpp.note = "the operator accepted the source's values for this profile"
    else:
        wpp.status = "exists"
        wpp.note = ("left as the destination has it — the operator declined "
                    "its fields")
    items[:] = keep
    return {"kept": kept, "dropped": dropped, "retuned": retuned}
