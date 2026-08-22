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


def _names_one_of(payload, names: Iterable[str]) -> list:
    """The fields of ``payload`` whose value is exactly one of ``names``.

    Only scalar, non-empty fields are looked at (:func:`clone._content_keys`),
    which is precisely what a FortiWeb reference field is: the NAME of another
    object written into a field of this one. Matching BY VALUE and not against a
    hand-kept table of field names is deliberate — the field naming a Custom
    Response is not called what the field naming a signature set is called, and
    a table of those names would be a second author for a fact the payload
    already states. ``id`` and lists are excluded by contract: an auto-assigned
    row id that happens to equal a declined object's name is not a reference,
    and a list field is re-pointed name by name elsewhere.
    """
    from .clone import _content_keys

    wanted = set(names or ())
    if not isinstance(payload, dict) or not wanted:
        return []
    return [k for k in _content_keys(payload)
            if str(payload.get(k, "")) in wanted]


def keep_original_fields(items: list, declined: Iterable[str]) -> list:
    """Un-write every field on a KEPT item that NAMES a declined section.

    Returns ``[(label, field, kept_value)]`` in plan order.

    ⚠ THIS IS THE HALF OF "DECLINE" THAT NOTHING DID, and its absence is why a
    decline could look like it had been ignored. Declining a section removed the
    object from the plan — but the profile that NAMES it was still written with
    the SOURCE's value for that field, so the destination ended up naming a
    sub-policy that box does not have. A FortiWeb answers such a write by
    seating a default of its own, so the operator who asked to keep the
    destination's original got NEITHER tree: not the destination's setting, and
    not the source's.

    The field is restored to what the destination reads TODAY (``dst_row``) and
    never to a blank. A blank is a third outcome nobody chose, and on this
    firmware an empty reference field is not "no profile" — it is an unparsable
    one.

    Narrow on purpose: only names declined inside THIS profile subtree are
    matched. Anything wider would revert fields nobody was asked about.
    """
    # No early-out for an empty ``declined``. :func:`_names_one_of` already
    # answers "nothing was declined" with an empty list for every item, and a
    # second guard over the same hole makes BOTH unprovable — removing either
    # breaks nothing, which is indistinguishable from a guard that never worked.
    wanted = set(declined or ())
    out: list = []
    for it in items:
        if it.status not in ("obj-update", "update"):
            continue
        if not isinstance(it.payload, dict):
            continue
        hit = _names_one_of(it.payload, wanted)
        if not hit:
            continue
        dst = it.dst_row if isinstance(it.dst_row, dict) else {}
        payload = dict(it.payload)
        for k in hit:
            keep = str(dst.get(k, ""))
            payload[k] = keep
            out.append((it.label, k, keep))
        it.payload = payload
        it.note = ((it.note + " · ") if it.note else "") + (
            "keeping the destination's own %s (the section it names was "
            "declined)" % ", ".join(hit))
    return out


class StaleDecision(RuntimeError):
    """The re-planned run offers something the decision set never covered."""


def apply_decisions(items: list, accepted: Iterable[str],
                    shown: Iterable[str], dst_reader=None) -> dict:
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

    ``dst_reader`` is what the destination's own values are read back from when
    a decline has to be honoured in a field (see :func:`keep_original_fields`)
    and when an accepted retune needs the minimal-edit body. One reader, fetched
    once, here — because the revert and the write must not disagree about what
    the destination currently holds.
    """
    from .clone import _WPP_URNS

    accepted, shown = set(accepted or ()), set(shown or ())
    wpp = next((it for it in items
                if it.urn in _WPP_URNS and it.kind == "object"), None)
    if wpp is None or wpp.status != "exists":
        return {"kept": 0, "dropped": 0, "retuned": False,
                "reverted": [], "cascaded": []}
    block = wpp_subtree(items, wpp)
    # Membership by IDENTITY, never by ``==``: ``CloneItem`` is a dataclass, so
    # two rows that happen to carry equal fields compare equal, and a value
    # test would pull an item outside the profile subtree into a decision
    # nobody was asked about.
    scope = {id(it) for it in block}
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
    declined_items: list = []
    for it in items:
        # NOT also `or it is wpp`: at this point the profile object is still
        # ``exists``, so the status branch below already keeps it, and its own
        # status is only rewritten AFTER this loop. A second guard for the same
        # case would make neither of them demonstrable.
        if id(it) not in scope or it.status not in ("create", "update"):
            keep.append(it)
            continue
        if item_key(it) in accepted:
            kept += 1
            keep.append(it)
        else:
            dropped += 1
            declined_items.append(it)
    retuned = item_key(wpp) in accepted
    if retuned:
        wpp.status = "obj-update"
        wpp.note = "the operator accepted the source's values for this profile"
        # The DESTINATION row, fetched HERE and once, so the minimal-edit body
        # and any field this decline has to put back read the same snapshot.
        if dst_reader is not None and not wpp.dst_row:
            try:
                rows = dst_reader.get_raw(wpp.urn, wpp.mkey)
                wpp.dst_row = rows[0] if rows else {}
            except Exception:  # noqa: BLE001 — an unreadable destination
                wpp.dst_row = {}   # reverts to blank-safe, never to the source
    else:
        wpp.status = "exists"
        wpp.note = ("left as the destination has it — the operator declined "
                    "its fields")

    # -- honouring the decline in the fields that NAME it ---------------------
    # A declined section is not merely an item struck from a list: everything
    # still in the plan that NAMED it has to stop naming it, or half the
    # decline is honoured and the missing half is the half that WRITES.
    #
    # Two repairs, because a surviving item is in one of two situations and
    # only one of them has an original to keep:
    #
    #   * it EXISTS at the destination (an accepted retune, or a keyed row being
    #     reconciled) -> the field goes back to the destination's own value.
    #   * it is itself a CREATE -> there is no destination value to keep, and
    #     writing it would name an object that is not going to exist (-651). It
    #     is dropped too, TRANSITIVELY, and named in the report. Never written,
    #     and never silently blanked.
    #
    # ⚠ A CREATE reaches a declined object by TWO different routes, and only one
    # of them is visible in a payload. A sub-table row does not NAME its parent
    # in a field — it is addressed by ``parent_mkey``, so a row whose parent
    # object was declined matches nothing in ``_names_one_of`` and would sail
    # through as accepted. It would then be written with ``?mkey=`` pointing at
    # an object that is not going to exist. Both routes are followed here.
    declined_names = {str(it.mkey) for it in declined_items
                      if it.kind == "object" and str(it.mkey or "")}
    # Parenthood is matched on the PAIR (collection, key), never on the key
    # alone: a row's own urn is its parent's urn plus the child table, so two
    # unrelated objects that share a name in different collections cannot drag
    # each other's rows out of the plan.
    declined_parents = {(str(it.urn), str(it.mkey)) for it in declined_items
                        if it.kind == "object" and str(it.mkey or "")}
    cascaded: list = []
    while declined_names:
        more = []
        for it in keep:
            if id(it) not in scope or it.status != "create":
                continue
            named = _names_one_of(it.payload, declined_names)
            orphan = (it.kind == "subrow"
                      and any(str(it.urn).startswith(u + "/")
                              and str(it.parent_mkey or "") == m
                              for u, m in declined_parents))
            if named or orphan:
                more.append((it, named, orphan))
        if not more:
            break
        gone = {id(it) for it, _n, _o in more}
        for it, named, orphan in more:
            if named:
                why = ("it names %s, which you declined"
                       % ", ".join(sorted({str(it.payload.get(k, ""))
                                           for k in named})))
            else:
                why = ("its parent %s was declined and will not exist"
                       % str(it.parent_mkey or ""))
            it.note = ("not created: %s — the destination keeps what it has"
                       % why)
            cascaded.append(it)
            if it.kind == "object" and str(it.mkey or ""):
                declined_names.add(str(it.mkey))
                declined_parents.add((str(it.urn), str(it.mkey)))
        keep = [it for it in keep if id(it) not in gone]

    items[:] = keep
    reverted = keep_original_fields(items, declined_names)
    return {"kept": kept, "dropped": dropped + len(cascaded),
            "retuned": retuned,
            "cascaded": [{"label": it.label, "mkey": str(it.mkey or ""),
                          "why": it.note} for it in cascaded],
            "reverted": [{"label": l, "field": f, "destination": v}
                         for l, f, v in reverted]}
