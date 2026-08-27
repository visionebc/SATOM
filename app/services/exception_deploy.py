"""Take one carve-out authored in SATOM and place it on one or MANY FortiWebs.

The second half of the operator's ask: *author here, then push to one or
several appliances*. Until :mod:`models_exceptions` gave a carve-out an
identity this could only be copy-and-paste, because two placements of "the
same" carve-out had nothing tying them together.

The flow is two decisions, deliberately kept apart:

* **place** — write the desired state on the destination scope (a
  :class:`~models.WppException` row linked to the same library item). Costs
  nothing on any appliance and is fully reversible through the versioner.
* **push** — send it to the box. That is :mod:`exception_inject`, per
  destination, dry-run first.

Placing without pushing is a legitimate end state (the estate now RECORDS the
intent), which is why the two are not one button. Pushing without placing is
not offered: a row on a box that SATOM has no record of is exactly the drift
this product exists to remove.

**A destination is refused, never silently skipped.** Every scope in the
result carries a verdict and a reason, including the ones that are fine. A
deploy screen that lists only the eligible destinations cannot be audited: the
operator has no way to tell "not offered" from "not applicable".
"""
from __future__ import annotations

from typing import Any

from ..models import WppException
from . import exception_versions as versions
from . import waf_fleet
from . import wpp_exceptions as store

READY = "ready"              # can be placed here
DUPLICATE = "already-here"   # an identical carve-out is already on this scope
LOCKED = "template-locked"   # the destination profile is template-managed
NO_PROFILE = "no-profile"    # the named WPP does not exist on this scope
SOURCE = "source"            # this IS the scope the carve-out came from
VERDICTS = (READY, DUPLICATE, LOCKED, NO_PROFILE, SOURCE)

VERDICT_LABEL = {
    READY: "Ready to place",
    DUPLICATE: "Already has this carve-out",
    LOCKED: "Profile is template-managed",
    NO_PROFILE: "Profile not recorded on this scope",
    SOURCE: "Source scope",
}


def _content_key(exc_type: str, payload: dict) -> str:
    from . import exception_fleet
    return exception_fleet.fingerprint(exc_type, payload)


def targets(exc, user=None, *, known_profiles: dict[int, set] | None = None
            ) -> list[dict[str, Any]]:
    """Every visible FortiWeb scope, with a verdict for THIS carve-out.

    ``known_profiles`` maps ``appliance_id -> {wpp names}`` when the caller has
    harvested them. Absent, profile existence is reported as UNKNOWN and the
    scope stays ``ready`` — refusing a destination because SATOM has not looked
    would block a correct deploy on a missing snapshot rather than on a fact.
    """
    key = _content_key(exc.exc_type, exc.payload_dict)
    existing: dict[int, list[int]] = {}
    for row in WppException.query.all():
        if _content_key(row.exc_type, row.payload_dict) == key:
            existing.setdefault(row.appliance_id, []).append(row.id)

    out: list[dict] = []
    for appl in waf_fleet.fortiweb_scopes(user):
        profiles = (known_profiles or {}).get(appl.id)
        if appl.id == exc.appliance_id:
            verdict, why = SOURCE, "the carve-out was authored here"
        elif appl.id in existing:
            verdict, why = DUPLICATE, (
                "an identical carve-out is already recorded on this scope "
                "(#%s)" % ", #".join(str(i) for i in existing[appl.id]))
        elif store.template_lock_error(exc.wpp_mkey):
            # The lock is a property of the PROFILE NAME, so it refuses the
            # destination for the same reason it refuses the source: a
            # template-managed profile stays clean everywhere.
            verdict, why = LOCKED, store.template_lock_error(exc.wpp_mkey)
        elif profiles is not None and exc.wpp_mkey and exc.wpp_mkey not in profiles:
            verdict, why = NO_PROFILE, (
                'no Web Protection Profile named "%s" in the latest snapshot '
                "of this scope" % exc.wpp_mkey)
        else:
            verdict, why = READY, ""
        out.append({
            "appliance_id": appl.id,
            "scope": waf_fleet.scope_label(appl),
            "device": waf_fleet.device_name(appl),
            "verdict": verdict,
            "verdict_label": VERDICT_LABEL[verdict],
            "why": why,
            "profiles_known": profiles is not None,
            "existing_ids": existing.get(appl.id, []),
        })
    return out


def promote_to_library(exc, *, author: str = "") -> str:
    """Give *exc* a library identity so its copies can be recognised as its own.

    Idempotent. Called on the first deploy rather than at authoring time: a
    carve-out that only ever lives on one box does not need a library entry,
    and minting one for all thirteen legacy rows would fill the library with
    items nobody declared.
    """
    from ..models_exceptions import ExceptionLibraryItem, new_uid
    from ..models import db
    import json as _json
    if exc.library_uid:
        return exc.library_uid
    uid = new_uid()
    item = ExceptionLibraryItem(
        uid=uid, name=exc.name or "", exc_type=store.canonical_type(exc.exc_type),
        category=exc.category or store.category_for(exc.exc_type),
        payload=_json.dumps(exc.payload_dict), reason=exc.reason or "",
        author=author or exc.author or "")
    db.session.add(item)
    exc.library_uid = uid
    versions.record(exc, action=versions.ACT_UPDATE, author=author,
                    note="promoted to the fleet library")
    db.session.commit()
    return uid


def plan(exc, appliance_ids: list[int], user=None,
         known_profiles: dict[int, set] | None = None) -> dict[str, Any]:
    """What placing *exc* on each chosen scope would do. Writes nothing."""
    rows = {t["appliance_id"]: t for t in targets(exc, user,
                                                  known_profiles=known_profiles)}
    chosen: list[dict] = []
    refused: list[dict] = []
    for aid in appliance_ids:
        t = rows.get(int(aid))
        if t is None:
            # An id this session cannot see is refused with the SAME words as
            # one that does not exist. Whether an appliance exists is not this
            # session's business.
            refused.append({"appliance_id": int(aid), "scope": "(not visible)",
                            "verdict": NO_PROFILE,
                            "why": "not a FortiWeb scope this session can see"})
            continue
        (chosen if t["verdict"] == READY else refused).append(t)
    return {"ok": bool(chosen), "would_place": chosen, "refused": refused,
            "summary": "%d scope(s) would receive it, %d refused"
                       % (len(chosen), len(refused))}


def place(exc, appliance_ids: list[int], *, author: str = "", user=None,
          known_profiles: dict[int, set] | None = None) -> dict[str, Any]:
    """Write the carve-out as desired state on every eligible chosen scope.

    Refused destinations are reported, not skipped in silence. The library
    promotion happens ONCE, before the loop: doing it per destination would
    mint a fresh uid on each pass and the copies would not recognise each
    other — which is the entire point of placing rather than copying.
    """
    res = plan(exc, appliance_ids, user, known_profiles=known_profiles)
    if not res["would_place"]:
        return {"ok": False, "placed": [], "refused": res["refused"],
                "error": "no chosen scope can receive this carve-out"}
    uid = promote_to_library(exc, author=author)
    placed: list[dict] = []
    for t in res["would_place"]:
        copy = store.add(
            t["appliance_id"], wpp_mkey=exc.wpp_mkey, exc_type=exc.exc_type,
            payload=exc.payload_dict, name=exc.name or "",
            reason=exc.reason or "", author=author,
            # Policy bindings are NOT copied: a Server Policy name is a fact
            # about the SOURCE appliance, and carrying it over would assert a
            # binding on a box where that policy may not exist.
            policies=[], category=exc.category, library_uid=uid,
            version_action=versions.ACT_CLONE,
            version_note="placed from carve-out #%d (%s)"
                         % (exc.id, versions.scope_label(exc)))
        placed.append({"appliance_id": t["appliance_id"], "scope": t["scope"],
                       "id": copy.id, "lineage": copy.lineage})
    return {"ok": True, "library_uid": uid, "placed": placed,
            "refused": res["refused"],
            "note": "Placed as desired state. Nothing was sent to any "
                    "appliance — push each placement from its own scope.",
            # Said explicitly rather than left to the operator to notice: a
            # placement with no Server Policy is INCOMPLETE, and the fleet
            # inventory will show it as unbound until somebody binds it.
            "unbound": [p["id"] for p in placed]}


def push_plan(exc, target: str) -> dict[str, Any]:
    """The device-side preview for ONE placement. Thin delegation on purpose:
    :mod:`exception_inject` owns how a carve-out is written to a box, and a
    second planner here would be a second answer to the same question."""
    from . import exception_inject
    return exception_inject.plan_injection(exc.exc_type, exc.payload_dict, target)


__all__ = [
    "READY", "DUPLICATE", "LOCKED", "NO_PROFILE", "SOURCE", "VERDICTS",
    "VERDICT_LABEL", "targets", "plan", "place", "promote_to_library",
    "push_plan",
]
