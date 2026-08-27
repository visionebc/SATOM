"""Lifecycle control for a carve-out: what deleting it would cost, and what
the safe alternative is.

The old ``purge`` was a verb with no question in front of it: name a Server
Policy, and every carve-out bound to it was unbound or dropped. That is fine
when a carve-out belongs to one policy and wrong the moment it does not —
because a carve-out is authored against a **Web Protection Profile**, and a
profile is usually SHARED. Deleting it to clean up policy A silently removes
the waiver policy B has been relying on, and nothing anywhere records that B
ever depended on it.

So this module refuses to delete and offers to **split** instead. Three rules,
all of them the operator's:

1. **A carve-out bound to more than one Server Policy cannot be deleted** —
   it can be CLONED so each policy owns its own copy, after which the copy
   belonging to the departing policy is deletable on its own terms.
2. **Deleting a Server Policy deletes its carve-outs** — but only the ones that
   would be left bound to nothing. A carve-out that still serves another policy
   survives with that policy's binding, and the change is versioned.
3. **Everything here is versioned before it happens.** A refusal costs nothing;
   an approved split or delete leaves a lineage that :mod:`exception_versions`
   can restore.

Nothing in this module contacts a device. Blast radius on the DEVICE side (is
the profile shared on the box?) comes from :mod:`wpp_scope`, which says
``unknown`` rather than "safe" when the appliance cannot be read — and an
unknown is treated here as a reason to refuse, not as a reason to proceed.
"""
from __future__ import annotations

from typing import Any

from ..models import WppException, db
from . import exception_versions as versions
from . import wpp_exceptions as store

#: Verdicts a delete request can get back. Closed set so the badge palette and
#: the branch logic cannot drift apart.
ALLOW = "allow"            # one policy (or none) — deleting costs nobody else
SPLIT = "split-required"   # several policies — clone first, then delete a copy
REVIEW = "review"          # shared profile / unreadable device — a human decides
VERDICTS = (ALLOW, SPLIT, REVIEW)

VERDICT_LABEL = {
    ALLOW: "Safe to delete",
    SPLIT: "Cannot delete — clone per policy first",
    REVIEW: "Needs review before deleting",
}


def impact(exc, *, bindings: dict[str, str] | None = None,
           siblings: bool = True) -> dict[str, Any]:
    """What deleting *exc* would take away, and from whom.

    ``bindings`` is the live ``{server_policy: wpp}`` map when the caller has
    one. It is OPTIONAL and its absence is reported as ``device_known=False``
    rather than filled with an assumption: "we could not read the box" and "the
    profile is not shared" are the same empty dict and mean opposite things.
    """
    policies = list(exc.policy_names)
    wpp = exc.wpp_mkey or ""

    # Everything else authored against the SAME profile on this scope. Deleting
    # this row does not touch them, but an operator cleaning up a profile needs
    # to know they exist before concluding the profile is now carve-out free.
    others: list[dict] = []
    if siblings and wpp:
        for sib in store.list_exceptions(exc.appliance_id):
            if sib.id != exc.id and sib.wpp_mkey == wpp:
                others.append({"id": sib.id, "name": sib.name or "",
                               "exc_type": sib.exc_type,
                               "policies": sib.policy_names})

    device_known = bindings is not None
    shared_with: list[str] = []
    if device_known and wpp:
        # Every policy the DEVICE says binds this profile — not just the ones
        # somebody remembered to record here. The gap between the two is the
        # whole reason a carve-out on a shared profile is dangerous.
        shared_with = sorted(p for p, w in (bindings or {}).items()
                             if w == wpp and p not in policies)

    if len(policies) > 1:
        verdict = SPLIT
    elif not device_known and wpp:
        verdict = REVIEW
    elif shared_with:
        verdict = REVIEW
    else:
        verdict = ALLOW

    reasons: list[str] = []
    if len(policies) > 1:
        reasons.append(
            'This carve-out is authored for %d Server Policies (%s). Deleting '
            'it removes the waiver from all of them at once. Clone it so each '
            'policy owns its own copy, then delete only the one you meant.'
            % (len(policies), ", ".join('"%s"' % p for p in policies)))
    if shared_with:
        reasons.append(
            'Web Protection Profile "%s" is also bound by %s on the appliance. '
            'Whatever this carve-out does, it does for those policies too — '
            'and removing it changes their behaviour without them appearing '
            'anywhere in this record.'
            % (wpp, ", ".join('"%s"' % p for p in shared_with[:6])))
    if not device_known and wpp:
        reasons.append(
            'SATOM has not read the appliance, so it cannot prove that "%s" is '
            'bound by this policy alone. An unproven exclusive is not an '
            'exclusive.' % wpp)

    return {
        "exc_id": exc.id,
        "name": exc.name or "",
        "exc_type": store.canonical_type(exc.exc_type),
        "wpp_mkey": wpp,
        "policies": policies,
        "policy_count": len(policies),
        "shared_with": shared_with,
        "device_known": device_known,
        "siblings_on_profile": others,
        "verdict": verdict,
        "verdict_label": VERDICT_LABEL[verdict],
        "can_delete": verdict == ALLOW,
        "can_clone": len(policies) > 1,
        "versioned": bool(exc.lineage),
        "reasons": reasons,
    }


def split_by_policy(exc, *, author: str = "") -> dict[str, Any]:
    """Turn one multi-policy carve-out into one carve-out PER policy.

    The remedy behind the SPLIT verdict. The original is not deleted and not
    left half-bound: it keeps the FIRST policy and the rest become independent
    copies, so at no point does a policy lose its waiver — which a
    delete-then-recreate would do, for as long as the operation takes.

    Every copy carries its OWN lineage. Sharing one would make a rollback on
    the copy for policy B rewrite the carve-out policy A depends on, which is
    the exact coupling the split exists to remove.
    """
    policies = list(exc.policy_names)
    if len(policies) < 2:
        return {"ok": False, "error": "nothing to split — this carve-out is "
                                      "bound to fewer than two policies"}
    keep, rest = policies[0], policies[1:]
    made: list[dict] = []
    for pol in rest:
        copy = store.add(
            exc.appliance_id, wpp_mkey=exc.wpp_mkey,
            exc_type=exc.exc_type, payload=exc.payload_dict,
            name=("%s (%s)" % (exc.name, pol)) if exc.name else "",
            reason=exc.reason or "", author=author, policies=[pol],
            category=exc.category,
            # The copies join the SAME library item where one exists: they are
            # one intent placed several times, which is precisely what the
            # library models. Only the version lineage is private.
            library_uid=exc.library_uid,
            version_action=versions.ACT_CLONE,
            version_note='split from carve-out #%d for policy "%s"' % (exc.id, pol))
        made.append({"id": copy.id, "policy": pol, "lineage": copy.lineage})

    store._set_policies(exc, [keep])
    versions.record(exc, action=versions.ACT_UPDATE, author=author,
                    note="split: kept policy \"%s\", %d copies created"
                         % (keep, len(made)))
    db.session.commit()
    return {"ok": True, "kept": {"id": exc.id, "policy": keep},
            "created": made}


def guarded_delete(exc, *, author: str = "", acknowledge: bool = False,
                   bindings: dict[str, str] | None = None) -> dict[str, Any]:
    """Delete *exc*, but only when the impact report says it costs nobody else.

    A ``REVIEW`` verdict can be overridden with ``acknowledge`` — a human has
    read the reasons and taken the decision. ``SPLIT`` cannot: the remedy exists
    and is not destructive, so letting an acknowledgement bypass it would make
    the safer path the one nobody takes.
    """
    rep = impact(exc, bindings=bindings)
    if rep["verdict"] == SPLIT:
        return {"ok": False, "code": 409, "impact": rep,
                "error": rep["reasons"][0] if rep["reasons"] else
                         "clone per policy before deleting"}
    if rep["verdict"] == REVIEW and not acknowledge:
        return {"ok": False, "code": 409, "impact": rep,
                "needs_acknowledge": True,
                "error": "This delete needs an explicit acknowledgement."}
    lineage = exc.lineage
    store.delete(exc.id, author=author,
                 note="guarded delete (%s)" % rep["verdict"])
    return {"ok": True, "impact": rep, "lineage": lineage,
            "restorable": bool(lineage)}


def on_server_policy_deleted(appliance_id: int, server_policy: str, *,
                             author: str = "", apply: bool = False
                             ) -> dict[str, Any]:
    """The cascade the operator asked for: a Server Policy dies, its carve-outs
    die with it — but ONLY the ones left bound to nothing.

    Dry-run by default. A cascade that fires without a preview is how a shared
    carve-out disappears alongside a policy that merely happened to reference
    it; the preview names every row and says which way it will go.
    """
    doomed: list[dict] = []
    kept: list[dict] = []
    for exc in store.list_exceptions(appliance_id):
        names = list(exc.policy_names)
        if server_policy not in names:
            continue
        rest = [p for p in names if p != server_policy]
        row = {"id": exc.id, "name": exc.name or "",
               "exc_type": store.canonical_type(exc.exc_type),
               "wpp_mkey": exc.wpp_mkey or "", "remaining": rest,
               "lineage": exc.lineage or ""}
        (kept if rest else doomed).append(row)

    if apply:
        # delete_for_policy already unbinds-or-deletes AND versions both
        # outcomes. Re-implementing the walk here would be a second author for
        # the rule, and the two would drift on the first change.
        store.delete_for_policy(appliance_id, server_policy)

    return {"ok": True, "applied": bool(apply), "server_policy": server_policy,
            "to_delete": doomed, "to_unbind": kept,
            "deleted": len(doomed), "unbound": len(kept),
            "summary": "%d carve-out(s) would be deleted, %d unbound"
                       % (len(doomed), len(kept))}


def clone_for_policy(exc, policy: str, *, author: str = "") -> dict[str, Any]:
    """One copy of *exc* dedicated to *policy*, leaving the original alone.

    The single-policy version of :func:`split_by_policy`, for the operator who
    wants a private copy before editing rather than a full split.
    """
    pol = (policy or "").strip()
    if not pol:
        return {"ok": False, "error": "a server policy is required"}
    copy = store.add(
        exc.appliance_id, wpp_mkey=exc.wpp_mkey, exc_type=exc.exc_type,
        payload=exc.payload_dict,
        name=("%s (%s)" % (exc.name, pol)) if exc.name else "",
        reason=exc.reason or "", author=author, policies=[pol],
        category=exc.category, library_uid=exc.library_uid,
        version_action=versions.ACT_CLONE,
        version_note="cloned from carve-out #%d" % exc.id)
    return {"ok": True, "id": copy.id, "lineage": copy.lineage, "policy": pol}


__all__ = [
    "ALLOW", "SPLIT", "REVIEW", "VERDICTS", "VERDICT_LABEL",
    "impact", "split_by_policy", "guarded_delete", "clone_for_policy",
    "on_server_policy_deleted",
]
