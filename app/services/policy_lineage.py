"""Read/write side of the clone registry (:mod:`app.models_lineage`).

Two entry points: :func:`record` (called once per executed policy, from the ONE
real-execution call site in ``policy_ops``) and :func:`for_policies` (called
once per page render to feed the row badges).
"""
from __future__ import annotations

from ..extensions import db
from ..models_lineage import ACTIONS, PolicyCloneEvent

# NOTE: the human wording for each verb ("Cloned to", "Migrated to"…) lives in
# the TEMPLATE and nowhere else. A copy of those strings here would be a second
# author of the same phrase — the failure mode this repo has hit repeatedly —
# and would also produce msgids gettext cannot extract from a runtime value.


def record(*, src_appliance_id: int, src_policy: str, action: str,
           dst_appliance_id: int | None = None, dst_appliance: str = "",
           dst_policy: str = "", ok: bool = False, error: str = "",
           by: str = "", job_id: str = "") -> PolicyCloneEvent | None:
    """Write one event. Returns the row, or ``None`` if nothing was recorded.

    **Never raises.** This runs immediately after a call that has already
    touched the device; a bookkeeping failure must not turn a completed clone
    into a job error, because the copy exists either way and an exception here
    would report the opposite.
    """
    if action not in ACTIONS or not src_policy:
        return None
    ev = PolicyCloneEvent(
        src_appliance_id=src_appliance_id,
        src_policy=str(src_policy),
        action=action,
        dst_appliance_id=dst_appliance_id,
        dst_appliance=str(dst_appliance or "")[:256],
        dst_policy=str(dst_policy or "")[:256],
        ok=bool(ok),
        error=str(error or "")[:512],
        by=str(by or "")[:128],
        job_id=str(job_id or "")[:64],
    )
    try:
        db.session.add(ev)
        db.session.commit()
        return ev
    except Exception:  # noqa: BLE001 — see docstring
        db.session.rollback()
        return None


def for_policies(appliance_id: int, names) -> dict:
    """``{policy name: [event dict, ...]}`` for the rows on one page.

    ONE query for the whole page — a per-row lookup over ~750 policies is 750
    round-trips to render a badge that is empty on most of them. Names absent
    from the result are simply missing from the dict, so the template's
    ``.get(name)`` yields nothing and no badge is drawn.

    Newest first: the last thing that happened to a policy is the thing an
    operator standing in front of it is deciding about.
    """
    names = [str(n) for n in (names or []) if n]
    if not appliance_id or not names:
        return {}
    try:
        rows = (PolicyCloneEvent.query
                .filter(PolicyCloneEvent.src_appliance_id == appliance_id,
                        PolicyCloneEvent.src_policy.in_(names))
                .order_by(PolicyCloneEvent.at.desc(),
                          PolicyCloneEvent.id.desc())
                .all())
    except Exception:  # noqa: BLE001 — a cold/missing table never breaks the list
        return {}
    out: dict = {}
    for r in rows:
        out.setdefault(r.src_policy, []).append(as_dict(r))
    return out


def as_dict(r: PolicyCloneEvent) -> dict:
    """Render-ready shape. ``where`` is the one string the popover shows for a
    destination: a same-box clone has no other appliance to name, and printing
    the source's own name there reads as a cross-box copy that never happened.
    """
    same_box = r.action == "clone_here"
    return {
        "action": r.action,
        "where": "" if same_box else (r.dst_appliance or "—"),
        "same_box": same_box,
        "dst_policy": r.dst_policy or "",
        "ok": bool(r.ok),
        "error": r.error or "",
        "at": r.at.strftime("%Y-%m-%d %H:%M") if r.at else "",
        "by": r.by or "—",
    }


def ok_count(events) -> int:
    """How many of ``events`` actually landed. The badge counter uses this, not
    ``len()``: a failed attempt is worth showing in the popover and worth NOT
    counting as a copy that exists."""
    return sum(1 for e in (events or []) if e.get("ok"))
