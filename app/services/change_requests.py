"""Change-request orchestration for the Automation subsystem (maintenance windows).

A Change Request (CR) is the control record for a risky, windowed change - above
all a firmware UPGRADE: WHICH devices + server policies are affected (the clients
to warn), WHEN (the window), WHAT runs (the action + params), an APPROVAL gate,
and the bound one-shot :class:`ScheduledAction` that actually executes it inside
the window. The upgrade executor refuses to flash unless its CR is approved/
scheduled and the clock is INSIDE the window (:func:`cr_runnable`).

This module is HEADLESS (no Qt, no Flask views). It is a pure SQLAlchemy port of
the desktop ``change_requests`` service: the status workflow stamps a
``ChangeRequestEvent`` per transition, scheduling binds a ``ScheduledAction``, the
maintenance notice is plain text rendering, and affected-policy discovery is a
best-effort live read (the web has no local policy cache).

Import side-effect-free: importing this module touches no DB and contacts no
device.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from ..models import (Appliance, ChangeRequest, ChangeRequestEvent,
                      ScheduledAction, db)
from . import scheduler

# Convenience constants for the UI (the lifecycle itself lives on the model:
# ChangeRequest.STATUSES / ChangeRequest.TERMINAL).
RISKS = ("low", "medium", "high")

# A CR may fire only from one of these live states (terminal/draft cannot run).
_RUNNABLE_STATES = ("approved", "scheduled", "in_progress")

# Cap for the stored outcome blurb (result_summary is TEXT; this only stops an
# executor traceback from being pasted whole into the record).
_RESULT_MAX = 4000


# --------------------------------------------------------------------------- #
#  Status workflow (every transition stamps a timeline event)                   #
# --------------------------------------------------------------------------- #
def _transition(cr, status: str, by: str = "", detail: str = "", **fields) -> None:
    """Move ``cr`` to ``status``, set any extra ``fields``, append a
    :class:`ChangeRequestEvent`, and commit."""
    cr.status = status
    for key, value in fields.items():
        setattr(cr, key, value)
    db.session.add(ChangeRequestEvent(
        cr_id=cr.id, kind=status, by=by, detail=detail, ts=datetime.utcnow()))
    db.session.commit()


WINDOW_INVERTED = ("The maintenance window ends at or before it starts, so no "
                   "instant lies inside it and the change could never fire.")


def validate_window(start, end) -> str:
    """``""`` if this pair is a window a change could fire inside, else why not.

    THE one author of that rule. It was written inline in the create path, so
    every OTHER way of putting a window on a change - the edit form, a batched
    wave, a future calendar drag - was free to store one that can never contain
    an instant. CR-0011 is stored ending a DAY before it begins: nothing failed,
    it simply sits in 'approved' looking healthy and never runs.

    A half-open window (an end with no start, or neither) is NOT refused here:
    'no window yet' is a legal state for a draft, and the run-gate refuses it
    at fire time with a reason of its own.
    """
    if start is not None and end is not None and end <= start:
        return WINDOW_INVERTED
    return ""


def revoke_approval(cr_id, by: str, detail: str = "") -> bool:
    """Send an approved/scheduled CR back to ``draft`` and unbind its one-shot.

    Returns True if there was an approval to void. Used when an edit changes
    something the approver decided ON - the window above all: an approval is a
    human saying yes to a specific outage at a specific time, and silently
    carrying it over to a different time is forging that answer.

    Disabling the bound action is the load-bearing half. A one-shot fires at the
    window start it was BOUND with; :func:`cr_runnable` re-checks the CR's
    CURRENT window at fire time, so a stale action cannot run outside the new
    window - but with ``catch_up`` it CAN fire at an instant nobody scheduled,
    if the old start happens to fall inside the new window. Forcing an explicit
    re-Schedule is what makes the scheduler's answer to "when does this run"
    true again.

    The EXTERNAL approval is cleared too. Keeping it would leave a change
    carrying a foreign authority's yes over a window that authority never saw.
    """
    cr = db.session.get(ChangeRequest, cr_id) if not isinstance(
        cr_id, ChangeRequest) else cr_id
    if cr is None:
        raise ValueError("change request not found")
    if cr.status not in ("approved", "scheduled"):
        return False
    if cr.scheduled_action_id:
        action = db.session.get(ScheduledAction, cr.scheduled_action_id)
        if action is not None:
            action.enabled = False  # committed by _transition below
    _transition(cr, "draft", by=by,
                detail=detail or "Approval voided by an edit; re-approval required",
                approved_by="", approved_at=None,
                external_approved_at=None, external_approved_by="")
    return True


def approve(cr_id: int, by: str) -> ChangeRequest:
    """Approve a CR (stamps ``approved_by`` / ``approved_at``)."""
    cr = db.session.get(ChangeRequest, cr_id)
    if cr is None:
        raise ValueError("change request not found")
    # Freeze the change-type wording AS APPROVED. From here on the document
    # prints these words, not whatever Administration -> Change Types says
    # later. Best-effort: an approval is a decision a human made, and a failure
    # to photocopy the boilerplate must not be able to un-make it.
    try:
        from . import cr_types
        cr.doc_profile = json.dumps(cr_types.snapshot(cr.action))
    except Exception:  # noqa: BLE001
        pass
    _transition(cr, "approved", by=by, detail="Change request approved",
                approved_by=by, approved_at=datetime.utcnow())
    # Tell the integrations the gate is passed. Best-effort by contract: an
    # approval is a decision a human made in this product, and a downstream
    # system being unreachable must not be able to un-make it.
    from . import cr_orchestrator
    cr_orchestrator.announce_approved(cr, by=by)
    # A plan written down while this was still a draft is carried out HERE,
    # through the very call the Schedule button makes - one author of "bind
    # the rows". Attached to the returned object rather than flashed from
    # inside a headless service: this module has no request and no session,
    # and the view that asked for the approval is the one that has to say in
    # words what its click created.
    cr.rollout_outcome = materialize_rollout_plan(cr, by=by)
    return cr


def cancel(cr_id: int, by: str, reason: str = "") -> ChangeRequest:
    """Cancel a CR and disable its bound scheduled action (so it won't fire)."""
    cr = db.session.get(ChangeRequest, cr_id)
    if cr is None:
        raise ValueError("change request not found")
    if cr.scheduled_action_id:
        action = db.session.get(ScheduledAction, cr.scheduled_action_id)
        if action is not None:
            action.enabled = False  # committed by _transition below
    _transition(cr, "cancelled", by=by,
                detail=reason or "Change request cancelled")
    return cr


#: How many rounds one change's rollout may be split into. REFUSES naming the
#: number rather than quietly making fewer rounds than were asked for: a round
#: that silently disappeared takes its appliances out of the window without
#: anybody being told. Same rule as the batched-wave cap on the flow page.
MAX_ROUNDS = 24

#: Minutes between two consecutive rounds when the caller does not say. It is
#: never 0: rounds that all start at the same instant are not rounds, they are
#: the un-batched fire wearing a plan's name.
DEFAULT_ROUND_GAP_MINUTES = 60

#: Where a rollout plan lives while the change is still waiting for a
#: signature. A key of ``ChangeRequest.params``, STRIPPED again in
#: :func:`schedule_change_request` before those params are copied onto the
#: rows the executor fires: that dict is the executor's instruction sheet, and
#: a key it does not understand riding along into it is exactly how a setting
#: nobody honours ends up being carried by the thing that acts. The leading
#: underscore keeps it from ever colliding with a real executor parameter.
PLAN_KEY = "_rollout_plan"


def rollout_plan(cr) -> dict:
    """The plan saved against a change that is not schedulable yet, or ``{}``.

    Empty once the plan has BECOME scheduled rows: from that moment the rows
    are the only description of what was saved, and a leftover copy here
    would be a second author that drifts the first time a round is edited in
    Scheduled Actions.
    """
    if cr is None:
        return {}
    value = cr.params_dict.get(PLAN_KEY)
    return value if isinstance(value, dict) else {}


def plannable(cr) -> tuple[bool, str]:
    """``(ok, reason)`` - may a rollout PLAN be saved against this change now?

    Deliberately NOT :func:`schedulable`, and the difference is the whole
    point: deciding how many appliances go down at a time is a plan, binding
    scheduled rows to it is an execution, and only the second one needs a
    signature. Collapsing the two forced an approval before the blast radius
    could even be written down - the approver signed, and only then saw what
    they had approved.

    Everything that is NOT about the signature is still enforced here, because
    a plan this gate accepts is a plan approval will have to carry out.
    """
    if cr is None:
        return False, "change request not found"
    if cr.status in ChangeRequest.TERMINAL:
        return False, (f"this change is {cr.status}, so its rollout can no "
                       f"longer be planned")
    if cr.window_start is None:
        return False, "set a maintenance-window start first"
    # A change type an administrator defined has NO executor. Refusing the
    # PLAN as well as the schedule matters: a plan stored against one would be
    # carried out at approval, fail there, and leave an approved change whose
    # rollout silently does not exist.
    from . import scheduled_actions as _sa
    if _sa.get_spec(cr.action) is None:
        return False, (
            f"'{cr.action}' is a documentary change type: it has no automated "
            f"executor. Carry the work out during the window and close this "
            f"change request by hand.")
    return True, ""


def schedulable(cr) -> tuple[bool, str]:
    """``(ok, reason)`` - may this change be bound to a scheduled task NOW?

    THE one author of that question. The page that OFFERS the save and the
    call that performs it must agree about it: a control offered over a change
    that cannot be scheduled teaches the operator that scheduling is broken,
    and one withheld from a change that can is a feature nobody can reach.
    Two spellings of this test is exactly how the NetBox button came to be
    live for appliances its own backend could not act on.
    """
    if cr is None:
        return False, "change request not found"
    if cr.status not in ("approved", "scheduled"):
        return False, "approve the change request before scheduling it"
    if cr.window_start is None:
        return False, "set a maintenance-window start first"
    # A change type an administrator defined has NO executor. Binding one to a
    # scheduled action would not fail here - it would fail at fire time, inside
    # the window, resolving to nothing and closing the change as failed hours
    # after anybody could act on it. Refuse while somebody is still looking.
    from . import scheduled_actions as _sa
    if _sa.get_spec(cr.action) is None:
        return False, (
            f"'{cr.action}' is a documentary change type: it has no automated "
            f"executor. Carry the work out during the window and close this "
            f"change request by hand.")
    return True, ""


def round_slices(device_ids, per_round) -> list[list]:
    """Split a change's appliances into rounds of at most ``per_round``.

    ``None``, 0, or a size that already covers everything give ONE round
    holding the whole list - which is precisely the un-batched change this
    product has always scheduled, so the default path is unchanged.

    Deterministic and clock-free on purpose: the arithmetic that decides which
    box goes down at 22:00 and which at 23:00 is the part that has to be
    assertable without a database, a request or a clock.
    """
    ids = list(device_ids or [])
    try:
        size = int(per_round or 0)
    except (TypeError, ValueError):
        size = 0
    if size < 1 or size >= len(ids):
        return [ids]
    return [ids[i:i + size] for i in range(0, len(ids), size)]


def round_siblings(cr_id: int) -> list:
    """Every EXTRA round row a change owns - round 2..N, never round 1.

    A change carries exactly ONE ``scheduled_action_id``, and rounds 2..N are
    deliberately not it. Without a way back to them, re-saving a plan would
    leave yesterday's rounds enabled and firing a second time against
    appliances the new plan had already moved - a duplicate reboot nobody
    ordered, from a page that reported success.

    Found by reading the params rather than by a column, because the binding
    the executor honours IS ``params['change_request_id']``: any other index
    could disagree with the thing that actually authorizes the fire.
    """
    out = []
    for row in ScheduledAction.query.all():
        p = row.params_dict
        if _as_int(p.get("change_request_id")) != cr_id:
            continue
        if (_as_int(p.get("round_index")) or 1) > 1:
            out.append(row)
    out.sort(key=lambda r: _as_int(r.params_dict.get("round_index")) or 0)
    return out


def plan_rounds(cr, per_round=None, round_gap_minutes=None):
    """``(rounds, starts, gap)`` for this change, or ``ValueError`` saying why
    this plan could not be carried out.

    THE one author of the round arithmetic and of its four refusals. A plan
    SAVED against a draft and a plan MATERIALISED at approval have to be
    judged by the same rules: a card that accepted a plan its own approval
    will later refuse would fail at the single moment nobody is watching, and
    leave an approved change whose rollout quietly does not exist.
    """
    rounds = round_slices(cr.device_ids_list, per_round)
    if len(rounds) > MAX_ROUNDS:
        raise ValueError(
            f"{len(cr.device_ids_list)} appliance(s) at {per_round} per round "
            f"is {len(rounds)} rounds; at most {MAX_ROUNDS} are scheduled at "
            f"once. Raise the appliances per round. Nothing was scheduled.")
    try:
        gap = int(round_gap_minutes or DEFAULT_ROUND_GAP_MINUTES)
    except (TypeError, ValueError):
        gap = DEFAULT_ROUND_GAP_MINUTES
    if len(rounds) > 1 and gap < 1:
        raise ValueError(
            "Rounds need at least one minute between them - starting them all "
            "at the same instant is the un-batched change under another name. "
            "Nothing was scheduled.")
    if cr.window_start is None:
        raise ValueError(
            "This change has no maintenance-window start, so no round has an "
            "hour to begin at. Set the window first. Nothing was scheduled.")

    starts = [cr.window_start + timedelta(minutes=gap * k)
              for k in range(len(rounds))]
    # A round that starts after the window closes is REFUSED here, not left to
    # be skipped at fire time: cr_runnable would answer "after the maintenance
    # window" at 02:00, to nobody, and those appliances would simply never be
    # touched while the plan on screen said they would be.
    if cr.window_end is not None and starts[-1] > cr.window_end:
        raise ValueError(
            f"{len(rounds)} rounds {gap} minute(s) apart would start the last "
            f"one at {_fmt_window(starts[-1])}, after this change's window "
            f"closes at {_fmt_window(cr.window_end)} - it would be refused at "
            f"fire time and those appliances would never be touched. Widen the "
            f"window, raise the appliances per round, or shorten the gap. "
            f"Nothing was scheduled.")
    return rounds, starts, gap


def save_rollout_plan(cr_id: int, by: str, per_round=None,
                      round_gap_minutes=None) -> dict:
    """Write the rollout plan onto the CHANGE itself and create nothing else.

    The honest half of "save" for a change nobody has signed: no
    :class:`ScheduledAction` row exists, so the executor has nothing to fire
    and the calendar has nothing to draw - which is precisely true of a plan
    that has not been approved. Saying "it is on the calendar" here would be
    a sentence the product could not keep.

    Judged by :func:`plan_rounds`, the same arithmetic approval will use.
    """
    cr = db.session.get(ChangeRequest, cr_id)
    if cr is None:
        raise ValueError("change request not found")
    ok, why = plannable(cr)
    if not ok:
        raise ValueError(why)
    rounds, _starts, gap = plan_rounds(cr, per_round, round_gap_minutes)
    try:
        size = int(per_round or 0)
    except (TypeError, ValueError):
        size = 0
    plan = {"size": size, "gap": gap, "total": len(rounds), "by": by,
            "at": datetime.utcnow().isoformat(timespec="seconds")}
    params = dict(cr.params_dict)
    params[PLAN_KEY] = plan
    cr.params = json.dumps(params)
    # Stamped on the timeline, NOT as a status transition: the change has not
    # moved: it is still a draft waiting for the same signature it was waiting
    # for a second ago. A plan that changed the status would read, on the
    # approver's screen, as work that had already begun.
    db.session.add(ChangeRequestEvent(
        cr_id=cr.id, kind="rollout_planned", by=by,
        detail=(f"Rollout plan saved: {len(rounds)} round(s) of at most "
                f"{size} appliance(s), {gap} minute(s) apart. Nothing is "
                f"scheduled until this change is approved."),
        ts=datetime.utcnow()))
    db.session.commit()
    return plan


def materialize_rollout_plan(cr, by: str) -> dict:
    """Turn a saved plan into the real scheduled rows. ``{}`` when the change
    carries no plan.

    Never raises, and that is deliberate: this runs immediately AFTER an
    approval has been committed. An approval is a decision a human made, and a
    rollout that cannot be bound - a window that moved, a round count that no
    longer fits - must not be able to un-make it. On failure the plan STAYS on
    the change, so the operator can widen the window and press Save again
    instead of re-deriving a plan the product threw away.

    Returns ``{"action_id": int, "plan": {...}}`` or ``{"error": str,
    "plan": {...}}``.
    """
    plan = rollout_plan(cr)
    if not plan:
        return {}
    try:
        action_id = schedule_change_request(
            cr.id, by, per_round=plan.get("size"),
            round_gap_minutes=plan.get("gap"))
    except Exception as exc:  # noqa: BLE001 - see docstring
        db.session.rollback()
        return {"error": str(exc), "plan": plan}
    return {"action_id": action_id, "plan": plan}


def schedule_change_request(cr_id: int, by: str, per_round=None,
                            round_gap_minutes=None) -> int:
    """Bind the ``once`` scheduled action(s) that carry out this change and move
    the CR to ``scheduled``. Returns the id of the FIRST round's action - the
    one bound back to the change.

    Requires an approved (or already scheduled) CR with a window start. Every
    created action carries ``change_request_id`` in its params so the executor
    re-checks approval + window at fire time (:func:`cr_runnable`).

    ``per_round`` splits the change's appliances into rounds: one round is one
    fire of the executor against its own slice, ``round_gap_minutes`` apart.
    Left out (or large enough to cover everything) this is byte-for-byte the
    single action this function has always created - the batched shape is
    additive, so nothing that scheduled a change before behaves differently.

    Why rounds are separate ACTIONS and not a parameter of one: the executor
    runs an action's targets straight through in a single fire
    (``scheduled_actions._run_targets``). A round size stored as a number the
    executor never reads would be a setting that lies - the page would promise
    twenty-five boxes at a time while sixty rebooted at once.
    """
    cr = db.session.get(ChangeRequest, cr_id)
    if cr is None:
        raise ValueError("change request not found")
    ok, why = schedulable(cr)
    if not ok:
        raise ValueError(why)

    rounds, starts, gap = plan_rounds(cr, per_round, round_gap_minutes)

    # Yesterday's extra rounds go BEFORE the new ones are written. A round
    # whose slice moved is a fire against boxes the new plan already covers.
    stale = round_siblings(cr.id)
    live = [r for r in stale if r.running_at is not None]
    if live:
        raise ValueError(
            "Round " + ", ".join(str(_as_int(r.params_dict.get("round_index")))
                                 for r in live)
            + " of this change is running right now. Re-planning would delete "
              "the record of a fire that is in progress. Nothing was changed.")
    for row in stale:
        db.session.delete(row)

    # The saved PLAN never reaches the executor's parameters. That dict is
    # copied verbatim onto every round, and the executor reads it as its
    # instruction sheet; a bookkeeping key riding along into it is how a
    # setting nobody honours ends up being carried by the thing that fires.
    base = {k: v for k, v in cr.params_dict.items() if k != PLAN_KEY}
    base["change_request_id"] = cr.id

    first = None
    if cr.scheduled_action_id:
        first = db.session.get(ScheduledAction, cr.scheduled_action_id)
    if first is None:
        first = ScheduledAction(created_by=by)
        db.session.add(first)

    total = len(rounds)
    for index, (members, at) in enumerate(zip(rounds, starts), 1):
        row = first
        if index > 1:
            row = ScheduledAction(created_by=by)
            db.session.add(row)
        params = dict(base)
        if total > 1:
            params["round_index"] = index
            params["round_total"] = total
            params["round_size"] = int(per_round or 0)
            params["round_gap_minutes"] = gap
        schedule = {"at": at.isoformat()}
        # The suffix is RESERVED out of the 120-character budget rather than
        # appended and truncated away: "- round 3/6" is the only thing telling
        # two rounds apart in the automations list, and it is exactly the part
        # a blind truncation cuts.
        suffix = f" - round {index}/{total}" if total > 1 else ""
        row.name = f"CR #{cr.id}: {cr.title}"[:120 - len(suffix)] + suffix
        row.scope = "admin"
        row.action = cr.action
        row.targets = json.dumps(members)
        row.params = json.dumps(params)
        row.schedule_kind = "once"
        row.schedule = json.dumps(schedule)
        row.enabled = True
        row.catch_up = True
        row.next_run = scheduler.compute_next_run("once", schedule)
    db.session.flush()  # assign ids before binding the first one to the CR

    # The plan has BECOME the rows. Leaving a copy on the change would give
    # the card two authors for "what was saved", and they would disagree the
    # first time a round is edited in Scheduled Actions.
    stored = cr.params_dict
    if PLAN_KEY in stored:
        stored.pop(PLAN_KEY)
        cr.params = json.dumps(stored)

    detail = f"Scheduled for {_fmt_window(cr.window_start)}"
    if total > 1:
        detail += (f" in {total} rounds of at most {per_round} appliance(s), "
                   f"{gap} minute(s) apart")
    _transition(cr, "scheduled", by=by, detail=detail,
                scheduled_action_id=first.id)
    return first.id


# --------------------------------------------------------------------------- #
#  Execution transitions (written by the EXECUTOR, never by a human)            #
# --------------------------------------------------------------------------- #
def _resolve(cr_or_id):
    """Accept a ``ChangeRequest`` row or its id - the executor only holds the id
    it read out of the action params."""
    if isinstance(cr_or_id, ChangeRequest):
        return cr_or_id
    return db.session.get(ChangeRequest, _as_int(cr_or_id))


def start(cr_or_id, by: str = "scheduler", detail: str = ""):
    """Move a firing CR to ``in_progress``.

    Called by the executor only AFTER :func:`cr_runnable` authorized this fire,
    so a gated (skipped) fire never touches the CR: a window that never opened
    must not leave a record that looks like a change that started. Idempotent
    and terminal-safe - a CR already closed is returned untouched."""
    cr = _resolve(cr_or_id)
    if cr is None or cr.status in ChangeRequest.TERMINAL:
        return cr
    if cr.status == "in_progress":
        return cr
    _transition(cr, "in_progress", by=by, detail=detail or "Execution started")
    # Open the external maintenance window HERE rather than in the executor:
    # a caller that forgets is a device changed with no window on record,
    # and this transition is the one place every authorized fire passes
    # through. Best-effort by contract - see cr_orchestrator.
    from . import cr_orchestrator
    cr_orchestrator.on_start(cr, by=by)
    return cr


def finish(cr_or_id, outcome: str, by: str = "scheduler", summary: str = ""):
    """Close a CR from an executor outcome: ``ok`` -> ``completed``, ANYTHING
    ELSE -> ``failed``, with the reason kept in ``result_summary``.

    ``skipped`` maps to **failed** on purpose. The bound action is a one-shot:
    its ``next_run`` is cleared after the fire, so a CR left open because
    nothing ran can never close by itself - which is exactly the stall these
    transitions exist to remove. A change whose window elapsed without the
    change happening did not succeed, and the operator has to see that with the
    reason attached rather than find a CR parked at ``scheduled`` forever."""
    cr = _resolve(cr_or_id)
    if cr is None or cr.status in ChangeRequest.TERMINAL:
        return cr
    status = "completed" if outcome == "ok" else "failed"
    _transition(cr, status, by=by, detail=(summary or f"run {outcome}")[:_RESULT_MAX],
                result_summary=(summary or outcome)[:_RESULT_MAX])
    # Close the window, tell the hooks, mail the affected clients - in that
    # order, so nobody is told service is restored before the window that
    # covered the outage is closed. Never re-grades the outcome above.
    from . import cr_orchestrator
    cr_orchestrator.on_finish(cr, outcome, summary=summary, by=by)
    return cr


def cr_runnable(cr, now: datetime | None = None) -> tuple[bool, str]:
    """``(ok, reason)`` - may the bound action run NOW? Ok only if the CR is
    approved/scheduled/in_progress AND the clock is inside the window
    (``window_start <= now <= window_end``). The upgrade executor uses this as the
    unattended authorization that replaces the desktop's interactive unlock."""
    if cr is None:
        return False, "no change request"
    now = now or datetime.utcnow()
    if cr.status in ChangeRequest.TERMINAL:
        return False, f"change request is {cr.status}"
    if cr.status not in _RUNNABLE_STATES:
        return False, "change request is not approved"
    # Fail-closed external approval. A CR routed through an external change
    # authority is authorized by THAT authority saying yes, never by it
    # failing to say no: unreachable, slow and ambiguous all land on the
    # un-runnable side of this line.
    from . import cr_orchestrator
    ext_ok, ext_reason = cr_orchestrator.external_gate(cr, now)
    if not ext_ok:
        return False, ext_reason
    if cr.window_start is None:
        return False, "no maintenance window"
    if now < cr.window_start:
        return False, "before the maintenance window"
    if cr.window_end is not None and now > cr.window_end:
        return False, "after the maintenance window"
    return True, "inside the maintenance window"


# --------------------------------------------------------------------------- #
#  Client maintenance notice (pure text)                                        #
# --------------------------------------------------------------------------- #
def _fmt_window(dt) -> str:
    """Format a stored (naive UTC) window datetime for a human.

    Renders in the admin-configured timezone via the ONE conversion path
    (:func:`app.services.settings_store.to_local`) and always prints the zone
    abbreviation. This text goes into the CUSTOMER's maintenance notice: a bare
    UTC time told a Zurich customer to expect an outage two hours after the one
    the operator scheduled, and neither of them could see the mismatch because
    the number on the screen and the number in the mail agreed."""
    if dt is None:
        return "(time TBD)"
    try:
        from . import settings_store
        return settings_store.to_local(dt, "%Y-%m-%d %H:%M %Z")
    except Exception:  # noqa: BLE001
        try:
            return dt.strftime("%Y-%m-%d %H:%M UTC")
        except Exception:  # noqa: BLE001
            return str(dt)


def _policies(cr) -> list:
    """The CR's stored affected-policy list (JSON in ``ChangeRequest.policies``)."""
    try:
        value = json.loads(cr.policies or "[]")
        return value if isinstance(value, list) else []
    except (ValueError, TypeError):
        return []


def frozen_policies(cr) -> list:
    """The affected-service inventory STORED on this change request.

    Public because the views render the change document and the export from it:
    reading the fleet live at render time is what would let an approved change
    and the change that ran describe different systems."""
    return _policies(cr)


def maintenance_notice(cr) -> str:
    """Render the client-facing maintenance notice (English, plain text).

    Lists every affected service policy + the window so it can be emailed/posted
    to the clients before the change. Pure text - sending is out of scope (the CR
    records ``notify_status`` / ``notify_log`` once the operator confirms)."""
    start = _fmt_window(cr.window_start)
    end = _fmt_window(cr.window_end) if cr.window_end else None
    when = f"from {start} to {end}" if end else f"starting {start}"
    lines = [
        "Subject: Scheduled maintenance window - service may be briefly interrupted",
        "",
        "Dear customer,",
        "",
        f"We will perform scheduled maintenance {when}.",
    ]
    if cr.reason:
        lines.append(f"Reason: {cr.reason}.")
    policies = _policies(cr)
    if policies:
        lines.append("")
        lines.append("Affected services:")
        seen = set()
        for p in policies:
            if not isinstance(p, dict):
                continue
            label = p.get("service") or p.get("policy") or "service"
            dedupe = (p.get("device"), p.get("policy"))
            if dedupe in seen:
                continue
            seen.add(dedupe)
            host = f" ({p['vserver']})" if p.get("vserver") else ""
            lines.append(f"  - {p.get('policy', 'service')}{host} on "
                         f"{p.get('device', '')} - {label}")
    lines += [
        "",
        "During the window the service(s) above may be briefly unavailable while "
        "the change is applied. We expect minimal disruption and will restore full "
        "service as soon as possible.",
        "",
        "We apologise for any inconvenience.",
        "",
        "- Operations team",
    ]
    return "\n".join(lines)


def recipients_for(cr) -> list[str]:
    """Who this CR mails: its own ``notify_to`` list, else the Email settings
    default list. ``[]`` means nobody is configured - an empty list is a REFUSAL
    to guess an address, not an error, and the caller records that as the
    reason nothing was sent."""
    from . import email_service as email
    explicit = email.parse_recipients(getattr(cr, "notify_to", "") or "")
    if explicit:
        return explicit
    return email.parse_recipients(email.config().get("default_to", ""))


def outcome_notice(cr, status: str | None = None) -> tuple[str, str]:
    """``(subject, body)`` for the END of the window - what the affected clients
    are told once the change is over.

    Deliberately NOT :func:`maintenance_notice` again: that one warns service
    *may* be interrupted. Re-sending it at the end would tell a customer to
    brace for an outage that already finished."""
    status = status or cr.status
    ok = status == "completed"
    when = _fmt_window(cr.window_start)
    head = ("Maintenance completed - service restored" if ok else
            "Maintenance window closed - change NOT completed")
    lines = [f"Subject: {head}", "", "Dear customer,", ""]
    if ok:
        lines.append(f"The scheduled maintenance that began {when} is complete "
                     "and the affected services are back in normal operation.")
    else:
        lines.append(f"The maintenance window that began {when} has closed "
                     "WITHOUT the planned change being applied. Services were "
                     "left in their previous state.")
    if cr.reason:
        lines += ["", f"Change: {cr.reason}"]
    policies = _policies(cr)
    if policies:
        lines += ["", "Services covered by this window:"]
        seen = set()
        for p in policies:
            if not isinstance(p, dict):
                continue
            dedupe = (p.get("device"), p.get("policy"))
            if dedupe in seen:
                continue
            seen.add(dedupe)
            host = f" ({p['vserver']})" if p.get("vserver") else ""
            lines.append(f"  - {p.get('policy', 'service')}{host} on "
                         f"{p.get('device', '')}")
    if not ok and cr.result_summary:
        lines += ["", f"Outcome: {cr.result_summary}"]
    lines += ["", "Thank you for your patience.", "", "- Operations team"]
    body = "\n".join(lines[1:]).lstrip("\n")
    return head, body


def notify_outcome(cr, *, by: str = "scheduler") -> dict:
    """Mail the end-of-window notice ONCE. Returns
    ``{sent: bool, detail: str, recipients: [...]}``.

    Best-effort BY CONTRACT: the caller records what happened but must never let
    it change the CR outcome. An upgrade that worked worked whether or not the
    SMTP server answered, and letting a mail failure re-grade the change would
    make the record lie about the device.

    Idempotent via ``final_notified_at`` - a second call after a successful send
    is a no-op, so a retried/duplicated fire cannot mail the customer twice."""
    from . import email_service as email
    if cr is None:
        return {"sent": False, "detail": "no change request", "recipients": []}
    if getattr(cr, "final_notified_at", None):
        return {"sent": False, "detail": "already notified", "recipients": []}

    stamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    def _log(text_line: str) -> None:
        cr.notify_log = ((cr.notify_log or "") + f"\n[{stamp}] {text_line}")[-8000:]
        db.session.commit()

    if not email.is_configured():
        _log("outcome notice NOT sent: email is not configured")
        return {"sent": False, "detail": "email not configured", "recipients": []}
    recipients = recipients_for(cr)
    if not recipients:
        _log("outcome notice NOT sent: no recipients configured")
        return {"sent": False, "detail": "no recipients", "recipients": []}

    subject, body = outcome_notice(cr)
    result = email.send_email(recipients, subject, body)
    if result.get("ok"):
        cr.final_notified_at = datetime.utcnow()
        _log(f"outcome notice sent to {', '.join(recipients)}")
        db.session.add(ChangeRequestEvent(
            cr_id=cr.id, kind="notified", by=by,
            detail=f"outcome notice to {len(recipients)} recipient(s)",
            ts=datetime.utcnow()))
        db.session.commit()
        return {"sent": True, "detail": result.get("detail", ""),
                "recipients": recipients}
    _log(f"outcome notice FAILED: {result.get('detail', '')}")
    return {"sent": False, "detail": result.get("detail", ""),
            "recipients": recipients}


# --------------------------------------------------------------------------- #
#  Affected-policy discovery (best-effort live read - the clients to warn)       #
# --------------------------------------------------------------------------- #
def _published_frontends(appliance, *, timeout: float) -> list[dict]:
    """The front-ends a window takes offline, read in THIS product's shape.

    FortiWeb publishes server POLICIES; FortiADC publishes VIRTUAL SERVERS.
    Reading only the FortiWeb shape made every FortiADC in a window come back
    with nothing - a maintenance notice that silently under-states the outage.
    FortiAnalyzer and FortiAuthenticator publish no equivalent object, so an
    empty list there is a fact about the product, not a failed read.
    """
    kind = (getattr(appliance, "kind", "") or "fortiweb").strip().lower()
    out: list[dict] = []
    if kind not in ("fortiweb", "fortiadc"):
        return out          # no front-end object for this product: do not connect
    client = appliance.build_client(timeout=timeout)
    if kind == "fortiweb":
        raw = client.list_server_policies()
        rows = raw.get("results", raw) if isinstance(raw, dict) else raw
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            out.append({
                "policy": r.get("name", ""),
                "vserver": r.get("vserver", ""),
                "service": (r.get("https-service") or r.get("http-service")
                            or r.get("service") or ""),
                "status": r.get("status", ""),
            })
        return out
    if kind == "fortiadc":
        raw = client.list_virtual_servers()
        rows = raw.get("payload", raw) if isinstance(raw, dict) else raw
        if isinstance(rows, dict):          # single object reads come back keyed
            rows = list(rows.values())
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            out.append({
                "policy": r.get("mkey") or r.get("name", ""),
                "vserver": r.get("interface", ""),
                "service": str(r.get("port") or r.get("port-range") or ""),
                "status": r.get("status", ""),
            })
        return out
    # No published-service object is modelled for this product.
    return out


def affected_policies(device_ids, *, timeout: float = 8.0) -> list[dict]:
    """Every server policy on the targeted devices -> the clients impacted by the
    window. Each row is ``{device, device_id, policy, vserver, service, status}``.

    Best-effort: the web has no local policy cache, so this reads each device live
    (like ``services.fleet_objects``) wrapped per-device - a dead/unauthenticated
    appliance is skipped rather than raising. An empty result is fine (the UI just
    shows no pre-filled policies)."""
    ids = [v for v in (_as_int(t) for t in (device_ids or [])) if v is not None]
    if not ids:
        return []
    appliances = {a.id: a for a in
                  Appliance.query.filter(Appliance.id.in_(ids)).all()}
    out: list[dict] = []
    for dev_id in ids:
        appliance = appliances.get(dev_id)
        if appliance is None:
            continue
        try:
            rows = _published_frontends(appliance, timeout=timeout)
        except Exception:  # noqa: BLE001 - connectivity miss must not break planning
            continue
        for row in rows:
            row["device"] = appliance.name
            row["device_id"] = dev_id
            out.append(row)
    return out


def _as_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


__all__ = [
    "RISKS",
    "WINDOW_INVERTED",
    "validate_window",
    "revoke_approval",
    "approve",
    "cancel",
    "schedule_change_request",
    "start",
    "finish",
    "cr_runnable",
    "maintenance_notice",
    "outcome_notice",
    "recipients_for",
    "notify_outcome",
    "affected_policies",
    "frozen_policies",
]
