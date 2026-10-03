"""A Change Request must be able to END.

The lifecycle declares seven states — ``draft, approved, scheduled,
in_progress, completed, failed, cancelled`` — and until 2026-08-09 only THREE
had a writer: ``approved``, ``cancelled`` and ``scheduled``. Nothing ever
assigned ``in_progress``, ``completed`` or ``failed``, so a CR that fired its
upgrade stayed at ``scheduled`` for good. The bound action is a one-shot: its
``next_run`` is cleared after the fire, so nothing was ever coming back to
close it.

Nothing failed while that was true. No exception, no red badge — the record
simply stopped describing reality, and the notification the operator wanted
("tell the affected users when it's done") hung off a transition that did not
exist.

The same audit found the gate cabled to a single action name
(``action_row.action == "upgrade"``) while ``CR_ACTIONS`` already offered
``upgrade_prep``: a CR could schedule that one and it would fire with no
approval and outside its window, which is the entire thing the gate is for.

Guarded here, in the order the defects were found:

1. the terminal transitions exist and grade an outcome honestly;
2. the executor actually drives them, and a GATED fire leaves the CR alone;
3. the gate is keyed off the CR binding, not off one action name;
4. the outcome notice is sent once, never re-grades the change, and never
   invents a recipient;
5. no state in ``STATUSES`` is left without a writer again.
"""
from __future__ import annotations

import ast
import json
import os
from datetime import datetime, timedelta

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SA_PATH = os.path.join(REPO, "app", "services", "scheduled_actions.py")
CR_PATH = os.path.join(REPO, "app", "services", "change_requests.py")


# --------------------------------------------------------------------------- #
#  helpers                                                                      #
# --------------------------------------------------------------------------- #
def _mk_cr(status="scheduled", *, action="upgrade", window=True, **kw):
    """Persist a CR whose window is OPEN right now unless told otherwise."""
    from app.extensions import db
    from app.models import ChangeRequest

    now = datetime.utcnow()
    cr = ChangeRequest(
        title=kw.pop("title", "CR under test"),
        reason=kw.pop("reason", "firmware 7.6.9"),
        status=status,
        action=action,
        params=json.dumps(kw.pop("params", {})),
        device_ids=json.dumps(kw.pop("device_ids", [])),
        policies=json.dumps(kw.pop("policies", [])),
        window_start=(now - timedelta(minutes=5)) if window else None,
        window_end=(now + timedelta(minutes=55)) if window else None,
        **kw,
    )
    db.session.add(cr)
    db.session.commit()
    return cr


def _mk_action(cr, *, action=None):
    """A one-shot ScheduledAction bound to ``cr`` the way the service binds it."""
    from app.extensions import db
    from app.models import ScheduledAction

    row = ScheduledAction(
        name=f"CR #{cr.id}", scope="admin", action=action or cr.action,
        targets="[]", params=json.dumps({"change_request_id": cr.id}),
        schedule_kind="once", schedule=json.dumps({"at": datetime.utcnow().isoformat()}),
        enabled=True, catch_up=True, created_by="tester")
    db.session.add(row)
    db.session.commit()
    return row


def _events(cr):
    from app.models import ChangeRequestEvent
    return [e.kind for e in ChangeRequestEvent.query.filter_by(cr_id=cr.id)
            .order_by(ChangeRequestEvent.id).all()]


def _sa_func(name):
    """The AST of one function in scheduled_actions.py (comments already gone —
    ast never sees them, which is the point: a guard asserted against raw text
    can be satisfied by the comment that explains it)."""
    tree = ast.parse(open(SA_PATH, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name}() not found in scheduled_actions.py")


# --------------------------------------------------------------------------- #
#  1. terminal transitions                                                      #
# --------------------------------------------------------------------------- #
def test_finish_ok_completes_the_change_request(session):
    from app.services import change_requests as svc

    cr = _mk_cr(status="in_progress")
    svc.finish(cr, "ok", summary="upgraded 3/3")
    assert cr.status == "completed"
    assert "3/3" in (cr.result_summary or "")
    assert _events(cr)[-1] == "completed"


def test_finish_failed_records_the_reason(session):
    from app.services import change_requests as svc

    cr = _mk_cr(status="in_progress")
    svc.finish(cr, "failed", summary="fortiweb08 never came back")
    assert cr.status == "failed"
    assert "never came back" in (cr.result_summary or "")


def test_skipped_is_graded_as_failed_not_left_open(session):
    """The load-bearing grade.

    A run that skipped means the window elapsed and the change did NOT happen.
    The bound action is a one-shot, so leaving the CR ``in_progress`` (or
    calling a skip a success) would reproduce the original stall by another
    route — the operator would never learn the change never ran.
    """
    from app.services import change_requests as svc

    cr = _mk_cr(status="in_progress")
    svc.finish(cr, "skipped", summary="all targets in maintenance")
    assert cr.status == "failed"
    assert cr.status != "completed"
    assert "maintenance" in (cr.result_summary or "")


def test_finish_never_reopens_a_terminal_change_request(session):
    from app.services import change_requests as svc

    cr = _mk_cr(status="cancelled")
    svc.finish(cr, "ok", summary="late fire")
    assert cr.status == "cancelled"
    assert "completed" not in _events(cr)


def test_start_moves_to_in_progress_and_is_idempotent(session):
    from app.services import change_requests as svc

    cr = _mk_cr(status="scheduled")
    svc.start(cr)
    svc.start(cr)
    assert cr.status == "in_progress"
    assert _events(cr).count("in_progress") == 1


def test_start_does_not_resurrect_a_cancelled_change_request(session):
    from app.services import change_requests as svc

    cr = _mk_cr(status="cancelled")
    svc.start(cr)
    assert cr.status == "cancelled"


def test_start_accepts_an_id_because_the_executor_only_holds_one(session):
    from app.services import change_requests as svc

    cr = _mk_cr(status="scheduled")
    svc.start(cr.id)
    assert cr.status == "in_progress"


# --------------------------------------------------------------------------- #
#  2. the executor drives the lifecycle                                         #
# --------------------------------------------------------------------------- #
def test_executor_closes_the_change_request_on_success(app, monkeypatch):
    from app.services import scheduled_actions as sa

    with app.app_context():
        cr = _mk_cr(status="scheduled")
        row = _mk_action(cr)
        monkeypatch.setattr(sa, "_run_targets",
                            lambda *a, **k: ("ok", "upgraded 1/1", ["done"]))
        run = sa.execute_and_record(row, trigger="schedule")
        assert run.status == "ok"
        assert cr.status == "completed"
        assert _events(cr) == ["in_progress", "completed"]


def test_executor_fails_the_change_request_when_the_run_fails(app, monkeypatch):
    from app.services import scheduled_actions as sa

    with app.app_context():
        cr = _mk_cr(status="scheduled")
        row = _mk_action(cr)
        monkeypatch.setattr(sa, "_run_targets",
                            lambda *a, **k: ("failed", "flash aborted", ["boom"]))
        sa.execute_and_record(row, trigger="schedule")
        assert cr.status == "failed"
        assert "flash aborted" in (cr.result_summary or "")


def test_executor_fails_the_change_request_when_the_action_explodes(app, monkeypatch):
    """A crash inside the run still has to close the CR — the stall must not
    come back through the exception path."""
    from app.services import scheduled_actions as sa

    def _boom(*a, **k):
        raise RuntimeError("device unreachable")

    with app.app_context():
        cr = _mk_cr(status="scheduled")
        row = _mk_action(cr)
        monkeypatch.setattr(sa, "_run_targets", _boom)
        run = sa.execute_and_record(row, trigger="schedule")
        assert run.status == "failed"
        assert cr.status == "failed"


def test_a_gated_fire_leaves_the_change_request_untouched(app, monkeypatch):
    """Outside the window the run is skipped and the CR must NOT move.

    A window that never opened is not a change that started and then failed;
    recording ``in_progress``/``failed`` here would make an un-run change
    indistinguishable from a broken one, and would burn the CR (terminal) so a
    later legitimate fire could never run it.
    """
    from app.services import scheduled_actions as sa

    with app.app_context():
        cr = _mk_cr(status="scheduled")
        cr.window_start = datetime.utcnow() + timedelta(hours=3)
        cr.window_end = datetime.utcnow() + timedelta(hours=4)
        from app.extensions import db
        db.session.commit()
        row = _mk_action(cr)
        monkeypatch.setattr(sa, "_run_targets",
                            lambda *a, **k: pytest.fail("must not run"))
        run = sa.execute_and_record(row, trigger="schedule")
        assert run.status == "skipped"
        assert cr.status == "scheduled"
        assert _events(cr) == []


def test_an_unapproved_change_request_cannot_fire(app, monkeypatch):
    from app.services import scheduled_actions as sa

    with app.app_context():
        cr = _mk_cr(status="draft")
        row = _mk_action(cr)
        monkeypatch.setattr(sa, "_run_targets",
                            lambda *a, **k: pytest.fail("must not run"))
        run = sa.execute_and_record(row, trigger="schedule")
        assert run.status == "skipped"
        assert cr.status == "draft"


# --------------------------------------------------------------------------- #
#  3. the gate is keyed off the BINDING, not off one action name                #
# --------------------------------------------------------------------------- #
def test_a_non_upgrade_action_bound_to_a_change_request_is_gated_too(app, monkeypatch):
    """``upgrade_prep`` is offered by ``CR_ACTIONS`` and was NOT gated.

    With the gate cabled to ``action == "upgrade"`` this run fired with the CR
    still in ``draft`` and hours away from its window.
    """
    from app.services import scheduled_actions as sa

    with app.app_context():
        cr = _mk_cr(status="draft", action="upgrade_prep")
        row = _mk_action(cr, action="upgrade_prep")
        monkeypatch.setattr(sa, "_run_targets",
                            lambda *a, **k: pytest.fail("must not run"))
        run = sa.execute_and_record(row, trigger="schedule")
        assert run.status == "skipped"
        assert "change request" in (run.summary or "")


def test_an_action_with_no_change_request_is_not_gated(app, monkeypatch):
    """The gate must not start refusing every ordinary scheduled action."""
    from app.extensions import db
    from app.models import ScheduledAction
    from app.services import scheduled_actions as sa

    with app.app_context():
        row = ScheduledAction(
            name="nightly backup", scope="admin", action="backup", targets="[]",
            params="{}", schedule_kind="daily", schedule=json.dumps({"time": "02:00"}),
            enabled=True, created_by="tester")
        db.session.add(row)
        db.session.commit()
        monkeypatch.setattr(sa, "_run_targets",
                            lambda *a, **k: ("ok", "backed up", []))
        run = sa.execute_and_record(row, trigger="schedule")
        assert run.status == "ok"


def test_the_gate_does_not_compare_the_action_name(app):
    """Structural: the historic cable, asserted on the AST so a comment that
    merely mentions ``upgrade`` cannot satisfy it."""
    fn = _sa_func("execute_and_record")
    for node in ast.walk(fn):
        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Attribute):
            if node.left.attr == "action":
                consts = [c.value for c in node.comparators
                          if isinstance(c, ast.Constant)]
                assert "upgrade" not in consts, (
                    "the CR gate is cabled to one action name again; it must key "
                    "off params['change_request_id']")


def test_the_bound_cr_bookkeeping_is_initialised_before_the_try(app):
    """``finally``/tail code that reads a name the ``try`` assigns is a
    NameError waiting for the first statement to raise."""
    fn = _sa_func("execute_and_record")
    # The try whose tail READS the names, not merely the first one in the
    # body: an earlier unrelated try (the lease guard) must not move the
    # goalposts of an invariant that still holds.
    first_try = next(i for i, st in enumerate(fn.body)
                     if isinstance(st, ast.Try)
                     and any(isinstance(n, ast.Name) and n.id == "cr_bound_id"
                             for n in ast.walk(st)))
    assigned = set()
    for st in fn.body[:first_try]:
        for node in ast.walk(st):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                assigned.add(node.id)
    assert {"cr_bound_id", "cr_gated"} <= assigned


def test_closing_the_cr_cannot_roll_back_the_run(app):
    """The e122dd9 lesson: a best-effort bookkeeping step that shares the
    caller's transaction and swallows its exception hands the caller a dead
    session. The CR close must sit in its own ``try`` WITH a rollback."""
    src = open(SA_PATH, encoding="utf-8").read()
    fn = _sa_func("execute_and_record")
    tries = [n for n in ast.walk(fn)
             if isinstance(n, ast.Try)
             and "change_requests.finish" in ast.get_source_segment(src, n)]
    assert tries, "the CR close is not wrapped in its own try/except"
    assert any("rollback" in ast.get_source_segment(src, h)
               for t in tries for h in t.handlers), \
        "the CR close swallows its exception without rolling the session back"


# --------------------------------------------------------------------------- #
#  4. the outcome notice                                                        #
# --------------------------------------------------------------------------- #
def test_no_mail_and_no_false_timestamp_when_email_is_unconfigured(session, monkeypatch):
    from app.services import change_requests as svc
    from app.services import email_service

    monkeypatch.setattr(email_service, "is_configured", lambda: False)
    cr = _mk_cr(status="completed", notify_to="ops@example.com")
    out = svc.notify_outcome(cr)
    assert out["sent"] is False
    assert cr.final_notified_at is None
    assert "not configured" in (cr.notify_log or "")


def test_no_recipient_is_never_invented(session, monkeypatch):
    from app.services import change_requests as svc
    from app.services import email_service

    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    monkeypatch.setattr(email_service, "config", lambda **k: {"default_to": ""})
    monkeypatch.setattr(email_service, "send_email",
                        lambda *a, **k: pytest.fail("must not send"))
    cr = _mk_cr(status="completed")
    out = svc.notify_outcome(cr)
    assert out["sent"] is False
    assert "no recipients" in out["detail"]


def test_the_notice_goes_to_the_change_requests_own_recipients(session, monkeypatch):
    from app.services import change_requests as svc
    from app.services import email_service

    seen = {}
    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    monkeypatch.setattr(email_service, "config", lambda **k: {"default_to": "fallback@x.io"})
    monkeypatch.setattr(email_service, "send_email",
                        lambda to, subject, body, **k: seen.update(
                            to=to, subject=subject, body=body) or {"ok": True, "detail": "sent"})
    cr = _mk_cr(status="completed", notify_to="a@x.io, b@x.io")
    out = svc.notify_outcome(cr)
    assert out["sent"] is True
    assert seen["to"] == ["a@x.io", "b@x.io"]
    assert "fallback@x.io" not in seen["to"]
    assert cr.final_notified_at is not None
    assert "notified" in _events(cr)


def test_the_settings_default_is_the_fallback(session, monkeypatch):
    from app.services import change_requests as svc
    from app.services import email_service

    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    monkeypatch.setattr(email_service, "config", lambda **k: {"default_to": "ops@x.io"})
    cr = _mk_cr(status="completed")
    assert svc.recipients_for(cr) == ["ops@x.io"]


def test_the_notice_is_sent_once(session, monkeypatch):
    from app.services import change_requests as svc
    from app.services import email_service

    calls = []
    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    monkeypatch.setattr(email_service, "config", lambda **k: {"default_to": ""})
    monkeypatch.setattr(email_service, "send_email",
                        lambda *a, **k: calls.append(1) or {"ok": True, "detail": "sent"})
    cr = _mk_cr(status="completed", notify_to="a@x.io")
    svc.notify_outcome(cr)
    svc.notify_outcome(cr)
    assert len(calls) == 1


def test_a_mail_failure_never_regrades_the_change(app, monkeypatch):
    """The contract. An upgrade that worked worked whether or not the SMTP
    server answered; letting a send error mark the CR failed would make the
    record lie about the device."""
    from app.services import email_service
    from app.services import scheduled_actions as sa

    with app.app_context():
        cr = _mk_cr(status="scheduled", notify_to="a@x.io")
        row = _mk_action(cr)
        monkeypatch.setattr(sa, "_run_targets",
                            lambda *a, **k: ("ok", "upgraded 1/1", []))
        monkeypatch.setattr(email_service, "is_configured", lambda: True)
        monkeypatch.setattr(email_service, "config", lambda **k: {"default_to": ""})

        def _explode(*a, **k):
            raise OSError("smtp unreachable")

        monkeypatch.setattr(email_service, "send_email", _explode)
        sa.execute_and_record(row, trigger="schedule")
        assert cr.status == "completed"


def test_a_failed_send_never_records_a_delivery(session, monkeypatch):
    """``final_notified_at`` is a CLAIM OF DELIVERY, and it is also the flag that
    makes the notice idempotent. Stamping it on a failure therefore does two
    bad things at once: the detail page tells the operator the customer was
    told, and the retry is suppressed for good — the one case where a retry is
    the whole point.
    """
    from app.services import change_requests as svc
    from app.services import email_service

    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    monkeypatch.setattr(email_service, "config", lambda **k: {"default_to": ""})
    monkeypatch.setattr(email_service, "send_email",
                        lambda *a, **k: {"ok": False, "detail": "connection refused"})
    cr = _mk_cr(status="completed", notify_to="a@x.io")
    out = svc.notify_outcome(cr)
    assert out["sent"] is False
    assert cr.final_notified_at is None
    assert "FAILED" in (cr.notify_log or "")

    # ...and because nothing was stamped, the retry is still possible.
    calls = []
    monkeypatch.setattr(email_service, "send_email",
                        lambda *a, **k: calls.append(1) or {"ok": True, "detail": "sent"})
    out = svc.notify_outcome(cr)
    assert calls == [1], "a failed send must leave the notice retryable"
    assert out["sent"] is True
    assert cr.final_notified_at is not None


def test_the_end_notice_is_not_the_pre_window_warning(session):
    """Re-sending ``maintenance_notice`` at the end tells a customer to brace
    for an outage that already finished."""
    from app.services import change_requests as svc

    done = _mk_cr(status="completed")
    subject, body = svc.outcome_notice(done)
    assert "complete" in subject.lower()
    assert "may be briefly" not in body

    bad = _mk_cr(status="failed", result_summary="all targets in maintenance")
    subject, body = svc.outcome_notice(bad)
    assert "not completed" in subject.lower()
    assert "previous state" in body
    assert "all targets in maintenance" in body


# --------------------------------------------------------------------------- #
#  5. no declared state may go back to having no writer                         #
# --------------------------------------------------------------------------- #
def test_every_declared_status_has_something_that_writes_it(app):
    """The guard that would have caught the original defect.

    Nothing fails when a lifecycle state has no writer — the enum simply
    describes a state the product can never reach, and the UI renders a badge
    nobody will ever see. ``draft`` is exempt: it is the model's column
    default, not a transition.
    """
    from app.models import ChangeRequest

    tree = ast.parse(open(CR_PATH, encoding="utf-8").read())
    written = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "_transition" and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)):
            written.add(node.args[1].value)
        # a transition assembled instead of passed literally still counts
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.IfExp)):
            for part in (node.value.body, node.value.orelse):
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    written.add(part.value)

    missing = set(ChangeRequest.STATUSES) - written - {"draft"}
    assert not missing, (
        f"{sorted(missing)} are declared in ChangeRequest.STATUSES but nothing "
        f"in change_requests.py ever assigns them — a CR can never reach them")


# --------------------------------------------------------------------------- #
#  Documentation Center audit 2026-10-03 (AU-08 .. AU-14)                       #
# --------------------------------------------------------------------------- #
def _two_appliances():
    from app.extensions import db
    from app.models import Appliance
    out = []
    for name in ("fw-a", "fw-b"):
        a = Appliance(name=name, host="192.0.2.%d" % (len(out) + 30),
                      username="admin", password_enc="x")
        db.session.add(a)
        out.append(a)
    db.session.commit()
    return out


@pytest.mark.parametrize("status", ["cancelled", "completed", "failed",
                                    "approved", "scheduled", "in_progress"])
def test_only_a_draft_can_be_approved(session, status):
    """AU-10: a direct POST used to re-approve a closed change."""
    from app.services import change_requests as svc
    cr = _mk_cr(status=status)
    with pytest.raises(ValueError):
        svc.approve(cr.id, by="approver")
    assert cr.status == status


def test_a_draft_still_approves(session):
    from app.services import change_requests as svc
    cr = _mk_cr(status="draft")
    svc.approve(cr.id, by="approver")
    assert cr.status == "approved"


@pytest.mark.parametrize("status", ["completed", "failed", "cancelled"])
def test_a_closed_change_cannot_be_cancelled(session, status):
    """AU-11: cancel() rewrote completed/failed records to cancelled."""
    from app.services import change_requests as svc
    cr = _mk_cr(status=status)
    with pytest.raises(ValueError):
        svc.cancel(cr.id, by="op")
    assert cr.status == status


def test_an_open_change_still_cancels(session):
    from app.services import change_requests as svc
    cr = _mk_cr(status="approved")
    svc.cancel(cr.id, by="op")
    assert cr.status == "cancelled"


def test_scheduling_inside_a_started_window_still_fires(session):
    """AU-9: a past window_start gave a one-shot with next_run None."""
    from app.extensions import db
    from app.models import ScheduledAction
    from app.services import change_requests as svc
    cr = _mk_cr(status="approved", action="device_sync")   # started 5 min ago
    action_id = svc.schedule_change_request(cr.id, by="op")
    row = db.session.get(ScheduledAction, action_id)
    assert row.next_run is not None
    assert row.next_run > datetime.utcnow()
    assert row.next_run <= cr.window_end


def test_scheduling_after_the_window_closed_is_refused(session):
    from app.extensions import db
    from app.services import change_requests as svc
    cr = _mk_cr(status="approved", action="device_sync")
    cr.window_start = datetime.utcnow() - timedelta(hours=3)
    cr.window_end = datetime.utcnow() - timedelta(hours=1)
    db.session.commit()
    with pytest.raises(ValueError, match="closed"):
        svc.schedule_change_request(cr.id, by="op")
    assert cr.status == "approved"


def test_a_future_window_keeps_its_start(session):
    from app.extensions import db
    from app.models import ScheduledAction
    from app.services import change_requests as svc
    cr = _mk_cr(status="approved", action="device_sync")
    start = datetime.utcnow() + timedelta(days=1)
    cr.window_start, cr.window_end = start, start + timedelta(hours=2)
    db.session.commit()
    row = db.session.get(ScheduledAction, svc.schedule_change_request(cr.id, by="op"))
    assert abs((row.next_run - start).total_seconds()) < 1


def test_a_multi_appliance_change_closes_after_its_last_appliance(session):
    """AU-08: one appliance's live run closed the whole change."""
    from app.services import change_requests as svc
    a, b = _two_appliances()
    cr = _mk_cr(status="in_progress", device_ids=[a.id, b.id])
    svc.finish_device(cr, a.id, "ok", summary="a done")
    assert cr.status == "in_progress"
    assert svc.device_results(cr) == {a.id: "ok"}
    svc.finish_device(cr, b.id, "ok", summary="b done")
    assert cr.status == "completed"
    assert "2/2" in (cr.result_summary or "")


def test_a_failed_appliance_fails_the_change_and_is_named(session):
    from app.services import change_requests as svc
    a, b = _two_appliances()
    cr = _mk_cr(status="in_progress", device_ids=[a.id, b.id])
    svc.finish_device(cr, a.id, "error", summary="boom")
    assert cr.status == "in_progress"
    svc.finish_device(cr, b.id, "ok")
    assert cr.status == "failed"
    assert "fw-a" in (cr.result_summary or "")


def test_a_retried_appliance_replaces_its_failure(session):
    from app.services import change_requests as svc
    a, b = _two_appliances()
    cr = _mk_cr(status="in_progress", device_ids=[a.id, b.id])
    svc.finish_device(cr, a.id, "error")
    svc.finish_device(cr, a.id, "ok")
    svc.finish_device(cr, b.id, "ok")
    assert cr.status == "completed"


def test_a_single_appliance_change_closes_at_once(session):
    from app.services import change_requests as svc
    a, _b = _two_appliances()
    cr = _mk_cr(status="in_progress", device_ids=[a.id])
    svc.finish_device(cr, a.id, "ok")
    assert cr.status == "completed"


def test_the_live_paths_record_per_appliance():
    """Every live caller in appliances.py goes through finish_device."""
    src = open(os.path.join(REPO, "app", "views", "appliances.py"),
               encoding="utf-8").read()
    tree = ast.parse(src)
    finish_calls = [n for n in ast.walk(tree)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "finish"
                    and getattr(n.func.value, "id", "") == "crsvc"]
    assert finish_calls == []


def test_a_documentary_change_is_closed_by_hand(session):
    """AU-14: nothing could ever close a documentary change."""
    from app.services import change_requests as svc
    cr = _mk_cr(status="approved", action="cable_swap_by_hand")
    svc.close_by_hand(cr.id, "completed", by="op", summary="swapped")
    assert cr.status == "completed"
    assert cr.result_summary == "swapped"


def test_an_executable_change_inside_its_window_is_not_closed_by_hand(session):
    from app.services import change_requests as svc
    cr = _mk_cr(status="approved", action="device_sync")
    with pytest.raises(ValueError):
        svc.close_by_hand(cr.id, "completed", by="op")
    assert cr.status == "approved"


def test_an_overrun_change_can_be_closed_by_hand(session):
    from app.extensions import db
    from app.services import change_requests as svc
    cr = _mk_cr(status="in_progress", action="upgrade")
    cr.window_end = datetime.utcnow() - timedelta(minutes=1)
    db.session.commit()
    svc.close_by_hand(cr.id, "failed", by="op")
    assert cr.status == "failed"


def test_closing_by_hand_needs_an_approval(session):
    from app.services import change_requests as svc
    cr = _mk_cr(status="draft", action="cable_swap_by_hand")
    with pytest.raises(ValueError):
        svc.close_by_hand(cr.id, "completed", by="op")
    ext = _mk_cr(status="approved", action="cable_swap_by_hand",
                 approval_mode="external")
    with pytest.raises(ValueError):
        svc.close_by_hand(ext.id, "completed", by="op")
    assert cr.status == "draft" and ext.status == "approved"


def test_close_by_hand_route_needs_user_manage_and_closes(app, client):
    from conftest import admin_user_id, login, make_user, profile_id
    from app.extensions import db
    from app.models import ChangeRequest
    with app.app_context():
        cid = _mk_cr(status="approved", action="cable_swap_by_hand").id
    uid = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, uid)
    client.post(f"/change-requests/{cid}/close-by-hand", data={"outcome": "completed"})
    with app.app_context():
        assert db.session.get(ChangeRequest, cid).status == "approved"
    login(client, admin_user_id(app))
    page = client.get(f"/change-requests/{cid}")
    assert b"close-by-hand" in page.data
    r = client.post(f"/change-requests/{cid}/close-by-hand", data={"outcome": "completed"})
    assert r.status_code == 302
    with app.app_context():
        assert db.session.get(ChangeRequest, cid).status == "completed"


def test_mark_notified_mails_the_changes_own_recipients(app, client, monkeypatch):
    """AU-12: the form posts no list, so the CR's notify_to must be used."""
    from conftest import admin_user_id, login
    from app.services import email_service
    seen = {}
    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    monkeypatch.setattr(email_service, "send_email",
                        lambda to, subject, body, **k: seen.update(to=to)
                        or {"ok": True, "detail": "sent"})
    with app.app_context():
        cid = _mk_cr(status="approved", notify_to="c1@x.io; c2@x.io").id
    login(client, admin_user_id(app))
    r = client.post(f"/change-requests/{cid}/mark-notified", data={})
    assert r.status_code == 302
    assert seen["to"] == ["c1@x.io", "c2@x.io"]
