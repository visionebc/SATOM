"""Alert engine — a scheduled automation that breaks has to be loud.

Background sweeps were made silent on 2026-07-28: a run that worked is not
news. That trade is only safe if the FAILING run is loud somewhere, and it was
not. ``scheduled_actions`` holds no ``notify`` call and this engine had no check
for it, so on the day this was written action 5 (``device_sync``) had failed
**24 consecutive scheduled runs** with nobody told; the day before,
``scheduler_guard.sh`` broke on ``runuser`` and the sidecar fired nothing at all
for hours while systemd still reported the unit ``active``.

Two distinct failure modes are guarded here, and the second is the one a naive
implementation misses: a scheduler that stops firing produces **no failed runs
at all**, so a streak-only check calls a dead scheduler healthy.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.models import ScheduledAction, ScheduledActionRun, db
from app.services import alerts


def _action(**kw):
    a = ScheduledAction(
        name=kw.pop("name", "nightly sync"),
        action=kw.pop("action", "device_sync"),
        product=kw.pop("product", "fortiweb"),
        schedule_kind=kw.pop("schedule_kind", "interval"),
        enabled=kw.pop("enabled", True),
        next_run=kw.pop("next_run", datetime.utcnow() + timedelta(hours=1)),
        **kw)
    db.session.add(a)
    db.session.commit()
    return a


def _run(action_id, status, minutes_ago, trigger="schedule", summary=""):
    r = ScheduledActionRun(
        action_id=action_id, status=status, trigger=trigger, summary=summary,
        started_at=datetime.utcnow() - timedelta(minutes=minutes_ago))
    db.session.add(r)
    db.session.commit()
    return r


# ------------------------------------------------------------- the regression
def test_repeated_scheduled_failures_produce_a_finding(app):
    """The device_sync case: 24 straight failures, zero notifications."""
    with app.app_context():
        a = _action()
        for i in range(24):
            _run(a.id, "failed", 60 * (i + 1), summary="1/5 ok (failed: fw7, fadc)")

        out = alerts._check_actions()
        assert len(out) == 1, out
        assert out[0]["severity"] == alerts.SEV_CRITICAL
        assert "24 consecutive" in out[0]["detail"]
        assert "fw7" in out[0]["detail"], "the reason must travel with the alert"


def test_one_finding_per_action_not_per_run(app):
    """Twenty-four failures are one broken action, not twenty-four alerts.
    A mailbox that gets 24 mails about one thing is a mailbox nobody reads."""
    with app.app_context():
        a = _action()
        for i in range(24):
            _run(a.id, "failed", 60 * (i + 1))
        assert len(alerts._check_actions()) == 1


def test_healthy_action_is_silent(app):
    with app.app_context():
        a = _action()
        for i in range(5):
            _run(a.id, "ok", 10 * (i + 1))
        assert alerts._check_actions() == []


def test_recovery_clears_the_streak(app):
    """A success in front of old failures means the action works now."""
    with app.app_context():
        a = _action()
        for i in range(5):
            _run(a.id, "failed", 60 * (i + 2))
        _run(a.id, "ok", 1)
        assert alerts._check_actions() == []


def test_single_failure_is_warning_streak_is_critical(app):
    with app.app_context():
        a = _action()
        _run(a.id, "failed", 5)
        assert alerts._check_actions()[0]["severity"] == alerts.SEV_WARNING
        _run(a.id, "failed", 4)
        _run(a.id, "failed", 3)
        assert alerts._check_actions()[0]["severity"] == alerts.SEV_CRITICAL


def test_severity_is_part_of_the_cooldown_key(app):
    """warn -> crit inside the cooldown window must still reach the operator."""
    with app.app_context():
        a = _action()
        _run(a.id, "failed", 5)
        warn_key = alerts._check_actions()[0]["key"]
        _run(a.id, "failed", 4)
        _run(a.id, "failed", 3)
        crit_key = alerts._check_actions()[0]["key"]
        assert warn_key != crit_key
        assert warn_key.endswith(".warn") and crit_key.endswith(".crit")


# ------------------------------------------------- the mode a streak can't see
def test_scheduler_that_stops_firing_is_reported(app):
    """No failed runs at all — the sidecar simply died. This is the
    ``scheduler_guard.sh`` outage of 2026-07-26, which nothing detected."""
    with app.app_context():
        a = _action(next_run=datetime.utcnow() - timedelta(hours=5))
        _run(a.id, "ok", 60 * 6)          # last thing it did was succeed

        out = alerts._check_actions()
        assert len(out) == 1
        assert "Overdue" in out[0]["detail"]
        assert "not firing" in out[0]["title"]


def test_overdue_escalates_to_critical(app):
    with app.app_context():
        a = _action(next_run=datetime.utcnow() - timedelta(hours=3, minutes=5))
        assert alerts._check_actions()[0]["severity"] == alerts.SEV_WARNING
        a.next_run = datetime.utcnow() - timedelta(hours=13)
        db.session.commit()
        assert alerts._check_actions()[0]["severity"] == alerts.SEV_CRITICAL


def test_action_due_soon_is_not_overdue(app):
    with app.app_context():
        _action(next_run=datetime.utcnow() + timedelta(minutes=30))
        assert alerts._check_actions() == []


# --------------------------------------------------------------- suppressions
def test_disabled_action_never_alerts(app):
    """Turning an automation off is the operator's own decision."""
    with app.app_context():
        a = _action(enabled=False, next_run=datetime.utcnow() - timedelta(days=9))
        for i in range(9):
            _run(a.id, "failed", 60 * (i + 1))
        assert alerts._check_actions() == []


def test_manual_runs_do_not_count(app):
    """A manual run is user-initiated and its result is already on screen.
    Worse, mixing them hides the 2026-07-28 case where the scheduled path
    failed on stale sidecar code while the manual path succeeded."""
    with app.app_context():
        a = _action()
        for i in range(4):
            _run(a.id, "failed", 60 * (i + 1), trigger="manual")
        assert alerts._check_actions() == []


def test_manual_success_does_not_mask_a_scheduled_streak(app):
    with app.app_context():
        a = _action()
        for i in range(4):
            _run(a.id, "failed", 60 * (i + 2))
        _run(a.id, "ok", 1, trigger="manual")
        out = alerts._check_actions()
        assert len(out) == 1 and out[0]["severity"] == alerts.SEV_CRITICAL


def test_skipped_run_clears_the_streak(app):
    """A skip terminates the streak as surely as a success does.

    Stepping over skips looks safer and is not: an action whose whole target set
    is in maintenance reports `skipped` on every future run, so the old failures
    would never clear and the alert would sit critical forever — the always-red
    state this check exists to prevent. A skip is a legitimate outcome, not a
    fault. If the action really is broken, its next real run restarts the
    streak, which is what `test_failure_after_a_skip_restarts_the_streak`
    pins down."""
    with app.app_context():
        a = _action()
        for i in range(3):
            _run(a.id, "failed", 60 * (i + 2))
        _run(a.id, "skipped", 1)
        assert alerts._check_actions() == []


def test_failure_after_a_skip_restarts_the_streak(app):
    with app.app_context():
        a = _action()
        for i in range(3):
            _run(a.id, "failed", 60 * (i + 5))
        _run(a.id, "skipped", 60 * 4)
        _run(a.id, "failed", 3)
        out = alerts._check_actions()
        assert len(out) == 1 and out[0]["severity"] == alerts.SEV_WARNING, \
            "only the failures NEWER than the skip count"


def test_an_all_parked_action_goes_quiet_on_its_next_run(app):
    """End-to-end of the interaction with maintenance: yesterday's failures plus
    today's skip must not equal a permanent critical alert."""
    with app.app_context():
        a = _action()
        for i in range(9):
            _run(a.id, "failed", 60 * (i + 2))
        _run(a.id, "skipped", 1,
             summary="Sync device: all targets in maintenance (fw6, fw7).")
        assert alerts._check_actions() == []


# ------------------------------------------------------------------- plumbing
def test_finding_carries_the_actions_adom(app):
    """An unstamped finding lands in the FortiWeb catch-all bucket (safeguards
    §9c-bis). The ADOM of an automation finding is the automation's own."""
    with app.app_context():
        a = _action(product="fortiadc")
        _run(a.id, "failed", 5)
        assert alerts._check_actions()[0]["product"] == "fortiadc"


def test_check_is_registered_and_toggleable(app):
    with app.app_context():
        assert any(fn is alerts._check_actions for _, fn in alerts._CHECKS), \
            "the check exists but evaluate() never calls it"
        a = _action()
        for i in range(4):
            _run(a.id, "failed", 60 * (i + 1))
        assert any(f["key"].startswith("action.broken.")
                   for f in alerts.evaluate())

        from app.models import AppSetting
        AppSetting.set(alerts.K_CHK_ACTIONS, "0")
        assert not any(f["key"].startswith("action.broken.")
                       for f in alerts.evaluate())
