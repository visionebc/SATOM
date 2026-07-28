"""Scheduled automations honour maintenance mode.

``Appliance.maintenance`` suppressed *alerts* but not *work*: the hourly sweep
kept SSH/REST-ing boxes the operator had explicitly parked and counted each as a
failure, pinning the action permanently ``failed``. Once a failing automation
raises its own alert (``alerts._check_actions``), that becomes a permanently
critical mail about boxes nobody expects to answer — the "always red, therefore
ignored" mode this codebase keeps designing against.

A manual run still reaches a parked box on purpose: you park one precisely to
work on it.
"""
from __future__ import annotations

import pytest

from app.models import Appliance, ScheduledAction, db
from app.services import scheduled_actions as sa


def _dev(name, kind="fortiweb", maintenance=False):
    a = Appliance(name=name, host=f"10.0.0.{abs(hash(name)) % 200 + 20}",
                  port=443, kind=kind, username="admin", maintenance=maintenance)
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


def _action(targets="[]", action="device_sync"):
    row = ScheduledAction(name="hourly sync", action=action, product="fortiweb",
                          schedule_kind="interval", targets=targets)
    db.session.add(row)
    db.session.commit()
    return row


def _spec():
    spec = sa.get_spec("device_sync")
    assert spec is not None and spec.needs_targets
    return spec


def test_scheduled_run_skips_parked_appliances(app):
    with app.app_context():
        live = _dev("live-fw")
        _dev("parked-fw", maintenance=True)
        got = sa._resolve_targets(_action(), _spec(), trigger="schedule")
        assert [d.name for d in got] == [live.name]


def test_manual_run_still_reaches_a_parked_appliance(app):
    """You park a box to work on it — the manual path must not be blocked."""
    with app.app_context():
        _dev("live-fw")
        _dev("parked-fw", maintenance=True)
        got = sa._resolve_targets(_action(), _spec(), trigger="manual")
        assert {d.name for d in got} == {"live-fw", "parked-fw"}


def test_default_trigger_is_the_automatic_one(app):
    """Any caller that forgets the kwarg must get the safe behaviour."""
    with app.app_context():
        _dev("parked-fw", maintenance=True)
        assert sa._resolve_targets(_action(), _spec()) == []


def test_all_targets_parked_is_skipped_not_failed(app):
    """The difference that matters: 'skipped' does not feed the failure streak,
    so a fleet parked on purpose never raises a critical alert."""
    with app.app_context():
        _dev("parked-a", maintenance=True)
        _dev("parked-b", maintenance=True)
        status, summary, log = sa._run_targets(_action(), _spec(), {},
                                               trigger="schedule")
        assert status == "skipped"
        assert "maintenance" in summary
        assert "parked-a" in summary and "parked-b" in summary


def test_no_appliances_at_all_is_still_skipped_with_its_own_wording(app):
    with app.app_context():
        status, summary, _ = sa._run_targets(_action(), _spec(), {},
                                             trigger="schedule")
        assert status == "skipped"
        assert "No matching" in summary


def test_parked_targets_lists_only_this_actions_kinds(app):
    """deep_capture is FortiWeb-only; a parked FortiADC is not its business.
    (device_sync deliberately spans all three products, so it is the wrong
    spec to prove a kind filter with.)"""
    with app.app_context():
        _dev("parked-fw", maintenance=True)
        _dev("parked-adc", kind="fortiadc", maintenance=True)
        _dev("live-fw")
        fw_only = sa.get_spec("deep_capture")
        assert fw_only.products == ("fortiweb",)
        row = _action(action="deep_capture")
        assert sa._parked_targets(row, fw_only) == ["parked-fw"]
        # the multi-product spec sees both, which is correct for it
        assert sorted(sa._parked_targets(_action(), _spec())) == ["parked-adc", "parked-fw"]


def test_explicit_target_list_is_respected(app):
    with app.app_context():
        a = _dev("chosen")
        _dev("other")
        row = _action(targets=f"[{a.id}]")
        assert [d.name for d in sa._resolve_targets(row, _spec(),
                                                    trigger="schedule")] == ["chosen"]
