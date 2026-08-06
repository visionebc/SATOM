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

import os
import sys

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


# ---------------------------------------------------------------------------
# The deep-monitor sweep was the one automatic path maintenance did NOT reach.
# It opened SSH and REST connections to parked boxes every few minutes. That
# stayed invisible until retired appliance rows had their hosts recycled, at
# which point the sweep was authenticating against unrelated live hardware --
# with a 3-attempt admin lockout on the other end. Host-key verification, not
# design, is what stopped it.
# ---------------------------------------------------------------------------

def _probe(dev, name, enabled=True):
    from app.models import MonitorProbe
    p = MonitorProbe(appliance_id=(dev.id if dev is not None else None),
                     kind="cpu", name=name, enabled=enabled, interval_min=3)
    db.session.add(p)
    db.session.commit()
    return p


def test_the_probe_sweep_skips_parked_appliances(app):
    with app.app_context():
        from app.services import deep_monitor as dm
        live = _dev("live-box")
        parked = _dev("parked-box", maintenance=True)
        _probe(live, "cpu-live")
        _probe(parked, "cpu-parked")

        names = {p.name for p in dm.due_probes(force=False)}

        assert "cpu-live" in names
        assert "cpu-parked" not in names, (
            "a parked appliance was still being probed on the scheduled path")


def test_a_manual_probe_run_still_reaches_a_parked_appliance(app):
    """Anti-vacuity: 'skip everything' would satisfy the test above.

    You park a device precisely in order to work on it, so *Probe now* has to
    reach it -- the same split scheduled_actions already draws.
    """
    with app.app_context():
        from app.services import deep_monitor as dm
        parked = _dev("parked-box", maintenance=True)
        _probe(parked, "cpu-parked")

        names = {p.name for p in dm.due_probes(force=True)}

        assert "cpu-parked" in names, "a manual run must still reach a parked box"


def test_a_probe_with_no_appliance_is_never_treated_as_parked(app):
    """A bare URL check has no appliance row. Dropping it would stop
    collecting and read as healthy -- the failure this repo keeps designing
    against. Absence of a device is not evidence of maintenance."""
    with app.app_context():
        from app.services import deep_monitor as dm
        _dev("parked-box", maintenance=True)
        _probe(None, "bare-url")

        assert "bare-url" in {p.name for p in dm.due_probes(force=False)}


# --- and the CLI must stop calling that expected state "lost coverage" ------

def _row(pid, name, enabled, status, dev, maint):
    return [pid, "cpu", name, enabled, status, "2026-08-06 14:00", 3,
            "detail", dev, maint]


def _monitors(monkeypatch, rows):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "deploy"))
    from satom_cli import cmd_ops, dbq
    monkeypatch.setattr(dbq, "query", lambda ctx, q: (rows, None))
    return cmd_ops.monitor_status(object(), [])


def test_a_parked_appliances_disabled_probe_is_not_lost_coverage(monkeypatch):
    res = _monitors(monkeypatch, [
        _row(1, "cpu-parked", False, "crit", "retired-box", True),
        _row(2, "cpu-live", True, "ok", "live-box", False),
    ])
    assert res.data["disabled"] == 0, (
        "disabling the probes of a device you parked is the correct response "
        "to parking it, not lost coverage")
    assert res.data["disabled_parked"] == 1
    assert res.status == "ok"


def test_a_live_appliances_disabled_probe_is_still_lost_coverage(monkeypatch):
    """Anti-vacuity: the exemption is about maintenance, not about being
    disabled. Silence on a box nobody parked is coverage that went missing."""
    res = _monitors(monkeypatch, [
        _row(1, "cpu-live", False, "ok", "live-box", False),
    ])
    assert res.data["disabled"] == 1
    assert res.data["disabled_parked"] == 0


def test_a_live_probe_in_crit_still_fails_the_check(monkeypatch):
    """The exemption must not be able to mask a real failure."""
    res = _monitors(monkeypatch, [
        _row(1, "cpu-parked", False, "crit", "retired-box", True),
        _row(2, "cpu-live", True, "crit", "live-box", False),
    ])
    assert res.status not in ("ok",), "a live probe in crit stopped failing"
