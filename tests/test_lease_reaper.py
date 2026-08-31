"""The scheduler must be able to lose a fire without losing the action.

``scheduled_action.running_at`` is claimed with a COMMITTED update before any
work starts, and ``due_actions`` filters leased actions out. So every way a fire
can die without reaching its ``finally`` - SIGKILL, OOM, a database that goes
away, an exception raised in the window before the try block even opens - used
to remove the action from the scheduler permanently. Not "the action fails":
the action silently stops existing, with an ``ok`` last_status still on the row
and a green unit in systemd.

That is not hypothetical. On 2026-08-22 Postgres went away on satom-node-1
between the claim commit and the history-row commit of three nightly actions.
The exception escaped ``execute_and_record`` (whose try/finally had not started
yet), the sidecar's own ``except`` rolled back a transaction that no longer held
anything, and actions 6 (deep capture), 7 (certificate scan) and 23 (CVE mirror)
sat leased for **nine days**. Two other actions that same second (15, 21) got one
statement further, so their leases were freed by the last-ditch branch - but
their history rows stayed 'running' forever, because the rollback discarded the
status write that the last-ditch branch does not repeat.

Both halves are guarded here, plus the backup check that fired on its own policy
working.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.models import AppSetting, ScheduledAction, ScheduledActionRun, db
from app.services import alerts, scheduled_actions as sa


def _action(**kw):
    a = ScheduledAction(
        name=kw.pop("name", "nightly deep capture"),
        action=kw.pop("action", "deep_capture"),
        product=kw.pop("product", "fortiweb"),
        schedule_kind=kw.pop("schedule_kind", "daily"),
        schedule=kw.pop("schedule", '{"time": "03:30"}'),
        enabled=kw.pop("enabled", True),
        next_run=kw.pop("next_run", datetime.utcnow() - timedelta(days=9)),
        **kw)
    db.session.add(a)
    db.session.commit()
    return a


# --------------------------------------------------------------- the reaper
def test_a_lease_inside_the_ttl_is_left_alone(app):
    """The longest run this fleet has ever recorded is 5.5 minutes. A reaper
    that took leases back too eagerly would fire a second copy of a live run -
    a worse bug than the one it fixes."""
    with app.app_context():
        a = _action(running_at=datetime.utcnow() - timedelta(minutes=10))
        db.session.commit()
        assert sa.reap_stale_leases(ttl_minutes=60) == []
        assert ScheduledAction.query.get(a.id).running_at is not None


def test_a_lease_past_the_ttl_is_released_and_rescheduled(app):
    with app.app_context():
        held = datetime.utcnow() - timedelta(days=9)
        a = _action(running_at=held)
        out = sa.reap_stale_leases(ttl_minutes=60)

        assert [r["id"] for r in out] == [a.id]
        row = ScheduledAction.query.get(a.id)
        assert row.running_at is None, "the lease must be handed back"
        assert row.next_run is not None and row.next_run > datetime.utcnow(), \
            "a released lease with a past next_run would still never fire"
        assert row.last_status == "failed"
        assert row.last_run == held, \
            "last_run must point at the fire that died, not at the reap"


def test_the_reaped_action_becomes_due_again(app):
    """The regression in one assertion: leased -> invisible to due_actions."""
    with app.app_context():
        a = _action(running_at=datetime.utcnow() - timedelta(days=9),
                    next_run=datetime.utcnow() - timedelta(days=9))
        later = datetime.utcnow() + timedelta(days=2)
        assert a.id not in [x.id for x in sa.due_actions(later)]
        sa.reap_stale_leases(ttl_minutes=60)
        assert a.id in [x.id for x in sa.due_actions(later)], \
            "after the reap the action has to come back into the queue"


def test_a_reap_with_no_history_row_records_the_gap(app):
    """Actions 6/7/23: the claim committed, the history INSERT never did, so
    there is no row to close. Writing none would leave a nine-day hole that
    reads as 'idle' rather than 'broken'."""
    with app.app_context():
        a = _action(running_at=datetime.utcnow() - timedelta(days=9))
        out = sa.reap_stale_leases(ttl_minutes=60)
        assert out[0]["closed_runs"] == 0

        runs = ScheduledActionRun.query.filter_by(action_id=a.id).all()
        assert len(runs) == 1
        assert runs[0].status == "failed"
        assert runs[0].finished_at is not None
        assert runs[0].trigger == "schedule", \
            "_check_actions only counts scheduled runs; any other trigger is invisible"
        assert "Lease reaped" in runs[0].summary


def test_a_reap_closes_the_run_row_the_dead_fire_left_open(app):
    """Actions 15/21: the row exists and says 'running' forever."""
    with app.app_context():
        a = _action(running_at=datetime.utcnow() - timedelta(days=9))
        r = ScheduledActionRun(action_id=a.id, status="running",
                               trigger="schedule",
                               started_at=datetime.utcnow() - timedelta(days=9))
        db.session.add(r)
        db.session.commit()

        out = sa.reap_stale_leases(ttl_minutes=60)
        assert out[0]["closed_runs"] == 1
        rows = ScheduledActionRun.query.filter_by(action_id=a.id).all()
        assert len(rows) == 1, "close the existing row, do not add a second one"
        assert rows[0].status == "failed"
        assert rows[0].finished_at is not None


def test_the_reap_is_visible_to_the_alert_engine(app):
    """A recovery nobody can see is indistinguishable from the outage going on."""
    with app.app_context():
        a = _action(running_at=datetime.utcnow() - timedelta(days=9))
        sa.reap_stale_leases(ttl_minutes=60)
        found = [f for f in alerts._check_actions() if str(a.id) in f["title"]]
        assert found, "a reaped lease must reach _check_actions"
        assert "Lease reaped" in found[0]["detail"]


def test_nothing_stale_is_a_no_op(app):
    with app.app_context():
        _action(running_at=None)
        assert sa.reap_stale_leases(ttl_minutes=60) == []


def test_a_disabled_action_is_still_reaped(app):
    """An action disabled while leased would keep the lease across a re-enable,
    and come back already invisible."""
    with app.app_context():
        a = _action(enabled=False,
                    running_at=datetime.utcnow() - timedelta(days=9))
        assert [r["id"] for r in sa.reap_stale_leases(ttl_minutes=60)] == [a.id]
        assert ScheduledAction.query.get(a.id).running_at is None


# ------------------------------------------------------------------ the TTL
def test_the_ttl_is_operator_tunable(app):
    with app.app_context():
        a = _action(running_at=datetime.utcnow() - timedelta(minutes=30))
        assert sa.reap_stale_leases() == [], "default TTL is 60 min"
        AppSetting.set("scheduler.lease_ttl_minutes", "10")
        assert [r["id"] for r in sa.reap_stale_leases()] == [a.id]


def test_a_broken_ttl_setting_falls_back_instead_of_disabling_the_reaper(app):
    """A setting typo must not silently restore the nine-day failure mode."""
    with app.app_context():
        AppSetting.set("scheduler.lease_ttl_minutes", "not a number")
        assert sa._lease_ttl_minutes() == sa.LEASE_TTL_MINUTES
        AppSetting.set("scheduler.lease_ttl_minutes", "0")
        assert sa._lease_ttl_minutes() == sa.LEASE_TTL_MINUTES


# ------------------------------------------- the window that caused the bug
def test_a_failure_opening_the_history_row_hands_the_lease_back(app, monkeypatch):
    """THE regression. Anything that raises between the claim and the try block
    must release the lease on its way out."""
    with app.app_context():
        a = _action(running_at=None)

        def boom(*args, **kw):
            raise RuntimeError("connection to server was lost")

        monkeypatch.setattr(sa, "ScheduledActionRun", boom)
        with pytest.raises(RuntimeError):
            sa.execute_and_record(a, trigger="schedule")

        db.session.rollback()
        assert ScheduledAction.query.get(a.id).running_at is None, \
            "the lease claimed one statement earlier was never released"


def test_release_lease_clears_only_its_own_action(app):
    with app.app_context():
        held = datetime.utcnow()
        a = _action(running_at=held)
        b = _action(name="other", running_at=held)
        assert sa.release_lease(a.id) is True
        assert ScheduledAction.query.get(a.id).running_at is None
        assert ScheduledAction.query.get(b.id).running_at is not None


def test_the_sidecar_reaps_before_it_asks_what_is_due(app):
    """Reaping after due_actions() would delay every recovery by a full tick,
    because due_actions() is exactly the query that cannot see a leased row."""
    from app import scheduler_runtime
    with app.app_context():
        aid = _action(running_at=datetime.utcnow() - timedelta(days=9),
                      next_run=datetime.utcnow() - timedelta(days=9)).id
    scheduler_runtime.tick(app)
    with app.app_context():
        row = ScheduledAction.query.get(aid)
        assert row.running_at is None, "the sidecar tick never called the reaper"
        assert row.next_run > datetime.utcnow()


# ------------------------- phase 2: the row whose lease freed itself
def test_an_orphan_run_row_is_closed_even_though_the_lease_is_gone(app):
    """Actions 15 and 21 on 2026-08-22. The last-ditch branch of the finally
    clears running_at with a bare UPDATE after the rollback already discarded
    the status write, so the action recovers and the row says 'running'
    forever. Phase 1 iterates LEASED actions and can never reach these."""
    with app.app_context():
        a = _action(running_at=None)
        r = ScheduledActionRun(action_id=a.id, status="running",
                               trigger="schedule",
                               started_at=datetime.utcnow() - timedelta(days=9))
        db.session.add(r)
        db.session.commit()

        out = sa.reap_stale_leases(ttl_minutes=60)
        assert [x["kind"] for x in out] == ["orphan-run"]
        assert ScheduledActionRun.query.get(r.id).status == "failed"
        assert ScheduledActionRun.query.get(r.id).finished_at is not None
        assert "Never finished" in ScheduledActionRun.query.get(r.id).summary


def test_a_live_run_row_is_never_closed(app):
    """A row younger than the TTL may simply belong to a fire that started
    between the lease read and the row read. Closing it would report a running
    job as failed - and _check_actions would raise an alert on healthy work."""
    with app.app_context():
        a = _action(running_at=None)
        r = ScheduledActionRun(action_id=a.id, status="running",
                               trigger="schedule",
                               started_at=datetime.utcnow() - timedelta(minutes=2))
        db.session.add(r)
        db.session.commit()
        assert sa.reap_stale_leases(ttl_minutes=60) == []
        assert ScheduledActionRun.query.get(r.id).status == "running"


def test_an_old_row_under_a_live_lease_is_never_closed(app):
    """The other half of the AND: a genuinely long fire holds its lease, and
    the reaper must leave both the lease and the row alone until the TTL."""
    with app.app_context():
        a = _action(running_at=datetime.utcnow() - timedelta(minutes=10))
        r = ScheduledActionRun(action_id=a.id, status="running",
                               trigger="schedule",
                               started_at=datetime.utcnow() - timedelta(days=9))
        db.session.add(r)
        db.session.commit()
        assert sa.reap_stale_leases(ttl_minutes=60) == []
        assert ScheduledActionRun.query.get(r.id).status == "running"


def test_phase_two_runs_even_when_no_lease_is_stale(app):
    """An early return on 'no stale leases' would skip the orphan sweep
    entirely - and the normal state of a healthy fleet is exactly that."""
    with app.app_context():
        a = _action(running_at=None)
        r = ScheduledActionRun(action_id=a.id, status="running",
                               trigger="schedule",
                               started_at=datetime.utcnow() - timedelta(days=9))
        db.session.add(r)
        db.session.commit()
        assert ScheduledAction.query.filter(
            ScheduledAction.running_at.isnot(None)).count() == 0
        assert len(sa.reap_stale_leases(ttl_minutes=60)) == 1


def test_a_closed_orphan_reaches_the_alert_engine(app):
    with app.app_context():
        a = _action(running_at=None)
        db.session.add(ScheduledActionRun(
            action_id=a.id, status="running", trigger="schedule",
            started_at=datetime.utcnow() - timedelta(days=9)))
        db.session.commit()
        sa.reap_stale_leases(ttl_minutes=60)
        found = [f for f in alerts._check_actions() if str(a.id) in f["title"]]
        assert found and "Never finished" in found[0]["detail"]


def test_phase_one_does_not_double_handle_its_own_rows(app):
    """A row closed by phase 1 must not be picked up again by phase 2 and
    reported twice - the operator would read one dead fire as two."""
    with app.app_context():
        a = _action(running_at=datetime.utcnow() - timedelta(days=9))
        db.session.add(ScheduledActionRun(
            action_id=a.id, status="running", trigger="schedule",
            started_at=datetime.utcnow() - timedelta(days=9)))
        db.session.commit()
        out = sa.reap_stale_leases(ttl_minutes=60)
        assert [x["kind"] for x in out] == ["lease"]
        assert ScheduledActionRun.query.filter_by(action_id=a.id).count() == 1


def test_every_repair_is_tagged_with_its_kind(app):
    """The sidecar branches on 'kind' to print the right sentence; an untagged
    entry would KeyError inside the except that protects the tick."""
    with app.app_context():
        a = _action(running_at=datetime.utcnow() - timedelta(days=9))
        b = _action(name="other", running_at=None)
        db.session.add(ScheduledActionRun(
            action_id=b.id, status="running", trigger="schedule",
            started_at=datetime.utcnow() - timedelta(days=9)))
        db.session.commit()
        out = sa.reap_stale_leases(ttl_minutes=60)
        assert sorted(x["kind"] for x in out) == ["lease", "orphan-run"]
        assert all({"id", "name", "held_minutes", "held_since"} <= set(x)
                   for x in out)


# ------------------------------------------------ the backup check's own bug
def _bk(monkeypatch, bundles):
    from app.services import system_backup
    monkeypatch.setattr(system_backup, "all_bundles", lambda: bundles)


def test_an_off_box_only_bundle_is_not_no_backups(app, monkeypatch):
    """Default retention is keep=0: the local copy is deleted once the upload is
    verified byte for byte. A local-only check therefore fired 'No database
    backup bundles present' every day, on the policy WORKING."""
    with app.app_context():
        _bk(monkeypatch, [{"name": "fmw-backup-%s-120000.tar.gz"
                                   % datetime.utcnow().strftime("%Y%m%d"),
                           "size": 123, "created": "", "local": False,
                           "off_box": True}])
        assert alerts._check_backup() == []


def test_an_off_box_bundle_still_ages(app, monkeypatch):
    """The name is the only clock an off-box row has; ignoring it would make
    every remote bundle look eternally fresh - a worse lie than the false
    alarm this replaced."""
    with app.app_context():
        old = (datetime.utcnow() - timedelta(days=9)).strftime("%Y%m%d")
        _bk(monkeypatch, [{"name": "fmw-backup-%s-013000.tar.gz" % old,
                           "size": 123, "created": "", "local": False,
                           "off_box": True}])
        out = alerts._check_backup()
        assert len(out) == 1 and out[0]["key"] == "backup.stale"


def test_nothing_anywhere_still_warns(app, monkeypatch):
    with app.app_context():
        _bk(monkeypatch, [])
        out = alerts._check_backup()
        assert len(out) == 1 and out[0]["key"] == "backup.none"
        assert "backup server" in out[0]["detail"], \
            "the operator must be told both places were checked"


def test_a_local_bundle_keeps_using_its_mtime(app, monkeypatch):
    with app.app_context():
        _bk(monkeypatch, [{"name": "fmw-backup-20200101-000000.tar.gz",
                           "size": 1, "local": True, "off_box": False,
                           "created": datetime.utcnow().isoformat(
                               timespec="seconds")}])
        assert alerts._check_backup() == [], \
            "an explicit timestamp must win over the name"
