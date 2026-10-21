"""Headless scheduler sidecar — the ONLY process that fires scheduled actions.

Runs as its own systemd unit (``satom-scheduler.service``), NOT inside
the gunicorn web workers (4 workers would otherwise fire every job up to 4×).
Single instance + a per-action DB-claim lease (``scheduled_action.running_at``)
guarantee each due action runs exactly once.

Ticks every ~45s: claims due actions and runs them through the shared
``scheduled_actions.execute_and_record`` path. Non-catch-up actions that are
badly overdue are rolled forward WITHOUT running (so a box that was off for a
week doesn't fire a week of backups at once).

Launch:  ``python -m app.scheduler_runtime`` (from /opt/satom).
"""
from __future__ import annotations

import signal
import time
from datetime import datetime

from sqlalchemy import text

from app import create_app
from app.models import db
from app.services import library_jobs, scheduled_actions, scheduler

def _configured_tz() -> str:
    """Wall-clock schedules ("daily at 02:00") are LOCAL times. The sidecar runs
    in UTC, so it has to be told which clock the operator meant — otherwise a
    nightly job drifts an hour twice a year with nothing in any log to show it."""
    from app.services import settings_store
    try:
        return settings_store.tz_name()
    except Exception:  # noqa: BLE001 - never stop the loop over a settings read
        return "UTC"


TICK_SECONDS = 45
_stop = False


def _handle_stop(signum, frame):  # noqa: ANN001
    global _stop
    _stop = True


def tick(app) -> None:
    with app.app_context():
        now = datetime.utcnow()
        # Hand back any lease a dead fire is still holding, BEFORE asking what
        # is due - due_actions() filters leased actions out, so reaping after
        # it would delay every recovery by a full tick for no reason.
        try:
            reaped = scheduled_actions.reap_stale_leases(now)
            for r in reaped:
                if r["kind"] == "lease":
                    print("reaped stale lease: #%s %s held %s min since %s; "
                          "next run %s"
                          % (r["id"], r["name"], r["held_minutes"],
                             r["held_since"], r["next_run"]), flush=True)
                else:
                    print("closed orphan run %s of #%s %s, open %s min "
                          "since %s" % (r["run_id"], r["id"], r["name"],
                                        r["held_minutes"], r["held_since"]),
                          flush=True)
        except Exception:  # noqa: BLE001 - a failed reap must not stop the tick
            db.session.rollback()
        # A lease whose process is gone (a restart killed the fire) does not
        # wait for the TTL: the claim marker names the owner.
        try:
            for r in scheduled_actions.reap_dead_owner_leases(now):
                print("released lease of ended pid %s: #%s %s held %s min since %s; "
                      "next run %s" % (r["pid"], r["id"], r["name"], r["held_minutes"],
                                       r["held_since"], r["next_run"]), flush=True)
        except Exception:  # noqa: BLE001 - a failed reap must not stop the tick
            db.session.rollback()
        for action in scheduled_actions.due_actions(now):
            spec = action.schedule_dict
            if (not action.catch_up
                    and scheduler.is_missed_fire(action.schedule_kind, spec, action.next_run, now)):
                # Overdue + no catch-up → roll forward, do not run.
                action.next_run = scheduler.compute_next_run(
                    action.schedule_kind, spec, now, tz=_configured_tz())
                action.last_status = "missed"
                db.session.commit()
                continue
            try:
                scheduled_actions.execute_and_record(action, trigger="schedule")
            except Exception:  # noqa: BLE001 — one bad action must not kill the loop
                db.session.rollback()
        # Script Library saved runs (cron): they live on disk next to the
        # scripts, so they are fired here rather than through scheduled_action.
        try:
            from app.services import script_schedules
            for sid in script_schedules.fire_due(now):
                print("script schedule %s queued" % sid, flush=True)
        except Exception as exc:  # noqa: BLE001 - never stop the loop over this
            print("script schedules: %s" % exc, flush=True)
        # The syslog receiver lives in THIS process (one listener thread, never
        # in the gunicorn workers). The tick only starts/stops it to match the
        # setting and drains its counters into the store; it never waits on
        # the network. service_tick is total.
        try:
            from app.services import syslog_receiver
            syslog_receiver.service_tick()
        except Exception as exc:  # noqa: BLE001 - never stop the loop over this
            print("syslog receiver: %s" % exc, flush=True)
        finally:
            db.session.remove()


def main() -> None:
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)
    app = create_app()
    # WAL keeps the sidecar's writes from blocking the web workers' reads —
    # but PRAGMA journal_mode is SQLite-only. On Postgres it is a syntax error,
    # so guard on the dialect; the rollback must stay INSIDE the app context
    # (it used to dedent out, raising "Working outside of application context"
    # the moment the prod DB became Postgres). (2026-06-30)
    with app.app_context():
        try:
            if db.engine.dialect.name == "sqlite":
                db.session.execute(text("PRAGMA journal_mode=WAL"))
                db.session.commit()
        except Exception:  # noqa: BLE001
            db.session.rollback()
    while not _stop:
        try:
            tick(app)
        except Exception:  # noqa: BLE001
            pass
        for i in range(TICK_SECONDS):  # SIGTERM-responsive sleep
            if _stop:
                break
            if i % library_jobs.TICK_S == 0:
                drive_library_jobs(app)
            time.sleep(1)
    # Close the syslog socket with the process, not after it: a listener left
    # to the interpreter's exit keeps the port busy for the restart.
    try:
        from app.services import syslog_receiver
        syslog_receiver.shutdown()
    except Exception:  # noqa: BLE001
        pass


def drive_library_jobs(app) -> None:
    """Advance Libraries card jobs (this node, then the peer) between ticks.

    Here and not in the web: the change restarts the web, and nobody may need
    to keep a browser open for the peer half to happen. Cheap when idle -- one
    listdir of the active-marker directory."""
    try:
        if not library_jobs.has_active():
            return
        with app.app_context():
            library_jobs.advance_all()
            db.session.remove()
    except Exception:  # noqa: BLE001 - never stop the loop over a job
        pass


if __name__ == "__main__":
    main()
