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
from app.services import scheduled_actions, scheduler

TICK_SECONDS = 45
_stop = False


def _handle_stop(signum, frame):  # noqa: ANN001
    global _stop
    _stop = True


def tick(app) -> None:
    with app.app_context():
        now = datetime.utcnow()
        for action in scheduled_actions.due_actions(now):
            spec = action.schedule_dict
            if (not action.catch_up
                    and scheduler.is_missed_fire(action.schedule_kind, spec, action.next_run, now)):
                # Overdue + no catch-up → roll forward, do not run.
                action.next_run = scheduler.compute_next_run(action.schedule_kind, spec, now)
                action.last_status = "missed"
                db.session.commit()
                continue
            try:
                scheduled_actions.execute_and_record(action, trigger="schedule")
            except Exception:  # noqa: BLE001 — one bad action must not kill the loop
                db.session.rollback()


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
        for _ in range(TICK_SECONDS):  # SIGTERM-responsive sleep
            if _stop:
                break
            time.sleep(1)


if __name__ == "__main__":
    main()
