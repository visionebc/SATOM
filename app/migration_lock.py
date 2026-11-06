"""Run the schema migration without losing a lock race to a live SATOM.

An update applies ``flask db upgrade`` while the previous release's web and
scheduler are still running (every update runner up to 4.11.2 does). A
scheduler job keeps its database transaction open while it talks to devices,
so it holds a read lock on ``appliances`` for as long as the slowest device
takes to answer. ``ALTER TABLE`` needs that table to itself (ACCESS
EXCLUSIVE), so it queued behind the job, and with the 120 s ``lock_timeout``
the boot lock left on the pooled connection it failed and the whole update
rolled back (SA-0019, ``LockNotAvailable ... ALTER TABLE appliances ADD
COLUMN tls_server_name``).

Waiting longer in one attempt is not the answer: a queued ``ALTER`` blocks
every later reader of the table, so the console would hang for as long as it
waits. Instead each attempt waits at most ``ATTEMPT_LOCK_TIMEOUT``; a failed
attempt rolls back (Postgres DDL is transactional, and the migrations are
idempotent via app.migration_guard) and the next one runs after a short pause,
in the gap between two scheduler transactions. Only when no attempt got the
lock before ``DEADLINE_S`` does the migration fail, naming the sessions that
held it and how to clear them. The deadline stays below the 600 s an update
runner gives ``flask db upgrade``.

This file is reached from ``migrations/env.py``, which is the new release's
code even when an older runner applies the update -- that is why the fix lives
here and not in the runner.
"""
from __future__ import annotations

import logging
import os
import time

log = logging.getLogger("alembic.env")

#: Longest one attempt waits for a table lock (Postgres interval syntax).
ATTEMPT_LOCK_TIMEOUT = os.environ.get("SATOM_MIGRATION_LOCK_TIMEOUT", "5s")
#: Give up after this many seconds of retrying.
DEADLINE_S = int(os.environ.get("SATOM_MIGRATION_LOCK_DEADLINE_S", "420"))
#: Pause between attempts: 2, 4, 8, then every 15 s.
PAUSES = (2, 4, 8, 15)

LOCK_NOT_AVAILABLE = "55P03"

FIX_HINT = ("Stop the scheduler (as root: satom execute stop scheduler) and "
            "apply the update again; the update starts it afterwards.")


class MigrationLockTimeout(RuntimeError):
    """No attempt got its table locks before the deadline."""


def is_lock_timeout(exc: BaseException) -> bool:
    """True for Postgres ``lock_not_available`` (55P03), however wrapped."""
    seen = set()
    cur = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        code = (getattr(cur, "sqlstate", None) or getattr(cur, "pgcode", None))
        if code == LOCK_NOT_AVAILABLE:
            return True
        cur = getattr(cur, "orig", None) or cur.__cause__
    return False


def set_attempt_lock_timeout(connection) -> None:
    """Bound this attempt's waits. SET LOCAL: it ends with the transaction,
    so nothing is left on a pooled connection."""
    if connection.dialect.name != "postgresql":
        return
    connection.exec_driver_sql(
        "SET LOCAL lock_timeout = '%s'" % ATTEMPT_LOCK_TIMEOUT.replace("'", ""))


BLOCKERS_SQL = (
    "SELECT pid, coalesce(nullif(application_name, ''), usename) AS who, state, "
    "round(extract(epoch FROM now() - xact_start)) AS age_s "
    "FROM pg_stat_activity WHERE datname = current_database() "
    "AND pid <> pg_backend_pid() AND xact_start IS NOT NULL "
    "AND now() - xact_start > interval '5 seconds' "
    "ORDER BY xact_start LIMIT 5")


def describe_blockers(engine) -> str:
    """The open transactions that can be holding the lock, for the log.
    Best effort: a failure here must not hide the real error."""
    try:
        if engine.dialect.name != "postgresql":
            return ""
        with engine.connect() as conn:
            rows = conn.exec_driver_sql(BLOCKERS_SQL).fetchall()
    except Exception:  # noqa: BLE001
        return ""
    return "; ".join("pid %s (%s, %s, transaction open %ss)" % tuple(r)
                     for r in rows)


def run_with_retry(attempt, *, engine=None, deadline_s: float = None,
                   sleep=time.sleep, clock=time.monotonic) -> None:
    """Call ``attempt()`` until it does not fail on a lock timeout.

    ``attempt`` runs the whole migration in one transaction. Any other error
    is raised at once; a lock timeout after the deadline raises
    :class:`MigrationLockTimeout` carrying the blockers and the fix."""
    deadline_s = DEADLINE_S if deadline_s is None else deadline_s
    end = clock() + deadline_s
    n = 0
    while True:
        n += 1
        try:
            attempt()
            if n > 1:
                log.info("schema migration applied on attempt %d", n)
            return
        except Exception as exc:  # noqa: BLE001 — re-raised unless a lock timeout
            if not is_lock_timeout(exc):
                raise
            blockers = describe_blockers(engine) if engine is not None else ""
            if clock() >= end:
                raise MigrationLockTimeout(
                    "the schema migration could not lock its tables in %d s "
                    "(%d attempts of %s each): another SATOM process kept a "
                    "transaction open the whole time%s. Nothing was changed. %s"
                    % (deadline_s, n, ATTEMPT_LOCK_TIMEOUT,
                       " -- " + blockers if blockers else "", FIX_HINT)) from exc
            pause = PAUSES[min(n - 1, len(PAUSES) - 1)]
            log.warning("schema migration attempt %d: a table it changes is in "
                        "use%s; retrying in %d s", n,
                        " (" + blockers + ")" if blockers else "", pause)
            sleep(pause)
