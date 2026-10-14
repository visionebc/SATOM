"""Serialize the schema bootstrap across gunicorn workers.

Every worker runs ``create_app()`` on its own (no ``--preload``), so the boot
block (``db.create_all()``, the additive column/width/index passes and the
seeds) runs four times at once. When a release adds a table, two workers issue
the same ``CREATE TABLE`` and the loser dies on
``pg_type_typname_nsp_index`` — the worker exits with code 3, gunicorn shuts
the whole master down, and the web is down until systemd restarts it
(a1, 2026-10-14 10:14, table ``diag_catalogs``).

A Postgres session-level advisory lock makes the block run one worker at a
time; the second worker then finds the table already there. The wait is
bounded (``lock_timeout``): a peer stuck mid-boot must not hold every other
worker forever, so on timeout the boot proceeds unlocked, which is exactly the
old behaviour, and says so in the log. Other databases (SQLite in tests) have
no peers and skip the lock.

If the process dies while holding the lock, Postgres releases it with the
connection.
"""
from __future__ import annotations

import logging

from sqlalchemy import text

log = logging.getLogger(__name__)

#: Arbitrary, fixed 64-bit key: "SATOMBOT" in ASCII.
BOOT_LOCK_KEY = 0x5341544F4D424F54
LOCK_WAIT = "120s"


def acquire(engine):
    """Take the bootstrap lock. Returns the holding connection, or ``None``
    when there is nothing to lock (not Postgres) or the wait timed out."""
    if getattr(engine.dialect, "name", "") != "postgresql":
        return None
    conn = engine.connect()
    try:
        conn.execute(text(f"SET lock_timeout = '{LOCK_WAIT}'"))
        conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": BOOT_LOCK_KEY})
        conn.commit()
        return conn
    except Exception:  # noqa: BLE001 — a lock we cannot take must not block boot
        log.warning("schema bootstrap lock not acquired within %s; booting "
                    "unlocked (a concurrent CREATE TABLE may fail)", LOCK_WAIT,
                    exc_info=True)
        try:
            conn.rollback()
            conn.close()
        except Exception:  # noqa: BLE001
            pass
        return None


def release(conn) -> None:
    """Release a lock taken by :func:`acquire` (``None`` is a no-op)."""
    if conn is None:
        return
    try:
        conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": BOOT_LOCK_KEY})
        conn.commit()
    except Exception:  # noqa: BLE001 — closing the connection releases it anyway
        log.warning("schema bootstrap lock release failed; closing the "
                    "connection releases it", exc_info=True)
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
