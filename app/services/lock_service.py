"""Lease-based resource locking for safe multi-user editing.

HTTP is stateless, so we cannot hold a row lock for the duration of an edit
session. Instead each editor acquires a short LEASE on a resource (e.g.
``server_policy:pol-x`` on a given appliance), refreshed by a JS heartbeat. If
the browser tab is abandoned the lease simply EXPIRES and another user can take
over. A DB unique constraint on (appliance_id, resource_key) makes acquire
race-free across the gunicorn workers + scheduler.

Pure over the Store-style session: every function takes an optional ``session``
so the tests drive it on a temp SQLite DB and the workers use their own conn.
"""
from __future__ import annotations

from datetime import datetime, timedelta

DEFAULT_TTL = 120          # seconds a lease is valid without a heartbeat
HEARTBEAT_EVERY = 30       # seconds (the JS cadence; informational here)


def _now():
    return datetime.utcnow()


def _purge_expired(session, appliance_id, resource_key, now):
    from ..models_cache import ResourceLock
    (session.query(ResourceLock)
     .filter(ResourceLock.appliance_id == appliance_id,
             ResourceLock.resource_key == resource_key,
             ResourceLock.expires_at < now)
     .delete(synchronize_session=False))


def _info(lock):
    return {
        "appliance_id": lock.appliance_id,
        "resource_key": lock.resource_key,
        "owner_user_id": lock.owner_user_id,
        "owner_label": lock.owner_label,
        "acquired_at": lock.acquired_at.isoformat() if lock.acquired_at else None,
        "heartbeat_at": lock.heartbeat_at.isoformat() if lock.heartbeat_at else None,
        "expires_at": lock.expires_at.isoformat() if lock.expires_at else None,
    }


def acquire(appliance_id, resource_key, *, user_id=None, owner_label=None,
            ttl=DEFAULT_TTL, session=None, now=None):
    """Try to take the lease. Returns (ok, info).

    ok=True  → caller owns the lease (info is theirs).
    ok=False → someone else holds a live lease (info is the holder's).
    A lease owned by the SAME user is refreshed (re-entrant).
    """
    from ..extensions import db
    from ..models_cache import ResourceLock
    from sqlalchemy.exc import IntegrityError
    session = session or db.session
    now = now or _now()

    _purge_expired(session, appliance_id, resource_key, now)
    session.flush()

    existing = (session.query(ResourceLock)
                .filter_by(appliance_id=appliance_id, resource_key=resource_key)
                .first())
    if existing is not None:
        if user_id is not None and existing.owner_user_id == user_id:
            existing.heartbeat_at = now
            existing.expires_at = now + timedelta(seconds=ttl)
            if owner_label:
                existing.owner_label = owner_label
            session.commit()
            return True, _info(existing)
        return False, _info(existing)

    lock = ResourceLock(
        appliance_id=appliance_id, resource_key=resource_key,
        owner_user_id=user_id, owner_label=owner_label,
        acquired_at=now, heartbeat_at=now,
        expires_at=now + timedelta(seconds=ttl))
    session.add(lock)
    try:
        session.commit()
    except IntegrityError:
        # Lost the race to another worker — report the winner.
        session.rollback()
        winner = (session.query(ResourceLock)
                  .filter_by(appliance_id=appliance_id, resource_key=resource_key)
                  .first())
        if winner is not None and (user_id is None or winner.owner_user_id != user_id):
            return False, _info(winner)
        return (winner is not None), (_info(winner) if winner else None)
    return True, _info(lock)


def heartbeat(appliance_id, resource_key, *, user_id=None, ttl=DEFAULT_TTL,
              session=None, now=None):
    """Extend the lease if the caller still owns it. Returns (ok, info)."""
    from ..extensions import db
    from ..models_cache import ResourceLock
    session = session or db.session
    now = now or _now()
    lock = (session.query(ResourceLock)
            .filter_by(appliance_id=appliance_id, resource_key=resource_key)
            .first())
    if lock is None:
        return False, None
    if lock.expires_at < now:
        return False, _info(lock)
    if user_id is not None and lock.owner_user_id != user_id:
        return False, _info(lock)
    lock.heartbeat_at = now
    lock.expires_at = now + timedelta(seconds=ttl)
    session.commit()
    return True, _info(lock)


def release(appliance_id, resource_key, *, user_id=None, session=None):
    """Release the lease if owned by the caller (or force when user_id None)."""
    from ..extensions import db
    from ..models_cache import ResourceLock
    session = session or db.session
    q = (session.query(ResourceLock)
         .filter_by(appliance_id=appliance_id, resource_key=resource_key))
    lock = q.first()
    if lock is None:
        return True
    if user_id is not None and lock.owner_user_id != user_id:
        return False
    q.delete(synchronize_session=False)
    session.commit()
    return True


def steal(appliance_id, resource_key, *, user_id=None, owner_label=None,
          ttl=DEFAULT_TTL, session=None, now=None):
    """Forcibly take over a lease (used after a clear expiry / explicit steal)."""
    from ..extensions import db
    from ..models_cache import ResourceLock
    session = session or db.session
    now = now or _now()
    (session.query(ResourceLock)
     .filter_by(appliance_id=appliance_id, resource_key=resource_key)
     .delete(synchronize_session=False))
    session.flush()
    lock = ResourceLock(
        appliance_id=appliance_id, resource_key=resource_key,
        owner_user_id=user_id, owner_label=owner_label,
        acquired_at=now, heartbeat_at=now,
        expires_at=now + timedelta(seconds=ttl))
    session.add(lock)
    session.commit()
    return True, _info(lock)


def status(appliance_id, resource_key, *, session=None, now=None):
    """Return (locked_by_other_or_none). info=None when free."""
    from ..extensions import db
    from ..models_cache import ResourceLock
    session = session or db.session
    now = now or _now()
    lock = (session.query(ResourceLock)
            .filter_by(appliance_id=appliance_id, resource_key=resource_key)
            .first())
    if lock is None or lock.expires_at < now:
        return None
    return _info(lock)
