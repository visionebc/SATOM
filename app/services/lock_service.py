"""Lease-based resource locking for safe multi-user editing.

HTTP is stateless, so we cannot hold a row lock for the duration of an edit
session. Instead each editor acquires a short LEASE on a resource (e.g.
``server-policy/policy:pol-x`` on a given appliance), refreshed by a JS
heartbeat. If the browser tab is abandoned the lease simply EXPIRES and another
user can take over. A DB unique constraint on (appliance_id, resource_key) makes
acquire race-free across the gunicorn workers + scheduler.

A lease belongs to a user AND to the editor (browser tab) that took it: each
editor sends its own ``token``. The same user with the object open in two tabs
gets the same "being edited" banner as a second user would -- until 2026-11-04
the lease was per user only, so two tabs of one operator overwrote each other
without a word. A caller that sends no token (the API, a job, an old page) is
matched on the user alone, as before.

Every writer honours a lease, not only the editors: :func:`holder` is the one
check (the object, or the object a sub-table row belongs to), and the device
clients call it for every write (``FortiWebClient._request``,
``FortiADCClient._api``, ``GuiOps.run``) with :func:`current_actor` -- the
signed-in user of a request (or the owner of a REST API token), the owner of a
background job, or nobody (an unattended run, which never writes over an
operator's open edit).

Pure over the Store-style session: every function takes an optional ``session``
so the tests drive it on a temp SQLite DB and the workers use their own conn.
"""
from __future__ import annotations

import contextlib
import contextvars
from datetime import datetime, timedelta

DEFAULT_TTL = 120          # seconds a lease is valid without a heartbeat
HEARTBEAT_EVERY = 30       # seconds (the JS cadence; informational here)

#: ``(user_id, token)`` a block of code writes as (:func:`acting_as`).
_ACTOR = contextvars.ContextVar("satom_lease_actor", default=None)


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
    # The token stays out: it names a tab, and the lease reaches other users.
    return {
        "appliance_id": lock.appliance_id,
        "resource_key": lock.resource_key,
        "owner_user_id": lock.owner_user_id,
        "owner_label": lock.owner_label,
        "acquired_at": lock.acquired_at.isoformat() if lock.acquired_at else None,
        "heartbeat_at": lock.heartbeat_at.isoformat() if lock.heartbeat_at else None,
        "expires_at": lock.expires_at.isoformat() if lock.expires_at else None,
    }


def _owns(lock, user_id, token) -> bool:
    """Does (``user_id``, ``token``) own ``lock``? The same user owns it unless
    both sides name a tab and the tabs differ."""
    if user_id is None or lock.owner_user_id != user_id:
        return False
    return not (token and lock.owner_token and token != lock.owner_token)


def _held_by_other(lock, user_id, token) -> dict:
    """The holder's info when ``lock`` keeps (``user_id``, ``token``) out."""
    info = _info(lock)
    # the same user in another tab: the page says "you, in another tab"
    info["same_user"] = user_id is not None and lock.owner_user_id == user_id
    return info


def acquire(appliance_id, resource_key, *, user_id=None, owner_label=None,
            token=None, ttl=DEFAULT_TTL, session=None, now=None):
    """Try to take the lease. Returns (ok, info).

    ok=True  → caller owns the lease (info is theirs).
    ok=False → someone else holds a live lease (info is the holder's; its
    ``same_user`` is True when that is the caller in another tab).
    A lease owned by the SAME user and tab is refreshed (re-entrant).
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
        if _owns(existing, user_id, token):
            existing.heartbeat_at = now
            existing.expires_at = now + timedelta(seconds=ttl)
            if owner_label:
                existing.owner_label = owner_label
            if token:
                existing.owner_token = token
            session.commit()
            return True, _info(existing)
        return False, _held_by_other(existing, user_id, token)

    lock = ResourceLock(
        appliance_id=appliance_id, resource_key=resource_key,
        owner_user_id=user_id, owner_label=owner_label, owner_token=token or None,
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
        if winner is not None and not _owns(winner, user_id, token):
            return False, _held_by_other(winner, user_id, token)
        return (winner is not None), (_info(winner) if winner else None)
    return True, _info(lock)


def heartbeat(appliance_id, resource_key, *, user_id=None, token=None,
              ttl=DEFAULT_TTL, session=None, now=None):
    """Extend the lease if the caller (and its tab) still owns it. Returns (ok, info)."""
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
    if user_id is not None and not _owns(lock, user_id, token):
        return False, _held_by_other(lock, user_id, token)
    lock.heartbeat_at = now
    lock.expires_at = now + timedelta(seconds=ttl)
    session.commit()
    return True, _info(lock)


def release(appliance_id, resource_key, *, user_id=None, token=None, session=None):
    """Release the lease if owned by the caller (or force when user_id None).

    A tab gives back only its own lease: closing the second tab of the same
    operator used to release the first tab's lease with it."""
    from ..extensions import db
    from ..models_cache import ResourceLock
    session = session or db.session
    q = (session.query(ResourceLock)
         .filter_by(appliance_id=appliance_id, resource_key=resource_key))
    lock = q.first()
    if lock is None:
        return True
    if user_id is not None and not _owns(lock, user_id, token):
        return False
    q.delete(synchronize_session=False)
    session.commit()
    return True


def steal(appliance_id, resource_key, *, user_id=None, owner_label=None,
          token=None, ttl=DEFAULT_TTL, session=None, now=None):
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
        owner_user_id=user_id, owner_label=owner_label, owner_token=token or None,
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


# --------------------------------------------------------------------------- #
#  The one check every writer makes                                            #
# --------------------------------------------------------------------------- #

def keys_for(coll: str, name: str) -> list:
    """The lease keys a write to ``name`` in ``coll`` falls under, the object's
    own first: ``server-policy/policy/http-content-routing-list`` + ``P`` ->
    ``…/http-content-routing-list:P``, ``server-policy/policy:P``,
    ``server-policy:P``. A sub-table row is written under its parent's name,
    so the parent's lease covers it. A FortiADC child table
    (``load_balance_pool_child_pool_member``) falls under its parent entity."""
    coll = (coll or "").strip("/")
    if not coll or not name:
        return []
    parts = coll.split("/")
    out = ["%s:%s" % ("/".join(parts[:i]), name) for i in range(len(parts), 0, -1)]
    if "_child_" in parts[-1]:
        out.append("%s:%s" % ("/".join(parts[:-1] + [parts[-1].split("_child_")[0]]), name))
    return out


def holder(appliance_id, coll, name, *, user_id=None, token=None, session=None,
           now=None):
    """The info of a live lease someone OTHER than (``user_id``, ``token``)
    holds on ``name`` in ``coll`` -- or on the object it belongs to -- else
    None. ``user_id`` None (an unattended run) is kept out by every lease."""
    from ..extensions import db
    from ..models_cache import ResourceLock
    keys = keys_for(coll, name)
    if appliance_id is None or not keys:
        return None
    session = session or db.session
    now = now or _now()
    for lock in (session.query(ResourceLock)
                 .filter(ResourceLock.appliance_id == appliance_id,
                         ResourceLock.resource_key.in_(keys)).all()):
        if lock.expires_at >= now and not _owns(lock, user_id, token):
            return _held_by_other(lock, user_id, token)
    return None


def refusal(info, name) -> str:
    """The sentence a refused write carries."""
    if info.get("same_user"):
        who = "you, in another tab or window"
    else:
        who = info.get("owner_label") or "another user"
    return ('"%s" is being edited by %s. Take over the edit lock first; '
            'nothing was sent to the device.' % (name, who))


@contextlib.contextmanager
def acting_as(user_id, token=None):
    """Writes inside the block are made as (``user_id``, ``token``)."""
    reset = _ACTOR.set((user_id, token))
    try:
        yield
    finally:
        _ACTOR.reset(reset)


def current_actor() -> tuple:
    """``(user_id, token)`` of whoever is writing now: :func:`acting_as`, else
    the signed-in user of the request (a REST API v1 call: its token's owner),
    else the owner of the background job this thread runs, else
    ``(None, None)`` -- an unattended run."""
    v = _ACTOR.get()
    if v is not None:
        return v
    try:
        from flask import g, has_request_context
        if has_request_context():
            from flask_login import current_user
            if current_user and current_user.is_authenticated:
                return getattr(current_user, "id", None), None
            # a REST API v1 call: the token's owner (app/api_v1/auth.py binds
            # it to g; the API has no login session, so current_user is
            # anonymous and the owner's own lease used to refuse the call)
            owner = getattr(g, "api_token_owner", None)
            if owner is not None:
                return getattr(owner, "id", None), None
    except Exception:  # noqa: BLE001 — outside an app: nobody
        pass
    try:
        from . import jobs
        job_id = getattr(jobs._RUN, "job_id", None)
        by = (jobs.get_job(job_id) or {}).get("by") if job_id else None
        if by:
            from ..models import User
            u = User.query.filter_by(username=by).first()
            if u is not None:
                return u.id, None
    except Exception:  # noqa: BLE001 — no job owner: nobody
        pass
    return None, None


def write_refusal(appliance_id, coll, name) -> str:
    """"" when the current actor may write ``name`` in ``coll``, else why not.
    Never raises: a lease table that cannot be read never stops a write (the
    editors' own check still runs)."""
    if appliance_id is None or not name:
        return ""
    try:
        uid, token = current_actor()
        info = holder(appliance_id, coll, name, user_id=uid, token=token)
    except Exception:  # noqa: BLE001
        return ""
    return refusal(info, name) if info else ""
