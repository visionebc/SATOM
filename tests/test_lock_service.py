"""Phase 4 — lease-lock service tests (deterministic via injected ``now``)."""
from datetime import datetime, timedelta

from app.services import lock_service as L


def test_acquire_fresh(session):
    ok, info = L.acquire(1, "server_policy:pol-x", user_id=10,
                         owner_label="alice", session=session)
    assert ok is True
    assert info["owner_user_id"] == 10


def test_second_user_blocked(session):
    L.acquire(1, "server_policy:pol-x", user_id=10, owner_label="alice",
              session=session)
    ok, info = L.acquire(1, "server_policy:pol-x", user_id=20,
                         owner_label="bob", session=session)
    assert ok is False
    assert info["owner_label"] == "alice"   # the holder is reported


def test_same_user_reentrant(session):
    L.acquire(1, "k", user_id=10, owner_label="alice", session=session)
    ok, info = L.acquire(1, "k", user_id=10, owner_label="alice",
                        session=session)
    assert ok is True


def test_expired_lease_is_takeable(session):
    t0 = datetime(2026, 1, 1, 12, 0, 0)
    L.acquire(1, "k", user_id=10, owner_label="alice", ttl=120,
              session=session, now=t0)
    # 3 minutes later the lease has expired → a new user can acquire
    later = t0 + timedelta(seconds=200)
    ok, info = L.acquire(1, "k", user_id=20, owner_label="bob",
                        session=session, now=later)
    assert ok is True
    assert info["owner_user_id"] == 20


def test_heartbeat_only_owner(session):
    L.acquire(1, "k", user_id=10, owner_label="alice", session=session)
    ok_owner, _ = L.heartbeat(1, "k", user_id=10, session=session)
    assert ok_owner is True
    ok_other, _ = L.heartbeat(1, "k", user_id=20, session=session)
    assert ok_other is False


def test_release_then_reacquire(session):
    L.acquire(1, "k", user_id=10, owner_label="alice", session=session)
    assert L.release(1, "k", user_id=10, session=session) is True
    ok, info = L.acquire(1, "k", user_id=20, owner_label="bob",
                        session=session)
    assert ok is True
    assert info["owner_user_id"] == 20


def test_release_not_owner_refused(session):
    L.acquire(1, "k", user_id=10, owner_label="alice", session=session)
    assert L.release(1, "k", user_id=20, session=session) is False


def test_steal_forces_takeover(session):
    L.acquire(1, "k", user_id=10, owner_label="alice", session=session)
    ok, info = L.steal(1, "k", user_id=20, owner_label="bob", session=session)
    assert ok is True
    assert info["owner_user_id"] == 20
    # the new holder blocks the old one
    ok2, _ = L.acquire(1, "k", user_id=10, owner_label="alice", session=session)
    assert ok2 is False


def test_status_free_then_held(session):
    assert L.status(1, "k", session=session) is None
    L.acquire(1, "k", user_id=10, owner_label="alice", session=session)
    info = L.status(1, "k", session=session)
    assert info is not None and info["owner_user_id"] == 10
