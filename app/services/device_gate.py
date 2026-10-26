"""At most N SATOM sessions at a time against one appliance, across workers.

SATOM fans out: one API call that reads or writes a device opens a session to
it, so a hundred parallel callers became a hundred parallel sessions to one
FortiADC or FortiWeb -- and the box gives up long before SATOM does. The gate
caps that per appliance; a caller over the cap is told to come back
(:class:`Busy` -> HTTP 429 with ``Retry-After``) instead of queueing a worker.

Shared across gunicorn workers through the same Redis the rate limiter and
``services.cache`` use: a sorted set per appliance whose members are the
holders and whose scores are when they entered. A worker that dies while
holding a slot cannot leak it forever -- entries older than ``HOLD_MAX_S``
are dropped on the next acquire. Without Redis the cap is per process (a
bounded semaphore), which still protects the box from one worker's threads.

``coalesce`` collapses identical live reads: the first caller reads the
device, callers within ``COALESCE_S`` get the same answer without a session.
"""
from __future__ import annotations

import threading
import time
import uuid
from contextlib import contextmanager

from . import cache

#: Concurrent SATOM sessions allowed per appliance (``api.device_concurrency``).
DEFAULT_LIMIT = 2
#: A slot held longer than this is presumed dead (worker killed mid-call).
HOLD_MAX_S = 180
#: Seconds a live read is shared with identical callers.
COALESCE_S = 5
SETTING_KEY = "api.device_concurrency"

_PREFIX = "satom:devgate:"
_local: dict[int, threading.BoundedSemaphore] = {}
_local_lock = threading.Lock()


class Busy(Exception):
    """The appliance already has ``limit`` SATOM sessions open."""

    def __init__(self, appliance_id: int, limit: int, retry_after: int = 2):
        super().__init__(f"appliance {appliance_id} already has {limit} "
                         "concurrent SATOM sessions; retry shortly")
        self.appliance_id, self.limit, self.retry_after = appliance_id, limit, retry_after


def limit() -> int:
    """The configured cap (1..20), default :data:`DEFAULT_LIMIT`."""
    try:
        from ..models import AppSetting
        v = int(str(AppSetting.get(SETTING_KEY) or DEFAULT_LIMIT).strip())
    except Exception:  # noqa: BLE001 — a bad setting never opens the gate wider
        v = DEFAULT_LIMIT
    return max(1, min(20, v))


def _sem(appliance_id: int, cap: int) -> threading.BoundedSemaphore:
    with _local_lock:
        s = _local.get(appliance_id)
        if s is None or getattr(s, "_satom_cap", None) != cap:
            s = threading.BoundedSemaphore(cap)
            s._satom_cap = cap  # type: ignore[attr-defined]
            _local[appliance_id] = s
        return s


@contextmanager
def slot(appliance_id: int, *, cap: int | None = None):
    """Hold one of the appliance's session slots for the ``with`` body, or
    raise :class:`Busy` at once (never waits: a waiting worker is the outage)."""
    cap = int(cap or limit())
    r = cache._redis_client()
    if r is not None:
        key = f"{_PREFIX}{appliance_id}"
        me = uuid.uuid4().hex
        now = time.time()
        try:
            pipe = r.pipeline()
            pipe.zremrangebyscore(key, "-inf", now - HOLD_MAX_S)
            pipe.zadd(key, {me: now})
            pipe.zcard(key)
            pipe.expire(key, HOLD_MAX_S)
            _, _, held, _ = pipe.execute()
        except Exception:  # noqa: BLE001 — Redis down: fall back to the process cap
            r = None
        else:
            if held > cap:
                try:
                    r.zrem(key, me)
                except Exception:  # noqa: BLE001
                    pass
                raise Busy(appliance_id, cap)
            try:
                yield
            finally:
                try:
                    r.zrem(key, me)
                except Exception:  # noqa: BLE001 — expires after HOLD_MAX_S
                    pass
            return
    sem = _sem(appliance_id, cap)
    if not sem.acquire(blocking=False):
        raise Busy(appliance_id, cap)
    try:
        yield
    finally:
        sem.release()


def coalesce(appliance_id: int, key: str, fetch, *, ttl: int = COALESCE_S):
    """``(value, shared)``: a recent identical read if there is one, else
    ``fetch()`` under :func:`slot` (its result is shared for *ttl* seconds).
    Only a successful read is shared -- *fetch* raising shares nothing."""
    ck = f"live:{key}"
    hit = cache.cache_get(appliance_id, ck)
    if hit is not None:
        return hit, True
    with slot(appliance_id):
        value = fetch()
    cache.cache_set(appliance_id, ck, value, ttl=ttl)
    return value, False
