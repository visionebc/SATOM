"""Short-TTL cache for appliance API responses — Redis-backed when available.

Production runs 4 gunicorn workers; the old in-process dict meant every worker
re-queried each appliance independently (4x duplicate device reads per fleet
page) and a cache entry never survived a reload. When ``CACHE_REDIS_URI`` (or
the rate-limiter's ``RATELIMIT_STORAGE_URI``, if it is a redis:// URL) points
at a Redis, all workers share ONE cache. Values are JSON-serialised — every
caller stores normalised cmdb dicts/lists, never live objects.

Redis being down must never break a page: any Redis error falls back to the
in-process dict for that call, and the client re-probes on later calls.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

TTL: int = 30  # seconds (callers may override per set)

_PREFIX = "fmcache:"

# in-process fallback: (appliance_id, key) -> (value, expire_at)
_cache: dict[tuple[int | str, str], tuple[Any, float]] = {}

_redis = None            # lazily-created client, shared per process
_redis_failed_at = 0.0   # backoff so a dead Redis isn't retried per-call
_REDIS_RETRY_S = 30.0


def _redis_client():
    """Return a Redis client or None (never raises)."""
    global _redis, _redis_failed_at
    if _redis is not None:
        return _redis
    if time.monotonic() - _redis_failed_at < _REDIS_RETRY_S:
        return None
    uri = os.environ.get("CACHE_REDIS_URI") or ""
    if not uri:
        rl = os.environ.get("RATELIMIT_STORAGE_URI") or ""
        if rl.startswith("redis://") or rl.startswith("rediss://"):
            uri = rl
    if not uri.startswith(("redis://", "rediss://")):
        _redis_failed_at = time.monotonic()
        return None
    try:
        import redis  # already a dependency via the rate limiter
        client = redis.Redis.from_url(
            uri, socket_connect_timeout=0.5, socket_timeout=0.5,
            decode_responses=True,
        )
        client.ping()
        _redis = client
        return _redis
    except Exception:  # noqa: BLE001 — cache must never break a request
        _redis_failed_at = time.monotonic()
        return None


def _rkey(appliance_id: int | str, key: str) -> str:
    return f"{_PREFIX}{appliance_id}:{key}"


def cache_get(appliance_id: int | str, key: str) -> Any | None:
    """Return cached value or None if missing / expired."""
    r = _redis_client()
    if r is not None:
        try:
            raw = r.get(_rkey(appliance_id, key))
            return json.loads(raw) if raw is not None else None
        except Exception:  # noqa: BLE001
            pass
    entry = _cache.get((appliance_id, key))
    if entry is None:
        return None
    value, expire_at = entry
    if time.monotonic() > expire_at:
        del _cache[(appliance_id, key)]
        return None
    return value


def cache_set(
    appliance_id: int | str,
    key: str,
    value: Any,
    ttl: int = TTL,
) -> None:
    """Store *value* under *(appliance_id, key)* for *ttl* seconds."""
    r = _redis_client()
    if r is not None:
        try:
            r.setex(_rkey(appliance_id, key), max(1, int(ttl)),
                    json.dumps(value, default=str))
            return
        except Exception:  # noqa: BLE001
            pass
    _cache[(appliance_id, key)] = (value, time.monotonic() + ttl)


def cache_invalidate(appliance_id: int | str) -> None:
    """Remove all cache entries for the given *appliance_id*."""
    r = _redis_client()
    if r is not None:
        try:
            pattern = f"{_PREFIX}{appliance_id}:*"
            keys = list(r.scan_iter(match=pattern, count=200))
            if keys:
                r.delete(*keys)
        except Exception:  # noqa: BLE001
            pass
    stale = [k for k in _cache if k[0] == appliance_id]
    for k in stale:
        del _cache[k]
