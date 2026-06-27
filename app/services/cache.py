"""Simple in-process TTL cache for appliance API responses."""
from __future__ import annotations

import time
from typing import Any

# (appliance_id, key) -> (value, expire_at)
_cache: dict[tuple[int | str, str], tuple[Any, float]] = {}

TTL: int = 30  # seconds


def cache_get(appliance_id: int | str, key: str) -> Any | None:
    """Return cached value or None if missing / expired."""
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
    _cache[(appliance_id, key)] = (value, time.monotonic() + ttl)


def cache_invalidate(appliance_id: int | str) -> None:
    """Remove all cache entries for the given *appliance_id*."""
    stale = [k for k in _cache if k[0] == appliance_id]
    for k in stale:
        del _cache[k]
