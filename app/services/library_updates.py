"""Library update check — best-effort PyPI lookup for the Settings → Libraries card.

``system_info.collect()`` lists the libraries the app is *built on*, read from the
venv at request time. This service answers a different question: is any of them
behind the latest release on PyPI?

It is deliberately kept OUT of the Settings page render path — ``system_info``
must never touch the network, so a slow/unreachable PyPI can never make the
Settings page hang or 500. This runs only when the "Check for updates" button
(or its cached result) asks for it, via the ``settings.library_updates`` endpoint.

Everything is guarded and time-boxed: an unreachable PyPI yields ``latest=None``
for that package, never an exception or a hung request. Lookups run concurrently
so the whole set resolves well within the gunicorn worker timeout, and results
are cached in-process (``_CACHE_TTL``) so repeated Settings visits don't re-hit
PyPI.

``latest=None`` means NOT CHECKED, never "up to date". A package PyPI did not
answer for is listed in ``unchecked``; when none answered (an air-gapped node,
a proxy, no DNS) the result carries ``unreachable=True`` and is not cached as a
good check. Before this, an offline node reported "All tracked libraries up to
date" after checking nothing.
"""
from __future__ import annotations

import concurrent.futures as _cf
import importlib.metadata as _meta
import threading
import time
from typing import Any

import httpx

try:
    from packaging.version import InvalidVersion, Version
except Exception:  # pragma: no cover - packaging ships with pip, effectively always present
    Version = None  # type: ignore
    InvalidVersion = Exception  # type: ignore

from .system_info import _LIBRARIES

#: Where the check looks, shown on the card so an operator knows what to open.
SOURCE = "pypi.org"
_PYPI = "https://pypi.org/pypi/{name}/json"
_HTTP_TIMEOUT = 3.0          # per-request hard cap (seconds)
_MAX_WORKERS = 8             # concurrent PyPI lookups
_CACHE_TTL = 6 * 3600        # 6 hours
#: After a check where PyPI answered nothing, page loads reuse that verdict for
#: this long instead of waiting on the timeouts again. The button still retries.
_UNREACHABLE_TTL = 600

_lock = threading.Lock()
_cache: dict[str, Any] = {"checked_at": 0.0, "packages": [], "source": SOURCE,
                          "unchecked": []}
_failed: dict[str, Any] = {"at": 0.0, "unchecked": []}


def _severity(installed: str, latest: str) -> str:
    """Rough upgrade risk from the version gap: major bump = high, minor = medium."""
    if not latest or installed == latest:
        return "none"
    if Version is None:
        return "update"
    try:
        cur, new = Version(installed), Version(latest)
    except InvalidVersion:
        return "update"
    if new <= cur:
        return "none"
    if new.major > cur.major:
        return "major"
    if new.minor > cur.minor:
        return "minor"
    return "patch"


def _latest_on_pypi(client: httpx.Client, name: str) -> str | None:
    try:
        r = client.get(_PYPI.format(name=name))
        if r.status_code != 200:
            return None
        return (r.json().get("info") or {}).get("version") or None
    except Exception:
        return None


def _collect() -> dict[str, Any]:
    installed: list[tuple[str, str]] = []
    for name in _LIBRARIES:
        try:
            installed.append((name, _meta.version(name)))
        except _meta.PackageNotFoundError:
            continue
        except Exception:
            continue

    packages: list[dict[str, Any]] = []
    headers = {"Accept": "application/json", "User-Agent": "SATOM-update-check"}
    try:
        with httpx.Client(headers=headers, follow_redirects=True,
                          timeout=_HTTP_TIMEOUT) as client:
            def _one(item: tuple[str, str]) -> dict[str, Any]:
                name, cur = item
                latest = _latest_on_pypi(client, name)
                return {
                    "name": name,
                    "installed": cur,
                    "latest": latest,
                    "severity": _severity(cur, latest or ""),
                }
            with _cf.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
                packages = list(ex.map(_one, installed))
    except Exception:
        pass

    # Preserve the curated display order regardless of completion order.
    order = {n: i for i, n in enumerate(_LIBRARIES)}
    packages.sort(key=lambda p: order.get(p["name"], 999))
    answered = {p["name"] for p in packages if p["latest"]}
    unchecked = [n for n, _ in installed if n not in answered]
    return {"checked_at": time.time(), "packages": packages, "source": SOURCE,
            "unchecked": unchecked, "installed_count": len(installed)}


def _unreachable(now: float, unchecked: list[str]) -> dict[str, Any]:
    """The last good result (if any) marked as NOT refreshed: PyPI answered
    for no package. ``checked_at`` stays the time of that good result."""
    out = dict(_cache)
    out.update(unreachable=True, attempted_at=now, source=SOURCE,
               unchecked=list(unchecked))
    return out


def check(force: bool = False) -> dict[str, Any]:
    """Return cached update info, refreshing from PyPI when stale (or forced).

    Best-effort and thread-safe. Never raises: when PyPI answers for no package
    the result says ``unreachable`` instead of passing an unchecked list off as
    up to date.
    """
    now = time.time()
    with _lock:
        fresh = (now - _cache["checked_at"]) < _CACHE_TTL and _cache["packages"]
        if fresh and not force:
            return dict(_cache)
        if not force and (now - _failed["at"]) < _UNREACHABLE_TTL:
            return _unreachable(_failed["at"], _failed["unchecked"])

    # Network work happens OUTSIDE the lock so concurrent callers don't serialize.
    data = _collect()
    with _lock:
        if data["installed_count"] and len(data["unchecked"]) >= data["installed_count"]:
            # Nothing answered. Keep the previous good result, never overwrite it.
            _failed.update(at=data["checked_at"], unchecked=data["unchecked"])
            return _unreachable(data["checked_at"], data["unchecked"])
        _failed.update(at=0.0, unchecked=[])
        if data["packages"]:
            _cache.update(data)
        return dict(_cache)
