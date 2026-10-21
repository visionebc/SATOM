"""Library update check — best-effort index lookup for the Settings → Libraries card.

``system_info.collect()`` lists the libraries the app is *built on*, read from the
venv at request time. This service answers a different question: is any of them
behind the latest release on the package index?

It is deliberately kept OUT of the Settings page render path — ``system_info``
must never touch the network, so a slow/unreachable index can never make the
Settings page hang or 500. This runs only when the "Check for updates" button
(or its cached result) asks for it, via the ``settings.library_updates`` endpoint.

Everything is guarded and time-boxed: an unreachable index yields ``latest=None``
for that package, never an exception or a hung request. Lookups run concurrently
so the whole set resolves well within the gunicorn worker timeout, and results
are cached in-process (``_CACHE_TTL``) so repeated Settings visits don't re-hit
the index.

``latest=None`` means NOT CHECKED, never "up to date". A package the index did
not answer for is listed in ``unchecked``; when none answered (an air-gapped node,
a proxy, no DNS) the result carries ``unreachable=True`` and is not cached as a
good check. Before this, an offline node reported "All tracked libraries up to
date" after checking nothing.

The index is pypi.org unless Settings → General → Update sources names another
one (an internal mirror or pipeline, optionally with a user and token). pypi.org
is read through its JSON API as before; a custom index through the Simple
Repository API every pip-compatible index serves (PEP 503 HTML, PEP 691 JSON).
The result is keyed by its source, so changing the index never shows the
previous index's answer.
"""
from __future__ import annotations

import base64
import concurrent.futures as _cf
import importlib.metadata as _meta
import re
import threading
import time
from html.parser import HTMLParser
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx

try:
    from packaging.utils import parse_sdist_filename, parse_wheel_filename
    from packaging.version import InvalidVersion, Version
except Exception:  # pragma: no cover - packaging ships with pip, effectively always present
    Version = None  # type: ignore
    InvalidVersion = Exception  # type: ignore
    parse_sdist_filename = parse_wheel_filename = None  # type: ignore

from .system_info import _LIBRARIES

#: The default source, shown on the card so an operator knows what was asked.
SOURCE = "pypi.org"
_PYPI = "https://pypi.org/pypi/{name}/json"
_SIMPLE_ACCEPT = ("application/vnd.pypi.simple.v1+json, "
                  "application/vnd.pypi.simple.v1+html;q=0.2, text/html;q=0.1")
_HTTP_TIMEOUT = 3.0          # per-request hard cap (seconds)
_MAX_WORKERS = 8             # concurrent index lookups
_CACHE_TTL = 6 * 3600        # 6 hours
#: After a check where the index answered nothing, page loads reuse that verdict
#: for this long instead of waiting on the timeouts again. The button still retries.
_UNREACHABLE_TTL = 600

_lock = threading.Lock()
_cache: dict[str, Any] = {"checked_at": 0.0, "packages": [], "source": SOURCE,
                          "unchecked": []}
_failed: dict[str, Any] = {"at": 0.0, "unchecked": [], "source": ""}


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


# ---- a custom index (Simple Repository API) ---------------------------------
def _normalize(name: str) -> str:
    """PEP 503 project name normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()


class _Anchors(HTMLParser):
    """(file name, yanked) of every link on a PEP 503 project page."""

    def __init__(self):
        super().__init__()
        self.files: list[tuple[str, bool]] = []
        self._href: str | None = None
        self._yanked = False
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            a = dict(attrs)
            self._href = a.get("href") or ""
            self._yanked = "data-yanked" in a
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            text = "".join(self._text).strip()
            if not text:
                text = unquote(urlsplit(self._href).path.rsplit("/", 1)[-1])
            self.files.append((text, self._yanked))
            self._href = None


def _version_of(filename: str):
    """The release version a distribution file belongs to, or None."""
    if parse_wheel_filename is None:
        return None
    try:
        if filename.endswith(".whl"):
            return parse_wheel_filename(filename)[1]
        return parse_sdist_filename(filename)[1]
    except Exception:  # noqa: BLE001 -- eggs, exe installers, junk: not ours
        return None


def latest_from_simple(content_type: str, body: bytes) -> str | None:
    """Newest final release on a Simple API project page (JSON or HTML).

    Yanked files and pre/dev releases are skipped, as pip skips them. With no
    file list (a PEP 700 ``versions`` list only) the newest final version wins.
    """
    if Version is None:
        return None
    found = []
    ctype = (content_type or "").split(";")[0].strip().lower()
    if ctype.endswith("json"):
        import json
        doc = json.loads(body.decode("utf-8"))
        files = doc.get("files")
        if isinstance(files, list) and files:
            for f in files:
                if not isinstance(f, dict) or f.get("yanked"):
                    continue
                v = _version_of(str(f.get("filename") or ""))
                if v is not None:
                    found.append(v)
        else:
            for raw in doc.get("versions") or []:
                try:
                    found.append(Version(str(raw)))
                except InvalidVersion:
                    continue
    else:
        p = _Anchors()
        p.feed(body.decode("utf-8", "replace"))
        for name, yanked in p.files:
            if yanked:
                continue
            v = _version_of(name)
            if v is not None:
                found.append(v)
    finals = [v for v in found if not (v.is_prerelease or v.is_devrelease)]
    return str(max(finals)) if finals else None


def _auth_header(url: str, auth) -> dict:
    """HTTP Basic for ``url`` only when it is on the source's own host. httpx
    drops the header on a redirect to another origin."""
    if not auth:
        return {}
    host, user, token = auth
    if not (host and user and token):
        return {}
    if (urlsplit(url).hostname or "").lower() != host:
        return {}
    cred = base64.b64encode(("%s:%s" % (user, token)).encode()).decode()
    return {"Authorization": "Basic " + cred}


def _simple_get(client: httpx.Client, base: str, name: str, auth) -> httpx.Response:
    url = base.rstrip("/") + "/" + _normalize(name) + "/"
    headers = {"Accept": _SIMPLE_ACCEPT}
    headers.update(_auth_header(url, auth))
    return client.get(url, headers=headers)


def _latest_on_index(client: httpx.Client, base: str, name: str, auth) -> str | None:
    try:
        r = _simple_get(client, base, name, auth)
        if r.status_code != 200:
            return None
        return latest_from_simple(r.headers.get("content-type", ""), r.content)
    except Exception:
        return None


def _verify():
    """The trust store: an internal index signed by the company CA verifies."""
    from . import trust_store
    return trust_store.verify_param()


def probe_index(url: str, auth, name: str = "Flask") -> dict:
    """One lookup with the reason when it fails -- the "Test" button of
    Update sources. The card's own check stays best-effort and quiet."""
    try:
        with httpx.Client(follow_redirects=True, timeout=_HTTP_TIMEOUT * 2,
                          headers={"User-Agent": "SATOM-update-check"},
                          verify=_verify()) as client:
            r = _simple_get(client, url, name, auth)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": "cannot reach %s: %s" % (url, exc)}
    if r.status_code in (401, 403):
        return {"ok": False, "error": "HTTP %s: the index wants credentials, or refused "
                                      "the ones given" % r.status_code}
    if r.status_code != 200:
        return {"ok": False, "error": "HTTP %s for %s" % (r.status_code, r.url)}
    try:
        latest = latest_from_simple(r.headers.get("content-type", ""), r.content)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": "the answer is not a package index page: %s" % exc}
    if not latest:
        return {"ok": False, "error": "the index answered but lists no release of %s"
                                      % name}
    return {"ok": True, "latest": latest}


# ---- the check --------------------------------------------------------------
def _index_target() -> dict:
    """The configured index (Settings → General → Update sources)."""
    from .update_sources import INDEX, target
    return target(INDEX)


def _collect(tgt: dict) -> dict[str, Any]:
    installed: list[tuple[str, str]] = []
    for name in _LIBRARIES:
        try:
            installed.append((name, _meta.version(name)))
        except _meta.PackageNotFoundError:
            continue
        except Exception:
            continue

    custom = bool(tgt.get("custom"))
    source = tgt.get("source") if custom else SOURCE
    packages: list[dict[str, Any]] = []
    headers = {"Accept": "application/json", "User-Agent": "SATOM-update-check"}
    try:
        with httpx.Client(headers=headers, follow_redirects=True,
                          timeout=_HTTP_TIMEOUT, verify=_verify()) as client:
            def _one(item: tuple[str, str]) -> dict[str, Any]:
                name, cur = item
                if custom:
                    latest = _latest_on_index(client, tgt["url"], name, tgt.get("auth"))
                else:
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
    return {"checked_at": time.time(), "packages": packages, "source": source,
            "custom": custom, "unchecked": unchecked,
            "installed_count": len(installed)}


def _unreachable(now: float, unchecked: list[str], source: str) -> dict[str, Any]:
    """The last good result FROM THIS SOURCE (if any) marked as NOT refreshed:
    the index answered for no package. ``checked_at`` stays the time of that
    good result."""
    out = dict(_cache) if _cache.get("source") == source else {
        "checked_at": 0.0, "packages": []}
    out.update(unreachable=True, attempted_at=now, source=source,
               unchecked=list(unchecked))
    return out


def check(force: bool = False) -> dict[str, Any]:
    """Return cached update info, refreshing from the index when stale (or forced).

    Best-effort and thread-safe. Never raises for the network: when the index
    answers for no package the result says ``unreachable`` instead of passing
    an unchecked list off as up to date. A configured index that cannot be used
    as configured (an unreadable token) is reported as ``error``, never quietly
    replaced by pypi.org.
    """
    tgt = _index_target()
    source = tgt.get("source") if tgt.get("custom") else SOURCE
    if tgt.get("problem"):
        return {"checked_at": 0.0, "packages": [], "source": source,
                "unchecked": [], "error": tgt["problem"]}
    now = time.time()
    with _lock:
        same = _cache.get("source") == source
        fresh = same and (now - _cache["checked_at"]) < _CACHE_TTL and _cache["packages"]
        if fresh and not force:
            return dict(_cache)
        if (not force and _failed.get("source") == source
                and (now - _failed["at"]) < _UNREACHABLE_TTL):
            return _unreachable(_failed["at"], _failed["unchecked"], source)

    # Network work happens OUTSIDE the lock so concurrent callers don't serialize.
    data = _collect(tgt)
    with _lock:
        if data["installed_count"] and len(data["unchecked"]) >= data["installed_count"]:
            # Nothing answered. Keep the previous good result, never overwrite it.
            _failed.update(at=data["checked_at"], unchecked=data["unchecked"],
                           source=source)
            return _unreachable(data["checked_at"], data["unchecked"], source)
        _failed.update(at=0.0, unchecked=[], source="")
        if data["packages"]:
            _cache.clear()
            _cache.update(data)
        return dict(_cache)
