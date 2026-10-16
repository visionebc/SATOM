# app/services/hsts_preload.py
"""The HSTS preload list, kept on the node for the HTTP Observatory.

The MDN HTTP Observatory awards ``hsts-preloaded`` (+5) to a site whose name is
on Chromium's HSTS preload list, and ``redirection-all-redirects-preloaded``
when every host of the HTTP redirect chain is. Until 2026-10-16 SATOM did not
carry the list, so a preloaded site scored 5 below mozilla.org (github.com: 110
here, 115 there). This module is the list:

* **Source** — the file MDN's own ``src/retrieve-hsts.js`` downloads,
  Chromium's ``net/http/transport_security_state_static.json``
  (:data:`SOURCE_URL`, fixed: there is no configurable URL to point the node
  at). Comment lines are stripped the way that script strips them.
* **Kept** — only the ``mode: force-https`` entries (the only ones
  ``isHstsPreloaded`` accepts), as ``{name: include_subdomains}``, gzipped in
  ``data/hsts-preload/`` (``SATOM_HSTS_PRELOAD_DIR`` overrides; tests use it).
  ``data/`` is what the standby copies, so a2 grades with a1's list.
* **Lookup** — :func:`lookup` is ``isHstsPreloaded`` from
  ``src/analyzer/hsts.js``: the exact name, else a parent name whose entry has
  ``include_subdomains``.
* **Refresh** — the ``hsts_preload_refresh`` scheduled action (weekly), the
  Refresh button on the HTTP Observatory page, or :func:`import_bytes` with a
  copy of the Chromium file for a node without internet access.

No list on the node is not an error: every lookup answers "not preloaded" and
the page says the list is missing, which is exactly what the grades were
before.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import threading
import time
from pathlib import Path

#: What MDN's retrieve-hsts.js downloads (read from its source, 2026-10-16).
SOURCE_URL = ("https://raw.githubusercontent.com/chromium/chromium/main/"
              "net/http/transport_security_state_static.json")
#: The Chromium file is ~15 MB; anything far past that is not it.
MAX_BYTES = 64 * 1024 * 1024
TIMEOUT = 60.0
#: A list older than this is reported as stale on the page.
STALE_AFTER_DAYS = 21
FILE_NAME = "preload.json.gz"

_LOCK = threading.Lock()
#: ``(mtime, entries, meta)`` of the file last read by this process.
_CACHE: dict = {"mtime": None, "entries": None, "meta": None}


class PreloadError(ValueError):
    """The download or the file is not a usable preload list."""


def _dir() -> Path:
    override = os.environ.get("SATOM_HSTS_PRELOAD_DIR")
    d = (Path(override) if override
         else Path(__file__).resolve().parents[2] / "data" / "hsts-preload")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path() -> Path:
    return _dir() / FILE_NAME


# --------------------------------------------------------------------------- #
#  Parsing                                                                     #
# --------------------------------------------------------------------------- #
def parse(raw: bytes | str) -> dict[str, bool]:
    """``{name: include_subdomains}`` of the ``force-https`` entries of a
    Chromium ``transport_security_state_static.json``.

    Comments go the way retrieve-hsts.js removes them (``//`` to end of line);
    names are trimmed and lower-cased; a later entry of the same name wins, as
    in the object that script builds. Raises :class:`PreloadError` for
    anything that is not that file."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    text = re.sub(r"//.*$", "", text, flags=re.M)
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise PreloadError("not the Chromium preload list: %s" % str(exc)[:120]) from None
    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise PreloadError("not the Chromium preload list: no 'entries'")
    out: dict[str, bool] = {}
    for e in entries:
        if not isinstance(e, dict):
            continue
        name = str(e.get("name") or "").strip().lower()
        if not name:
            continue
        if e.get("mode") == "force-https":
            out[name] = bool(e.get("include_subdomains"))
        else:
            # A later non-forcing entry replaces an earlier forcing one there.
            out.pop(name, None)
    if not out:
        raise PreloadError("the list has no force-https entries")
    return out


def _write(entries: dict[str, bool], meta: dict) -> dict:
    meta = dict(meta, count=len(entries), saved_at=time.time())
    body = json.dumps({"meta": meta, "entries": entries}, separators=(",", ":"))
    path = _path()
    tmp = path.with_suffix(".tmp")
    with gzip.open(tmp, "wt", encoding="utf-8") as fh:
        fh.write(body)
    os.replace(tmp, path)
    with _LOCK:
        _CACHE.update(mtime=None, entries=None, meta=None)
    return meta


def _load() -> tuple[dict[str, bool] | None, dict | None]:
    path = _path()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None, None
    with _LOCK:
        if _CACHE["mtime"] == mtime:
            return _CACHE["entries"], _CACHE["meta"]
    try:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            data = json.load(fh)
        entries = {str(k): bool(v) for k, v in (data.get("entries") or {}).items()}
        meta = dict(data.get("meta") or {})
    except (OSError, ValueError, AttributeError):
        return None, {"error": "the stored list is unreadable"}
    with _LOCK:
        _CACHE.update(mtime=mtime, entries=entries, meta=meta)
    return entries, meta


# --------------------------------------------------------------------------- #
#  Lookup — isHstsPreloaded()                                                  #
# --------------------------------------------------------------------------- #
def lookup(host: str) -> dict | None:
    """``{"name", "include_subdomains"}`` of the entry that preloads *host*,
    or None. The exact name counts whatever its include_subdomains; a parent
    only when its entry includes subdomains (hsts.js)."""
    entries, _meta = _load()
    if not entries:
        return None
    h = str(host or "").strip().lower().rstrip(".")
    if not h:
        return None
    if h in entries:
        return {"name": h, "include_subdomains": entries[h]}
    parts = h.split(".")
    for i in range(1, len(parts)):
        d = ".".join(parts[i:])
        if entries.get(d):
            return {"name": d, "include_subdomains": True}
    return None


def lookup_many(hosts) -> dict[str, dict | None]:
    """``{host: lookup(host)}`` — what a scan stores next to its retrieval so
    the engine (pure) and every later re-grade read the same answer."""
    out: dict[str, dict | None] = {}
    for h in hosts:
        k = str(h or "").strip().lower().rstrip(".")
        if k and k not in out:
            out[k] = lookup(k)
    return out


def status() -> dict:
    """What the page shows: whether a list is loaded, how big, how old."""
    entries, meta = _load()
    meta = meta or {}
    if not entries:
        return {"available": False, "count": 0, "source": SOURCE_URL,
                "error": meta.get("error") or "", "stale": True,
                "fetched_at": None, "origin": ""}
    fetched = meta.get("fetched_at") or meta.get("saved_at")
    age_days = (time.time() - fetched) / 86400 if fetched else None
    return {"available": True, "count": len(entries), "source": meta.get("source") or SOURCE_URL,
            "origin": meta.get("origin") or "", "fetched_at": fetched,
            "etag": meta.get("etag") or "",
            "stale": age_days is None or age_days > STALE_AFTER_DAYS, "error": ""}


# --------------------------------------------------------------------------- #
#  Refresh                                                                     #
# --------------------------------------------------------------------------- #
def import_bytes(raw: bytes, *, origin: str = "upload") -> dict:
    """Store a copy of the Chromium file (a node without internet access)."""
    if len(raw) > MAX_BYTES:
        raise PreloadError("the file is larger than %d MB" % (MAX_BYTES // (1024 * 1024)))
    entries = parse(raw)
    return _write(entries, {"source": SOURCE_URL, "origin": origin,
                            "fetched_at": time.time(), "bytes": len(raw)})


def refresh(*, timeout: float = TIMEOUT) -> dict:
    """Download :data:`SOURCE_URL` and replace the stored list. A failed
    download or a file that does not parse leaves the current list as it was
    (raises :class:`PreloadError`)."""
    import httpx

    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=True) as client:
            with client.stream("GET", SOURCE_URL,
                               headers={"User-Agent": "SATOM hsts-preload"}) as resp:
                if resp.status_code != 200:
                    raise PreloadError("download answered HTTP %s" % resp.status_code)
                chunks, size = [], 0
                for chunk in resp.iter_bytes():
                    size += len(chunk)
                    if size > MAX_BYTES:
                        raise PreloadError("download larger than %d MB" % (MAX_BYTES // (1024 * 1024)))
                    chunks.append(chunk)
                etag = resp.headers.get("etag") or ""
    except httpx.HTTPError as exc:
        raise PreloadError("download failed: %s" % str(exc)[:200]) from None
    raw = b"".join(chunks)
    entries = parse(raw)
    return _write(entries, {"source": SOURCE_URL, "origin": "download",
                            "fetched_at": time.time(), "etag": etag, "bytes": len(raw)})


def scheduled_refresh(dry_run: bool = False) -> dict:
    """The ``hsts_preload_refresh`` scheduled action's body."""
    if dry_run:
        st = status()
        return {"ok": True, "summary": "[dry-run] would download the HSTS preload list "
                "(now: %s)." % ("%d names" % st["count"] if st["available"] else "none"),
                "log": SOURCE_URL}
    before = status()
    try:
        meta = refresh()
    except PreloadError as exc:
        return {"ok": False, "summary": "HSTS preload list not refreshed: %s%s" % (
            exc, "; the stored list (%d names) stays" % before["count"] if before["available"] else ""),
            "log": SOURCE_URL}
    return {"ok": True, "summary": "HSTS preload list: %d force-https names (was %s)."
            % (meta["count"], before["count"] if before["available"] else "none"),
            "log": SOURCE_URL}


__all__ = ["SOURCE_URL", "PreloadError", "parse", "lookup", "lookup_many", "status",
           "import_bytes", "refresh", "scheduled_refresh"]
