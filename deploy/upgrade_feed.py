"""The system-upgrade feed: find and download the newest signed update package.

Every release publishes ``satom-system-upgrades/latest.json`` in the public
repository. It names the newest ``satom-update-<version>.tar.gz``, where the
release hosts it, its size and its sha256. A node that can reach that URL uses
this module to fetch the package instead of an operator downloading it, copying
it over and running ``tar``/``sha256sum`` by hand.

What this module is NOT: a reason to trust anything. The feed is an address
book. The bytes it leads to are checked against the sha256 the feed declares
(so a truncated or swapped download fails here, early, with a clear message),
and then the package goes through the same path as an uploaded one: the
signature is verified against the root-owned trust store by the worker's
preflight and again, as root, by the runner. A forged feed can at most point at
a package that no trusted key signed, and that package is refused.

Rules, same as ``update_package.py`` and for the same reason (the CLI runs this
as root from a copy in ``/usr/local/lib/satom-runner``):

* standard library only;
* HTTPS only, redirects included (GitHub release assets redirect to a CDN);
* nothing is written outside the staging directory the caller names, and the
  file only appears under its final name once size and sha256 both match.

Nothing calls this on its own. A node fetches the feed when an operator asks
(the Software Update button or ``satom execute update fetch``) -- an on-premise
security product does not phone home on a timer.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

FEED_SCHEMA = "satom.upgrade-feed/1"
DEFAULT_FEED_URL = ("https://raw.githubusercontent.com/visionebc/SATOM/main/"
                    "satom-system-upgrades/latest.json")
#: A feed document is a few hundred bytes; anything bigger is not a feed.
MAX_FEED_BYTES = 64 * 1024
#: Same ceiling as an uploaded package (update_package_service.MAX_UPLOAD_BYTES).
MAX_PACKAGE_BYTES = 400 * 1024 * 1024
PKG_RE = re.compile(r"^satom-update-[0-9][A-Za-z0-9._-]{0,60}\.tar\.gz$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_UA = "satom-upgrade-feed/1"


class FeedError(Exception):
    """The feed or the download it points at cannot be used."""


def feed_url() -> str:
    """The feed this node reads. ``SATOM_UPGRADE_FEED`` overrides it -- a fork,
    or an internal mirror for nodes that reach a proxy but not GitHub."""
    return (os.environ.get("SATOM_UPGRADE_FEED") or DEFAULT_FEED_URL).strip()


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise FeedError("refusing a redirect away from HTTPS: %s" % newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url: str, timeout: float):
    if not (url or "").lower().startswith("https://"):
        raise FeedError("only https:// URLs are fetched (got %r)" % url)
    opener = urllib.request.build_opener(_HttpsOnlyRedirect())
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        return opener.open(req, timeout=timeout)
    except FeedError:
        raise
    except urllib.error.HTTPError as exc:
        raise FeedError("%s answered HTTP %s" % (url, exc.code)) from None
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise FeedError("cannot reach %s (%s). A node with no route to the "
                        "internet takes the package by upload instead."
                        % (url, reason)) from None


def parse_feed(raw: bytes) -> dict:
    """Validate a feed document. Raises FeedError on anything unexpected."""
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise FeedError("the feed is not JSON: %s" % exc) from None
    if not isinstance(doc, dict) or doc.get("schema") != FEED_SCHEMA:
        raise FeedError("not a SATOM upgrade feed (schema %r)"
                        % (doc.get("schema") if isinstance(doc, dict) else None))
    pkg = doc.get("package")
    if not isinstance(pkg, dict):
        raise FeedError("the feed names no package")
    name, url, sha = pkg.get("name") or "", pkg.get("url") or "", pkg.get("sha256") or ""
    if not PKG_RE.match(name):
        raise FeedError("the feed names %r, which is not an update package" % name)
    if not url.lower().startswith("https://") or not url.endswith("/" + name):
        raise FeedError("the package URL must be https:// and end in /%s" % name)
    if not _SHA_RE.match(sha):
        raise FeedError("the feed carries no valid sha256 for %s" % name)
    size = pkg.get("size")
    if not isinstance(size, int) or not 0 < size <= MAX_PACKAGE_BYTES:
        raise FeedError("the feed declares an implausible size for %s: %r" % (name, size))
    ver = str(doc.get("version") or "")
    if name != "satom-update-%s.tar.gz" % ver:
        raise FeedError("the feed version %r does not match its package %s" % (ver, name))
    return doc


def fetch_small(url: str, timeout: float = 10, max_bytes: int = MAX_FEED_BYTES) -> bytes:
    """GET a small document (a feed) over HTTPS with this module's rules:
    https only, redirects included, at most ``max_bytes``. Shared by the
    knowledge-pack feed (``app/services/knowledge_fetch.py``) so both feeds go
    through the same client, proxy environment and TLS verification."""
    with _open(url, timeout) as resp:
        raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise FeedError("the feed at %s is larger than %d KB" % (url, max_bytes // 1024))
    return raw


def fetch_feed(url: str = "", timeout: float = 10) -> dict:
    """Download and validate the feed document."""
    url = url or feed_url()
    doc = parse_feed(fetch_small(url, timeout))
    doc["_feed_url"] = url
    return doc


def download_package(feed: dict, dest_dir, progress=None, timeout: float = 60) -> Path:
    """Download the package the feed names into ``dest_dir``.

    Streams to a hidden ``.part`` file and only renames it once the byte count
    and the sha256 match the feed; a mismatch deletes it. ``progress(done,
    total)`` is called every few MB. Returns the final path.
    """
    pkg = feed["package"]
    return download_file(pkg["url"], pkg["name"], pkg["sha256"], pkg["size"], dest_dir,
                         progress=progress, timeout=timeout)


def download_file(url: str, name: str, want_sha: str, size: int, dest_dir,
                  progress=None, timeout: float = 60) -> Path:
    """Download ``url`` to ``dest_dir/name``, atomically and verified.

    The file only appears under ``name`` once exactly ``size`` bytes arrived
    and their sha256 is ``want_sha``; more bytes than declared stop the
    download at once. Used for update packages and knowledge packs alike."""
    if not _SHA_RE.match(want_sha or ""):
        raise FeedError("no valid sha256 for %s" % name)
    if not isinstance(size, int) or not 0 < size <= MAX_PACKAGE_BYTES:
        raise FeedError("implausible size for %s: %r" % (name, size))
    if not name or "/" in name or name.startswith("."):
        raise FeedError("%r is not a file name" % name)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    final = dest_dir / name
    part = dest_dir / (".%s.part" % name)
    h = hashlib.sha256()
    done = 0
    last = 0
    try:
        with _open(url, timeout) as resp, open(part, "wb") as fh:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                done += len(chunk)
                if done > size:
                    raise FeedError("%s is larger than the %d bytes the feed declares"
                                    % (name, size))
                h.update(chunk)
                fh.write(chunk)
                if progress and done - last >= 4 << 20:
                    last = done
                    progress(done, size)
        if done != size:
            raise FeedError("%s: got %d bytes, the feed declares %d (interrupted?)"
                            % (name, done, size))
        got = h.hexdigest()
        if got != want_sha:
            raise FeedError("%s: sha256 %s does not match the feed (%s)"
                            % (name, got, want_sha))
        os.replace(part, final)
    finally:
        try:
            part.unlink()
        except FileNotFoundError:
            pass
    if progress:
        progress(size, size)
    return final


__all__ = ["FEED_SCHEMA", "DEFAULT_FEED_URL", "FeedError", "feed_url", "parse_feed",
           "fetch_feed", "fetch_small", "download_package", "download_file", "PKG_RE"]
