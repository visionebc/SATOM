"""Portable themes — the file format, brand assets, and fetching a theme from elsewhere.

Settings -> Appearance can bring a look in from three places, and all three
land here so they cannot drift apart:

* **A theme file** (Export / Import). Schema ``satom.ui-theme/2`` carries the
  token overrides AND the logo and favicon, base64-encoded. ``/1`` files
  (tokens only, everything exported before v2) still import.
* **Another SATOM node.** ``GET <node>/api/v1/ui/theme`` returns the same v2
  document, so a node-to-node copy is an export + import without the file.
* **A website** — see :mod:`app.services.theme_from_site`, which builds a v2
  document from a page's colours and icons.

Two rules hold this together:

* **Everything that arrives is untrusted.** Tokens go through
  :func:`theme_service.validate_tokens` (a whole file is refused if one token
  fails), rasters are re-encoded through Pillow, SVG is sanitised, and the
  asset route serves SVG under a ``sandbox`` CSP as the backstop.
* **The node fetches only what an admin typed, and never from itself.**
  :func:`fetch` refuses loopback, link-local (which includes the cloud metadata
  address 169.254.169.254), multicast and reserved destinations, re-checks every
  redirect, verifies TLS against the node's trust store and caps the size. RFC
  1918 addresses ARE allowed: a company's own site or a peer node usually lives
  on one.
"""
from __future__ import annotations

import base64
import io
import ipaddress
import re
import socket
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import theme_service

SCHEMA_V1 = "satom.ui-theme/1"
SCHEMA_V2 = "satom.ui-theme/2"
SCHEMAS = (SCHEMA_V1, SCHEMA_V2)

ASSET_KINDS = ("logo", "favicon")
RASTER_EXT = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico"}
LOGO_MAX_PX = 256
MAX_SVG_BYTES = 512 * 1024
MAX_RASTER_BYTES = 4 * 1024 * 1024

#: What a remote theme document may weigh: two assets at their caps, base64
#: inflated, plus the tokens.
MAX_DOCUMENT_BYTES = 12 * 1024 * 1024


# ── brand assets ────────────────────────────────────────────────────────────
def asset_dir() -> Path:
    """``data/branding`` (``SATOM_BRANDING_DIR`` overrides it). Under ``data/``
    so ``satom-ha-datasync`` replicates it to the standby; the system backup
    bundle carries it too (``system_backup.branding_dir``)."""
    import os
    d = Path(os.environ.get("SATOM_BRANDING_DIR")
             or Path(__file__).resolve().parents[2] / "data" / "branding")
    d.mkdir(parents=True, exist_ok=True)
    return d


_SVG_DROP_ELEMENTS = ("script", "foreignObject", "iframe", "embed", "object",
                      "audio", "video", "handler", "listener")


def sanitize_svg(text: str) -> "str | None":
    """Strip what can run or load from an SVG. ``None`` if it is not an SVG.

    A regex pass is not an XML sanitiser, and it is not the only layer: the
    asset route serves SVG with ``Content-Security-Policy: ...; sandbox`` and
    every page shows the logo through ``<img>``, where an SVG cannot run script
    at all. This pass removes the obvious carriers so a file opened directly
    is inert too.
    """
    for tag in _SVG_DROP_ELEMENTS:
        text = re.sub(r"(?is)<%s\b.*?</%s\s*>" % (tag, tag), "", text)
        text = re.sub(r"(?is)<%s\b[^>]*/?>" % tag, "", text)
    text = re.sub(r"(?is)<!DOCTYPE[^>[]*(\[.*?\])?\s*>", "", text)
    text = re.sub(r"(?is)<\?xml-stylesheet.*?\?>", "", text)
    # Event handlers: double-quoted, single-quoted and unquoted values.
    text = re.sub(r'(?i)\son[a-z]+\s*=\s*"[^"]*"', "", text)
    text = re.sub(r"(?i)\son[a-z]+\s*=\s*'[^']*'", "", text)
    text = re.sub(r"(?i)\son[a-z]+\s*=\s*[^\s>]+", "", text)
    # Links may point inside the document (#id) or at an embedded image only.
    text = re.sub(r'(?i)\s(?:xlink:)?href\s*=\s*"(?!#|data:image/(?:png|jpe?g|gif|webp);)[^"]*"',
                  "", text)
    text = re.sub(r"(?i)\s(?:xlink:)?href\s*=\s*'(?!#|data:image/(?:png|jpe?g|gif|webp);)[^']*'",
                  "", text)
    text = re.sub(r"(?i)javascript\s*:", "", text)
    if "<svg" not in text.lower():
        return None
    return text


def sniff_ext(raw: bytes, name: str = "", content_type: str = "") -> str:
    """Best guess at a file's real type: ``.svg``, a raster extension, or ``""``."""
    head = raw[:512].lstrip()
    if head.startswith(b"\x89PNG"):
        return ".png"
    if head.startswith(b"\xff\xd8"):
        return ".jpg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return ".webp"
    if head[:4] == b"\x00\x00\x01\x00":
        return ".ico"
    low = head.lower()
    if b"<svg" in raw[:4096].lower() or (low.startswith(b"<?xml") and b"<svg" in raw.lower()):
        return ".svg"
    ctype = (content_type or "").split(";")[0].strip().lower()
    if ctype == "image/svg+xml":
        return ".svg"
    ext = Path(urlsplit(name).path if "://" in name else name).suffix.lower()
    return ext if ext in RASTER_EXT or ext == ".svg" else ""


def store_asset(theme, kind: str, raw: bytes, ext: str, dest: Path) -> "str | None":
    """Write a brand asset for *theme* under *dest*. Returns an error, or ``None``.

    Rasters are re-encoded to PNG and fitted to 256 px, which is also what
    rejects a file that merely claims to be an image; SVG is sanitised.
    """
    if kind not in ASSET_KINDS:
        return "Unknown asset kind %r." % kind
    ext = (ext or "").lower()
    if ext == ".svg":
        if len(raw) > MAX_SVG_BYTES:
            return "SVG too large (max 512 KB)."
        text = sanitize_svg(raw.decode("utf-8", "replace"))
        if text is None:
            return "Not a valid SVG file."
        rel = "theme-%d-%s.svg" % (theme.id, kind)
        stale = dest / ("theme-%d-%s.png" % (theme.id, kind))
        (dest / rel).write_text(text, encoding="utf-8")
    elif ext in RASTER_EXT:
        if len(raw) > MAX_RASTER_BYTES:
            return "Image too large (max 4 MB)."
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(raw))
            if img.format == "ICO":
                # An .ico holds several sizes and Pillow opens the first; the
                # largest is the one worth keeping.
                sizes = sorted(img.info.get("sizes") or [], reverse=True)
                if sizes:
                    img.size = sizes[0]  # type: ignore[misc]
            img.load()
            if img.mode not in ("RGBA", "RGB"):
                img = img.convert("RGBA")
            img.thumbnail((LOGO_MAX_PX, LOGO_MAX_PX), Image.LANCZOS)
            rel = "theme-%d-%s.png" % (theme.id, kind)
            stale = dest / ("theme-%d-%s.svg" % (theme.id, kind))
            img.save(str(dest / rel), "PNG")
        except Exception as exc:  # noqa: BLE001
            return "Image could not be processed: %s" % exc
    else:
        return "Unsupported %s type (use PNG, JPG, WEBP, GIF, ICO or SVG)." % kind
    try:
        stale.unlink()
    except OSError:
        pass
    setattr(theme, kind, rel)
    return None


# ── the portable document ───────────────────────────────────────────────────
def export_document(row, asset_dir: Path) -> dict:
    """The v2 document for a theme row: tokens plus its logo and favicon."""
    assets: dict = {}
    for kind in ASSET_KINDS:
        rel = getattr(row, kind, "") or ""
        if not rel or "/" in rel or "\\" in rel:
            continue
        path = asset_dir / rel
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        assets[kind] = {"type": "svg" if rel.endswith(".svg") else "png",
                        "data": base64.b64encode(raw).decode("ascii")}
    return {"schema": SCHEMA_V2, "name": row.name,
            "description": row.description or "",
            "tokens": row.tokens, "assets": assets}


@dataclass
class Parsed:
    name: str
    description: str
    tokens: dict
    assets: dict          # kind -> (raw bytes, ext)
    errors: list


def parse_document(payload) -> Parsed:
    """Validate a v1 or v2 theme document. Any error refuses the whole thing."""
    errors: list = []
    if not isinstance(payload, dict) or payload.get("schema") not in SCHEMAS:
        return Parsed("", "", {}, {}, [
            "Not a SATOM theme (expected schema %s or %s)." % (SCHEMA_V2, SCHEMA_V1)])
    tokens, terrors = theme_service.validate_tokens(payload.get("tokens") or {})
    errors.extend(terrors)
    assets: dict = {}
    raw_assets = payload.get("assets") or {}
    if payload.get("schema") == SCHEMA_V2 and not isinstance(raw_assets, dict):
        errors.append("assets: expected an object.")
        raw_assets = {}
    for kind, item in raw_assets.items():
        if kind not in ASSET_KINDS:
            errors.append("assets: unknown asset %r." % kind)
            continue
        if not isinstance(item, dict) or item.get("type") not in ("svg", "png"):
            errors.append("%s: expected {type: svg|png, data: base64}." % kind)
            continue
        try:
            raw = base64.b64decode(str(item.get("data") or ""), validate=True)
        except Exception:  # noqa: BLE001
            errors.append("%s: data is not valid base64." % kind)
            continue
        if not raw:
            continue
        assets[kind] = (raw, "." + item["type"])
    name = " ".join(str(payload.get("name") or "").split())[:100] or "Imported theme"
    desc = " ".join(str(payload.get("description") or "").split())[:300]
    return Parsed(name, desc, tokens, assets, errors)


# ── fetching from elsewhere ─────────────────────────────────────────────────
class FetchError(Exception):
    """A fetch the operator should be told about, worded for the UI."""


@dataclass
class Fetched:
    body: bytes
    url: str
    content_type: str


_MAX_REDIRECTS = 4
_BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost",
                      "metadata", "metadata.google.internal"}


def _blocked_reason(ip) -> "str | None":
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return "a loopback address"
    if ip.is_link_local:
        return "a link-local address (this range holds cloud metadata services)"
    if ip.is_multicast:
        return "a multicast address"
    if ip.is_unspecified:
        return "an unspecified address"
    if ip.is_reserved:
        return "a reserved address"
    return None


def check_url(url: str):
    """Refuse a URL this node must not fetch. Returns the split URL."""
    url = (url or "").strip()
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise FetchError("%r is not a valid URL." % url[:200])
    if parts.scheme not in ("http", "https"):
        raise FetchError("Only http:// and https:// URLs can be fetched.")
    if not parts.hostname:
        raise FetchError("The URL has no host name.")
    if parts.username or parts.password:
        raise FetchError("Credentials inside the URL are not accepted.")
    host = parts.hostname.rstrip(".").lower()
    if host in _BLOCKED_HOSTNAMES:
        raise FetchError("%s refers to this node itself; it cannot be fetched." % host)
    try:
        infos = socket.getaddrinfo(host, port or (443 if parts.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        raise FetchError("%s does not resolve from this node." % host)
    for info in infos:
        try:
            ip = ipaddress.ip_address(str(info[4][0]).split("%")[0])
        except ValueError:
            continue
        why = _blocked_reason(ip)
        if why:
            raise FetchError("%s resolves to %s, %s; this node does not fetch from it."
                             % (host, ip, why))
    return parts


@contextmanager
def _open(url: str, headers: dict, timeout: float, verify):
    """One GET, redirects NOT followed, body streamed. The seam tests replace."""
    import httpx
    with httpx.Client(verify=verify, timeout=timeout, follow_redirects=False) as client:
        with client.stream("GET", url, headers=headers) as resp:
            yield resp


def fetch(url: str, *, max_bytes: int, timeout: float = 10.0,
          headers: "dict | None" = None, accept: str = "*/*") -> Fetched:
    """GET *url* with the guards above. *headers* (e.g. an API token) are sent
    to the ORIGINAL host only — never to a host a redirect points at."""
    import httpx

    from . import trust_store
    verify = trust_store.verify_param()
    first_host = (urlsplit(url).hostname or "").lower()
    current = url
    for _hop in range(_MAX_REDIRECTS + 1):
        parts = check_url(current)
        host = (parts.hostname or "").lower()
        send = {"User-Agent": "SATOM-theme-import/1", "Accept": accept}
        if headers and host == first_host:
            send.update(headers)
        try:
            with _open(current, send, timeout, verify) as resp:
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location")
                    if not loc:
                        raise FetchError("%s redirected without a Location." % host)
                    current = urljoin(current, loc)
                    continue
                if resp.status_code != 200:
                    raise FetchError("%s answered HTTP %d." % (host, resp.status_code))
                declared = resp.headers.get("Content-Length") or ""
                if declared.isdigit() and int(declared) > max_bytes:
                    raise FetchError("%s is larger than %d KB." % (current[:120], max_bytes // 1024))
                buf = bytearray()
                for chunk in resp.iter_bytes(65536):
                    buf += chunk
                    if len(buf) > max_bytes:
                        raise FetchError("%s is larger than %d KB."
                                         % (current[:120], max_bytes // 1024))
                return Fetched(bytes(buf), current, resp.headers.get("Content-Type") or "")
        except httpx.TimeoutException:
            raise FetchError("%s did not answer within %d s." % (host, int(timeout)))
        except httpx.HTTPError as exc:
            if "CERTIFICATE_VERIFY_FAILED" in str(exc) or "SSL" in type(exc).__name__:
                raise FetchError("TLS verification failed for %s. If it uses a private "
                                 "CA, add that CA under Settings -> Trust store." % host)
            raise FetchError("Could not reach %s (%s)." % (host, type(exc).__name__))
    raise FetchError("Too many redirects starting at %s." % url[:120])


def peer_endpoint(base: str, name: str = "") -> str:
    """The theme URL on another SATOM node, from whatever the operator pasted
    (``https://node``, ``https://node/``, ``https://node/settings/...``)."""
    parts = urlsplit((base or "").strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise FetchError("Enter the other node's address, e.g. https://satom.example.com.")
    url = "%s://%s/api/v1/ui/theme" % (parts.scheme, parts.netloc)
    if name:
        from urllib.parse import quote
        url += "?name=" + quote(name, safe="")
    return url


def fetch_from_node(base: str, token: str, name: str = "") -> dict:
    """The v2 document of a theme on another SATOM node (its active theme
    unless *name* is given). The token is used for this request and nothing
    else: it is never stored or logged."""
    token = (token or "").strip()
    if not token:
        raise FetchError("An API token from the other node is required.")
    url = peer_endpoint(base, name)
    got = fetch(url, max_bytes=MAX_DOCUMENT_BYTES, accept="application/json",
                headers={"Authorization": "Bearer " + token})
    import json
    try:
        doc = json.loads(got.body.decode("utf-8"))
    except Exception:  # noqa: BLE001
        raise FetchError("The other node did not answer with JSON. Is it a SATOM "
                         "node recent enough to share its theme over /api/v1?")
    if isinstance(doc, dict) and doc.get("error"):
        raise FetchError("The other node refused: %s" % str(doc.get("message") or doc["error"])[:200])
    return doc
