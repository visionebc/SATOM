"""Which link targets may go into an ``href`` or a ``src`` -- the rule alone.

The Wiki's Markdown renderer (``wiki_markdown``) and the Plugin Studio app
designer (``studio_design``, *Link button* blocks) judge an address the same
way. The rule lives here, with nothing but the standard library, so the
database-free rules pack (``rules_pack``) carries it without python-markdown;
``wiki_markdown`` re-exports it unchanged.

Kept: http(s), mailto, in-page (``#x``), site paths (``/x``) and relative
targets. Dropped: ``javascript:``, ``data:``, ``vbscript:`` and every other
scheme -- scheme case, embedded whitespace and entity-encoded colons
(``javascript&#58;``) included.
"""
from __future__ import annotations

import html
import re
from urllib.parse import urlsplit

_SAFE_SCHEMES = {"http", "https", "mailto"}
_WS = re.compile(r"[\x00-\x20\x7f]+")


def _decoded(raw: str) -> str:
    """``raw`` with HTML entities decoded until nothing changes.
    python-markdown keeps ``&#58;`` in an href as written and the browser
    decodes it, so ``javascript&#58;`` IS ``javascript:`` — the scheme is
    judged on what the browser will see, and that is what gets emitted (a
    fixpoint holds no entity left to decode)."""
    for _ in range(8):
        nxt = html.unescape(raw)
        if nxt == raw:
            return raw
        raw = nxt
    return ""


def safe_url(raw: str | None, *, image: bool = False) -> str | None:
    """``raw`` if it is safe to put in href/src, else ``None``."""
    url = _WS.sub("", _decoded(str(raw or "")))
    if not url:
        return None
    if url.startswith(("#", "/")) and not url.startswith("//"):
        return url
    scheme = urlsplit(url).scheme.lower()
    if not scheme:
        # "page", "./img.png" — relative. A colon before any slash would
        # have been parsed as a scheme above.
        return url
    allowed = {"http", "https"} if image else _SAFE_SCHEMES
    return url if scheme in allowed else None
