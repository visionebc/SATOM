"""The manual, served by the node itself (``/manual/``).

WHAT IS SERVED is the published artefact, never the Markdown: the reference
pages ``deploy/gen_site_docs.py`` writes into ``site/``, and the public build
of the Documentation Center vendored into ``docs-center/``. Both went through
the redact-then-scan pipeline of :mod:`app.services.doc_publication` when they
were generated. Serving that output -- not re-rendering the source -- is what
keeps this from becoming the second, unguarded copy that leaked in 2026-08
(``tests/test_public_docs.py``): the routes that rendered ``docs/*.md`` stay
gone, and nothing here reads ``docs/``.

URL space: ``/manual/docs-center/<file>`` reads ``docs-center/``; every other
path reads ``site/``. The Documentation Center links the site pages as
``../index.html``, ``../assets/site.css`` ..., so the two trees resolve into
one another exactly as they do on the public host.

Public on purpose. The sign-in page links it, and the operator who cannot
sign in is the one who needs the installation guide and the recovery
runbooks -- on a management network with no route to the public site, this
copy is the only one there is. Everything here is already published.
"""
from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path, PurePosixPath

from flask import Blueprint, abort, redirect, send_from_directory, url_for

from app.services import doc_publication as pubdoc

bp = Blueprint("manual", __name__, url_prefix=pubdoc.MANUAL_PREFIX)

#: What a published page loads. Anything else in those trees -- the README.md
#: that explains a directory, CNAME, dotfiles -- is not part of the manual.
SERVED_SUFFIXES = frozenset({
    ".html", ".css", ".js", ".json", ".png", ".webp", ".svg", ".ico",
    ".jpg", ".jpeg", ".gif", ".woff", ".woff2",
})

#: Executable inline scripts only: a bare ``<script>``. The JSON data islands
#: (``<script type="application/json">``) are never executed, so CSP does not
#: govern them and they need no hash.
_INLINE_SCRIPT = re.compile(r"<script>(.*?)</script>", re.S)
_csp_cache: dict[tuple[str, float], str] = {}


def resolve(path: str) -> tuple[Path, str] | None:
    """``(directory, relative file)`` for a request path, or None.

    None for anything that is not a file of a served type inside one of the
    two trees: traversal, dotfiles, backslashes, symlinks that leave the tree.
    """
    if not path or path.endswith("/"):
        path += "index.html"
    if "\\" in path or "\x00" in path:
        return None
    parts = PurePosixPath(path).parts
    if any(p in ("", ".", "..") or p.startswith(".") for p in parts):
        return None
    if PurePosixPath(path).suffix.lower() not in SERVED_SUFFIXES:
        return None
    if parts[0] == "docs-center":
        base, rel = pubdoc.DOCS_CENTER_DIR, parts[1:]
    else:
        base, rel = pubdoc.SITE_DIR, parts
    if not rel:
        return None
    target = base.joinpath(*rel)
    try:
        if not target.is_file() or not target.resolve().is_relative_to(base.resolve()):
            return None
    except OSError:
        return None
    return base, "/".join(rel)


def csp_for(page: Path) -> str:
    """The page's own policy: the app-wide one forbids inline script, and the
    published pages carry one (the theme bootstrap, which must run before
    first paint). Each is allowed by its hash, never by ``'unsafe-inline'``,
    so an injected script still does not run. No third-party origin: the web
    font the public pages request is refused and the system font is used,
    which is what an isolated node gets anyway."""
    key = (str(page), page.stat().st_mtime)
    csp = _csp_cache.get(key)
    if csp is None:
        text = page.read_text(encoding="utf-8", errors="replace")
        hashes = sorted({
            "'sha256-%s'" % base64.b64encode(
                hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii")
            for body in _INLINE_SCRIPT.findall(text)})
        csp = "; ".join((
            "default-src 'self'",
            " ".join(["script-src 'self'"] + hashes),
            "script-src-attr 'none'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self' data:",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            # The release notes sidebar search is a GET form to releases.html.
            "form-action 'self'",
            "frame-ancestors 'none'",
        ))
        if len(_csp_cache) > 4096:
            _csp_cache.clear()
        _csp_cache[key] = csp
    return csp


@bp.route("/")
def home():
    """The Documentation Center home, by redirect.

    Not the page itself, and not ``page()`` with a default path: the pages link
    relatively, so they must be served from /manual/docs-center/. A default on
    the same endpoint makes the router canonicalise /manual/docs-center/ BACK to
    /manual/ (a 308), where every relative link resolves one level too high --
    and the redirect happens before any view runs, so even the product gate
    sees no endpoint.
    """
    return redirect(url_for("manual.page", path="docs-center/"))


@bp.route("/<path:path>")
def page(path: str):
    if path == "docs-center":
        # Without the slash, the pages' relative links would resolve one
        # level too high.
        return redirect(url_for("manual.page", path="docs-center/"), code=301)
    found = resolve(path)
    if found is None:
        abort(404)
    base, rel = found
    response = send_from_directory(base, rel, max_age=300)
    if rel.endswith(".html"):
        response.headers["Content-Security-Policy"] = csp_for(base / rel)
    return response
