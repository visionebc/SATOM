#!/usr/bin/env python3
"""Stamp the site's CSS/JS references with a content hash.

WHY THIS EXISTS
---------------
The site is static files behind nginx, which sends no ``Cache-Control`` and no
``Expires``. With neither, a browser applies *heuristic* freshness (roughly a
tenth of the document's age) and may keep serving a cached copy for hours.

That is survivable for a stylesheet and fatal for behaviour. The theme picker
ships as markup in the HTML and handlers in ``assets/site.js``. A visitor whose
HTML is fresh but whose JS is not sees three swatches that do nothing — the
control is visibly there and inert, which reads as "the feature is broken", not
"your cache is old".

Versioning the URL removes the guess: ``site.js?v=<hash>`` is a different
resource the moment the file changes, so a deploy always reaches every browser,
and unchanged assets stay cached. No server configuration, so it also holds on
GitHub Pages, where we do not control the headers at all.

``--check`` exits 1 if any page is unstamped or carries a stale hash;
``tests/test_site_assets.py`` runs it so a deploy cannot forget.

Usage::

    python3 deploy/stamp_site_assets.py           # rewrite
    python3 deploy/stamp_site_assets.py --check   # verify only
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "site")
ASSETS = ("site.css", "site.js")

# The hero pill carries the shipped version. It was a literal, which is how
# the application footer sat at "v1.0" through four releases: a number only a
# human can update is a number that will be wrong. Derived from the repo-root
# VERSION file -- the same file the bundle builders and the CLI read.
VERSION_FILE = os.path.join(ROOT, "VERSION")
VERSION_RE = re.compile(r'(<div class="pill"><span class="dot"></span>\s*)v[0-9][0-9A-Za-z.\-]*')


#: href="…/site.css"  or  src="…/site.js", with or without an existing ?v=
_REF = re.compile(
    r'((?:href|src)=")([^"]*?)(%s)(\?v=[0-9a-f]+)?(")'
    % "|".join(re.escape(a) for a in ASSETS))


def digest(name: str) -> str:
    path = os.path.join(SITE, "assets", name)
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()[:10]


def pages() -> "list[str]":
    out = []
    for base, _dirs, files in os.walk(SITE):
        for f in files:
            if f.endswith(".html"):
                out.append(os.path.join(base, f))
    return sorted(out)


def stamp(text: str, hashes: "dict[str, str]") -> str:
    def repl(m: "re.Match") -> str:
        pre, path, name, _old, post = m.groups()
        return "%s%s%s?v=%s%s" % (pre, path, name, hashes[name], post)
    return _REF.sub(repl, text)


def shipped_version() -> str:
    with open(VERSION_FILE, encoding="utf-8") as fh:
        return fh.read().strip()


def stamp_version(text: str, version: str) -> str:
    """Rewrite the hero pill to the shipped version."""
    return VERSION_RE.sub(lambda m: m.group(1) + "v" + version, text)


def main(argv: "list[str]") -> int:
    check = "--check" in argv
    hashes = {a: digest(a) for a in ASSETS}
    version = shipped_version()
    stale: "list[str]" = []
    written = 0
    for page in pages():
        with io.open(page, encoding="utf-8") as fh:
            src = fh.read()
        out = stamp_version(stamp(src, hashes), version)
        if out == src:
            continue
        rel = os.path.relpath(page, ROOT)
        if check:
            stale.append(rel)
            continue
        with io.open(page, "w", encoding="utf-8") as fh:
            fh.write(out)
        written += 1
    if check:
        if stale:
            sys.stderr.write(
                "asset references or the version pill are stale in %d page(s):\n  %s\n"
                "run: python3 deploy/stamp_site_assets.py\n"
                % (len(stale), "\n  ".join(stale)))
            return 1
        print("site asset stamps are current (v%s; %s)" %
              (version, ", ".join("%s=%s" % kv for kv in sorted(hashes.items()))))
        return 0
    print("stamped %d page(s) (v%s; %s)" %
          (written, version, ", ".join("%s=%s" % kv for kv in sorted(hashes.items()))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
