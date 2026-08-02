"""Guard: every site page must reference content-stamped CSS/JS.

The failure this prevents is specific and was reported from production: the
theme picker is markup in the HTML and handlers in ``assets/site.js``. nginx
sends no ``Cache-Control`` for the static site, so a returning visitor can hold
a pre-feature ``site.js`` while receiving fresh HTML — three swatches rendered
and inert. A content hash in the URL makes that impossible: changed asset,
changed URL.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "site")
STAMPER = os.path.join(ROOT, "deploy", "stamp_site_assets.py")


def _pages() -> "list[str]":
    out = []
    for base, _d, files in os.walk(SITE):
        out += [os.path.join(base, f) for f in files if f.endswith(".html")]
    return sorted(out)


def test_every_page_reference_is_stamped_with_the_current_hash():
    r = subprocess.run([sys.executable, STAMPER, "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr or r.stdout


def test_no_page_links_a_bare_site_asset():
    """A single unstamped reference is enough to re-introduce the stale cache."""
    bare = re.compile(r'(?:href|src)="[^"]*site\.(?:css|js)"')
    offenders = [os.path.relpath(p, ROOT) for p in _pages()
                 if bare.search(open(p, encoding="utf-8").read())]
    assert offenders == [], offenders


def test_the_generator_emits_stamped_references_too():
    """gen_site_docs writes 21 of the 27 pages; if it emits bare URLs the very
    next regeneration silently undoes the stamping."""
    gen = open(os.path.join(ROOT, "deploy", "gen_site_docs.py"),
               encoding="utf-8").read()
    assert "stamp_site_assets" in gen, (
        "gen_site_docs.py must stamp its output; otherwise regenerating the "
        "docs reverts every asset URL to the uncacheable bare form")


def test_the_stamp_changes_when_the_asset_changes():
    """The hash must be derived from CONTENT, not from a version constant that
    a change can forget to bump."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("stamper", STAMPER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    before = mod.digest("site.js")
    path = os.path.join(SITE, "assets", "site.js")
    original = open(path, "rb").read()
    try:
        open(path, "wb").write(original + b"\n/* probe */\n")
        assert mod.digest("site.js") != before
    finally:
        open(path, "wb").write(original)
    assert mod.digest("site.js") == before
