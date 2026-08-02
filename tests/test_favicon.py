"""The favicon must be the PRODUCT's, on every surface, including the one the
browser asks for without being told.

Three real defects motivated these guards (2026-08-02):

1. ``product/select.html`` — the ADOM chooser, the FIRST page after login —
   still shipped ``img/favicon.svg``, which is the *vendor* Fortinet mark in
   red ``#ee3124``, as both its favicon and its header logo. It survived three
   project renames because no text sweep for "fortinet"/"ofortmaut" matches a
   filename that says neither.
2. ``/favicon.ico`` 404'd on all three hosts. Browsers request that path
   implicitly, regardless of any ``<link rel="icon">`` tag, and they cache the
   ANSWER — a 404 included. A missing route is precisely why a stale icon
   outlives a rebrand.
3. The shipped fallback itself was the vendor logo, so any install without a
   theme asset served Fortinet's mark, not SATOM's.
"""
from __future__ import annotations

import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
VENDOR_SVG = "img/favicon.svg"


def _live_templates():
    """Templates Flask can actually render — editor backups are not surfaces."""
    return [p for p in (ROOT / "app" / "templates").rglob("*.html")
            if ".bak" not in p.name and ".pre-" not in p.name]


def test_no_live_template_serves_the_vendor_mark():
    offenders = [str(p.relative_to(ROOT)) for p in _live_templates()
                 if VENDOR_SVG in p.read_text()]
    assert offenders == [], (
        "these templates still serve the Fortinet vendor mark: %s" % offenders)


@pytest.mark.parametrize("rel", [
    "app/static/img/favicon.ico",
    "app/static/img/favicon.png",
    "app/static/img/satom-mark.png",
    "site/favicon.ico",
])
def test_product_icon_assets_are_shipped(rel):
    assert (ROOT / rel).is_file(), "%s is missing" % rel


def test_favicon_ico_is_multi_resolution_and_keeps_its_alpha():
    """A single-size opaque .ico is why rebrands look half-done: the browser
    upscales one bitmap and the square background fights every tab strip."""
    Image = pytest.importorskip("PIL.Image")
    for rel in ("app/static/img/favicon.ico", "site/favicon.ico"):
        ico = Image.open(ROOT / rel)
        sizes = set(ico.info.get("sizes", []))
        assert {(16, 16), (32, 32), (48, 48)} <= sizes, (
            "%s only carries %s" % (rel, sorted(sizes)))
        ico.size = (16, 16)
        corner = ico.convert("RGBA").getpixel((0, 0))
        assert corner[3] == 0, "%s has an opaque corner (plate, not mark)" % rel


def test_bare_root_favicon_is_served_not_404(client):
    """The path the browser asks for on its own. 404 here = stale icon forever."""
    r = client.get("/favicon.ico")
    assert r.status_code in (200, 302), (
        "/favicon.ico returned %s; browsers cache that answer" % r.status_code)
    if r.status_code == 302:
        assert "favicon" in r.headers.get("Location", "")


@pytest.mark.parametrize("page", sorted(
    [p for p in (ROOT / "site").rglob("*.html")],
    key=lambda p: str(p)))
def test_every_site_page_declares_the_ico(page):
    """Includes the 21 GENERATED docs pages: the generator is a separate
    surface and has drifted from the curated pages before (it served the
    Vision EBC company shield long after the curated nav moved on)."""
    assert 'href="favicon.ico"' in page.read_text() or \
           'favicon.ico" sizes' in page.read_text(), \
        "%s does not declare favicon.ico" % page.relative_to(ROOT)


def test_generator_emits_the_ico_link():
    """Guard the EXACT emitted artifact, not prose about it — a substring guard
    over self-documenting source has produced three false passes in this repo."""
    src = (ROOT / "deploy" / "gen_site_docs.py").read_text()
    assert '<link rel="icon" href="{up}favicon.ico" sizes="any">' in src
