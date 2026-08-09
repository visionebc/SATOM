"""One SATOM mark, named after the product, on every surface that shows a brand.

Three defects motivated these guards (2026-08-10, reported by the user as
"el logo ... no es el correcto"):

1. The product site's header mark was the CHARACTER ``S`` in a gradient box —
   a placeholder, not an asset. The only real vector the product owned was
   filed as ``assets/favicon.svg``: the mark was named after ONE OF ITS USES,
   so nothing named "logo" or "mark" existed to find.
2. The console and the repo site drew a raster emblem that reads as a "G".
3. Those surfaces drifted independently: ``app/static/img/satom-mark.png``,
   ``site/assets/satom-mark.png`` and the uploaded theme override were three
   separate files that nothing forced to agree.

The guards below are mostly ABSENCE and IDENTITY assertions, because a brand
never fails loudly — it just quietly says two different things in two places.
"""
from __future__ import annotations

import hashlib
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MARK_SVG = ROOT / "app" / "static" / "img" / "satom-mark.svg"
SITE_MARK_SVG = ROOT / "site" / "assets" / "satom-mark.svg"


def _digest(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _live_templates():
    """Editor backups under ``backups/`` are dead text, not surfaces."""
    return [p for p in (ROOT / "app" / "templates").rglob("*.html")
            if ".bak" not in p.name and ".pre-" not in p.name]


def _site_pages():
    return sorted((ROOT / "site").rglob("*.html"))


# ── the asset exists and is named after the product ────────────────────────
@pytest.mark.parametrize("rel", [
    "app/static/img/satom-mark.svg",
    "site/assets/satom-mark.svg",
])
def test_vector_mark_is_shipped_under_the_product_name(rel):
    assert (ROOT / rel).is_file(), (
        "%s is missing — the brand mark must be findable by the product's "
        "name, not by one of its uses (favicon/icon)" % rel)


def test_vector_mark_carries_the_product_NAME_not_just_a_glyph():
    """A logo an assistive reader announces as "image" has no name at all."""
    svg = MARK_SVG.read_text()
    assert 'aria-label="SATOM"' in svg, "the mark must be labelled SATOM"
    assert "<title>SATOM</title>" in svg, (
        "the mark must carry a <title> — aria-label alone is dropped by some "
        "readers when the SVG is referenced through <img>")


# ── one mark, not several ──────────────────────────────────────────────────
def test_every_copy_of_the_mark_is_byte_identical():
    """Three copies that nothing forces to agree is how a rebrand ends up
    half-applied: the console says one thing and the site says another."""
    copies = {
        "app/static/img/satom-mark.svg": _digest(MARK_SVG),
        "site/assets/satom-mark.svg": _digest(SITE_MARK_SVG),
    }
    assert len(set(copies.values())) == 1, (
        "the shipped marks have drifted apart: %s" % copies)


def test_raster_variants_are_rendered_from_the_vector_at_the_same_size():
    """The PNG is a DERIVATIVE. If it stops matching the vector's aspect and
    palette, the tab icon and the header stop being the same logo."""
    Image = pytest.importorskip("PIL.Image")
    for rel in ("app/static/img/satom-mark.png", "site/assets/satom-mark.png"):
        im = Image.open(ROOT / rel)
        assert im.size == (256, 256), "%s is %s" % (rel, im.size)
        assert im.mode == "RGBA", "%s lost its alpha (%s)" % (rel, im.mode)
    assert _digest(ROOT / "app/static/img/satom-mark.png") == \
        _digest(ROOT / "site/assets/satom-mark.png"), (
            "console and site ship different rasters of the same mark")


# ── no surface still points at the superseded raster ───────────────────────
def test_no_live_template_points_at_the_superseded_raster():
    offenders = [str(p.relative_to(ROOT)) for p in _live_templates()
                 if "img/satom-mark.png" in p.read_text()]
    assert offenders == [], (
        "these templates still request the raster mark instead of the vector: "
        "%s" % offenders)


BRAND_ANCHOR = re.compile(r'<a class="brand".*?</a>', re.S)
ICON_LINKS = re.compile(r'<link rel="[^"]*icon[^"]*"[^>]*>')


def _brand_chrome(page: pathlib.Path) -> str:
    """The header brand plus the icon links — the CHROME, never the body.

    Scanning a whole page is the eighth assert-by-substring in this repo to
    match its own documentation: the generated CHANGELOG and safeguards pages
    NAME ``satom-mark.png`` in prose while correctly linking the vector, and a
    full-page sweep calls that a regression.
    """
    text = page.read_text()
    return "\n".join(BRAND_ANCHOR.findall(text) + ICON_LINKS.findall(text))


def test_no_site_page_points_at_the_superseded_raster():
    offenders = [str(p.relative_to(ROOT)) for p in _site_pages()
                 if "satom-mark.png" in _brand_chrome(p)]
    assert offenders == [], (
        "these site pages still request the raster mark: %s" % offenders)


def test_the_generator_template_agrees_with_the_pages_it_regenerates():
    """Two authors of one string is how ``index.html`` lost its Docs link: a
    page fixed by hand is reverted by the next regeneration."""
    gen = (ROOT / "deploy" / "gen_site_docs.py").read_text()
    assert "assets/satom-mark.svg" in gen, (
        "the site generator still stamps the old mark — every regenerated "
        "page would revert")
    assert "satom-mark.png" not in gen


def test_every_site_page_shows_the_mark_in_its_header():
    """A header that renders only the wordmark is the placeholder state this
    change removed; it must not come back one page at a time."""
    missing = [str(p.relative_to(ROOT)) for p in _site_pages()
               if 'class="brand"' in p.read_text()
               and "satom-mark.svg" not in _brand_chrome(p)]
    assert missing == [], "these pages render a brand with no mark: %s" % missing


def test_the_mark_is_not_the_vendor_palette():
    """Renamed-copy guard: the vendor glyph survived three project renames
    because no sweep for its NAME could match it. Sweep the colour."""
    for p in (MARK_SVG, SITE_MARK_SVG):
        assert not re.search(r"ee3124", p.read_text(), re.I), (
            "%s carries the vendor red" % p)
