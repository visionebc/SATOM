"""Guards for the public site's theme layer.

Three failure modes these lock down, all of which shipped at least once:

1. A single ``--accent`` served both the light canvas and the navy chrome.
   The wordmark rendered at 1.65:1 -- present, legible to nobody. A brand
   colour cannot span a light and a dark background; the split into
   ``--accent`` / ``--accent-on-chrome`` is what these tests protect.

2. A theme block that omits a token silently inherits the previous theme's
   value, so "switch to dark" leaves light-canvas values behind with no
   error anywhere.

3. The docs generator drifted from the hand-written pages (it still shipped
   the Vision EBC shield in its nav long after the product mark landed).
   Both surfaces are asserted against the same expectations.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
CSS = SITE / "assets" / "site.css"
JS = SITE / "assets" / "site.js"
GENERATOR = ROOT / "deploy" / "gen_site_docs.py"

THEMES = ("aurora", "abyss", "classic")
STORAGE_KEY = "satom.site.theme"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _css() -> str:
    return CSS.read_text(encoding="utf-8")


def _theme_block(name: str) -> str:
    """Return the declaration body of one theme's override block."""
    src = _css()
    if name == "aurora":
        pat = r':root,\s*\nhtml\[data-theme="aurora"\]\s*\{(.*?)\}'
    else:
        pat = r'html\[data-theme="%s"\]\s*\{(.*?)\}' % re.escape(name)
    m = re.search(pat, src, re.S)
    assert m, f"no theme block for {name!r}"
    return m.group(1)


def _tokens(block: str) -> dict[str, str]:
    return {
        m.group(1): m.group(2).strip()
        for m in re.finditer(r"(--[a-z0-9-]+)\s*:\s*([^;]+);", block)
    }


def _pages() -> list[Path]:
    """Every page the site serves.

    rglob, not two hand-listed directories: the release-notes tree
    (``site/releases/``) was invisible to a two-directory enumeration, so a new
    subdirectory of pages would silently escape the theme and reveal guards.
    An enumeration that quietly covers less than it claims is the failure mode
    this suite exists to catch.
    """
    return sorted(p for p in SITE.rglob("*.html") if p.is_file())


def _luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    parts = [int(h[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in parts]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(fg: str, bg: str) -> float:
    a, b = _luminance(fg), _luminance(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


# --------------------------------------------------------------------------
# 1. every theme is complete
# --------------------------------------------------------------------------
def test_every_theme_defines_the_same_tokens():
    sets = {name: set(_tokens(_theme_block(name))) for name in THEMES}
    reference = sets["aurora"]
    for name in THEMES[1:]:
        missing = reference - sets[name]
        extra = sets[name] - reference
        assert not missing, (
            f"theme {name!r} is missing {sorted(missing)} -- it would silently "
            f"inherit the previously-applied theme's values"
        )
        assert not extra, f"theme {name!r} defines tokens no other theme has: {sorted(extra)}"


@pytest.mark.parametrize("name", THEMES)
def test_theme_defines_both_accent_slots(name):
    tokens = _tokens(_theme_block(name))
    for slot in ("--accent", "--accent-on-chrome", "--cta-bg", "--cta-edge", "--cta-fg"):
        assert slot in tokens, f"{name} has no {slot}"


# --------------------------------------------------------------------------
# 2. contrast -- the regression this whole split exists to prevent
# --------------------------------------------------------------------------
AA = 4.5

# (fg token, bg token) pairs that carry text or a legible mark.
PAIRS = [
    ("--accent-on-chrome", "--header"),   # wordmark + active underline on the bar
    ("--cta-fg", "--cta-edge"),           # nav CTA label on its button
    ("--accent", "--surface"),            # links / stats on a card
    ("--text", "--bg"),                   # body copy
    ("--text-2", "--surface"),            # secondary copy
    ("--on-chrome-2", "--header"),        # nav links
    ("--on-chrome-3", "--header"),        # footer copy
]


@pytest.mark.parametrize("name", THEMES)
def test_theme_passes_wcag_aa_on_every_text_pair(name):
    tokens = _tokens(_theme_block(name))
    failures = []
    for fg_tok, bg_tok in PAIRS:
        fg, bg = tokens.get(fg_tok, ""), tokens.get(bg_tok, "")
        if not (fg.startswith("#") and bg.startswith("#")):
            continue  # non-literal (var()/gradient) -- covered by the token tests
        ratio = contrast(fg, bg)
        if ratio < AA:
            failures.append(f"{fg_tok} ({fg}) on {bg_tok} ({bg}) = {ratio:.2f}:1")
    assert not failures, f"theme {name!r} below AA {AA}:1 -> " + "; ".join(failures)


def test_canvas_accent_is_never_painted_on_the_chrome():
    """The exact bug: --accent is a canvas colour; on the navy bar it vanished."""
    src = _css()
    chrome_rules = [
        r"\.brand b \{[^}]*\}",
        r"\.nav-links a\.active::after \{[^}]*\}",
        r"\.nav-cta \{[^}]*\}",
        r"footer \.addr \{[^}]*\}",
    ]
    for pat in chrome_rules:
        m = re.search(pat, src, re.S)
        assert m, f"chrome rule not found: {pat}"
        rule = m.group(0)
        assert "var(--accent)" not in rule, (
            f"{pat} paints var(--accent) -- a canvas colour -- on the chrome. "
            f"Use var(--accent-on-chrome) or the --cta-* pair."
        )


def test_no_gradient_is_used_where_css_needs_a_solid():
    """border-color/outline silently ignore a gradient; the border disappears."""
    src = _css()
    for prop in ("border-color", "outline-color", "caret-color"):
        for m in re.finditer(rf"{prop}\s*:\s*([^;]+);", src):
            value = m.group(1)
            assert "gradient" not in value and "--cta-bg" not in value, (
                f"{prop} is given a gradient-valued token ({value.strip()!r}); "
                f"use --cta-edge or another solid"
            )


# --------------------------------------------------------------------------
# 3. every page can actually switch -- both surfaces, no drift
# --------------------------------------------------------------------------
def test_there_are_pages_to_check():
    pages = _pages()
    assert len(pages) >= 20, f"expected the full site, found {len(pages)} pages"


@pytest.mark.parametrize("page", _pages(), ids=lambda p: str(p.relative_to(SITE)))
def test_page_bootstraps_the_theme_before_paint(page):
    """Without a blocking read in <head> the page paints Aurora, then flips."""
    html = page.read_text(encoding="utf-8")
    head = html.split("</head>", 1)[0]
    assert STORAGE_KEY in head, f"{page.name}: no theme bootstrap in <head>"
    assert "setAttribute" in head and "data-theme" in head, (
        f"{page.name}: bootstrap does not set data-theme"
    )


@pytest.mark.parametrize("page", _pages(), ids=lambda p: str(p.relative_to(SITE)))
def test_page_offers_every_theme(page):
    html = page.read_text(encoding="utf-8")
    for name in THEMES:
        assert f'data-theme-set="{name}"' in html, f"{page.name}: no {name} switch"


@pytest.mark.parametrize("page", _pages(), ids=lambda p: str(p.relative_to(SITE)))
def test_page_uses_the_product_mark_not_the_company_shield(page):
    """The generator kept shipping visionebc-shield.png after the rename."""
    html = page.read_text(encoding="utf-8")
    nav = html.split("</nav>", 1)[0]
    assert "visionebc-shield" not in nav, f"{page.name}: nav still uses the company shield"


def test_generator_matches_the_hand_written_pages():
    """The 20 generated pages must not drift from the 6 curated ones."""
    import ast

    src = GENERATOR.read_text(encoding="utf-8")
    assert STORAGE_KEY in src, "generator emits no theme bootstrap"
    # The template is an f-string, so every literal brace must be doubled. Assert
    # on the OUTPUT rather than on a byte sequence of the source: pinning the
    # exact source text made this test fail for any edit to the bootstrap, which
    # tells you nothing about whether the escaping is right.
    ast.parse(src)  # a mis-escaped f-string cannot even be parsed

    def bootstrap(path):
        text = path.read_text(encoding="utf-8").split("</head>")[0]
        for line in text.splitlines():
            if STORAGE_KEY in line:
                return line.strip()
        return ""

    generated = sorted((SITE / "docs").glob("*.html")) + sorted(
        (SITE / "releases").glob("*.html"))
    assert generated, "no generated pages to check"
    emitted = bootstrap(generated[0])
    curated = bootstrap(SITE / "index.html")
    assert emitted and curated, "a page carries no theme bootstrap"
    assert emitted == curated, (
        "the generated bootstrap has drifted from the curated one -- either the "
        "f-string escaping is wrong or one surface was edited alone:\n"
        f"  generated: {emitted}\n  curated:   {curated}")
    for name in THEMES:
        assert f'data-theme-set="{name}"' in src, f"generator omits the {name} switch"
    assert "visionebc-shield" not in src, "generator nav still uses the company shield"


def test_js_only_accepts_known_themes():
    """A stored value from an old release must not be written to the DOM."""
    js = JS.read_text(encoding="utf-8")
    assert STORAGE_KEY in js
    assert "THEMES.indexOf(name) < 0" in js, "applyTheme does not validate its input"
    for name in THEMES:
        assert f"'{name}'" in js, f"{name} missing from the JS theme list"


# --------------------------------------------------------------------------
# 4. brand assets
# --------------------------------------------------------------------------
@pytest.mark.parametrize("asset", ["satom-mark.png", "favicon.png"])
def test_brand_mark_keeps_its_transparency(asset):
    """The mark ships with no plate and no frame; flattening it re-adds both."""
    png = SITE / "assets" / asset
    assert png.exists(), f"{asset} missing"
    Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")
    with Image.open(png) as im:
        assert im.mode == "RGBA", f"{asset} has no alpha channel ({im.mode})"
        alpha = im.getchannel("A")
        w, h = im.size
        corners = [alpha.getpixel(p) for p in ((0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1))]
        assert corners == [0, 0, 0, 0], (
            f"{asset} corners are opaque {corners} -- the background/frame is back"
        )
