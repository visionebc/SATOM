"""Guards for the scroll-reveal animation on the public site.

Context: the documentation body is wrapped in <section class="wrap reveal">.
When `.reveal` hid content by default and an IntersectionObserver with a
FRACTIONAL threshold was the only thing that could un-hide it, every manual
taller than a few viewports rendered permanently blank -- the ratio reported by
the observer is intersecting-area / element-area, so a 35 000 px page in an
813 px viewport tops out at 2.3 % and never crosses 0.12.

Two independent guards, either of which alone keeps the page readable:
  1. CSS hides nothing unless the head bootstrap has set html.js.
  2. The observer threshold is 0, so any pixel on screen reveals the section.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
CSS = SITE / "assets" / "site.css"
JS = SITE / "assets" / "site.js"

# rglob, not two hand-listed directories -- see tests/test_site_theme.py::_pages.
PAGES = sorted(p for p in SITE.rglob("*.html") if p.is_file())


def _strip_comments(js: str) -> str:
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    return re.sub(r"^\s*//.*$", "", js, flags=re.M)


def _rule_body(css: str, selector: str) -> str:
    """Body of the rule whose selector list is exactly `selector`."""
    for m in re.finditer(r"(?m)^([^{}\n@][^{}\n]*)\{([^{}]*)\}", css):
        if m.group(1).strip() == selector:
            return m.group(2)
    return ""


def test_bare_reveal_selector_does_not_hide_content():
    body = _rule_body(CSS.read_text(encoding="utf-8"), ".reveal")
    assert body, "the .reveal rule disappeared -- update this guard deliberately"
    opacity = re.search(r"opacity\s*:\s*([0-9.]+)", body)
    assert opacity, ".reveal must state its opacity explicitly"
    assert float(opacity.group(1)) == 1.0, (
        "`.reveal` hides content with no JS involved. A blocked, stale or "
        "CSP-stripped site.js then renders every documentation page blank. "
        "Gate the hiding on `html.js .reveal` instead."
    )


def test_hiding_is_gated_on_the_js_flag():
    body = _rule_body(CSS.read_text(encoding="utf-8"), "html.js .reveal")
    opacity = re.search(r"opacity\s*:\s*([0-9.]+)", body)
    assert opacity and float(opacity.group(1)) == 0.0, (
        "the animation start state must live behind html.js")


def test_observer_threshold_is_zero():
    js = _strip_comments(JS.read_text(encoding="utf-8"))
    thresholds = re.findall(r"threshold\s*:\s*([0-9.]+)", js)
    assert thresholds, "no IntersectionObserver threshold found in site.js"
    for value in thresholds:
        assert float(value) == 0.0, (
            f"threshold {value} requires that fraction of the ELEMENT be on "
            "screen. A page taller than 1/{value} viewports can never reach it "
            "and stays invisible for ever. Use 0.")


def test_safety_net_reveals_whatever_is_already_on_screen():
    js = _strip_comments(JS.read_text(encoding="utf-8"))
    assert "getBoundingClientRect" in js and "innerHeight" in js, (
        "the post-load safety net that reveals in-viewport sections is gone")


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_every_page_sets_the_js_flag_before_the_stylesheet(page):
    html = page.read_text(encoding="utf-8")
    flag = html.find('className+=" js"')
    assert flag != -1, f"{page.name} never sets html.js -- .reveal would never arm"
    sheet = html.find("site.css")
    assert sheet != -1 and flag < sheet, (
        f"{page.name} sets html.js after the stylesheet: the browser can paint "
        "the un-hidden state first and flash the content")


def test_site_js_announces_that_it_ran():
    js = JS.read_text(encoding="utf-8")
    assert "window.__satomReveal = true" in js, (
        "site.js must flag that it executed, or the head bootstrap cannot tell "
        "a working page from one whose script 404'd")


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_bootstrap_drops_the_flag_when_site_js_never_runs(page):
    """html.js arms the hiding; if the file that un-hides never executes the
    flag must be withdrawn, or a 404/stale site.js blanks the page again."""
    html = page.read_text(encoding="utf-8")
    head = html.split("</head>")[0]
    assert "__satomReveal" in head and "setTimeout" in head, (
        f"{page.name} arms html.js with no failsafe: a missing site.js would "
        "leave the whole document at opacity 0")
