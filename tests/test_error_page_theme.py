"""The standalone error pages must be SATOM light, and must stay standalone.

Why this file exists: every other page in the product has a per-page dark
theme guard (test_calendar_view, test_spo_wizard, test_cert_inspect, ...).
The three error templates had none, so they kept the fleet's dark
glassmorphism theme long after the rest of the product moved to light -- and
so did the inline fallback in ``_safe_render``, which is the surface that
renders when even the template cannot. Fixing the templates without a guard
here is what let it drift the first time.

Read-only: it reads source files and renders a 404 through the test client.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ERRORS = ROOT / "app" / "templates" / "errors"
PAGES = ["403.html", "404.html", "500.html"]

# The fleet's dark glassmorphism palette (feedback_default_style). It is the
# house style for Power Panel and friends; it is NOT this product's, which is
# light-only (safeguards Sec. 9m). Written split so this guard cannot match
# its own docstring the way an earlier draft did.
DARK_TOKENS = [
    "#" + "080d1a", "#" + "0f172a", "#" + "8b5cf6", "#" + "3b82f6",
    "rgba(15,23,42", "rgba(30,41,59", "backdrop-filter",
    "#" + "e2e8f0", "#" + "94a3b8", "#" + "cbd5e1", "#" + "fbbf24",
    "#" + "6ee7b7", "#" + "fcd34d", "#" + "fca5a5",
]

# From :root in static/css/fortiweb.css.
LIGHT_BG = "#F3F6FC"
LIGHT_SURFACE = "#FFFFFF"
ACCENT = "#0A3F9F"


def _strip_comments(css_or_py: str) -> str:
    """Drop /* ... */ and leading-# comments.

    A guard that reads raw source cannot tell a colour it forbids from the
    same colour named in a comment explaining why it is forbidden. Three
    drafts of this check failed on their own prose before this existed.
    """
    out = re.sub(r"/\*.*?\*/", "", css_or_py, flags=re.S)
    return "\n".join(
        ln for ln in out.splitlines() if not ln.lstrip().startswith("#"))


@pytest.mark.parametrize("name", PAGES)
def test_error_page_has_no_fleet_dark_tokens(name):
    body = _strip_comments((ERRORS / name).read_text(encoding="utf-8"))
    hits = [t for t in DARK_TOKENS if t.lower() in body.lower()]
    assert not hits, f"{name} carries fleet dark theme tokens: {hits}"


@pytest.mark.parametrize("name", PAGES)
def test_error_page_uses_satom_light_palette(name):
    body = (ERRORS / name).read_text(encoding="utf-8")
    assert LIGHT_BG in body, f"{name} does not set the SATOM content background"
    assert LIGHT_SURFACE in body, f"{name} does not set the SATOM card surface"
    assert ACCENT in body, f"{name} does not use the SATOM accent"


@pytest.mark.parametrize("name", PAGES)
def test_error_page_is_self_contained(name):
    """No external asset. These pages are reached exactly when serving the
    stylesheet may itself be broken, so a <link> would render them unstyled."""
    body = (ERRORS / name).read_text(encoding="utf-8")
    assert "<link" not in body, f"{name} pulls an external stylesheet"
    assert not re.search(r"<script[^>]+\bsrc=", body), f"{name} pulls an external script"
    assert "{% extends" not in body, f"{name} extends a base template"


def test_safe_render_fallback_is_light():
    """The fallback inside _safe_render is a fourth surface and drifted with
    the other three. It renders when the template render already failed."""
    src = (ROOT / "app" / "errors.py").read_text(encoding="utf-8")
    assert "_safe_render" in src
    frag = src.split("def _safe_render", 1)[1].split(
        "def register_error_handlers", 1)[0]
    frag = _strip_comments(frag)
    hits = [t for t in DARK_TOKENS if t.lower() in frag.lower()]
    assert not hits, f"_safe_render fallback carries dark tokens: {hits}"
    assert LIGHT_BG in frag, "_safe_render fallback does not set the light background"


def test_rendered_404_is_light(client):
    """Renders through the real handler -- a template nobody serves is not a
    page. The source checks above would pass on a file that is never used."""
    resp = client.get("/a-route-that-does-not-exist-ever-9f2b")
    assert resp.status_code == 404
    html = resp.get_data(as_text=True)
    assert LIGHT_BG in html
    body = _strip_comments(html)
    hits = [t for t in DARK_TOKENS if t.lower() in body.lower()]
    assert not hits, f"served 404 carries dark tokens: {hits}"
