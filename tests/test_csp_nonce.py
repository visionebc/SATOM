"""Every inline <script>/<style> this product ships carries the CSP nonce.

WHY THIS FILE EXISTS
--------------------
The app serves ``script-src-elem 'self' 'nonce-<per-session>'`` (app/__init__.py
``_csp_nonce``).  An inline ``<script>`` without that attribute is therefore
**blocked by the browser** -- and nothing anywhere reports it:

  * the template compiles,
  * the route returns 200,
  * the markup is valid and the element is present in the DOM,
  * every server-side test passes,
  * a headless render without the header (the obvious way to "check the page")
    passes too, because the header is what does the blocking.

The only visible symptom is a control that silently does nothing.  On
2026-08-23 that was the whole Admin Console menu: the accordion script moved
from ``settings/index.html`` (whose block carried the nonce) into the shared
``settings/_nav.html`` partial, the attribute did not come with it, and every
group on every Settings surface stopped expanding at once.  Measured in
chromium against the live CSP: 0 of 9 groups opened; with the same page and no
header, 9 of 9.  The sweep that followed found **ten more** blocks in the same
state -- the Vault tab's test/migrate script, the incident page's layer charts,
integrations, change requests, upgrade flow, and two ``<style>`` blocks
(``style-src-elem`` names a nonce too, so inline styles are blocked the same
way).  None of them had ever worked in a browser.

So this is not a style rule.  It is the only mechanism that can catch the
class.
"""
from __future__ import annotations

import os
import re

import pytest

from tests.conftest import admin_user_id, login

TEMPLATES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "app", "templates")

_TAG = re.compile(r"<(script|style)\b([^>]*)>", re.I)
# A block the browser never executes is not subject to script-src.
_NONEXEC = re.compile(r'type\s*=\s*[\'"](application/json|text/template|text/x-template)', re.I)

_JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.S)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
_C_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"^[ \t]*//[^\n]*", re.M)


def _uncommented(src: str) -> str:
    """Blank out every comment, preserving offsets so line numbers stay true.

    Prose about this rule necessarily contains the very markup the rule
    forbids -- the docstring above does, and so does the header of
    ``settings/_nav.html``.  A scan that reads comments reports its own
    explanation as a violation, and the obvious "fix" is to delete the
    explanation.  (Same trap, ninth time: see safeguards §107.)
    """
    out = src
    for rx in (_JINJA_COMMENT, _HTML_COMMENT, _C_COMMENT, _LINE_COMMENT):
        out = rx.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), out)
    return out


def _offenders(kind: str) -> list[tuple[str, int]]:
    hits: list[tuple[str, int]] = []
    for dirpath, _dirs, files in os.walk(TEMPLATES):
        for fn in sorted(files):
            if not fn.endswith(".html"):
                continue
            path = os.path.join(dirpath, fn)
            with open(path, encoding="utf-8") as fh:
                src = _uncommented(fh.read())
            for m in _TAG.finditer(src):
                if m.group(1).lower() != kind:
                    continue
                attrs = m.group(2)
                if "src=" in attrs or "href=" in attrs:
                    continue          # external asset: covered by 'self'
                if _NONEXEC.search(attrs):
                    continue
                if "csp_nonce" in attrs:
                    continue
                rel = os.path.relpath(path, TEMPLATES)
                hits.append((rel, src.count("\n", 0, m.start()) + 1))
    return hits


def _walked() -> list[str]:
    seen = []
    for dirpath, _dirs, files in os.walk(TEMPLATES):
        seen += [os.path.relpath(os.path.join(dirpath, f), TEMPLATES)
                 for f in files if f.endswith(".html")]
    return seen


def test_the_scan_actually_walks_the_template_tree():
    """A scan that reads NOTHING passes both assertions below.

    Found by mutation: pointing TEMPLATES at a path that does not exist left
    every other test in this file green.  An empty walk and a clean tree are
    indistinguishable from the outside, so the census has to be asserted.
    """
    seen = _walked()
    assert len(seen) > 100, f"only {len(seen)} templates walked -- TEMPLATES is wrong"
    for must in ("base.html", os.path.join("settings", "_nav.html"),
                 os.path.join("settings", "index.html")):
        assert must in seen, f"{must} not walked"


def test_every_inline_script_in_a_template_carries_the_nonce():
    bad = _offenders("script")
    assert not bad, (
        "inline <script> without nonce=\"{{ csp_nonce }}\" -- these are BLOCKED "
        "in a browser and fail silently: "
        + ", ".join(f"{f}:{ln}" for f, ln in bad)
    )


def test_every_inline_style_in_a_template_carries_the_nonce():
    bad = _offenders("style")
    assert not bad, (
        "inline <style> without nonce=\"{{ csp_nonce }}\" -- style-src-elem "
        "names a nonce, so these never apply: "
        + ", ".join(f"{f}:{ln}" for f, ln in bad)
    )


def test_the_scan_can_actually_see_a_violation():
    """The scan above is only a guard if it can fail.

    Both assertions read a tree that is currently clean, so "passes" and
    "reads nothing at all" look identical -- a broken walker, a wrong
    TEMPLATES path or an over-eager comment stripper would be invisible.
    """
    src = _uncommented("<div>\n<script>\nvar x = 1;\n</script>\n")
    m = _TAG.search(src)
    assert m is not None and "csp_nonce" not in m.group(2)
    # ...and prose about the rule is NOT a violation.
    assert _TAG.search(_uncommented("{# never write <script> bare #}")) is None
    assert _TAG.search(_uncommented("<!-- <style> in an HTML comment -->")) is None
    assert _TAG.search(_uncommented("  // a <script> in a JS line comment")) is None


def test_the_csp_still_requires_a_nonce_for_inline_scripts(client):
    """If the policy stops naming a nonce, the two scans above mean nothing."""
    resp = client.get("/auth/login")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert csp, "no CSP header at all"
    elem = [d.strip() for d in csp.split(";") if d.strip().startswith("script-src-elem")]
    assert elem, f"no script-src-elem directive: {csp}"
    assert "'nonce-" in elem[0], elem[0]
    assert "'unsafe-inline'" not in elem[0], (
        "script-src-elem allows unsafe-inline -- inline scripts would run "
        "without a nonce and this whole guard is vacuous"
    )


@pytest.mark.parametrize("path", ["/settings/", "/settings/sentinel"])
def test_the_rendered_settings_surfaces_carry_no_blocked_inline_script(app, client, path):
    """Render-level check: a template scan cannot see markup built by a macro."""
    login(client, admin_user_id(app))
    resp = client.get(path)
    assert resp.status_code == 200, resp.status_code
    # Comment-stripped: a JS comment inside any of the page's own scripts
    # may legitimately SPELL a script tag while explaining this very rule,
    # and reading it would make the guard report the explanation.
    html = _uncommented(resp.get_data(as_text=True))
    nonce = resp.headers.get("Content-Security-Policy", "")
    nonce = re.search(r"'nonce-([^']+)'", nonce)
    assert nonce, "rendered page served without a nonce in its CSP"
    blocked = []
    for m in _TAG.finditer(html):
        attrs = m.group(2)
        if "src=" in attrs or "href=" in attrs or _NONEXEC.search(attrs):
            continue
        if nonce.group(1) not in attrs:
            blocked.append(m.group(0)[:70])
    assert not blocked, f"{path} ships inline blocks the browser will drop: {blocked}"


def test_the_admin_console_menu_script_is_nonced(app, client):
    """The regression that cost the whole menu, named directly.

    The accordion is the only script in ``settings/_nav.html``; without the
    nonce the menu renders perfectly and no group can be opened.
    """
    login(client, admin_user_id(app))
    html = _uncommented(client.get("/settings/").get_data(as_text=True))
    assert "satom.settingsnav.open.v1" in html, "accordion script missing entirely"
    head = html[: html.index("satom.settingsnav.open.v1")]
    tag = head[head.rindex("<script") :]
    assert "nonce=" in tag, "the menu's accordion script carries no nonce"
