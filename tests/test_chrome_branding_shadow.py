"""The chrome's product name, and the kwarg that silently replaced it.

``base.html`` prints ``{{ product.title }}`` beside the logo. ``product`` is
the ADOM's branding DICT, put there by the branding context processor for
every template in the app.

A view that renders with ``product=<the product KEY>`` shadows that dict with
a **string** — and Jinja resolves ``.title`` on a str to the bound METHOD, so
the topbar rendered ``<built-in method title of str object at 0x…>``. Reported
by the operator on 2026-09-16 against three pages at once (API versions,
registry reconcile, the analysis fallback), which is the tell that this is a
name collision and not three typos.

Nothing failed. The page returned 200, every panel rendered, and the only
symptom was a line of Python repr in the chrome — so the guard is the fix:
the immediate repair renames the kwarg on three views, and the static test
below stops the fourth one being written.
"""
import io
import os
import re

import pytest

from tests.conftest import admin_user_id, login

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

#: Every name the branding context processor owns. A view kwarg that collides
#: with one of these replaces it for the whole template, chrome included.
RESERVED = ("product",)

PAGES = [
    "/web/registry/versions",
    "/adc/api/versions",
    "/web/registry/reconcile",
]


def _sources():
    for sub in ("app", "app/views"):
        d = os.path.join(ROOT, sub)
        for f in sorted(os.listdir(d)):
            if f.endswith(".py"):
                yield os.path.join(sub, f), io.open(
                    os.path.join(d, f), encoding="utf-8").read()


def _calls(src):
    """Every ``render_template(...)`` argument list, balanced."""
    for m in re.finditer(r"render_template\(", src):
        i, depth, j = m.end(), 1, m.end()
        while depth and j < len(src):
            if src[j] == "(":
                depth += 1
            elif src[j] == ")":
                depth -= 1
            j += 1
        yield src[:m.start()].count("\n") + 1, src[i:j - 1]


@pytest.mark.parametrize("name", RESERVED)
def test_no_view_shadows_a_branding_context_name(name):
    """The permanent half. The three renames are the symptom's repair; this is
    what stops the next page inheriting the bug — it cost nothing to write and
    the bug it catches raises no error at all."""
    bad = []
    for path, src in _sources():
        for line, args in _calls(src):
            args = re.sub(r"#[^\n]*", "", args)
            if re.search(r"(^|[\s,(])%s\s*=" % name, args):
                bad.append("%s:%d" % (path, line))
    assert not bad, (
        "these views pass %r to a template, shadowing the branding dict the "
        "chrome reads as %s.title — rename the kwarg (product_key): %s"
        % (name, name, bad))


def test_the_context_processor_really_supplies_a_dict(app, client):
    """The premise. If ``product`` ever stopped being a mapping, the guard
    above would be policing a rule that no longer buys anything."""
    login(client, admin_user_id(app))
    with client:
        client.get("/")
        from flask import g  # noqa: F401
        from app.branding import get_product
        p = get_product(None)
    assert hasattr(p, "get") and p.get("title"), p


@pytest.mark.parametrize("url", PAGES)
def test_no_page_prints_a_python_repr_in_its_chrome(app, client, url):
    """The symptom itself, pinned end to end.

    The static guard above would pass on a page that shadowed the dict some
    other way (a context processor of its own, a ``**ctx`` splat). This one
    does not care how it happened.
    """
    login(client, admin_user_id(app))
    html = client.get(url, follow_redirects=True).get_data(as_text=True)
    assert "<built-in method" not in html, \
        "%s printed a bound method: %s" % (
            url, re.findall(r"&lt;built-in method[^&]*|<built-in method[^<]*", html)[:2])
    assert "object at 0x" not in html, url
