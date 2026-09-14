"""The sidebar must never collapse the section the operator is standing in.

Reported 2026-09-14: clicking Administrator -> Change Types lands on
``/administration/change-types/`` with the Administrator section folded shut.
The cause was structural, not cosmetic — see ``app/nav_state.py``: each group's
``open`` state was a hand-written blueprint list in ``base.html``, a second
author for a fact the group body already states by marking one item ``active``.
Nothing failed when the two disagreed; the section just closed.

So this guard asserts the RELATION, not a list of pages: for every page that
marks a sidebar item active, the group containing that item renders ``open``.
Written as a sweep over the live route map on purpose — a fixture of known URLs
would keep passing when the next blueprint is added, which is exactly the
failure being closed. The whole sweep costs a few seconds.
"""
from __future__ import annotations

import re

import pytest

from conftest import admin_user_id, login

from app.nav_state import _CLASS, _DIV_OPEN, _extent, _has_active_item, autoopen

#: Every ADOM renders its OWN sidebar block in base.html, each with its own
#: group list, so a drift can exist in one and not the others.
ADOMS = ["global", "fortiweb", "fortiadc", "fortianalyzer", "fortiauthenticator"]

_NAME = re.compile(r'data-nav-(?:sub)?group="([^"]*)"')


def _sidebar(html: str) -> str:
    i = html.find('id="fw-sidebar"')
    if i < 0:
        return ""
    j = html.find("</aside>", i)
    return html[i: j if j > 0 else len(html)]


def _groups_holding_active(html: str) -> list[tuple[str, bool]]:
    """[(group name, is open)] for every group whose extent holds an active item."""
    sb = _sidebar(html)
    out = []
    for m in _DIV_OPEN.finditer(sb):
        cm = _CLASS.search(m.group(1))
        cls = cm.group(1).split() if cm else []
        if not any(t in cls for t in ("fw-nav-group", "fw-nav-subgroup")):
            continue
        if _has_active_item(sb[m.end():_extent(sb, m.end())]):
            nm = _NAME.search(m.group(1))
            out.append((nm.group(1) if nm else "?", "open" in cls))
    return out


def _pages(app):
    return sorted({r.rule for r in app.url_map.iter_rules()
                   if "GET" in r.methods and not r.arguments
                   and not r.rule.startswith("/static")})


def _render(client, rule):
    """GET *rule*, or None when it is not an HTML page we can inspect."""
    resp = client.get(rule)
    if resp.status_code != 200 or "html" not in (resp.content_type or ""):
        return None
    html = resp.get_data().decode("utf-8", "replace")
    return html if 'id="fw-sidebar"' in html else None


# ---------------------------------------------------------------------------
# The relation, swept over every page
# ---------------------------------------------------------------------------

def test_no_page_collapses_the_section_it_is_in(app, client):
    uid = admin_user_id(app)
    collapsed: dict[str, set[str]] = {}
    checked = 0
    observed = 0
    for adom in ADOMS:
        for rule in _pages(app):
            # Re-seat the session per request: /auth/logout is one of the rules,
            # and a single login() up front made the sweep log ITSELF out and
            # then "pass" over 176 redirects to the login page.
            login(client, uid, product=adom)
            html = _render(client, rule)
            if html is None:
                continue
            checked += 1
            for name, is_open in _groups_holding_active(html):
                observed += 1
                if not is_open:
                    collapsed.setdefault(rule, set()).add("%s/%s" % (adom, name))

    assert not collapsed, "sections render collapsed on their own page: %r" % collapsed

    # Guard the guard: an empty sweep would satisfy the line above in silence,
    # which is the same shape of hollow green this file exists to prevent.
    # Measured 2026-09-14: 381 pages rendered, 265 group-hits. Floors sit below
    # that so ordinary growth does not trip them, but a sweep that collapses to
    # a handful of pages (an auth regression, a redirect loop) does.
    assert checked > 300, "sweep only rendered %d pages" % checked
    assert observed > 200, "sweep saw only %d active items inside groups" % observed


def test_the_reported_regression(app, client):
    """The two pages that were actually broken, named, per ADOM."""
    uid = admin_user_id(app)
    for adom in ADOMS:
        login(client, uid, product=adom)
        for rule in ("/administration/change-types/", "/adom-assets/"):
            html = _render(client, rule)
            assert html is not None, "%s did not render under %s" % (rule, adom)
            held = _groups_holding_active(html)
            assert held, "%s marks no sidebar item active under %s" % (rule, adom)
            assert all(is_open for _n, is_open in held), \
                "%s under %s: %r" % (rule, adom, held)


def test_base_html_pipes_the_sidebar_through_the_filter(app):
    """Deleting the ``{% filter %}`` wrapper must fail here, not in production.

    Asserted on the TEMPLATE SOURCE because it is markup that never reaches the
    response: the whole point of the filter is that its output is indistinguish-
    able from a correctly hand-written list.
    """
    src = app.jinja_env.loader.get_source(app.jinja_env, "base.html")[0]
    nav = src[src.index('id="fw-sidebar"'):src.index("</aside>")]
    assert re.search(r"{%\s*filter\s+nav_autoopen\s*%}", nav)
    assert re.search(r"{%\s*endfilter\s*%}", nav)
    # ...and the filter is really registered under that name.
    assert "nav_autoopen" in app.jinja_env.filters


# ---------------------------------------------------------------------------
# autoopen() itself
# ---------------------------------------------------------------------------

GROUP = ('<div class="fw-nav-group" data-nav-group="G">'
         '<div class="fw-nav-group-body">%s</div></div>')
ACTIVE = '<a class="fw-nav-item active" href="#">x</a>'
IDLE = '<a class="fw-nav-item" href="#">x</a>'


def test_opens_a_group_holding_an_active_item():
    assert 'class="fw-nav-group open"' in autoopen(GROUP % ACTIVE)


def test_leaves_a_group_with_no_active_item_shut():
    assert "open" not in autoopen(GROUP % IDLE)


def test_is_idempotent():
    once = autoopen(GROUP % ACTIVE)
    assert str(autoopen(str(once))) == str(once)


def test_never_removes_an_open_the_template_set():
    """``ADOMs`` is unconditionally open and holds no active item; pages that
    mark nothing active still lean on the blueprint lists. Only ever add."""
    src = '<div class="fw-nav-group open" data-nav-group="ADOMs">%s</div>' % IDLE
    assert 'class="fw-nav-group open"' in autoopen(src)


def test_opens_the_subgroup_and_its_parent():
    src = ('<div class="fw-nav-group" data-nav-group="Ops">'
           '<div class="fw-nav-group-body">'
           '<div class="fw-nav-subgroup" data-nav-subgroup="Troubleshooting">'
           '<div class="fw-nav-subgroup-body">%s</div></div>'
           '</div></div>') % ACTIVE
    out = str(autoopen(src))
    assert 'class="fw-nav-group open"' in out
    assert 'class="fw-nav-subgroup open"' in out


def test_a_sibling_group_is_not_opened():
    src = (GROUP % IDLE).replace('"G"', '"Quiet"') + (GROUP % ACTIVE)
    out = str(autoopen(src))
    assert out.index('data-nav-group="Quiet"') < out.index("open")


def test_group_body_is_not_mistaken_for_a_group():
    """``"fw-nav-group" in "fw-nav-group-body"`` is true; token equality is the
    only thing keeping every body from becoming its own accordion section."""
    out = str(autoopen(GROUP % ACTIVE))
    assert 'class="fw-nav-group-body open"' not in out
    assert out.count(" open") == 1


def test_a_section_header_is_not_an_active_item():
    """Headers carry ``fw-nav-item`` too (``.fw-nav-subtoggle``). Only the pair
    ``fw-nav-item`` + ``active`` counts, or a header would open everything."""
    hdr = '<button class="fw-nav-item fw-nav-subtoggle">h</button>'
    assert "open" not in autoopen(GROUP % hdr)


def test_markup_without_groups_is_returned_unchanged():
    assert str(autoopen("<p>no nav here</p>")) == "<p>no nav here</p>"


def test_unbalanced_markup_does_not_raise():
    """A malformed sidebar must still render; the extent falls back to EOF."""
    assert autoopen('<div class="fw-nav-group">%s' % ACTIVE) is not None
