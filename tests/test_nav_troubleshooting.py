"""Backend Reachability and Config Compare live under Operations -> Troubleshooting
in the FortiWeb ADOM, and stay under Fleet in the Global one.

Nothing here FAILS when it rots, which is the whole reason the file exists. A
menu entry that was moved into a group the reader never opens is still
"present" to every existing guard: ``test_adom_menu_reachability`` walks the
rendered links and finds it wherever it sits, and both pages keep answering by
URL. The claim that quietly becomes false is *where* the operator can find it.

Three distinct ways this move can break, each silent:

1. **Half a move.** Adding the entries to Operations without removing them from
   Fleet leaves TWO live copies of the same page in one sidebar — which is how
   the Monitoring group drifted before it became a partial. Guarded by asserting
   Fleet's absence, not only Troubleshooting's presence.

2. **A move that reached the wrong console.** The four ``<a>`` lines are
   byte-identical in the Global branch of ``base.html`` and in the FortiWeb one;
   a text substitution aimed at either will happily strike the other. The first
   attempt at this change did exactly that. Global has no Operations group to
   move them into, so its copies must survive under Fleet.

3. **A group that never opens itself.** ``_g_ops`` decides whether Operations is
   expanded on load. Leave the two blueprints out of it and the operator lands
   on /reachability/ with the menu entry that took them there collapsed out of
   sight — the page works, the navigation lies.
"""
from __future__ import annotations

import re

import pytest

from conftest import admin_user_id, login

HOME = {"global": "/", "fortiweb": "/web/"}

#: The two pages this file is about, with the URL each menu entry points at.
PAGES = {"Backend Reachability": "/reachability/",
         "Config Compare": "/compare/"}


def _sidebar(client, adom, path=None):
    r = client.get((path or HOME[adom]) + "?_adom=" + adom, follow_redirects=True)
    assert r.status_code == 200, f"{adom} {path or HOME[adom]} -> {r.status_code}"
    return r.get_data(as_text=True)


def _group(html, name):
    """One nav group's markup, opening tag included. Sliced at the next GROUP,
    so the subgroups this change adds stay inside it."""
    m = re.search(r'<div class="fw-nav-group([^"]*)" data-nav-group="%s">'
                  r'(?:(?!<div class="fw-nav-group[^"]*" data-nav-group=).)*' % re.escape(name),
                  html, re.S)
    return m.group(0) if m else None


def _labels(markup):
    return re.findall(r"<span>([^<]+)</span></a>", markup)


# ── the FortiWeb ADOM: the entries moved, and moved WHOLE ───────────────────
def test_operations_carries_a_troubleshooting_subgroup(app, client):
    login(client, admin_user_id(app), product="fortiweb")
    ops = _group(_sidebar(client, "fortiweb"), "Operations")
    assert ops, "no Operations group in the FortiWeb sidebar"
    assert 'data-nav-subgroup="Troubleshooting"' in ops, \
        "Operations has no Troubleshooting subgroup"


def test_both_pages_are_inside_that_subgroup(app, client):
    login(client, admin_user_id(app), product="fortiweb")
    ops = _group(_sidebar(client, "fortiweb"), "Operations")
    sub = re.search(r'data-nav-subgroup="Troubleshooting">.*?</button>(.*?)</div>\s*</div>',
                    ops, re.S)
    assert sub, "the Troubleshooting subgroup rendered no body"
    labels = _labels(sub.group(1))
    for want, href in PAGES.items():
        assert want in labels, f"{want} is not under Troubleshooting"
        assert f'href="{href}"' in sub.group(1), f"{want} does not point at {href}"


def test_operations_keeps_the_entries_it_already_had(app, client):
    """The subgroup is an addition, not a replacement. A nested <div> closed one
    level too early swallows the siblings below it and nothing raises."""
    login(client, admin_user_id(app), product="fortiweb")
    labels = _labels(_group(_sidebar(client, "fortiweb"), "Operations"))
    for want in ("Device Backups", "Log Collection", "Import Backup"):
        assert want in labels, f"{want} fell out of Operations"


def test_fleet_no_longer_lists_them_in_this_adom(app, client):
    """Half a move is worse than none: two live copies of one page in one
    sidebar, and the next edit updates whichever the author happened to find."""
    login(client, admin_user_id(app), product="fortiweb")
    fleet = _group(_sidebar(client, "fortiweb"), "Fleet")
    assert fleet, "no Fleet group in the FortiWeb sidebar"
    labels = _labels(fleet)
    assert "Search" in labels, "the Fleet slice is empty — the guard below proves nothing"
    for gone in PAGES:
        assert gone not in labels, f"{gone} is still in the FortiWeb Fleet menu"


# ── the Global ADOM is untouched ────────────────────────────────────────────
def test_global_keeps_both_under_fleet(app, client):
    """The same four lines exist in both branches of base.html; an edit aimed at
    FortiWeb strikes Global just as easily. Global has no Operations group."""
    login(client, admin_user_id(app), product="global")
    html = _sidebar(client, "global")
    # Global's fleet list is a nav CONTEXT, not a collapsible group.
    m = re.search(r'data-nav-context="Global">.*?(?=data-nav-group=)', html, re.S)
    assert m, "no Global context block in the Global sidebar"
    labels = _labels(m.group(0))
    assert "DNS Lookup" in labels, "the Global slice is empty — the guard below proves nothing"
    for want in PAGES:
        assert want in labels, f"{want} was removed from the Global menu"


def test_global_has_no_operations_group(app, client):
    """States the premise the move rests on. If Global ever grows one, this
    fails and the decision gets re-made deliberately instead of by drift."""
    login(client, admin_user_id(app), product="global")
    assert _group(_sidebar(client, "global"), "Operations") is None


# ── the group opens itself on the pages it now owns ─────────────────────────
@pytest.mark.parametrize("path", sorted(PAGES.values()))
def test_operations_and_the_subgroup_are_open_on_their_own_pages(app, client, path):
    login(client, admin_user_id(app), product="fortiweb")
    html = _sidebar(client, "fortiweb", path)
    ops = _group(html, "Operations")
    assert ops.startswith('<div class="fw-nav-group open"'), \
        f"Operations is collapsed while {path} is open"
    assert '<div class="fw-nav-subgroup open" data-nav-subgroup="Troubleshooting">' in ops, \
        f"the Troubleshooting subgroup is collapsed while {path} is open"


@pytest.mark.parametrize("path", sorted(PAGES.values()))
def test_fleet_does_not_open_for_them_any_more(app, client, path):
    """It opened for these two because it used to own them. Left behind, it
    expands a group that no longer contains the page you are on."""
    login(client, admin_user_id(app), product="fortiweb")
    fleet = _group(_sidebar(client, "fortiweb", path), "Fleet")
    assert not fleet.startswith('<div class="fw-nav-group open"'), \
        f"Fleet still auto-opens on {path}"


# ── the links resolve (a menu entry that bounces is a dead one) ─────────────
@pytest.mark.parametrize("path", sorted(PAGES.values()))
def test_both_pages_answer_in_the_fortiweb_adom(app, client, path):
    login(client, admin_user_id(app), product="fortiweb")
    r = client.get(path + "?_adom=fortiweb", follow_redirects=False)
    assert r.status_code == 200, \
        f"fortiweb bounced off {path} ({r.status_code} -> {r.headers.get('Location')})"
