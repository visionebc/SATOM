"""The Admin Console menu: a lateral list, grouped by theme, every group
collapsible.

Nothing here *fails* when it rots. A pane whose menu entry was never added is
simply unreachable — the section exists, answers, keeps its state, and no
operator can get to it. A menu entry whose pane was deleted is worse: it looks
like a section and opens nothing. Both survive a green suite and a manual
click-through of the entries you happen to remember, which is exactly how the
horizontal strip that preceded this menu ended up with a ``<li>`` holding two
buttons.

So the guards below assert the *pairing* between the menu and the panes, and
they read the RENDERED page rather than the template text: an assertion on
template source matches the comment that explains it (this repo has collected
eleven of those), and it cannot see what a permission check removed.
"""
from __future__ import annotations

import re

from tests.conftest import admin_user_id, login, make_user, profile_id

# The menu is the <aside> alone. Slicing at the main column instead would drag
# in the product's OWN sidebar (base.html) and the <head>: the chrome guard
# below then trips on a colour that belongs to the fleet navigation, and the
# pairing guards would count entries that are not on this page's menu.
ASIDE_OPEN = '<aside class="nav fw-settings-nav"'
MAIN = '<div class="fw-settings-main">'

TARGET = re.compile(r'data-bs-target="#(tab-[a-z-]+)"')
PANE = re.compile(r'class="tab-pane[^"]*"\s+id="(tab-[a-z-]+)"')
GROUP = re.compile(r'data-set-group="([a-z-]+)"')


def _page(client):
    html = client.get("/settings/").get_data(as_text=True)
    assert MAIN in html, "the settings layout no longer splits menu from panes"
    assert ASIDE_OPEN in html, "the lateral menu is gone"
    nav = html.split(ASIDE_OPEN, 1)[1].split("</aside>", 1)[0]
    panes = html.split(MAIN, 1)[1]
    assert MAIN not in nav, "the aside was never closed — the slice ran into the panes"
    return html, nav, panes


def _nav_targets(nav):
    return TARGET.findall(nav)


def _groups(nav):
    """[(key, [target, ...]), ...] in render order."""
    out = []
    chunks = nav.split('data-set-group="')[1:]
    for chunk in chunks:
        key = chunk.split('"', 1)[0]
        out.append((key, TARGET.findall(chunk)))
    return out


# ------------------------------------------------------------- menu ↔ panes --

def test_every_pane_an_admin_can_open_has_exactly_one_menu_entry(app, client):
    login(client, admin_user_id(app))
    html, nav, _ = _page(client)
    targets = _nav_targets(nav)
    panes = PANE.findall(html)

    assert set(targets) == set(panes), (
        "menu entries with no pane: %s / panes with no menu entry: %s"
        % (sorted(set(targets) - set(panes)), sorted(set(panes) - set(targets)))
    )
    dupes = sorted(t for t in set(targets) if targets.count(t) > 1)
    assert not dupes, "listed twice in the menu: %s" % dupes
    # Guards the guard: a split that swallowed the menu would make the two
    # sets trivially equal (both empty).
    assert len(targets) >= 20, "only %d menu entries — the menu was truncated" % len(targets)


def test_every_menu_entry_belongs_to_a_group(app, client):
    """An entry rendered outside every group is invisible: the groups are the
    only thing that gets drawn."""
    login(client, admin_user_id(app))
    _, nav, _ = _page(client)
    grouped = [t for _key, ts in _groups(nav) for t in ts]
    assert sorted(grouped) == sorted(_nav_targets(nav))


def test_no_group_is_empty(app, client):
    login(client, admin_user_id(app))
    _, nav, _ = _page(client)
    empty = [k for k, ts in _groups(nav) if not ts]
    assert not empty, "groups promising a section they do not have: %s" % empty


# ------------------------------------------------------------- collapsible --

def test_every_group_has_a_toggle_and_a_body(app, client):
    login(client, admin_user_id(app))
    _, nav, _ = _page(client)
    keys = [k for k, _ts in _groups(nav)]
    assert keys, "no groups rendered at all"
    for key in keys:
        assert 'data-set-toggle="%s"' % key in nav, "%s cannot be collapsed" % key
    assert nav.count("fw-set-nav-body") == len(keys)
    assert nav.count('aria-expanded="true"') == len(keys)


def test_the_menu_opens_expanded(app, client):
    """The default has to be the state an empty store produces, and the store
    holds the CLOSED groups (see the script in settings/index.html). Rendering
    groups closed server-side would collapse the console for every operator who
    has never touched it, and no click would be recorded to undo it."""
    login(client, admin_user_id(app))
    _, nav, _ = _page(client)
    assert nav.count("fw-set-nav-group open") == len(_groups(nav))


def test_the_group_holding_the_selected_section_is_marked(app, client):
    """Exactly one entry is selected on load and its group is identifiable, so
    the restore step can refuse to collapse the group the selection is in."""
    login(client, admin_user_id(app))
    _, nav, _ = _page(client)
    assert nav.count('class="nav-link active"') == 1
    assert nav.count("data-set-anchor") == 1
    anchor = nav.split("data-set-anchor", 1)[0].split('data-set-group="')[-1].split('"')[0]
    holder = dict(_groups(nav))[anchor]
    active = nav.split('class="nav-link active"', 1)[1].split('data-bs-target="#', 1)[1].split('"')[0]
    assert active in holder, "%s is selected but the anchor is on group %r" % (active, anchor)


# -------------------------------------------------------------- identifiers --

def test_the_targets_are_identifiers_and_are_never_translated(app, client):
    """The panes, the in-page links (``…#tab-auth``), the URL-hash restore and
    tests/test_theme.py all key off the target. Translating one silently
    detaches the menu entry from its section in that language only — the shape
    of the sidebar's ``data-nav-group`` regression (safeguards §68).

    Asserted by rendering the same page twice in two languages: a grep for
    ``_(`` in the template would also match the comment forbidding it.
    """
    uid = admin_user_id(app)
    login(client, uid)
    _, en, _ = _page(client)

    from app.services import user_settings_store as ustore
    with app.app_context():
        ustore.save_language(uid, "es")
    try:
        _, es, _ = _page(client)
    finally:
        with app.app_context():
            ustore.save_language(uid, "")

    assert _nav_targets(es) == _nav_targets(en)
    assert [k for k, _ in _groups(es)] == [k for k, _ in _groups(en)]
    # …and the labels DID move, or the comparison above proves nothing.
    assert es != en, "the page is byte-identical in Spanish — the locale never changed"


# ------------------------------------------------------------- permissions --

def test_a_non_admin_gets_only_their_own_account_group(app, client):
    """The menu is built from one list; a group that forgets its admin flag
    hands a read-only user a door to the whole console."""
    uid = make_user(app, "navreader", role="readonly",
                    profile_id=profile_id(app, "readonly"))
    login(client, uid)
    _, nav, _ = _page(client)
    assert [k for k, _ts in _groups(nav)] == ["account"]
    assert sorted(_nav_targets(nav)) == ["tab-password", "tab-security"]
    assert nav.count('class="nav-link active"') == 1


# ------------------------------------------------------------------ chrome --

def test_the_menu_uses_the_light_product_chrome(app, client):
    """SATOM has one theme. Dark glass from the fleet standard renders as a grey
    slab on this page — it has happened here before (safeguards §9m)."""
    login(client, admin_user_id(app))
    _, nav, _ = _page(client)
    for literal in ("#080d1a", "rgba(30,41,59", "backdrop-filter", "#0f172a", "#8b5cf6"):
        assert literal not in nav, literal
