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

import io
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
    assert nav.count('aria-expanded="false"') == len(keys)


def test_the_menu_starts_collapsed(app, client):
    """The default has to be the state an EMPTY store produces, and the store
    holds the OPEN groups (see the script in settings/index.html). The two have
    to be decided together: a server that renders groups open while the script
    treats an empty store as "nothing open" gives every untouched operator a
    menu that expands on first paint and folds a frame later.

    Asserted on the rendered aside, not on the template: the ``open`` class is
    also written by the script, and the point here is what arrives BEFORE any
    script runs."""
    login(client, admin_user_id(app))
    _, nav, _ = _page(client)
    assert _groups(nav), "no groups rendered at all"
    assert "fw-set-nav-group open" not in nav, \
        "a group is expanded server-side — the empty-store default is collapsed"


def test_the_store_key_moved_with_its_meaning(app, client):
    """The key is the contract. The previous key held the CLOSED groups; this
    one holds the OPEN ones. Reading a set saved under the old name would open
    exactly the groups an operator had chosen to collapse — the same inversion
    the probe-card store hit (safeguards §9j), which is why that one was renamed
    too. Nothing fails when this rots: the menu just restores the complement."""
    login(client, admin_user_id(app))
    html, _, _ = _page(client)
    assert "satom.settingsnav.open.v1" in html, "the open-set store key is gone"
    reads = html.split("satom.settingsnav.closed.v1")
    assert len(reads) <= 2, "the retired key is used more than once"
    if len(reads) == 2:
        # It may appear ONLY to be dropped, never to be read.
        assert "removeItem" in reads[0][-160:] or "removeItem" in reads[1][:160], \
            "the retired closed-set key is still being read"


def test_the_group_holding_the_selected_section_is_marked(app, client):
    """Exactly one entry is selected on load and its group is identifiable.
    The menu starts collapsed, so this marker is the only thing on the page
    that says WHERE the visible pane lives; a second marker, or none, and the
    statement stops being true of anything."""
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


# ------------------------------------------------------------ pane columns --
# These read the stylesheet, because there is no rendered artefact to read: the
# panes carry no layout class of their own. The source is stripped of comments
# FIRST — every assertion below has a comment beside the rule it protects that
# repeats its own words, and this repo has collected eleven guards that passed
# by matching their own explanation.

import os

CSS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "app", "static", "css", "fortiweb.css")
PANE_SEL = ".fw-settings-main .tab-content > .tab-pane.active"


def _css_rules():
    """[(selector, body), ...] with comments removed."""
    src = io.open(CSS_PATH, encoding="utf-8").read()
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    out = []
    for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", src):
        sel = " ".join(sel.split())
        if sel.startswith("@"):
            continue
        out.append((sel, " ".join(body.split())))
    return out


def _decls(match):
    """Merged body of every rule whose selector list contains `match`."""
    got = []
    for sel, body in _css_rules():
        if any(part.strip() == match for part in sel.split(",")):
            got.append(body)
    return got


def test_the_pane_lays_its_blocks_out_in_one_column():
    """The operator asked for one column: the blocks of a pane stack, full
    width, in the order they are written."""
    bodies = _decls(PANE_SEL)
    assert bodies, "no rule lays the active pane out at all"
    grid = [b for b in bodies if "display: grid" in b]
    assert grid, "the pane is not a grid"
    assert any("grid-template-columns: minmax(0, 1fr)" in b for b in grid), \
        "the pane grid is not a single column"


def test_nothing_puts_the_panes_back_into_two_columns():
    """This is the guard that carries the request, and it has to cover BOTH
    places a pane can split: the pane grid itself, and a top-level Bootstrap
    row whose columns sit side by side without the pane grid having any say.
    A second column reintroduced in either one looks identical to the operator
    and would read as 'unchanged' in a diff that only touched the other."""
    for sel, body in _css_rules():
        if PANE_SEL not in sel:
            continue
        assert "repeat(2," not in body, \
            "%s puts the pane back into two columns" % sel
        for half in ("width: 50%", "width: 49", "flex: 0 0 50%", "grid-column: span 1 / span 1"):
            assert half not in body, \
                "%s halves a top-level block: %s" % (sel, half)


def test_only_the_active_pane_becomes_a_grid():
    """Bootstrap hides the other 23 panes with `display:none` on `.tab-pane`.
    A grid rule that drops `.active` outranks that and paints every section of
    the console at once, stacked — and the page still 'works', which is how it
    would survive review."""
    for sel, body in _css_rules():
        if "display: grid" not in body:
            continue
        for part in sel.split(","):
            part = part.strip()
            if ".tab-pane" in part:
                assert ".tab-pane.active" in part, \
                    "%s makes inactive panes visible" % part


def _stacking_rules():
    return [(sel, body) for sel, body in _css_rules()
            if PANE_SEL in sel and "col-" in sel and "width: 100%" in body]


def test_the_bootstrap_columns_stack_at_every_depth():
    """A pane splits in two WITHOUT the pane grid having any say: `col-lg-7`
    beside `col-lg-5` at the top level, and a `row g-4` inside a card body
    laying two tables abreast. Both read as two columns to the operator, so a
    rule that only reaches the top level leaves half the request undone — and
    the screenshot still shows two columns."""
    rules = _stacking_rules()
    assert rules, "nothing stacks the Bootstrap columns inside the panes"
    descendant = []
    for sel, body in rules:
        if "max-width: 100%" not in body:
            continue
        for part in sel.split(","):
            part = part.strip()
            if ".tab-pane.active" not in part:
                continue
            tail = part.split(".tab-pane.active", 1)[1]
            if ">" not in tail:
                descendant.append(part)
    assert descendant, \
        "the stacking only reaches direct children — nested grids still split"


def test_the_inline_col_auto_is_left_alone():
    """`col-auto` means 'size to the content': it is how this page writes an
    inline toolbar and the button beside a field. Stretched to the full width
    it does not give one column, it gives a vertical stack of buttons — which
    is a worse layout than the one being fixed, arrived at by being literal."""
    rules = _stacking_rules()
    assert rules, "nothing stacks the Bootstrap columns inside the panes"
    assert all("col-auto" in sel for sel, _ in rules), \
        "a stacking rule swallows col-auto and stacks the inline toolbars"


def test_a_long_badge_wraps_instead_of_leaving_the_card():
    """Bootstrap's `.badge` is `white-space: nowrap`. The DNS provider card's
    `missing: A, B, C, D, E` ran past the card — a truncated list of
    environment variables, with no scrollbar to say so. One column is wider
    than two, but a card is still narrower than that run, so the rule stays:
    it was never the column count that caused it."""
    bodies = _decls("%s .badge" % PANE_SEL)
    assert bodies, "nothing lets a long badge wrap inside the console panes"
    assert any("white-space: normal" in b for b in bodies), \
        "the badge still cannot wrap"
