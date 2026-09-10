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


# ------------------------------------------------------------ group order --

def _group_chunk(nav, key):
    """The rendered slice of ONE group, ending where the next group opens."""
    parts = nav.split('data-set-group="%s"' % key, 1)
    assert len(parts) == 2, "there is no %r group in the menu" % key
    return parts[1].split('data-set-group="', 1)[0]


def test_sentinel_is_a_group_of_its_own(app, client):
    """Sentinel left Monitoring & Alerts.

    It is not one knob beside the SMTP settings: it is a pipeline with its own
    incidents console and its own architecture. Filed as a single entry under
    an unrelated group, two of its three surfaces had no menu entry at all —
    reachable only from a button inside the third.
    """
    login(client, admin_user_id(app))
    _, nav, _ = _page(client)
    groups = dict(_groups(nav))
    assert "sentinel" in groups, "Sentinel is not a group of its own"
    assert groups["sentinel"] == SN_ENTRIES, groups["sentinel"]
    assert "tab-sentinel" not in groups.get("monitoring", []), \
        "Sentinel is still filed under Monitoring & Alerts"


#: The six entries, in the order the menu draws them: the four CONFIGURATION
#: surfaces, then the reference document, then the live console. Asserted as a
#: LIST because here the position is part of the answer — Context and Response
#: policy were added to this group precisely so they would stop being reachable
#: only from a button inside the console, and filing them after it would
#: recreate that reading order in the menu.
#:
#: Border blocklist (1.19.0) is last of the four configuration surfaces
#: because it is the only one READ by something outside this product: a
#: FortiGate fetches it. It is configuration, not a live view, so it belongs
#: before the document and not next to the console.
SN_ENTRIES = ["tab-sentinel", "tab-sentinel-context", "tab-sentinel-policy",
              "tab-sentinel-blocklist", "tab-sentinel-docs",
              "tab-sentinel-console"]


def test_the_sentinel_group_offers_all_six_surfaces(app, client):
    """Settings, Context, Response policy, Border blocklist, Architecture,
    Incidents console.

    They were links to /sentinel/... until the operator asked for them to be
    shown "there, in that screen, like the Sentinel settings". Context and
    Response policy were the worst of the set: neither had a menu entry at
    all, and the only way to either was a button drawn at the top of the
    incidents console — so removing those buttons without adding these entries
    would have removed the function, not a duplicate.
    """
    login(client, admin_user_id(app))
    _, nav, _ = _page(client)
    chunk = _group_chunk(nav, "sentinel")
    for target in SN_ENTRIES:
        assert 'data-bs-target="#%s"' % target in chunk, "no %s entry" % target
    with app.test_request_context():
        from flask import url_for
        leaving = (url_for("sentinel.docs"), url_for("sentinel.index"),
                   url_for("sentinel.context"), url_for("sentinel.policies"))
    for href in leaving:
        assert 'href="%s"' % href not in chunk, (
            "the Sentinel menu still navigates to %s instead of switching a "
            "pane" % href
        )


def test_no_sentinel_entry_leaves_the_console(app, client):
    """The leaving arrow marks a row that replaces the whole page.

    None of Sentinel's five rows does that any more, so none may carry it: an
    arrow on a row that only swaps a pane warns of a page change that does not
    happen, and an operator who trusts it saves their edits first for nothing.
    The branch that draws it stays in the menu for the next entry that really
    does leave — this asserts only that Sentinel is not one.
    """
    login(client, admin_user_id(app))
    _, nav, _ = _page(client)
    chunk = _group_chunk(nav, "sentinel")
    assert chunk.count("fw-set-nav-out") == 0, \
        "a Sentinel entry is still marked as leaving the console"


def test_scout_is_the_last_group(app, client):
    """Scout at the bottom, below Sentinel.

    This guard read "sentinel is last", and it was correct until
    2026-09-10, when the operator asked for Scout's configuration to sit
    BELOW Sentinel. Renamed rather than deleted: the property worth
    protecting is that the bottom of this menu is a decision, not wherever
    the newest group happened to land.
    """
    login(client, admin_user_id(app))
    _, nav, _ = _page(client)
    keys = [k for k, _ts in _groups(nav)]
    assert keys[-1] == "scout", \
        "Scout is not the last group — the order is %s" % keys


def test_monitoring_and_alerts_sits_just_above_sentinel(app, client):
    """It was moved to the bottom for the same reason and kept that position
    when Sentinel went below it, and again when Scout went below Sentinel:
    alert plumbing is configured once and then left alone, unlike the
    groups above it. Asserted as a THREE-key tail rather than a two-key
    one, so a group inserted between them cannot pass by landing last."""
    login(client, admin_user_id(app))
    _, nav, _ = _page(client)
    keys = [k for k, _ts in _groups(nav)]
    assert keys[-3:] == ["monitoring", "sentinel", "scout"], \
        "the configure-once groups are not at the bottom — order is %s" % keys


# ------------------------------------------------------- one menu, one file --

def test_the_menu_is_defined_in_exactly_one_template(app):
    """The menu is included, never copied.

    Nothing fails when a second copy appears: both render, and the operator
    gets a different menu depending on which URL they arrived by. That is how
    the horizontal strip this menu replaced ended up with two entries for one
    pane. The literal therefore lives in ONE file and every surface includes
    it.
    """
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1] / "app" / "templates"
    holders = sorted(p.relative_to(root).as_posix()
                     for p in root.rglob("*.html")
                     if "set nav_groups" in p.read_text())
    assert holders == ["settings/_nav.html"], (
        "the menu literal is defined in %s — it must live only in "
        "settings/_nav.html" % holders
    )
    includers = sorted(p.relative_to(root).as_posix()
                       for p in root.rglob("*.html")
                       if 'include "settings/_nav.html"' in p.read_text())
    assert includers == ["settings/index.html", "settings/sentinel.html"], includers


def test_a_standalone_settings_page_keeps_the_submenu(app, client):
    """/settings/sentinel is reached by deep link and by the save redirect.

    It used to render bare: the whole Admin Console submenu vanished, and the
    only way back was the browser's Back button. Nothing failed — the page was
    correct, it just stopped being part of the console.
    """
    login(client, admin_user_id(app))
    html = client.get("/settings/sentinel").get_data(as_text=True)
    assert ASIDE_OPEN in html, "the standalone Sentinel page has no submenu"
    nav = html.split(ASIDE_OPEN, 1)[1].split("</aside>", 1)[0]
    console_keys = [k for k, _ts in _groups(_page(client)[1])]
    assert [k for k, _ts in _groups(nav)] == console_keys, \
        "the standalone page draws a DIFFERENT menu from the console"


def test_the_standalone_menu_navigates_instead_of_switching_panes(app, client):
    """There are no panes on that page. A tab button there is a row that
    highlights on hover and then does nothing — a dead control the menu cannot
    report."""
    login(client, admin_user_id(app))
    html = client.get("/settings/sentinel").get_data(as_text=True)
    nav = html.split(ASIDE_OPEN, 1)[1].split("</aside>", 1)[0]
    assert 'data-bs-toggle="tab"' not in nav, \
        "the standalone menu still renders tab buttons for panes that are not there"
    assert 'href="/settings/#tab-users"' in nav, \
        "the standalone menu does not link back into the console"
    assert nav.count('class="nav-link active"') == 1, \
        "the standalone page does not mark exactly one entry as the one shown"
    assert '#tab-sentinel"' in nav.split('class="nav-link active"', 1)[1][:200], \
        "the entry marked active is not Sentinel"


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


# --------------------------------------------------------- the accordion --
#
# The menu holds ONE open group. Nothing fails when that rots: a second group
# simply stays expanded, and the operator scrolls past entries they did not ask
# for — the wall the collapsed default exists to avoid, arrived at one click at
# a time. The script never runs in a Flask test, so these read the RENDERED
# script and assert on its structure.

SCRIPT_HEAD = "(function () {"
SCRIPT_ANCHOR = "var KEY = 'satom.settingsnav.open.v1'"
# The menu script now ships INSIDE settings/_nav.html, so the slice ends at
# that partial's own </script>. Anchoring on whatever line happened to follow
# it in the console page made the slice unbounded the moment the menu moved:
# it then swallowed the whole page's JavaScript and every rule below became a
# statement about unrelated code (one of them promptly failed on a .push() in
# the Sentinel demo lab).
SCRIPT_END = "</script>"


def _strip_comments(code):
    """Drop ``//`` comments, respecting quotes.

    This repo has collected eleven assertions that matched the comment
    explaining the rule they guard. Every rule below names things the comments
    also name (``selectGroup``, ``shown.bs.tab``), so the comments go first.
    Quotes are tracked because the block holds selectors — ``'[data-bs-toggle=
    "tab"]'`` — whose contents have to survive.
    """
    out = []
    for line in code.splitlines():
        quote, cut, i = None, None, 0
        while i < len(line):
            c = line[i]
            if quote:
                if c == "\\":
                    i += 2
                    continue
                if c == quote:
                    quote = None
            elif c in "\"'":
                quote = c
            elif c == "/" and line[i + 1:i + 2] == "/":
                cut = i
                break
            i += 1
        out.append(line if cut is None else line[:cut])
    return "\n".join(out)


def _menu_script(html):
    """The lateral-menu IIFE, comments removed. Loud when it finds nothing:
    a slice that silently comes back empty turns every rule below into a
    statement about the empty string (docs/safeguards.md §68)."""
    at = html.find(SCRIPT_ANCHOR)
    assert at != -1, "the lateral-menu script is gone from the rendered page"
    head = html.rfind(SCRIPT_HEAD, 0, at)
    assert head != -1, "the menu script is no longer wrapped in an IIFE"
    end = html.find(SCRIPT_END, at)
    assert end != -1, "the menu script tag is never closed"
    code = _strip_comments(html[head:end])
    assert code.count("{") == code.count("}"), "the slice does not hold whole blocks"
    return code


def _block(code, opener):
    """The braced body that follows ``opener``, brace-balanced.

    Balanced rather than a fixed window: a window wide enough for the body
    today reaches into the NEXT function tomorrow and reports a rule satisfied
    by code the operator never runs through this path."""
    at = code.find(opener)
    assert at != -1, "%r is not in the menu script" % opener
    start = code.index("{", at)
    depth = 0
    for i in range(start, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[start:i + 1]
    raise AssertionError("%r is never closed" % opener)


def _script(app, client):
    login(client, admin_user_id(app))
    html, _, _ = _page(client)
    return _menu_script(html)


def test_opening_a_group_collapses_every_other_group(app, client):
    """One routine opens a group, and it is the same one that folds the rest.
    Split in two — one that opens, one that folds — and every caller has to
    remember to call both; the caller that forgets is the one that ships."""
    body = _block(_script(app, client), "function selectGroup(")
    assert "allGroups()" in body, "selectGroup no longer looks at the other groups"
    assert re.search(r"!==\s*g\b", body), \
        "nothing in selectGroup separates the chosen group from the rest"
    assert re.search(r"paint\(\s*\w+\s*,\s*false\s*\)", body), \
        "selectGroup opens a group without folding the others — not an accordion"
    assert re.search(r"paint\(\s*g\s*,\s*true\s*\)", body), \
        "selectGroup no longer opens the group it was given"


def test_selecting_a_section_folds_the_other_groups(app, client):
    """The fold has to fire on the ENTRIES, not only on the group headers.
    Selecting a section is how this menu is used; a fold bound to the headers
    alone leaves the previous group expanded for the whole session."""
    handler = _block(_script(app, client), "nav.addEventListener('click'")
    assert 'data-bs-toggle="tab"' in handler, \
        "the click handler no longer recognises a section entry"
    tail = handler.split('data-bs-toggle="tab"', 1)[1]
    assert "selectGroup(" in tail, \
        "a section is selected without folding the other groups"


def test_re_selecting_the_open_section_folds_the_rest_too(app, client):
    """No early return on "already open". Bootstrap does not fire
    ``shown.bs.tab`` when the clicked section is already the active one, and a
    group can be open while ANOTHER one is still expanded from an earlier
    click — the case an early return leaves untouched, which is the case this
    accordion is for."""
    body = _block(_script(app, client), "function selectGroup(")
    assert "contains('open')" not in body, \
        "selectGroup returns early for a group already open — the rest never fold"


def test_a_tab_shown_without_the_menu_folds_the_rest(app, client):
    """The in-page links, the URL-hash restore and the redirect after a save
    activate a section without touching the menu. They go through the same
    routine, or those paths keep the multi-open behaviour that was removed."""
    code = _script(app, client)
    at = code.find("shown.bs.tab")
    assert at != -1, "the menu no longer follows a tab it did not open"
    assert "selectGroup(" in code[at:at + 220], \
        "a tab shown from elsewhere opens its group without folding the others"


def test_the_store_never_holds_more_than_one_group(app, client):
    """The store is the state on the next load. Keep appending to it and the
    menu is an accordion for exactly as long as the page stays open."""
    code = _script(app, client)
    body = _block(code, "function selectGroup(")
    assert re.search(r"write\(\s*\[\s*keyOf\(\s*g\s*\)\s*\]\s*\)", body), \
        "selectGroup does not store its group as the only open one"
    assert ".push(" not in code, \
        "the store is appended to — it holds a set of open groups again"


def test_a_store_from_the_multi_open_version_restores_one_group(app, client):
    """The key did not change, so stores holding SEVERAL groups are already out
    there. Restoring all of them would paint the state this change removes, on
    the first load after it, for the operators who used the menu most."""
    code = _script(app, client)
    parts = code.split("var saved = read();")
    assert len(parts) == 2, "the restore no longer reads the store"
    loop = parts[1].split("nav.addEventListener", 1)[0]
    assert "saved.length - 1" in loop and "i--" in loop, \
        "the restore no longer starts from the most recently opened group"
    assert "break" in loop, "the restore keeps opening groups after the first hit"
    assert "selectGroup(" in loop, \
        "the restore opens a group without folding the rest or rewriting the store"


# ------------------------------------------------- Sentinel's inline panes --

SN_SECTIONS = {
    "tab-sentinel-docs": ("sentinel/_docs_section.html", 'id="diagrams"'),
    "tab-sentinel-console": ("sentinel/_console_section.html",
                             "Behavioural baseline"),
    "tab-sentinel-context": ("sentinel/_context_section.html",
                             "Trusted sources"),
    "tab-sentinel-policy": ("sentinel/_policy_section.html",
                            "Operating mode"),
}


def _post_forms(body):
    """Every POST form in a rendered fragment, as its own string.

    Split on the opening tag and cut at the matching close, so an assertion
    about "this form" cannot be satisfied by an attribute belonging to the
    next one — which is precisely how a count-based check passes while one
    form has lost its redirect.
    """
    out = []
    for chunk in body.split("<form ")[1:]:
        form = chunk.split("</form>", 1)[0]
        if 'method="post"' in form.split(">", 1)[0].lower() or "csrf_token" in form:
            out.append(form)
    return out


def _pane_body(panes, target):
    """The rendered body of ONE pane, ending where the next pane opens.

    Sliced rather than searched whole-page: both sections also exist at their
    own URLs, and this page includes three Sentinel partials, so a whole-page
    search answers "is this pane filled?" with content from a different one.
    """
    parts = panes.split('id="%s">' % target, 1)
    assert len(parts) == 2, "there is no %r pane" % target
    return parts[1].split('<div class="tab-pane', 1)[0]


def test_the_sentinel_panes_render_their_sections_inline(app, client):
    """The operator asked for Architecture and the Incidents console to be
    shown in the Settings screen, the way the Sentinel settings are.

    An empty pane is the failure this catches and the menu cannot: the entry
    is there, it highlights, it switches — and shows nothing. That is exactly
    what a context the view forgot to pass produces, because a missing name in
    Jinja renders as the empty string rather than raising.
    """
    login(client, admin_user_id(app))
    _, _, panes = _page(client)
    for target, (_tpl, marker) in SN_SECTIONS.items():
        body = _pane_body(panes, target)
        assert marker in body, (
            "the %s pane rendered without %r — its section is empty"
            % (target, marker)
        )


def test_each_section_lives_in_one_file_and_is_included_twice(app):
    """One file per section, two surfaces including it.

    A hand-copied second surface is a second place for numbers that are
    generated from live tables to be read wrongly — and nothing fails when the
    copies disagree; the operator simply gets a different answer depending on
    which URL they arrived by.
    """
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1] / "app" / "templates"
    for target, (tpl, _marker) in SN_SECTIONS.items():
        includers = sorted(p.relative_to(root).as_posix()
                           for p in root.rglob("*.html")
                           if 'include "%s"' % tpl in p.read_text())
        assert len(includers) == 2 and "settings/index.html" in includers, (
            "%s is included by %s; it must be the console pane plus its own "
            "standalone page" % (tpl, includers)
        )


def test_the_console_pane_controls_stay_inside_the_console(app, client):
    """Every control the pane draws must keep the operator where they are.

    This is the whole point of rendering the console inline: a filter, a sweep
    or a baseline rebuild that jumps to /sentinel/ takes the Admin Console away
    from under an operator who was told the section lived here. None of the
    three fails when it regresses — each one works perfectly, somewhere else.
    """
    login(client, admin_user_id(app))
    _, _, panes = _page(client)
    body = _pane_body(panes, "tab-sentinel-console")
    assert 'href="/sentinel/?status=' not in body, \
        "the status filter still jumps to the standalone console"
    assert 'href="/settings/?sn_status=' in body, \
        "the status filter does not reload the console it is drawn in"
    assert body.count('name="return_to" value="pane"') == 2, (
        "the sweep and the baseline rebuild do not both come back to the pane"
    )
    # NOT data-bs-toggle="tab": outside the tab list Bootstrap builds no Tab
    # and its own click handler throws, so that variant is the inert button
    # this assertion used to require. See safeguards.md §112.
    assert 'data-fw-pane="#tab-sentinel-policy"' in body, \
        "the Response policy button still loads a page instead of the pane"
    assert 'data-bs-toggle="tab"' not in body, \
        "a tab toggle outside the tab list is inert"


def test_the_console_no_longer_duplicates_two_menu_entries(app, client):
    """Architecture and Context are gone from the console's header.

    The operator asked for them to go, and the reason they could go is that
    both became entries in the Sentinel menu in the same change. That order
    matters: this assertion is only safe next to the one above it, which holds
    that the menu offers all six surfaces. Removed on their own, these two
    buttons were the ONLY way to either page, and Context is not decoration —
    a trusted source is worth -35 points, the largest single weight in the
    scoring table, and without it Sentinel scores an authorised scan exactly
    as it scores an intrusion.
    """
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[1] / "app" / "templates"
           / "sentinel" / "_console_section.html").read_text()
    # Asserted on the SOURCE, and with comments stripped, because the file
    # explains in prose why these two controls left: an assertion that reads
    # the explanation of a rule as a violation of it is the trap this repo has
    # now fallen into nine times.
    from tests.test_csp_nonce import _uncommented
    code = _uncommented(src)
    for gone, what in (("sentinel.docs", "the Architecture button"),
                       ("sentinel.context", "the Context button")):
        assert gone not in code, \
            "%s is still drawn in the incidents console" % what
    login(client, admin_user_id(app))
    _, _, panes = _page(client)
    body = _pane_body(panes, "tab-sentinel-console")
    assert 'href="/sentinel/context"' not in body, \
        "the rendered console still links out to the Context page"


def test_the_standalone_console_still_navigates(app, client):
    """/sentinel/ is the operational page and has no panes.

    Drawing the pane-switching variants there would give the operator buttons
    that highlight and do nothing — the same dead control the standalone
    Settings menu exists to avoid.
    """
    login(client, admin_user_id(app))
    html = client.get("/sentinel/").get_data(as_text=True)
    assert 'data-bs-target="#tab-sentinel-policy"' not in html, \
        "the standalone console draws a tab button for a pane that is not there"
    assert 'data-fw-pane=' not in html, \
        "the standalone console draws a pane-switching button with no pane"
    assert 'href="/sentinel/policies"' in html, "no Response policy link"
    assert 'href="/sentinel/?status=all"' in html, \
        "the standalone console's filter no longer reloads itself"
    assert 'name="return_to" value="page"' in html


SN_PARTIALS = ("sentinel/_context_section.html",
               "sentinel/_policy_section.html",
               "sentinel/_console_section.html")


def test_every_post_form_in_a_shared_section_carries_the_return_marker(app):
    """Asserted on the SOURCE, because most of these forms are drawn per row.

    Delete a trusted source, delete a maintenance window, save a topology row,
    save one action's policy: each exists once per record, so a fixture with
    an empty table renders none of them and a render-only check calls the
    section clean while half its forms have no redirect at all. The operator
    finds out by pressing Remove on a trust entry and landing on a different
    page — a bug that only appears once there is something to remove.
    """
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1] / "app" / "templates"
    from tests.test_csp_nonce import _uncommented
    for rel in SN_PARTIALS:
        src = _uncommented((root / rel).read_text())
        forms = _post_forms(src)
        assert forms, "%s declares no POST form" % rel
        for form in forms:
            assert 'name="return_to"' in form, (
                "a form in %s has no return_to: %s" % (rel, form[:220])
            )


def test_every_sentinel_pane_post_comes_back_to_its_own_pane(app, client):
    """A form inside a pane must return to THAT pane, not to a page.

    Four sections, four anchors, and nothing fails when one of them keeps the
    old redirect: the POST succeeds, the data is saved, and the operator is
    simply somewhere else. Counted per pane rather than page-wide because a
    page-wide count is satisfied by one section carrying all the markers.
    """
    login(client, admin_user_id(app))
    _, _, panes = _page(client)
    for target in ("tab-sentinel-context", "tab-sentinel-policy",
                   "tab-sentinel-console"):
        body = _pane_body(panes, target)
        forms = _post_forms(body)
        assert forms, "%s draws no POST form at all" % target
        # EVERY form, not a count. A floor ("at least five") is satisfied
        # while one form quietly keeps the old redirect, and most of these
        # sections draw a form per ROW, so an exact number would assert
        # something about the fixture's data instead of about the contract.
        for i, form in enumerate(forms):
            assert 'name="return_to" value="pane"' in form, (
                "form %d of %d in %s does not come back to the pane: %s"
                % (i + 1, len(forms), target, form[:200])
            )
        assert 'name="return_to" value="page"' not in body, (
            "%s carries a form that returns to the standalone page" % target
        )


def test_a_pane_post_comes_back_to_the_pane(app):
    """The redirect target is decided by the posted surface, not by the route.

    Asserted on the helper directly: firing the real sweep would reach an
    appliance, which is the one thing this console promises not to do on a
    render.
    """
    from app.views.sentinel import _back_to_console
    with app.test_request_context("/sentinel/run", method="POST",
                                  data={"return_to": "pane"}):
        assert _back_to_console().headers["Location"].endswith(
            "#tab-sentinel-console")
    with app.test_request_context("/sentinel/run", method="POST", data={}):
        assert _back_to_console().headers["Location"].rstrip("/").endswith(
            "/sentinel")
