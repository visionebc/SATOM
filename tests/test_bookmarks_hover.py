"""Guards for the ROW HOVER wash in the bookmarks panel.

Pointing at a row lights it in the reader's own banner colour instead of the
neutral grey it used to take. Four things can go wrong, and every one of them
is invisible from this side of the screen:

*   **The row can drown the chip.** The device-type chip paints its own rgba
    OVER the row it sits in. Give the row the chip's alpha and the two land at
    the same weight -- so the chip you are pointing at is the one chip that
    stops reading as a chip. The alphas are therefore ordered, not shared.

*   **The drop target can vanish while you aim at it.** During a drag the
    pointer IS over the row, so ``:hover`` and ``.bm-dragover`` always apply
    together, at equal specificity. Source order is the only thing deciding
    which one the operator sees, and it has to be the drop target.

*   **The fallback can be defeated by an empty value.** ``var(--x, fallback)``
    takes the fallback when the property is *not set* -- not when it is set to
    nothing. An empty custom property is a valid declared value, so a row
    would simply stop answering the pointer with no error anywhere.

*   **The wash can reach the text.** Same defect this console shipped in its
    status pills: legible-looking markup at ~1.4:1.

Nothing here asserts against the page as a whole. The panel draws a marked
device twice -- once under its bookmark row, once under the inventory lens --
and a whole-body substring check answers from whichever copy is healthy.
"""
from __future__ import annotations

import os
import re

from app.models import UserSetting
from app.services import bookmarks as bk
from app.services import user_settings_store as ustore

from tests.conftest import admin_user_id, login, make_user

CSS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "app/static/css/fortiweb.css")


# --- helpers ---------------------------------------------------------------

def _panel(client):
    r = client.get("/bookmarks/panel")
    assert r.status_code == 200
    return r.get_data(as_text=True)


def _tree_style(body):
    m = re.search(r'class="bm-tree"[^>]*style="([^"]*)"', body)
    assert m, "the tree carries no style attribute"
    return m.group(1)


def _alpha(rgba):
    return float(rgba.rsplit(",", 1)[1].strip(" )"))


def _css():
    with open(CSS_PATH, encoding="utf-8") as fh:
        return fh.read()


def _strip_comments(text):
    """Comments have to go before any assertion runs over a block.

    A guard that forbids a token tends to be explained by a comment naming
    that exact token, and then the guard fails against a correct stylesheet.
    """
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def _rule(css, selector):
    """The declaration block of *selector*, comments removed."""
    m = re.search(re.escape(selector) + r"\s*\{(.*?)\}", css, re.S)
    assert m, "rule %r is gone" % selector
    return _strip_comments(m.group(1))


# --- the colour ------------------------------------------------------------

def test_the_reader_tint_carries_a_hover_wash(session):
    got = bk.reader_tint(1, "fortiweb")
    assert "hover" in got, "the row has no colour to light up with"
    assert got["hover"].startswith("rgba("), got["hover"]


def test_the_row_wash_is_lighter_than_the_chip_that_sits_on_it(session):
    """The chip paints over the row. Equal alphas flatten the chip into its
    own row at exactly the moment the reader is pointing at it."""
    got = bk.reader_tint(1, "fortiweb")
    assert _alpha(got["hover"]) < _alpha(got["fill"]), got


def test_the_row_wash_is_not_invisible(session):
    """A hover nobody can see is the same as no hover, and it would replace a
    grey that WAS visible."""
    assert _alpha(bk.reader_tint(1, "fortiweb")["hover"]) >= 0.03


def test_the_row_and_the_chip_are_the_same_colour(app, session):
    """One banner, one hue. A row lit in a different colour from the chip it
    contains reads as two unrelated states rather than one row."""
    uid = make_user(app, "hov_hue", "operator")
    with app.app_context():
        UserSetting.set(uid, ustore.K_BANNER_PREFIX + "fortiweb", "ember")
        got = bk.reader_tint(uid, "fortiweb")
    channels = lambda v: v.rsplit(",", 1)[0]          # noqa: E731
    assert channels(got["hover"]) == channels(got["fill"])
    assert got["hover"].startswith("rgba(192, 57, 43,")


def test_two_readers_with_different_banners_light_rows_differently(
        app, session):
    a = make_user(app, "hov_a", "operator")
    b = make_user(app, "hov_b", "operator")
    with app.app_context():
        UserSetting.set(a, ustore.K_BANNER_PREFIX + "fortiweb", "ember")
        UserSetting.set(b, ustore.K_BANNER_PREFIX + "fortiweb", "emerald")
        ha = bk.reader_tint(a, "fortiweb")["hover"]
        hb = bk.reader_tint(b, "fortiweb")["hover"]
    assert ha != hb, "the banner is a PERSONAL setting"


def test_a_reader_who_never_chose_a_banner_still_lights_rows(app, session):
    uid = make_user(app, "hov_none", "operator")
    with app.app_context():
        got = bk.reader_tint(uid, "fortiweb")["hover"]
    assert got.startswith("rgba(")


def test_a_broken_settings_store_still_yields_a_colour(app, session,
                                                       monkeypatch):
    """The rail is drawn on EVERY page. A store that raises must cost the
    panel its colour, never its rows."""
    def _boom(*a, **kw):
        raise RuntimeError("store down")
    monkeypatch.setattr(ustore, "banner_bg", _boom)
    got = bk.reader_tint(1, "fortiweb")["hover"]
    assert got.startswith("rgba("), got


def test_the_hover_alpha_is_named_not_borrowed_from_the_chip():
    """Two numbers with one name is how the chip drags the row along on the
    day somebody retunes the chip alone."""
    assert isinstance(bk.ROW_HOVER_ALPHA, float)
    assert 0 < bk.ROW_HOVER_ALPHA < 0.08


# --- what reaches the page -------------------------------------------------

def test_the_panel_ships_the_hover_wash_as_a_custom_property(
        app, client, session):
    login(client, admin_user_id(app))
    style = _tree_style(_panel(client))
    assert "--bm-row-hover: rgba(" in style, style


def test_the_shipped_property_is_never_empty(app, client, session):
    """``var(--x, fallback)`` does NOT fall back when the property is set to
    nothing -- an empty value is a valid declared value. A blank here would
    take hover off the rows with nothing to show for it."""
    login(client, admin_user_id(app))
    style = _tree_style(_panel(client))
    m = re.search(r"--bm-row-hover:\s*([^;\"]*)", style)
    assert m and m.group(1).strip(), style


def test_the_page_ships_the_SAME_colour_the_service_computed(
        app, client, session):
    """The service and the page must not each own a copy of this decision."""
    uid = make_user(app, "hov_same", "operator")
    with app.app_context():
        UserSetting.set(uid, ustore.K_BANNER_PREFIX + "fortiweb", "emerald")
        want = bk.reader_tint(uid, "fortiweb")["hover"]
    login(client, uid)
    assert "--bm-row-hover: %s" % want in _tree_style(_panel(client))


def test_the_colour_travels_as_a_custom_property_not_per_row(
        app, client, session):
    """One element carries the colour. A style= on every row is what stops
    working the day style-src-attr drops unsafe-inline -- and the sibling
    guard on .bm-row inline styles would start passing for the wrong reason."""
    login(client, admin_user_id(app))
    body = _panel(client)
    for m in re.finditer(r'<div class="bm-row[^"]*"([^>]*)>', body):
        assert "style=" not in m.group(1), m.group(0)


# --- the stylesheet --------------------------------------------------------

def test_the_hover_rule_reads_the_property_with_a_fallback():
    """A row fragment rendered outside the tree inherits no colour. Without a
    fallback it would answer the pointer with nothing at all."""
    block = _rule(_css(), ".bm-row:hover, .bm-row:focus-within")
    assert re.search(r"var\(\s*--bm-row-hover\s*,\s*var\(--fw-surface-alt\)\s*\)",
                     block), block


def test_the_hover_rule_paints_the_BACKGROUND_only():
    """A row lit by recolouring its text is a row you cannot read."""
    block = _rule(_css(), ".bm-row:hover, .bm-row:focus-within")
    assert "background:" in block
    assert not re.search(r"(^|[;\s])color\s*:", block), block


def test_a_focused_row_lights_up_like_a_pointed_one():
    """This row already treats a focused descendant as equivalent to hover for
    .bm-actions; the buttons must not appear on an unlit row."""
    css = _strip_comments(_css())
    assert ".bm-row:focus-within" in css
    m = re.search(r"\.bm-row:hover[^{]*\{[^}]*\}", css)
    assert ":focus-within" in m.group(0), m.group(0)


def test_the_drop_target_still_wins_while_the_pointer_is_over_it():
    """Dragging means hovering. Both rules are (0,2,0), so the LATER one is
    what the operator sees -- and it has to be the dashed drop outline, not a
    wash that hides where the row is about to land."""
    css = _strip_comments(_css())
    hover = css.index(".bm-row:hover")
    drag = css.index(".bm-row.bm-dragover")
    assert drag > hover, "hover would paint over the drop target"


def test_the_chip_still_paints_over_the_row():
    """The chip's own wash is what keeps it distinct from a lit row."""
    block = _rule(_css(), ".bm-grp .bm-name.bm-type")
    assert "--bm-type-fill" in block, block


def test_the_hover_wash_is_declared_once():
    """Two authors for one visual rule is how the chrome of this console
    drifted before. A second .bm-row hover background would silently win by
    source order."""
    css = _strip_comments(_css())
    hits = re.findall(r"\.bm-row:hover[^{,]*[,{]", css)
    assert len(hits) == 2, hits          # the wash, and the .bm-actions reveal
