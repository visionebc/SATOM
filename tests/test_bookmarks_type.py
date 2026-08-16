"""Guards for the DEVICE-TYPE bucket in the bookmarks panel.

Two things are being defended, and each one fails silently in its own way:

*   **The name.** ``kind`` is stored lowercase (``fortiweb``) and the product
    is called **FortiWeb**. Raising only the first letter would give
    "Fortiweb", which is not the name of anything, and ``str.capitalize`` would
    lower-case the rest and mangle a custom kind. The label therefore comes
    from the ADOM registry, and a kind with no registry row keeps every letter
    it was given except the first. Nothing fails when this drifts -- the panel
    simply starts calling a product by a name it does not have.

*   **The colour.** The wash is the READER'S OWN banner, resolved through the
    same store the top bar is painted from, at an alpha low enough to read as
    paper. Two failure modes bracket it: taking the wrong end of a gradient
    (every template collapses to the same near-black anchor) and letting the
    tint reach the TEXT (a pill that says FortiWeb at ~1.4:1, which is the
    defect this console's status pills already shipped once).

And one structural guard that is easy to lose: the node KEY is still built
from the raw stored value. The open/closed set is indexed by that key, so if
the label became the key, renaming a product in the ADOM registry would
collapse the product branch of every user who had it open.

No assertion here matches a substring the template would contain for another
reason: the sibling panel suite lost six guards to exactly that.
"""
from __future__ import annotations

import re

import pytest

from app.extensions import db
from app.models import Appliance, User, UserSetting
from app.services import bookmarks as bk
from app.services import settings_store as store
from app.services import user_settings_store as ustore

from tests.conftest import admin_user_id, login, make_user


# --- helpers ---------------------------------------------------------------

def _appl(app, name, kind="fortiweb", host="192.0.2.13", **kw):
    with app.app_context():
        a = Appliance(name=name, kind=kind, host=host, port=443,
                      username="admin", password_enc="x", verify_ssl=False,
                      **kw)
        db.session.add(a)
        db.session.commit()
        return a.id


def _panel(client):
    r = client.get("/bookmarks/panel")
    assert r.status_code == 200
    return r.get_data(as_text=True)


def _set_lens(app, uid, stack):
    with app.app_context():
        UserSetting.set(uid, bk.LENS_SETTING_KEY, ",".join(stack))


def _group_names(body):
    """(key, rendered name, is_chip) for every group node in the panel."""
    out = []
    for m in re.finditer(
            r'data-bm-node="([^"]+)".*?<span class="bm-name([^"]*)">([^<]*)<',
            body, re.S):
        out.append((m.group(1), m.group(3).strip(), "bm-type" in m.group(2)))
    return out


def _lum(hex_color):
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


# --- the label -------------------------------------------------------------

def test_a_registered_kind_is_written_the_way_the_registry_spells_it(session):
    assert bk.dimension_label("kind", "fortiweb") == "FortiWeb"


def test_the_label_is_not_merely_the_first_letter_raised(session):
    """"Fortiweb" is not the name of any product. This is the whole point of
    going to the registry instead of calling ``.title()`` on the column."""
    assert bk.dimension_label("kind", "fortiweb") != "Fortiweb"
    assert bk.dimension_label("kind", "fortiadc") == "FortiADC"
    assert bk.dimension_label("kind", "fortiadc") != "Fortiadc"


def test_every_kind_in_this_fleet_has_a_registry_name(session):
    for k, expect in (("fortiweb", "FortiWeb"), ("fortiadc", "FortiADC"),
                      ("fortianalyzer", "FortiAnalyzer"),
                      ("fortiauthenticator", "FortiAuthenticator")):
        assert bk.dimension_label("kind", k) == expect


def test_an_unregistered_kind_is_not_labelled_as_the_default_product(session):
    """``get_product`` answers FortiWeb for a key it does not know. Calling it
    without checking first would give every unknown kind a confident wrong
    name rather than an honest raw one."""
    got = bk.dimension_label("kind", "acmebox")
    assert got != "FortiWeb"
    assert got == "Acmebox"


def test_an_unregistered_kind_keeps_the_letters_after_the_first(session):
    """``.capitalize()`` would return "Mybox" and destroy the operator's own
    spelling; only the first character may be touched."""
    assert bk.dimension_label("kind", "myBOX") == "MyBOX"


def test_the_synthetic_buckets_are_left_alone(session):
    for v in (bk.UNCLASSIFIED, bk.NO_SEGMENT, bk.NON_DEVICE):
        assert bk.dimension_label("kind", v) == v


def test_the_synthetic_guard_does_not_ride_on_how_they_are_spelled(
        monkeypatch, session):
    """The sentinel check is provably REDUNDANT today, and kept anyway.

    All three sentinels currently begin with ``(``, a character with no upper
    case, so the fallback path would hand them back unchanged even with the
    check deleted — which is why deleting it survives every assertion above.
    That is an accident of spelling, not a property of the code: respell
    ``(unclassified)`` without its bracket and the check becomes the only
    thing between it and "Unclassified" being rendered as though somebody had
    declared a product by that name. Pinned here rather than approved as an
    equivalent mutant."""
    monkeypatch.setattr(bk, "UNCLASSIFIED", "unclassified")
    assert bk.dimension_label("kind", "unclassified") == "unclassified"
    monkeypatch.setattr(bk, "NO_SEGMENT", "no segment")
    assert bk.dimension_label("kind", "no segment") == "no segment"


def test_only_the_kind_dimension_is_relabelled(session):
    """A zone that happens to be named after a product is a ZONE."""
    assert bk.dimension_label("zone", "fortiweb") == "fortiweb"
    assert bk.dimension_label("department", "netops") == "netops"
    assert bk.dimension_label("tag", "fortiadc") == "fortiadc"


def test_an_empty_value_stays_empty(session):
    assert bk.dimension_label("kind", "") == ""
    assert bk.dimension_label("kind", None) == ""


# --- the colour ------------------------------------------------------------

def test_a_solid_template_tints_from_its_own_colour():
    assert bk.banner_accent("#162940") == "#162940"


def test_a_gradient_tints_from_the_END_of_the_ramp_not_the_anchor():
    """Crimson is #ee3124. Its ramp STARTS at #14233a, a near-black shared in
    spirit by all fourteen gradients -- tinting from there would make Ocean,
    Ember and Emerald indistinguishable."""
    bg = store.BANNER_TEMPLATES["crimson"]["bg"]
    assert bk.banner_accent(bg) == "#ee3124"
    assert bk.banner_accent(bg) != "#14233a"


def test_every_gradient_tints_from_its_bright_end():
    """Property version of the test above, over the whole catalogue: no
    template may tint from a stop darker than the one it starts on."""
    for key, tpl in store.BANNER_TEMPLATES.items():
        stops = re.findall(r"#[0-9a-fA-F]{6}", tpl["bg"])
        if len(stops) < 2:
            continue
        assert _lum(bk.banner_accent(tpl["bg"])) > _lum(stops[0]), key


def test_a_short_hex_is_expanded_before_it_is_split_into_channels():
    assert bk.banner_accent("#0af") == "#00aaff"


def test_a_bg_with_no_colour_in_it_falls_back_instead_of_crashing():
    assert bk.banner_accent("") == bk.BANNER_FALLBACK
    assert bk.banner_accent("var(--fw-topbar-bg)") == bk.BANNER_FALLBACK
    assert bk.banner_accent(None) == bk.BANNER_FALLBACK


def test_the_tint_is_a_translucent_fill_never_a_flat_colour():
    """A chip painted with an opaque brand colour is a dark slab on a white
    panel; the request was for a wash."""
    got = bk.tint("#ee3124", 0.08)
    assert got.startswith("rgba(")
    assert got == "rgba(238, 49, 36, 0.08)"


def test_the_tint_carries_the_channels_of_the_colour_it_was_given():
    assert bk.tint("#0a3f9f", 0.2) == "rgba(10, 63, 159, 0.2)"


def test_the_wash_is_extremely_light_and_the_outline_still_lighter_than_solid(
        session):
    fill = bk.reader_tint(1, "fortiweb")["fill"]
    line = bk.reader_tint(1, "fortiweb")["line"]
    a_fill = float(fill.rsplit(",", 1)[1].strip(" )"))
    a_line = float(line.rsplit(",", 1)[1].strip(" )"))
    assert 0 < a_fill <= 0.12, "the fill must read as paper, not as a slab"
    assert a_fill < a_line < 0.5


def test_the_tint_follows_the_readers_OWN_banner_choice(app, session):
    uid = make_user(app, "tintuser", "operator")
    with app.app_context():
        UserSetting.set(uid, ustore.K_BANNER_PREFIX + "fortiweb", "ember")
        got = bk.reader_tint(uid, "fortiweb")
    # Ember's ramp ends on #c0392b.
    assert got["accent"] == "#c0392b"
    assert got["fill"].startswith("rgba(192, 57, 43,")


def test_two_readers_with_different_banners_get_different_washes(app, session):
    a = make_user(app, "tint_a", "operator")
    b = make_user(app, "tint_b", "operator")
    with app.app_context():
        UserSetting.set(a, ustore.K_BANNER_PREFIX + "fortiweb", "ember")
        UserSetting.set(b, ustore.K_BANNER_PREFIX + "fortiweb", "emerald")
        ta = bk.reader_tint(a, "fortiweb")
        tb = bk.reader_tint(b, "fortiweb")
    assert ta["fill"] != tb["fill"], "the banner is a PERSONAL setting"


def test_a_reader_who_never_chose_a_banner_still_gets_a_colour(app, session):
    uid = make_user(app, "tint_none", "operator")
    with app.app_context():
        got = bk.reader_tint(uid, "fortiweb")
    assert got["fill"].startswith("rgba(")


# --- the panel -------------------------------------------------------------

def test_the_product_bucket_renders_its_registry_name_with_the_chip(
        app, client, session):
    uid = admin_user_id(app)
    _appl(app, "fw-typed", kind="fortiweb", host="192.0.2.13")
    _set_lens(app, uid, ["kind"])
    login(client, uid)
    body = _panel(client)
    hit = [g for g in _group_names(body) if g[1] == "FortiWeb"]
    assert hit, "the product bucket did not render its registry name"
    assert hit[0][2], "the product bucket is not wearing the type chip"


def test_the_node_KEY_is_still_the_raw_stored_value(app, client, session):
    """The open/closed set is indexed by this string. Keying on the label
    would collapse everybody's product branch the day the registry renames a
    product -- punishing readers for a change they never made."""
    uid = admin_user_id(app)
    _appl(app, "fw-key", kind="fortiweb", host="192.0.2.13")
    _set_lens(app, uid, ["kind"])
    login(client, uid)
    keys = [k for k, _n, _c in _group_names(_panel(client))]
    assert any(k.endswith("|fortiweb") for k in keys), keys
    assert not any(k.endswith("|FortiWeb") for k in keys), keys


def test_a_bucket_that_is_not_a_device_type_gets_no_chip(app, client, session):
    """Only the product level is a device type. A zone in a tinted pill would
    read as one."""
    uid = admin_user_id(app)
    _appl(app, "fw-zoned", kind="fortiweb", host="192.0.2.13", zone="dmz")
    _set_lens(app, uid, ["zone", "kind"])
    login(client, uid)
    groups = _group_names(_panel(client))
    zone = [g for g in groups if g[1] == "dmz"]
    assert zone, groups
    assert not zone[0][2], "a zone bucket must not wear the product chip"


def test_the_unclassified_product_bucket_is_not_dressed_as_a_product(
        app, client, session):
    uid = admin_user_id(app)
    _appl(app, "fw-nokind", kind="", host="192.0.2.13")
    _set_lens(app, uid, ["kind"])
    login(client, uid)
    groups = _group_names(_panel(client))
    unc = [g for g in groups if g[1] == bk.UNCLASSIFIED]
    assert unc, groups
    assert not unc[0][2], "(unclassified) is not a product"


def test_device_rows_keep_a_bare_name_class(app, client, session):
    """The sibling suites cut a bookmark row out of the page by
    ``<span class="bm-name">``. Widening that attribute on ITEMS would make
    those guards match nothing and pass in silence."""
    uid = admin_user_id(app)
    _appl(app, "fw-bare", kind="fortiweb", host="192.0.2.13")
    _set_lens(app, uid, ["kind"])
    login(client, uid)
    body = _panel(client)
    assert '<span class="bm-name">fw-bare</span>' in body


def test_the_panel_ships_the_wash_as_custom_properties(app, client, session):
    """One element carries the colour; the stylesheet keeps the rule. A
    ``style=`` on every chip is what stops working the day ``style-src-attr``
    drops ``unsafe-inline``."""
    login(client, admin_user_id(app))
    body = _panel(client)
    m = re.search(r'class="bm-tree"[^>]*style="([^"]+)"', body)
    assert m, "the tree carries no tint"
    assert "--bm-type-fill: rgba(" in m.group(1)
    assert "--bm-type-line: rgba(" in m.group(1)


def test_searching_the_stored_value_still_finds_the_renamed_bucket(
        app, client, session):
    """The operator types what the database holds; the panel shows what the
    registry calls it. Relabelling must not make the bucket unsearchable."""
    uid = admin_user_id(app)
    _appl(app, "fw-search", kind="fortiweb", host="192.0.2.13")
    _set_lens(app, uid, ["kind"])
    login(client, uid)
    r = client.get("/bookmarks/panel?q=fortiweb")
    assert r.status_code == 200
    assert "FortiWeb" in r.get_data(as_text=True)


def test_the_chip_never_paints_the_TEXT_with_the_wash():
    """The stylesheet rule may set a background from the tint; it may not set
    ``color`` from it. A label at 8% alpha on white is unreadable, and the
    console has shipped exactly that defect before."""
    import os
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    css = open(os.path.join(here, "app/static/css/fortiweb.css"),
               encoding="utf-8").read()
    m = re.search(r"\.bm-grp \.bm-name\.bm-type \{(.*?)\}", css, re.S)
    assert m, "the chip rule is gone"
    block = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)
    assert "--bm-type-fill" in block
    assert not re.search(r"(^|[;\s])color\s*:", block), block
