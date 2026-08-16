"""Guards for the bookmarks GROUPING ORDER — one lens, chosen per user.

What changed, and why each half needs defending:

*   The panel used to show four fixed classification roots at once. It now
    shows **one**, nested in the order the reader picked on their profile page,
    and **named after that order**. A regression here is silent in both
    directions: four roots render perfectly and merely answer a question nobody
    asked, and a root whose heading stops tracking the order looks correct
    while grouping by something else entirely.
*   Reading the preference is deliberately FORGIVING and writing it is
    deliberately STRICT. Those two must not converge. If reading became strict,
    a value a later release stopped recognising would raise on every page in
    the console, because the rail renders everywhere. If writing became
    forgiving, the page would show one order and the tree would use another.

None of these assertions matches a substring the template would contain for
another reason — the sibling panel suite lost six guards to exactly that, and
``"hidden" in body`` is the one everybody remembers.
"""
from __future__ import annotations

import re

import pytest

from app.extensions import db
from app.models import Appliance, AuditLog, User, UserSetting
from app.models_bookmarks import Bookmark, KIND_APPLIANCE, SCOPE_PERSONAL
from app.services import bookmarks as bk

from tests.conftest import admin_user_id, login, make_user


# --- helpers ---------------------------------------------------------------

def _appl(app, name, **kw):
    with app.app_context():
        a = Appliance(name=name, kind=kw.pop("kind", "fortiweb"),
                      host=kw.pop("host", "192.0.2.13"), port=443,
                      username="admin", password_enc="x", verify_ssl=False,
                      **kw)
        db.session.add(a)
        db.session.commit()
        return a.id


def _panel(client):
    r = client.get("/bookmarks/panel")
    assert r.status_code == 200
    return r.get_data(as_text=True)


def _nodes(body):
    """Every group node key the panel rendered."""
    return re.findall(r'data-bm-node="([^"]+)"', body)


def _user(app, uid):
    with app.app_context():
        return User.query.get(uid)


def _row_name(body, bid):
    """The name rendered on ONE bookmark row, by id."""
    m = re.search(r'data-bm-id="%d"(.*?)</div>' % bid, body, re.S)
    assert m, f"no row for bookmark {bid}"
    n = re.search(r'<span class="bm-name">([^<]+)</span>', m.group(1))
    assert n, "row has no name"
    return n.group(1).strip()


# --- parse_lens: the STRICT half ------------------------------------------

def test_parse_lens_keeps_the_submitted_order():
    """The stack is an ORDER, not a set. Sorting it would quietly hand back a
    different tree from the one the operator asked for."""
    assert bk.parse_lens(["department", "kind", "line"]) == \
        ["department", "kind", "line"]


def test_parse_lens_skips_blank_slots():
    """The form is a fixed row of selects; an empty tail is how you ask for a
    shallow tree, not a mistake to reject."""
    assert bk.parse_lens(["zone", "", "  ", "kind"]) == ["zone", "kind"]


def test_parse_lens_refuses_an_empty_stack_by_name():
    """With no dimensions the inventory root cannot nest, and dropping the root
    would take every device off the panel to honour a preference the operator
    cannot see they set."""
    with pytest.raises(bk.BookmarkDenied) as exc:
        bk.parse_lens(["", ""])
    assert exc.value.reason == "empty_lens"


def test_parse_lens_refuses_a_repeated_dimension_and_names_it():
    """A repeat is REFUSED, never de-duplicated: below its first level every
    device already shares one value, and a form that saves something other than
    what was submitted leaves the page disagreeing with the tree."""
    with pytest.raises(bk.BookmarkDenied) as exc:
        bk.parse_lens(["department", "kind", "line", "zone", "department"])
    assert exc.value.reason == "duplicate_dimension"
    # The operator is told WHICH one, in the word the form used.
    assert "Department" in str(exc.value)


def test_parse_lens_refuses_an_unknown_dimension():
    with pytest.raises(bk.BookmarkDenied) as exc:
        bk.parse_lens(["zone", "colour"])
    assert exc.value.reason == "unknown_dimension"
    assert "colour" in str(exc.value)


# --- lens_for: the FORGIVING half -----------------------------------------

def test_default_reproduces_the_previous_fixed_root(app):
    """An upgrade must not re-shape a tree nobody asked to re-shape. From the
    operator's chair that is indistinguishable from somebody having
    re-classified the fleet overnight."""
    uid = admin_user_id(app)
    with app.app_context():
        assert bk.lens_for(_user(app, uid)) == ["line", "zone", "department"]
    assert list(bk.DEFAULT_LENS) == ["line", "zone", "department"]


def test_lens_for_never_raises_on_a_stored_value_it_cannot_use(app):
    """The rail renders on EVERY page. A strict read would turn one retired
    dimension into a 500 on the whole console, not a wrong sidebar."""
    uid = admin_user_id(app)
    with app.app_context():
        UserSetting.set(uid, bk.LENS_SETTING_KEY, "]not,json,at,all[")
        db.session.commit()
        assert bk.lens_for(_user(app, uid)) == list(bk.DEFAULT_LENS)


def test_lens_for_drops_only_the_unusable_entry(app):
    """Falling all the way back to the default would discard a preference that
    is still 90% valid — the operator would see their order replaced rather
    than trimmed."""
    uid = admin_user_id(app)
    with app.app_context():
        UserSetting.set(uid, bk.LENS_SETTING_KEY, "kind,retired_dim,zone,kind")
        db.session.commit()
        assert bk.lens_for(_user(app, uid)) == ["kind", "zone"]


def test_lens_title_is_the_order(app):
    assert bk.lens_title(["department", "kind"]) == "Department › Product"


# --- the panel: ONE root, named after the order ---------------------------

def test_panel_shows_exactly_one_inventory_root(app, client):
    """Four roots answered "how COULD this be grouped". The operator wants one
    answer, and wants it visible without opening a control."""
    _appl(app, "fw-a")
    uid = admin_user_id(app)
    login(client, uid)
    body = _panel(client)
    keys = _nodes(body)
    assert keys.count("r:lens") == 1
    # The retired per-dimension roots are GONE, not merely re-labelled.
    for dead in ("r:class", "r:kind", "r:segment", "r:tag"):
        assert dead not in keys


def test_the_root_is_named_after_the_chosen_order(app, client):
    _appl(app, "fw-a")
    uid = admin_user_id(app)
    with app.app_context():
        UserSetting.set(uid, bk.LENS_SETTING_KEY, "department,kind")
        db.session.commit()
    login(client, uid)
    body = _panel(client)
    assert "Department › Product" in body
    # …and not the previous fixed title, which would mean the heading stopped
    # tracking the order while the tree followed it.
    assert "Line / Zone / Department" not in body


def test_the_tree_nests_in_the_chosen_order(app, client):
    """The order is not decoration: it is the nesting. Product-then-zone and
    zone-then-product render the same device count and completely different
    trees, so only the node KEYS can tell them apart."""
    _appl(app, "fw-a", zone="internal")
    uid = admin_user_id(app)
    login(client, uid)

    with app.app_context():
        UserSetting.set(uid, bk.LENS_SETTING_KEY, "kind,zone")
        db.session.commit()
    keys = _nodes(_panel(client))
    assert "r:lens|fortiweb|internal" in keys
    assert "r:lens|internal|fortiweb" not in keys

    with app.app_context():
        UserSetting.set(uid, bk.LENS_SETTING_KEY, "zone,kind")
        db.session.commit()
    keys = _nodes(_panel(client))
    assert "r:lens|internal|fortiweb" in keys
    assert "r:lens|fortiweb|internal" not in keys


def test_the_root_key_survives_a_reorder(app, client):
    """The stored open-set is keyed by node key. A root key derived from the
    order would slam the root shut every time somebody re-ordered their own
    tree — punishing exactly the action this feature exists to allow."""
    _appl(app, "fw-a", zone="internal")
    uid = admin_user_id(app)
    login(client, uid)
    with app.app_context():
        UserSetting.set(uid, bk.LENS_SETTING_KEY, "kind,zone")
        db.session.commit()
    first = _nodes(_panel(client))
    with app.app_context():
        UserSetting.set(uid, bk.LENS_SETTING_KEY, "zone,kind")
        db.session.commit()
    second = _nodes(_panel(client))
    assert "r:lens" in first and "r:lens" in second


def test_the_stores_are_not_lenses(app, client):
    """Favourites, Folders and Shared are STORES, not views of the inventory.
    Collapsing them into the one-view rule would mean a bookmark shared to you
    is unreachable whenever your chosen grouping is something else."""
    _appl(app, "fw-a")
    uid = admin_user_id(app)
    login(client, uid)
    keys = _nodes(_panel(client))
    for store in ("r:fav", "r:folders", "r:shared"):
        assert store in keys


def test_one_persons_order_does_not_touch_anybody_elses(app, client):
    """It is a per-user display preference. If it leaked, re-ordering your own
    sidebar would re-shape the panel of everyone on the team."""
    _appl(app, "fw-a", zone="internal")
    uid = admin_user_id(app)
    with app.app_context():
        UserSetting.set(uid, bk.LENS_SETTING_KEY, "kind")
        db.session.commit()
    other_id = make_user(app, username="carol", role="admin")
    login(client, other_id)
    body = _panel(client)
    assert "Line › Zone › Department" in body
    assert "r:lens|fortiweb" not in _nodes(body)


# --- the way in -----------------------------------------------------------

def test_the_panel_links_to_the_setting_twice(app, client):
    """Once in the toolbar and once ON the heading that shows the order: the
    operator who wants to change it is looking at the order when they decide
    to, not at the toolbar."""
    _appl(app, "fw-a")
    uid = admin_user_id(app)
    login(client, uid)
    body = _panel(client)
    assert body.count("/auth/profile#bookmark-view") >= 2
    assert "data-bm-order" in body


def test_the_profile_page_offers_every_dimension(app, client):
    uid = admin_user_id(app)
    login(client, uid)
    r = client.get("/auth/profile")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert 'id="bookmark-view"' in body
    for key, _label, _icon in bk.DIMENSIONS:
        assert f'value="{key}"' in body


def test_the_form_shows_the_order_that_is_actually_in_force(app, client):
    """The page and the tree must agree.

    A form that renders blank while the panel groups by something looks like a
    preference that was never saved — so the operator saves again, and the
    order they *thought* they had is silently replaced by whatever the blank
    form submitted. The slot index is the level, so this checks position, not
    mere presence.
    """
    uid = admin_user_id(app)
    with app.app_context():
        UserSetting.set(uid, bk.LENS_SETTING_KEY, "kind,zone")
        db.session.commit()
    login(client, uid)
    body = client.get("/auth/profile").get_data(as_text=True)
    slots = re.findall(r'id="bmdim-(\d+)"(.*?)</select>', body, re.S)
    chosen = {}
    for idx, block in slots:
        m = re.search(r'<option value="([a-z]*)"[^>]*selected', block)
        chosen[int(idx)] = m.group(1) if m else ""
    assert chosen[0] == "kind"
    assert chosen[1] == "zone"
    # Every remaining level is offered empty, not pre-filled with a dimension
    # the operator never picked.
    assert all(v == "" for k, v in chosen.items() if k >= 2), chosen


# --- saving ---------------------------------------------------------------

def test_saving_an_order_changes_the_tree(app, client):
    _appl(app, "fw-a", zone="internal")
    uid = admin_user_id(app)
    login(client, uid)
    r = client.post("/auth/profile/bookmark-view",
                    data={"dim": ["kind", "", "zone", "", "", ""]},
                    follow_redirects=False)
    assert r.status_code == 302
    with app.app_context():
        assert UserSetting.get(uid, bk.LENS_SETTING_KEY, "") == "kind,zone"
    assert "r:lens|fortiweb|internal" in _nodes(_panel(client))


def test_a_refused_order_is_not_stored(app, client):
    """The refusal must leave the previous order intact. Writing a rejected
    value and then repairing it on read is how the page and the tree end up
    disagreeing."""
    uid = admin_user_id(app)
    login(client, uid)
    client.post("/auth/profile/bookmark-view", data={"dim": ["kind", "zone"]})
    r = client.post("/auth/profile/bookmark-view",
                    data={"dim": ["department", "kind", "department"]},
                    follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        assert UserSetting.get(uid, bk.LENS_SETTING_KEY, "") == "kind,zone"


def test_a_refusal_tells_the_operator_which_rule_stopped_them(app, client):
    """A bare "invalid" at 03:00 is what sends people looking for a way around
    a rule instead of a way to satisfy it."""
    uid = admin_user_id(app)
    login(client, uid)
    r = client.post("/auth/profile/bookmark-view",
                    data={"dim": ["zone", "zone"]}, follow_redirects=True)
    body = r.get_data(as_text=True)
    assert "appears twice" in body


def test_an_empty_order_is_refused_rather_than_emptying_the_panel(app, client):
    _appl(app, "fw-a")
    uid = admin_user_id(app)
    login(client, uid)
    client.post("/auth/profile/bookmark-view",
                data={"dim": ["", "", "", "", "", ""]}, follow_redirects=True)
    with app.app_context():
        assert UserSetting.get(uid, bk.LENS_SETTING_KEY, "") == ""
    # The panel still groups the fleet, using the default.
    assert "r:lens" in _nodes(_panel(client))


def test_saving_is_audited(app, client):
    """Language is audited and this is the same class of act. An unaudited
    preference change is one nobody can attribute when a tree is 'wrong'."""
    uid = admin_user_id(app)
    login(client, uid)
    client.post("/auth/profile/bookmark-view", data={"dim": ["kind", "zone"]})
    with app.app_context():
        rows = AuditLog.query.filter_by(action="profile.bookmark_view").all()
        assert len(rows) == 1
        assert "kind,zone" in (rows[0].target or "")


def test_a_refused_order_is_not_audited_as_a_save(app, client):
    """An audit trail that records attempts as changes makes the trail useless
    for answering "who re-ordered this"."""
    uid = admin_user_id(app)
    login(client, uid)
    client.post("/auth/profile/bookmark-view", data={"dim": ["zone", "zone"]})
    with app.app_context():
        assert AuditLog.query.filter_by(action="profile.bookmark_view").count() == 0


# --- the survivor from the previous round ---------------------------------

def test_an_unlabelled_bookmark_follows_the_LIVE_device_name(app, client):
    """A stored copy of the device name is the first field to go stale after a
    rename, and it goes stale invisibly: the row still renders, still links to
    the right device, and merely calls it by a name that no longer exists.

    Renaming is the only way to catch it — asserting the name on a device that
    was never renamed passes against a cached copy just as well.
    """
    aid = _appl(app, "fw-old-name")
    uid = admin_user_id(app)
    with app.app_context():
        bm = Bookmark(owner_user_id=uid, scope=SCOPE_PERSONAL,
                      kind=KIND_APPLIANCE, appliance_id=aid, label=None,
                      product="fortiweb")
        db.session.add(bm)
        db.session.commit()
        bid = bm.id
    login(client, uid)
    # Read the name off the BOOKMARK ROW, not off the page. The inventory lens
    # prints the live appliance name by a different path entirely, so a
    # whole-body assertion passes against a bookmark row that has gone stale.
    assert _row_name(_panel(client), bid) == "fw-old-name"

    with app.app_context():
        Appliance.query.get(aid).name = "fw-renamed"
        db.session.commit()
    assert _row_name(_panel(client), bid) == "fw-renamed"


def test_an_author_typed_label_is_NOT_overwritten_by_the_device_name(app, client):
    """The live name is the FALLBACK, not the rule. If it won unconditionally,
    every deliberate label an operator typed would vanish."""
    aid = _appl(app, "fw-a")
    uid = admin_user_id(app)
    with app.app_context():
        db.session.add(Bookmark(
            owner_user_id=uid, scope=SCOPE_PERSONAL, kind=KIND_APPLIANCE,
            appliance_id=aid, label="prod WAF pair", product="fortiweb"))
        db.session.commit()
    login(client, uid)
    assert "prod WAF pair" in _panel(client)
