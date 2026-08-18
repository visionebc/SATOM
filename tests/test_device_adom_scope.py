"""Device-wide verbs belong to the CHASSIS, not to each ADOM row of it.

A FortiWeb in ADOM mode can only be registered one row per ADOM (the auth
token carries exactly one — see test_chassis_grouping). Firmware, the
config-backup vault and the CLI console act on the BOX: one flash partition,
one boot image, and an ``execute backup`` that emits every ADOM. Before this,
each ADOM row offered all three, so:

* the same upgrade was offered three times for one appliance, and
* "restore adom_dev" would in fact have restored adom_prod and root with it,
  with nothing on the page saying so.

Classification (zone / line / department), policies and the row's own
credential stay PER-ADOM — that is the whole point of registering them
separately, and a guard here also pins that they were not swept up.

The gate lives on the ROUTE. A template that only hides the button is
decorated, not scoped: that is exactly how ``visible_appliance_or_404`` shipped
a by-id hole for a week (see test_appliance_adom_scope).
"""
from __future__ import annotations

import io
import re
from pathlib import Path

from conftest import admin_user_id, login

ROOT = Path(__file__).resolve().parents[1]
INDEX_TPL = ROOT / "app" / "templates" / "appliances" / "index.html"
DETAIL_TPL = ROOT / "app" / "templates" / "appliances" / "detail.html"
CSS = ROOT / "app" / "static" / "css" / "fortiweb.css"


class _Row:
    """Duck-typed appliance row for the pure-function half (no DB)."""

    def __init__(self, id, name, vdom=None, kind="fortiweb", host="192.0.2.14",
                 port=443, is_cluster=False):
        self.id = id
        self.name = name
        self.vdom = vdom
        self.kind = kind
        self.host = host
        self.port = port
        self.is_cluster = is_cluster


def _mk(app, name, vdom=None, host="192.0.2.14", kind="fortiweb", port=443):
    from app.extensions import db
    from app.models import Appliance

    with app.app_context():
        a = Appliance(name=name, kind=kind, host=host, port=port, vdom=vdom,
                      username="u", password_enc="placeholder")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        return a.id


def _chassis(app):
    """fortiweb09 as it is really registered: root + three ADOM rows."""
    return {
        "root": _mk(app, "fortiweb09", vdom="root"),
        "prod": _mk(app, "fortiweb09@adom_prod", vdom="adom_prod"),
        "dmz": _mk(app, "fortiweb09@adom_dmz", vdom="adom_dmz"),
        "dev": _mk(app, "fortiweb09@adom_dev", vdom="adom_dev"),
        "other": _mk(app, "fortiweb10", vdom=None, host="192.0.2.15"),
    }


# --------------------------------------------------------------------------- #
#  chassis_device_row / owns_device_scope                                       #
# --------------------------------------------------------------------------- #
def test_the_root_adom_row_owns_the_device_verbs(app):
    from app.models import Appliance, chassis_device_row, owns_device_scope

    ids = _chassis(app)
    with app.app_context():
        for key in ("root", "prod", "dmz", "dev"):
            row = Appliance.query.get(ids[key])
            assert chassis_device_row(row).id == ids["root"], key
        assert owns_device_scope(Appliance.query.get(ids["root"])) is True
        for key in ("prod", "dmz", "dev"):
            assert owns_device_scope(Appliance.query.get(ids[key])) is False, key


def test_a_device_registered_once_always_owns_its_own_verbs(app):
    """The gate collapses DUPLICATES. It must never take a verb away from a
    device that has only one row to offer it on — including a lone row that is
    registered inside a non-root ADOM."""
    from app.models import Appliance, owns_device_scope

    plain = _mk(app, "fortiweb10", vdom=None, host="192.0.2.15")
    lone_adom = _mk(app, "fortiweb11@adom_a", vdom="adom_a", host="192.0.2.16")
    with app.app_context():
        assert owns_device_scope(Appliance.query.get(plain)) is True
        assert owns_device_scope(Appliance.query.get(lone_adom)) is True


def test_a_chassis_with_no_root_row_still_has_exactly_one_owner(app):
    """Nobody typed the root credential. The box must stay upgradable, and the
    button must land on the SAME row between two renders — so the choice is
    deterministic (first by name), not 'whichever the query returned first'."""
    from app.models import Appliance, chassis_device_row, owns_device_scope

    b = _mk(app, "fwb@adom_b", vdom="adom_b", host="192.0.2.9")
    a = _mk(app, "fwb@adom_a", vdom="adom_a", host="192.0.2.9")
    with app.app_context():
        rows = [Appliance.query.get(a), Appliance.query.get(b)]
        owners = {chassis_device_row(r).id for r in rows}
        assert owners == {a}
        assert [owns_device_scope(r) for r in rows] == [True, False]


def test_a_row_with_no_adom_counts_as_the_device_row(app):
    """A pre-ADOM registration has an empty vdom, not 'root'. Treating that as
    a partition would leave a chassis whose only global row is invisible."""
    from app.models import Appliance, chassis_device_row

    bare = _mk(app, "fwb", vdom=None, host="192.0.2.8")
    _mk(app, "fwb@adom_x", vdom="adom_x", host="192.0.2.8")
    with app.app_context():
        assert chassis_device_row(Appliance.query.get(bare)).id == bare


def test_two_different_boxes_are_never_one_chassis(app):
    from app.models import Appliance, owns_device_scope

    ids = _chassis(app)
    with app.app_context():
        assert owns_device_scope(Appliance.query.get(ids["other"])) is True


def test_an_ha_cluster_node_zero_owns_its_verbs():
    """Node 0 in per-node mode has no connection of its own, so chassis_key is
    None. Grouping every such container under one 'no host' bucket would merge
    unrelated clusters and hand one of them the other's firmware button."""
    from app.models import owns_device_scope

    assert owns_device_scope(_Row(1, "cluster", host="", is_cluster=True)) is True


# --------------------------------------------------------------------------- #
#  The ROUTE gate                                                               #
# --------------------------------------------------------------------------- #
GATED = (
    "/appliances/{id}/console",
    "/appliances/{id}/upgrade",
    "/appliances/{id}/upgrade/prep",
    "/appliances/{id}/downgrade",
    "/appliances/{id}/restore",
    "/backups/{id}",
)


def test_every_device_wide_page_refuses_an_adom_row(app, client):
    ids = _chassis(app)
    login(client, admin_user_id(app))
    for url in GATED:
        r = client.get(url.format(id=ids["dev"]))
        assert r.status_code == 302, url
        # and it says WHERE the button went — a gate that only says no is a
        # dead end for the operator holding the ticket.
        assert r.headers["Location"].endswith("/appliances/%d" % ids["root"]), url


def test_the_same_pages_open_on_the_device_row(app, client):
    """The gate must not cost the chassis its verbs. Checked on the two pages
    that touch no device (console presets, the vault listing) so a lab without
    a reachable FortiWeb still proves the positive half."""
    ids = _chassis(app)
    login(client, admin_user_id(app))
    for url in ("/appliances/{id}/console", "/backups/{id}"):
        assert client.get(url.format(id=ids["root"])).status_code == 200, url


def test_a_write_is_refused_too_not_just_the_page(app, client):
    """Hiding the form while the POST still lands is the failure mode this
    whole file exists for."""
    ids = _chassis(app)
    login(client, admin_user_id(app))
    r = client.post("/appliances/%d/restore/upload" % ids["prod"], data={})
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/appliances/%d" % ids["root"])


def test_a_json_caller_gets_409_not_a_redirect(app, client):
    """A 302 to an HTML page renders as a parse error in the console's fetch,
    which reads as 'the app broke', not as 'wrong row'."""
    ids = _chassis(app)
    login(client, admin_user_id(app))
    r = client.post("/appliances/%d/console/run" % ids["dev"],
                    json={"command": "get system status"})
    assert r.status_code == 409
    body = r.get_json()
    assert body["ok"] is False
    assert body["device_appliance_id"] == ids["root"]


def test_the_per_adom_verbs_are_untouched(app, client):
    """Policies, discovery and this row's own credential are the REASON the
    ADOM has a row at all. Sweeping them into the gate would make the row
    useless."""
    ids = _chassis(app)
    login(client, admin_user_id(app))
    for url in ("/appliances/{id}", "/appliances/{id}/edit"):
        assert client.get(url.format(id=ids["dev"])).status_code == 200, url


def test_classification_stays_editable_per_adom(app, client):
    """Zone / line / department are per-ADOM ON PURPOSE — two ADOMs of one box
    can legitimately serve different zones."""
    ids = _chassis(app)
    login(client, admin_user_id(app))
    html = client.get("/appliances/%d/edit" % ids["dev"]).get_data(as_text=True)
    for field in ('name="zone"', 'name="line"', 'name="department"'):
        assert field in html, field


def test_the_backups_menu_lands_on_the_chassis_row(app, client):
    """The sidebar entry must OPEN the vault, not bounce off the gate it just
    walked into."""
    ids = _chassis(app)
    login(client, admin_user_id(app))
    with client.session_transaction() as sess:
        sess["appliance_id"] = ids["dev"]
    r = client.get("/backups/")
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/backups/%d" % ids["root"])


# --------------------------------------------------------------------------- #
#  The rendered roster                                                          #
# --------------------------------------------------------------------------- #
def _roster(app, client):
    login(client, admin_user_id(app))
    return client.get("/appliances/").get_data(as_text=True)


def test_the_adoms_render_as_children_of_their_device(app, client):
    ids = _chassis(app)
    html = _roster(app, client)
    assert 'data-adom-toggle="%d"' % ids["root"] in html
    for key in ("prod", "dmz", "dev"):
        assert 'data-adom-of="%d"' % ids["root"] in html
    assert html.count('data-adom-of="%d"' % ids["root"]) == 3


def test_the_children_start_folded(app, client):
    """With one row per ADOM on a 60-device fleet, an expanded default is a
    roster nobody can read."""
    ids = _chassis(app)
    html = _roster(app, client)
    for chunk in re.findall(r'<tr class="fw-adom-row"[^>]*>', html):
        assert "display:none" in chunk


def test_the_group_anchors_on_the_device_row_not_on_the_first_name(app, client):
    """The parent row and the device buttons must be the SAME row. Anchoring
    on whichever name sorts first puts the fold's root on a row that then
    shows no firmware button — a chassis that reads as having lost its verbs,
    with the real ones hidden one fold down."""
    child = _mk(app, "aa-fwb@adom_a", vdom="adom_a", host="192.0.2.7")
    root = _mk(app, "zz-fwb", vdom="root", host="192.0.2.7")
    html = _roster(app, client)
    assert 'data-adom-toggle="%d"' % root in html
    assert 'data-adom-of="%d"' % root in html
    assert 'data-adom-toggle="%d"' % child not in html
    assert "/appliances/%d/upgrade" % root in html
    assert "/appliances/%d/upgrade" % child not in html


def test_a_device_with_no_adoms_gets_no_toggle(app, client):
    """Most of the fleet is one row. Those must render exactly as before."""
    ids = _chassis(app)
    html = _roster(app, client)
    assert 'data-adom-toggle="%d"' % ids["other"] not in html


def test_only_the_device_row_offers_firmware_in_the_roster(app, client):
    ids = _chassis(app)
    html = _roster(app, client)
    assert '/appliances/%d/upgrade' % ids["root"] in html
    for key in ("prod", "dmz", "dev"):
        assert '/appliances/%d/upgrade' % ids[key] not in html, key
        assert '/appliances/%d/console' % ids[key] not in html, key


def test_every_row_keeps_its_own_edit_and_inspector(app, client):
    ids = _chassis(app)
    html = _roster(app, client)
    for key in ("root", "prod", "dmz", "dev"):
        assert '/appliances/%d/inspector' % ids[key] in html, key
        assert '/appliances/%d/delete' % ids[key] in html, key


def test_an_adom_row_points_at_the_row_that_has_the_verbs(app, client):
    """Without this the operator sees three buttons vanish and nothing saying
    where they went — and on a page boundary the device row may not even be
    on screen."""
    ids = _chassis(app)
    html = _roster(app, client)
    assert "fw-adom-owner-link" in html
    assert html.count("fw-adom-owner-link") == 3


def test_the_detail_page_says_why_the_buttons_are_missing(app, client):
    ids = _chassis(app)
    login(client, admin_user_id(app))
    html = client.get("/appliances/%d" % ids["dev"]).get_data(as_text=True)
    assert "/appliances/%d/upgrade" % ids["dev"] not in html
    assert "act on the whole appliance" in html
    assert "/appliances/%d" % ids["root"] in html
    root_html = client.get("/appliances/%d" % ids["root"]).get_data(as_text=True)
    assert "/appliances/%d/upgrade" % ids["root"] in root_html


# --------------------------------------------------------------------------- #
#  The fold, in the page's own JS                                               #
# --------------------------------------------------------------------------- #
def test_the_store_holds_the_open_set_never_the_closed_one():
    """A stored CLOSED set has to be seeded per chassis on first sight, so any
    chassis it had never seen would open itself. Reusing a key that once held
    a closed set would also read it back as an open one and expand exactly the
    rows the operator had folded."""
    src = io.open(INDEX_TPL, encoding="utf-8").read()
    assert "satom.appliances.adom.open" in src
    # Match the STORE KEY, not the word: the comment that explains this guard
    # says "collapsed" itself, and an assertion that fires on its own rationale
    # is the seventh of its kind in this repo.
    assert re.search(r"""['"]satom\.[A-Za-z.]*collaps""", src) is None


def test_a_search_reaches_a_folded_adom():
    """A row that matches the query and stays hidden reads as 'no such
    device' — the one answer the search box must not give."""
    src = io.open(INDEX_TPL, encoding="utf-8").read()
    m = re.search(r"const folded\s*=\s*([^;]+);", src)
    assert m, "the fold decision moved; re-pin it"
    assert "q === ''" in m.group(1)


def test_the_fold_chrome_is_light():
    """SATOM is a light product — no dark glassmorphism (safeguards 9m)."""
    css = io.open(CSS, encoding="utf-8").read()
    block = css[css.index(".fw-adom-toggle"):]
    for leak in ("#080d1a", "backdrop-filter", "rgba(30,41,59"):
        assert leak not in block, leak


# --------------------------------------------------------------------------- #
#  The roster cards count DEVICES, and one of them counts ADOMs                 #
# --------------------------------------------------------------------------- #
def _stat_tiles(html):
    """[(value, label)] for the stat row, in render order."""
    return re.findall(
        r'fw-stat-value[^>]*>([^<]*)</div>\s*<div class="fw-stat-label"[^>]*>([^<]*)<',
        html)


def test_the_tally_folds_the_adom_rows_of_one_appliance(app):
    """fortiweb09 is registered four times because the auth token carries one
    ADOM. It is still ONE box, and the card sits under a device icon."""
    from app.models import Appliance, chassis_tally

    _chassis(app)
    with app.app_context():
        rows = Appliance.query.filter(Appliance.parent_id.is_(None)).all()
    assert len(rows) == 5
    assert chassis_tally(rows) == (2, 4)


def test_root_is_an_adom_like_the_tree_badge_says(app):
    """The row that owns the chassis verbs is registered in ``root``, and the
    tree badge next to it already reads "ADOM \u00b7 4". A tally that skipped
    root would print 3 beside a badge that says 4."""
    from app.models import Appliance, chassis_tally

    _chassis(app)
    with app.app_context():
        rows = Appliance.query.filter(Appliance.vdom.is_not(None)).all()
    assert chassis_tally(rows)[1] == 4


def test_two_appliances_partitioned_into_root_are_two_adoms(app):
    """Deduplicating ADOMs by NAME reports half the partitions the fleet has:
    ``root`` on one box and ``root`` on another are two domains, administered
    by two credentials, on two chassis."""
    from app.models import Appliance, chassis_tally

    _mk(app, "fortiweb09", vdom="root", host="192.0.2.14")
    _mk(app, "fortiweb10", vdom="root", host="192.0.2.15")
    with app.app_context():
        rows = Appliance.query.all()
    assert chassis_tally(rows) == (2, 2)


def test_a_row_with_no_adom_is_not_counted_as_one(app):
    """A device registered before ADOMs were turned on has no partition to
    count — an empty ``vdom`` is not the name of an administrative domain."""
    from app.models import Appliance, chassis_tally

    _mk(app, "fortiweb10", vdom=None, host="192.0.2.15")
    _mk(app, "fortiadc02", vdom="", host="192.0.2.76", kind="fortiadc")
    with app.app_context():
        rows = Appliance.query.all()
    assert chassis_tally(rows) == (2, 0)


def test_two_cluster_containers_are_two_devices():
    """An HA container has no host of its own, so it has no chassis key.
    Bucketing every keyless row together would merge unrelated clusters into
    one device."""
    from app.models import chassis_tally

    rows = [_Row(1, "clusterA", host="", is_cluster=True),
            _Row(2, "clusterB", host="", is_cluster=True)]
    assert chassis_tally(rows) == (2, 0)


def test_the_same_box_on_another_port_is_another_device():
    """The fold key is (kind, host, port) — the same rule the tree groups by.
    Widening it to the host alone would fold two appliances behind one NAT."""
    from app.models import chassis_tally

    rows = [_Row(1, "a", vdom="root", port=443),
            _Row(2, "b", vdom="root", port=8443)]
    assert chassis_tally(rows) == (2, 2)


def test_the_index_cards_report_devices_and_adoms(app, client):
    """End to end: the page, not the helper. The count the operator reads has
    to survive the view and the template, and it has to agree with the tree
    directly below it."""
    _chassis(app)
    login(client, admin_user_id(app))
    html = client.get("/appliances/").get_data(as_text=True)
    tiles = _stat_tiles(html)
    assert [t[1] for t in tiles][:2] == ["Devices", "ADOMs"]
    assert tiles[0][0] == "2", tiles
    assert tiles[1][0] == "4", tiles
    # The tree says the same thing one element down.
    assert "ADOM \u00b7 4" in html or "ADOM &#183; 4" in html or "ADOM · 4" in html


def test_the_index_cards_are_fleet_wide_not_page_wide(app, client):
    """The tiles are stats about the FLEET; the table under them is paginated
    and filtered. A search must not silently redefine what the fleet is."""
    _chassis(app)
    login(client, admin_user_id(app))
    html = client.get("/appliances/?q=fortiweb10").get_data(as_text=True)
    tiles = _stat_tiles(html)
    assert tiles[0][0] == "2", tiles
    assert tiles[1][0] == "4", tiles


def test_online_counts_an_appliance_once():
    """Four ADOM rows probe one box. Counting every status pill made Online
    add up to the ROW count while the tile beside it counts devices — two
    numbers about the same fleet that can never agree."""
    src = io.open(INDEX_TPL, encoding="utf-8").read()
    m = re.search(r"const statuses\s*=\s*([^;]+);", src)
    assert m, "the status roll-up moved; re-pin it"
    assert "fw-adom-row" in m.group(1)


def test_the_five_tiles_fit_one_row():
    """A fifth tile in a hardcoded col-md-3 grid wraps alone onto a second
    line. The row has to declare how many tiles it carries."""
    src = io.open(INDEX_TPL, encoding="utf-8").read()
    block = src[:src.index("fw-toolbar")]
    assert "row-cols-xl-5" in block
    assert "col-md-3 col-sm-6" not in block
