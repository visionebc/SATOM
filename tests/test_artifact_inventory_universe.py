"""Guards: on /artifacts/inventory the (device, ADOM) selection IS the universe.

The reported defect, twice in two days: an operator picks one device and one
ADOM and the page still shows the fleet. It did — the ``appl`` filter was
applied to the row table and to the coverage table and to nothing else, so the
nine headline counters, the by-type table and "where the copies live" kept
summing every chassis. A page cut to 30 objects printed 170 above them and
enumerated four ADOMs the operator was not on.

Two things make that failure invisible without these guards:

* **the page renders perfectly either way.** No error, no empty table — only a
  number that answers a question about one ADOM with twelve ADOMs' rows, and
  the bigger number is the one that reads as authoritative;
* **a filtered page and an unfiltered one can print identical figures.** Two
  ADOMs of one chassis legitimately hold the same NUMBER of objects. That is
  why the fixture below is *symmetric by construction* and has its own control
  test: with ADOMs of different sizes an unfiltered page would print a
  different number and every guard here would pass for the wrong reason.

The universe is narrowed ONCE, in ``_narrow``, before any figure is computed —
so a section added later inherits it. These guards are written against the
ROUTE, never against the services: the services already computed correctly when
the defect shipped; the page was what lied.
"""
from __future__ import annotations

import re
from datetime import datetime

import pytest


@pytest.fixture()
def ctx(app, tmp_path, monkeypatch):
    monkeypatch.setenv("SATOM_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    with app.app_context():
        from app import db
        yield db


def _appl(name, host, vdom):
    from app import db
    from app.models import Appliance

    row = Appliance(name=name, kind="fortiweb", host=host, port=443,
                    username="u", password_enc="x", vdom=vdom)
    db.session.add(row)
    db.session.commit()
    return row


def _ref(aid, policy, kind, name, wpp="wpp-x"):
    from app import db
    from app.models_artifact_refs import WafArtifactRef

    now = datetime.utcnow()
    db.session.add(WafArtifactRef(appliance_id=aid, policy_mkey=policy,
                                  kind=kind, name=name, wpp_mkey=wpp, urn="",
                                  derived_from="test", first_seen_at=now,
                                  seen_at=now))
    db.session.commit()


def _put(kind, name, body, appliance_id=None):
    from app.services import waf_artifacts as wa

    row, _created = wa.put(kind, name, body.encode("utf-8"),
                           appliance_id=appliance_id, source="uploaded")
    return row


# --------------------------------------------------------------------------- #
#  the fixture: one chassis, two ADOMs, SAME SHAPE, DISJOINT NAMES             #
# --------------------------------------------------------------------------- #
CHASSIS = "192.0.2.1"
OTHER_HOST = "192.0.2.2"


def _fleet():
    """Two ADOMs of one box plus a second box.

    prod and dev are mirror images: two held objects, one policy, three edges,
    and one edge each to a name the *other* ADOM holds — the ``borrowed`` case,
    present in both directions so the symmetry survives it. Nothing about the
    numbers can distinguish the two, which is the point: only the NAMES can,
    and names are what the guards read.
    """
    prod = _appl("fw@prod", CHASSIS, "adom_prod")
    dev = _appl("fw@dev", CHASSIS, "adom_dev")
    other = _appl("fw2@root", OTHER_HOST, "adom_root")

    _put("wsdl", "sch-prod-1", "<prod1/>", appliance_id=prod.id)
    _put("wsdl", "sch-prod-2", "<prod2/>", appliance_id=prod.id)
    _put("wsdl", "sch-dev-1", "<dev1/>", appliance_id=dev.id)
    _put("wsdl", "sch-dev-2", "<dev2/>", appliance_id=dev.id)
    _put("wsdl", "sch-other-1", "<other1/>", appliance_id=other.id)

    for name in ("sch-prod-1", "sch-prod-2", "sch-dev-1"):
        _ref(prod.id, "pol-prod", "wsdl", name, wpp="wpp-prod")
    for name in ("sch-dev-1", "sch-dev-2", "sch-prod-1"):
        _ref(dev.id, "pol-dev", "wsdl", name, wpp="wpp-dev")
    _ref(other.id, "pol-other", "wsdl", "sch-other-1", wpp="wpp-other")
    return prod, dev, other


def _get(client, app, path, on=None):
    """Fetch a page while STANDING on a device.

    ``?appl=`` is no longer a scope of its own: the page takes its (device,
    ADOM) from the session, the way every other per-device page in this product
    does, and a link that carries an id moves the session and re-issues the
    request. That hop is why ``follow_redirects`` is on — the old links still
    land where they promised, in one more round trip.
    """
    from flask import g

    from tests.conftest import admin_user_id, login

    login(client, admin_user_id(app))
    if on is not None:
        with client.session_transaction() as sess:
            sess["appliance_id"] = on
        # TEST-HARNESS ONLY. ``current_appliance()`` memoises on ``g``, and
        # ``ctx`` holds ONE app context open for the whole test — Flask reuses
        # it instead of pushing a fresh one per request, so without this the
        # second request in a test renders the FIRST one's device while the
        # session already holds the new one. In production every request gets
        # its own app context and ``set_current`` clears this itself; the cache
        # is only reachable across requests here.
        g.__dict__.pop("_current_appliance", None)
    res = client.get(path, follow_redirects=True)
    assert res.status_code == 200, path
    return res.get_data(as_text=True)


def _whole_document(html):
    """No strip. Deliberately.

    Every guard in this module used to remove ``<select>`` before asserting,
    on the reasoning that "the dropdowns list the whole fleet BY DESIGN". They
    did, and that reasoning is what kept three rounds of fixes from seeing the
    half the operator was still looking at: the filters. The pickers are now
    scoped like the rest of the page, so the assertions read the document as
    rendered.
    """
    assert "<select" in html, "no <select> on the page — a picker guard here " \
                              "would be vacuous"
    return html


def _head(html, key):
    m = re.search(r'data-head="%s"[^>]*>([^<]*)<' % key, html)
    assert m, "no headline counter %r on the page" % key
    return m.group(1).strip()


def _table(html, anchor):
    start = html.index(anchor)
    return html[start:html.index("</table>", start)]


# --------------------------------------------------------------------------- #
#  the control: the fixture cannot distinguish the two ADOMs by counting       #
# --------------------------------------------------------------------------- #
def test_control_the_two_adoms_are_identical_in_every_count(app, client, ctx):
    """If this ever fails, every guard below is worthless.

    An unfiltered page would then print a number that differs from the scoped
    one for reasons that have nothing to do with filtering, and the guards
    would go green on a page that never narrowed anything.
    """
    prod, dev, _other = _fleet()
    a = _get(client, app, "/artifacts/inventory?appl=%s" % prod.id)
    b = _get(client, app, "/artifacts/inventory?appl=%s" % dev.id)
    for key in ("objects", "versions", "edges", "policies", "unheld",
                "orphans"):
        assert _head(a, key) == _head(b, key), key
    assert "sch-dev" not in _table(a, "data-held-table")
    assert "sch-prod" not in _table(b, "data-held-table")


# --------------------------------------------------------------------------- #
#  the headline                                                                 #
# --------------------------------------------------------------------------- #
def test_the_headline_counts_only_the_selected_pair(app, client, ctx):
    """The defect verbatim: 170 objects printed over a list of 30.

    ``wa.stats()`` and ``ar.stats()`` take no scope — they answer for the whole
    store and cannot do anything else — so the header had to stop calling them.
    """
    prod, _dev, _other = _fleet()
    scoped = _get(client, app, "/artifacts/inventory?appl=%s" % prod.id)
    assert _head(scoped, "objects") == "2"
    assert _head(scoped, "edges") == "3"
    assert _head(scoped, "policies") == "1"
    #: sch-dev-1: named by this ADOM's policy, held for the other one.
    assert _head(scoped, "unheld") == "1"


def test_positive_control_a_second_chassis_gets_its_own_universe(
        app, client, ctx):
    """Narrowing must not have become "always show the same scope".

    The fleet-wide reading this control used to assert no longer exists — a
    page that renders every ADOM while the banner names one is the defect, not
    a control. What still discriminates is standing somewhere ELSE and getting
    different numbers and different names.
    """
    prod, _dev, other = _fleet()
    theirs = _get(client, app, "/artifacts/inventory", on=other.id)
    assert _head(theirs, "objects") == "1"
    assert _head(theirs, "edges") == "1"
    assert "sch-other-1" in theirs
    assert "sch-prod-1" not in theirs


def test_the_objects_counter_is_the_number_of_rows_under_it(app, client, ctx):
    """One name held by two scopes is TWO files and two rows.

    Counting distinct names instead printed 78 over a table of 170 on the live
    fleet — a header that contradicts its own page, which is the defect this
    module exists to prevent, one card higher up.
    """
    a = _appl("fwA@root", "192.0.2.1", "adom_root")
    b = _appl("fwB@root", "192.0.2.2", "adom_root")
    # One name, two SCOPED copies, plus a shared one this pair also reads: on
    # a's page that is two files and two rows, and counting distinct NAMES
    # would print 1 over them.
    _put("wsdl", "sch-same", "<a/>", appliance_id=a.id)
    _put("wsdl", "sch-same", "<b/>", appliance_id=b.id)
    _put("wsdl", "sch-shared", "<lib/>")
    _ref(a.id, "pol-a", "wsdl", "sch-shared")
    html = _get(client, app, "/artifacts/inventory", on=a.id)
    rows = _table(html, "data-held-table").count("<tr>") - 1  # minus the head
    assert rows == 2, rows
    assert _head(html, "objects") == "2"

# --------------------------------------------------------------------------- #
#  the tables                                                                   #
# --------------------------------------------------------------------------- #
def test_where_the_copies_live_lists_only_the_selected_pair(app, client, ctx):
    """This table enumerated every device and ADOM in the fleet — on a page the
    operator had just cut to one. It is the most literal form of the report."""
    prod, _dev, _other = _fleet()
    scoped = _table(_get(client, app, "/artifacts/inventory?appl=%s" % prod.id),
                    "data-scopes-table")
    assert "adom_prod" in scoped
    assert "adom_dev" not in scoped
    assert "adom_root" not in scoped
    assert OTHER_HOST not in scoped


def test_positive_control_the_sibling_adom_lists_ITS_pair(app, client, ctx):
    """The mirror of the guard above: standing on dev, this table names
    adom_dev and not adom_prod. Without it, a table that had simply stopped
    rendering would satisfy "adom_dev not in scoped"."""
    _prod, dev, _other = _fleet()
    theirs = _table(_get(client, app, "/artifacts/inventory", on=dev.id),
                    "data-scopes-table")
    assert "adom_dev" in theirs
    assert "adom_prod" not in theirs


def _by_type_objects(html: str) -> int:
    """The Objects column of the by-type table, summed.

    Read per ROW — the table prints one row per known object type and most of
    them are legitimately zero, so a flat grep for the first numbers on the
    card reads a row that holds nothing.
    """
    block = html[html.index("By object type"):html.index("Where the copies live")]
    total = 0
    for tr in block.split("<tr>")[1:]:
        nums = re.findall(r"<td>(\d+)</td>", tr)
        if nums:
            total += int(nums[0])
    return total


def test_the_by_type_table_counts_only_the_selected_pair(app, client, ctx):
    """Same universe as the rows under it. A by-type table summing the fleet
    over a scoped row list is a card that contradicts its own page."""
    prod, _dev, _other = _fleet()
    scoped = _get(client, app, "/artifacts/inventory?appl=%s" % prod.id)
    assert _by_type_objects(scoped) == 2
    #: Positive control in the same test: narrowing must not have become
    #: "always show the same scope", which would pass the assertion above.
    assert _by_type_objects(
        _get(client, app, "/artifacts/inventory", on=_other.id)) == 1


def test_the_used_on_column_names_no_other_pair(app, client, ctx):
    """``usage_index`` is keyed (kind, name) with NO scope in the key, so a copy
    held here whose name another ADOM also uses arrived carrying that ADOM's
    edges. sch-prod-1 is referenced by both policies — on prod's page only
    prod's pair may appear against it."""
    prod, _dev, _other = _fleet()
    held = _table(_get(client, app, "/artifacts/inventory?appl=%s" % prod.id),
                  "data-held-table")
    assert "sch-prod-1" in held
    assert "adom_prod" in held
    assert "adom_dev" not in held, "another ADOM's edges reached this row"


def test_a_copy_held_by_another_scope_is_not_listed_as_held_here(
        app, client, ctx):
    """It is NOT this pair's copy, and saying so is not pedantry: resolve()
    would fall back to the other box's bytes — the ``borrowed`` guess. It
    belongs under "needed and NOT held", flagged."""
    prod, _dev, _other = _fleet()
    html = _get(client, app, "/artifacts/inventory?appl=%s" % prod.id)
    assert "sch-dev-1" not in _table(html, "data-held-table")
    missing = _table(html, "data-missing-table")
    assert "sch-dev-1" in missing
    assert "held elsewhere" in missing


def test_the_missing_table_omits_what_another_scopes_policies_need(
        app, client, ctx):
    """dev's blockers are not prod's. A shared "not held" list makes a device
    look unmigratable because of a policy on a different chassis."""
    prod, _dev, _other = _fleet()
    missing = _table(_get(client, app, "/artifacts/inventory?appl=%s" % prod.id),
                     "data-missing-table")
    assert "sch-other" not in missing
    assert "sch-dev-2" not in missing


def test_no_other_device_or_adom_survives_anywhere_on_a_scoped_page(
        app, client, ctx):
    """The whole-document sweep — INCLUDING the pickers.

    It used to exclude them, and that exemption is exactly where the fleet
    survived three rounds of narrowing: the tables were clean and the dropdown
    still offered every ADOM, which is what the operator kept reporting.
    """
    prod, _dev, _other = _fleet()
    body = _whole_document(
        _get(client, app, "/artifacts/inventory?appl=%s" % prod.id))
    assert "adom_dev" not in body
    assert "adom_root" not in body
    assert OTHER_HOST not in body
    assert "pol-dev" not in body and "pol-other" not in body


# --------------------------------------------------------------------------- #
#  keeping the selection                                                        #
# --------------------------------------------------------------------------- #
def test_the_page_names_the_scope_it_is_showing(app, client, ctx):
    """Two ADOMs of one chassis can print identical figures. Unlabelled, a
    narrowed page is indistinguishable from one that never narrowed."""
    prod, _dev, _other = _fleet()
    html = _get(client, app, "/artifacts/inventory?appl=%s" % prod.id)
    assert 'data-scope-banner="%s"' % prod.id in html
    banner = html[html.index("data-scope-banner"):]
    banner = banner[:banner.index("</div>", banner.index("fw-card-body"))]
    assert CHASSIS in banner and "adom_prod" in banner


def test_an_unscoped_page_is_not_a_thing_that_can_render(app, client, ctx):
    """There is no "whole fleet" reading left to label.

    This used to assert that an unscoped page SAID it was unscoped, which was
    the best that could be done while the fleet page existed. It does not any
    more: with no device chosen the operator is sent to pick one, so the state
    that banner described is unreachable.
    """
    from tests.conftest import admin_user_id, login

    _fleet()
    login(client, admin_user_id(app))
    r = client.get("/artifacts/inventory")
    assert r.status_code == 302 and "/architecture" in r.headers["Location"]


def test_the_type_links_do_not_need_to_carry_the_scope(app, client, ctx):
    """Clicking an object type used to reset the page to the fleet, and the fix
    was to thread ``appl=`` through every link. The scope lives in the session
    now, so the plain link is the correct one — and it must still land scoped,
    which is what this asserts rather than the shape of the href."""
    prod, _dev, _other = _fleet()
    html = _get(client, app, "/artifacts/inventory", on=prod.id)
    block = html[html.index("By object type"):html.index("Where the copies live")]
    links = re.findall(r'href="(/artifacts/inventory[^"]*)"', block)
    assert links, "the by-type table has no links"
    followed = _get(client, app, links[0], on=prod.id)
    assert 'data-scope-banner="%s"' % prod.id in followed
    assert "adom_dev" not in followed


def test_a_link_built_by_the_statistics_page_still_lands_scoped(
        app, client, ctx):
    """/artifacts/ published ``?scope=`` first and those links are in
    operators' hands. They move the session device and re-issue; what they must
    never do is open a second, disagreeing notion of where the operator is."""
    prod, _dev, _other = _fleet()
    html = _get(client, app, "/artifacts/inventory?scope=%s" % prod.id)
    assert _head(html, "objects") == "2"
    assert 'data-scope-banner="%s"' % prod.id in html


def test_the_scope_survives_the_nav_without_being_threaded_through_it(
        app, client, ctx):
    """"Where I am" has to survive the nav, or the operator re-picks the ADOM
    on every page and the complaint returns.

    It used to survive by having every sidebar link carry ``appl=``. Threading
    a context through N links means the N+1st forgets it — and the sidebar's
    own links had, which is how a click from Statistics to Inventory landed on
    the fleet. The session carries it now, so the assertion is about where the
    links LAND, not about their query strings.
    """
    prod, _dev, _other = _fleet()
    _get(client, app, "/artifacts/inventory", on=prod.id)
    for path in ("/artifacts/", "/artifacts/audit", "/artifacts/manage"):
        html = client.get(path, follow_redirects=True).get_data(as_text=True)
        assert "adom_dev" not in html, path
        assert OTHER_HOST not in html, path


def test_an_unknown_scope_complains_instead_of_moving_in_silence(
        app, client, ctx):
    """An id that matches nothing must not silently do anything at all.

    It used to fall back to the fleet — answering a question about one ADOM
    with every ADOM's rows, which looks like a correct answer. Now the device
    the operator is on is kept, and the mismatch is said out loud rather than
    leaving them somewhere they did not ask to be.
    """
    prod, _dev, _other = _fleet()
    html = _get(client, app, "/artifacts/inventory?appl=999999", on=prod.id)
    assert _head(html, "objects") == "2"
    assert 'data-scope-banner="%s"' % prod.id in html
    #: NOT `"999999" in html` — the id is echoed back inside every `back=`
    #: value on the page, so that assertion passes with the complaint deleted.
    assert "No device with id 999999" in html, \
        "the page ignored an unknown id without saying so"
