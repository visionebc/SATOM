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


def _get(client, app, path):
    from tests.conftest import admin_user_id, login

    login(client, admin_user_id(app))
    res = client.get(path)
    assert res.status_code == 200, path
    return res.get_data(as_text=True)


def _head(html, key):
    m = re.search(r'data-head="%s"[^>]*>([^<]*)<' % key, html)
    assert m, "no headline counter %r on the page" % key
    return m.group(1).strip()


def _table(html, anchor):
    start = html.index(anchor)
    return html[start:html.index("</table>", start)]


def _without_pickers(html):
    """The dropdowns list the whole fleet BY DESIGN.

    A grep over the raw document matches them and reports a leak that is a
    picker — the ninth time in this repo an assertion matched itself.
    """
    out = re.sub(r"<select.*?</select>", "[PICKER]", html, flags=re.S)
    assert "[PICKER]" in out, "no <select> removed — this strip is vacuous"
    return out


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


def test_positive_control_the_fleet_page_still_counts_the_fleet(
        app, client, ctx):
    """Narrowing must not become "always show one scope"."""
    _fleet()
    fleet = _get(client, app, "/artifacts/inventory")
    assert _head(fleet, "objects") == "5"
    assert _head(fleet, "edges") == "7"
    assert _head(fleet, "policies") == "3"



def test_the_objects_counter_is_the_number_of_rows_under_it(app, client, ctx):
    """One name held by two scopes is TWO files and two rows.

    Counting distinct names instead printed 78 over a table of 170 on the live
    fleet — a header that contradicts its own page, which is the defect this
    module exists to prevent, one card higher up.
    """
    a = _appl("fwA@root", "192.0.2.1", "adom_root")
    b = _appl("fwB@root", "192.0.2.2", "adom_root")
    _put("wsdl", "sch-same", "<a/>", appliance_id=a.id)
    _put("wsdl", "sch-same", "<b/>", appliance_id=b.id)
    html = _get(client, app, "/artifacts/inventory")
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


def test_positive_control_where_the_copies_live_spans_the_fleet_unscoped(
        app, client, ctx):
    _fleet()
    fleet = _table(_get(client, app, "/artifacts/inventory"),
                   "data-scopes-table")
    for adom in ("adom_prod", "adom_dev", "adom_root"):
        assert adom in fleet, adom


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
    #: "always show one scope", which would pass the assertion above.
    assert _by_type_objects(_get(client, app, "/artifacts/inventory")) == 5


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
    """The whole-document sweep, with the pickers removed because they list the
    fleet by design."""
    prod, _dev, _other = _fleet()
    body = _without_pickers(
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


def test_the_unscoped_page_says_so_rather_than_saying_nothing(
        app, client, ctx):
    """Blank is not neutral — it is read as whatever scope the reader had in
    mind."""
    _fleet()
    html = _get(client, app, "/artifacts/inventory")
    assert 'data-scope-banner=""' in html
    assert "whole fleet" in html


def test_the_type_links_keep_the_scope(app, client, ctx):
    """Clicking an object type reset the page to the fleet — the same defect
    one click later."""
    prod, _dev, _other = _fleet()
    html = _get(client, app, "/artifacts/inventory?appl=%s" % prod.id)
    block = html[html.index("By object type"):html.index("Where the copies live")]
    links = re.findall(r'href="(/artifacts/inventory\?[^"]+)"', block)
    assert links, "the by-type table has no links"
    for href in links:
        assert "appl=%s" % prod.id in href, href


def test_the_scope_survives_a_link_built_by_the_statistics_page(
        app, client, ctx):
    """/artifacts/ published ``?scope=`` first and those links exist. Two names
    for one concept is how a click lands on a page that widened back."""
    prod, _dev, _other = _fleet()
    html = _get(client, app, "/artifacts/inventory?scope=%s" % prod.id)
    assert _head(html, "objects") == "2"
    assert 'data-scope-banner="%s"' % prod.id in html


def test_the_sidebar_carries_the_scope_between_the_artifact_pages(
        app, client, ctx):
    """"Where I am" has to survive the nav, or the operator re-picks the ADOM
    on every page and the complaint returns."""
    prod, _dev, _other = _fleet()
    html = _get(client, app, "/artifacts/inventory?appl=%s" % prod.id)
    nav = html[html.index("fw-so-nav"):]
    assert "/artifacts/audit?appl=%s" % prod.id in nav
    assert "scope=%s" % prod.id in nav


def test_an_unknown_scope_complains_instead_of_widening_in_silence(
        app, client, ctx):
    """Falling back to the fleet answers a question about one ADOM with every
    ADOM's rows, and looks like a correct answer."""
    _fleet()
    html = _get(client, app, "/artifacts/inventory?appl=999999")
    assert _head(html, "objects") == "5"
    #: NOT `"999999" in html` — the id is echoed back inside every `back=`
    #: value on the page, so that assertion passes with the complaint deleted.
    #: It has to be the complaint's own words, and they must not be the
    #: banner's ("whole fleet" alone is printed by the unscoped banner).
    assert "showing the whole fleet" in html, \
        "the page widened to the fleet without saying so"
