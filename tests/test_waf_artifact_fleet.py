"""Guards: the fleet-wide ARTIFACTS page (``/waf/artifacts``).

Four properties, each of them a mistake this repo has already paid for:

1. **The universe is what this console may see**, and it is the SAME one every
   other ``/waf/*`` page is a function of — ``waf_fleet.fortiweb_scopes``. The
   guards go through the ROUTE, never the service: on ``/artifacts/*`` the
   services computed correctly for the whole time the leak was live and it was
   the PAGE that showed the fleet (safeguards §122).

2. **Absence is not zero, in two different places here.** A scope nobody swept
   is ``swept=False``, not a tidy row of zeros; a scope with no configuration
   snapshot has ``unwalked=None``, not 0, because "how many policies does it
   have" genuinely has no answer for it.

3. **Held is not usable.** A zero-byte newest version answers every "do we have
   it?" check in the codebase and configures nothing (safeguards §124), so it
   is flagged next to the ``ok`` that is also true of it.

4. **A verdict has ONE author.** ``artifact_refs.verdict_of`` is shared by
   ``device_audit``, ``artifact_stats.scope_stats`` and this page; the comment
   that used to say "identical expression, deliberately" was a promise, not a
   mechanism.
"""
from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timedelta

import pytest

from tests.conftest import admin_user_id, login, make_user, profile_id

CHASSIS = "192.0.2.1"
OTHER = "192.0.2.2"


@pytest.fixture()
def ctx(app, tmp_path, monkeypatch):
    monkeypatch.setenv("SATOM_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    with app.app_context():
        from app import db
        yield db


# --------------------------------------------------------------------------- #
#  fixture plumbing                                                             #
# --------------------------------------------------------------------------- #
def _appl(name, host=CHASSIS, vdom="root", kind="fortiweb", maintenance=False):
    from app import db
    from app.models import Appliance

    row = Appliance(name=name, kind=kind, host=host, port=443, username="u",
                    password_enc="x", vdom=vdom, maintenance=maintenance)
    db.session.add(row)
    db.session.commit()
    return row


def _snapshot(policy_names):
    return {"sections": {
        "Server Policy": {"server_policy": [{"name": n} for n in policy_names]},
        "Server Objects": {"vserver": [], "server_pool": []},
        "Web Protection": {"webprotection_profile_inline": [],
                           "webprotection_profile_offline": [],
                           "signature": [], "custom_rule": []},
        "System": {"certificate": []},
    }, "total_objects": len(policy_names)}


def _record(appliance, policy_names):
    from app.services import sot_store
    from app.services.device_sync import slugify

    return sot_store.record(slugify(appliance.name), _snapshot(policy_names),
                            source="test")


def _ref(aid, policy, kind, name, wpp="wpp-x", age_days=0):
    from app import db
    from app.models_artifact_refs import WafArtifactRef

    seen = datetime.utcnow() - timedelta(days=age_days)
    db.session.add(WafArtifactRef(appliance_id=aid, policy_mkey=policy,
                                  kind=kind, name=name, wpp_mkey=wpp, urn="",
                                  derived_from="test", first_seen_at=seen,
                                  seen_at=seen))
    db.session.commit()


def _scan(aid, policy, ok=True):
    from app import db
    from app.models_artifact_refs import WafArtifactScan

    db.session.add(WafArtifactScan(appliance_id=aid, policy_mkey=policy, ok=ok,
                                   error="", refs=1,
                                   scanned_at=datetime.utcnow()))
    db.session.commit()


def _put(kind, name, body: bytes, appliance_id=None):
    from app.services import waf_artifacts as wa

    return wa.put(kind, name, body, appliance_id=appliance_id,
                  source="uploaded")


def _get(client, url, uid, product="fortiweb"):
    """Log in as *uid* and GET *url*, from a CLEARED session.

    ``conftest.login`` writes ``_user_id`` over whatever is already there and
    flask-login keeps serving the FIRST identity, so a body that switches user
    silently re-asserts the same one — which is how the control half of a
    permission guard passes for the wrong reason.
    """
    with client.session_transaction() as sess:
        sess.clear()
    login(client, uid, product=product)
    return client.get(url)


@pytest.fixture()
def estate(ctx):
    """One fleet with every state on this page present exactly once.

    ``web1`` needs four objects: one held for itself, one held by nobody and
    unreadable, one held only by ``web2``, and one served by the shared
    library. ``web2`` additionally holds a copy nothing names (orphan) and an
    EMPTY one that a policy does name.
    """
    web1 = _appl("web1")
    _record(web1, ["pol-a", "pol-b", "pol-never-walked"])
    web2 = _appl("web2", host=OTHER)
    _record(web2, ["pol-c"])

    # web1 — walked policies
    _scan(web1.id, "pol-a")
    _scan(web1.id, "pol-b", ok=False)
    _ref(web1.id, "pol-a", "openapi", "api-a.json")          # held here -> ok
    _ref(web1.id, "pol-a", "wsdl", "svc.wsdl")               # nowhere -> blocked
    _ref(web1.id, "pol-a", "json_schema", "gone.json")       # nowhere -> at-risk
    _ref(web1.id, "pol-b", "xml_dtd", "doc.dtd", wpp="")     # web2 only -> borrowed
    _ref(web1.id, "pol-b", "json_schema", "shared.json")     # library -> ok
    _put("openapi", "api-a.json", b"{openapi}", appliance_id=web1.id)

    # web2
    _scan(web2.id, "pol-c")
    _ref(web2.id, "pol-c", "xml_dtd", "doc.dtd")
    _ref(web2.id, "pol-c", "json_schema", "shared.json")
    _ref(web2.id, "pol-c", "openapi", "hollow.json")
    _put("xml_dtd", "doc.dtd", b"<!ELEMENT a>", appliance_id=web2.id)
    _put("openapi", "hollow.json", b"", appliance_id=web2.id)     # held, EMPTY
    _put("openapi", "dead.json", b"{}", appliance_id=web2.id)     # orphan copy

    # library-wide, read by both
    _put("json_schema", "shared.json", b"{\"$schema\":1}", appliance_id=None)

    # another product, and a device in maintenance
    adc = _appl("adc1", host="192.0.2.3", kind="fortiadc", vdom=None)
    _ref(adc.id, "adc-pol", "wsdl", "adc-secret.wsdl")
    maint = _appl("web-maint", host="192.0.2.4", maintenance=True)
    _record(maint, ["pol-maint"])
    _scan(maint.id, "pol-maint")
    _ref(maint.id, "pol-maint", "openapi", "maint-secret.json")

    # registered, swept, but never harvested: its policy total is UNKNOWN
    never = _appl("web-never", host="192.0.2.5")
    _scan(never.id, "pol-unknown")
    _ref(never.id, "pol-unknown", "openapi", "ghost.json")

    # registered and nobody has ever looked at it
    quiet = _appl("web-quiet", host="192.0.2.6")
    _record(quiet, ["pol-quiet"])
    return {"web1": web1.id, "web2": web2.id, "adc": adc.id,
            "never": never.id, "quiet": quiet.id, "maint": maint.id}


def _rows(app, user=None):
    from app.services import waf_artifact_fleet as svc

    return svc.collect(user=user)


def _row(universe, scope_part, kind, name):
    for r in universe["rows"]:
        if r["kind"] == kind and r["name"] == name and scope_part in r["scope"]:
            return r
    raise AssertionError("no row for %s/%s in %s" % (kind, name, scope_part))


# --------------------------------------------------------------------------- #
#  the universe                                                                 #
# --------------------------------------------------------------------------- #
def test_the_page_never_shows_another_products_artifact(app, client, estate):
    uid = admin_user_id(app)
    html = _get(client, "/waf/artifacts", uid).get_data(as_text=True)
    assert "adc-secret.wsdl" not in html
    assert "adc1" not in html


def test_the_global_console_counts_only_the_fortiwebs(app, client, estate):
    """The guard above cannot see the ``kind`` filter; this one can.

    In a FortiWeb session ``visible_appliances()`` already drops FortiADC, so
    removing the narrowing changes nothing there. GLOBAL is the console where
    the fleet really is every product, and it is one of the two this page is
    offered in.
    """
    uid = admin_user_id(app)
    html = _get(client, "/waf/artifacts", uid, product="global").get_data(as_text=True)
    assert "adc-secret.wsdl" not in html
    data = _get(client, "/waf/api/artifacts.json", uid,
                product="global").get_json()
    scopes = [s["scope"] for s in data["per_scope"]]
    assert not any("adc1" in s for s in scopes), scopes


def test_a_maintenance_scope_is_hidden_from_an_operator_without_the_permission(
        app, client, estate):
    ro = make_user(app, username="ro-art", role="readonly",
                   profile_id=profile_id(app, "readonly"))
    html = _get(client, "/waf/artifacts", ro).get_data(as_text=True)
    assert "maint-secret.json" not in html
    assert "web-maint" not in html


def test_the_same_maintenance_scope_is_shown_to_an_admin(app, client, estate):
    """Control: the row exists, and only the permission was hiding it."""
    html = _get(client, "/waf/artifacts", admin_user_id(app)).get_data(as_text=True)
    assert "maint-secret.json" in html


def test_the_universe_is_the_one_every_other_waf_page_uses(app, estate):
    """Not a style point: a second query here is a second answer to "which
    devices is this console allowed to count", and the two drift silently."""
    from app.services import waf_fleet

    with app.app_context():
        universe = _rows(app)
        expected = {waf_fleet.scope_label(a) for a in waf_fleet.fortiweb_scopes()}
    assert {s["scope"] for s in universe["scopes"]} == expected


# --------------------------------------------------------------------------- #
#  verdicts                                                                     #
# --------------------------------------------------------------------------- #
def test_a_copy_held_for_this_scope_is_ok(app, estate):
    with app.app_context():
        assert _row(_rows(app), "web1", "openapi", "api-a.json")["state"] == "ok"


def test_a_copy_only_another_scope_holds_is_borrowed_never_ok(app, estate):
    """``resolve()`` would serve web2's bytes to web1. That is a guess the
    operator has to be allowed to refuse, so it cannot render as held."""
    with app.app_context():
        universe = _rows(app)
        assert _row(universe, "web1", "xml_dtd", "doc.dtd")["state"] == "borrowed"
        # Control: the scope that actually owns the copy is not borrowing it.
        assert _row(universe, "web2", "xml_dtd", "doc.dtd")["state"] == "ok"


def test_an_unreadable_type_with_no_copy_is_blocked_and_a_readable_one_is_at_risk(
        app, estate):
    """The whole reason the two words exist: a WSDL can never be read back off
    a FortiWeb, so a missing copy is permanent; a JSON Schema is still
    capturable while the box is alive. Same absence, opposite remedies."""
    with app.app_context():
        universe = _rows(app)
        assert _row(universe, "web1", "wsdl", "svc.wsdl")["state"] == "blocked"
        assert _row(universe, "web1", "json_schema", "gone.json")["state"] == "at-risk"


def test_the_verdict_has_one_author(app, estate):
    """This page, ``artifact_stats`` and ``device_audit`` must agree object by
    object. They used to hold three copies of the expression."""
    from app.services import artifact_refs as ar
    from app.services import artifact_stats as ast_
    from app.services import waf_fleet

    with app.app_context():
        universe = _rows(app)
        appls = waf_fleet.fortiweb_scopes()
        fleet = ast_.fleet_stats(appls)
        mine = {}
        for r in universe["rows"]:
            if r["needed"]:
                mine[(r["appliance_id"], r["kind"], r["name"])] = r["state"]
        for appl in appls:
            audit = ar.device_audit(appl.id)
            for need in audit["artifacts"]:
                key = (appl.id, need["kind"], need["name"])
                assert mine.get(key) == need["verdict"], key
        for scope in fleet["scopes"]:
            counted = {v: 0 for v in ("blocked", "at-risk", "borrowed", "ok")}
            for (aid, _k, _n), state in mine.items():
                if aid == scope["appliance_id"]:
                    counted[state] += 1
            for verdict, n in counted.items():
                assert scope["totals"][verdict] == n, (scope["scope"], verdict)


# --------------------------------------------------------------------------- #
#  states that are NOT verdicts                                                 #
# --------------------------------------------------------------------------- #
def test_a_stored_copy_no_walked_policy_names_is_an_orphan(app, estate):
    """And it is NOT counted as readiness: there is no need behind it, so
    folding it into ``ok`` would inflate the share of the estate that is ready
    to move with copies nothing is waiting for."""
    with app.app_context():
        universe = _rows(app)
        from app.services import waf_artifact_fleet as svc
        row = _row(universe, "web2", "openapi", "dead.json")
        assert row["state"] == "orphan"
        assert row["needed"] is False
        assert svc.stats(universe)["ok"] == sum(
            1 for r in universe["rows"] if r["state"] == "ok")
        assert row["state"] not in svc.VERDICTS


def test_the_library_copy_is_its_own_row_and_says_how_many_scopes_it_serves(
        app, estate):
    """It belongs to no device, so it cannot be folded into a scope — and
    omitting it would hide the copy ``resolve()`` really does serve to
    everyone. The count IS the blast radius of editing it."""
    with app.app_context():
        universe = _rows(app)
        from app.services import waf_artifact_fleet as svc
        row = _row(universe, svc.LIBRARY_SCOPE, "json_schema", "shared.json")
        assert row["state"] == "library"
        assert row["appliance_id"] is None
        assert row["serves"] == 2, "web1 and web2 both resolve to it"


def test_a_scope_served_by_the_library_gets_its_own_sentence_not_the_borrowed_one(
        app, estate):
    """The verdict stays ``borrowed`` — that is what ``device_audit`` and
    ``artifact_stats`` already say about a scope with no copy of its own, and
    this page does not get a private vocabulary.

    But the REMEDY differs, and it has to: telling an operator to go and find
    "another appliance's bytes" when the file is a deliberate shared copy sends
    them looking for a device that is not in the story. ``resolve()`` prefers
    the library over any other appliance, so these really are two branches.
    """
    with app.app_context():
        universe = _rows(app)
        lib = _row(universe, "web1", "json_schema", "shared.json")
        assert lib["state"] == "borrowed"
        assert lib["library_only"] is True
        assert "library" in lib["remedy"]
        # Control: a plain borrowed row keeps the generic sentence, and the
        # scope's own copy is not marked as coming from the library at all.
        plain = _row(universe, "web1", "xml_dtd", "doc.dtd")
        assert plain["state"] == "borrowed" and plain["library_only"] is False
        assert plain["remedy"] != lib["remedy"]
        assert _row(universe, "web1", "openapi", "api-a.json")["library_only"] is False


def test_library_backed_rows_are_counted_apart_from_the_borrowed_total(
        app, estate):
    """Reading N borrowed as "N guesses" overstates the risk by exactly the
    number of them that a deliberate shared copy answers."""
    from app.services import waf_artifact_fleet as svc

    with app.app_context():
        st = svc.stats(_rows(app))
        assert st["by_state"]["borrowed"] == 3, "web1+web2 shared.json, web1 doc.dtd"
        assert st["library_backed"] == 2


# --------------------------------------------------------------------------- #
#  empty                                                                        #
# --------------------------------------------------------------------------- #
def test_a_zero_byte_newest_version_is_flagged_empty_although_it_is_held(
        app, estate):
    """The state stays ``ok`` because every "is it held?" check in the codebase
    says yes — that is exactly why the flag has to exist beside it."""
    with app.app_context():
        row = _row(_rows(app), "web2", "openapi", "hollow.json")
        assert row["state"] == "ok"
        assert row["empty"] is True


def test_an_empty_version_under_a_newer_full_one_is_not_flagged(app, estate):
    """Emptiness is decided on the version ``resolve()`` would serve. An older
    hollow version is not what a clone carries."""
    with app.app_context():
        _put("openapi", "hollow.json", b"{\"now\": true}",
             appliance_id=estate["web2"])
        row = _row(_rows(app), "web2", "openapi", "hollow.json")
        assert row["empty"] is False
        assert row["versions"] == 2


def test_the_empty_count_survives_the_table_filters(app, client, estate):
    """The tiles are the fleet; the filters are the table. A warning a filter
    can hide is a warning that is not there."""
    uid = admin_user_id(app)
    html = _get(client, "/waf/artifacts?scope=web1+%2F+root", uid).get_data(as_text=True)
    assert "hollow.json" not in html, "the filter did not narrow the table"
    data = _get(client, "/waf/api/artifacts.json", uid).get_json()
    assert data["stats"]["empty"] == 1
    assert "Held, but EMPTY" in html
    # ... and the finding's own link reaches exactly the empty rows.
    only_empty = _get(client, "/waf/artifacts?flag=empty", uid).get_data(as_text=True)
    assert "hollow.json" in only_empty
    assert "api-a.json" not in only_empty


# --------------------------------------------------------------------------- #
#  absence is not zero                                                          #
# --------------------------------------------------------------------------- #
def test_a_scope_nobody_swept_is_reported_unswept_not_as_zero_artifacts(
        app, estate):
    with app.app_context():
        universe = _rows(app)
        quiet = [s for s in universe["scopes"] if s["scope"].startswith("web-quiet")][0]
        assert quiet["swept"] is False
        assert quiet["edges"] == 0
        from app.services import waf_artifact_fleet as svc
        assert svc.stats(universe)["unswept"] >= 1


def test_a_scope_with_no_configuration_snapshot_has_an_unknown_policy_total(
        app, estate):
    """``None``, never ``0``: "we have not harvested this box" and "this box
    has no server policies" are different facts and only one of them is true."""
    with app.app_context():
        universe = _rows(app)
        never = [s for s in universe["scopes"]
                 if s["scope"].startswith("web-never")][0]
        assert never["in_config"] is None
        assert never["unwalked"] is None
        # ... and it is excluded from the fleet figure rather than counted as 0.
        from app.services import waf_artifact_fleet as svc
        assert svc.stats(universe)["unknown_scopes"] >= 1


def test_unwalked_counts_the_policies_the_sweep_has_never_looked_at(app, estate):
    """The page's own blind spot, as a number. web1 has three policies in its
    snapshot and two scan rows."""
    with app.app_context():
        universe = _rows(app)
        web1 = [s for s in universe["scopes"] if s["scope"].startswith("web1")][0]
        assert web1["in_config"] == 3
        assert web1["walked"] == 2
        assert web1["unwalked"] == 1


def test_a_policy_deleted_after_its_sweep_cannot_make_unwalked_negative(
        app, estate):
    """A negative backlog is a timing artefact, and printing it sends someone
    hunting for policies that no longer exist."""
    with app.app_context():
        _scan(estate["web1"], "pol-since-deleted-1")
        _scan(estate["web1"], "pol-since-deleted-2")
        universe = _rows(app)
        web1 = [s for s in universe["scopes"] if s["scope"].startswith("web1")][0]
        assert web1["walked"] == 4 and web1["in_config"] == 3
        assert web1["unwalked"] == 0


# --------------------------------------------------------------------------- #
#  the page                                                                     #
# --------------------------------------------------------------------------- #
def test_the_filters_narrow_the_table_and_not_the_tiles(app, client, estate):
    uid = admin_user_id(app)
    everything = _get(client, "/waf/artifacts", uid).get_data(as_text=True)
    blocked = _get(client, "/waf/artifacts?state=blocked", uid).get_data(as_text=True)
    assert "svc.wsdl" in blocked
    assert "api-a.json" not in blocked, "an ok row survived a blocked filter"
    assert "api-a.json" in everything
    # The fleet figure is on BOTH pages, unmoved by the filter.
    for html in (everything, blocked):
        assert "Objects the estate needs" in html


def test_unheld_is_the_compound_of_the_three_not_ok_states(app, client, estate):
    uid = admin_user_id(app)
    html = _get(client, "/waf/artifacts?state=unheld", uid).get_data(as_text=True)
    for name in ("svc.wsdl", "gone.json", "doc.dtd"):
        assert name in html, name
    assert "dead.json" not in html, "an orphan is not an unmet need"
    assert "api-a.json" not in html


def test_the_csv_carries_exactly_the_filtered_rows(app, client, estate):
    uid = admin_user_id(app)
    resp = _get(client, "/waf/artifacts?state=blocked&format=csv", uid)
    assert resp.mimetype == "text/csv"
    rows = list(csv.DictReader(io.StringIO(resp.get_data(as_text=True))))
    assert [r["Object"] for r in rows] == ["svc.wsdl"]
    assert rows[0]["Recoverable from device"].startswith("no")


def test_the_chart_feed_and_the_page_report_the_same_totals(app, client, estate):
    """One author per figure: the doughnut and the tiles are the same numbers,
    not two computations that happen to agree today (safeguards §119)."""
    uid = admin_user_id(app)
    data = _get(client, "/waf/api/artifacts.json", uid).get_json()
    buckets = sum(r["value"] for r in data["readiness"])
    assert buckets == data["stats"]["needed"]
    assert data["stats"]["blocked"] == 1


def test_the_chart_feed_drops_object_types_with_nothing_in_them(app, client, estate):
    """A bar of zeros for a type the fleet does not use reads as a gap. The
    TABLE keeps them — there, an absent row would read as an unsupported
    type."""
    uid = admin_user_id(app)
    data = _get(client, "/waf/api/artifacts.json", uid).get_json()
    labels = {k["label"] for k in data["by_kind"]}
    assert "XML Schema (XSD)" not in labels
    html = _get(client, "/waf/artifacts", uid).get_data(as_text=True)
    assert "XML Schema (XSD)" in html


def test_the_shared_scope_banner_states_this_pages_denominator(app, client, estate):
    """The banner over every /waf page is the DENOMINATOR of the figures under
    it, and this page has to feed it the same universe it counted. Handing the
    header an empty device list leaves a page full of numbers over the sentence
    "0 scopes visible here" — internally contradictory, and green under every
    other guard here because they all read the table."""
    html = _get(client, "/waf/artifacts", admin_user_id(app)).get_data(as_text=True)
    m = re.search(r"<strong>(\d+)</strong>\s*device/ADOM scopes visible here", html)
    assert m, "the shared scope banner did not render"
    assert m.group(1) == "5", "web1, web2, web-maint, web-never, web-quiet"
    # ... and the scope with no snapshot is NAMED there, not dropped.
    assert "never harvested" in html


def test_the_sweep_series_only_carries_scopes_with_a_known_denominator(
        app, client, estate):
    uid = admin_user_id(app)
    data = _get(client, "/waf/api/artifacts.json", uid).get_json()
    unknown = [s for s in data["per_scope"] if s["in_config"] is None]
    assert unknown, "the fixture has a never-harvested scope"
    assert all(s["unwalked"] is None for s in unknown)
