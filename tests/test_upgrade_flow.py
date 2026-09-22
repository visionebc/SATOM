"""The bulk upgrade flow — one pre-upgrade, N pieces of evidence, one change.

Three defects are guarded here, and the first is the one that made the other
two unreachable:

1. **There were two implementations of "upgrade prep", and the multi-target
   one stored nothing.** ``views.appliances.upgrade_prep_run`` called
   ``upgrade.prepare()`` (backup + health + maintenance permission + service
   probes) and persisted an ``UpgradePrep``. ``scheduled_actions.
   _do_upgrade_prep`` — the ONLY path that accepts more than one device —
   called ``create_backup()`` + ``status_check()`` and persisted nothing.
   Neither failed. Pre-flighting a whole maintenance window simply produced no
   evidence any change request could cite, which is why "pre-upgrade in bulk,
   then raise the change" could not be built.

2. **A change request could cite exactly one run.** ``ChangeRequest.prep_id``
   is scalar and the create path dropped any run whose appliance was not among
   the devices — so a twenty-device window carried one device's baseline and
   an approver reading "the pre-upgrade passed" was told the truth about one
   box and nothing about nineteen.

3. **The frozen inventory came off that single run**, and the customer-impact
   spreadsheet is generated from exactly that field — so the outage warning
   under-stated itself by however many devices were not the cited one.

Nothing raised for any of the three. That is the whole reason they lasted: a
silently narrow document reads exactly like a complete one.
"""
from __future__ import annotations

import json
import os
from datetime import datetime

import pytest

from conftest import admin_user_id, login

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- #
#  helpers                                                                      #
# --------------------------------------------------------------------------- #
def _mk_appliance(name, *, kind="fortiweb", host=None):
    from app.extensions import db
    from app.models import Appliance

    a = Appliance(name=name, host=host or f"10.0.0.{abs(hash(name)) % 200 + 20}",
                  port=443, kind=kind, username="admin")
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


def _mk_prep(appliance, *, ok=True, inventory=None, summary="backup ok"):
    from app.extensions import db
    from app.models import UpgradePrep

    prep = UpgradePrep(
        appliance_id=appliance.id, created_by="operator", ok=ok,
        summary=summary, result=json.dumps({"firmware": "7.6.8"}),
        inventory=json.dumps(inventory if inventory is not None else []),
        created_at=datetime.utcnow())
    db.session.add(prep)
    db.session.commit()
    return prep


def _mk_cr(device_ids):
    from app.extensions import db
    from app.models import ChangeRequest

    cr = ChangeRequest(title="window", action="upgrade", status="draft",
                       device_ids=json.dumps(device_ids))
    db.session.add(cr)
    db.session.commit()
    return cr


# =========================================================================== #
#  1. ONE implementation of the pre-upgrade                                    #
# =========================================================================== #
def test_the_scheduled_action_delegates_to_the_same_runner_as_the_page(app,
                                                                      monkeypatch):
    """The multi-target path must PERSIST a run, like the per-device page.

    This is the defect, stated as a test: before the fix the scheduled action
    took a backup and a health read and left no ``UpgradePrep`` behind, so a
    sweep over a maintenance window produced zero citable evidence.
    """
    from app.extensions import db
    from app.models import UpgradePrep
    from app.services import prep_store, scheduled_actions

    with app.app_context():
        a = _mk_appliance("sched-box")
        monkeypatch.setattr(
            "app.services.upgrade.prepare",
            lambda appliance, **kw: {"firmware": "7.6.8",
                                     "backup": {"ok": True},
                                     "health": {"ok": True}})
        monkeypatch.setattr(
            "app.services.change_requests.affected_policies",
            lambda ids, **kw: [{"device": "sched-box", "device_id": ids[0],
                                "policy": "shop"}])

        before = UpgradePrep.query.count()
        out = scheduled_actions._do_upgrade_prep(a, False)
        after = UpgradePrep.query.filter_by(appliance_id=a.id).all()

        assert out["ok"] is True
        assert UpgradePrep.query.count() == before + 1, \
            "the scheduled pre-upgrade left no evidence behind"
        assert len(after) == 1
        assert after[0].inventory_list, \
            "the stored run carries no affected-service inventory"
        assert f"#{after[0].id}" in out["log"], \
            "the run's log does not name the row it stored"
        db.session.remove()


def test_a_dry_run_touches_neither_the_device_nor_the_table(app):
    from app.models import UpgradePrep
    from app.services import scheduled_actions

    with app.app_context():
        a = _mk_appliance("dry-box")
        out = scheduled_actions._do_upgrade_prep(a, True)
        assert out["ok"] is True
        assert "dry-run" in out["summary"]
        assert UpgradePrep.query.count() == 0


def test_a_run_that_cannot_be_stored_says_so_instead_of_claiming_evidence(app,
                                                                         monkeypatch):
    """The calls went out to a live device; only the row failed. Reporting
    "stored" here sends somebody looking for evidence that is not there —
    hours later, inside the window."""
    from app.services import prep_store, scheduled_actions

    with app.app_context():
        a = _mk_appliance("nostore-box")
        monkeypatch.setattr("app.services.upgrade.prepare",
                            lambda appliance, **kw: {"backup": {"ok": True}})
        monkeypatch.setattr("app.services.prep_store.record",
                            lambda *args, **kw: (_ for _ in ()).throw(
                                RuntimeError("disk full")))
        out = scheduled_actions._do_upgrade_prep(a, False)
        assert "NOT STORED" in out["log"]


def test_run_for_returns_the_result_even_when_persistence_fails(app, monkeypatch):
    from app.services import prep_store

    with app.app_context():
        a = _mk_appliance("keepresult-box")
        seen = []
        monkeypatch.setattr("app.services.upgrade.prepare",
                            lambda appliance, **kw: {"firmware": "7.6.9"})
        monkeypatch.setattr("app.services.prep_store.record",
                            lambda *args, **kw: (_ for _ in ()).throw(
                                RuntimeError("nope")))
        result, prep = prep_store.run_for(a, on_store_error=seen.append)
        assert result == {"firmware": "7.6.9"}
        assert prep is None
        assert len(seen) == 1, "the storage failure was swallowed silently"


# =========================================================================== #
#  2. the sweep: one row per appliance, ALWAYS                                 #
# =========================================================================== #
def test_one_dead_appliance_does_not_end_the_sweep(app, monkeypatch):
    """A sweep over three boxes returns THREE rows even when the middle one
    raises. Stopping would leave the rest of the window un-prepared; dropping
    the row would let a sweep over twenty return nineteen and read as
    complete."""
    from app.services import prep_store

    with app.app_context():
        boxes = [_mk_appliance(f"sweep-{i}") for i in range(3)]

        def _prepare(appliance, **kw):
            if appliance.name == "sweep-1":
                raise RuntimeError("connection refused")
            return {"firmware": "7.6.8", "backup": {"ok": True}}

        monkeypatch.setattr("app.services.upgrade.prepare", _prepare)
        monkeypatch.setattr("app.services.change_requests.affected_policies",
                            lambda ids, **kw: [])

        rows = prep_store.run_bulk(boxes)
        assert len(rows) == 3, "the sweep dropped an appliance"
        assert [r["name"] for r in rows] == ["sweep-0", "sweep-1", "sweep-2"]
        bad = [r for r in rows if r["name"] == "sweep-1"][0]
        assert bad["ok"] is False and bad["stored"] is False
        assert "connection refused" in bad["error"]
        assert all(r["stored"] for r in rows if r["name"] != "sweep-1")


# =========================================================================== #
#  3. N:N binding                                                              #
# =========================================================================== #
def test_a_change_can_rest_on_every_device_it_covers(app):
    from app.models import CrPrep
    from app.services import prep_store

    with app.app_context():
        boxes = [_mk_appliance(f"bind-{i}") for i in range(3)]
        preps = [_mk_prep(b) for b in boxes]
        cr = _mk_cr([b.id for b in boxes])

        prep_store.bind_many(cr, preps)
        assert CrPrep.query.filter_by(cr_id=cr.id).count() == 3
        assert [p.id for p in prep_store.preps_for_cr(cr)] == [p.id for p in preps]
        assert {p.cr_id for p in preps} == {cr.id}


def test_binding_is_idempotent_and_never_repoints_an_already_printed_document(app):
    """``cr.prep_id`` keeps naming the FIRST run bound. A document already
    printed cites a specific run; letting a later binding move that pointer
    would silently change what an approved document claims to rest on."""
    from app.models import CrPrep
    from app.services import prep_store

    with app.app_context():
        a, b = _mk_appliance("first"), _mk_appliance("second")
        p1, p2 = _mk_prep(a), _mk_prep(b)
        cr = _mk_cr([a.id, b.id])

        prep_store.bind_many(cr, [p1])
        assert cr.prep_id == p1.id
        prep_store.bind_many(cr, [p1, p2])          # p1 again + a new one
        assert CrPrep.query.filter_by(cr_id=cr.id).count() == 2, \
            "the same run was bound twice — a double count in the export"
        assert cr.prep_id == p1.id, "the scalar pointer moved to a later run"


def test_a_change_raised_before_the_bridge_existed_still_shows_its_evidence(app):
    """Legacy rows have no ``cr_preps`` entry. Returning [] for them would make
    a change that DID carry evidence render as one that never had any."""
    from app.services import prep_store

    with app.app_context():
        a = _mk_appliance("legacy")
        prep = _mk_prep(a)
        cr = _mk_cr([a.id])
        cr.prep_id = prep.id                    # the old 1:1 link, no bridge row
        from app.extensions import db
        db.session.commit()

        assert [p.id for p in prep_store.preps_for_cr(cr)] == [prep.id]


# =========================================================================== #
#  4. the merged inventory                                                     #
# =========================================================================== #
def test_the_inventory_merges_across_runs_without_double_counting(app):
    from app.services import prep_store

    with app.app_context():
        a, b = _mk_appliance("inv-a"), _mk_appliance("inv-b")
        # 'shop' exists on BOTH devices — a legitimate name collision that must
        # survive the de-duplication, and 'a' was pre-flighted twice, which
        # must not.
        p1 = _mk_prep(a, inventory=[{"device": "inv-a", "device_id": a.id,
                                     "policy": "shop"}])
        p1b = _mk_prep(a, inventory=[{"device": "inv-a", "device_id": a.id,
                                      "policy": "shop"}])
        p2 = _mk_prep(b, inventory=[{"device": "inv-b", "device_id": b.id,
                                     "policy": "shop"}])

        rows = prep_store.merged_inventory([p1, p1b, p2])
        assert len(rows) == 2, \
            "a re-run double-counted its services, overstating the outage"
        assert {r["device"] for r in rows} == {"inv-a", "inv-b"}, \
            "two devices publishing the same policy name collapsed into one"


def test_latest_for_many_returns_the_newest_run_per_appliance(app):
    from app.services import prep_store

    with app.app_context():
        a, b = _mk_appliance("latest-a"), _mk_appliance("latest-b")
        _mk_prep(a, summary="older")
        newest = _mk_prep(a, summary="newer")
        pb = _mk_prep(b)

        out = prep_store.latest_for_many([a.id, b.id, 999999])
        assert out[a.id].id == newest.id, "an older run shadowed the newest"
        assert out[b.id].id == pb.id
        assert 999999 not in out


# =========================================================================== #
#  5. the create path: per-RUN device check, merged freeze                     #
# =========================================================================== #
def test_the_change_form_binds_every_run_and_freezes_all_of_them(app, client):
    from app.models import ChangeRequest, CrPrep
    from app.services import prep_store

    with app.app_context():
        a, b = _mk_appliance("form-a"), _mk_appliance("form-b")
        pa = _mk_prep(a, inventory=[{"device": "form-a", "device_id": a.id,
                                     "policy": "pa"}])
        pb = _mk_prep(b, inventory=[{"device": "form-b", "device_id": b.id,
                                     "policy": "pb"}])
        ids = (a.id, b.id, pa.id, pb.id)

    login(client, admin_user_id(app))
    resp = client.post("/web/change-requests/new", data={
        "title": "bulk window", "action": "upgrade", "risk": "medium",
        "device_ids": [str(ids[0]), str(ids[1])],
        "prep_ids": [str(ids[2]), str(ids[3])],
    }, follow_redirects=False)
    assert resp.status_code in (302, 303)

    with app.app_context():
        cr = ChangeRequest.query.order_by(ChangeRequest.id.desc()).first()
        assert CrPrep.query.filter_by(cr_id=cr.id).count() == 2, \
            "the change bound fewer runs than the devices it covers"
        frozen = json.loads(cr.policies)
        assert {r["policy"] for r in frozen} == {"pa", "pb"}, \
            "the frozen inventory covers only one device — the customer-impact " \
            "export is generated from exactly this field"


def test_a_run_belonging_to_another_device_is_refused_per_run(app, client):
    """The check is PER RUN. A bulk change must not inherit permission for
    twenty devices from the one run that happened to match."""
    from app.models import ChangeRequest, CrPrep

    with app.app_context():
        a, b = _mk_appliance("mine"), _mk_appliance("theirs")
        mine = _mk_prep(a, inventory=[{"device": "mine", "device_id": a.id,
                                       "policy": "ok"}])
        theirs = _mk_prep(b, inventory=[{"device": "theirs", "device_id": b.id,
                                         "policy": "leak"}])
        ids = (a.id, mine.id, theirs.id)

    login(client, admin_user_id(app))
    client.post("/web/change-requests/new", data={
        "title": "single device", "action": "upgrade", "risk": "medium",
        "device_ids": [str(ids[0])],
        "prep_ids": [str(ids[1]), str(ids[2])],
    })

    with app.app_context():
        cr = ChangeRequest.query.order_by(ChangeRequest.id.desc()).first()
        bound = CrPrep.query.filter_by(cr_id=cr.id).all()
        assert [r.prep_id for r in bound] == [ids[1]], \
            "a change certified a machine it does not target"
        assert "leak" not in cr.policies


def test_the_singular_prep_id_field_still_works(app, client):
    """Existing links, forms and tests post ``prep_id``. It is the
    one-element case, not a second code path."""
    from app.models import ChangeRequest, CrPrep

    with app.app_context():
        a = _mk_appliance("compat")
        prep = _mk_prep(a)
        ids = (a.id, prep.id)

    login(client, admin_user_id(app))
    client.post("/web/change-requests/new", data={
        "title": "compat", "action": "upgrade", "risk": "medium",
        "device_ids": [str(ids[0])], "prep_id": str(ids[1]),
    })

    with app.app_context():
        cr = ChangeRequest.query.order_by(ChangeRequest.id.desc()).first()
        assert CrPrep.query.filter_by(cr_id=cr.id).count() == 1
        assert cr.prep_id == ids[1]


# =========================================================================== #
#  6. the page                                                                 #
# =========================================================================== #
def test_the_supported_products_are_derived_from_the_action_not_re_listed(app):
    """A hand-kept copy is how this page would come to offer a product the
    pre-upgrade cannot run against — the sweep would fire and every device
    would raise."""
    from app.services import scheduled_actions as sa
    from app.views import upgrade_flow

    assert upgrade_flow.prep_kinds() == \
        tuple(sa.ALL_ACTIONS["upgrade_prep"].products)


def test_the_page_lists_eligible_devices_and_their_latest_run(app, client):
    with app.app_context():
        a = _mk_appliance("page-fw", kind="fortiweb")
        _mk_appliance("page-faz", kind="fortianalyzer")
        _mk_prep(a, ok=False, summary="health FAILED")

    login(client, admin_user_id(app))
    resp = client.get("/web/upgrade-flow/")
    body = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "page-fw" in body
    assert "page-faz" not in body, \
        "a product the pre-upgrade cannot run against is on the picker"
    assert "not clean" in body, "a failed verdict rendered as a pass"


def test_the_page_is_light_chrome(app, client):
    """SATOM has no dark theme. A translucent slate card renders here as an
    opaque grey slab and dark-theme pastel pills land at ~1.4:1 on white."""
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/").get_data(as_text=True)
    for banned in ("backdrop-filter", "rgba(30,41,59", "#080d1a", "#0f172a"):
        assert banned not in body, f"dark-theme chrome leaked in: {banned}"


def test_an_oversized_sweep_starts_nothing_and_says_how_many(app, client,
                                                             monkeypatch):
    """Silently pre-flighting the first N of a larger selection and reporting
    success is how devices enter a window with no baseline.

    The appliances are REAL. An earlier version of this test posted invented
    ids, which meant a truncating implementation still fell into the "one or
    more do not exist" branch and never swept — so the test passed against the
    very defect it names. With real devices the cap is the only thing that can
    stop it.
    """
    from app.views import upgrade_flow

    n = upgrade_flow.MAX_SWEEP + 1
    with app.app_context():
        ids = [_mk_appliance(f"cap-{i}", host=f"10.1.{i // 250}.{i % 250}").id
               for i in range(n)]

    called = []
    monkeypatch.setattr("app.services.prep_store.run_bulk",
                        lambda *a, **kw: called.append(1) or [])
    login(client, admin_user_id(app))
    resp = client.post("/web/upgrade-flow/prep",
                       data={"device_ids": [str(i) for i in ids]},
                       follow_redirects=True)
    body = resp.get_data(as_text=True)
    assert not called, "the sweep ran despite exceeding the cap"
    assert "nothing was started" in body, \
        "the selection was truncated instead of refused"
    assert str(n) in body, "the refusal does not name how many were selected"


def test_an_invisible_device_id_is_not_backed_up_because_it_was_posted(app,
                                                                      client,
                                                                      monkeypatch):
    called = []
    monkeypatch.setattr("app.services.prep_store.run_bulk",
                        lambda *a, **kw: called.append(1) or [])
    login(client, admin_user_id(app))
    client.post("/web/upgrade-flow/prep", data={"device_ids": ["424242"]},
                follow_redirects=True)
    assert not called, "a device that does not exist was pre-flighted"


# =========================================================================== #
#  7. the menu                                                                 #
# =========================================================================== #
def test_the_automation_menu_offers_the_flow_where_it_can_run():
    """And ONLY there: in the FortiAnalyzer / FortiAuthenticator ADOMs the
    picker can only ever be empty, which reads as "this fleet has no
    appliances" rather than "this stage does not apply here"."""
    nav = os.path.join(REPO, "app", "templates", "partials",
                       "nav_automation.html")
    with open(nav, encoding="utf-8") as fh:
        text = fh.read()
    assert "upgrade_flow.index" in text
    assert "'fortiweb', 'fortiadc'" in text, \
        "the menu entry is not scoped to the products the pre-upgrade supports"
    assert "can('backup')" in text, \
        "the link is not gated on the permission the page requires — it leads " \
        "to a 403"
    assert "'upgrade_flow'" in text.split("_auto_bps")[1][:200], \
        "the group does not open when the flow is the active page"

import re  # noqa: E402  (appended section)

# =========================================================================== #
#  8. the hand-off from a single appliance's pre-upgrade page                   #
# =========================================================================== #
#  ``/appliances/<id>/upgrade/prep`` asks whether the box is part of a full
#  upgrade window and, ONLY on "yes", opens this page with ``?device=<id>``.
#  Two ways for that to be wrong, neither of which raises:
#
#    * the wrong row comes back ticked — a maintenance window silently gains an
#      appliance nobody chose;
#    * NOTHING comes back ticked and the page says nothing — indistinguishable
#      from a page opened by hand, so the operator ticks a box themselves and
#      never learns the link pointed somewhere this console cannot act.
#
#  Both are measured on the RENDERED page, per row, never by counting the word
#  "checked" in the document: the stage-1 select-all script contains
#  ``.checked`` on its own.
def _checked_ids(html):
    """Ids whose device checkbox came back ticked, read off the markup."""
    return set(re.findall(r'name="device_ids" value="(\d+)"[^>]*checked', html))


def test_the_hand_off_preselects_exactly_the_device_it_names(app, client):
    with app.app_context():
        a = _mk_appliance("handoff-a", kind="fortiweb")
        b = _mk_appliance("handoff-b", kind="fortiweb")
        aid, bid = a.id, b.id

    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?device=%d" % aid).get_data(as_text=True)
    assert _checked_ids(body) == {str(aid)}, \
        "the hand-off ticked something other than the appliance it came from"
    assert str(bid) not in _checked_ids(body)
    assert "Pre-selected from its pre-upgrade page" in body, \
        "the row is ticked but unnamed — in sixty rows that is not an answer " \
        "to 'did the link bring the right box'"
    # The name is read out of the BANNER. Asserting it against the whole page
    # proves nothing: every eligible appliance is in the table below.
    banner = body.split("Pre-selected from its pre-upgrade page", 1)[1][:400]
    assert "handoff-a" in banner, "the banner does not say which box it ticked"
    assert "handoff-b" not in banner


def test_an_id_this_page_cannot_pre_flight_is_reported_not_ignored(app, client):
    """A FortiAnalyzer is a real, visible appliance the pre-upgrade does not
    support. Arriving with its id must not read like arriving with none."""
    with app.app_context():
        faz = _mk_appliance("handoff-faz", kind="fortianalyzer")
        fid = faz.id

    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?device=%d" % fid).get_data(as_text=True)
    assert _checked_ids(body) == set(), "an unsupported product was ticked"
    assert "is not on this list" in body, \
        "a hand-off that resolved to nothing rendered as an ordinary visit"
    assert "device=%d" % fid in body, \
        "the complaint does not say WHICH id failed to resolve"


def test_a_device_parameter_that_is_not_a_number_is_reported_too(app, client):
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?device=abc").get_data(as_text=True)
    assert _checked_ids(body) == set()
    assert "is not on this list" in body
    assert "Pre-selected from its pre-upgrade page" not in body


def test_without_the_parameter_nothing_is_preselected_and_nothing_is_claimed(
        app, client):
    with app.app_context():
        _mk_appliance("handoff-plain", kind="fortiweb")

    login(client, admin_user_id(app))
    for url in ("/web/upgrade-flow/", "/web/upgrade-flow/?device="):
        body = client.get(url).get_data(as_text=True)
        assert _checked_ids(body) == set(), url
        assert "Pre-selected from its pre-upgrade page" not in body, url
        assert "is not on this list" not in body, url


def test_the_preselection_resolves_against_the_rendered_list(app):
    """Against the LIST, never the database: an id the operator cannot see
    must not be able to tick a row here merely because it exists."""
    from app.views.upgrade_flow import preselect_device

    class _D:
        def __init__(self, i):
            self.id = i

    devices = [_D(7), _D(9)]
    assert preselect_device("9", devices) == (9, None)
    assert preselect_device("8", devices) == (None, "8"), \
        "an id outside the rendered list resolved to a selection"
    assert preselect_device("x", devices) == (None, "x")
    assert preselect_device("", devices) == (None, None)
    assert preselect_device(None, devices) == (None, None)


def test_the_page_names_the_preselection_kwarg_to_the_template(app, client):
    """render_template ENUMERATES its kwargs here. A value the view computes
    but does not pass simply never reaches the page, with every assertion on
    the resolver still green — which is how a banner gets written, reviewed
    and shipped without ever rendering."""
    with app.app_context():
        a = _mk_appliance("handoff-kwarg", kind="fortiweb")
        aid = a.id

    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?device=%d" % aid).get_data(as_text=True)
    assert "handoff-kwarg" in body and _checked_ids(body) == {str(aid)}


# =========================================================================== #
#  6. The hand-off carries the RUN, not only the appliance                     #
# =========================================================================== #
#  A pre-flight page hands off with "this box, and THIS run of it". Carrying
#  only the appliance made the flow pick whatever was newest — and the newest
#  run is very often a re-run made to test a fix, i.e. precisely the one the
#  operator did NOT mean to sign the change against. Both readings render an
#  identical page.
def _chooser(body, dev_id):
    import re
    m = re.search(r'<select[^>]*uf-prep[^>]*data-dev="%d"[^>]*>(.*?)</select>'
                  % dev_id, body, re.S)
    return m.group(1) if m else ""


def _selected_run(body, dev_id):
    import re
    return re.findall(r'<option value="(\d*)" selected>', _chooser(body, dev_id))


def test_a_prep_hand_off_cites_that_run_even_when_it_is_not_the_newest(app,
                                                                      client):
    with app.app_context():
        a = _mk_appliance("evidence-pick", kind="fortiweb")
        old = _mk_prep(a, summary="the run we mean")
        _mk_prep(a, summary="a re-run made afterwards")
        aid, oid = a.id, old.id

    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?device=%d&prep=%d"
                      % (aid, oid)).get_data(as_text=True)
    assert _selected_run(body, aid) == [str(oid)], \
        "the flow cited the newest run instead of the one the link named"
    assert "#%d" % oid in body and "citing its recorded pre-upgrade run" in body, \
        "the page does not SAY which run it is citing — a selection buried " \
        "in one of sixty rows is not an answer to 'did it bring the right one'"


def test_without_a_prep_the_newest_run_is_proposed_not_imposed(app, client):
    with app.app_context():
        a = _mk_appliance("evidence-default", kind="fortiweb")
        _mk_prep(a, summary="older")
        new = _mk_prep(a, summary="newer")
        aid, nid = a.id, new.id

    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?device=%d" % aid).get_data(as_text=True)
    assert _selected_run(body, aid) == [str(nid)]
    # Every run is offered, and so is "cite nothing" — an appliance with no
    # baseline is a real, sayable state, not an absence of options.
    assert _chooser(body, aid).count("<option") >= 3, \
        "the operator cannot choose a different run, so the default is imposed"
    assert '<option value="">' in _chooser(body, aid), \
        "there is no way to cite no run for an appliance the change covers"


def test_a_run_belonging_to_another_appliance_is_refused_and_reported(app,
                                                                     client):
    """Signed-against-the-wrong-box is the failure this guards. Silence would
    leave the change citing whatever was newest while the operator followed a
    link that named something else."""
    with app.app_context():
        a = _mk_appliance("evidence-mine", kind="fortiweb")
        other = _mk_appliance("evidence-theirs", kind="fortiweb")
        theirs = _mk_prep(other, summary="not this box")
        mine = _mk_prep(a, summary="this box")
        aid, tid, mid = a.id, theirs.id, mine.id

    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?device=%d&prep=%d"
                      % (aid, tid)).get_data(as_text=True)
    assert _selected_run(body, aid) == [str(mid)], \
        "another appliance's run was pre-chosen as this one's evidence"
    assert "is not one of that appliance" in body, \
        "the mismatch was swallowed; it must read differently from arriving " \
        "with no run at all"
    assert "prep=%d" % tid in body, "the complaint does not name the run"


def test_a_prep_parameter_that_is_not_a_number_is_reported_too(app, client):
    with app.app_context():
        a = _mk_appliance("evidence-junk", kind="fortiweb")
        _mk_prep(a)
        aid = a.id

    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?device=%d&prep=zz"
                      % aid).get_data(as_text=True)
    assert "is not one of that appliance" in body
    assert "prep=zz" in body


def test_the_prep_preselection_resolves_against_the_rendered_runs(app):
    from app.views.upgrade_flow import preselect_prep

    class _R:
        def __init__(self, i):
            self.id = i

    runs = {4: [_R(11), _R(12)]}
    assert preselect_prep("12", 4, runs) == (12, None)
    assert preselect_prep("99", 4, runs) == (None, "99")
    assert preselect_prep("11", 5, runs) == (None, "11"), \
        "a run was accepted for an appliance whose rows it is not among"
    assert preselect_prep("11", None, runs) == (None, "11"), \
        "a run was accepted with no appliance to belong to"
    assert preselect_prep("x", 4, runs) == (None, "x")
    assert preselect_prep("", 4, runs) == (None, None)
    assert preselect_prep(None, 4, runs) == (None, None)


def test_the_page_names_the_prep_kwargs_to_the_template(app, client):
    """render_template ENUMERATES its kwargs. A value the view computes and
    does not pass reaches nothing, with every resolver assertion still green."""
    with app.app_context():
        a = _mk_appliance("evidence-kwarg", kind="fortiweb")
        p = _mk_prep(a)
        aid, pid = a.id, p.id

    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?device=%d&prep=%d"
                      % (aid, pid)).get_data(as_text=True)
    assert "citing its recorded pre-upgrade run" in body
    body2 = client.get("/web/upgrade-flow/?device=%d&prep=4242"
                       % aid).get_data(as_text=True)
    assert "is not one of that appliance" in body2


def test_every_recorded_run_is_offered_per_appliance_and_capped_there(app):
    """Capped PER APPLIANCE, not by a LIMIT on the query: one busy box would
    otherwise spend the whole budget and the rest would read 'never run'."""
    from app.services import prep_store

    with app.app_context():
        busy = _mk_appliance("evidence-busy", kind="fortiweb")
        quiet = _mk_appliance("evidence-quiet", kind="fortiweb")
        for _ in range(5):
            _mk_prep(busy)
        q = _mk_prep(quiet)
        rows = prep_store.recent_for_many([busy.id, quiet.id], 2)
        assert len(rows[busy.id]) == 2, "the per-appliance cap is not applied"
        assert rows[quiet.id] and rows[quiet.id][0].id == q.id, \
            "a busy appliance consumed another one's rows"
        ids = [r.id for r in rows[busy.id]]
        assert ids == sorted(ids, reverse=True), "runs are not newest-first"
        assert prep_store.recent_for_many([], 2) == {}
        assert prep_store.recent_for_many(["x"], 2) == {}


# =========================================================================== #
#  7. Stage 2 asks everything a change request is                              #
# =========================================================================== #
def test_stage_two_carries_the_whole_change_request_field_set(app, client):
    """A windowed change used to come out with no owner, nobody notified and
    manual approval by default — differences nobody chose, on the path meant
    for the larger job."""
    with app.app_context():
        _mk_appliance("cr-fields", kind="fortiweb")

    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/").get_data(as_text=True)
    for field in ('name="owner"', 'name="notify_to"', 'name="approval_mode"'):
        assert field in body, "stage 2 does not ask for %s" % field
    assert 'value="external"' in body, "the fail-closed approval mode is absent"


def test_stage_two_actually_stores_owner_notify_and_approval(app, client):
    """The fields must reach the change, not merely appear. An input whose
    name the create path ignores renders identically to one it honours."""
    from app.models import ChangeRequest

    with app.app_context():
        a = _mk_appliance("cr-fields-post", kind="fortiweb")
        aid = a.id

    login(client, admin_user_id(app))
    client.post("/web/change-requests/new", data={
        "title": "windowed upgrade", "action": "upgrade", "risk": "medium",
        "reason": "r", "rollback": "b", "device_ids": [str(aid)],
        "owner": "kim", "notify_to": "ops@example.com",
        "approval_mode": "external",
    }, follow_redirects=True)
    with app.app_context():
        cr = (ChangeRequest.query.filter_by(title="windowed upgrade")
              .order_by(ChangeRequest.id.desc()).first())
        assert cr is not None
        assert cr.owner == "kim"
        assert cr.notify_to == "ops@example.com"
        assert cr.approval_mode == "external"


def test_the_waves_path_carries_the_same_three_fields(app, client):
    """A wave that drops them is silently the un-owned, un-notified,
    locally-approved variant of the same change."""
    import inspect

    from app.views import upgrade_flow as uf

    src = inspect.getsource(uf.waves)
    for field in ("'owner'", "'notify_to'", "'approval_mode'"):
        assert field in src, "waves() drops %s" % field

    with app.app_context():
        a = _mk_appliance("wave-fields", kind="fortiweb")
        aid = a.id
    login(client, admin_user_id(app))
    from app.models import ChangeRequest
    client.post("/web/upgrade-flow/waves", data={
        "device_ids": [str(aid)], "wave_size": "1", "title": "waved",
        "risk": "low", "reason": "r", "rollback": "b",
        "owner": "kim", "notify_to": "ops@example.com",
        "approval_mode": "external",
    }, follow_redirects=True)
    with app.app_context():
        cr = (ChangeRequest.query.filter(ChangeRequest.title.like("waved%"))
              .order_by(ChangeRequest.id.desc()).first())
        assert cr is not None, "no wave was raised"
        assert (cr.owner, cr.notify_to, cr.approval_mode) == \
            ("kim", "ops@example.com", "external")


def test_the_customer_impact_and_execution_card_is_gone(app, client):
    """Removed at the operator's request: both live on the change itself and
    the register was a second copy of Change Requests."""
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/").get_data(as_text=True)
    assert "Customer impact and execution" not in body
    assert ">3\u20134<" not in body, "the 3-4 stage badge is still rendered"


# --------------------------------------------------------------------------- #
#  stage 2 IS the change request — not half of it                              #
# --------------------------------------------------------------------------- #
def _stage_two(client):
    """The markup of the stage-2 form only, never the whole page.

    Asserting against the page would let the SINGLE-change form's own fields
    (reachable from the nav) or the waves mirrors answer a question about stage
    2, which is how a field can be "present" on a card that does not have it.

    Bounded at this form's own ``</form>``, and with every element BOUND
    ELSEWHERE stripped out. The waves fields now sit INSIDE this card carrying
    ``form="uf-waves"``, and ``window_start`` exists in both — a slice that
    kept them would let a waves input answer a question about the single
    change. Splitting at ``id="uf-waves"`` no longer bounds anything: that form
    element is hoisted ABOVE this one, so the split would return the rest of
    the page and every assertion below would widen in silence.
    """
    body = client.get("/web/upgrade-flow/").get_data(as_text=True)
    assert 'id="uf-cr"' in body, "stage-2 form is missing entirely"
    head, rest = body.split('id="uf-cr"', 1)
    form = rest.split("</form>", 1)[0]
    form = re.sub(r'<[^>]*\bform="uf-waves"[^>]*>', "", form)
    return body, form


def test_stage_two_asks_everything_the_single_change_form_asks(app, client):
    """Every field ``change_requests.new`` reads from its POST is on this card.

    The window used to be raised here with no owner, no completion notice, no
    approval mode and no change type in sight — defaults nobody chose, on the
    path meant for the larger and riskier job. The list is the CREATE path's
    own, so a field added there fails here instead of quietly never being
    asked on this one.
    """
    login(client, admin_user_id(app))
    _, form = _stage_two(client)
    for field in ("doc_lang", "action", "risk", "title", "reason", "rollback",
                  "owner", "notify_to", "approval_mode",
                  "window_start", "window_end"):
        assert 'name="%s"' % field in form, \
            "stage 2 never asks for %s" % field


def test_the_wording_is_inside_stage_two_not_floating_above_it(app, client):
    """It used to be an UNNUMBERED card between stages 1 and 2.

    Half of what raising the change takes sat outside the card numbered 2, so
    the badge named half the work and the rest read as a detour. One heading,
    and it comes after the badge.
    """
    login(client, admin_user_id(app))
    body, _ = _stage_two(client)
    assert body.count("Proposed wording") == 1, \
        "two wording blocks is two authors of the same document"
    badge = body.index('me-2">2</span>')
    assert body.index("Proposed wording") > badge, \
        "the wording still renders above the stage-2 badge"
    # 2b is not a stage any more. The waves fields live INSIDE this card,
    # after its own submit, at the operator's request: "one window or several"
    # is the same stage answering a second question over the same ticks, the
    # same wording and the same owner. What used to be guarded here — "2b comes
    # after 2" — guarded a card that no longer exists, and the form element it
    # named is now hoisted ABOVE this one on purpose (an empty form outside the
    # card, its fields bound in by form="uf-waves").
    assert not re.search(r">\s*2b\s*<", body), \
        "the waves block is numbered as a stage of its own again"
    assert body.index("Or split the same selection into waves") > \
        body.index("Raise one change request"), \
        "the waves block must come after stage 2's own submit, inside its card"


def test_the_change_type_is_named_on_the_page(app, client):
    """Posted as a hidden field and shown nowhere: a value the operator signs
    for and cannot read. Named, with its key, next to the risk it carries."""
    login(client, admin_user_id(app))
    from app.views.upgrade_flow import CR_ACTION, cr_draft_context

    _, form = _stage_two(client)
    with app.app_context():
        label = cr_draft_context()["labels"].get("en", "")
    assert CR_ACTION in form
    if label:
        assert label in form, "the change type is posted but never displayed"


def test_stage_two_names_the_appliances_instead_of_counting_them(app, client):
    """"4 appliance(s) selected" answers neither half of the question the
    operator arrived with: WHICH boxes, and which run each is signed against.

    The names are built client-side from stage 1's ticks, so what is guarded
    here is that the containers exist and that the hidden fields are NOT the
    only place the selection appears.
    """
    login(client, admin_user_id(app))
    body, form = _stage_two(client)
    assert 'id="uf-cr-chips"' in form, "no visible list of covered appliances"
    assert 'id="uf-cr-fields"' in form, "the posted fields lost their box"
    assert 'id="uf-cr-empty"' in form, \
        "an empty selection must say so, not render as nothing"
    # Built with textContent, never innerHTML: an appliance name is operator
    # data and this page has a CSP nonce precisely because that matters.
    assert "chip.textContent" in body
    assert "chips.innerHTML = ''" in body, "the list is never cleared"


def test_the_hand_off_link_carries_the_adom_it_was_pressed_in(app, client):
    """Two spellings of one link is the drift, not the scope.

    The table row's link carried ``_adom`` and the button rendered after a run
    finished did not, so the same operator pressing what looks like the same
    control landed in Global — different chrome, different nav, different
    visible inventory — depending on which one they pressed.
    """
    from app.views.appliances import _prep_payload

    with app.app_context():
        a = _mk_appliance("adom-link", kind="fortiweb")
        prep = _mk_prep(a)
        pid, aid = prep.id, a.id

    # NO nested app context: `g` belongs to the app context, so pushing a
    # second one inside the request throws the ADOM away and the guard would
    # be measuring its own scaffolding.
    from app.models import UpgradePrep
    with app.test_request_context("/appliances/%d/upgrade/prep" % aid):
        from flask import g
        g.product = "fortiweb"
        url = _prep_payload(UpgradePrep.query.get(pid))["cr_url"]
    assert "_adom=fortiweb" in url, "the button drops the ADOM: %s" % url
    assert "device=%d" % aid in url and "prep=%d" % pid in url

    # An unresolved scope omits the parameter rather than sending an empty one.
    with app.test_request_context("/appliances/%d/upgrade/prep" % aid):
        url2 = _prep_payload(UpgradePrep.query.get(pid))["cr_url"]
    assert "_adom=&" not in url2 and not url2.endswith("_adom="), \
        "empty scope parameter: %s" % url2


# =========================================================================== #
#  9. stage 2 raises the change WITHOUT leaving the flow                       #
# =========================================================================== #
#  It used to post straight at ``change_requests.new``, which cannot do either
#  of the two things a stage inside a staged page has to do:
#
#    * on SUCCESS it redirected to the new change's own page — out of the flow,
#      two stages from the end, with no way back to the selection just built;
#    * on REFUSAL it redirected to an EMPTY ``/change-requests/new`` — the form
#      the operator had deliberately not used, with everything they had typed
#      gone and the per-appliance evidence they had chosen gone with it.
#
#  Neither failed. A change simply could not be raised from this page without
#  leaving it, and a refused one cost the whole card.
# --------------------------------------------------------------------------- #
_STAGE2 = {
    "doc_lang": "en", "risk": "high",
    "title": "October window", "reason": "reason typed by hand",
    "rollback": "rollback typed by hand",
    "owner": "someone-else", "notify_to": "ops@example.com",
    "approval_mode": "external",
    "window_start": "2026-10-01T22:00", "window_end": "2026-10-01T23:30",
}


def _post_stage_two(client, **over):
    data = dict(_STAGE2)
    data.update(over)
    return client.post("/web/upgrade-flow/change", data=data)


def test_stage_two_posts_to_the_flow_not_to_the_single_change_form(app, client):
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/").get_data(as_text=True)
    assert 'action="/web/upgrade-flow/change" id="uf-cr"' in body, \
        "stage 2 no longer posts to the flow's own handler"
    assert 'action="/web/change-requests/new" id="uf-cr"' not in body, \
        "stage 2 posts at the single-change form again — success leaves the " \
        "flow and a refusal empties the card"


def test_a_raised_change_comes_back_to_the_flow_citing_itself(app, client):
    from app.models import ChangeRequest, CrPrep

    with app.app_context():
        a = _mk_appliance("come-back")
        prep = _mk_prep(a, inventory=[{"device": "come-back",
                                       "device_id": a.id, "policy": "p"}])
        ids = (a.id, prep.id)

    login(client, admin_user_id(app))
    resp = _post_stage_two(client, device_ids=[str(ids[0])],
                           prep_ids=[str(ids[1])])
    assert resp.status_code in (302, 303)
    where = resp.headers["Location"]
    assert "/web/upgrade-flow/" in where, \
        "raising the change still throws the operator out of the flow"
    assert "/web/change-requests/" not in where

    with app.app_context():
        cr = ChangeRequest.query.order_by(ChangeRequest.id.desc()).first()
        cid, ref, action = cr.id, cr.ref, cr.action
        # Only create_change_request stamps a ref, freezes the inventory and
        # binds the runs. Their presence is what says this route did NOT grow
        # its own idea of what raising a change is.
        bound = CrPrep.query.filter_by(cr_id=cid).count()
        frozen = json.loads(cr.policies or "[]")
    assert action == "upgrade" and ref and bound == 1 and frozen
    assert "cr=%d" % cid in where, "the flow comes back citing nothing"

    body = client.get(where).get_data(as_text=True)
    assert ref in body, "the change the flow just raised is not named on it"
    assert "/web/change-requests/%d" % cid in body, \
        "no way from the citation to the change document"
    # The "Execution" shortcut that used to sit beside this citation was
    # removed on request (2026-09-19) with the summary strip it lived in,
    # so stage 2 no longer reaches the per-appliance execution view
    # directly — it is reached from the change itself. The link to the
    # change is asserted just above and is now the ONLY route out of the
    # citation, which is exactly why it is guarded.


def test_a_refused_change_re_renders_the_flow_with_what_was_typed(app, client):
    with app.app_context():
        a = _mk_appliance("refused")
        ids = (a.id,)

    login(client, admin_user_id(app))
    resp = _post_stage_two(client, title="", device_ids=[str(ids[0])])
    assert resp.status_code == 200, "a refusal must not redirect anywhere"
    assert resp.headers.get("Location") is None
    body = resp.get_data(as_text=True)
    assert 'id="uf-cr"' in body and 'id="uf-all"' in body, \
        "the refusal landed somewhere other than the flow"
    assert "A title is required" in body, "the refusal is not shown"
    for kept in ("reason typed by hand", "rollback typed by hand",
                 "someone-else", "ops@example.com",
                 '"2026-10-01T22:00"', '"2026-10-01T23:30"'):
        assert kept in body, "%s was lost when the change was refused" % kept
    assert '<option value="high" selected>' in body, "the risk was reset"
    assert '<option value="external" selected>' in body, \
        "the approval mode was reset to the default nobody chose"
    import re as _re
    assert _re.search(r'value="%d"[^>]*data-name="[^"]*"[^>]*checked' % ids[0],
                      body), \
        "the appliances the change covers came back unticked — the selection " \
        "is mirrored from stage 1, so losing the ticks loses the change's scope"


def test_a_refusal_creates_nothing(app, client):
    from app.models import ChangeRequest

    with app.app_context():
        a = _mk_appliance("refuse-nothing")
        ids = (a.id,)
        before = ChangeRequest.query.count()

    login(client, admin_user_id(app))
    _post_stage_two(client, title="", device_ids=[str(ids[0])])
    # An inverted window is refused by create_change_request, not by the page.
    _post_stage_two(client, device_ids=[str(ids[0])],
                    window_start="2026-10-02T23:30",
                    window_end="2026-10-02T22:00")
    with app.app_context():
        assert ChangeRequest.query.count() == before


def test_a_refusal_keeps_the_run_each_appliance_cited(app, client):
    """The evidence chooser is per appliance and the newest run is only a
    PROPOSAL. A re-render that re-proposed it would silently re-cite a run the
    operator had replaced — or one they had deliberately cleared — and the page
    would look exactly as if they had chosen it."""
    with app.app_context():
        a = _mk_appliance("cited")
        older = _mk_prep(a, summary="the run the operator wants")
        newer = _mk_prep(a, summary="a re-run made to test a fix")
        ids = (a.id, older.id, newer.id)

    login(client, admin_user_id(app))
    fresh = client.get("/web/upgrade-flow/").get_data(as_text=True)
    assert _selected_run(fresh, ids[0]) == [str(ids[2])], \
        "the newest run is no longer proposed on a plain visit"

    body = _post_stage_two(client, title="", device_ids=[str(ids[0])],
                           prep_ids=[str(ids[1])]).get_data(as_text=True)
    assert _selected_run(body, ids[0]) == [str(ids[1])], \
        "the refusal re-proposed the newest run over the operator's choice"

    cleared = _post_stage_two(client, title="", device_ids=[str(ids[0])],
                              prep_ids=[]).get_data(as_text=True)
    chooser = _chooser(cleared, ids[0])
    assert '<option value="" selected>' in chooser, \
        "'no run cited' is a real answer and it was not kept"
    assert 'value="%d" selected' % ids[2] not in chooser


def test_a_refusal_tells_an_edited_field_from_an_untouched_proposal(app, client):
    """``data-auto`` is what stops the page overwriting the operator's words,
    and what the 'auto' chip reports. Marking all three edited on the way back
    would be simpler and wrong: an operator who corrected only the window would
    find the wording frozen, with a chip claiming text is theirs."""
    import re as _re
    from app.views.upgrade_flow import cr_draft_context

    with app.app_context():
        a = _mk_appliance("auto-flag")
        ids = (a.id,)
        crdoc = cr_draft_context()
        draft = crdoc["drafts"].get("en") or {}
        token = crdoc["devices_token"]
    proposal = {k: (draft.get(k) or "").replace(token, "auto-flag")
                for k in ("title", "reason", "rollback")}

    login(client, admin_user_id(app))
    body = _post_stage_two(
        client, title="", reason=proposal["reason"],
        rollback="changed by hand", device_ids=[str(ids[0])]).get_data(as_text=True)

    def _auto(el):
        m = _re.search(r'<(?:input|textarea)[^>]*id="%s".*?>' % el, body, _re.S)
        assert m, "%s is missing from the re-rendered card" % el
        got = _re.search(r'data-auto="(\d)"', m.group(0))
        return got.group(1) if got else "?"

    assert _auto("uf-reason") == "1", \
        "an untouched proposal came back marked as the operator's own words"
    assert _auto("uf-rollback") == "0", \
        "an edited field came back marked auto — the proposal would overwrite it"


def test_the_citation_never_names_a_change_this_operator_cannot_see(app, client):
    """Decoration on a page that renders perfectly without it: an unknown id
    must read as no citation, never as a 404 and never as the existence of
    something outside this ADOM."""
    login(client, admin_user_id(app))
    for raw in ("999999", "abc", ""):
        resp = client.get("/web/upgrade-flow/?cr=%s" % raw)
        assert resp.status_code == 200, "?cr=%s broke the page" % raw
        assert "Open its own page" not in resp.get_data(as_text=True), \
            "?cr=%s produced a citation of nothing" % raw


def test_the_flow_does_not_reimplement_what_raising_a_change_is(app, client):
    """The rules live in ``change_requests.create_change_request``; this route
    only decides where the operator ends up. Two implementations of "raise a
    change" is the defect this whole feature was built to remove."""
    import inspect

    from app.views import upgrade_flow

    src = inspect.getsource(upgrade_flow.change)
    assert "create_change_request(" in src, \
        "stage 2 no longer goes through the one create path"
    assert "ChangeRequest(" not in src, \
        "stage 2 builds its own change row"
    assert "'action': CR_ACTION" in src or '"action": CR_ACTION' in src, \
        "the change type is read from the post again — a type the page cannot " \
        "propose wording for could be substituted into it"


# --------------------------------------------------------------------------- #
#  Stage 2 IS the change request — the whole of it, not a link to it            #
#                                                                              #
#  Raising the change without leaving the flow fixed the SUBMIT; approving it,  #
#  scheduling it, marking it notified, exporting its inventory or reading its   #
#  document were all still a trip to /web/change-requests/<id>. What stage 2    #
#  renders now is the same seven blocks that page renders, from ONE builder     #
#  (``change_requests.cr_view_context``) and ONE partial                        #
#  (``change_requests/_view.html``).                                            #
#                                                                              #
#  These guards exist because nothing FAILS when the two drift: both pages      #
#  render, and the embedded one — read once, at the end of a window nobody      #
#  re-opens — is the one that goes stale.                                       #
# --------------------------------------------------------------------------- #
_CR_BLOCKS = {
    # NOT the old "Run-gate:" strip: that label was removed on request
    # 2026-09-19 while the bar and every button in it stayed. A sentinel
    # that can be deleted without the thing it stands for going away is
    # a guard that reports on the wrong noun.
    "action bar": "<!-- ACTION BAR -->",
    "overview": ">Overview<",
    "change document": ">Change document<",
    "affected services": ">Affected services<",
    "inventory export": "Download .xlsx",
    "external change record": ">External change record<",
    "timeline": ">Timeline<",
    "maintenance notice": ">Maintenance notice<",
}
_CR_ACTIONS = {
    "approve": "/approve\"",
    "mark notified": "/mark-notified\"",
    "cancel": "/cancel\"",
    "edit": "bi-pencil-square",
    "change ticket": "/request-crq\"",
}


def _raise_one(app, client, name):
    """Raise a change THROUGH stage 2 and hand back (cr_id, ref, appliance_id).

    Through the page, never by inserting a row: a change built by hand would
    carry no frozen inventory and no bound run, so the blocks under test would
    be legitimately empty and every assertion about them would pass by being
    vacuous."""
    from app.models import ChangeRequest

    with app.app_context():
        a = _mk_appliance(name)
        prep = _mk_prep(a, inventory=[{"device": name, "device_id": a.id,
                                       "policy": "pol-1", "vserver": "vs-1",
                                       "service": "HTTPS", "status": "enable"}])
        ids = (a.id, prep.id)
    login(client, admin_user_id(app))
    resp = _post_stage_two(client, device_ids=[str(ids[0])],
                           prep_ids=[str(ids[1])])
    assert resp.status_code in (302, 303), \
        "stage 2 refused the fixture change: %s" % resp.status_code
    with app.app_context():
        cr = ChangeRequest.query.order_by(ChangeRequest.id.desc()).first()
        return cr.id, cr.ref, ids[0]


def _both(client, cid):
    flow = client.get("/web/upgrade-flow/?cr=%d" % cid).get_data(as_text=True)
    own = client.get("/web/change-requests/%d" % cid).get_data(as_text=True)
    return flow, own


def test_stage_two_renders_the_whole_change_not_a_link_to_it(app, client):
    cid, ref, _ = _raise_one(app, client, "whole-change")
    flow = client.get("/web/upgrade-flow/?cr=%d" % cid).get_data(as_text=True)
    assert ref in flow
    missing = [k for k, v in _CR_BLOCKS.items() if v not in flow]
    assert not missing, \
        "stage 2 cites the change but does not show %s — still a trip to " \
        "another screen" % ", ".join(missing)
    missing = [k for k, v in _CR_ACTIONS.items() if v not in flow]
    assert not missing, \
        "stage 2 shows the change but cannot drive it: no %s" % ", ".join(missing)


def test_the_flow_and_the_change_page_show_the_same_change(app, client):
    """The anti-drift guard. Presence compared BOTH ways, and every block
    required on both: two pages agreeing that a block is absent is not the two
    pages agreeing."""
    cid, _, _ = _raise_one(app, client, "same-change")
    flow, own = _both(client, cid)
    for label, marker in list(_CR_BLOCKS.items()) + list(_CR_ACTIONS.items()):
        assert marker in own, "%s vanished from the change's own page" % label
        assert marker in flow, "%s is on the change's page but not in stage 2" % label


def test_there_is_exactly_one_author_for_those_blocks(app, client):
    """Two copies of this markup is the defect, not the symptom. The flow was
    already a second author of the CRQ FORM once; the round that fixed that is
    the reason this is asserted on the files and not only on the output."""
    def _read(rel):
        with open(os.path.join(REPO, *rel.split("/")), encoding="utf-8") as fh:
            return fh.read()

    partial = _read("app/templates/change_requests/_view.html")
    detail = _read("app/templates/change_requests/detail.html")
    flow = _read("app/templates/upgrade_flow/index.html")

    assert "change_requests/_view.html" in detail, \
        "the change's own page no longer includes the shared view"
    assert "change_requests/_view.html" in flow, \
        "stage 2 no longer includes the shared view"
    for marker in ("_('Timeline')", "_('Maintenance notice')",
                   "change_requests.request_crq", "change_requests.approve",
                   "_('Affected services')"):
        assert marker in partial, "%s left the shared partial" % marker
        assert marker not in detail, \
            "%s is written a SECOND time in detail.html" % marker
        assert marker not in flow, \
            "%s is written a SECOND time in the flow template" % marker


def test_no_form_is_nested_inside_another_on_the_flow(app, client):
    """The embedded blocks carry forms of their own (approve, schedule, cancel,
    ticket, export) and stage 2 is itself a form. A <form> inside a <form> is
    invalid HTML the browser silently unnests — every button in the inner one
    then posts the wrong thing, or nothing, and the page still LOOKS right."""
    cid, _, _ = _raise_one(app, client, "no-nesting")
    body = client.get("/web/upgrade-flow/?cr=%d" % cid).get_data(as_text=True)
    depth = deepest = 0
    for m in re.finditer(r"<form\b|</form>", body):
        depth += 1 if m.group(0) == "<form" else -1
        deepest = max(deepest, depth)
    assert deepest == 1, "forms are nested %d deep on the flow page" % deepest
    assert depth == 0, "unbalanced <form> tags on the flow page"


def test_approving_from_the_flow_comes_back_to_the_flow(app, client):
    from app.models import ChangeRequest

    cid, _, _ = _raise_one(app, client, "approve-back")
    resp = client.post("/web/change-requests/%d/approve" % cid,
                       data={"back": "upgrade_flow"})
    assert resp.status_code in (302, 303)
    where = resp.headers["Location"]
    assert "/web/upgrade-flow/" in where and "cr=%d" % cid in where, \
        "approving from stage 2 threw the operator out of the flow: %s" % where
    with app.app_context():
        assert db_get_status(ChangeRequest, cid) == "approved", \
            "the round trip came back to the flow without approving anything"


def db_get_status(model, cid):
    from app.extensions import db
    return db.session.get(model, cid).status


def test_approving_from_the_changes_own_page_still_lands_there(app, client):
    cid, _, _ = _raise_one(app, client, "approve-here")
    resp = client.post("/web/change-requests/%d/approve" % cid, data={})
    where = resp.headers["Location"]
    assert where.endswith("/web/change-requests/%d" % cid), \
        "the change's own page stopped being its own return target: %s" % where


@pytest.mark.parametrize("token", ["https://evil.example/x", "//evil.example",
                                   "/web/upgrade-flow/", "UPGRADE_FLOW", "junk"])
def test_the_return_target_is_a_token_never_a_url(app, client, token):
    """These buttons now render on a page any operator can reach. A redirect
    target read straight out of the form is an open redirect; only the known
    token is honoured, and anything else falls back to the change itself."""
    cid, _, _ = _raise_one(app, client, "token-%d" % (abs(hash(token)) % 9999))
    resp = client.post("/web/change-requests/%d/cancel" % cid,
                       data={"back": token, "reason": "guard"})
    where = resp.headers["Location"]
    assert where.endswith("/web/change-requests/%d" % cid), \
        "%r was honoured as a redirect target: %s" % (token, where)
    assert "evil.example" not in where


def test_every_lifecycle_button_carries_the_return_token(app, client):
    """One button left without it silently walks the operator out of the flow
    — and only that one button, which is how this would be found in the field
    instead of here."""
    cid, _, _ = _raise_one(app, client, "token-on-each")
    flow, own = _both(client, cid)
    posts = len(re.findall(r'<form[^>]+method="?POST"?', flow, re.I))
    tokens = flow.count('name="back" value="upgrade_flow"')
    assert tokens >= 4, "only %d of the embedded forms return to the flow" % tokens
    assert 'name="back" value="upgrade_flow"' not in own, \
        "the change's own page posts a return token it was never given"


def test_the_live_comparison_does_not_leave_the_flow(app, client):
    """Asking for the drift read from inside stage 2 must not be a way out of
    stage 2 — it is the same question asked about the page you are on."""
    cid, _, _ = _raise_one(app, client, "drift-stays")
    flow, own = _both(client, cid)

    def _compare_link(body):
        # By ID, not by icon: the sidebar has a bi-arrow-repeat of its own and
        # a search by icon happily returns THAT one — a guard that reads a
        # different link than the one under test measures nothing.
        m = re.search(r'id="crv-drift"\s+href="([^"]+)"', body)
        assert m, "the 'compare against the devices now' link is gone"
        return m.group(1)

    here = _compare_link(flow)
    assert "/web/upgrade-flow/" in here and "drift=1" in here \
        and "cr=%d" % cid in here, "the drift link leaves the flow: %s" % here
    there = _compare_link(own)
    assert "/web/change-requests/%d" % cid in there and "drift=1" in there

    drifted = client.get("/web/upgrade-flow/?cr=%d&drift=1" % cid).get_data(as_text=True)
    assert "Drift vs. the devices right now" in drifted, \
        "the flow accepts drift=1 and renders no comparison"
    assert 'id="uf-cr"' in drifted, "asking for drift landed somewhere else"


def test_editing_from_the_flow_returns_to_the_flow(app, client):
    cid, _, _ = _raise_one(app, client, "edit-back")
    flow, own = _both(client, cid)
    assert "/web/change-requests/%d/edit?back=upgrade_flow" % cid in flow, \
        "Edit pressed inside the flow does not carry where it came from"
    assert "/edit?back=" not in own, \
        "the change's own page sends a return token it was never given"

    page = client.get("/web/change-requests/%d/edit?back=upgrade_flow" % cid)
    body = page.get_data(as_text=True)
    assert 'name="back" value="upgrade_flow"' in body, \
        "the edit form drops the return token on the way through"
    # Prefix, not the whole attribute: the return URL also carries the ADOM
    # it was pressed in, and the & is HTML-escaped in the href.
    assert body.count('href="/web/upgrade-flow/?cr=%d' % cid) >= 2, \
        "Back and Discard on the edit screen still leave the flow"

    resp = client.post("/web/change-requests/%d/edit" % cid, data={
        "title": "edited from inside the flow", "risk": "high",
        "reason": "r", "rollback": "rb", "owner": "o",
        "notify_to": "ops@example.com", "doc_lang": "en",
        "approval_mode": "manual",
        "window_start": "2026-10-01T22:00", "window_end": "2026-10-01T23:30",
        "back": "upgrade_flow"})
    where = resp.headers["Location"]
    assert "/web/upgrade-flow/" in where and "cr=%d" % cid in where, \
        "saving an edit opened from the flow lands elsewhere: %s" % where


def test_a_citation_of_nothing_embeds_nothing(app, client):
    """An id naming a change outside this operator's scope reads as NO citation
    — it must not render that change's blocks as a consolation prize."""
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?cr=999999").get_data(as_text=True)
    for label, marker in _CR_BLOCKS.items():
        if label == "overview":
            continue  # stage 1 has a heading of its own by that name
        assert marker not in body, \
            "an unciteable change still rendered its %s" % label


def test_a_reader_who_cannot_drive_the_change_gets_no_buttons(app, client):
    """A button that answers 403 is worse than no button: it reads as an action
    this operator may take.

    MEASURED, not assumed: stage 2 of the flow sits behind ``user_manage``
    today, so on that page ``can_act`` is belt-and-braces — which is exactly
    why it is guarded on the PARTIAL rather than on the flow. A guard written
    against the flow page would have passed by finding an empty stage 2 and
    said nothing about the gate at all.
    """
    from flask import render_template
    from flask_login import login_user

    from app.extensions import db
    from app.models import ChangeRequest, User
    from app.views.change_requests import cr_view_context
    from conftest import make_user, profile_id

    cid, _, _ = _raise_one(app, client, "read-only")
    uid = make_user(app, username="ops-reader", role="operator",
                    profile_id=profile_id(app, "operator"))

    with app.test_request_context("/web/change-requests/%d" % cid):
        reader = db.session.get(User, uid)
        assert reader.can("backup") and not reader.can("user_manage")
        login_user(reader)
        crv = cr_view_context(db.session.get(ChangeRequest, cid))
        assert crv["can_act"] is False, \
            "a user without user_manage was handed the workflow"
        body = render_template("change_requests/_view.html", crv=crv)

    assert "<!-- ACTION BAR -->" in body, \
        "the reader cannot read the change either"
    assert ">Timeline<" in body and ">Maintenance notice<" in body
    for label, marker in _CR_ACTIONS.items():
        assert marker not in body, \
            "a reader without user_manage was offered %s" % label
    assert "needs the user-manage permission" in body, \
        "the buttons are gone and nothing says why"

    with app.test_request_context("/web/change-requests/%d" % cid):
        admin = db.session.get(User, admin_user_id(app))
        login_user(admin)
        crv = cr_view_context(db.session.get(ChangeRequest, cid))
        assert crv["can_act"] is True, \
            "can_act is False for everyone — the guard above proves nothing"
        allowed = render_template("change_requests/_view.html", crv=crv)
    for label, marker in _CR_ACTIONS.items():
        assert marker in allowed, "%s is gated off for everybody" % label


def test_the_flow_does_not_rebuild_the_change_view(app, client):
    """One BUILDER as well as one partial: a second assembly of these values is
    how the two pages would come to disagree about a change while both render."""
    import inspect

    from app.views import upgrade_flow

    src = inspect.getsource(upgrade_flow.page_context)
    assert "cr_view_context(" in src, \
        "the flow builds the embedded change some other way"
    assert "maintenance_notice(" not in src and "frozen_policies(" not in src, \
        "the flow assembles the change view itself again"


# --------------------------------------------------------------------------- #
#  stage 2 IS the change request: the picker, and the waves folded into it      #
# --------------------------------------------------------------------------- #
def test_every_waves_field_is_bound_to_the_waves_form(app, client):
    """The waves inputs sit inside the stage-2 form's card. Unbound, they
    belong to it — and ``window_start`` exists in BOTH, so the single change
    would post two of them with the same name and different meanings.

    Nothing would fail: the server would read one, and which one is an accident
    of ordering. Guarded by counting, inside the stage-2 slice, the fields that
    are NOT bound away.
    """
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/").get_data(as_text=True)
    head, rest = body.split('id="uf-cr"', 1)
    raw = rest.split("</form>", 1)[0]          # the card, waves fields included
    for name in ("wave_size", "wave_minutes", "wave_gap"):
        for tag in re.findall(r'<input[^>]*name="%s"[^>]*>' % name, raw):
            assert 'form="uf-waves"' in tag, \
                "%s would be posted by the single change" % name
    unbound = [t for t in re.findall(r'<input[^>]*name="window_start"[^>]*>', raw)
               if 'form="uf-waves"' not in t]
    assert len(unbound) == 1, \
        "the stage-2 form posts %d window_start fields, not 1" % len(unbound)
    assert re.search(r'<button[^>]*form="uf-waves"[^>]*>', raw), \
        "the waves submit would raise the single change instead"


def test_the_waves_form_element_is_empty_and_not_nested(app, client):
    """It carries the hidden wording mirrors and nothing else. A form element
    inside a form element is invalid HTML the browser silently unnests — the
    page looks right and the buttons post the wrong thing."""
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/").get_data(as_text=True)
    assert body.count('id="uf-waves"') == 1
    waves = body.split('id="uf-waves"', 1)[1].split("</form>", 1)[0]
    assert "<form" not in waves and "fw-card" not in waves, \
        "the waves form element grew a card again"
    for mirror in ("uf-w-title", "uf-w-reason", "uf-w-rollback", "uf-w-lang"):
        assert mirror in waves, "%s left the waves post" % mirror
    # Depth, measured on MARKUP only: this page's own script comments talk
    # about form elements, and counting those is how a checker answers itself.
    markup = re.sub(r"<script\b.*?</script>", "", body, flags=re.S | re.I)
    depth = maximum = 0
    for tok in re.findall(r"<form\b|</form>", markup):
        depth += -1 if tok == "</form>" else 1
        maximum = max(maximum, depth)
    assert maximum == 1 and depth == 0, \
        "form nesting depth %d, balance %d" % (maximum, depth)


def test_stage_two_shows_one_change_and_never_a_list_of_them(app, client):
    """Stage 2 renders ONE change: the newest, whole, with nothing that lists
    the others.

    It used to carry a picker listing every change this flow had raised. The
    user removed it (2026-09-19): the stage is the change request, not a menu
    of them. This guard is what keeps it removed — the list is the kind of
    thing that grows back the next time someone wants to "switch quickly", and
    a second reference to a change nobody opened is exactly what made the
    stage read as a chooser rather than as the record.

    Asserting the label alone would be an assertion that answers itself, so it
    raises TWO changes and counts the OLDER one's ref DIFFERENTIALLY: stage 1
    legitimately cites the change each prep run was handed to, so "absent from
    the page" is the wrong question and would fail against correct markup. The
    right one is whether opening the stage adds a mention the closed stage does
    not have -- which is precisely what a list of raised changes would add.
    """
    _old_id, old_ref, _ = _raise_one(app, client, "not-listed-older")
    _new_id, new_ref, _ = _raise_one(app, client, "not-listed-newer")
    # Raising leaves a flash naming the change, and a flash survives until a
    # request consumes it -- so the FIRST page load after two raises carries
    # both refs in its banner and nothing to do with the stage. Burn them, or
    # this guard measures the flash queue and fails against correct markup.
    client.get("/web/upgrade-flow/")
    body = client.get("/web/upgrade-flow/").get_data(as_text=True)

    # Scoped to the stage-2 card, not the whole page: stage 1 legitimately
    # cites the change a prep run was handed to, so a page-wide absence check
    # would fail against correct markup. find()+index comparison rather than
    # index()/slicing, which raises and takes the other assertions with it.
    start = body.find('id="uf-cr-section"')
    end = body.find('id="uf-cr"', start + 1)
    assert start != -1 and end > start, \
        "the stage-2 card is not on the page at all"
    stage = body[start:end]

    assert new_ref in stage, "the open change is not named in stage 2"
    assert old_ref not in stage, \
        "an older change is named in stage 2 — the list of raised changes is back"
    assert "Changes raised from this flow" not in stage, \
        "the removed picker heading is back on the stage"


def test_a_plain_visit_opens_the_newest_change_whole(app, client):
    """Stage 2 IS the change request, without a click.

    Requiring ?cr= meant every visit after the one that pressed the button
    showed a bare form, which is indistinguishable from the stage never having
    been built. A plain visit renders the newest change raised from this flow:
    document, inventory, external record, timeline, notice and the action bar.
    """
    cid, ref, _ = _raise_one(app, client, "plain-visit-opens")
    body = client.get("/web/upgrade-flow/").get_data(as_text=True)
    for label, marker in _CR_BLOCKS.items():
        assert marker in body, \
            "a plain visit did not render %s" % label
    for label, marker in _CR_ACTIONS.items():
        # "edit" is matched by a bare Bootstrap icon class the nav also uses
        # (Custom Signature); on a whole-page assertion it answers itself.
        if label == "edit":
            continue
        assert marker in body, "%s is missing on a plain visit" % label
    # The change it opened is NAMED. These buttons act on a real record the
    # operator did not pick, so a page that renders them without saying which
    # change they belong to is the actual hazard -- not the auto-open.
    assert ref in body, "the open change is not named on the page"


def test_the_newest_is_what_opens_and_an_explicit_id_still_wins(app, client):
    """Newest-first, and ?cr= overrides it.

    If the default were "the first one found" it would drift with insertion
    order, and the operator would be approving whichever change the query
    happened to return.
    """
    old_id, old_ref, _ = _raise_one(app, client, "older-change")
    new_id, new_ref, _ = _raise_one(app, client, "newer-change")
    assert new_id > old_id

    plain = client.get("/web/upgrade-flow/").get_data(as_text=True)
    assert new_ref in plain, "the newest change is not the one opened"

    picked = client.get("/web/upgrade-flow/?cr=%d" % old_id).get_data(as_text=True)
    assert old_ref in picked
    # ...and it really switched, rather than rendering both.
    assert picked.count(new_ref) < plain.count(new_ref), \
        "asking for an older change did not displace the default"


def test_no_url_leaves_the_stage_as_a_bare_form(app, client):
    """There is no closed state left, because its only control was removed.

    ``?cr=0`` WAS the closed state, written by the picker's "Close it" button.
    The picker went on request (2026-09-19) and the state outlived it: an
    operator who had pressed Close it -- or anyone holding that URL, which is
    what a browser keeps across a reload -- sat on a bare form with the change
    gone and NOTHING on the page able to bring it back. That is the bug this
    guard exists to keep fixed, so it measures the three spellings that used
    to differ: plain, the old closed state, and an id that resolves to nothing
    this operator may see. All three must open the newest change, whole.
    """
    _raise_one(app, client, "no-dead-end")
    for url in ("/web/upgrade-flow/",
                "/web/upgrade-flow/?cr=0",
                "/web/upgrade-flow/?cr=99999"):
        html = client.get(url).get_data(as_text=True)
        for label, marker in _CR_BLOCKS.items():
            assert marker in html, \
                "%s missing on %s -- the stage is a bare form again" % (
                    label, url)
    # The control whose removal created the dead end must stay removed: put it
    # back and the state it writes is reachable again.
    opened = client.get("/web/upgrade-flow/").get_data(as_text=True)
    assert "Close it" not in opened, \
        "the removed Close control is back on the stage"
