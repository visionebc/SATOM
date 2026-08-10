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
