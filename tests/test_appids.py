"""AppID catalog — importer/mapping purity + authority (billing/access) tests."""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import AppId, AppIdPolicy, Appliance
from app.services import appids as svc


# --------------------------------------------------------------------------- #
#  Parsing + mapping (pure, no DB)                                             #
# --------------------------------------------------------------------------- #
def test_parse_csv_with_header():
    data = b"AppID,Client,Env\nAPP-1,Acme,prod\nAPP-2,Globex,stage\n"
    t = svc.parse_upload("catalog.csv", data)
    assert t.columns == ["AppID", "Client", "Env"]
    assert t.kind == "csv"
    assert len(t.rows) == 3  # header + 2 data rows


def test_parse_tsv_sniffed():
    data = b"AppID\tClient\nAPP-9\tWayne\n"
    t = svc.parse_upload("catalog.txt", data)
    assert t.columns[0] == "AppID"
    assert t.rows[1] == ["APP-9", "Wayne"]


def test_apply_mapping_by_header_name():
    t = svc.parse_upload("c.csv", b"AppID,Client,Env\nAPP-1,Acme,prod\n")
    mapping = {"has_header": True,
               "fields": {"app_id": "AppID", "customer": "Client"},
               "extra": {"environment": "Env"}}
    recs = svc.apply_mapping(t, mapping)
    assert recs == [{"app_id": "APP-1", "customer": "Acme", "label": "",
                     "rate": "", "extra": {"environment": "prod"}}]


def test_apply_mapping_by_index_no_header():
    t = svc.parse_upload("c.csv", b"APP-1,Acme\nAPP-2,Globex\n")
    mapping = {"has_header": False, "fields": {"app_id": "0", "customer": "1"}}
    recs = svc.apply_mapping(t, mapping)
    assert [r["app_id"] for r in recs] == ["APP-1", "APP-2"]
    assert recs[0]["customer"] == "Acme"


def test_apply_mapping_drops_blank_appid():
    t = svc.parse_upload("c.csv", b"AppID,Client\nAPP-1,Acme\n,Orphan\n")
    recs = svc.apply_mapping(t, {"has_header": True, "fields": {"app_id": "AppID"}})
    assert len(recs) == 1  # the blank-AppID row is dropped


# --------------------------------------------------------------------------- #
#  Import — additive upsert + stale (needs DB)                                 #
# --------------------------------------------------------------------------- #
def test_import_creates_then_updates_additively(session):
    recs = [{"app_id": "APP-1", "customer": "Acme", "extra": {"env": "prod"}}]
    r1 = svc.import_records(recs, product="fortiweb")
    assert (r1.created, r1.updated) == (1, 0)
    row = AppId.query.filter_by(app_id="APP-1").one()
    assert row.customer == "Acme" and row.extra_dict == {"env": "prod"}

    # Second import: same key, customer omitted -> must NOT blank the old value.
    r2 = svc.import_records([{"app_id": "APP-1", "label": "Checkout"}],
                            product="fortiweb")
    assert (r2.created, r2.updated) == (0, 1)
    row = AppId.query.filter_by(app_id="APP-1").one()
    assert row.customer == "Acme"          # preserved
    assert row.label == "Checkout"          # filled


def test_import_flags_vanished_as_stale_never_deletes(session):
    svc.import_records([{"app_id": "APP-1"}, {"app_id": "APP-2"}], product="fortiweb")
    # A later feed only has APP-1: APP-2 must be flagged stale, still present.
    svc.import_records([{"app_id": "APP-1"}], product="fortiweb")
    two = AppId.query.filter_by(app_id="APP-2").one()
    assert two.stale is True and two.stale_reason
    assert AppId.query.count() == 2  # nothing deleted


def test_manual_appid_never_auto_staled(session):
    svc.create_manual(app_id="APP-M", customer="ByHand")
    svc.import_records([{"app_id": "APP-X"}], product="fortiweb")
    manual = AppId.query.filter_by(app_id="APP-M").one()
    assert manual.stale is False  # manual rows are immune to feed-stale


def test_create_manual_rejects_duplicate(session):
    svc.create_manual(app_id="APP-D")
    with pytest.raises(ValueError):
        svc.create_manual(app_id="app-d")  # case-insensitive dup


# --------------------------------------------------------------------------- #
#  Authority — 1 AppID per policy + token scope resolution                     #
# --------------------------------------------------------------------------- #
def _appliance(session, name="fw1"):
    a = Appliance(name=name, host="192.0.2.1", kind="fortiweb", username="admin")
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


def test_assign_is_one_appid_per_policy(session):
    a = _appliance(session)
    app1 = svc.create_manual(app_id="APP-1")
    app2 = svc.create_manual(app_id="APP-2")
    svc.assign(app_id_pk=app1.id, appliance_id=a.id, server_policy="pol-x")
    # Reassign the SAME (device, policy) to another AppID -> moves, no dup row.
    svc.assign(app_id_pk=app2.id, appliance_id=a.id, server_policy="pol-x")
    binds = AppIdPolicy.query.filter_by(appliance_id=a.id, server_policy="pol-x").all()
    assert len(binds) == 1
    assert binds[0].app_id_id == app2.id


def test_token_scope_targets_resolves_bindings(session):
    a = _appliance(session)
    app1 = svc.create_manual(app_id="APP-1")
    svc.assign(app_id_pk=app1.id, appliance_id=a.id, server_policy="pol-x")
    svc.assign(app_id_pk=app1.id, appliance_id=a.id, server_policy="pol-y")
    targets = svc.token_scope_targets(["APP-1"], product="fortiweb")
    assert targets == {(a.id, "pol-x"), (a.id, "pol-y")}
    assert svc.token_scope_targets(["APP-NONE"]) == set()


# --------------------------------------------------------------------------- #
#  audit 2026-10-03: header checkbox, policy existence on assign               #
# --------------------------------------------------------------------------- #
def test_an_unticked_header_box_imports_the_first_row(app, client):
    """An unticked checkbox is not submitted; the server defaulted to "has a
    header" and silently dropped the first record."""
    import io
    from tests.conftest import admin_user_id, login
    login(client, admin_user_id(app))
    data = {"has_header": "0", "map_app_id": "0", "map_customer": "1",
            "catalog_file": (io.BytesIO(b"APP-FIRST,Acme\nAPP-SECOND,Beta\n"),
                             "cat.csv")}
    r = client.post("/web/appids/import", data=data,
                    content_type="multipart/form-data")
    assert r.status_code == 302
    with app.app_context():
        names = {a.app_id for a in AppId.query.all()}
        assert {"APP-FIRST", "APP-SECOND"} <= names
        assert svc.get_mapping()["has_header"] is False


def test_a_ticked_header_box_still_skips_the_header(app, client):
    import io
    from tests.conftest import admin_user_id, login
    login(client, admin_user_id(app))
    data = {"has_header": ["0", "1"], "map_app_id": "AppID",
            "catalog_file": (io.BytesIO(b"AppID\nAPP-ONLY\n"), "cat.csv")}
    client.post("/web/appids/import", data=data,
                content_type="multipart/form-data")
    with app.app_context():
        assert {a.app_id for a in AppId.query.all()} == {"APP-ONLY"}


def _cached_policy(app, aid, name):
    from app.models_cache import DeviceObject, DeviceSnapshot
    with app.app_context():
        snap = DeviceSnapshot(appliance_id=aid, layer="config")
        db.session.add(snap)
        db.session.flush()
        db.session.add(DeviceObject(
            appliance_id=aid, snapshot_id=snap.id, layer="config",
            section="Server Policy", logical_name="server_policy",
            mkey=name, payload={"name": name}, depth=0))
        db.session.commit()


def _assign_setup(app):
    with app.app_context():
        a = Appliance(name="fw-asg", host="192.0.2.5", kind="fortiweb",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        pk = svc.create_manual(app_id="APP-ASG").id
        return a.id, pk


def test_assign_refuses_a_policy_the_device_does_not_have(app, client):
    from tests.conftest import admin_user_id, login
    aid, pk = _assign_setup(app)
    _cached_policy(app, aid, "pol-real")
    login(client, admin_user_id(app))
    client.post("/web/appids/assign", data={
        "app_id_pk": str(pk), "appliance_id": str(aid),
        "server_policy": "pol-typo"})
    with app.app_context():
        assert svc.binding_for(aid, "pol-typo") is None


def test_assign_binds_a_policy_the_device_has(app, client):
    from tests.conftest import admin_user_id, login
    aid, pk = _assign_setup(app)
    _cached_policy(app, aid, "pol-real")
    login(client, admin_user_id(app))
    client.post("/web/appids/assign", data={
        "app_id_pk": str(pk), "appliance_id": str(aid),
        "server_policy": "pol-real"})
    with app.app_context():
        assert svc.binding_for(aid, "pol-real") is not None


def test_the_header_checkbox_has_a_hidden_fallback():
    import pathlib
    body = (pathlib.Path(__file__).resolve().parents[1]
            / "app/templates/appids/index.html").read_text("utf-8")
    i = body.index('id="hasHeader"')
    before = body[:i]
    assert before.rfind('<input type="hidden" name="has_header" value="0">') \
        > before.rfind("<div")
