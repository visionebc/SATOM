"""Analysis over the DEEP cache layer (WPP feature matrix, sub-element counts,
drill-down trees, orphans, freshness). All over a seeded cache — no box, no
network. SQL aggregation only."""
from datetime import datetime

import pytest


@pytest.fixture()
def seeded_deep_cache(app):
    """A deep-layer cache: 2 WPPs (one binds signature-rule, both bind bot), one
    server policy whose pool has 2 members (sub-elements at depth 2), an unused
    WPP, and a deep snapshot for freshness. Yields the appliance id."""
    from app.extensions import db
    from app.models import Appliance
    from app.models_cache import (DeviceObject, DeviceSnapshot,
                                  DeviceServerPolicy, DeviceWebProtectionProfile)
    with app.app_context():
        a = Appliance(name="fw1", kind="fortiweb", host="192.0.2.1", port=443,
                      username="admin", password_enc="x", verify_ssl=False)
        db.session.add(a)
        db.session.commit()
        aid = a.id
        snap = DeviceSnapshot(appliance_id=aid, layer="deep", section="Web Protection",
                              source="live", generated_at=datetime(2026, 6, 30, 18, 40),
                              blob_hash="h", object_count=7)
        db.session.add(snap)
        db.session.flush()

        def obj(**kw):
            row = DeviceObject(appliance_id=aid, snapshot_id=snap.id, layer="deep", **kw)
            db.session.add(row)
            db.session.flush()
            return row

        wpp_a = obj(section="Web Protection", logical_name="web_protection_profile",
                    mkey="wpp-a", depth=0, idx=0,
                    payload={"name": "wpp-a", "signature-rule": "sig-a",
                             "bot-mitigate-policy": "bot-a"})
        wpp_b = obj(section="Web Protection", logical_name="web_protection_profile",
                    mkey="wpp-b", depth=0, idx=1,
                    payload={"name": "wpp-b", "signature-rule": "",
                             "bot-mitigate-policy": "bot-b"})
        db.session.add(DeviceWebProtectionProfile(object_id=wpp_a.id, appliance_id=aid,
                       name="wpp-a", kind="inline", signature_rule="sig-a"))
        db.session.add(DeviceWebProtectionProfile(object_id=wpp_b.id, appliance_id=aid,
                       name="wpp-b", kind="inline", signature_rule=""))

        pol = obj(section="Server Policy", logical_name="server_policy", mkey="pol-a",
                  depth=0, idx=0, payload={"name": "pol-a", "server-pool": "pool-a",
                                           "web-protection-profile": "wpp-a", "vserver": "vs-a"})
        db.session.add(DeviceServerPolicy(object_id=pol.id, appliance_id=aid, name="pol-a",
                       server_pool="pool-a", web_protection_profile="wpp-a", vserver="vs-a"))
        pool = obj(section="Server Policy", logical_name="server_policy/server_pool",
                   mkey="pool-a", subtable="server_pool", depth=1, idx=0,
                   parent_id=pol.id, payload={"name": "pool-a"})
        obj(section="Server Policy", logical_name="server_policy/server_pool/pserver-list",
            mkey="1", subtable="pserver-list", depth=2, idx=0, parent_id=pool.id,
            payload={"id": "1", "ip": "192.0.2.5"})
        obj(section="Server Policy", logical_name="server_policy/server_pool/pserver-list",
            mkey="2", subtable="pserver-list", depth=2, idx=1, parent_id=pool.id,
            payload={"id": "2", "ip": "192.0.2.6"})
        db.session.commit()
        yield aid


def test_wpp_feature_matrix_counts_bound_features(app, seeded_deep_cache):
    from app.services import analysis_deep
    with app.app_context():
        matrix = analysis_deep.wpp_feature_matrix(device_ids=None)
    sig = next(r for r in matrix if r["field"] == "signature-rule")
    assert sig["bound"] == 1 and sig["total"] == 2
    assert sig["label"]  # carries a human label


def test_subelement_counts_groups_by_logical(app, seeded_deep_cache):
    from app.services import analysis_deep
    with app.app_context():
        counts = analysis_deep.subelement_counts(device_ids=None)
    by = {c["logical_name"]: c["count"] for c in counts}
    assert any(ln.endswith("pserver-list") for ln in by)
    assert by["server_policy/server_pool/pserver-list"] == 2


def test_wpp_drilldown_returns_nested_tree(app, seeded_deep_cache):
    from app.services import analysis_deep
    with app.app_context():
        tree = analysis_deep.wpp_drilldown(appliance_id=seeded_deep_cache, mkey="wpp-a")
    assert tree["mkey"] == "wpp-a"
    assert "children" in tree


def test_policy_drilldown_shows_pool_and_members(app, seeded_deep_cache):
    from app.services import analysis_deep
    with app.app_context():
        tree = analysis_deep.server_policy_drilldown(appliance_id=seeded_deep_cache, mkey="pol-a")
    assert tree["mkey"] == "pol-a"
    pool = next(c for c in tree["children"] if c["mkey"] == "pool-a")
    members = [c for c in pool["children"] if c["subtable"] == "pserver-list"]
    assert len(members) == 2


def test_orphan_objects_flags_unused_wpp(app, seeded_deep_cache):
    from app.services import analysis_deep
    with app.app_context():
        orphans = analysis_deep.orphan_objects(device_ids=None)
    mkeys = {o["mkey"] for o in orphans}
    assert "wpp-b" in mkeys   # bound by no server policy
    assert "wpp-a" not in mkeys


def test_deep_freshness_reports_per_device(app, seeded_deep_cache):
    from app.services import analysis
    with app.app_context():
        fr = analysis.deep_freshness(device_ids=None)
    aid = str(seeded_deep_cache)
    assert aid in fr
    assert fr[aid]["captured_at"]


def test_deep_routes_smoke(app, client, seeded_deep_cache):
    from tests.conftest import login, admin_user_id
    login(client, admin_user_id(app))
    r = client.get('/analysis/wpp-matrix')
    assert r.status_code == 200
    assert any(row['field'] == 'signature-rule' for row in r.get_json())
    r2 = client.get(f'/analysis/wpp/{seeded_deep_cache}/wpp-a')
    assert r2.status_code == 200 and r2.get_json()['mkey'] == 'wpp-a'
    r3 = client.get('/analysis/subelements')
    assert r3.status_code == 200
    r4 = client.get('/analysis/freshness')
    assert r4.status_code == 200 and str(seeded_deep_cache) in r4.get_json()
    r5 = client.get('/analysis/orphans')
    assert r5.status_code == 200 and any(o['mkey'] == 'wpp-b' for o in r5.get_json())


def test_deep_objects_route_lists_wpps(app, client, seeded_deep_cache):
    from tests.conftest import login, admin_user_id
    login(client, admin_user_id(app))
    r = client.get('/analysis/deep/objects?kind=wpp')
    assert r.status_code == 200
    mkeys = {o['mkey'] for o in r.get_json()}
    assert {'wpp-a', 'wpp-b'} <= mkeys
    r2 = client.get('/analysis/deep/objects?kind=policy')
    assert r2.status_code == 200
    assert any(o['mkey'] == 'pol-a' for o in r2.get_json())
