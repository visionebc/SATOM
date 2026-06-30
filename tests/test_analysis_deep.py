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
