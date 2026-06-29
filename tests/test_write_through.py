"""Phase 5 — approval diff + write-through to the local cache."""
from __future__ import annotations

from app.services import write_through as W


def _seed(session, appliance_id, logical, mkey, payload):
    from app.models_cache import DeviceObject, DeviceSnapshot
    snap = DeviceSnapshot(appliance_id=appliance_id, section="Server Objects",
                          source="live", object_count=1)
    session.add(snap); session.flush()
    obj = DeviceObject(appliance_id=appliance_id, snapshot_id=snap.id,
                       parent_id=None, layer="config", section="Server Objects",
                       logical_name=logical, mkey=mkey, payload=payload,
                       depth=0, idx=0)
    session.add(obj); session.commit()
    return obj.id


def test_collection_maps_to_logical():
    # server-policy/server-pool is a real registry endpoint -> logical server_pool
    assert W.logical_for_collection("server-policy/server-pool") == "server_pool"


def test_diff_reports_only_changes(session):
    _seed(session, 1, "server_pool", "pool-x",
          {"type": "reverse-proxy", "protocol": "http"})
    diff = W.diff_object(1, "server-policy/server-pool", "pool-x",
                         {"type": "reverse-proxy", "protocol": "https"},
                         session=session)
    assert "protocol" in diff and diff["protocol"]["after"] == "https"
    assert "type" not in diff   # unchanged


def test_local_update_merges_payload(session):
    oid = _seed(session, 1, "server_pool", "pool-x",
                {"type": "reverse-proxy", "protocol": "http"})
    ok = W.local_update(1, "server-policy/server-pool", "pool-x",
                        {"protocol": "https"}, session=session)
    assert ok is True
    from app.models_cache import DeviceObject
    obj = session.get(DeviceObject, oid)
    assert obj.payload["protocol"] == "https"
    assert obj.payload["type"] == "reverse-proxy"   # preserved


def test_local_delete_removes_subtree(session):
    from app.models_cache import DeviceObject, DeviceSnapshot
    snap = DeviceSnapshot(appliance_id=1, section="Server Objects",
                          source="live", object_count=2)
    session.add(snap); session.flush()
    parent = DeviceObject(appliance_id=1, snapshot_id=snap.id, layer="config",
                          section="Server Objects", logical_name="server_pool",
                          mkey="pool-x", payload={"type": "rp"}, depth=0, idx=0)
    session.add(parent); session.flush()
    child = DeviceObject(appliance_id=1, snapshot_id=snap.id, parent_id=parent.id,
                         layer="config", section="Server Objects",
                         logical_name="pserver_list", mkey="1",
                         payload={"ip": "192.0.2.1"}, depth=1, idx=0)
    session.add(child); session.commit()
    assert W.local_delete(1, "server-policy/server-pool", "pool-x",
                          session=session) is True
    assert session.query(DeviceObject).filter_by(appliance_id=1).count() == 0


def test_diff_no_cache_treats_all_new(session):
    diff = W.diff_object(1, "server-policy/server-pool", "ghost",
                         {"protocol": "http"}, session=session)
    assert diff["protocol"]["before"] is None
