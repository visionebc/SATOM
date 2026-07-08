"""Phase 3 — DB-first read layer + freshness + workspace integration."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.services import device_store as ds
from app.services import read_layer as rl
from tests.conftest import admin_user_id, login


SECTIONS = {
    "Server Policy": {"server_policy": [
        {"name": "pol-one", "deployment-mode": "single-server",
         "server-pool": "pool-one", "web-protection-profile": "wpp-one",
         "status": "enable"},
        {"name": "pol-two", "deployment-mode": "server-pool",
         "server-pool": "pool-two", "status": "disable"},
    ]},
}


def _appliance(session, name="fw-rl"):
    from app.models import Appliance
    a = Appliance(name=name, kind="fortiweb", host="192.0.2.9", port=443,
                  username="admin", password_enc="x", verify_ssl=False)
    session.add(a); session.commit()
    return a


def test_read_objects_returns_payloads_and_meta(session):
    a = _appliance(session)
    ds.ingest_sections(a.id, SECTIONS, source="live", session=session)
    payloads, meta = rl.read_objects(a.id, "server_policy", session=session)
    assert {p["name"] for p in payloads} == {"pol-one", "pol-two"}
    # raw hyphenated keys preserved for the template
    assert payloads[0]["deployment-mode"] in ("single-server", "server-pool")
    assert meta["total"] == 2 and meta["source"] == "live"
    assert meta["generated_at"] is not None


def test_read_objects_filter_q(session):
    a = _appliance(session)
    ds.ingest_sections(a.id, SECTIONS, source="live", session=session)
    payloads, meta = rl.read_objects(a.id, "server_policy", q="one", session=session)
    assert [p["name"] for p in payloads] == ["pol-one"]


def test_freshness_label():
    assert rl.freshness_label({}) == "no local data — refresh"
    now = datetime.utcnow()
    assert "just now" in rl.freshness_label({"generated_at": now, "source": "DB"})
    assert "h ago" in rl.freshness_label(
        {"generated_at": now - timedelta(hours=3), "source": "live"})


def test_workspace_page_renders_from_cache(app, client, session):
    a = _appliance(session, name="fw-page")
    ds.ingest_sections(a.id, SECTIONS, source="live", session=session)
    login(client, admin_user_id(app))
    r = client.get(f"/workspace/{a.id}")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "pol-one" in body and "pol-two" in body
    assert "Refresh from device" in body
    assert "DB ·" in body  # freshness badge rendered


def _deep_snapshot(session, aid):
    from app.models_cache import DeviceSnapshot
    snap = DeviceSnapshot(appliance_id=aid, layer="deep", section="Server Policy",
                          source="live", object_count=0)
    session.add(snap); session.commit()
    return snap


def _obj(session, aid, snap_id, **kw):
    from app.models_cache import DeviceObject
    row = DeviceObject(appliance_id=aid, snapshot_id=snap_id, **kw)
    session.add(row); session.commit()
    return row


def test_policy_full_cached_resolves_content_routing_pools(session):
    """A content-routing policy leaves the top-level server-pool empty; each pool
    lives on the http_content_routing object the CR rule names. policy_full_cached
    must break that down so the detail view shows a pool per rule (the desglose)."""
    a = _appliance(session, name="fw-cr")
    snap = _deep_snapshot(session, a.id)
    pol = _obj(session, a.id, snap.id, layer="deep", section="Server Policy",
               logical_name="server_policy", mkey="pol-cr", depth=0,
               payload={"name": "pol-cr", "deployment-mode": "http-content-routing",
                        "server-pool": ""})
    # CR-list row names the routing policy but carries NO pool of its own
    _obj(session, a.id, snap.id, layer="deep", section="Server Policy",
         parent_id=pol.id, logical_name="server_policy/http-content-routing-list",
         subtable="http-content-routing-list", mkey="1", depth=1,
         payload={"id": "1", "content-routing-policy-name": "cr-api",
                  "web-protection-profile": ""})
    # the routing-policy object (top-level, config layer) carries the server-pool
    _obj(session, a.id, None, layer="config", section="Server Policy",
         logical_name="http_content_routing", mkey="cr-api", depth=0,
         payload={"name": "cr-api", "server-pool": "pool-api"})
    # the pool + its backends (deep so pserver-list children resolve)
    pool = _obj(session, a.id, snap.id, layer="deep", section="Server Objects",
                logical_name="server_pool", mkey="pool-api", depth=0,
                payload={"name": "pool-api"})
    _obj(session, a.id, snap.id, layer="deep", section="Server Objects",
         parent_id=pool.id, logical_name="server_pool/pserver-list",
         subtable="pserver-list", mkey="1", depth=1,
         payload={"id": "1", "ip": "192.0.2.9", "port": "80"})

    data, cr, meta = rl.policy_full_cached(a.id, "pol-cr", session=session)
    assert meta["layer"] == "deep"
    assert len(cr) == 1
    entry = cr[0]
    assert entry["pool"] == "pool-api"                       # the desglose
    assert [b["ip"] for b in entry["backends"]] == ["192.0.2.9"]
