"""Fleet objects — DB-FIRST aggregation from the Postgres cache (device_objects).

Verifies the fleet-wide browser reads the local source of truth (no appliance
network call) after the Phase-7 DB-first conversion.
"""
from __future__ import annotations

from app.services import device_store as ds
from app.services import fleet_objects as svc


def _appliance(session, name):
    from app.models import Appliance
    a = Appliance(name=name, kind="fortiweb", host="192.0.2.9", port=443,
                  username="admin", password_enc="x", verify_ssl=False)
    session.add(a); session.commit()
    return a


SECTIONS = {
    "Server Policy": {"server_policy": [
        {"name": "pol-a", "deployment-mode": "single-server",
         "server-pool": "pool-a", "web-protection-profile": "wpp-a",
         "status": "enable"},
        {"name": "pol-b", "deployment-mode": "server-pool",
         "server-pool": "pool-b", "status": "disable"},
    ]},
    "Server Pool": {"server_pool": [
        {"name": "pool-a", "type": "reverse-proxy", "protocol": "HTTP"},
    ]},
    "Web Protection": {
        "webprotection_profile_inline": [{"name": "wpp-a", "signature-rule": "sig-a"}],
        "webprotection_profile_offline": [{"name": "wpp-off"}],
    },
}


def test_collect_objects_db_first_server_policy(app, session):
    a = _appliance(session, "fw-fo1")
    ds.ingest_sections(a.id, SECTIONS, source="live", session=session)
    rows, errors = svc.collect_objects("server_policy")
    assert errors == []                      # DB-first → no live errors
    names = {r["name"] for r in rows if r["device"] == "fw-fo1"}
    assert names == {"pol-a", "pol-b"}
    row_a = next(r for r in rows if r["name"] == "pol-a")
    assert row_a["device"] == "fw-fo1"
    assert row_a["deployment_mode"] == "single-server"
    assert row_a["server_pool"] == "pool-a"


def test_collect_objects_wpp_merges_inline_and_offline_with_kind(app, session):
    a = _appliance(session, "fw-fo2")
    ds.ingest_sections(a.id, SECTIONS, source="live", session=session)
    rows, _ = svc.collect_objects("wpp")
    mine = [r for r in rows if r["device"] == "fw-fo2"]
    kinds = {r["name"]: r["kind"] for r in mine}
    assert kinds.get("wpp-a") == "inline-protection"
    assert kinds.get("wpp-off") == "offline-protection"


def test_collect_search_db_first(app, session):
    a = _appliance(session, "fw-fo3")
    ds.ingest_sections(a.id, SECTIONS, source="live", session=session)
    rows, _ = svc.collect_search("pool-a")
    assert any(r["device"] == "fw-fo3" and "pool-a" in r["value"].lower()
               for r in rows)
