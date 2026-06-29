"""Phase 1 — device-structure cache decomposer + ingest."""
from __future__ import annotations

import pytest

from app.services import device_store as ds


# Synthetic snapshot: a server policy with a nested pool sub-table, plus a pool
# with a 2-member pserver-list (nested object → child rows).
SECTIONS = {
    "server_policy": {
        "server_policy": [
            {"name": "pol-a", "deployment-mode": "single-server",
             "vserver": "vs-a", "server-pool": "pool-a",
             "web-protection-profile": "wpp-a", "status": "enable",
             "http-content-routing-list": [
                 {"id": "1", "content-routing-policy-name": "cr-1"},
             ]},
        ],
    },
    "server_objects": {
        "server_pool": [
            {"name": "pool-a", "type": "reverse-proxy", "protocol": "http",
             "pserver-list": [
                 {"id": "1", "ip": "192.0.2.1", "port": "80"},
                 {"id": "2", "ip": "192.0.2.2", "port": "80"},
             ]},
        ],
    },
}


def test_split_payload_separates_subtables():
    own, subs = ds.split_payload(SECTIONS["server_objects"]["server_pool"][0])
    assert own["name"] == "pool-a" and own["type"] == "reverse-proxy"
    assert "pserver-list" in subs and "pserver-list" not in own
    assert len(subs["pserver-list"]) == 2


def test_nodes_and_flatten_depth_and_parent_links():
    roots = ds.nodes_from_sections(SECTIONS)
    flat = ds.flatten(roots)
    # 2 roots (policy + pool) + 1 CR row + 2 pserver rows = 5 nodes
    assert len(flat) == 5
    by_logical = {}
    for node, parent in flat:
        by_logical.setdefault(node.logical_name, []).append((node, parent))
    # pool members are depth 1 under the pool, subtable=pserver-list
    members = by_logical["server_pool/pserver-list"]
    assert len(members) == 2
    for node, parent in members:
        assert node.depth == 1 and node.subtable == "pserver-list"
        assert parent is not None
    # the policy root has no parent and mkey from 'name'
    pol = by_logical["server_policy"][0][0]
    assert pol.depth == 0 and pol.mkey == "pol-a"
    # the CR sub-row hangs under the policy
    assert by_logical["server_policy/http-content-routing-list"][0][0].depth == 1


def test_content_hash_is_stable_and_excludes_children():
    obj = SECTIONS["server_objects"]["server_pool"][0]
    own, _ = ds.split_payload(obj)
    h1 = ds.content_hash(own)
    h2 = ds.content_hash(dict(reversed(list(own.items()))))  # key order invariant
    assert h1 == h2
    # changing a scalar changes the hash
    own2 = dict(own, type="offline")
    assert ds.content_hash(own2) != h1


def test_typed_projection_extractors():
    sp = ds.server_policy_row(SECTIONS["server_policy"]["server_policy"][0])
    assert sp["name"] == "pol-a" and sp["deployment_mode"] == "single-server"
    assert sp["server_pool"] == "pool-a" and sp["web_protection_profile"] == "wpp-a"
    pool = ds.server_pool_row(SECTIONS["server_objects"]["server_pool"][0])
    assert pool["name"] == "pool-a" and pool["protocol"] == "http"


# --- ingest round-trip (uses the test DB) -----------------------------------

def _make_appliance(session):
    from app.models import Appliance
    a = Appliance(name="fw-test", kind="fortiweb", host="192.0.2.9", port=443,
                  username="admin", password_enc="x", verify_ssl=False)
    session.add(a)
    session.commit()
    return a.id


def test_ingest_persists_objects_and_projections(session):
    aid = _make_appliance(session)
    res = ds.ingest_sections(aid, SECTIONS, source="import", session=session)
    assert res["server_policy"]["objects"] == 2     # policy + CR row
    assert res["server_objects"]["objects"] == 3    # pool + 2 members
    assert res["server_policy"]["changed"] is True

    from app.models_cache import (DeviceObject, DeviceServerPolicy,
                                  DeviceServerPool)
    assert session.query(DeviceObject).filter_by(appliance_id=aid).count() == 5
    # typed projections populated for the hot types
    sp = session.query(DeviceServerPolicy).filter_by(appliance_id=aid).one()
    assert sp.name == "pol-a" and sp.server_pool == "pool-a"
    pool = session.query(DeviceServerPool).filter_by(appliance_id=aid).one()
    assert pool.name == "pool-a"

    # parent linkage: members point at the pool row
    pool_obj = session.query(DeviceObject).filter_by(
        appliance_id=aid, logical_name="server_pool", depth=0).one()
    members = session.query(DeviceObject).filter_by(
        appliance_id=aid, logical_name="server_pool/pserver-list").all()
    assert len(members) == 2 and all(m.parent_id == pool_obj.id for m in members)


def test_ingest_is_idempotent_and_detects_no_change(session):
    aid = _make_appliance(session)
    ds.ingest_sections(aid, SECTIONS, source="import", session=session)
    res2 = ds.ingest_sections(aid, SECTIONS, source="import", session=session)
    # same content → changed False on the second run
    assert res2["server_policy"]["changed"] is False
    from app.models_cache import DeviceObject
    # replace-per-section: count stays 5, not doubled
    assert session.query(DeviceObject).filter_by(appliance_id=aid).count() == 5
