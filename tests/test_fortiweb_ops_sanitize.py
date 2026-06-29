"""FortiWebOps.sanitize_payload — write-time id-stripping (errcode 10 guard).

FortiWeb rejects a write that echoes back an auto-assigned id with
``errcode 10 "CMDB failed to be saved"``. These tests lock the cleaner to the
desktop standalone's verified ``_clean_for_write`` behaviour.
"""
from __future__ import annotations


def test_strips_auto_assigned_ids_and_metadata():
    from app.services.fortiweb_ops import sanitize_payload
    raw = {
        "name": "pol-x", "status": "enable", "vserver": "vs-x",
        "policy-id": 7, "profile-id": 3, "server-pool-id": 9, "vserver-id": 2,
        "health-id": 1, "index": 4, "status_val": "enable",
        "deployment-mode_val": "1", "q_ref": 1, "_ref": "x", "can_clone": 1,
        "can_view": 1, "is_default": 0, "flag": 2,
        # KEPT — real sub-row keys FortiWeb reassigns, not auto object ids
        "signature_id": "010000001", "main_class_id": 10, "id": 5,
    }
    out = sanitize_payload(raw)
    for gone in ("policy-id", "profile-id", "server-pool-id", "vserver-id",
                 "health-id", "index", "status_val", "deployment-mode_val",
                 "q_ref", "_ref", "can_clone", "can_view", "is_default", "flag"):
        assert gone not in out, f"{gone} should be stripped"
    assert out["name"] == "pol-x"
    assert out["status"] == "enable"
    assert out["vserver"] == "vs-x"
    assert out["signature_id"] == "010000001"
    assert out["main_class_id"] == 10
    assert out["id"] == 5


def test_recurses_into_data_wrapper_and_sublists():
    from app.services.fortiweb_ops import sanitize_payload
    raw = {"data": {
        "name": "pool-x", "server-pool-id": 11,
        "pserver-list": [
            {"id": 1, "ip": "192.0.2.5", "server-id": 99, "status_val": "enable"},
            {"id": 2, "ip": "192.0.2.6", "server-id": 100},
        ],
    }}
    out = sanitize_payload(raw)
    inner = out["data"]
    assert "server-pool-id" not in inner
    rows = inner["pserver-list"]
    assert all("server-id" not in r for r in rows), "row -id must be stripped"
    assert all("status_val" not in r for r in rows)
    assert rows[0]["ip"] == "192.0.2.5" and rows[0]["id"] == 1


def test_non_dict_passthrough():
    from app.services.fortiweb_ops import sanitize_payload
    assert sanitize_payload("x") == "x"
    assert sanitize_payload(None) is None
    assert sanitize_payload(5) == 5
