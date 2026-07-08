"""Tests for the discovery → physical-inventory sync (hybrid auto-fill).

Covers ``rediscovery.apply_inventory`` / ``maybe_apply_inventory``:
interfaces + model + HW/VM are auto-filled from a snapshot, while
operator-entered fields (connected_to, notes) are never overwritten and
existing rows are never deleted.
"""
import json

import pytest

from app.extensions import db
from app.models import Appliance, ApplianceInterface
from app.services import rediscovery


def _make_appliance(app, **kw):
    with app.app_context():
        a = Appliance(
            name=kw.get("name", "fw-sync"),
            kind="fortiweb",
            host="192.0.2.99",
            port=443,
            username="admin",
            verify_ssl=False,
            password_enc="placeholder",
            hw_type="unknown",
        )
        a.set_password("secret")
        db.session.add(a)
        db.session.commit()
        return a.id


def _write_snapshot(devdir, ifaces, generated_at="2026-06-28T00:00:00"):
    snap = {
        "generated_at": generated_at,
        "sections": {"Network": {"interface_2": ifaces}},
    }
    (devdir / "_config.json").write_text(json.dumps(snap), encoding="utf-8")


@pytest.fixture
def patched(app, tmp_path, monkeypatch):
    """Redirect the rediscovery data dir to a tmp path and stub the live
    status probe so the sync never hits the network."""
    monkeypatch.setattr(rediscovery, "_dev_dir", lambda aid: tmp_path)
    monkeypatch.setattr(rediscovery, "_model_from_status",
                        lambda appliance: ("FortiWeb-KVM 8.0.5", "vm", None))
    return tmp_path


def test_apply_creates_interfaces_and_sets_model(app, patched):
    aid = _make_appliance(app)
    _write_snapshot(patched, [
        {"name": "port1", "type": "physical", "ip": "192.0.2.10/24"},
        {"name": "port2", "type": "physical", "ip": "0.0.0.0/0"},  # blank IP
        {"name": "vlan10", "type": "vlan", "ip": "192.168.10.1/24"},
    ])
    with app.app_context():
        a = db.session.get(Appliance, aid)
        res = rediscovery.apply_inventory(a)
        assert res["applied"] is True
        assert res["interfaces_added"] == 3
        a = db.session.get(Appliance, aid)
        assert a.model == "FortiWeb-KVM 8.0.5"
        assert a.hw_type == "vm"
        by_name = {i.name: i for i in a.interfaces}
        assert by_name["port1"].ip_address == "192.0.2.10/24"
        assert by_name["port1"].if_type == "physical"
        assert by_name["port2"].ip_address is None  # 0.0.0.0/0 cleaned out
        assert by_name["vlan10"].if_type == "vlan"


def test_reapply_preserves_manual_fields_and_never_deletes(app, patched):
    aid = _make_appliance(app)
    _write_snapshot(patched, [{"name": "port1", "type": "physical", "ip": "192.0.2.10/24"}])
    with app.app_context():
        a = db.session.get(Appliance, aid)
        rediscovery.apply_inventory(a)
        # operator fills in the cabling + notes, and adds a doc-only interface
        a = db.session.get(Appliance, aid)
        p1 = next(i for i in a.interfaces if i.name == "port1")
        p1.connected_to = "Core-SW-A / Gi1/0/24"
        p1.notes = "uplink"
        db.session.add(ApplianceInterface(
            appliance_id=a.id, name="mgmt-doc", if_type="1G", connected_to="OOB switch"))
        db.session.commit()

    # a later discovery sees port1 with a changed type, and a new port2
    _write_snapshot(patched, [
        {"name": "port1", "type": "aggregate", "ip": "192.0.2.11/24"},
        {"name": "port2", "type": "physical", "ip": "192.0.2.12/24"},
    ], generated_at="2026-06-28T01:00:00")
    with app.app_context():
        a = db.session.get(Appliance, aid)
        res = rediscovery.apply_inventory(a)
        assert res["interfaces_added"] == 1   # only port2
        a = db.session.get(Appliance, aid)
        by_name = {i.name: i for i in a.interfaces}
        # auto fields refreshed
        assert by_name["port1"].if_type == "aggregate"
        assert by_name["port1"].ip_address == "192.0.2.11/24"
        # manual fields untouched
        assert by_name["port1"].connected_to == "Core-SW-A / Gi1/0/24"
        assert by_name["port1"].notes == "uplink"
        # doc-only interface not deleted
        assert "mgmt-doc" in by_name
        assert by_name["mgmt-doc"].connected_to == "OOB switch"


def test_maybe_apply_is_idempotent_per_snapshot(app, patched, monkeypatch):
    aid = _make_appliance(app)
    _write_snapshot(patched, [{"name": "port1", "type": "physical", "ip": "192.0.2.10/24"}])
    calls = {"n": 0}
    real_apply = rediscovery.apply_inventory

    def _counting_apply(appliance):
        calls["n"] += 1
        return real_apply(appliance)

    monkeypatch.setattr(rediscovery, "apply_inventory", _counting_apply)
    with app.app_context():
        a = db.session.get(Appliance, aid)
        first = rediscovery.maybe_apply_inventory(a)
        second = rediscovery.maybe_apply_inventory(a)  # same snapshot
        assert first is not None and first["applied"] is True
        assert second is None          # not re-applied
        assert calls["n"] == 1


def test_apply_without_snapshot_is_safe(app, patched):
    aid = _make_appliance(app)
    with app.app_context():
        a = db.session.get(Appliance, aid)
        res = rediscovery.apply_inventory(a)
        assert res == {"applied": False, "reason": "no snapshot"}
