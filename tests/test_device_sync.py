"""Phase 2 — sync orchestration + per-device JSON backup + backfill."""
from __future__ import annotations

import json
import os

import pytest

from app.services import device_sync as dsync


SNAP = {
    "device": "fw-sync", "appliance_id": None,  # filled per-test
    "generated_at": "2026-06-29T12:00:00", "total_objects": 3,
    "sections": {
        "server_policy": {"server_policy": [
            {"name": "pol-x", "deployment-mode": "single-server",
             "server-pool": "pool-x", "status": "enable"}]},
        "server_objects": {"server_pool": [
            {"name": "pool-x", "type": "reverse-proxy",
             "pserver-list": [{"id": "1", "ip": "1.1.1.1"},
                              {"id": "2", "ip": "1.1.1.2"}]}]},
    },
}


def _make_appliance(session, name="fw-sync"):
    from app.models import Appliance
    a = Appliance(name=name, kind="fortiweb", host="192.0.2.9", port=443,
                  username="admin", password_enc="x", verify_ssl=False)
    session.add(a)
    session.commit()
    return a


def test_persist_writes_json_and_cache_and_syncrun(session, tmp_path, monkeypatch):
    monkeypatch.setenv("FORTINET_REPORTS_DIR", str(tmp_path))
    a = _make_appliance(session)
    snap = dict(SNAP, appliance_id=a.id)

    run = dsync.persist_snapshot(a, snap, source="import", publish=False,
                                 session=session)
    # SyncRun recorded ok
    assert run.status == "ok" and run.section == "_all"
    # JSON backup written under reports/<slug>/_config.json
    p = tmp_path / "fw-sync" / "_config.json"
    assert p.exists()
    on_disk = json.loads(p.read_text())
    assert on_disk["sections"]["server_policy"]["server_policy"][0]["name"] == "pol-x"
    # cache populated
    from app.models_cache import DeviceObject, DeviceServerPolicy, SyncRun
    assert session.query(DeviceObject).filter_by(appliance_id=a.id).count() == 4
    assert session.query(DeviceServerPolicy).filter_by(appliance_id=a.id).one().name == "pol-x"
    assert session.query(SyncRun).filter_by(appliance_id=a.id).count() == 1


def test_backfill_from_git_seeds_cache(session, tmp_path, monkeypatch):
    monkeypatch.setenv("FORTINET_REPORTS_DIR", str(tmp_path))
    a = _make_appliance(session, name="fw-bf")
    # drop a reports/<slug>/_config.json as if pulled from git
    d = tmp_path / "fw-bf"
    d.mkdir()
    (d / "_config.json").write_text(json.dumps(dict(SNAP, appliance_id=a.id)))

    out = dsync.backfill_from_git(session=session)
    assert out["fw-bf"]["appliance_id"] == a.id
    from app.models_cache import DeviceObject
    assert session.query(DeviceObject).filter_by(appliance_id=a.id).count() == 4


def test_slugify():
    assert dsync.slugify("FW Demo / Ecom") == "FW-Demo-Ecom"
    assert dsync.slugify("") == "device"
