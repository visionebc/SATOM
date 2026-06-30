"""The opt-in deep-capture branch of rediscovery (_run_deep), exercised without
a live box by monkeypatching the deep snapshot/persist functions."""
import json


def test_run_deep_persists_and_reports(app, monkeypatch, tmp_path):
    from app.services import rediscovery, device_sync
    monkeypatch.setattr(rediscovery, "_APP", app)
    captured = {}

    def fake_snapshot(appliance, **kw):
        return {"sections": {"Server Policy": {"server_policy": [{"name": "pol-z"}]}},
                "generated_at": "2026-06-30T18:40:00", "total_objects": 1}

    def fake_persist(appliance, snapshot, **kw):
        captured["snapshot"] = snapshot
        captured["appliance_id"] = appliance.id
        return {"Server Policy": {"objects": 1, "changed": True}}

    monkeypatch.setattr(device_sync, "deep_snapshot_from_device", fake_snapshot)
    monkeypatch.setattr(device_sync, "persist_deep_snapshot", fake_persist)

    from types import SimpleNamespace
    snap = SimpleNamespace(id=7, name="fw-z")
    pp = tmp_path / "progress.json"
    state = {"state": "done"}
    rediscovery._run_deep(snap, pp, state)

    assert state["state"] == "done"
    assert state["deep_objects"] == 1
    assert "deep_error" not in state
    assert captured["snapshot"]["total_objects"] == 1
    assert captured["appliance_id"] == 7
    # progress file written
    assert json.loads(pp.read_text())["state"] == "done"


def test_run_deep_records_error_without_breaking(app, monkeypatch, tmp_path):
    from app.services import rediscovery, device_sync
    monkeypatch.setattr(rediscovery, "_APP", app)

    def boom(appliance, **kw):
        raise RuntimeError("device unreachable")

    monkeypatch.setattr(device_sync, "deep_snapshot_from_device", boom)
    from types import SimpleNamespace
    state = {"state": "done"}
    rediscovery._run_deep(SimpleNamespace(id=1, name="x"), tmp_path / "p.json", state)
    assert state["state"] == "done"           # shallow run still 'done'
    assert "device unreachable" in state["deep_error"]
