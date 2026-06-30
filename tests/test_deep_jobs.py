"""deep_jobs — resumable per-device checkpoints + bounded device-level pool.
No network, no DB; state is a JSON file in a temp dir (monkeypatched)."""
import pathlib
import tempfile
import threading
import time

from app.services import deep_jobs


def test_checkpoint_roundtrip_and_resume(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setattr(deep_jobs, "_state_dir", lambda: pathlib.Path(d))
    job = deep_jobs.new_job(device_ids=[1, 2, 3], by="tester")
    deep_jobs.mark_device(job["job_id"], 1, "ingested", objects=42)
    deep_jobs.mark_device(job["job_id"], 2, "failed", error="timeout")
    state = deep_jobs.load_job(job["job_id"])
    assert state["devices"]["1"]["state"] == "ingested"
    assert state["devices"]["1"]["objects"] == 42
    assert state["devices"]["2"]["state"] == "failed"
    # resume = only the not-yet-ingested devices
    assert set(deep_jobs.pending_device_ids(job["job_id"])) == {2, 3}


def test_run_fleet_processes_all_devices_with_bounded_concurrency(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setattr(deep_jobs, "_state_dir", lambda: pathlib.Path(d))
    seen, peak = [], {"n": 0, "cur": 0}
    lk = threading.Lock()

    def fake_capture(device_id):
        with lk:
            peak["cur"] += 1
            peak["n"] = max(peak["n"], peak["cur"])
        time.sleep(0.02)
        with lk:
            peak["cur"] -= 1
            seen.append(device_id)
        return 7  # objects

    job = deep_jobs.new_job(device_ids=[1, 2, 3, 4, 5], by="t")
    deep_jobs.run_fleet(job["job_id"], [1, 2, 3, 4, 5], fake_capture, max_workers=2)
    assert sorted(seen) == [1, 2, 3, 4, 5]
    assert peak["n"] <= 2  # never more than max_workers devices at once
    assert deep_jobs.load_job(job["job_id"])["percent"] == 100


def test_run_fleet_one_failure_does_not_sink_the_fleet(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setattr(deep_jobs, "_state_dir", lambda: pathlib.Path(d))

    def cap(device_id):
        if device_id == 2:
            raise RuntimeError("boom")
        return 3

    job = deep_jobs.new_job(device_ids=[1, 2, 3], by="t")
    deep_jobs.run_fleet(job["job_id"], [1, 2, 3], cap, max_workers=3)
    st = deep_jobs.load_job(job["job_id"])
    assert st["devices"]["1"]["state"] == "ingested"
    assert st["devices"]["2"]["state"] == "failed"
    assert "boom" in (st["devices"]["2"]["error"] or "")
    assert st["devices"]["3"]["state"] == "ingested"
