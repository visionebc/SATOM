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
