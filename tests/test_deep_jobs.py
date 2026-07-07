"""deep_jobs — fleet deep-capture MIGRATED onto the global job framework
(services.jobs): the job is visible in the Job Manager, honours the cooperative
pause/stop checkpoints, and keeps the legacy per-device ledger + poll shape."""
import pathlib
import tempfile
import threading
import time
import types

import pytest

from app.services import deep_jobs, jobs


@pytest.fixture()
def tmpjobs(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setattr(jobs, "_state_dir", lambda: pathlib.Path(d))
    monkeypatch.setattr(jobs, "_PAUSE_POLL_S", 0.02)
    return d


def _wait_terminal(job_id, timeout_s=5.0):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        st = jobs.get_job(job_id)
        if st and st.get("status") not in jobs._ACTIVE:
            return st
        time.sleep(0.02)
    return jobs.get_job(job_id)


def test_new_job_is_a_global_job(tmpjobs):
    job = deep_jobs.new_job(device_ids=[1, 2, 3], by="tester")
    listed = jobs.list_jobs(type_=deep_jobs.JOB_TYPE)
    assert [j["id"] for j in listed] == [job["job_id"]]
    assert listed[0]["by"] == "tester"


def test_checkpoint_roundtrip_and_resume(tmpjobs):
    job = deep_jobs.new_job(device_ids=[1, 2, 3], by="tester")
    deep_jobs.mark_device(job["job_id"], 1, "ingested", objects=42)
    deep_jobs.mark_device(job["job_id"], 2, "failed", error="timeout")
    state = deep_jobs.load_job(job["job_id"])
    assert state["devices"]["1"]["state"] == "ingested"
    assert state["devices"]["1"]["objects"] == 42
    assert state["devices"]["2"]["state"] == "failed"
    # resume = only the not-yet-ingested devices
    assert set(deep_jobs.pending_device_ids(job["job_id"])) == {2, 3}


def test_run_fleet_processes_all_devices_with_bounded_concurrency(tmpjobs):
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


def test_run_fleet_one_failure_does_not_sink_the_fleet(tmpjobs):
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


def test_stop_skips_pending_devices(tmpjobs):
    """A Stop landing mid-fleet finishes the in-flight device and SKIPS the rest
    (the checkpoint contract) — the job never keeps hammering a fleet."""
    job = deep_jobs.new_job(device_ids=[1, 2, 3], by="t")

    def cap(device_id):
        jobs.request_cancel(job["job_id"])   # the stop lands during device 1
        return 1

    deep_jobs.run_fleet(job["job_id"], [1, 2, 3], cap, max_workers=1)
    st = deep_jobs.load_job(job["job_id"])
    assert st["devices"]["1"]["state"] == "ingested"
    assert st["devices"]["2"]["state"] == "skipped"
    assert st["devices"]["3"]["state"] == "skipped"


def test_start_fleet_job_success_end_to_end(tmpjobs, monkeypatch):
    monkeypatch.setattr(deep_jobs, "capture_device", lambda app, did: 5)
    job = deep_jobs.start_fleet_job(types.SimpleNamespace(), [1, 2], by="t")
    st = _wait_terminal(job["job_id"])
    assert st["status"] == jobs.SUCCESS
    assert st["result"]["done"] == 2
    legacy = deep_jobs.load_job(job["job_id"])
    assert legacy["finished"]
    assert legacy["percent"] == 100


def test_start_fleet_job_all_unreachable_marks_error(tmpjobs, monkeypatch):
    """Destination gone for the WHOLE fleet -> the job must terminate as error,
    never hang 'running' forever (the fw5 ghost)."""
    def dead(app, did):
        raise ConnectionError("connect timeout")

    monkeypatch.setattr(deep_jobs, "capture_device", dead)
    job = deep_jobs.start_fleet_job(types.SimpleNamespace(), [1, 2], by="t")
    st = _wait_terminal(job["job_id"])
    assert st["status"] == jobs.ERROR
    legacy = deep_jobs.load_job(job["job_id"])
    assert all(d["state"] == "failed" for d in legacy["devices"].values())
    assert legacy["finished"]


def test_stopped_fleet_job_lands_cancelled(tmpjobs, monkeypatch):
    def cap_then_cancel(app, did):
        jid = jobs.list_jobs(type_=deep_jobs.JOB_TYPE)[0]["id"]
        jobs.request_cancel(jid)
        return 1

    monkeypatch.setattr(deep_jobs, "capture_device", cap_then_cancel)
    job = deep_jobs.start_fleet_job(types.SimpleNamespace(), [1, 2, 3], by="t",
                                    max_workers=1)
    st = _wait_terminal(job["job_id"])
    assert st["status"] == jobs.CANCELLED
