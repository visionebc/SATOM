"""Cooperative cancellation + the reusable Rollback harness (services.jobs), and
the cooperative Stop wired into bulk.apply's device/item loop (bulk._run_one).
No network, no DB; job state is a JSON file in a temp dir (monkeypatched)."""
import pathlib
import tempfile
import time
import types

import pytest

from app.services import jobs


@pytest.fixture()
def tmpjobs(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setattr(jobs, "_state_dir", lambda: pathlib.Path(d))
    return d


# ── cancel primitive ────────────────────────────────────────────────────────
def test_create_defaults_and_cancel_flags(tmpjobs):
    job = jobs.create_job("bulk_apply", "Apply", by="ana")
    assert job["status"] == jobs.PENDING
    assert job["cancelable"] is True and job["reversible"] is False
    assert job["cancel_requested"] is False


def test_request_cancel_flips_status_and_sets_flag(tmpjobs):
    job = jobs.create_job("bulk_apply", "Apply", by="ana")
    jobs.update_job(job["id"], status=jobs.RUNNING)
    updated = jobs.request_cancel(job["id"])
    assert updated["status"] == jobs.CANCELLING
    assert updated["cancel_requested"] is True
    assert jobs.is_cancel_requested(job["id"]) is True


def test_checkpoint_raises_when_cancelled(tmpjobs):
    job = jobs.create_job("t", "x", by="ana")
    jobs.checkpoint(job["id"])  # no cancel yet → no raise
    jobs.request_cancel(job["id"])
    with pytest.raises(jobs.JobCancelled):
        jobs.checkpoint(job["id"])


def test_request_cancel_leaves_terminal_job_untouched(tmpjobs):
    job = jobs.create_job("t", "x", by="ana")
    jobs.finish_success(job["id"], message="done")
    out = jobs.request_cancel(job["id"])
    assert out["status"] == jobs.SUCCESS
    assert out["cancel_requested"] is False


def test_finish_cancelled_is_terminal_and_distinct_from_error(tmpjobs):
    job = jobs.create_job("t", "x", by="ana")
    jobs.request_cancel(job["id"])
    jobs.finish_cancelled(job["id"], message="Stopped", result={"mid_change": []})
    st = jobs.get_job(job["id"])
    assert st["status"] == jobs.CANCELLED
    assert st["error"] is None
    assert st["finished"] is not None
    # cancelling jobs are still "active" for the poller; cancelled is not
    active = jobs.list_jobs(by="ana", active_only=True)
    assert all(j["id"] != job["id"] for j in active)


def test_set_progress_reflects_pending_cancel(tmpjobs):
    job = jobs.create_job("t", "x", by="ana")
    jobs.update_job(job["id"], status=jobs.RUNNING)
    jobs.request_cancel(job["id"])
    jobs.set_progress(job["id"], 40, "still going")
    assert jobs.get_job(job["id"])["status"] == jobs.CANCELLING


def test_run_async_marks_cancelled_when_worker_raises(tmpjobs):
    app = types.SimpleNamespace(logger=types.SimpleNamespace(
        exception=lambda *a, **k: None))
    job = jobs.create_job("t", "x", by="ana")

    def worker(_app, job_id):
        for _ in range(50):
            jobs.checkpoint(job_id)   # will raise once cancelled
            time.sleep(0.01)

    jobs.run_async(app, job["id"], worker)
    time.sleep(0.03)
    jobs.request_cancel(job["id"])
    # wait for the daemon thread to observe the cancel and finalize
    for _ in range(100):
        if jobs.get_job(job["id"])["status"] in jobs._TERMINAL:
            break
        time.sleep(0.02)
    assert jobs.get_job(job["id"])["status"] == jobs.CANCELLED


# ── Rollback harness ────────────────────────────────────────────────────────
def test_rollback_replays_in_reverse_best_effort():
    rb = jobs.Rollback()
    order = []
    rb.add(lambda: order.append("a"), label="a")
    rb.add(lambda: (_ for _ in ()).throw(RuntimeError("boom")), label="b")
    rb.add(lambda: order.append("c"), label="c")
    report = rb.run()
    # newest-first replay: c, b(fails), a
    assert order == ["c", "a"]
    assert [(r["label"], r["ok"]) for r in report] == [("c", True), ("b", False), ("a", True)]
    assert "boom" in report[1]["error"]


def test_rollback_empty_is_noop():
    assert jobs.Rollback().run() == []


# ── bulk cooperative stop (pure; fake ops, no DB) ───────────────────────────
def _fake_opresult(ok):
    return types.SimpleNamespace(ok=ok)


def test_bulk_run_one_stops_at_item_boundary_and_records_committed(tmpjobs, monkeypatch):
    from app.services import bulk

    calls = []

    class FakeOps:
        def __init__(self, appliance):
            pass

        def create(self, ep, data, *, mkey=None, dry_run=True):
            calls.append((ep, mkey)); return _fake_opresult(True)

        def update(self, ep, mkey, data, *, dry_run=True):
            calls.append((ep, mkey)); return _fake_opresult(True)

        def delete(self, ep, mkey, *, dry_run=True):
            calls.append((ep, mkey)); return _fake_opresult(True)

    monkeypatch.setattr(bulk, "FortiWebOps", FakeOps)

    job = jobs.create_job("bulk_apply", "x", by="ana")
    items = [
        {"action": "create", "endpoint": "pool", "mkey": "p1", "data": {}},
        {"action": "create", "endpoint": "vserver", "mkey": "v1", "data": {}},
        {"action": "create", "endpoint": "policy", "mkey": "pol1", "data": {}},
    ]
    # cancel becomes true after the first item has been applied
    seq = {"n": 0}

    def fake_cancel(jid):
        seq["n"] += 1
        return seq["n"] > 1   # False on the first check, True afterward

    monkeypatch.setattr(jobs, "is_cancel_requested", fake_cancel)

    appliance = types.SimpleNamespace(id=7, name="fw1")
    out = bulk._run_one(appliance, items, dry_run=False, job_id=job["id"])

    assert out["cancelled"] is True
    # only the first item was applied before the stop was seen
    assert calls == [("pool", "p1")]
    assert out["committed"] == [{"endpoint": "pool", "mkey": "p1", "action": "create"}]
