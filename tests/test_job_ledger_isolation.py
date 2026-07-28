"""The job ledger is isolated, and ghosts do not haunt the dock forever.

Two defects met here on 2026-07-28, and together they put a floating "Working…"
window with a dead Stop button in front of the operator on EVERY page load:

1. the suite wrote REAL job files into the production ``data/jobs/`` tree —
   running the tests to verify a change was itself the thing that created the
   noise the change was meant to remove;
2. ``sweep_orphans`` ran ONLY at boot, so a job that went stale afterwards
   stayed "active" until the next restart. The dock re-opened a toast for it on
   every navigation, and Stop could never work because the worker never existed.

Contract pinned here: the ledger path is env-overridable and the tests are
somewhere else; a job that never got a pid is reaped in minutes, not hours; and
the read paths reap before they answer.
"""
from __future__ import annotations

import json
import pathlib
from datetime import datetime, timedelta

import pytest

from app.services import jobs as jobsvc
from tests.conftest import admin_user_id, login


@pytest.fixture()
def job_dir(tmp_path, monkeypatch):
    d = tmp_path / "jobs"
    d.mkdir()
    monkeypatch.setattr(jobsvc, "_state_dir", lambda: pathlib.Path(d))
    monkeypatch.setattr(jobsvc, "_last_sweep", 0.0)
    return d


def _backdate(job_dir, job_id, minutes):
    p = pathlib.Path(job_dir) / f"{job_id}.json"
    st = json.loads(p.read_text())
    old = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
    st["created"] = st["updated"] = old
    p.write_text(json.dumps(st))


# ---------------------------------------------------------------- isolation --

def test_the_suite_never_writes_into_the_repo_ledger():
    """conftest must redirect the ledger. Without this the tests litter the
    live app with jobs no worker will ever finish."""
    live = pathlib.Path(jobsvc.__file__).resolve().parents[2] / "data" / "jobs"
    assert jobsvc._state_dir().resolve() != live.resolve()


def test_state_dir_honours_the_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("SATOM_JOBS_DIR", str(tmp_path / "elsewhere"))
    assert jobsvc._state_dir() == (tmp_path / "elsewhere")


# ------------------------------------------------------------------ reaping --

def test_a_job_that_never_got_a_pid_is_reaped(job_dir):
    """run_async stamps the pid the instant the thread starts, so a job still
    missing one 11 minutes later was never dispatched."""
    job = jobsvc.create_job("deep_monitor", "Deep monitors — probe", by="admin")
    _backdate(job_dir, job["id"], 11)
    swept = jobsvc.sweep_orphans()
    assert [j["id"] for j in swept] == [job["id"]]
    assert jobsvc.get_job(job["id"])["status"] == jobsvc.ERROR


def test_a_fresh_job_awaiting_its_worker_survives(job_dir):
    job = jobsvc.create_job("deep_monitor", "Deep monitors — probe", by="admin")
    assert jobsvc.sweep_orphans() == []
    assert jobsvc.get_job(job["id"])["status"] == jobsvc.PENDING


def test_the_sweep_is_throttled(job_dir, monkeypatch):
    """The dock polls on every navigation; the sweep must not run every time."""
    calls = []
    monkeypatch.setattr(jobsvc, "sweep_orphans", lambda **k: calls.append(1) or [])
    jobsvc.maybe_sweep_orphans()
    jobsvc.maybe_sweep_orphans()
    jobsvc.maybe_sweep_orphans()
    assert len(calls) == 1


def test_the_sweep_never_breaks_the_feed_it_cleans(job_dir, monkeypatch):
    def boom(**k):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(jobsvc, "sweep_orphans", boom)
    assert jobsvc.maybe_sweep_orphans() == []


# --------------------------------------------------------------- the feeds --

def test_the_dock_feed_retires_a_ghost_instead_of_replaying_it(
        app, client, job_dir):
    """The end-to-end symptom: a stale job must not come back as a toast."""
    uid = admin_user_id(app)
    with app.app_context():
        from app.models import User
        me = User.query.get(uid).username
    login(client, uid)

    ghost = jobsvc.create_job("deep_monitor", "Deep monitors — probe", by=me)
    _backdate(job_dir, ghost["id"], 11)

    body = client.get("/jobs/?active=1").get_json()
    assert [j["id"] for j in body["jobs"]] == []
    assert jobsvc.get_job(ghost["id"])["status"] == jobsvc.ERROR


def test_a_live_foreground_job_still_reaches_the_dock(app, client, job_dir):
    uid = admin_user_id(app)
    with app.app_context():
        from app.models import User
        me = User.query.get(uid).username
    login(client, uid)

    live = jobsvc.create_job("bulk_apply", "Bulk apply", by=me)
    body = client.get("/jobs/?active=1").get_json()
    assert [j["id"] for j in body["jobs"]] == [live["id"]]
