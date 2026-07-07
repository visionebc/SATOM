"""Job Manager: cooperative pause/resume, orphan sweep, and the /jobs manager
API scope (admin sees everyone's jobs, a regular user only their own)."""
import pathlib
import tempfile
import threading
import time
import types

import pytest

from app.services import jobs
from tests.conftest import admin_user_id, login, make_user


@pytest.fixture()
def tmpjobs(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setattr(jobs, "_state_dir", lambda: pathlib.Path(d))
    # keep the parked-checkpoint loop fast in tests
    monkeypatch.setattr(jobs, "_PAUSE_POLL_S", 0.02)
    return d


# ── pause / resume primitives ───────────────────────────────────────────────
def test_request_pause_flips_status_and_flag(tmpjobs):
    job = jobs.create_job("bulk_apply", "Apply", by="ana")
    jobs.update_job(job["id"], status=jobs.RUNNING)
    st = jobs.request_pause(job["id"])
    assert st["status"] == jobs.PAUSING
    assert st["pause_requested"] is True
    st = jobs.request_resume(job["id"])
    assert st["status"] == jobs.RUNNING
    assert st["pause_requested"] is False


def test_pause_ignored_on_terminal_or_cancelling(tmpjobs):
    job = jobs.create_job("t", "x", by="ana")
    jobs.finish_success(job["id"])
    assert jobs.request_pause(job["id"])["pause_requested"] is False
    job2 = jobs.create_job("t", "x", by="ana")
    jobs.request_cancel(job2["id"])
    assert jobs.request_pause(job2["id"])["pause_requested"] is False


def test_cancel_overrides_pending_pause(tmpjobs):
    job = jobs.create_job("t", "x", by="ana")
    jobs.update_job(job["id"], status=jobs.RUNNING)
    jobs.request_pause(job["id"])
    st = jobs.request_cancel(job["id"])
    assert st["status"] == jobs.CANCELLING
    assert st["pause_requested"] is False


def test_set_progress_respects_pause(tmpjobs):
    job = jobs.create_job("t", "x", by="ana")
    jobs.update_job(job["id"], status=jobs.RUNNING)
    jobs.request_pause(job["id"])
    jobs.set_progress(job["id"], 40, "ticking toward a checkpoint")
    assert jobs.get_job(job["id"])["status"] == jobs.PAUSING


def test_checkpoint_parks_while_paused_then_resumes(tmpjobs):
    job = jobs.create_job("t", "x", by="ana")
    jobs.update_job(job["id"], status=jobs.RUNNING)
    jobs.request_pause(job["id"])
    released = threading.Event()

    def parked():
        jobs.checkpoint(job["id"])   # blocks until resume
        released.set()

    t = threading.Thread(target=parked, daemon=True)
    t.start()
    for _ in range(100):             # wait for it to park + report paused
        if (jobs.get_job(job["id"]) or {}).get("status") == jobs.PAUSED:
            break
        time.sleep(0.02)
    assert jobs.get_job(job["id"])["status"] == jobs.PAUSED
    assert not released.is_set()
    jobs.request_resume(job["id"])
    assert released.wait(2.0)
    assert jobs.get_job(job["id"])["status"] == jobs.RUNNING


def test_checkpoint_cancel_while_parked_raises(tmpjobs):
    job = jobs.create_job("t", "x", by="ana")
    jobs.update_job(job["id"], status=jobs.RUNNING)
    jobs.request_pause(job["id"])
    raised = threading.Event()

    def parked():
        try:
            jobs.checkpoint(job["id"])
        except jobs.JobCancelled:
            raised.set()

    threading.Thread(target=parked, daemon=True).start()
    time.sleep(0.1)
    jobs.request_cancel(job["id"])
    assert raised.wait(2.0)


def test_paused_jobs_are_active_for_pollers(tmpjobs):
    job = jobs.create_job("t", "x", by="ana")
    jobs.update_job(job["id"], status=jobs.PAUSED)
    active = jobs.list_jobs(by="ana", active_only=True)
    assert any(j["id"] == job["id"] for j in active)


# ── orphan sweep ────────────────────────────────────────────────────────────
def test_sweep_marks_dead_pid_job_as_error(tmpjobs):
    job = jobs.create_job("signatures_sync", "Sync fw5", by="ana")
    jobs.update_job(job["id"], status=jobs.RUNNING, pid=999999999)
    swept = jobs.sweep_orphans()
    assert [j["id"] for j in swept] == [job["id"]]
    st = jobs.get_job(job["id"])
    assert st["status"] == jobs.ERROR
    assert "restarted" in st["error"]
    assert st["finished"] is not None


def test_sweep_spares_live_pid_and_terminal_jobs(tmpjobs):
    import os
    live = jobs.create_job("t", "live", by="ana")
    jobs.update_job(live["id"], status=jobs.RUNNING, pid=os.getpid())
    done = jobs.create_job("t", "done", by="ana")
    jobs.finish_success(done["id"])
    assert jobs.sweep_orphans() == []
    assert jobs.get_job(live["id"])["status"] == jobs.RUNNING


def test_sweep_marks_stale_pidless_job(tmpjobs):
    job = jobs.create_job("t", "legacy", by="ana")
    # write directly — update_job would re-stamp ``updated`` with "now"
    st = jobs.get_job(job["id"])
    st.update(status=jobs.RUNNING, pid=None, updated="2020-01-01T00:00:00")
    jobs._write(job["id"], st)
    swept = jobs.sweep_orphans()
    assert [j["id"] for j in swept] == [job["id"]]


@pytest.mark.parametrize("status", [jobs.PENDING, jobs.CANCELLING,
                                    jobs.PAUSING, jobs.PAUSED])
def test_sweep_covers_every_nonterminal_state(tmpjobs, status):
    """ANY non-terminal job whose worker no longer exists is failed by the boot
    sweep — cancelling/pausing/paused ghosts included, not just 'running'."""
    job = jobs.create_job("t", "ghost-%s" % status, by="ana")
    jobs.update_job(job["id"], status=status, pid=999999999)
    swept = jobs.sweep_orphans()
    assert [j["id"] for j in swept] == [job["id"]]
    st = jobs.get_job(job["id"])
    assert st["status"] == jobs.ERROR
    assert st["finished"] is not None


def test_sweep_leaves_other_hosts_jobs_alone(tmpjobs):
    job = jobs.create_job("t", "elsewhere", by="ana")
    jobs.update_job(job["id"], status=jobs.RUNNING, pid=999999999,
                    host="another-box")
    assert jobs.sweep_orphans() == []
    assert jobs.get_job(job["id"])["status"] == jobs.RUNNING


# ── manager API scope + controls ────────────────────────────────────────────
def _seed_two_users_jobs(tmpjobs):
    mine = jobs.create_job("bulk_apply", "Bob's job", by="bob")
    jobs.update_job(mine["id"], status=jobs.RUNNING)
    other = jobs.create_job("bulk_apply", "Admin's job", by="admin")
    jobs.update_job(other["id"], status=jobs.RUNNING)
    return mine, other


def test_all_endpoint_scopes_regular_user_to_own_jobs(app, client, tmpjobs):
    mine, other = _seed_two_users_jobs(tmpjobs)
    uid = make_user(app, username="bob", role="readonly")
    login(client, uid)
    data = client.get("/jobs/all").get_json()
    ids = {j["id"] for j in data["jobs"]}
    assert mine["id"] in ids and other["id"] not in ids
    assert data["admin"] is False


def test_all_endpoint_gives_admin_everything(app, client, tmpjobs):
    mine, other = _seed_two_users_jobs(tmpjobs)
    login(client, admin_user_id(app))
    data = client.get("/jobs/all").get_json()
    ids = {j["id"] for j in data["jobs"]}
    assert {mine["id"], other["id"]} <= ids
    assert data["admin"] is True


def test_admin_can_pause_and_resume_someone_elses_job(app, client, tmpjobs):
    mine, _ = _seed_two_users_jobs(tmpjobs)
    login(client, admin_user_id(app))
    r = client.post(f"/jobs/{mine['id']}/pause")
    assert r.status_code == 200
    assert jobs.get_job(mine["id"])["status"] == jobs.PAUSING
    r = client.post(f"/jobs/{mine['id']}/resume")
    assert r.status_code == 200
    assert jobs.get_job(mine["id"])["status"] == jobs.RUNNING


def test_regular_user_cannot_touch_foreign_job(app, client, tmpjobs):
    _, other = _seed_two_users_jobs(tmpjobs)
    uid = make_user(app, username="bob", role="readonly")
    login(client, uid)
    assert client.post(f"/jobs/{other['id']}/pause").status_code == 404
    assert client.post(f"/jobs/{other['id']}/cancel").status_code == 404
    assert client.get(f"/jobs/{other['id']}").status_code == 404


def test_pause_refused_for_non_cancelable_or_finished(app, client, tmpjobs):
    locked = jobs.create_job("firmware_flash", "Flash", by="admin",
                             cancelable=False)
    jobs.update_job(locked["id"], status=jobs.RUNNING)
    done = jobs.create_job("t", "done", by="admin")
    jobs.finish_success(done["id"])
    login(client, admin_user_id(app))
    assert client.post(f"/jobs/{locked['id']}/pause").status_code == 409
    assert client.post(f"/jobs/{done['id']}/pause").status_code == 409
    assert client.post(f"/jobs/{done['id']}/resume").status_code == 409


def test_manager_page_renders(app, client, tmpjobs):
    login(client, admin_user_id(app))
    r = client.get("/jobs/manager")
    assert r.status_code == 200
    assert b"Jobs" in r.data
