"""Housekeeping jobs are silent unless they break.

Until 2026-07-28 every background job raised a floating toast with a Stop
button — a monitoring sweep the operator never asked to watch looked exactly
like a firmware flash they were waiting on — AND pushed a bell notification on
every successful run. Both are noise, and noise is how a notification area
stops being read.

The contract these tests pin:

1. a job is FOREGROUND unless it declares ``background=True`` (no job type can
   go silent by accident);
2. the toast dock's feed (``GET /jobs/?active=1``) never returns a background
   job, while the Job Manager (``/jobs/all``) still shows every one of them;
3. a background sweep that RAN pushes nothing; a sweep that FAILED pushes
   exactly one error notification — that is the only outcome the page itself
   cannot show.
"""
from __future__ import annotations

import pathlib

import pytest

from app.models import Appliance, MonitorProbe, User, db
from app.models_notifications import Notification
from app.services import jobs as jobsvc
from tests.conftest import login


@pytest.fixture(autouse=True)
def job_dir(tmp_path, monkeypatch):
    """Never write job files into the live data/jobs tree."""
    d = tmp_path / "jobs"
    d.mkdir()
    monkeypatch.setattr(jobsvc, "_state_dir", lambda: pathlib.Path(d))
    return d


@pytest.fixture()
def admin_id(app):
    with app.app_context():
        u = User.query.filter_by(role="admin").first()
        if u is None:
            u = User(username="bgadmin", role="admin", is_active=True)
            u.set_password("x" * 12)
            db.session.add(u)
            db.session.commit()
        return u.id


@pytest.fixture()
def me(app, admin_id):
    with app.app_context():
        return User.query.get(admin_id).username


@pytest.fixture()
def device(app):
    with app.app_context():
        a = Appliance(name="fw-bg", host="192.0.2.75", kind="fortiweb",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.flush()
        # one probe per page: cpu belongs to Deep monitors, sessions to
        # Service Monitor — so both /run routes have something to sweep.
        db.session.add(MonitorProbe(appliance_id=a.id, kind="cpu",
                                    name="fw-bg-cpu", enabled=True))
        db.session.add(MonitorProbe(appliance_id=a.id, kind="sessions",
                                    name="fw-bg-sessions", enabled=True))
        db.session.commit()
        return a.id


@pytest.fixture()
def sync_jobs(monkeypatch):
    """Run the worker inline so the assertion sees a finished job."""
    monkeypatch.setattr(jobsvc, "run_async",
                        lambda app, jid, worker: worker(app, jid))


# ---------------------------------------------------------------------------
# 1. the flag itself
# ---------------------------------------------------------------------------

def test_a_job_is_foreground_unless_it_says_otherwise(app):
    with app.app_context():
        assert jobsvc.create_job("t", "plain")["background"] is False
        assert jobsvc.create_job("t", "sweep", background=True)["background"] is True


# ---------------------------------------------------------------------------
# 2. the dock feed vs the Job Manager
# ---------------------------------------------------------------------------

def test_dock_feed_hides_background_jobs_but_manager_shows_them(
        app, client, admin_id, me):
    with app.app_context():
        fg = jobsvc.create_job("firmware_finalize", "Verifying image.out", by=me)
        bg = jobsvc.create_job("deep_monitor", "Deep monitors — probe",
                               by=me, background=True)
    login(client, admin_id)

    dock = client.get("/jobs/?active=1",
                      headers={"X-Requested-With": "XMLHttpRequest"}).get_json()
    ids = {j["id"] for j in dock["jobs"]}
    assert fg["id"] in ids, "a job someone is waiting on must still toast"
    assert bg["id"] not in ids, "housekeeping must not open a floating window"

    mgr = client.get("/jobs/all",
                     headers={"X-Requested-With": "XMLHttpRequest"}).get_json()
    assert {fg["id"], bg["id"]} <= {j["id"] for j in mgr["jobs"]}, \
        "the Jobs page is where background work stays visible"


# ---------------------------------------------------------------------------
# 3. the sweep is silent when it works, loud when it does not
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path,mod", [
    ("/monitoring/deep/run", "app.views.monitor_probes"),
    ("/monitoring/services/run", "app.views.monitor_probes"),
])
def test_successful_sweep_is_created_background_and_notifies_nobody(
        app, client, admin_id, device, sync_jobs, monkeypatch, path, mod):
    import importlib
    dm = importlib.import_module(mod).dm
    monkeypatch.setattr(dm, "sweep", lambda **kw: {
        "ran": 1, "counts": {"ok": 1}, "worst": "ok", "results": []})

    login(client, admin_id)
    r = client.post(path, headers={"X-Requested-With": "XMLHttpRequest"})
    assert r.status_code == 200, r.get_data(as_text=True)[:200]

    with app.app_context():
        job = jobsvc.get_job(r.get_json()["job_id"])
        assert job["background"] is True
        assert job["status"] == "success"
        assert Notification.query.count() == 0, \
            "a sweep that ran is not news — the table refreshes itself"


def test_failed_sweep_pushes_exactly_one_error_notification(
        app, client, admin_id, device, sync_jobs, monkeypatch):
    from app.views import monitor_probes

    def boom(**kw):
        raise RuntimeError("ssh refused")

    monkeypatch.setattr(monitor_probes.dm, "sweep", boom)

    login(client, admin_id)
    r = client.post("/monitoring/deep/run",
                    headers={"X-Requested-With": "XMLHttpRequest"})
    assert r.status_code == 200

    with app.app_context():
        job = jobsvc.get_job(r.get_json()["job_id"])
        assert job["status"] == "error"
        rows = Notification.query.all()
        assert len(rows) == 1, "the one outcome the page cannot show"
        assert rows[0].kind == Notification.KIND_ERROR
        assert "ssh refused" in (rows[0].title or "")


# ---------------------------------------------------------------------------
# 4. same rule for the fleet hardware scan
# ---------------------------------------------------------------------------

def test_hardware_scan_silent_on_a_clean_run_and_warns_on_a_partial_one(
        app, admin_id, device, monkeypatch):
    from app.services import hardware as hwsvc
    from app.views import monitoring

    with app.app_context():
        job = jobsvc.create_job("hardware_scan", "Hardware scan — fleet",
                                background=True)
        monkeypatch.setattr(hwsvc, "scan_appliance", lambda a: None)
        monitoring._run_hw_scan(app, job["id"], [device], admin_id, "t", "/x")
        assert jobsvc.get_job(job["id"])["status"] == "success"
        assert Notification.query.count() == 0

        def refuse(a):
            raise RuntimeError("no route to host")

        job2 = jobsvc.create_job("hardware_scan", "Hardware scan — fleet",
                                 background=True)
        monkeypatch.setattr(hwsvc, "scan_appliance", refuse)
        monitoring._run_hw_scan(app, job2["id"], [device], admin_id, "t", "/x")
        rows = Notification.query.all()
        assert len(rows) == 1
        assert rows[0].kind == Notification.KIND_ERROR
