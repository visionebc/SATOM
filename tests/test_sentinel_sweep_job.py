"""The sweep picker, and the sweep as a JOB.

The console's "Run sweep now" ran the whole fleet synchronously inside the
request. At five appliances that is invisible; at the ninety this product is
sized for it holds a gunicorn worker for minutes, shows no progress at all,
and a browser that gives up leaves a sweep running that nobody is told about.

Two things are held here, and the second is the one that is easy to lose:

* the sweep can be **restricted to chosen devices**, and the restriction is
  applied inside :func:`pipeline.sweep` rather than only in the caller — the
  rule that a device in maintenance is never contacted belongs to the sweep,
  which is exactly the lesson the deep monitors paid for when they probed
  recycled IPs every three minutes because that rule lived in a caller;
* the scheduled sweep is **unchanged**. It calls ``sweep()`` with no
  arguments, and nothing about the picker may alter what that does.
"""
from __future__ import annotations

import pytest

from app.models import Appliance, db
from tests.conftest import admin_user_id, login


@pytest.fixture()
def admin(app, client):
    login(client, admin_user_id(app), product="global")
    return client


def _dev(name, kind="fortiweb", maintenance=False, host=None):
    a = Appliance(name=name, host=host or "10.0.0.%d" % (abs(hash(name)) % 200 + 20),
                  port=443, kind=kind, username="admin", maintenance=maintenance)
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


def _fleet(app):
    with app.app_context():
        _dev("fw-a")
        _dev("fw-b")
        _dev("fw-maint", maintenance=True)
        _dev("fw-dead", host="retired.invalid")
        _dev("adc-a", kind="fortiadc")


# ------------------------------------------------------------- the picker --

def test_the_picker_offers_fortiweb_only(app, admin):
    """A FortiADC has no attack log, which is what a sweep ingests. Offering
    one would offer a selection that can only ever return nothing — the kind
    of control that looks broken because it is meaningless."""
    _fleet(app)
    with app.test_request_context():
        login_free = None  # noqa: F841  (documenting: no request state needed)
    with app.app_context():
        from app.views.sentinel import sweep_targets
        names = [r["name"] for r in sweep_targets()]
    assert "fw-a" in names and "fw-b" in names
    assert "adc-a" not in names, "the picker offers a FortiADC"


def test_the_picker_lists_a_skipped_device_and_says_why(app):
    """Listed, not hidden. The pipeline skips a retired ``.invalid`` host
    deliberately; a device missing from the list looks like a device that does
    not exist, and the operator goes looking for it instead of reading why it
    was not swept."""
    _fleet(app)
    with app.app_context():
        from app.views.sentinel import sweep_targets
        rows = {r["name"]: r for r in sweep_targets()}
    assert rows["fw-dead"]["eligible"] is False
    assert rows["fw-dead"]["reason"], "a skipped device gives no reason"
    assert rows["fw-a"]["eligible"] is True and not rows["fw-a"]["reason"]


def test_a_maintenance_device_is_never_offered_as_eligible(app):
    """Two rules meet here and both must hold.

    Appliance VISIBILITY is scoped by ``appliances.view_maintenance``, so a
    caller without it does not see the row at all — the picker must not be the
    place that leaks it back. And a caller WITH it sees the row, in which case
    it has to be marked ineligible rather than offered: the sweep would skip it
    anyway, and a tickable box for work that will not happen is a lie the
    result page then has to explain.
    """
    _fleet(app)
    with app.app_context():
        from app.views.sentinel import sweep_targets
        rows = {r["name"]: r for r in sweep_targets()}
    row = rows.get("fw-maint")
    assert row is None or row["eligible"] is False, row


def test_the_console_draws_the_picker(app, admin):
    _fleet(app)
    body = admin.get("/sentinel/").get_data(as_text=True)
    assert 'id="sn-sweep-modal"' in body, "no sweep picker on the console"
    assert 'name="device" value="fw-a"' in body
    assert 'name="device" value="adc-a"' not in body


# ---------------------------------------------------------- the restriction --

def _sweep(app, monkeypatch, trace=None, **kw):
    """Run a sweep with the device read stubbed out, and report who was read.

    Stubbed because the real collector opens a session to an appliance, and a
    test that reaches a device is a test that fails for reasons that have
    nothing to do with what it asserts. ``trace``, when given, receives a
    "collect:<name>" entry — the progress test needs the two kinds of event in
    ONE ordered list, or "before" and "after" are indistinguishable.
    """
    from app.services.sentinel import pipeline
    seen = []

    def _collect(appliance, limit=None):
        seen.append(appliance.name)
        if trace is not None:
            trace.append("collect:" + appliance.name)
        return {"device": appliance.name, "read": 0, "new": 0, "duplicate": 0,
                "status": "ok", "detail": "", "ms": 1}

    monkeypatch.setattr(pipeline, "collect_device", _collect)
    monkeypatch.setattr(pipeline, "_report", lambda result: None)
    with app.app_context():
        result = pipeline.sweep(**kw)
    return seen, result


def test_a_sweep_with_no_argument_still_reads_every_eligible_device(app, monkeypatch):
    """The scheduled action passes nothing. The picker must not have changed
    what that means, or an operator's convenience would have quietly narrowed
    the automatic sweep."""
    _fleet(app)
    seen, result = _sweep(app, monkeypatch)
    assert sorted(seen) == ["fw-a", "fw-b"]
    assert result["ok"] and not result.get("skipped")


def test_a_sweep_reads_only_the_devices_it_was_given(app, monkeypatch):
    _fleet(app)
    seen, result = _sweep(app, monkeypatch, devices=["fw-b"])
    assert seen == ["fw-b"]
    assert "1 device(s)" in result["detail"], result["detail"]


def test_the_sweep_itself_drops_an_ineligible_name(app, monkeypatch):
    """Belt and braces on purpose: the route filters too, but the rule that a
    device in maintenance is never contacted has to hold for any caller."""
    _fleet(app)
    seen, _ = _sweep(app, monkeypatch, devices=["fw-a", "fw-maint", "fw-dead"])
    assert seen == ["fw-a"]


def test_progress_is_reported_before_each_device(app, monkeypatch):
    """Before, not after — and the ordering is what is asserted.

    The counters look identical either way, so a test that only reads them
    passes against a callback moved after the read. It matters because the
    read is the slow part: fired afterwards, the operator sees nothing at all
    for the whole of the first (and possibly slowest) device, and a sweep that
    is slow becomes indistinguishable from a sweep that is stuck. The same
    call site is the job's stop CHECKPOINT, so afterwards it would also mean a
    Stop is honoured only once the device it was meant to spare has been read.
    """
    _fleet(app)
    trace = []
    _sweep(app, monkeypatch, trace=trace,
           on_device=lambda d, t, n: trace.append("progress:%d/%d:%s" % (d, t, n)))
    assert trace == ["progress:0/2:fw-a", "collect:fw-a",
                     "progress:1/2:fw-b", "collect:fw-b"], trace


# ------------------------------------------------------------- the route --

def test_the_route_starts_a_job_and_does_not_sweep_in_the_request(app, admin,
                                                                 monkeypatch):
    """The response must come back before the work does. A route that still
    swept inline would pass every other test in this file and go on holding a
    worker for minutes."""
    _fleet(app)
    from app.services.sentinel import sweep_job
    started = {}

    def _start(flask_app, names, by=""):
        started["names"] = list(names)
        started["by"] = by
        return {"id": "job-1"}

    monkeypatch.setattr(sweep_job, "start", _start)
    r = admin.post("/sentinel/run",
                   data={"device": ["fw-a", "fw-b"], "return_to": "pane"})
    assert r.status_code == 302
    assert r.headers["Location"].endswith("#tab-sentinel-console")
    assert started["names"] == ["fw-a", "fw-b"]
    assert started["by"], "the job does not record who asked for it"


def test_an_unknown_device_is_refused_not_quietly_dropped(app, admin,
                                                          monkeypatch):
    """Running "the rest of them" would report a sweep of a selection nobody
    made. A stale page or a hand-built POST has to fail visibly."""
    _fleet(app)
    from app.services.sentinel import sweep_job
    monkeypatch.setattr(sweep_job, "start",
                        lambda *a, **k: pytest.fail("a job was started"))
    r = admin.post("/sentinel/run", data={"device": ["fw-a", "nope"]})
    assert r.status_code == 400


def test_a_selection_of_only_ineligible_devices_starts_nothing(app, admin,
                                                               monkeypatch):
    """Distinct from the empty selection, which means "everything". Starting a
    fleet-wide sweep because every picked device turned out to be skippable is
    the opposite of what was asked for."""
    _fleet(app)
    from app.services.sentinel import sweep_job
    monkeypatch.setattr(sweep_job, "start",
                        lambda *a, **k: pytest.fail("a job was started"))
    r = admin.post("/sentinel/run", data={"device": ["fw-maint"]})
    assert r.status_code == 302


def test_the_route_says_so_when_sentinel_is_switched_off(app, admin,
                                                          monkeypatch):
    _fleet(app)
    from app.services.sentinel import config, sweep_job
    monkeypatch.setattr(sweep_job, "start",
                        lambda *a, **k: pytest.fail("a job was started"))
    with app.app_context():
        config.set_value("enabled", False)
    r = admin.post("/sentinel/run", data={})
    assert r.status_code == 302


def test_the_worker_finishes_the_job_with_the_sweep_result(app, monkeypatch,
                                                            tmp_path):
    """The job is a way of RUNNING the sweep, not a second opinion about what
    it found: the pipeline's own result dict is what lands on the job."""
    import os
    os.environ["SATOM_JOBS_DIR"] = str(tmp_path / "jobs")
    _fleet(app)
    from app.services import jobs
    from app.services.sentinel import pipeline, sweep_job
    monkeypatch.setattr(pipeline, "collect_device",
                        lambda a, limit=None: {"device": a.name, "read": 0,
                                               "new": 0, "duplicate": 0,
                                               "status": "ok", "detail": "",
                                               "ms": 1})
    monkeypatch.setattr(pipeline, "_report", lambda result: None)
    job = jobs.create_job(sweep_job.JOB_TYPE, "t", by="tester")
    with app.app_context():
        result = sweep_job.run(job["id"], ["fw-a"])
    assert result["ok"]
    state = jobs.get_job(job["id"])
    assert state["status"] == jobs.SUCCESS
    assert state["result"]["detail"] == result["detail"]
    os.environ.pop("SATOM_JOBS_DIR", None)
