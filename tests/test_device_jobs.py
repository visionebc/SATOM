"""Every action on a device runs as a background job (services/device_jobs).

What has to hold for that to be safe rather than merely present:

* coverage: every POST of a device blueprint is wrapped or excluded with a
  reason — a new route cannot silently stay synchronous;
* fidelity: a fast action returns its real response unchanged, a slow one
  answers 202 (fetch) / 303 to the wait page (form) and its stored response
  replays exactly, flashes included;
* the ledger lists device work only — a validation error leaves no job;
* writes to one device queue behind each other, a queued job can be stopped,
  and a job writing to the device can no longer be stopped mid-way;
* standby and API-token callers keep the old synchronous path.

No device is contacted: httpx.Client is replaced.
"""
from __future__ import annotations

import inspect
import json
import pathlib
import re
import threading
import time

import pytest

from app.clients import base as client_base
from app.extensions import db
from app.models import Appliance
from app.services import device_jobs, job_progress, jobs, rediscovery
from tests.conftest import admin_user_id, login

ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _private_jobs(tmp_path, monkeypatch):
    monkeypatch.setenv("SATOM_JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("SATOM_REDISCOVERY_DIR", str(tmp_path / "rediscovery"))
    monkeypatch.setattr(device_jobs, "_is_standby", lambda: False)
    monkeypatch.setattr(job_progress, "_LOCK_POLL_S", 0.02)
    monkeypatch.setattr(jobs, "_PAUSE_POLL_S", 0.02)


class _Resp:
    status_code = 200

    def json(self):
        return {"results": {"version": "v7.6.8"}}


def _fake_httpx(monkeypatch, delay=0.0, calls=None):
    class _Client:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def request(self, method, url, **kw):
            time.sleep(delay)
            if calls is not None:
                calls.append((method, url))
            return _Resp()
    monkeypatch.setattr(client_base.httpx, "Client", _Client)


@pytest.fixture()
def jobs_app(app):
    app.config["DEVICE_JOBS_ENABLED"] = True
    with app.app_context():
        a = Appliance(name="fw-job", kind="fortiweb", host="fw-job.test",
                      port=443, username="admin", verify_ssl=False)
        a.password = "x"
        db.session.add(a)
        db.session.commit()
        app.config["_TEST_AID"] = a.id
    return app


def _wait_terminal(jid, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        st = jobs.get_job(jid) or {}
        if st.get("status") in ("success", "error", "cancelled"):
            return st
        time.sleep(0.05)
    raise AssertionError(f"job {jid} did not finish: {jobs.get_job(jid)}")


# ── coverage ────────────────────────────────────────────────────────────────
def test_every_post_of_a_device_blueprint_is_wrapped_or_excluded(app):
    wrapped = device_jobs.wrapped_endpoints(app)
    missing = []
    for rule in app.url_map.iter_rules():
        ep = rule.endpoint
        if "POST" not in rule.methods or "." not in ep:
            continue
        if ep.split(".", 1)[0] not in device_jobs.DEVICE_BLUEPRINTS:
            continue
        if ep not in wrapped and ep not in device_jobs.EXCLUDED:
            missing.append(ep)
    assert not missing, f"device POST routes neither wrapped nor excluded: {missing}"
    assert len(wrapped) > 150


def test_excluded_entries_name_real_post_endpoints(app):
    posts = {r.endpoint for r in app.url_map.iter_rules() if "POST" in r.methods}
    stale = sorted(set(device_jobs.EXCLUDED) - posts)
    assert not stale, f"EXCLUDED names endpoints that no longer exist: {stale}"


def test_views_that_start_their_own_job_are_excluded(app):
    """Wrapping a view that already spawns a job would put a job around a job."""
    spawn = re.compile(r"\b(run_async|create_job|_spawn_flash_job)\(")
    offenders = []
    for ep in device_jobs.wrapped_endpoints(app):
        fn = app.view_functions[ep]
        src = inspect.getsource(inspect.unwrap(fn))
        if spawn.search(src):
            offenders.append(ep)
    assert not offenders, f"wrapped views that start their own job: {offenders}"


def test_wrapper_is_off_under_testing_unless_asked(app):
    with app.app_context():
        assert device_jobs.enabled(app) is False
        app.config["DEVICE_JOBS_ENABLED"] = True
        assert device_jobs.enabled(app) is True


@pytest.mark.parametrize("ep,read", [
    ("appliances.test_connection", True),
    ("workspace.preview", True),
    ("exceptions.ip_list_add", False),
    ("appliances.failover_preflight", False),
    ("appliances.restore_run", False),
    ("objedit.save", False),
    ("appliances.console_run", False),
])
def test_write_words_win_the_read_write_split(ep, read):
    assert device_jobs.is_read(ep) is read


# ── fidelity ────────────────────────────────────────────────────────────────
def test_fast_action_returns_its_real_response_and_logs_the_device_call(jobs_app, monkeypatch):
    calls = []
    _fake_httpx(monkeypatch, calls=calls)
    client = jobs_app.test_client()
    login(client, admin_user_id(jobs_app))
    aid = jobs_app.config["_TEST_AID"]
    r = client.post(f"/appliances/{aid}/test", headers={"X-Requested-With": "XMLHttpRequest"})
    assert r.status_code == 200
    assert r.get_json()["ok"] is True
    assert calls, "the action never reached the (fake) device"
    lst = jobs.list_jobs(appliance_id=aid)
    assert len(lst) == 1, "a device action must leave exactly one job"
    j = lst[0]
    assert j["type"] == "device_action" and j["status"] == "success"
    assert j["meta"]["steps"][0]["label"].startswith("GET /api/v2.0/system/status")
    assert j["meta"]["appliance"] == "fw-job"


def test_csrf_is_checked_again_in_the_job_and_passes(jobs_app, monkeypatch):
    """The replayed request runs preprocess_request again, CSRF included: a
    valid token must survive the replay, a missing one must still be refused."""
    _fake_httpx(monkeypatch)
    jobs_app.config["WTF_CSRF_ENABLED"] = True
    client = jobs_app.test_client()
    login(client, admin_user_id(jobs_app))
    aid = jobs_app.config["_TEST_AID"]
    page = client.get(f"/appliances/{aid}")
    m = re.search(rb'name="csrf-token" content="([^"]+)"', page.data)
    assert m, "no csrf meta on the appliance page"
    ok = client.post(f"/appliances/{aid}/test",
                     headers={"X-Requested-With": "XMLHttpRequest",
                              "X-CSRFToken": m.group(1).decode()})
    assert ok.status_code == 200 and ok.get_json()["ok"] is True
    bad = client.post(f"/appliances/{aid}/test",
                      headers={"X-Requested-With": "XMLHttpRequest"})
    assert bad.status_code in (400, 302, 403)


def test_action_that_never_reaches_the_device_leaves_no_job(jobs_app, monkeypatch):
    _fake_httpx(monkeypatch)
    client = jobs_app.test_client()
    login(client, admin_user_id(jobs_app))
    aid = jobs_app.config["_TEST_AID"]
    r = client.post(f"/appliances/{aid}/console/run", json={"command": "config system global"})
    assert r.status_code == 400
    assert jobs.list_jobs(limit=50) == []


def test_slow_fetch_action_answers_202_and_replays_the_response(jobs_app, monkeypatch):
    _fake_httpx(monkeypatch, delay=0.5)
    monkeypatch.setattr(device_jobs, "INLINE_S", 0.1)
    client = jobs_app.test_client()
    login(client, admin_user_id(jobs_app))
    aid = jobs_app.config["_TEST_AID"]
    r = client.post(f"/appliances/{aid}/test",
                    headers={"X-Requested-With": "XMLHttpRequest", "Sec-Fetch-Mode": "cors"})
    assert r.status_code == 202
    jid = r.headers["X-SATOM-Job"]
    assert r.get_json()["job_id"] == jid
    st = _wait_terminal(jid)
    assert st["status"] == "success"
    assert st["result"]["kind"] == "json"
    rr = client.get(f"/jobs/{jid}/response")
    assert rr.status_code == 200 and rr.get_json()["ok"] is True


def test_slow_form_post_goes_to_the_wait_page(jobs_app, monkeypatch):
    _fake_httpx(monkeypatch, delay=0.5)
    monkeypatch.setattr(device_jobs, "INLINE_S", 0.1)
    client = jobs_app.test_client()
    login(client, admin_user_id(jobs_app))
    aid = jobs_app.config["_TEST_AID"]
    r = client.post(f"/appliances/{aid}/test",
                    headers={"Sec-Fetch-Mode": "navigate",
                             "Referer": f"http://localhost/appliances/{aid}"})
    assert r.status_code == 303
    loc = r.headers["Location"]
    assert re.match(r"^/jobs/[\w-]+/wait\?back=%2Fappliances%2F\d+$", loc), loc
    jid = loc.split("/")[2]
    page = client.get(loc)
    assert page.status_code == 200
    assert b"Test connection" in page.data and b'id="jw-steps"' in page.data
    _wait_terminal(jid)


def test_offsite_referer_gives_no_back_link(jobs_app, monkeypatch):
    _fake_httpx(monkeypatch, delay=0.4)
    monkeypatch.setattr(device_jobs, "INLINE_S", 0.05)
    client = jobs_app.test_client()
    login(client, admin_user_id(jobs_app))
    aid = jobs_app.config["_TEST_AID"]
    r = client.post(f"/appliances/{aid}/test",
                    headers={"Sec-Fetch-Mode": "navigate", "Referer": "https://evil.example/x"})
    assert r.status_code == 303 and "back=" not in r.headers["Location"]
    _wait_terminal(r.headers["Location"].split("/")[2])


def test_replay_runs_the_before_request_hooks(app, monkeypatch):
    """The job re-runs preprocess_request: state the gates put on ``g`` (the
    device context, the CSP nonce, the ADOM) exists for the view in the job."""
    from flask import g, request as rq

    @app.before_request
    def _mark():
        g.replay_marker = "gate-ran"

    seen = {}

    def view():
        seen["marker"] = getattr(g, "replay_marker", None)
        seen["body"] = rq.form.get("k")
        return "ok"

    jid = jobs.create_job("device_action", "replay", by="t")["id"]
    with app.test_request_context("/x", method="POST", data={"k": "v"}):
        env = device_jobs._environ_copy()
    device_jobs._worker(app, jid, view, env, False)
    assert seen == {"marker": "gate-ran", "body": "v"}
    assert jobs.get_job(jid)["status"] == "success"


def test_the_response_is_for_its_owner_only(jobs_app, monkeypatch):
    _fake_httpx(monkeypatch)
    jid = jobs.create_job("device_action", "x", by="somebody-else")["id"]
    jobs.finish_success(jid)
    device_jobs._store(jid, device_jobs._json_cap({"ok": True, "secret": "cfg"}, 200))
    client = jobs_app.test_client()
    login(client, admin_user_id(jobs_app))
    r = client.get(f"/jobs/{jid}/response")
    assert r.status_code == 404 and b"cfg" not in r.data, \
        "another user's device response was replayed"
    mine = jobs.create_job("device_action", "y", by="admin")["id"]
    jobs.finish_success(mine)
    device_jobs._store(mine, device_jobs._json_cap({"ok": True}, 200))
    assert client.get(f"/jobs/{mine}/response").status_code == 200


def test_wait_page_back_link_stays_on_site(jobs_app):
    jid = jobs.create_job("device_action", "x", by="admin")["id"]
    client = jobs_app.test_client()
    login(client, admin_user_id(jobs_app))
    page = client.get(f"/jobs/{jid}/wait?back=//evil.example/x")
    assert b"evil.example" not in page.data


def test_flashes_from_the_job_reach_the_next_page(app):
    cap = {"status": 302, "headers": {"Location": "/x"}, "body": "",
           "session": {"set": {"_flashes": [["success", "Saved on the device"]]}, "del": []}}
    ok, msg, kind = device_jobs.outcome(cap)
    assert (ok, msg, kind) == (True, "Saved on the device", "redirect")
    with app.test_request_context("/"):
        from flask import session
        session["_flashes"] = [("info", "earlier")]
        device_jobs.apply_session(cap["session"])
        assert session["_flashes"] == [("info", "earlier"), ("success", "Saved on the device")]


@pytest.mark.parametrize("body,status,ok", [
    ({"ok": False, "status": "connect timeout"}, 200, False),
    ({"error": "refused"}, 200, False),
    ({"started": False, "reason": "busy"}, 200, False),
    ({"ok": True, "message": "fine"}, 200, True),
    ({"detail": "x"}, 500, False),
])
def test_json_outcome(body, status, ok):
    import base64
    cap = {"status": status, "headers": {"Content-Type": "application/json"},
           "body": base64.b64encode(json.dumps(body).encode()).decode()}
    got_ok, msg, _ = device_jobs.outcome(cap)
    assert got_ok is ok
    if not ok:
        assert msg and msg != "HTTP 200"


def test_danger_flash_marks_the_job_failed():
    cap = {"status": 302, "headers": {"Location": "/x"}, "body": "",
           "session": {"set": {"_flashes": [["danger", "Device refused"]]}}}
    assert device_jobs.outcome(cap)[:2] == (False, "Device refused")


# ── queue + stop ────────────────────────────────────────────────────────────
def _job(title):
    j = jobs.create_job("device_action", title, by="t")
    jobs.update_job(j["id"], status=jobs.RUNNING)
    return j["id"]


def test_second_write_to_a_device_queues_until_the_first_ends():
    j1, j2 = _job("first write"), _job("second write")
    s1 = job_progress.JobSink(j1, exclusive=True)
    s1.before_call("https://fw-q.test:443")
    assert jobs.get_job(j1)["cancelable"] is False, \
        "a job writing to the device must not offer a Stop"
    s2 = job_progress.JobSink(j2, exclusive=True)
    done = threading.Event()
    threading.Thread(target=lambda: (s2.before_call("https://fw-q.test:443"), done.set()),
                     daemon=True).start()
    end = time.time() + 3
    while time.time() < end and not jobs.get_job(j2)["meta"].get("queued"):
        time.sleep(0.02)
    st2 = jobs.get_job(j2)
    assert st2["meta"]["queued"] is True
    assert "first write" in st2["message"]
    assert not done.is_set()
    s1.release()
    assert done.wait(3), "the queued write never started after the first ended"
    assert jobs.get_job(j2)["meta"]["queued"] is False
    s2.release()


def test_a_queued_write_can_be_stopped():
    j1, j2 = _job("holder"), _job("waiter")
    s1 = job_progress.JobSink(j1, exclusive=True)
    s1.before_call("https://fw-c.test:443")
    errs = []
    s2 = job_progress.JobSink(j2, exclusive=True)

    def run():
        try:
            s2.before_call("https://fw-c.test:443")
        except jobs.JobCancelled as exc:
            errs.append(exc)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    time.sleep(0.2)
    jobs.request_cancel(j2)
    t.join(3)
    assert errs, "Stop on a queued write did not end it"
    s1.release()


def test_reads_never_queue_behind_a_write():
    j1, j2 = _job("writer"), _job("reader")
    s1 = job_progress.JobSink(j1, exclusive=True)
    s1.before_call("https://fw-r.test:443")
    s2 = job_progress.JobSink(j2, exclusive=False)
    t0 = time.time()
    s2.before_call("https://fw-r.test:443")
    assert time.time() - t0 < 0.5
    assert jobs.get_job(j2)["cancelable"] is True
    s1.release()


def test_steps_are_recorded_without_query_strings():
    j = _job("steps")
    s = job_progress.JobSink(j, exclusive=False)
    s.before_call("https://fw-s.test:443")
    s.after_call("GET", "/api/v2.0/cmdb/x?token=secret", 200, time.monotonic())
    st = jobs.get_job(j)
    assert st["meta"]["steps"][-1]["label"] == "GET /api/v2.0/cmdb/x"
    assert "secret" not in json.dumps(st)
    assert 0 < st["percent"] < 100


# ── pass-through ────────────────────────────────────────────────────────────
def test_standby_keeps_the_synchronous_path(jobs_app, monkeypatch):
    _fake_httpx(monkeypatch)
    monkeypatch.setattr(device_jobs, "_is_standby", lambda: True)
    client = jobs_app.test_client()
    login(client, admin_user_id(jobs_app))
    r = client.post(f"/appliances/{jobs_app.config['_TEST_AID']}/test")
    assert r.status_code == 200
    assert jobs.list_jobs(limit=50) == []


def test_api_token_callers_keep_the_synchronous_path(jobs_app, monkeypatch):
    _fake_httpx(monkeypatch)
    client = jobs_app.test_client()
    login(client, admin_user_id(jobs_app))
    r = client.post(f"/appliances/{jobs_app.config['_TEST_AID']}/test",
                    headers={"Authorization": "Bearer fmk_x_y"})
    assert r.status_code == 200
    assert jobs.list_jobs(limit=50) == []


# ── rediscovery mirrored into a job ─────────────────────────────────────────
def test_rediscovery_progress_and_stop_go_through_its_job(app):
    aid = 77
    jid = _job("Discovery · fw")
    rediscovery._write_json(rediscovery._dev_dir(aid) / "progress.json",
                            {"state": "running", "job_id": jid, "total": 10, "done": 4,
                             "percent": 40, "objects": 12, "section": "System"})
    st = jobs.get_job(jid)
    assert st["percent"] == 40 and "4/10 endpoints" in st["message"]
    assert rediscovery._stop_requested(aid) is False
    jobs.request_cancel(jid)
    assert rediscovery._stop_requested(aid) is True, \
        "Stop pressed on the job did not reach the sweep"
    rediscovery._write_json(rediscovery._dev_dir(aid) / "progress.json",
                            {"state": "done", "job_id": jid, "summary": "12 object(s)"})
    rediscovery._finish_job(aid, jid)
    assert jobs.get_job(jid)["status"] == "success"


def test_jobs_filter_by_appliance(app):
    a = jobs.create_job("device_action", "a", meta={"appliance_id": 5})
    jobs.create_job("device_action", "b", meta={"appliance_id": 6})
    assert [j["id"] for j in jobs.list_jobs(appliance_id=5)] == [a["id"]]


# ── stylesheet: the button classes the templates use exist ─────────────────
def test_button_classes_used_by_templates_are_defined():
    css = (ROOT / "app/static/css/fortiweb.css").read_text(encoding="utf-8")
    used = set()
    for p in (ROOT / "app/templates").rglob("*.html"):
        used |= set(re.findall(r"\b((?:fw-btn|btn-fw)-[a-z]+)\b", p.read_text(encoding="utf-8")))
    # A base rule, not just a :hover/:focus variant: the selector must be
    # followed by "," or "{".
    undefined = sorted(c for c in used
                       if not re.search(r"\." + re.escape(c) + r"\s*[,{]", css))
    assert not undefined, f"button classes used but defined in no stylesheet: {undefined}"
