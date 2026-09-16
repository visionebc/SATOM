"""Guards for the 2026-09-15 async round: **nothing on the discovery card is a
synchronous request any more, and no "running" state can outlive its worker.**

Four defects, and they are four different shapes of the same lie — a screen
that reports a state nobody is in:

1. **The run was synchronous.** ``POST /discovery/run`` fired up to 960 GETs
   inside the HTTP request. nginx cuts a proxied request at 120 s and gunicorn
   at 600 s, so a run against a slow or degraded appliance — the case whose
   answer matters most — returned a **504** to the browser while the worker
   kept spending the budget for minutes more. The findings those GETs bought
   existed only in a response body nobody received, so the operator could not
   register a single one, and the audit row said the run went fine.
2. **The load job had no reader.** ``rediscovery.start`` has always been a
   background thread with a ``progress.json`` and a status endpoint — the
   Rediscover page polls it. This card started the same worker and showed a
   flash message, so "is it still running?" was answered by guessing.
3. **A ``running`` file outlived its process.** The sweep's state is a file and
   its worker is a daemon thread, so ``systemctl restart satom`` turned every
   live sweep into a permanent ``running``. Appliance 4 read **71 %** from
   2026-07-03 to 2026-09-15.
4. **The suite wrote into production.** ``tests/test_rediscovery_*`` drove real
   sweeps against the TEST database into the PRODUCTION ``data/`` tree, and
   ``api_matrix`` rebuilds itself from that tree: the live
   ``data/api_matrix/fortiweb.json`` was reduced to ``swept: 0, devices: []``.
   Untracked, so git said nothing, and an empty matrix renders as a page with
   **no differences** rather than as an error.

Trap notes, all of them paid for in this repo: source assertions run over
docstring- AND comment-stripped code (this prose quotes the identifiers it
forbids — the tenth such near-miss was on 2026-09-15); assertions about a key
are scoped to the dict LITERAL, never to "somewhere in this function"; and the
card renders a LEGEND of its own badges, so a substring assertion about a badge
can be satisfied with the badge removed from every real branch.
"""
from __future__ import annotations

import ast
import io
import json
import os
import re
import time
from datetime import datetime, timedelta

import pytest

from conftest import admin_user_id, login

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VIEW = os.path.join(REPO, "app", "views", "_discovery.py")
JOBSVC = os.path.join(REPO, "app", "services", "discovery_jobs.py")
REDISC = os.path.join(REPO, "app", "services", "rediscovery.py")
TPL = os.path.join(REPO, "app", "templates", "partials", "_discovery_run.html")
RTPL = os.path.join(REPO, "app", "templates", "appliances", "rediscover.html")


def _read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def _func(path, name):
    tree = ast.parse(_read(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            if ast.get_docstring(node):
                node.body = node.body[1:]
            return node
    raise AssertionError("%s not found in %s" % (name, path))


def _body(path, name):
    """Source of one function: docstring AND comments gone.

    ``ast.unparse`` KEEPS the docstring — that is how an assertion about
    ``adc_menu`` survived the call being deleted on 2026-09-15 — so it is
    stripped from the node before unparsing, and comment lines after.
    """
    out = ast.unparse(_func(path, name))
    return "\n".join(ln for ln in out.splitlines()
                     if not ln.strip().startswith("#"))


def _tpl(path=TPL):
    return re.sub(r"\{#.*?#\}", "", _read(path), flags=re.S)


# --------------------------------------------------------------------------- #
#  fixtures                                                                    #
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def _no_stray_jobs():
    """Purge active jobs around every test in this module.

    The job ledger is ONE directory for the whole session while each test gets
    a fresh database, so appliance ids repeat — and a job another test left
    active for id 1 makes the next test "reconnect" to it instead of starting
    its own. That collision is an artefact of the suite (production ids do not
    repeat), so it is isolated here rather than weakened in the code: the
    reconnect rule itself is what stops one appliance being asked twice.
    """
    from app.services import jobs

    def _purge():
        for st in jobs.list_jobs(limit=200, active_only=True):
            jobs.finish_cancelled(st["id"], message="test teardown")

    _purge()
    yield
    _purge()


@pytest.fixture()
def box(app):
    from app.models import Appliance, db

    with app.app_context():
        a = Appliance(name="fw-async", host="192.0.2.231", port=443,
                      kind="fortiweb", username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        return a.id


def _finding(dr, path="log alertmail", name="log.alertmail",
             urns=("log/alertmail",)):
    return dr.Finding(path=path, name=name, configured=True, instances=2,
                      candidates=[dr.Candidate(urn=u) for u in urns])


def _probe_ok(firmware="FortiWeb-KVM 7.6.8,build1128(GA.M),260602"):
    def _p(appliance):
        return {"ok": True, "firmware": firmware, "changed": False,
                "previous": "", "checked_at": "2026-09-15T18:00:00"}
    return _p


def _inline_dispatch(monkeypatch):
    """Run the job worker in THIS thread so a guard can assert on its result.

    Mirrors ``jobs.run_async``'s finalisation rules exactly; a simplified stand-in
    would let the real one drift away from what is tested here.
    """
    from app.services import jobs

    def _run_async(flask_app, job_id, worker):
        jobs.update_job(job_id, status=jobs.RUNNING, pid=os.getpid())
        try:
            result = worker(flask_app, job_id)
            st = jobs.get_job(job_id) or {}
            if st.get("status") in jobs._ACTIVE:
                jobs.finish_success(job_id, result=result)
        except jobs.JobCancelled:
            st = jobs.get_job(job_id) or {}
            if st.get("status") in jobs._ACTIVE:
                jobs.finish_cancelled(job_id)
        except Exception as exc:  # noqa: BLE001
            st = jobs.get_job(job_id) or {}
            if st.get("status") in jobs._ACTIVE:
                jobs.finish_error(job_id, "%s: %s" % (type(exc).__name__, exc))

    monkeypatch.setattr(jobs, "run_async", _run_async)


def _plan_returns(monkeypatch, rows, chosen=None):
    """Pin what the REQUEST plans, so these guards test the dispatch and the
    worker rather than re-testing the planner (tests/test_discovery_run.py)."""
    from app.views import _discovery as view

    rep = {"chosen": chosen if chosen is not None else
           {"appliance": "fortiweb16", "appliance_id": 999, "line": "7.6",
            "created_at": "2026-09-14 22:46"},
           "diff": {}}
    monkeypatch.setattr(view, "_findings_for",
                        lambda *a, **k: (rep, list(rows), {}, {}))


# =========================================================================== #
#  1. the route DISPATCHES — it does not ask the device                        #
# =========================================================================== #
def test_the_run_route_does_no_device_io_at_all():
    """The whole point. If this function can probe, it can also hang past
    nginx's 120 s and hand the browser a 504 with the budget already spent."""
    code = _body(VIEW, "run_payload")
    assert "probe_endpoint" not in code
    assert "discovery_run.run(" not in code
    assert "version_check" not in code


def test_the_run_route_hands_back_a_job_id(app, client, monkeypatch, box):
    from app.services import discovery_run as dr

    _inline_dispatch(monkeypatch)
    _plan_returns(monkeypatch, [_finding(dr)])
    monkeypatch.setattr("app.services.firmware_probe.refresh", _probe_ok())
    monkeypatch.setattr("app.services.rediscovery.probe_endpoint",
                        lambda a, urn: ([{"x": 1}], dr.SERVED, ""))
    login(client, admin_user_id(app))
    r = client.post("/web/api-explorer/discovery/run",
                    data={"appliance_id": box, "budget": 5})
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True and body["started"] is True
    assert body["job_id"]


def test_the_findings_are_PERSISTED_on_the_job(app, client, monkeypatch, box):
    """Register reads from this table. A result that lived only in the browser
    meant closing the tab threw away GETs fired at a production appliance."""
    from app.services import discovery_run as dr
    from app.services import jobs

    _inline_dispatch(monkeypatch)
    _plan_returns(monkeypatch, [_finding(dr)])
    monkeypatch.setattr("app.services.firmware_probe.refresh", _probe_ok())
    monkeypatch.setattr("app.services.rediscovery.probe_endpoint",
                        lambda a, urn: ([{"x": 1}], dr.SERVED, ""))
    login(client, admin_user_id(app))
    jid = client.post("/web/api-explorer/discovery/run",
                      data={"appliance_id": box, "budget": 5}).get_json()["job_id"]
    st = jobs.get_job(jid)
    assert st["status"] == "success"
    res = st["result"]
    assert res["findings"], "the findings must survive the request"
    assert res["findings"][0]["served_urn"] == "log/alertmail"
    assert res["findings"][0]["registerable"] is True
    assert res["device"] == "fw-async"


def test_the_stored_result_carries_the_provenance(app, client, monkeypatch, box):
    from app.services import discovery_run as dr
    from app.services import jobs

    _inline_dispatch(monkeypatch)
    _plan_returns(monkeypatch, [_finding(dr)])
    monkeypatch.setattr("app.services.firmware_probe.refresh", _probe_ok())
    monkeypatch.setattr("app.services.rediscovery.probe_endpoint",
                        lambda a, urn: ([], dr.ABSENT, "-20001"))
    login(client, admin_user_id(app))
    jid = client.post("/web/api-explorer/discovery/run",
                      data={"appliance_id": box, "budget": 5}).get_json()["job_id"]
    res = jobs.get_job(jid)["result"]
    for key in ("evidence", "evidence_line", "evidence_captured",
                "same_device", "version"):
        assert key in res, key
    assert res["version"]["line"] == "7.6"
    # The dump came off appliance 999, the questions went to this box.
    assert res["same_device"] is False


def test_a_second_run_reconnects_instead_of_doubling_the_budget(
        app, client, monkeypatch, box):
    """Two concurrent runs is twice the budget for one answer, and both then
    compete for the same device's session limit."""
    from app.services import discovery_run as dr
    from app.services import jobs

    _plan_returns(monkeypatch, [_finding(dr)])
    monkeypatch.setattr(jobs, "run_async", lambda *a, **k: None)  # leave it active
    login(client, admin_user_id(app))
    first = client.post("/web/api-explorer/discovery/run",
                        data={"appliance_id": box, "budget": 5}).get_json()
    second = client.post("/web/api-explorer/discovery/run",
                         data={"appliance_id": box, "budget": 5}).get_json()
    assert second["started"] is False
    assert second["reconnected"] is True
    assert second["job_id"] == first["job_id"]


def test_nothing_to_ask_is_not_a_job_and_reads_no_version(
        app, client, monkeypatch, box):
    """A complete answer that costs the device nothing. ``same_device`` is
    None, never False: 'no comparison was made' is not 'it disagreed'."""
    from app.services import firmware_probe

    _plan_returns(monkeypatch, [])
    called = []
    monkeypatch.setattr(firmware_probe, "refresh",
                        lambda a: called.append(1) or _probe_ok()(a))
    login(client, admin_user_id(app))
    body = client.post("/web/api-explorer/discovery/run",
                       data={"appliance_id": box}).get_json()
    assert body["job_id"] == ""
    assert body["started"] is False
    assert body["same_device"] is None
    assert body["version"] == {}
    assert called == [], "the empty path must not touch the device"


# =========================================================================== #
#  2. the worker: progress, cancellation, and the rules that moved with it     #
# =========================================================================== #
def test_progress_is_reported_BEFORE_the_block_is_asked():
    """A run that dies mid-GET must leave the last message naming the block it
    was ASKING about, not the one it had already finished."""
    from app.services import discovery_run as dr

    seen = []
    rows = [_finding(dr, path="a", name="a", urns=("a",)),
            _finding(dr, path="b", name="b", urns=("b",))]

    def _probe(urn):
        seen.append(("probe", urn))
        return ([], dr.ABSENT, "")

    dr.run(rows, _probe, budget=9,
           on_progress=lambda i, t, s, p: seen.append(("progress", p)))
    assert seen[0] == ("progress", "a")
    assert seen[1] == ("probe", "a")
    assert seen[2] == ("progress", "b")


def test_stopping_leaves_the_unasked_blocks_not_probed(
        app, client, monkeypatch, box):
    """Stop is cooperative: the blocks after it stayed UNASKED, and that is
    ``not_probed`` — never ``absent``, which would be the device denying them."""
    from app.services import discovery_run as dr
    from app.services import jobs

    _inline_dispatch(monkeypatch)
    rows = [_finding(dr, path="a", name="a", urns=("a",)),
            _finding(dr, path="b", name="b", urns=("b",)),
            _finding(dr, path="c", name="c", urns=("c",))]
    _plan_returns(monkeypatch, rows)
    monkeypatch.setattr("app.services.firmware_probe.refresh", _probe_ok())
    monkeypatch.setattr("app.services.rediscovery.probe_endpoint",
                        lambda a, urn: ([], dr.ABSENT, "-20001"))

    real_checkpoint = jobs.checkpoint
    calls = {"n": 0}

    def _checkpoint(job_id):
        calls["n"] += 1
        if calls["n"] > 2:
            raise jobs.JobCancelled()
        return real_checkpoint(job_id)

    monkeypatch.setattr(jobs, "checkpoint", _checkpoint)
    login(client, admin_user_id(app))
    jid = client.post("/web/api-explorer/discovery/run",
                      data={"appliance_id": box, "budget": 50}).get_json()["job_id"]
    st = jobs.get_job(jid)
    assert st["status"] == "cancelled"
    res = st["result"]
    assert res["stopped"] is True
    statuses = [f["status"] for f in res["findings"]]
    assert statuses.count(dr.NOT_PROBED) >= 1
    assert res["not_probed"] >= 1


def test_a_stopped_run_still_hands_back_what_it_learned(
        app, client, monkeypatch, box):
    """The GETs were spent against a production box. Throwing the answers away
    would make Stop more expensive than letting the run finish."""
    from app.services import discovery_run as dr
    from app.services import jobs

    _inline_dispatch(monkeypatch)
    rows = [_finding(dr, path="a", name="a", urns=("a",)),
            _finding(dr, path="b", name="b", urns=("b",))]
    _plan_returns(monkeypatch, rows)
    monkeypatch.setattr("app.services.firmware_probe.refresh", _probe_ok())
    monkeypatch.setattr("app.services.rediscovery.probe_endpoint",
                        lambda a, urn: ([{"r": 1}], dr.SERVED, ""))
    calls = {"n": 0}

    def _checkpoint(job_id):
        calls["n"] += 1
        if calls["n"] > 1:
            raise jobs.JobCancelled()

    monkeypatch.setattr(jobs, "checkpoint", _checkpoint)
    login(client, admin_user_id(app))
    jid = client.post("/web/api-explorer/discovery/run",
                      data={"appliance_id": box, "budget": 50}).get_json()["job_id"]
    res = jobs.get_job(jid)["result"]
    assert res["served"] == 1, "the block it DID ask about is kept"
    assert res["spent"] == 1


def test_the_worker_never_gates_on_the_version_verdict():
    """Moved here with the code it protects. A refusal built on this vocabulary
    would reject a legitimate run because OUR read failed: ``unknown`` is a
    statement about us, not about the box."""
    node = _func(JOBSVC, "_execute")
    tests = [ast.unparse(n.test) for n in ast.walk(node) if isinstance(n, ast.If)]
    for t in tests:
        assert "verdict" not in t, t
        assert "version" not in t, t


def test_the_provenance_literal_still_names_both_halves():
    """Scoped to the dict LITERAL: the audit rows below spell ``evidence_line``
    too, so a whole-function assertion stayed green with the key dropped."""
    code = _body(JOBSVC, "_execute")
    prov = code[code.index("provenance = {"):]
    prov = prov[:prov.index("}") + 1]
    for key in ("'evidence'", "'evidence_line'", "'same_device'", "'version'"):
        assert key in prov, key


def test_every_audit_row_in_the_worker_carries_the_actor():
    """``log_action`` reads ``current_user``; in a worker thread there is none,
    so every async run would otherwise be attributed to "system".

    Asserted over EVERY ``log_action`` call in the function, by AST. The first
    version sliced from the first ``log_action`` to the end of the function and
    asked whether the key appeared *somewhere* — and there are two calls (the
    stopped path and the finished path), so dropping ``by`` from the finished
    one left the guard green. Eleventh time this repo has been bitten by an
    assertion satisfied by the wrong occurrence.
    """
    node = _func(JOBSVC, "_execute")
    calls = [n for n in ast.walk(node) if isinstance(n, ast.Call)
             and getattr(n.func, "id", "") == "log_action"]
    assert len(calls) == 2, "the stopped path and the finished path both log"
    for call in calls:
        extra = [kw.value for kw in call.keywords if kw.arg == "extra"]
        assert extra, ast.unparse(call)[:160]
        keys = [k.value for k in extra[0].keys if isinstance(k, ast.Constant)]
        for key in ("by", "firmware", "version_verdict", "evidence"):
            assert key in keys, "%s missing from %s" % (key, ast.unparse(call)[:160])


def test_the_dispatch_is_audited_in_the_request_with_the_real_operator():
    code = _body(VIEW, "run_payload")
    assert "log_action('discovery_run.start'" in code


def test_a_deleted_appliance_is_an_error_not_an_empty_result():
    """'no findings' and 'there was nothing to ask' read the same on screen and
    mean opposite things."""
    code = _body(JOBSVC, "_execute")
    assert "raise RuntimeError" in code


# =========================================================================== #
#  3. no "running" outlives its worker                                         #
# =========================================================================== #
def _write_progress(tmp_path, appliance_id, **fields):
    from app.services import rediscovery

    d = rediscovery._dev_dir(appliance_id)
    state = {"state": "running", "appliance_id": appliance_id,
             "appliance": "fw%s" % appliance_id, "percent": 71,
             "started": datetime.utcnow().isoformat(),
             "heartbeat": datetime.utcnow().isoformat(),
             "host": rediscovery._HOST, "pid": os.getpid()}
    state.update(fields)
    (d / "progress.json").write_text(json.dumps(state), encoding="utf-8")
    return d / "progress.json"


def test_a_dead_pid_is_reconciled_to_interrupted(app):
    from app.services import rediscovery

    p = _write_progress(None, 8101, pid=999999)
    out = rediscovery.reconcile_stale_runs()
    assert any(s["appliance_id"] == 8101 for s in out)
    assert json.loads(p.read_text())["state"] == rediscovery.INTERRUPTED


def test_a_LIVE_pid_is_never_touched(app):
    """Any booting gunicorn worker runs this while another worker may be
    mid-sweep. Judging a live pid would kill a running sweep's status."""
    from app.services import rediscovery

    p = _write_progress(None, 8102, pid=os.getpid())
    rediscovery.reconcile_stale_runs()
    assert json.loads(p.read_text())["state"] == "running"


def test_a_file_from_another_host_is_never_judged(app):
    """satom-ha-datasync pulls this whole tree onto the standby every 5 minutes,
    so a2 sees a1's progress files — and a1's pids mean nothing on a2."""
    from app.services import rediscovery

    p = _write_progress(None, 8103, pid=999999, host="satom-node-1-elsewhere")
    rediscovery.reconcile_stale_runs()
    assert json.loads(p.read_text())["state"] == "running"


def test_a_pidless_file_is_judged_by_age_not_assumed_dead(app):
    """Files written before ``pid`` existed. Recent ones are left alone; the
    2026-07-03 ghost is not."""
    from app.services import rediscovery

    old = (datetime.utcnow() - timedelta(days=74)).isoformat()
    fresh = _write_progress(None, 8104, started=datetime.utcnow().isoformat(),
                            heartbeat=datetime.utcnow().isoformat())
    stale = _write_progress(None, 8105, started=old, heartbeat=old)
    for p in (fresh, stale):
        st = json.loads(p.read_text())
        st.pop("pid")
        p.write_text(json.dumps(st), encoding="utf-8")
    rediscovery.reconcile_stale_runs()
    assert json.loads(fresh.read_text())["state"] == "running"
    assert json.loads(stale.read_text())["state"] == rediscovery.INTERRUPTED


def test_interrupted_is_its_own_word(app):
    from app.services import rediscovery

    assert rediscovery.INTERRUPTED not in ("done", "running", rediscovery.FAILED)
    assert rediscovery.FAILED != "done"


def test_the_reconciler_carries_a_reason_the_operator_can_act_on(app):
    from app.services import rediscovery

    p = _write_progress(None, 8106, pid=999999)
    rediscovery.reconcile_stale_runs()
    st = json.loads(p.read_text())
    assert st["error"]
    assert st["finished"]


def test_an_unreadable_progress_file_never_breaks_the_sweep(app):
    """Housekeeping must not be able to block boot."""
    from app.services import rediscovery

    d = rediscovery._dev_dir(8107)
    (d / "progress.json").write_text("{not json", encoding="utf-8")
    rediscovery.reconcile_stale_runs()   # must not raise


def test_a_crashing_sweep_writes_failed_and_reraises(app, monkeypatch):
    """Without this, an exception in the sweep left ``running`` on disk
    forever, indistinguishable from a sweep still in flight."""
    from types import SimpleNamespace

    from app.services import rediscovery

    snap = SimpleNamespace(id=8108, name="fw-boom", kind="fortiweb")

    def _boom(*a, **k):
        raise RuntimeError("the sweep exploded")

    monkeypatch.setattr(rediscovery, "_sweep", _boom)
    _write_progress(None, 8108)
    with pytest.raises(RuntimeError):
        rediscovery._run(snap, "tester")
    st = rediscovery.status(8108)
    assert st["state"] == rediscovery.FAILED
    assert "the sweep exploded" in st["error"]


def test_the_boot_reconcile_is_wired_into_the_app_factory():
    code = _read(os.path.join(REPO, "app", "__init__.py"))
    assert "reconcile_stale_runs()" in code


def test_the_sweep_records_who_is_running_it(app, monkeypatch):
    """pid + host are what let a reconciler tell a live sweep from a ghost."""
    code = _read(REDISC)
    start = code[code.index("def start(appliance"):]
    init = start[start.index("init = {"):start.index("threading.Thread")]
    assert "os.getpid()" in init
    assert "_HOST" in init


# =========================================================================== #
#  4. the suite cannot write into the production data tree                     #
# =========================================================================== #
def test_the_rediscovery_dir_is_redirected_away_from_the_repo():
    """The measured damage: a test sweep rebuilt the PRODUCTION api_matrix from
    the test tree and left ``swept: 0``."""
    from app.services import rediscovery

    here = str(rediscovery._data_dir())
    assert not here.startswith(os.path.join(REPO, "data")), here


def test_the_matrix_root_is_redirected_away_from_the_repo():
    from app.services import api_matrix

    assert not api_matrix.MATRIX_ROOT.startswith(os.path.join(REPO, "data"))
    assert api_matrix.MATRIX_ROOT_DEFAULT.startswith(os.path.join(REPO, "data"))


def test_both_overrides_are_actually_honoured(monkeypatch, tmp_path):
    """Set the env and the code follows it — not merely 'conftest sets a var'.

    🚨 The restore is the delicate half, and the first version of this test got
    it wrong in exactly the way the module is about: it did ``delenv`` and THEN
    reloaded, so ``MATRIX_ROOT`` fell back to the in-tree default and STAYED
    there for the rest of the session — monkeypatch's own teardown runs after
    the reload, so it restored the variable into a module that had already read
    it. The very next test that wrote a matrix wrote it into PRODUCTION. The
    original value is therefore captured and put back BEFORE the reload, and
    the result is asserted rather than hoped for.
    """
    import importlib

    from app.services import rediscovery

    monkeypatch.setenv("SATOM_REDISCOVERY_DIR", str(tmp_path / "rd"))
    assert str(rediscovery._data_dir()) == str(tmp_path / "rd")

    import app.services.api_matrix as am

    original = os.environ["SATOM_API_MATRIX_DIR"]
    monkeypatch.setenv("SATOM_API_MATRIX_DIR", str(tmp_path / "am"))
    try:
        am2 = importlib.reload(am)
        assert am2.MATRIX_ROOT == str(tmp_path / "am")
    finally:
        os.environ["SATOM_API_MATRIX_DIR"] = original
        am3 = importlib.reload(am)
        assert not am3.MATRIX_ROOT.startswith(os.path.join(REPO, "data")), \
            "the reload must not leave the module pointing at the live tree"


def test_conftest_sets_both_isolations():
    code = _read(os.path.join(REPO, "tests", "conftest.py"))
    assert "SATOM_REDISCOVERY_DIR" in code
    assert "SATOM_API_MATRIX_DIR" in code


# =========================================================================== #
#  5. the card READS the sweep it starts                                       #
# =========================================================================== #
def test_the_card_polls_the_sweep_status_endpoint():
    code = _tpl()
    assert "appliances.rediscover_status" in code
    assert "setInterval" in code


def test_the_load_redirect_tells_the_card_what_to_watch():
    code = _body(VIEW, "load")
    assert "dr_watch=appliance.id" in code


def test_the_three_cli_outcomes_stay_three_in_the_card():
    """captured / skipped / failed send the operator to three different places.
    Asserted on the RENDERING branches, not on the file: each key must be read."""
    code = _tpl()
    paint = code[code.index("function paintSweep"):]
    paint = paint[:paint.index("function pollSweep")]
    for key in ("cli_kb", "cli_skipped", "cli_error"):
        # The CONDITION, not the identifier. `if (false && p.cli_skipped)` still
        # contains "p.cli_skipped", so a substring assertion stayed green with
        # the branch disabled -- the same class of near-miss as the audit row
        # above.
        assert re.search(r"if \(p\.%s !?=?=? ?\w*\)\s*\{" % key, paint) \
            or re.search(r"if \(p\.%s\)\s*\{" % key, paint), key


def test_the_card_names_every_sweep_phase():
    """A bar with no words cannot tell a REST sweep from an SSH capture, and
    they have very different expected durations."""
    code = _tpl()
    phases = code[code.index("var SWEEP_PHASE"):]
    # Sliced on "};", never on the first "}": the phase labels are Jinja
    # `{{ _("…") }}` calls, so the first brace belongs to a translation marker
    # and the window closed before a single state was in it.
    phases = phases[:phases.index("};")]
    for state in ("'running'", "'deep-running'", "'cli-running'"):
        assert state in phases, state


def test_interrupted_is_rendered_apart_from_done_and_failed_in_both_pages():
    for path in (TPL, RTPL):
        code = _tpl(path)
        assert "interrupted" in code, path
    card = _tpl(TPL)
    paint = card[card.index("function paintSweep"):]
    paint = paint[:paint.index("function pollSweep")]
    assert "'interrupted'" in paint and "'failed'" in paint
    assert "'done'" in paint


def test_the_card_no_longer_drives_a_job_at_all():
    """Inverted on 2026-09-17, when *Run discovery* was removed.

    The old guard required a Stop button and a job poller, and it was anchored
    to the BUTTON ELEMENT on purpose: ``data-js="dr-stop"`` also appears as the
    selector that shows and hides it, so a bare substring check was answered by
    the JavaScript while the button itself had been renamed away. The inverse
    needs the same care in reverse — leaving the poller behind with no button
    is a timer nothing can stop, so BOTH halves are asserted gone.
    """
    code = _tpl()
    assert not re.search(r'<button[^>]*data-js="dr-stop"', code), "Stop button back"
    assert not re.search(r'data-js="dr-stop"\]', code), "Stop wiring back"
    for token in ("DRJOBID", "function pollJob", "function watchJob",
                  "function finishJob", "function paintJob", "jobs.cancel"):
        assert token not in code, token


def test_the_job_still_persists_its_result_for_whoever_reads_it_next():
    """The card stopped rendering findings; the JOB did not stop storing them.

    This is the half of the old guard that survives the removal. The result is
    persisted so a run outlives the request that started it — and the routes
    that start one are still registered (see views/_discovery.py). A worker
    that quietly stopped storing would break them with nothing on screen to
    say so, because the screen no longer looks.
    """
    import inspect

    from app.services import discovery_jobs

    src = inspect.getsource(discovery_jobs)
    assert "result" in src
    assert hasattr(discovery_jobs, "start")
