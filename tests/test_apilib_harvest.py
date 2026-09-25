"""Guards for the incremental API-library harvest (services/apilib_harvest.py).

The failures these pin are quiet ones: a harvest queued twice reads the same
box twice; a product with no live harvester that "succeeds" reads as measured
on the next page; and a ``needs_harvest`` that accepts vendor or line-level
evidence stops the one build nobody has measured from ever being measured.
No test here contacts a device: every harvester is replaced at its seam.
"""
from __future__ import annotations

import json
import time

import pytest

from app.extensions import db
from app.models import Appliance
from app.models_apilib import ApiLibEvidence
from app.services import api_library as lib
from app.services import apilib_harvest as ah
from app.services import jobs


@pytest.fixture(autouse=True)
def _private_stores(tmp_path, monkeypatch):
    """A job ledger and a rediscovery tree per TEST. The session-wide ones
    outlive each test's database, and appliance ids restart at 1 in every
    fresh DB: a pending harvest left by one test would dedup the next."""
    monkeypatch.setenv("SATOM_JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("SATOM_REDISCOVERY_DIR", str(tmp_path / "rediscovery"))


@pytest.fixture()
def ctx(app):
    with app.app_context():
        yield app


def _ap(name, kind="fortiweb", firmware="FortiWeb-KVM 7.6.8,build1128(GA.M),260602",
        maintenance=False):
    a = Appliance(name=name, kind=kind, host=f"{name}.test", port=443,
                  username="admin", verify_ssl=False, firmware=firmware,
                  maintenance=maintenance)
    a.password = "secret"
    db.session.add(a)
    db.session.commit()
    return a


def _doc(product="fortiweb", source="sweep", version="7.6.8", healthy=True,
         scope=None, device="fwA"):
    return {
        "product": product, "source": source, "captured_at": "2026-09-01T00:00:00",
        "origin_ref": "test:%s:%s@%s" % (source, device, version),
        "device": {"appliance_id": None, "name": device, "serial": "", "model": "",
                   "hw_type": "vm", "firmware_raw": version},
        "scope": scope or {"kind": "build", "version": version, "build": ""},
        "healthy": healthy, "skip_reason": "" if healthy else "broken",
        "endpoints": {"admin": {"urn": "/api/v2.0/cmdb/system/admin", "section": "System",
                                "verdict": "ok", "rows": 1,
                                "fields": {"name": {"type": "str"}}}},
    }


def _harvest_jobs():
    return jobs.list_jobs(limit=500, type_=ah.JOB_TYPE)


def _wait_terminal(job_id, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        st = jobs.get_job(job_id) or {}
        if st.get("status") in ("success", "error", "cancelled"):
            return st
        time.sleep(0.05)
    raise AssertionError("job %s never finished: %s" % (job_id, jobs.get_job(job_id)))


# --------------------------------------------------------------------------
# the product table is one table
# --------------------------------------------------------------------------

def test_every_live_source_has_a_harvester_and_nothing_else_does():
    """Two lists that must agree: a product in LIVE_SOURCE with no harvester
    would be judged 'needs a harvest' forever and never harvested."""
    assert set(ah.LIVE_SOURCE) == set(ah._HARVESTERS)
    assert "fortianalyzer" not in ah.LIVE_SOURCE
    assert "fortigate" not in ah.LIVE_SOURCE
    assert set(ah.LIVE_SOURCE) <= set(lib.PRODUCTS)
    assert set(ah.LIVE_SOURCE.values()) <= set(lib.SOURCES)


# --------------------------------------------------------------------------
# enqueue
# --------------------------------------------------------------------------

@pytest.mark.parametrize("kind", ["fortianalyzer", "fortigate"])
def test_enqueue_unsupported_product_is_explicit(ctx, monkeypatch, kind):
    ctx.config[ah.DISPATCH_CONFIG] = True
    monkeypatch.setattr(ah, "_dispatch", lambda *a, **k: pytest.fail("dispatched"))
    a = _ap("box-" + kind, kind=kind)
    res = ah.enqueue(a.id, "firmware_change:7.4.1->7.4.2")
    assert res["queued"] is False
    assert res["reason"] == "unsupported"
    assert res["msg"] == "no live harvester for %s" % kind
    assert _harvest_jobs() == []


def test_enqueue_dedups_one_pending_harvest_per_appliance(ctx, monkeypatch):
    ctx.config[ah.DISPATCH_CONFIG] = True
    dispatched = []
    # The job stays pending: nothing runs it, exactly the window a second
    # probe of the same box lands in.
    monkeypatch.setattr(ah, "_dispatch", lambda app, jid, aid: dispatched.append((jid, aid)))
    a = _ap("fw-dedup")
    b = _ap("fw-other")
    first = ah.enqueue(a.id, "firmware_change:7.6.7->7.6.8")
    assert first["queued"] is True and first["job_id"]
    second = ah.enqueue(a.id, "firmware_change:7.6.7->7.6.8")
    assert second["queued"] is False
    assert second["reason"] == "duplicate"
    assert second["job_id"] == first["job_id"]
    third = ah.enqueue(b.id, "firmware_change:7.6.7->7.6.8")
    assert third["queued"] is True and third["job_id"] != first["job_id"]
    assert [aid for _, aid in dispatched] == [a.id, b.id]
    job = jobs.get_job(first["job_id"])
    assert job["type"] == ah.JOB_TYPE
    assert job["meta"]["appliance_id"] == a.id
    assert job["meta"]["reason"] == "firmware_change:7.6.7->7.6.8"
    assert job["background"] is True


def test_a_finished_harvest_does_not_block_the_next(ctx, monkeypatch):
    ctx.config[ah.DISPATCH_CONFIG] = True
    monkeypatch.setattr(ah, "_dispatch", lambda *a: None)
    a = _ap("fw-again")
    first = ah.enqueue(a.id, "r")
    jobs.finish_success(first["job_id"])
    again = ah.enqueue(a.id, "r")
    assert again["queued"] is True and again["job_id"] != first["job_id"]


def test_enqueue_is_off_under_testing_unless_asked(ctx):
    """The safety net for every OTHER test that probes a fake box at a LAN
    address: no background sweep may grow out of it."""
    assert ctx.config.get(ah.DISPATCH_CONFIG) is None
    a = _ap("fw-testing")
    res = ah.enqueue(a.id, "r")
    assert res == {"queued": False, "reason": "disabled",
                   "msg": "background harvest is disabled (%s)" % ah.DISPATCH_CONFIG}
    assert _harvest_jobs() == []


def test_enqueue_skips_maintenance_and_missing(ctx, monkeypatch):
    ctx.config[ah.DISPATCH_CONFIG] = True
    monkeypatch.setattr(ah, "_dispatch", lambda *a: pytest.fail("dispatched"))
    a = _ap("fw-parked", maintenance=True)
    assert ah.enqueue(a.id, "r")["reason"] == "maintenance"
    assert ah.enqueue(987654, "r")["reason"] == "not_found"
    assert _harvest_jobs() == []


def test_enqueue_outside_an_app_context_does_not_raise():
    res = ah.enqueue(1, "r")
    assert res["queued"] is False and res["reason"] == "no_app_context"


def test_enqueue_runs_through_the_job_runner(ctx, monkeypatch):
    """The real dispatch: jobs.run_async, the worker's own app context, and a
    terminal state that tells success from failure."""
    ctx.config[ah.DISPATCH_CONFIG] = True
    seen = []

    def _fake_run(aid):
        from flask import has_app_context
        seen.append((aid, has_app_context()))
        return {"ok": aid == ok_id, "msg": "fake harvest %s" % aid, "reason": "x"}

    monkeypatch.setattr(ah, "run", _fake_run)
    ok_id = _ap("fw-job-ok").id
    bad_id = _ap("fw-job-bad").id
    ok = _wait_terminal(ah.enqueue(ok_id, "r")["job_id"])
    bad = _wait_terminal(ah.enqueue(bad_id, "r")["job_id"])
    assert ok["status"] == "success" and ok["result"]["msg"] == "fake harvest %d" % ok_id
    assert bad["status"] == "error" and bad["error"] == "fake harvest %d" % bad_id
    assert bad["result"]["ok"] is False
    assert seen == [(ok_id, True), (bad_id, True)]


# --------------------------------------------------------------------------
# run — dispatch per product
# --------------------------------------------------------------------------

def _fake_sweep(monkeypatch, calls, apilib):
    from app.services import rediscovery

    def _run(snap, by="", deep=False, plan=None, cli=False):
        calls.append({"id": snap.id, "kind": snap.kind, "by": by, "deep": deep,
                      "plan": plan, "cli": cli})
        state = {"state": "done", "summary": "3 object(s)",
                 "started": "2026-09-01T00:00:00"}
        state.update(apilib)
        p = rediscovery._dev_dir(snap.id) / "progress.json"
        p.write_text(json.dumps(state), encoding="utf-8")

    monkeypatch.setattr(rediscovery, "_run", _run)
    monkeypatch.setattr(rediscovery, "plan_for",
                        lambda ap: [{"name": "p-" + ap.kind, "urn": "/x", "section": "s"}])


@pytest.mark.parametrize("kind", ["fortiweb", "fortiadc"])
def test_run_sweeps_fortiweb_and_fortiadc(ctx, monkeypatch, kind):
    calls = []
    _fake_sweep(monkeypatch, calls, {"apilib": {"evidence_id": 41, "created": True,
                                                "healthy": True, "skip_reason": ""}})
    monkeypatch.setattr("app.services.apilib_fac.harvest",
                        lambda *a, **k: pytest.fail("FAC harvester used for %s" % kind))
    a = _ap("sw-" + kind, kind=kind)
    res = ah.run(a.id)
    assert res["ok"] is True, res
    assert res["harvester"] == "sweep" and res["evidence_id"] == 41
    assert calls == [{"id": a.id, "kind": kind, "by": "apilib_harvest", "deep": False,
                      "plan": [{"name": "p-" + kind, "urn": "/x", "section": "s"}],
                      "cli": False}]


def test_run_reports_a_library_failure_of_the_sweep(ctx, monkeypatch):
    calls = []
    _fake_sweep(monkeypatch, calls, {"apilib_error": "OperationalError: no table"})
    a = _ap("sw-liberr")
    res = ah.run(a.id)
    assert res["ok"] is False and res["reason"] == "library_error"
    assert "OperationalError" in res["msg"]


def test_run_unhealthy_sweep_is_not_ok(ctx, monkeypatch):
    calls = []
    _fake_sweep(monkeypatch, calls, {"apilib": {"evidence_id": 7, "created": True,
                                                "healthy": False,
                                                "skip_reason": "283/321 endpoints errored"}})
    a = _ap("sw-sick")
    res = ah.run(a.id)
    assert res["ok"] is False and res["reason"] == "unhealthy"
    assert "283/321" in res["msg"]


def test_run_refuses_while_a_sweep_is_running(ctx, monkeypatch):
    from datetime import datetime
    from app.services import rediscovery
    calls = []
    _fake_sweep(monkeypatch, calls, {})
    a = _ap("sw-busy")
    progress = rediscovery._dev_dir(a.id) / "progress.json"
    # The rediscovery dir is shared by the whole session and ids restart per
    # test DB: leave no live-looking "running" behind for a later test.
    try:
        progress.write_text(json.dumps(
            {"state": "running", "started": datetime.utcnow().isoformat()}),
            encoding="utf-8")
        res = ah.run(a.id)
    finally:
        progress.unlink(missing_ok=True)
    assert res["ok"] is False and res["reason"] == "busy"
    assert calls == []


def test_run_fortiauthenticator_harvests_schema_and_ingests(ctx, monkeypatch):
    from app.services import apilib_fac, rediscovery
    monkeypatch.setattr(rediscovery, "_run",
                        lambda *a, **k: pytest.fail("a FAC must not be swept"))
    a = _ap("fac01", kind="fortiauthenticator",
            firmware="FACVMKVM v6.6.1, build1234 (GA)")

    def _harvest(appliance, client=None, registry=None, raw=None):
        assert appliance.id == a.id
        raw.update({"responses": {"/api/v1/": {"status": 200}}})
        doc = _doc(product="fortiauthenticator", source="schema", version="6.6.1",
                   device="fac01")
        doc["device"]["appliance_id"] = appliance.id
        return doc

    monkeypatch.setattr(apilib_fac, "harvest", _harvest)
    res = ah.run(a.id)
    assert res["ok"] is True, res
    assert res["harvester"] == "schema" and res["created"] is True
    ev = db.session.get(ApiLibEvidence, res["evidence_id"])
    assert ev.product == "fortiauthenticator" and ev.source == "schema"
    assert ev.appliance_id == a.id and ev.raw_gz
    assert ah.needs_harvest(a) is False


@pytest.mark.parametrize("kind", ["fortianalyzer", "fortigate"])
def test_run_unsupported_is_explicit(ctx, monkeypatch, kind):
    from app.services import apilib_fac, rediscovery
    monkeypatch.setattr(rediscovery, "_run", lambda *a, **k: pytest.fail("swept"))
    monkeypatch.setattr(apilib_fac, "harvest", lambda *a, **k: pytest.fail("harvested"))
    a = _ap("u-" + kind, kind=kind)
    res = ah.run(a.id)
    assert res == {"ok": False, "reason": "unsupported", "product": kind,
                   "msg": "no live harvester for %s" % kind}


def test_run_never_raises(ctx, monkeypatch):
    from app.services import apilib_fac
    monkeypatch.setattr(apilib_fac, "harvest",
                        lambda *a, **k: (_ for _ in ()).throw(ConnectionError("refused")))
    a = _ap("fac-dead", kind="fortiauthenticator")
    res = ah.run(a.id)
    assert res["ok"] is False and res["reason"] == "error"
    assert "ConnectionError: refused" in res["msg"]
    assert ah.run(987654)["reason"] == "not_found"


# --------------------------------------------------------------------------
# needs_harvest
# --------------------------------------------------------------------------

def test_needs_harvest_for_a_build_with_no_evidence(ctx):
    a = _ap("n-empty")
    assert ah.needs_harvest(a) is True


def test_healthy_sweep_evidence_for_the_exact_build_satisfies_it(ctx):
    a = _ap("n-done")
    lib.ingest(_doc(version="7.6.8"))
    assert ah.needs_harvest(a) is False


def test_other_builds_and_unhealthy_evidence_do_not_count(ctx):
    a = _ap("n-other")
    lib.ingest(_doc(version="7.6.7"))
    lib.ingest(_doc(version="7.6.8", healthy=False, device="fwSick"))
    assert ah.needs_harvest(a) is True


@pytest.mark.parametrize("source", ["vendor_doc", "legacy_matrix", "schema", "manual"])
def test_non_live_sources_do_not_count_for_fortiweb(ctx, source):
    a = _ap("n-src-" + source)
    lib.ingest(_doc(version="7.6.8", source=source))
    assert ah.needs_harvest(a) is True


def test_line_evidence_is_not_evidence_for_the_build(ctx):
    a = _ap("n-line")
    lib.ingest(_doc(version="7.6", scope={"kind": "line", "line": "7.6"}))
    assert ah.needs_harvest(a) is True


def test_fac_needs_schema_evidence_not_sweep(ctx):
    a = _ap("fac-n", kind="fortiauthenticator", firmware="FACVMKVM v6.6.1, build1 (GA)")
    lib.ingest(_doc(product="fortiauthenticator", source="sweep", version="6.6.1"))
    assert ah.needs_harvest(a) is True
    lib.ingest(_doc(product="fortiauthenticator", source="schema", version="6.6.1"))
    assert ah.needs_harvest(a) is False


def test_evidence_of_another_product_does_not_count(ctx):
    a = _ap("n-prod")
    lib.ingest(_doc(product="fortiadc", version="7.6.8"))
    assert ah.needs_harvest(a) is True


@pytest.mark.parametrize("kind,firmware", [
    ("fortianalyzer", "v7.4.2"),        # no live harvester
    ("fortigate", "v7.4.2"),
    ("fortiweb", None),                 # build unknown
    ("fortiweb", "FortiWeb 8.0"),       # line only: not a build
])
def test_nothing_to_harvest(ctx, kind, firmware):
    a = _ap("n-none-%s-%s" % (kind, firmware), kind=kind, firmware=firmware)
    assert ah.needs_harvest(a) is False
