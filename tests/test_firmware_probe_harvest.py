"""``firmware_probe.refresh`` queues an API-library harvest on a build change.

Pinned both ways: a probe that sees a NEW normalized version queues exactly
one harvest, and a probe that re-reads the same build (every probe, almost
always) queues nothing — a harvest per probe would sweep the fleet every few
minutes. And the library can never cost the probe its answer.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Appliance
from app.services import apilib_harvest, firmware_probe
from app.services import api_library as lib


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


def _ap(firmware, kind="fortiweb", name="fw-probe-h"):
    a = Appliance(name=name, kind=kind, host="fw-probe-h.test", port=443,
                  username="admin", verify_ssl=False, firmware=firmware)
    a.password = "secret"
    db.session.add(a)
    db.session.commit()
    return a


def _reads(monkeypatch, firmware):
    monkeypatch.setattr(firmware_probe, "read", lambda a: {
        "ok": True, "firmware": firmware, "model": "FortiWeb-KVM", "hw_type": "vm",
        "hostname": "", "serial": "", "error": "", "detail": ""})


@pytest.fixture()
def queued(monkeypatch):
    calls = []

    def _enqueue(appliance_id, reason, **kw):
        calls.append((appliance_id, reason))
        return {"queued": True, "job_id": "job-%d" % len(calls), "msg": "queued"}

    monkeypatch.setattr(apilib_harvest, "enqueue", _enqueue)
    return calls


def test_a_version_change_enqueues_one_harvest(ctx, monkeypatch, queued):
    a = _ap("FortiWeb-KVM 7.6.7,build1100,250101")
    _reads(monkeypatch, "FortiWeb-KVM 7.6.8,build1128(GA.M),260602")
    res = firmware_probe.refresh(a)
    assert res["ok"] and res["changed"] is True
    assert queued == [(a.id, "firmware_change:7.6.7->7.6.8")]
    assert res["apilib_harvest"] == {"queued": True, "job_id": "job-1", "msg": "queued"}


def test_the_same_version_does_not_enqueue(ctx, monkeypatch, queued):
    same = "FortiWeb-KVM 7.6.8,build1128(GA.M),260602"
    a = _ap(same)
    _reads(monkeypatch, same)
    res = firmware_probe.refresh(a)
    assert res["ok"] and res["changed"] is False
    assert queued == []
    assert "apilib_harvest" not in res


def test_a_cosmetic_raw_change_on_the_same_version_does_not_enqueue(ctx, monkeypatch, queued):
    """The raw string moved (build suffix, date), the normalized version did
    not. ``changed`` is honest about the string; the harvest keys on the build."""
    a = _ap("FortiWeb-KVM 7.6.8,build1128(GA.M),260602")
    _reads(monkeypatch, "FortiWeb-KVM 7.6.8,build1128(GA.M),260615")
    res = firmware_probe.refresh(a)
    assert res["changed"] is True
    assert queued == []


def test_repeated_probes_enqueue_once(ctx, monkeypatch, queued):
    a = _ap("FortiWeb-KVM 7.6.7,build1100,250101")
    _reads(monkeypatch, "FortiWeb-KVM 7.6.8,build1128(GA.M),260602")
    for _ in range(3):
        firmware_probe.refresh(a)
    assert len(queued) == 1


def test_first_version_enqueues_only_when_the_build_needs_it(ctx, monkeypatch, queued):
    a = _ap(None)
    _reads(monkeypatch, "FortiWeb-KVM 7.6.8,build1128(GA.M),260602")
    firmware_probe.refresh(a)
    assert queued == [(a.id, "firmware_change:none->7.6.8")]

    # A second box on a build the library has measured: nothing to learn.
    lib.ingest({"product": "fortiweb", "source": "sweep",
                "captured_at": "2026-09-01T00:00:00", "origin_ref": "t",
                "device": None, "scope": {"kind": "build", "version": "7.6.8", "build": ""},
                "healthy": True, "skip_reason": "",
                "endpoints": {"admin": {"urn": "/x", "section": "s", "verdict": "ok",
                                        "rows": 0, "fields": None}}})
    b = _ap(None, name="fw-probe-h2")
    firmware_probe.refresh(b)
    assert queued == [(a.id, "firmware_change:none->7.6.8")]


def test_a_failed_read_enqueues_nothing(ctx, monkeypatch, queued):
    a = _ap("FortiWeb-KVM 7.6.7,build1100,250101")
    monkeypatch.setattr(firmware_probe, "read",
                        lambda a: firmware_probe._fail("unreachable", "timeout"))
    res = firmware_probe.refresh(a)
    assert res["ok"] is False
    assert queued == []


def test_a_library_fault_never_fails_the_probe(ctx, monkeypatch):
    a = _ap("FortiWeb-KVM 7.6.7,build1100,250101")
    _reads(monkeypatch, "FortiWeb-KVM 7.6.8,build1128(GA.M),260602")

    def _boom(*a, **k):
        raise RuntimeError("job ledger unwritable")

    monkeypatch.setattr(apilib_harvest, "enqueue", _boom)
    res = firmware_probe.refresh(a)
    assert res["ok"] is True and res["checked_at"]
    assert res["apilib_harvest"]["queued"] is False
    assert "job ledger unwritable" in res["apilib_harvest"]["msg"]
    db.session.expire_all()
    row = db.session.get(Appliance, a.id)
    assert row.firmware.startswith("FortiWeb-KVM 7.6.8")
    assert row.firmware_checked_at is not None


def test_the_real_enqueue_stays_off_under_testing(ctx, monkeypatch):
    """End to end through the real enqueue: under TESTING the dispatch is off,
    so no other test that probes a fake box can grow a background sweep."""
    from app.services import jobs
    a = _ap("FortiWeb-KVM 7.6.7,build1100,250101")
    _reads(monkeypatch, "FortiWeb-KVM 7.6.8,build1128(GA.M),260602")
    res = firmware_probe.refresh(a)
    assert res["apilib_harvest"]["reason"] == "disabled"
    assert jobs.list_jobs(type_=apilib_harvest.JOB_TYPE) == []


def test_an_unsupported_product_is_answered_by_name(ctx, monkeypatch):
    a = _ap("v7.4.1-build2000", kind="fortianalyzer", name="faz-h")
    _reads(monkeypatch, "v7.4.2-build2100")
    res = firmware_probe.refresh(a)
    assert res["apilib_harvest"] == {"queued": False, "reason": "unsupported",
                                     "product": "fortianalyzer",
                                     "msg": "no live harvester for fortianalyzer"}
