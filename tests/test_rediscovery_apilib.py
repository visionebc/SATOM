"""A rediscovery sweep files its snapshot into the API library.

Three properties, each a way to lose evidence without an error on screen:

* the sweep INGESTS — otherwise the library only grows when somebody runs a
  backfill, and the next sweep's overwrite of ``_config.json`` is a loss again;
* a library failure does NOT fail the sweep — the files are the export every
  existing consumer still reads;
* the write goes to the database of the ACTIVE app context, never to a stale
  module-level app — the 2026-09-15 contamination (a test sweep rewriting
  production data) moved from files into rows.

No device is contacted: the per-endpoint probe and the firmware read are
replaced at their seams.
"""
from __future__ import annotations

import json
import logging
from types import SimpleNamespace

import pytest

from app.extensions import db
from app.models import Appliance
from app.models_apilib import ApiLibBuild, ApiLibEvidence
from app.services import rediscovery

PLAN = [
    {"name": "admin", "urn": "/api/v2.0/cmdb/system/admin", "section": "System"},
    {"name": "ghost", "urn": "/api/v2.0/cmdb/system/ghost", "section": "System"},
]


def _make(app, name="fw-lib"):
    with app.app_context():
        a = Appliance(name=name, kind="fortiweb", host="fw-lib.test", port=443,
                      username="admin", verify_ssl=False,
                      firmware="FortiWeb-KVM 7.6.8,build1128(GA.M),260602",
                      model="FortiWeb-KVM 7.6.8", hw_type="vm", serial="FVVM01TEST")
        a.password = "secret"
        db.session.add(a)
        db.session.commit()
        return a.id


def _snap(aid, name="fw-lib"):
    return SimpleNamespace(id=aid, name=name, host="fw-lib.test", port=443,
                           verify_ssl=False, username="admin", password="x",
                           vdom="", kind="fortiweb")


@pytest.fixture(autouse=True)
def _private_stores(tmp_path, monkeypatch):
    """A job ledger and a rediscovery tree per TEST. The session-wide ones
    outlive each test's database, and appliance ids restart at 1 in every
    fresh DB: a pending harvest left by one test would dedup the next."""
    monkeypatch.setenv("SATOM_JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("SATOM_REDISCOVERY_DIR", str(tmp_path / "rediscovery"))


@pytest.fixture()
def offline(monkeypatch):
    """Every device read the sweep would make, answered locally."""
    def _probe(client, ep):
        if ep["name"] == "ghost":
            return [], rediscovery.VERDICT_ABSENT, "errcode -20001"
        return [{"name": "admin", "accprofile": "prof_admin"}], rediscovery.VERDICT_OK, ""

    monkeypatch.setattr(rediscovery, "_probe_fortiweb", _probe)
    monkeypatch.setattr(rediscovery, "_device_firmware", lambda *a, **k: "7.6.8")
    monkeypatch.setattr(rediscovery, "_refresh_api_matrix", lambda *a, **k: None)


def test_a_sweep_ingests_its_snapshot_with_device_identity(app, offline, monkeypatch):
    aid = _make(app)
    monkeypatch.setattr(rediscovery, "_APP", app)
    rediscovery._run(_snap(aid), by="t", deep=False, plan=PLAN)

    st = rediscovery.status(aid)
    assert st["state"] == "done"
    assert "apilib_error" not in st
    assert st["apilib"]["created"] is True and st["apilib"]["healthy"] is True
    with app.app_context():
        ev = db.session.get(ApiLibEvidence, st["apilib"]["evidence_id"])
        assert ev.product == "fortiweb" and ev.source == "sweep"
        assert ev.scope_kind == "build" and ev.healthy
        assert (ev.appliance_id, ev.device_name, ev.device_serial) == (aid, "fw-lib", "FVVM01TEST")
        assert (ev.device_model, ev.device_hw_type) == ("FortiWeb-KVM 7.6.8", "vm")
        assert ev.firmware_raw.startswith("FortiWeb-KVM 7.6.8,build1128")
        assert ev.origin_ref == "rediscovery:%d@7.6.8" % aid
        assert ev.raw_gz
        b = db.session.get(ApiLibBuild, ev.build_id)
        # The build token comes from the row's raw firmware (the sweep keeps
        # only X.Y.Z) because it names the same version the sweep measured.
        assert (b.version, b.build) == ("7.6.8", "build1128")
        assert ev.summary["verdicts"] == {"ok": 1, "absent": 1, "error": 0}
    # The files are still written: they are the export/compat copy.
    devdir = rediscovery._dev_dir(aid)
    assert json.loads((devdir / "_config.json").read_text())["firmware"] == "7.6.8"
    assert (devdir / rediscovery.VERSION_DIR / "7.6.8.json").exists()


def test_a_second_identical_sweep_confirms_instead_of_duplicating(app, offline, monkeypatch):
    aid = _make(app)
    monkeypatch.setattr(rediscovery, "_APP", app)
    rediscovery._run(_snap(aid), by="t", plan=PLAN)
    first = rediscovery.status(aid)["apilib"]
    rediscovery._run(_snap(aid), by="t", plan=PLAN)
    second = rediscovery.status(aid)["apilib"]
    assert second["evidence_id"] == first["evidence_id"]
    assert second["created"] is False
    with app.app_context():
        assert ApiLibEvidence.query.count() == 1
        assert db.session.get(ApiLibEvidence, first["evidence_id"]).confirmations == 2
        # The sweep knows only X.Y.Z; the row's full string of the SAME
        # version must survive it, or the next ingest changes identity.
        assert db.session.get(Appliance, aid).firmware.startswith("FortiWeb-KVM 7.6.8,build1128")


def test_a_sweep_still_records_a_new_version_on_the_row(app, offline, monkeypatch):
    aid = _make(app)
    monkeypatch.setattr(rediscovery, "_APP", app)
    monkeypatch.setattr(rediscovery, "_device_firmware", lambda *a, **k: "8.0.3")
    rediscovery._run(_snap(aid), by="t", plan=PLAN)
    with app.app_context():
        assert db.session.get(Appliance, aid).firmware == "8.0.3"
        ev = db.session.get(ApiLibEvidence, rediscovery.status(aid)["apilib"]["evidence_id"])
        # The row still said 7.6.8 when the sweep ingested: the evidence is
        # filed under what the SWEEP measured, never the stale row.
        assert db.session.get(ApiLibBuild, ev.build_id).version == "8.0.3"
        assert ev.firmware_raw == "8.0.3"


def test_a_library_failure_does_not_fail_the_sweep(app, offline, monkeypatch, caplog):
    from app.services import api_library
    aid = _make(app)
    monkeypatch.setattr(rediscovery, "_APP", app)

    def _boom(*a, **k):
        raise RuntimeError("library is down")

    monkeypatch.setattr(api_library, "ingest", _boom)
    with caplog.at_level(logging.WARNING, logger="app.services.rediscovery"):
        rediscovery._run(_snap(aid), by="t", plan=PLAN)
    st = rediscovery.status(aid)
    assert st["state"] == "done"
    assert st["apilib_error"] == "RuntimeError: library is down"
    assert "apilib" not in st
    assert "1 absent" in st["summary"]
    devdir = rediscovery._dev_dir(aid)
    assert (devdir / "_config.json").exists()
    assert (devdir / rediscovery.VERSION_DIR / "7.6.8.json").exists()
    assert any("API library ingest failed" in r.getMessage() for r in caplog.records)
    with app.app_context():
        assert ApiLibEvidence.query.count() == 0


class _ForeignApp:
    """A stale ``_APP`` from somewhere else. Using it is the contamination."""

    def app_context(self):
        raise AssertionError("the sweep wrote through a stale module-level app")


def test_ingest_goes_to_the_active_app_context_not_a_stale_global(app, offline, monkeypatch):
    aid = _make(app)
    monkeypatch.setattr(rediscovery, "_APP", _ForeignApp())
    with app.app_context():
        rediscovery._run(_snap(aid), by="t", plan=PLAN)
        st = rediscovery.status(aid)
        assert "apilib_error" not in st, st.get("apilib_error")
        assert db.session.get(ApiLibEvidence, st["apilib"]["evidence_id"]) is not None


def test_no_app_at_all_is_a_recorded_failure_not_a_guessed_database(app, offline, monkeypatch):
    """No hard-coded fallback: without an app the write fails and says so."""
    aid = _make(app)
    monkeypatch.setattr(rediscovery, "_APP", None)
    rediscovery._run(_snap(aid), by="t", plan=PLAN)
    st = rediscovery.status(aid)
    assert st["state"] == "done"
    assert "application context" in st["apilib_error"]
    with app.app_context():
        assert ApiLibEvidence.query.count() == 0


def test_a_deleted_row_still_files_evidence_under_the_snapshot_identity(app, offline, monkeypatch):
    monkeypatch.setattr(rediscovery, "_APP", app)
    rediscovery._run(_snap(424242, name="fw-gone"), by="t", plan=PLAN)
    st = rediscovery.status(424242)
    with app.app_context():
        ev = db.session.get(ApiLibEvidence, st["apilib"]["evidence_id"])
        assert (ev.appliance_id, ev.device_name) == (424242, "fw-gone")
        assert ev.healthy


def test_the_ingest_happens_after_the_files_are_written():
    import inspect
    code = inspect.getsource(rediscovery._sweep)
    assert code.index('"_config.json"') < code.index("_ingest_library(")
    assert code.index("archive_snapshot(aid, snapshot)") < code.index("_ingest_library(")


def test_every_db_write_uses_the_active_app_not_the_captured_global(app):
    """``_APP`` outlives the app it was captured from. Inside another app's
    context it must lose, or firmware, matrix export and library evidence land
    in the wrong database (the 2026-09-15 contamination)."""
    from flask import Flask
    from app.services import rediscovery
    stale = Flask("stale")
    saved = rediscovery._APP
    rediscovery._APP = stale
    try:
        with app.app_context():
            assert rediscovery._get_flask_app() is app
        # Outside any context (the bare worker thread) the global is the answer.
        assert rediscovery._get_flask_app() is stale
    finally:
        rediscovery._APP = saved
