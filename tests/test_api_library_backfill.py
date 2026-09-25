"""Backfill of the on-disk evidence stores into the API library.

The fixture tree mirrors the real ``data/`` layout on 2026-09-25, including
the three shapes that the file-based matrix lost or mishandled: a DELETED
appliance's by-version archive (the 8.0.3 FortiADC evidence), a pre-ledger
snapshot with no firmware, and a frozen line-only ``fortiadc.json`` matrix.
"""
from __future__ import annotations

import json

import pytest

from app.extensions import db
from app.models import Appliance
from app.models_apilib import ApiLibBuild, ApiLibEndpointFact, ApiLibEvidence
from app.services import api_library as lib


@pytest.fixture()
def ctx(app):
    with app.app_context():
        yield app


def _write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj))


def _snap(device, aid, firmware, ledger, sections=None, at="2026-08-12T23:08:26.794242"):
    return {"device": device, "appliance_id": aid, "firmware": firmware,
            "generated_at": at, "endpoint_status": ledger, "sections": sections or {}}


def _fixture_tree(root, live_id):
    red = root / "rediscovery"
    fw_ledger = {
        "admin": {"urn": "/api/v2.0/cmdb/system/admin", "section": "System",
                  "verdict": "ok", "rows": 1},
        "json_policy": {"urn": "/api/v2.0/cmdb/waf/json-validation.policy",
                        "section": "API", "verdict": "ok", "rows": 0},
        "gone": {"urn": "/api/v2.0/cmdb/x", "section": "S", "verdict": "absent", "rows": 0},
    }
    fw_sections = {"System": {"admin": [{"name": "admin", "q_type": 1, "access": "rw"}]}}
    # A live FortiWeb: by-version archive AND the same snapshot as _config.json.
    snap = _snap("fortiweb15", live_id, "7.6.8", fw_ledger, fw_sections,
                 at="2026-09-15T19:56:17.437413")
    _write(red / str(live_id) / "by-version" / "7.6.8.json", snap)
    _write(red / str(live_id) / "_config.json", snap)
    # Its inventory marker came from a LATER sweep: its model must not be
    # stamped on this evidence (the model string embeds the running version).
    _write(red / str(live_id) / "_inventory_applied.json", {
        "generated_at": "2026-09-20T00:00:00",
        "result": {"model": "FortiWeb-KVM 8.0.5", "hw_type": "vm"}})
    # A device with only _config.json (no archive yet) on 8.0.5, with its
    # inventory marker written from the SAME snapshot.
    snap = _snap("fortiweb17", 34, "8.0.5", dict(fw_ledger, ntp={
        "urn": "/api/v2.0/cmdb/system/ntp", "section": "System", "verdict": "ok",
        "rows": 1}), {"System": {"ntp": [{"server": "x", "can_view": 1}]}},
        at="2026-09-16T22:45:26.180633")
    _write(red / "34" / "_config.json", snap)
    _write(red / "34" / "_inventory_applied.json", {
        "generated_at": "2026-09-16T22:45:26.180633",
        "result": {"model": "FortiWeb-KVM 8.0.5", "hw_type": "vm"}})
    # A DELETED FortiADC (no appliance row): its by-version archive is the
    # only build-level 8.0.3 evidence left.
    adc_ledger = {"config_sync_list": {"urn": "/api/config_sync_list", "section": "System",
                                       "verdict": "ok", "rows": 1}}
    snap = _snap("fortiadc02", 16, "8.0.3", adc_ledger,
                 {"System": {"config_sync_list": [{"mkey": "a", "peer": "x"}]}})
    _write(red / "16" / "by-version" / "8.0.3.json", snap)
    _write(red / "16" / "_config.json", snap)
    # A pre-ledger snapshot with no firmware (the June format).
    _write(red / "2" / "_config.json", {
        "device": "fw2", "appliance_id": 2, "generated_at": "2026-07-02T22:24:50",
        "sections": {"DoS": {"dos_policy": [{"id": 1, "q_type": 1}]}}})
    # An empty appliance directory is not evidence.
    (red / "18").mkdir(parents=True)

    sch = root / "field_schemas" / "fortiweb"
    _write(sch / "7.6" / "admin.json", {
        "object": "admin", "endpoint": "system_admin", "source": "live:fw2@7.6",
        "generated_at": "2026-06-28",
        "fields": [{"name": "name", "type": "text", "required": True, "default": ""},
                   {"name": "access", "type": "text"}]})
    _write(sch / "7.6" / "_coverage.json", {"appliance": "fortiweb08",
                                             "device_firmware": "7.6.8"})
    _write(sch / "8.0" / "admin.json", {
        "object": "admin", "endpoint": "system_admin", "source": "live:fw1@8.0",
        "generated_at": "2026-06-28",
        "fields": [{"name": "name"}, {"name": "access"}, {"name": "fortiai"}]})
    _write(sch / "_default" / "admin.json", {
        "object": "admin", "endpoint": "system_admin", "source": "default<-fw1@8.0",
        "fields": [{"name": "name"}]})

    mat = root / "api_matrix"
    _write(mat / "fortiadc.json", {
        "product": "fortiadc", "built_at": "2026-08-13T00:42:13", "sweepable": True,
        "fleet_lines": ["8.0"], "notes": [],
        "witnesses": [{"id": 16, "name": "fortiadc02", "line": "8.0",
                       "firmware": "8.0.3 build0093,260401"}],
        "lines": {"8.0": {"line": "8.0", "in_fleet": True, "devices": ["fortiadc02"],
                          "objects": {}, "counts": {},
                          "endpoints": {
                              "config_sync_list": {"endpoint": "config_sync_list",
                                                   "urn": "/api/config_sync_list",
                                                   "section": "System", "verdict": "ok",
                                                   "fields": ["mkey", "peer"],
                                                   "devices": ["fortiadc02", "fortiadc03"]},
                              "old_only": {"endpoint": "old_only", "urn": "/api/old",
                                           "section": "System", "verdict": "ok",
                                           "fields": None, "devices": ["fortiadc03"]}}}}})
    # A modern (version-axis) matrix is derived from the snapshots above and
    # must NOT be imported a second time.
    _write(mat / "fortiweb.json", {"product": "fortiweb", "versions": {}, "lines": {
        "7.6": {"endpoints": {"phantom": {"verdict": "ok", "fields": ["x"]}}}}})


def test_backfill_reads_every_store_and_is_idempotent(ctx, tmp_path):
    live = Appliance(name="fortiweb15", kind="fortiweb", host="fw15.test", port=443,
                     username="admin", verify_ssl=False, firmware="7.6.8")
    live.password = "secret"
    db.session.add(live)
    db.session.commit()
    _fixture_tree(tmp_path, live.id)

    first = lib.backfill(str(tmp_path))
    n_evidence = ApiLibEvidence.query.count()
    n_facts = ApiLibEndpointFact.query.count()
    # live 7.6.8 (archive; identical _config skipped), 34 (_config), 16 (archive),
    # 2 (pre-ledger, stored unhealthy), schema 7.6 + 8.0, legacy fortiadc 8.0.
    assert first["documents"] == 7 and first["created"] == 7
    assert n_evidence == 7

    again = lib.backfill(str(tmp_path))
    assert again["created"] == 0 and again["confirmed"] == 7
    assert ApiLibEvidence.query.count() == n_evidence
    assert ApiLibEndpointFact.query.count() == n_facts

    web = {b["version"]: b for b in lib.builds("fortiweb")}
    assert {"7.6.8", "8.0.5", "7.6", "8.0"} <= set(web)
    assert web["7.6"]["line_only"] is True and web["7.6"]["sources"] == ["schema"]
    adc = {b["version"]: b for b in lib.builds("fortiadc")}
    assert {"8.0.3", "8.0"} <= set(adc)
    assert adc["8.0"]["sources"] == ["legacy_matrix"]
    assert adc["8.0.3"]["measured"] is True

    # The deleted appliance: identity from the snapshot, product from its URNs.
    ev = ApiLibEvidence.query.filter_by(appliance_id=16).one()
    assert (ev.product, ev.device_name, ev.healthy) == ("fortiadc", "fortiadc02", True)
    assert ev.origin_ref == "rediscovery:16@8.0.3"
    # Model/hw only from an inventory marker of the SAME snapshot.
    ev34 = ApiLibEvidence.query.filter_by(appliance_id=34).one()
    assert (ev34.device_model, ev34.device_hw_type) == ("FortiWeb-KVM 8.0.5", "vm")
    ev_live = ApiLibEvidence.query.filter_by(appliance_id=live.id).one()
    assert (ev_live.device_model, ev_live.device_hw_type) == ("", "")
    # Pre-ledger, no firmware: kept, unattributed, never folded.
    ev2 = ApiLibEvidence.query.filter_by(appliance_id=2).one()
    assert ev2.healthy is False and ev2.build_id is None and ev2.product == "fortiweb"
    # The modern fortiweb.json was not imported.
    assert "phantom" not in lib.endpoints_at("fortiweb", "7.6")

    # Line-scoped evidence stays at line granularity.
    assert lib.fields_at("fortiweb", "system_admin", "8.0")["status"] == "measured"
    assert lib.fields_at("fortiweb", "system_admin", "8.0.5")["status"] == "unmeasured"
    # ...and a build nobody ever measured is not answered from its line either.
    assert lib.fields_at("fortiweb", "system_admin", "8.0.9")["status"] == "unmeasured"
    assert lib.endpoints_at("fortiweb", "8.0.9") == {}
    diff = lib.compare("fortiweb", "7.6", "8.0", endpoint="system_admin")
    assert diff["endpoints"]["system_admin"]["added"] == ["fortiai"]
    assert set(lib.fields_at("fortiadc", "config_sync_list", "8.0")["fields"]) == {"mkey", "peer"}
    assert lib.endpoints_at("fortiadc", "8.0")["old_only"]["witnesses"] == ["fortiadc03"]

    doc = lib.matrix_doc("fortiadc")
    assert "8.0.3" in doc["versions"] and "8.0" in doc["lines"]
    assert "old_only" in doc["lines"]["8.0"]["endpoints"]
    assert {w["name"] for w in doc["witnesses"] if w["retired"]} == {"fortiadc02"}
    web_doc = lib.matrix_doc("fortiweb")
    assert sorted(web_doc["versions"]) == ["7.6.8", "8.0.5"]
    assert web_doc["versions"]["8.0.5"]["objects"]["admin"]["fields"] == ["access", "fortiai", "name"]
    assert any(n["skipped"].startswith("snapshot records no firmware") for n in web_doc["notes"])


def test_backfill_product_filter(ctx, tmp_path):
    _fixture_tree(tmp_path, 1)
    res = lib.backfill(str(tmp_path), products=["fortiadc"])
    assert set(res["by_product"]) == {"fortiadc"}
    assert ApiLibBuild.query.filter_by(product="fortiweb").count() == 0


def test_backfill_cli(ctx, tmp_path):
    _fixture_tree(tmp_path, 1)
    res = ctx.test_cli_runner().invoke(args=["apilib", "backfill", "--data-root",
                                             str(tmp_path), "--product", "fortiadc"])
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)["by_product"]["fortiadc"]["documents"] == 2


# --------------------------------------------------------------------------
# a live sweep ingest and a backfill of the same file are ONE measurement
# --------------------------------------------------------------------------

_LEDGER = {"admin": {"urn": "/api/v2.0/cmdb/system/admin", "section": "System",
                     "verdict": "ok", "rows": 1}}
_SECTIONS = {"System": {"admin": [{"name": "admin", "q_type": 1}]}}


def _live_device(aid, name):
    """What rediscovery._library_device copies from the appliance row."""
    return {"appliance_id": aid, "name": name, "serial": "FVVM%04d" % aid,
            "model": "FortiWeb-KVM 7.6.8", "hw_type": "vm",
            "firmware_raw": "FortiWeb-KVM 7.6.8,build1128(GA.M),260602"}


def _live_ingest(aid, name, snap):
    doc = lib.evidence_from_sweep("fortiweb", snap, _live_device(aid, name),
                                  "rediscovery:%d@7.6.8" % aid)
    return lib.ingest(doc, raw=snap)


def _archive_file(root, aid, snap):
    _write(root / "rediscovery" / str(aid) / "by-version" / "7.6.8.json", snap)


def test_backfill_after_a_live_ingest_confirms_instead_of_duplicating(ctx, tmp_path):
    snap = _snap("fw-live", 41, "7.6.8", _LEDGER, _SECTIONS)
    live = _live_ingest(41, "fw-live", snap)
    _archive_file(tmp_path, 41, snap)
    res = lib.backfill(str(tmp_path))
    assert (res["created"], res["confirmed"]) == (0, 1)
    ev = ApiLibEvidence.query.one()
    assert ev.id == live["evidence_id"] and ev.confirmations == 2
    # The live row's richer identity is what stays.
    assert (ev.device_serial, ev.device_model) == ("FVVM0041", "FortiWeb-KVM 7.6.8")


def test_a_live_ingest_after_a_backfill_confirms_and_fills_the_blanks(ctx, tmp_path):
    snap = _snap("fw-live", 41, "7.6.8", _LEDGER, _SECTIONS)
    _archive_file(tmp_path, 41, snap)
    lib.backfill(str(tmp_path))
    ev = ApiLibEvidence.query.one()
    assert (ev.device_serial, ev.device_model) == ("", "")
    res = _live_ingest(41, "fw-live", snap)
    assert res["created"] is False and ApiLibEvidence.query.count() == 1
    ev = ApiLibEvidence.query.one()
    assert ev.confirmations == 2
    assert (ev.device_serial, ev.device_model, ev.device_hw_type) == \
        ("FVVM0041", "FortiWeb-KVM 7.6.8", "vm")
    # Filled, never overwritten: the backfill's raw firmware string stays.
    assert ev.firmware_raw == "7.6.8"
    assert db.session.get(ApiLibBuild, ev.build_id).build == "build1128"


def test_two_devices_with_identical_content_stay_two_witnesses(ctx, tmp_path):
    """Dropping device identity from the hash must not merge two boxes that
    happen to answer identically on one build: that would lose a witness."""
    for aid, name in ((41, "boxA"), (42, "boxB")):
        snap = _snap(name, aid, "7.6.8", _LEDGER, _SECTIONS)
        _live_ingest(aid, name, snap)
        _archive_file(tmp_path, aid, snap)
    res = lib.backfill(str(tmp_path))
    assert (res["created"], res["confirmed"]) == (0, 2)
    rows = ApiLibEvidence.query.order_by(ApiLibEvidence.appliance_id).all()
    assert [(r.device_name, r.confirmations) for r in rows] == [("boxA", 2), ("boxB", 2)]
    assert ApiLibEndpointFact.query.one().witnesses == ["boxA", "boxB"]
    assert lib.endpoints_at("fortiweb", "7.6.8")["admin"]["witnesses"] == ["boxA", "boxB"]
    doc = lib.matrix_doc("fortiweb")
    assert doc["versions"]["7.6.8"]["devices"] == ["boxA", "boxB"]
    assert {w["name"] for w in doc["witnesses"]} == {"boxA", "boxB"}
