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
