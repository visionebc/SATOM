"""Guards for the API library (services/api_library.py, models_apilib.py).

Every failure covered here is silent: a library that double-counts, forgets a
retired device, reads "not asked" as "not served" or lets a vendor range run
past what the vendor knew still renders a full page and still answers a
preflight — it just answers wrong, right before a write to a real appliance.
"""
from __future__ import annotations

import gzip
import importlib.util
import json
import os
import time
from types import SimpleNamespace

import pytest
import sqlalchemy as sa

from app.extensions import db
from app.models import Appliance
from app.models_apilib import (ApiLibBuild, ApiLibEndpointFact, ApiLibEvidence,
                               ApiLibFieldFact, ApiLibFieldMap, ApiLibSpan)
from app.services import api_library as lib
from app.services import api_matrix as am
from app.services import firmware_versions as fv

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

@pytest.fixture()
def ctx(app):
    with app.app_context():
        yield app


def _doc(version="7.6.8", endpoints=None, product="fortiweb", source="sweep",
         device="fwA", appliance_id=None, healthy=True, captured="2026-09-01T00:00:00",
         scope=None):
    return {
        "product": product, "source": source, "captured_at": captured,
        "origin_ref": "test:%s@%s" % (device, version),
        "device": ({"appliance_id": appliance_id, "name": device, "serial": "",
                    "model": "", "hw_type": "vm", "firmware_raw": version}
                   if device else None),
        "scope": scope or {"kind": "build", "version": version, "build": ""},
        "healthy": healthy, "skip_reason": "" if healthy else "broken",
        "endpoints": endpoints if endpoints is not None else {
            "admin": {"urn": "/api/v2.0/cmdb/system/admin", "section": "System",
                      "verdict": "ok", "rows": 1,
                      "fields": {"name": {"type": "str"}, "access": {"type": "str"}}},
        },
    }


def _ep(verdict="ok", fields=None, urn="/api/x"):
    return {"urn": urn, "section": "s", "verdict": verdict, "rows": None, "fields": fields}


def _vendor_doc(endpoints, versions, origin="ansible:fortinet.fortios:1.0.0",
                product="fortigate"):
    return {"product": product, "source": "vendor_doc", "captured_at": "2026-01-01",
            "origin_ref": origin, "device": None,
            "scope": {"kind": "spans", "versions": versions},
            "healthy": True, "skip_reason": "", "endpoints": endpoints,
            "summary": {"max_version": versions[-1], "min_version": versions[0]}}


def _appliance(name, kind="fortiweb", firmware="7.6.8"):
    a = Appliance(name=name, kind=kind, host=f"{name}.test", port=443,
                  username="admin", verify_ssl=False, firmware=firmware)
    a.password = "secret"
    db.session.add(a)
    db.session.commit()
    return a


# --------------------------------------------------------------------------
# version_key
# --------------------------------------------------------------------------

def test_version_key_orders_exactly_like_sort_key():
    vs = ["8.0.10", "8.0.9", "8.0", "7.6.8", "10.0.0", "8.0.0", "7.6"]
    assert sorted(vs, key=lib.version_key) == sorted(vs, key=fv.sort_key)
    assert lib.version_key("8.0.5") == "00008.00000.00005"
    assert lib.version_key("8.0") == "00008.00000"
    assert lib.version_key("") == ""


# --------------------------------------------------------------------------
# ingest: idempotent, bounded, unhealthy kept but not folded
# --------------------------------------------------------------------------

def test_same_content_twice_is_one_row_confirmed_twice(ctx):
    first = lib.ingest(_doc())
    # captured_at is not content: a re-harvest a day later is a confirmation.
    second = lib.ingest(_doc(captured="2026-09-02T00:00:00"))
    assert first["created"] is True and second["created"] is False
    assert first["evidence_id"] == second["evidence_id"]
    assert ApiLibEvidence.query.count() == 1
    ev = ApiLibEvidence.query.one()
    assert ev.confirmations == 2
    assert ev.raw_gz and json.loads(gzip.decompress(ev.raw_gz))["product"] == "fortiweb"


def test_content_change_is_new_evidence(ctx):
    lib.ingest(_doc())
    doc = _doc()
    doc["endpoints"]["admin"]["fields"]["theme"] = {"type": "str"}
    res = lib.ingest(doc)
    assert res["created"] is True
    assert ApiLibEvidence.query.count() == 2


def test_facts_are_bounded_by_builds_not_sweeps(ctx):
    """Two sweeps of the same build with different content update the SAME
    fact rows. Keyed by harvest, facts would grow with every sweep forever."""
    lib.ingest(_doc(device="fwA"))
    lib.ingest(_doc(device="fwB"))
    assert ApiLibEvidence.query.count() == 2
    assert ApiLibEndpointFact.query.count() == 1
    assert ApiLibFieldFact.query.count() == 2
    fact = ApiLibEndpointFact.query.one()
    assert fact.witnesses == ["fwA", "fwB"]


def test_verdict_merge_within_a_build_ok_wins(ctx):
    lib.ingest(_doc(device="fwA", endpoints={"waf": _ep("absent")}))
    lib.ingest(_doc(device="fwB", endpoints={"waf": _ep("ok", {"x": {}})}))
    lib.ingest(_doc(device="fwC", endpoints={"waf": _ep("error")}))
    assert ApiLibEndpointFact.query.one().verdict == "ok"
    assert lib.endpoints_at("fortiweb", "7.6.8")["waf"]["verdict"] == "ok"


def test_unhealthy_evidence_is_stored_but_never_folded(ctx):
    res = lib.ingest(_doc(healthy=False))
    ev = db.session.get(ApiLibEvidence, res["evidence_id"])
    assert ev is not None and ev.healthy is False and ev.skip_reason == "broken"
    assert ApiLibEndpointFact.query.count() == 0
    assert ApiLibFieldFact.query.count() == 0
    assert lib.endpoints_at("fortiweb", "7.6.8") == {}
    assert lib.fields_at("fortiweb", "admin", "7.6.8")["status"] == "unmeasured"
    notes = lib.matrix_doc("fortiweb")["notes"]
    assert notes and notes[0]["skipped"] == "broken"


def test_sweep_adapter_applies_error_ratio():
    ledger = {"e%d" % i: {"urn": "/api/v2.0/cmdb/e", "section": "s",
                          "verdict": "error" if i < 3 else "ok", "rows": 0}
              for i in range(10)}
    snap = {"firmware": "7.6.8", "generated_at": "2026-09-01T00:00:00",
            "endpoint_status": ledger, "sections": {}}
    doc = lib.evidence_from_sweep("fortiweb", snap, {"name": "fw"}, "t")
    assert doc["healthy"] is False and "3/10" in doc["skip_reason"]
    ledger["e0"]["verdict"] = "ok"   # 2/10 errored: under the threshold
    assert lib.evidence_from_sweep("fortiweb", snap, {"name": "fw"}, "t")["healthy"] is True


def test_sweep_adapter_empty_rows_are_blind_not_empty():
    snap = {"firmware": "8.0.5", "generated_at": "2026-09-01T00:00:00",
            "endpoint_status": {
                "empty": {"urn": "/api/v2.0/cmdb/a", "section": "S", "verdict": "ok", "rows": 0},
                "full": {"urn": "/api/v2.0/cmdb/b", "section": "S", "verdict": "ok", "rows": 1}},
            "sections": {"S": {"full": [{"name": "x", "rules": [{"id": 1, "host": "h"}]}]}}}
    doc = lib.evidence_from_sweep("fortiweb", snap, {"name": "fw", "firmware_raw": "8.0.5,build0123"}, "t")
    assert doc["endpoints"]["empty"]["fields"] is None
    assert doc["endpoints"]["full"]["fields"]["name"]["type"] == "str"
    assert doc["endpoints"]["full"]["fields"]["rules"]["children"] == ["host", "id"]
    assert doc["scope"] == {"kind": "build", "version": "8.0.5", "build": "build0123"}


# --------------------------------------------------------------------------
# blind vs measured-empty vs unmeasured vs absent
# --------------------------------------------------------------------------

def test_fields_none_is_blind_and_empty_dict_is_measured(ctx):
    lib.ingest(_doc(endpoints={"blind": _ep("ok", None), "none": _ep("ok", {}),
                               "gone": _ep("absent")}))
    assert lib.fields_at("fortiweb", "blind", "7.6.8")["status"] == "blind"
    empty = lib.fields_at("fortiweb", "none", "7.6.8")
    assert empty["status"] == "measured" and empty["fields"] == {}
    assert lib.fields_at("fortiweb", "gone", "7.6.8")["status"] == "absent"
    assert lib.fields_at("fortiweb", "never_asked", "7.6.8")["status"] == "unmeasured"
    eps = lib.endpoints_at("fortiweb", "7.6.8")
    assert eps["blind"]["fields_known"] is False and eps["none"]["fields_known"] is True


def test_unmeasured_build_is_listed_and_answers_unknown(ctx):
    lib.ingest(_doc())
    ok, _msg, _v = fv.declare("fortiweb", "8.0.9", note="coming")
    assert ok
    rows = {b["version"]: b for b in lib.builds("fortiweb")}
    assert rows["7.6.8"]["measured"] is True and rows["7.6.8"]["evidence"] == 1
    assert rows["8.0.9"]["measured"] is False
    assert rows["8.0.9"]["origin"] == "declared"
    assert "manual" in rows["8.0.9"]["declared_sources"]
    assert ApiLibBuild.query.filter_by(version="8.0.9").first() is None, \
        "a query must not write a build row"
    assert lib.endpoints_at("fortiweb", "8.0.9") == {}
    assert lib.fields_at("fortiweb", "admin", "8.0.9")["status"] == "unmeasured"


def test_builds_marks_fleet_versions_even_unmeasured(ctx):
    _appliance("live1", firmware="7.6.9")
    rows = {b["version"]: b for b in lib.builds("fortiweb")}
    assert rows["7.6.9"]["in_fleet"] is True and rows["7.6.9"]["measured"] is False


def test_removal_requires_both_builds_measured(ctx):
    lib.ingest(_doc(version="7.6.8", endpoints={"x": _ep("ok", {}), "y": _ep("ok", {})}))
    # 8.0.5 was measured, but never asked about x; it said no to y.
    lib.ingest(_doc(version="8.0.5", endpoints={"y": _ep("absent"), "z": _ep("ok", {})}))
    diff = lib.compare("fortiweb", "7.6.8", "8.0.5")
    assert [r["endpoint"] for r in diff["endpoints_removed"]] == ["y"]
    assert [r["endpoint"] for r in diff["endpoints_unknown"]] == ["x", "z"]
    assert diff["endpoints_added"] == []
    # And against a build nobody measured: nothing is "removed".
    diff = lib.compare("fortiweb", "7.6.8", "9.0.0")
    assert diff["endpoints_removed"] == [] and diff["target_measured"] is False
    assert {r["endpoint"] for r in diff["endpoints_unknown"]} == {"x", "y"}


def test_compare_fields_only_within_one_kind_of_evidence(ctx):
    lib.ingest(_doc(version="7.6.8", endpoints={"admin": _ep("ok", {"a": {}, "a_val": {}})}))
    lib.ingest(_doc(version="8.0.5", source="schema", device=None,
                    endpoints={"admin": _ep("ok", {"a": {}, "b": {}})}))
    diff = lib.compare("fortiweb", "7.6.8", "8.0.5")
    assert diff["endpoints"]["admin"]["unknown"] is True
    assert diff["totals"]["fields_removed"] == 0


def test_compare_detects_added_removed_retyped(ctx):
    lib.ingest(_doc(version="7.6.8", endpoints={"admin": _ep("ok", {
        "a": {"type": "str"}, "gone": {"type": "str"}, "t": {"type": "int"}})}))
    lib.ingest(_doc(version="8.0.5", endpoints={"admin": _ep("ok", {
        "a": {"type": "str"}, "new": {"type": "str"}, "t": {"type": "str"}})}))
    ep = lib.compare("fortiweb", "7.6.8", "8.0.5")["endpoints"]["admin"]
    assert ep["added"] == ["new"] and ep["removed"] == ["gone"]
    assert ep["retyped"] == [{"field": "t", "from": "int", "to": "str"}]


def test_field_map_turns_lost_plus_added_into_rename(ctx):
    lib.ingest(_doc(version="7.6.8", endpoints={"admin": _ep("ok", {"old-name": {}, "k": {}})}))
    lib.ingest(_doc(version="8.0.5", endpoints={"admin": _ep("ok", {"new-name": {}, "k": {}})}))
    before = lib.compare("fortiweb", "7.6.8", "8.0.5")["endpoints"]["admin"]
    assert before["removed"] == ["old-name"] and before["added"] == ["new-name"]
    db.session.add(ApiLibFieldMap(product="fortiweb", endpoint="admin",
                                  from_version="7.6.8", from_field="old-name",
                                  to_version="8.0.5", to_field="new-name", note="renamed"))
    db.session.commit()
    diff = lib.compare("fortiweb", "7.6.8", "8.0.5")
    assert "admin" not in diff["endpoints"] or not diff["endpoints"]["admin"]["removed"]
    assert diff["totals"]["fields_renamed"] == 1
    assert diff["endpoints"]["admin"]["renamed"] == [
        {"from": "old-name", "to": "new-name", "note": "renamed"}]
    back = lib.compare("fortiweb", "8.0.5", "7.6.8")["endpoints"]["admin"]
    assert back["renamed"][0] == {"from": "new-name", "to": "old-name", "note": "renamed"}


# --------------------------------------------------------------------------
# vendor spans
# --------------------------------------------------------------------------

def _fortigate_fixture():
    lib.ingest(_vendor_doc({
        "firewall_policy": {
            "urn": "/api/v2/cmdb/firewall/policy", "section": "firewall", "rows": None,
            "spans": [["6.0.0", ""]],
            "fields": {"name": {"type": "string", "spans": [["6.0.0", ""]]},
                       "old": {"type": "string", "spans": [["6.0.0", "6.2.0"]]},
                       "fresh": {"type": "integer", "spans": [["7.0.0", ""]]}}},
        "legacy_thing": {
            "urn": "/api/v2/cmdb/legacy/thing", "section": "legacy", "rows": None,
            "spans": [["6.0.0", "6.2.0"]], "fields": {"a": {"type": "string"}}},
    }, ["6.0.0", "6.2.0", "7.0.0"]))


def test_vendor_spans_resolve_per_build(ctx):
    _fortigate_fixture()
    assert ApiLibSpan.query.count() > 0
    assert ApiLibEndpointFact.query.count() == 0, "vendor ranges are never expanded per build"
    at62 = lib.fields_at("fortigate", "firewall_policy", "6.2.0")
    assert at62["status"] == "measured" and set(at62["fields"]) == {"name", "old"}
    at70 = lib.fields_at("fortigate", "firewall_policy", "7.0.0")
    assert set(at70["fields"]) == {"name", "fresh"}
    # A build between samples is inside the vendor's range.
    at64 = lib.fields_at("fortigate", "firewall_policy", "6.4.3")
    assert set(at64["fields"]) == {"name"}
    eps = lib.endpoints_at("fortigate", "7.0.0")
    assert eps["firewall_policy"]["verdict"] == "ok"
    assert eps["legacy_thing"]["verdict"] == "absent"
    assert eps["firewall_policy"]["vendor_only"] is True
    diff = lib.compare("fortigate", "6.2.0", "7.0.0")
    assert [r["endpoint"] for r in diff["endpoints_removed"]] == ["legacy_thing"]
    assert diff["endpoints"]["firewall_policy"]["added"] == ["fresh"]
    assert diff["endpoints"]["firewall_policy"]["removed"] == ["old"]


def test_open_vendor_range_is_capped_at_max_version(ctx):
    """7.2.0 is newer than anything the collection knew: unmeasured, not ok."""
    _fortigate_fixture()
    assert lib.endpoints_at("fortigate", "7.2.0") == {}
    assert lib.fields_at("fortigate", "firewall_policy", "7.2.0")["status"] == "unmeasured"
    assert lib.resolve_appliance(SimpleNamespace(
        kind="fortigate", name="fg", fw_version="7.2.0", firmware=""))["status"] == "unmeasured"
    assert lib.resolve_appliance(SimpleNamespace(
        kind="fortigate", name="fg", fw_version="7.0.0", firmware=""))["status"] == "vendor_only"
    ev = ApiLibEvidence.query.filter_by(source="vendor_doc").one()
    assert ev.summary["max_version"] == "7.0.0"
    rows = {b["version"]: b for b in lib.builds("fortigate")}
    assert rows["7.0.0"]["vendor_only"] is True and rows["7.0.0"]["origin"] == "vendor"


def test_newer_vendor_collection_supersedes_older(ctx):
    _fortigate_fixture()
    lib.ingest(_vendor_doc({
        "firewall_policy": {"urn": "/api/v2/cmdb/firewall/policy", "section": "firewall",
                            "rows": None, "spans": [["6.0.0", ""]],
                            "fields": {"name": {"type": "string", "spans": [["6.0.0", "6.4.0"]]}}},
    }, ["6.0.0", "6.4.0", "7.4.0"], origin="ansible:fortinet.fortios:2.0.0"))
    at70 = lib.fields_at("fortigate", "firewall_policy", "7.0.0")
    assert at70["fields"] == {}, "the newer collection says name ended at 6.4.0"
    assert lib.endpoints_at("fortigate", "7.4.0")["firewall_policy"]["verdict"] == "ok"


def test_sweep_outranks_vendor_claim(ctx):
    lib.ingest(_vendor_doc({"thing": {"urn": "/u", "section": "s", "rows": None,
                                      "spans": [["7.0.0", ""]], "fields": {"a": {}}}},
                           ["7.0.0", "7.2.0"], product="fortianalyzer"))
    lib.ingest(_doc(product="fortianalyzer", version="7.2.0",
                    endpoints={"thing": _ep("absent")}))
    assert lib.endpoints_at("fortianalyzer", "7.2.0")["thing"]["verdict"] == "absent"
    assert lib.fields_at("fortianalyzer", "thing", "7.2.0")["status"] == "absent"


def test_field_history_covers_facts_and_vendor_spans(ctx):
    _fortigate_fixture()
    h = lib.field_history("fortigate", "firewall_policy", "old")
    assert h["known"] and h["first_build"] == "6.0.0" and h["last_build"] == "6.2.0"
    assert h["sources"] == ["vendor_doc"]
    lib.ingest(_doc(version="7.6.8"))
    lib.ingest(_doc(version="8.0.5"))
    h = lib.field_history("fortiweb", "admin", "access")
    assert [b["version"] for b in h["builds"]] == ["7.6.8", "8.0.5"]
    assert lib.field_history("fortiweb", "admin", "nope")["known"] is False


def test_products_lists_every_product_and_fortigate_is_catalog_only(ctx):
    rows = {p["product"]: p for p in lib.products()}
    assert set(lib.PRODUCTS) <= set(rows)
    assert rows["fortigate"]["catalog_only"] is True
    assert rows["fortiweb"]["catalog_only"] is False


def test_resolve_appliance_statuses(ctx):
    lib.ingest(_doc())
    ap = SimpleNamespace(kind="fortiweb", name="fwA", fw_version="",
                         firmware="FortiWeb-KVM 7.6.8,build1128(GA.M)")
    res = lib.resolve_appliance(ap)
    assert res["status"] == "measured" and res["build"]["version"] == "7.6.8"
    ap.firmware = "7.6.9"
    assert lib.resolve_appliance(ap)["status"] == "unmeasured"
    ap.firmware = ""
    assert lib.resolve_appliance(ap)["status"] == "unknown_firmware"


# --------------------------------------------------------------------------
# matrix_doc
# --------------------------------------------------------------------------

def test_retired_device_evidence_stays_in_matrix_doc(ctx):
    live = _appliance("fw-live", firmware="7.6.8")
    lib.ingest(_doc(version="7.6.8", device="fw-live", appliance_id=live.id))
    lib.ingest(_doc(version="8.0.3", device="fw-gone", appliance_id=9999,
                    endpoints={"only_803": _ep("ok", {"f": {}})}))
    doc = lib.matrix_doc("fortiweb")
    assert "8.0.3" in doc["versions"], "a deleted appliance's evidence must survive"
    assert doc["versions"]["8.0.3"]["devices"] == ["fw-gone"]
    wit = {w["id"]: w for w in doc["witnesses"]}
    assert wit[9999]["retired"] is True and wit[9999]["name"] == "fw-gone"
    assert wit[live.id]["retired"] is False
    assert doc["fleet_versions"] == ["7.6.8"]
    assert doc["versions"]["7.6.8"]["in_fleet"] is True
    assert doc["versions"]["8.0.3"]["in_fleet"] is False


def _keys_match(a: dict, b: dict, where: str, extra=()):
    assert set(a) <= set(b), "%s: library lacks %s" % (where, sorted(set(a) - set(b)))
    assert set(b) - set(a) <= set(extra), "%s: unexpected %s" % (where, sorted(set(b) - set(a)))


def test_matrix_doc_has_the_api_matrix_shape(ctx, tmp_path, monkeypatch):
    red, sch = tmp_path / "rediscovery", tmp_path / "field_schemas"
    red.mkdir()
    sch.mkdir()
    monkeypatch.setattr(am, "REDISCOVERY_ROOT", str(red))
    monkeypatch.setattr(am, "SCHEMA_ROOT", str(sch))
    a1 = _appliance("fw1", firmware="7.6.8")
    a2 = _appliance("fw2", firmware="7.6.9")
    for ap, fw in ((a1, "7.6.8"), (a2, "7.6.9")):
        d = red / str(ap.id)
        d.mkdir()
        (d / "_config.json").write_text(json.dumps({
            "device": ap.name, "appliance_id": ap.id, "firmware": fw,
            "generated_at": "2026-09-01T00:00:00",
            "endpoint_status": {
                "admin": {"urn": "/api/v2.0/cmdb/system/admin", "section": "S",
                          "verdict": "ok", "rows": 1},
                "ntp": {"urn": "/api/v2.0/cmdb/system/ntp", "section": "S",
                        "verdict": "ok" if fw == "7.6.9" else "absent", "rows": 0},
                "empty": {"urn": "/api/v2.0/cmdb/e", "section": "S", "verdict": "ok",
                          "rows": 0}},
            "sections": {"S": {"admin": [{"name": "x", "access": "rw"}]}}}))
    ln = sch / "fortiweb" / "7.6"
    ln.mkdir(parents=True)
    (ln / "admin.json").write_text(json.dumps({
        "object": "admin", "endpoint": "system_admin", "source": "live:fw1@7.6",
        "generated_at": "2026-06-28", "fields": [{"name": "name"}, {"name": "access"}]}))

    old = am.build("fortiweb")
    lib.backfill(str(tmp_path))
    new = lib.matrix_doc("fortiweb")

    _keys_match(old, new, "top")
    assert sorted(old["versions"]) == sorted(new["versions"]) == ["7.6.8", "7.6.9"]
    assert sorted(old["lines"]) == sorted(new["lines"]) == ["7.6"]
    for v in old["versions"]:
        o, n = old["versions"][v], new["versions"][v]
        _keys_match(o, n, "versions[%s]" % v)
        _keys_match(o["counts"], n["counts"], "versions[%s].counts" % v)
        assert o["counts"] == n["counts"]
        assert sorted(o["endpoints"]) == sorted(n["endpoints"])
        for e in o["endpoints"]:
            _keys_match(o["endpoints"][e], n["endpoints"][e], "versions[%s].%s" % (v, e))
            for k in ("verdict", "fields", "urn", "section", "origin", "devices"):
                assert o["endpoints"][e][k] == n["endpoints"][e][k], (v, e, k)
        assert sorted(o["objects"]) == sorted(n["objects"])
        for obj in o["objects"]:
            _keys_match(o["objects"][obj], n["objects"][obj], "objects[%s]" % obj)
            assert o["objects"][obj]["fields"] == n["objects"][obj]["fields"]
            assert n["objects"][obj]["granularity"] == "line"
    lo, lnw = old["lines"]["7.6"], new["lines"]["7.6"]
    _keys_match(lo, lnw, "lines[7.6]")
    _keys_match(lo["counts"], lnw["counts"], "lines[7.6].counts")
    assert lo["counts"] == lnw["counts"]
    assert lo["partial_endpoints"] == lnw["partial_endpoints"]
    for e in lo["endpoints"]:
        _keys_match(lo["endpoints"][e], lnw["endpoints"][e], "lines.%s" % e)
        assert lo["endpoints"][e]["attested_on"] == lnw["endpoints"][e]["attested_on"]
    for obj in lo["objects"]:
        _keys_match(lo["objects"][obj], lnw["objects"][obj], "lines.objects[%s]" % obj)
    for w_old, w_new in zip(old["witnesses"], new["witnesses"]):
        _keys_match(w_old, w_new, "witness", extra=("retired", "live"))
    assert old["fleet_versions"] == new["fleet_versions"]
    assert old["fleet_lines"] == new["fleet_lines"]
    # Existing consumers keep working on the library document.
    d = am.diff("fortiweb", "7.6.8", "7.6.9", matrix=new)
    assert [r["endpoint"] for r in d["endpoints_added"]] == ["ntp"]
    assert am.preflight("fortiweb", "7.6.8", "admin", ["name"], matrix=new)["status"] == "ok"


def test_matrix_doc_versions_filter(ctx):
    lib.ingest(_doc(version="7.6.8"))
    lib.ingest(_doc(version="8.0.5"))
    doc = lib.matrix_doc("fortiweb", versions=["8.0.5"])
    assert list(doc["versions"]) == ["8.0.5"] and list(doc["lines"]) == ["8.0"]


# --------------------------------------------------------------------------
# performance shape: a few statements per build, whatever the size
# --------------------------------------------------------------------------

def test_large_vendor_document_is_fast_and_queries_are_constant(ctx):
    versions = ["6.0.0", "6.2.0", "6.4.0", "7.0.0", "7.2.0", "7.4.0"]
    eps = {}
    for i in range(200):
        fields = {"f%d" % j: {"type": "string",
                              "spans": [["6.0.0", ""]] if j % 3 else [["6.0.0", "7.0.0"]]}
                  for j in range(60)}
        eps["ep%03d" % i] = {"urn": "/api/v2/cmdb/x/ep%d" % i, "section": "x",
                             "rows": None, "spans": [["6.0.0", ""]], "fields": fields}
    t0 = time.monotonic()
    lib.ingest(_vendor_doc(eps, versions))
    assert time.monotonic() - t0 < 30
    assert ApiLibSpan.query.count() == 200 * 61

    statements = []

    def _count(*_a, **_k):
        statements.append(1)

    engine = db.engine
    sa.event.listen(engine, "before_cursor_execute", _count)
    try:
        assert len(lib.endpoints_at("fortigate", "7.2.0")) == 200
        n_endpoints = len(statements)
        statements.clear()
        diff = lib.compare("fortigate", "6.4.0", "7.2.0")
        n_compare = len(statements)
        statements.clear()
        assert lib.fields_at("fortigate", "ep007", "7.2.0")["status"] == "measured"
        n_fields = len(statements)
    finally:
        sa.event.remove(engine, "before_cursor_execute", _count)
    assert diff["totals"]["fields_removed"] == 200 * 20
    assert n_endpoints <= 8 and n_fields <= 8 and n_compare <= 16, \
        (n_endpoints, n_fields, n_compare)


# --------------------------------------------------------------------------
# migration + model + CLI wiring
# --------------------------------------------------------------------------

def _migration():
    path = os.path.join(_ROOT, "migrations", "versions", "apilib01_api_library.py")
    spec = importlib.util.spec_from_file_location("apilib01", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_migration_chain_and_schema_match_models():
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    mod = _migration()
    assert mod.revision == "apilib01" and mod.down_revision == "upgtgt01"
    heads = []
    vdir = os.path.join(_ROOT, "migrations", "versions")
    for fname in os.listdir(vdir):
        if fname.endswith(".py"):
            with open(os.path.join(vdir, fname)) as fh:
                src = fh.read()
            if "down_revision = 'upgtgt01'" in src or 'down_revision = "upgtgt01"' in src:
                heads.append(fname)
    assert "apilib01_api_library.py" in heads

    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()
            mod.upgrade()   # idempotent: create_all may have been first
        insp = sa.inspect(conn)
        tables = set(insp.get_table_names())
        assert set(mod._TABLES) <= tables
        for t in mod._TABLES:
            model_cols = set(db.metadata.tables[t].columns.keys())
            mig_cols = {c["name"] for c in insp.get_columns(t)}
            assert model_cols == mig_cols, t
        with Operations.context(MigrationContext.configure(conn)):
            mod.downgrade()
        assert not set(mod._TABLES) & set(sa.inspect(conn).get_table_names())


def test_cli_status_and_ingest_file(ctx, tmp_path):
    path = tmp_path / "doc.json.gz"
    path.write_bytes(gzip.compress(json.dumps(_doc()).encode()))
    runner = ctx.test_cli_runner()
    res = runner.invoke(args=["apilib", "ingest-file", str(path)])
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)[0]["created"] is True
    res = runner.invoke(args=["apilib", "ingest-file", str(path)])
    assert json.loads(res.output)[0]["created"] is False
    res = runner.invoke(args=["apilib", "status"])
    assert res.exit_code == 0, res.output
    assert "fortiweb" in res.output and "7.6.8" in res.output


def test_cli_import_vendor_calls_the_adapter(ctx, tmp_path, monkeypatch):
    import app.services.apilib_vendor as vendor
    monkeypatch.setattr(vendor, "evidence_from_ansible_collection",
                        lambda p: [_vendor_doc({"a": {"urn": "/u", "section": "s", "rows": None,
                                                      "spans": [["7.0.0", ""]], "fields": {}}},
                                               ["7.0.0"])])
    res = ctx.test_cli_runner().invoke(args=["apilib", "import-vendor", str(tmp_path)])
    assert res.exit_code == 0, res.output
    assert ApiLibEvidence.query.filter_by(source="vendor_doc").count() == 1


def test_ingest_rejects_unknown_source(ctx):
    with pytest.raises(ValueError):
        lib.ingest(dict(_doc(), source="guess"))
