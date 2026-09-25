"""``version_compat`` reading the API LIBRARY (``services.api_library``).

The sibling ``test_version_compat.py`` states its evidence as a hand-built
matrix document; these guards state it as evidence documents ingested into
the library, which is where production reads it from. Same six verdicts, same
rules — plus the three things only the library carries: operator-authored
renames, provenance (measured vs vendor claim), and field specs for the
destination's new fields.
"""
from __future__ import annotations

from datetime import datetime

import pytest

from app.extensions import db
from app.models_apilib import ApiLibFieldMap
from app.services import api_library as lib
from app.services import version_compat as vc


@pytest.fixture()
def ctx(app):
    with app.app_context():
        yield app


def _ep(verdict="ok", fields=None, urn="/api/x"):
    return {"urn": urn, "section": "s", "verdict": verdict, "rows": None, "fields": fields}


def _sweep(version, endpoints, product="fortiweb", device="fwA"):
    return {"product": product, "source": "sweep", "captured_at": "2026-09-01T00:00:00",
            "origin_ref": "test:%s@%s" % (device, version),
            "device": {"appliance_id": None, "name": device, "serial": "", "model": "",
                       "hw_type": "vm", "firmware_raw": version},
            "scope": {"kind": "build", "version": version, "build": ""},
            "healthy": True, "skip_reason": "", "endpoints": endpoints}


def _f(*names, **specs):
    out = {n: {"type": "str"} for n in names}
    out.update(specs)
    return out


def _seed():
    lib.ingest(_sweep("7.6.8", {
        "widget": _ep(fields=_f("name", "old-only", "shared", "shared_val", "q_type",
                                "sz_rows", "legacy")),
        "goner": _ep(fields=_f("name", "x")),
        "blindspot": _ep(fields=None),
    }))
    lib.ingest(_sweep("8.0.5", {
        "widget": _ep(fields=_f("name", "shared", "shared_val", "q_type", "sz_rows",
                                "modern",
                                **{"brand-new": {"type": "str",
                                                 "options": ["enable", "disable"],
                                                 "default": "disable"}})),
        "goner": _ep("absent", None),
        "blindspot": _ep(fields=None),
    }))


def _rename(frm="legacy", to="modern", retired=False):
    db.session.add(ApiLibFieldMap(product="fortiweb", endpoint="widget",
                                  from_version="7.6.8", from_field=frm,
                                  to_version="8.0.5", to_field=to, note="doc",
                                  retired_at=datetime.utcnow() if retired else None))
    db.session.commit()


class _Appl:
    def __init__(self, name="box", fw="7.6.8", kind="fortiweb", ident=1):
        self.name, self.fw_version, self.kind, self.id = name, fw, kind, ident


# --------------------------------------------------------------------------
#  the six verdicts, from the library
# --------------------------------------------------------------------------
def test_the_default_evidence_is_the_library(ctx):
    _seed()
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["name"], source_version="7.6.8")
    assert r["evidence"] == "library"
    assert r["state"] == vc.STATE_OK


def test_same_build_is_same_and_not_ok(ctx):
    _seed()
    r = vc.compare_object("fortiweb", "7.6.8", "widget", ["name"], source_version="7.6.8")
    assert r["state"] == vc.STATE_SAME and r["level"] == "ok"


def test_a_field_the_target_never_showed_is_dropped(ctx):
    _seed()
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["name", "old-only"],
                          source_version="7.6.8")
    assert r["state"] == vc.STATE_DROPPED
    assert r["dropped"] == ["old-only"]
    assert "200" in r["reason"]


def test_an_endpoint_the_box_rejected_is_absent_and_blocks(ctx):
    _seed()
    rep = vc.compare_many("fortiweb", "8.0.5", [("goner", ["name"])], source_version="7.6.8")
    assert rep["rows"][0]["state"] == vc.STATE_ABSENT
    assert rep["level"] == "block"
    assert rep["absent_total"] == 1 and rep["dropped_total"] == 0


def test_an_empty_collection_is_blind_never_ok(ctx):
    _seed()
    r = vc.compare_object("fortiweb", "8.0.5", "blindspot", ["x"], source_version="7.6.8")
    assert r["state"] == vc.STATE_BLIND
    assert r["dropped"] == []


def test_an_unknown_build_is_unmeasured_and_not_answered_from_its_line(ctx):
    _seed()
    r = vc.compare_object("fortiweb", "8.0.6", "widget", ["name"], source_version="7.6.8")
    assert r["state"] == vc.STATE_UNMEASURED
    assert r["level"] == "warn"


def test_line_evidence_is_reported_beside_an_unmeasured_build_labelled(ctx):
    _seed()
    lib.ingest({"product": "fortiweb", "source": "schema", "captured_at": "2026-01-01",
                "origin_ref": "field_schemas:fortiweb/8.0", "device": None,
                "scope": {"kind": "line", "line": "8.0"}, "healthy": True,
                "skip_reason": "", "endpoints": {"widget": _ep(fields=_f("name"))}})
    r = vc.compare_object("fortiweb", "8.0.6", "widget", ["name"], source_version="7.6.8")
    assert r["state"] == vc.STATE_UNMEASURED        # the line is NOT the build
    assert r["line_hint"]["line"] == "8.0"
    assert r["line_hint"]["status"] == "measured"
    assert "not proof" in r["reason"]


def test_transport_echoes_are_stripped_and_reported(ctx):
    _seed()
    r = vc.compare_object("fortiweb", "8.0.5", "widget",
                          ["name", "shared", "shared_val", "q_type"], source_version="7.6.8")
    assert "shared_val" in r["ignored"] and "q_type" in r["ignored"]
    assert r["state"] == vc.STATE_OK


# --------------------------------------------------------------------------
#  provenance
# --------------------------------------------------------------------------
def test_a_measured_answer_says_which_evidence_it_used(ctx):
    _seed()
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["name"], source_version="7.6.8")
    assert r["claim"] == vc.CLAIM_MEASURED
    used = [p["source"] for p in r["provenance"]["target"] if p.get("used")]
    assert used == ["sweep"]


def _vendor_doc():
    return {"product": "fortigate", "source": "vendor_doc", "captured_at": "2026-01-01",
            "origin_ref": "ansible:fortinet.fortios:2.6.0", "device": None,
            "scope": {"kind": "spans", "versions": ["7.2.4", "7.4.0", "7.6.4"]},
            "healthy": True, "skip_reason": "",
            "summary": {"min_version": "7.2.4", "max_version": "7.6.4"},
            "endpoints": {
                "firewall_policy": {"urn": "/api/v2/cmdb/firewall/policy", "section": "firewall",
                                    "verdict": "ok", "rows": None, "spans": [["7.2.4", ""]],
                                    "fields": {"name": {"type": "string", "spans": [["7.2.4", ""]]},
                                               "old": {"type": "string", "spans": [["7.2.4", "7.4.0"]]},
                                               "fresh": {"type": "string", "options": ["enable", "disable"],
                                                         "spans": [["7.6.4", ""]]}}},
                "firewall_legacy": {"urn": "/api/v2/cmdb/firewall/legacy", "section": "firewall",
                                    "verdict": "ok", "rows": None, "spans": [["7.2.4", "7.4.0"]],
                                    "fields": {"name": {"type": "string", "spans": [["7.2.4", "7.4.0"]]}}},
            }}


def test_a_vendor_only_answer_is_labelled_a_claim(ctx):
    lib.ingest(_vendor_doc())
    r = vc.compare_object("fortigate", "7.6.4", "firewall_policy", ["name", "old"],
                          source_version="7.2.4")
    assert r["claim"] == vc.CLAIM_VENDOR
    assert r["state"] == vc.STATE_DROPPED and r["dropped"] == ["old"]
    assert "vendor documentation claims" in r["reason"]
    assert r["new_fields"] == ["fresh"]
    assert r["new_field_specs"]["fresh"]["claim"] == vc.CLAIM_VENDOR
    assert r["new_field_specs"]["fresh"]["options"] == ["enable", "disable"]


def test_a_vendor_claimed_absence_warns_and_never_blocks(ctx):
    """Only the APPLIANCE saying "I do not serve this URN" blocks."""
    lib.ingest(_vendor_doc())
    rep = vc.compare_many("fortigate", "7.6.4", [("firewall_legacy", ["name"])],
                          source_version="7.2.4")
    row = rep["rows"][0]
    assert row["state"] == vc.STATE_ABSENT and row["claim"] == vc.CLAIM_VENDOR
    assert row["level"] == "warn"
    assert rep["level"] == "warn"
    assert rep["claims"] == {vc.CLAIM_VENDOR: 1}


# --------------------------------------------------------------------------
#  new fields — with specs from the library
# --------------------------------------------------------------------------
def test_new_fields_carry_type_options_and_default(ctx):
    _seed()
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["name", "shared"],
                          source_version="7.6.8")
    assert r["new_fields_state"] == "measured"
    assert "brand-new" in r["new_fields"]
    spec = r["new_field_specs"]["brand-new"]
    assert spec["options"] == ["enable", "disable"] and spec["default"] == "disable"
    assert spec["claim"] == vc.CLAIM_MEASURED


def test_gains_across_different_kinds_of_evidence_are_unknown_not_invented(ctx):
    """A sweep carries wire noise a schema strips; subtracting one from the
    other is how 56 phantom changes were once reported."""
    lib.ingest(_sweep("8.0.5", {"only": _ep(fields=_f("a", "b", "c"))}))
    lib.ingest({"product": "fortiweb", "source": "schema", "captured_at": "2026-01-01",
                "origin_ref": "field_schemas:fortiweb/7.6.8", "device": None,
                "scope": {"kind": "build", "version": "7.6.8", "build": ""},
                "healthy": True, "skip_reason": "",
                "endpoints": {"only": _ep(fields=_f("a"))}})
    r = vc.compare_object("fortiweb", "8.0.5", "only", ["a"], source_version="7.6.8")
    assert r["new_fields"] == []
    assert r["new_fields_state"] == "unmeasured"
    assert "different kinds of evidence" in r["new_fields_reason"]


# --------------------------------------------------------------------------
#  renames
# --------------------------------------------------------------------------
def test_a_mapped_rename_is_reported_as_renamed_not_dropped_plus_new(ctx):
    _seed()
    _rename()
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["name", "legacy"],
                          source_version="7.6.8")
    assert r["dropped"] == []
    assert r["renamed"] == [{"from": "legacy", "to": "modern", "note": "doc"}]
    assert "modern" not in r["new_fields"]
    assert r["new_field_specs"]["modern"]["renamed_from"] == "legacy"
    assert r["state"] == vc.STATE_OK
    rep = vc.compare_many("fortiweb", "8.0.5", [("widget", ["name", "legacy"])],
                          source_version="7.6.8")
    assert rep["renamed_total"] == 1 and rep["dropped_total"] == 0


def test_without_the_mapping_the_same_rename_reads_as_lost_plus_added(ctx):
    _seed()
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["name", "legacy"],
                          source_version="7.6.8")
    assert r["dropped"] == ["legacy"]
    assert "modern" in r["new_fields"]


def test_a_retired_mapping_is_not_honoured(ctx):
    _seed()
    _rename(retired=True)
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["name", "legacy"],
                          source_version="7.6.8")
    assert r["renamed"] == [] and r["dropped"] == ["legacy"]
    assert lib.compare("fortiweb", "7.6.8", "8.0.5")["totals"]["fields_renamed"] == 0


def test_a_rename_whose_new_name_the_target_does_not_serve_is_still_dropped(ctx):
    _seed()
    _rename(to="nowhere")
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["legacy"], source_version="7.6.8")
    assert r["dropped"] == ["legacy"] and r["renamed"] == []


# --------------------------------------------------------------------------
#  adapters: exact builds via resolve_appliance, offline, unreadable library
# --------------------------------------------------------------------------
def test_for_clone_resolves_both_boxes_to_their_exact_builds(ctx):
    _seed()
    rep = vc.for_clone(_Appl("src", "7.6.8,build1128"), _Appl("dst", "8.0.5 build0099", ident=2),
                       [("widget", ["name", "old-only"])])
    assert (rep["source_version"], rep["target_version"]) == ("7.6.8", "8.0.5")
    assert rep["target_status"] == "measured" and rep["source_status"] == "measured"
    assert rep["dropped_total"] == 1


def test_for_upgrade_needs_no_device_only_the_library(ctx):
    _seed()
    rep = vc.for_upgrade(_Appl("box", "7.6.8"), "8.0.5",
                         [("widget", ["name", "old-only"]), ("goner", ["name"])])
    assert rep["absent_total"] == 1 and rep["dropped_total"] == 1


def test_an_unreadable_library_is_unmeasured_never_compatible():
    """No app context at all: every read fails. The answer is 'not measured',
    with the reason, never 'ok'."""
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["name"], source_version="7.6.8")
    assert r["state"] == vc.STATE_UNMEASURED
    assert "could not be read" in r["reason"]


# --------------------------------------------------------------------------
#  the offer
# --------------------------------------------------------------------------
def test_offer_lists_gains_and_rename_targets_independent_of_payload(ctx):
    _seed()
    _rename()
    off = vc.offer("fortiweb", "7.6.8", "8.0.5", "widget")
    assert set(off) == {"brand-new", "modern"}
    assert off["modern"]["renamed_from"] == "legacy"


def test_offer_is_empty_for_the_same_build_and_for_an_unmeasured_target(ctx):
    _seed()
    assert vc.offer("fortiweb", "8.0.5", "8.0.5", "widget") == {}
    assert vc.offer("fortiweb", "7.6.8", "8.0.6", "widget") == {}
    assert vc.offer("fortiweb", "7.6.8", "8.0.5", "blindspot") == {}


def test_an_open_ended_mapping_offers_nothing_on_the_same_build(ctx):
    """A mapping with no builds applies to every comparison — including one
    that is not an upgrade at all. Same build, nothing to offer."""
    _seed()
    db.session.add(ApiLibFieldMap(product="fortiweb", endpoint="widget",
                                  from_field="name", to_field="modern"))
    db.session.commit()
    assert vc.offer("fortiweb", "8.0.5", "8.0.5", "widget") == {}
    assert "modern" in vc.offer("fortiweb", "7.6.8", "8.0.5", "widget")
