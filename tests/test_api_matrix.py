"""Guards for the firmware-line API matrix (services/api_matrix.py).

Every failure this file covers is silent. A matrix that stops telling
"measured and absent" apart from "never measured" still renders a full page,
still fills a table and still answers a preflight — it just answers wrong, and
the caller's next move is a write to a production appliance.

Live grounding for the constants (2026-08-13, this fleet's own artifacts):
  * fortiweb09/10 run 7.6.8 → line ``7.6``; fortiadc02/03 run 8.0.3 → ``8.0``
  * fortiweb08 answers ``-20010`` (peer VM licence) to 283 of 321 CMDB reads
    while the inventory still calls it ``online``
  * schema evidence, 7.6 → 8.0: ``admin`` 40 → 42 (+fortiai, +old-password),
    ``global`` 60 → 63, ``ntp`` 3 → 4. This is the whole reason the module
    exists: same api_version (v2.0), different fields.
  * comparing a SWEEP field set against a SCHEMA field set reported 56 phantom
    removals — the sweep carries FortiWeb's ``_val``/``sz_`` companions that
    the schema harvester strips on purpose.
"""
from __future__ import annotations

import ast
import io
import json
import os

import pytest

from app.extensions import db
from app.models import Appliance
from app.services import api_matrix as am
from tests.conftest import admin_user_id, login, make_user


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

@pytest.fixture()
def isolated(app, session, tmp_path, monkeypatch):
    """Redirect BOTH evidence roots and the store.

    Without this a test writes into the live node's ``data/`` and the real
    API-versions page starts reporting fixtures as fleet evidence.
    """
    red = tmp_path / "rediscovery"
    sch = tmp_path / "field_schemas"
    mat = tmp_path / "api_matrix"
    for p in (red, sch, mat):
        p.mkdir()
    monkeypatch.setattr(am, "REDISCOVERY_ROOT", str(red))
    monkeypatch.setattr(am, "SCHEMA_ROOT", str(sch))
    monkeypatch.setattr(am, "MATRIX_ROOT", str(mat))
    return {"rediscovery": red, "field_schemas": sch, "api_matrix": mat}


def _appliance(name, kind="fortiweb", firmware="7.6.8", host=None,
               maintenance=False):
    a = Appliance(name=name, kind=kind, host=host or f"{name}.test", port=443,
                  username="admin", verify_ssl=False, maintenance=maintenance,
                  firmware=firmware)
    a.password = "secret"
    db.session.add(a)
    db.session.commit()
    return a


def _snapshot(isolated, appliance, ledger, sections=None, firmware="7.6.8",
              generated_at="2099-01-01T00:00:00"):
    d = isolated["rediscovery"] / str(appliance.id)
    d.mkdir(parents=True, exist_ok=True)
    (d / "_config.json").write_text(json.dumps({
        "device": appliance.name, "appliance_id": appliance.id,
        "generated_at": generated_at, "firmware": firmware,
        "endpoint_status": ledger, "sections": sections or {},
    }))


def _schema(isolated, product, line, obj, fields, endpoint=None):
    d = isolated["field_schemas"] / product / line
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{obj}.json").write_text(json.dumps({
        "object": obj, "endpoint": endpoint or obj, "label": obj,
        "product": product, "line": line, "source": f"live:test@{line}",
        "fields": [{"name": f} for f in fields],
    }))


def _ok(n=1):
    return {"verdict": "ok", "rows": n, "urn": "/api/v2.0/cmdb/x", "section": "s",
            "detail": ""}


def _absent():
    return {"verdict": "absent", "rows": 0, "urn": "/api/v2.0/cmdb/x",
            "section": "s", "detail": "-20001"}


def _error():
    return {"verdict": "error", "rows": 0, "urn": "/api/v2.0/cmdb/x",
            "section": "s", "detail": "-20010"}


# --------------------------------------------------------------------------
# firmware_line — the granularity the whole module is keyed on
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("7.6.8", "7.6"),
    ("FortiWeb-KVM 7.6.8,build1128(GA.M),260602", "7.6"),
    ("8.0.3 build0093,260401", "8.0"),
    ("8.0", "8.0"),
    ("", ""),
    (None, ""),
    ("no digits here", ""),
])
def test_firmware_line_is_major_minor(raw, expected):
    assert am.firmware_line(raw) == expected


def test_patch_releases_collapse_onto_one_line():
    """7.6.8 and 7.6.9 must be the SAME line.

    Keying by the full version would give every build its own column of
    one-device evidence that never accumulates, and every patch release would
    reset the fleet to "unmeasured".
    """
    assert am.firmware_line("7.6.8") == am.firmware_line("7.6.9")


# --------------------------------------------------------------------------
# RULE 1 — ``fields=None`` is not ``fields=[]``
# --------------------------------------------------------------------------

def test_ok_with_zero_rows_leaves_fields_unknown(app, isolated):
    """An endpoint that exists but returned an empty collection says NOTHING
    about its fields. Recording ``[]`` would make the diff invent a removal of
    every field of that object on the other line."""
    a = _appliance("fw09")
    _snapshot(isolated, a, {"vips": _ok(0)}, sections={})
    m = am.build("fortiweb")
    rec = m["lines"]["7.6"]["endpoints"]["vips"]
    assert rec["verdict"] == "ok"
    assert rec["fields"] is None, "empty collection must not mint an empty field set"


def test_rows_with_keys_do_mint_a_field_set(app, isolated):
    a = _appliance("fw09")
    _snapshot(isolated, a, {"vips": _ok(2)},
              sections={"s": {"vips": [{"name": "a", "ip": "1.2.3.4"},
                                       {"name": "b", "port": 443}]}})
    rec = am.build("fortiweb")["lines"]["7.6"]["endpoints"]["vips"]
    assert rec["fields"] == ["ip", "name", "port"]


def test_unknown_fields_never_become_a_removal(app, isolated):
    """The diff of (known 3 fields) against (never measured) is UNKNOWN."""
    a = _appliance("fw09")
    _snapshot(isolated, a, {"vips": _ok(1)},
              sections={"s": {"vips": [{"a": 1, "b": 2, "c": 3}]}})
    b = _appliance("fadc-ish", kind="fortiweb", firmware="8.0.1")
    _snapshot(isolated, b, {"vips": _ok(0)}, sections={}, firmware="8.0.1")
    d = am.diff("fortiweb", "7.6", "8.0")
    assert d["totals"]["fields_removed"] == 0
    assert [u["key"] for u in d["fields_unknown"]] == ["vips"]


# --------------------------------------------------------------------------
# RULE 2 — an unmeasured line is never "compatible"
# --------------------------------------------------------------------------

def test_preflight_on_an_unknown_line_is_unmeasured(app, isolated):
    _appliance("fw09")
    am.rebuild("fortiweb")
    out = am.preflight("fortiweb", "9.9", "admin", ["anything"])
    assert out["status"] == am.STATUS_UNMEASURED
    assert out["status"] != am.STATUS_OK
    assert out["unknown"] == []


def test_preflight_flags_a_field_the_line_does_not_have(app, isolated):
    """The scenario the module exists for: an 8.0 payload aimed at a 7.6 box."""
    _appliance("fw09")
    _schema(isolated, "fortiweb", "7.6", "admin", ["name", "password", "trusthost1"])
    _schema(isolated, "fortiweb", "8.0", "admin",
            ["name", "password", "trusthost1", "fortiai", "old-password"])
    out = am.preflight("fortiweb", "7.6", "admin", ["name", "fortiai", "old-password"])
    assert out["status"] == am.STATUS_UNKNOWN_FIELDS
    assert out["unknown"] == ["fortiai", "old-password"]
    assert out["known"] == ["name"]
    # …and the same payload is fine on the line it was built for.
    assert am.preflight("fortiweb", "8.0", "admin",
                        ["name", "fortiai", "old-password"])["status"] == am.STATUS_OK


def test_preflight_statuses_are_all_distinguishable(app, isolated):
    """Five outcomes, five names, asserted CASE BY CASE.

    The first version of this test compared the *set* of statuses against the
    set of names, and a mutation that made a never-measured endpoint answer
    ``ok`` survived it: another case in the same batch was already producing
    ``unmeasured``, so the union never changed. A set assertion cannot see
    which input produced which output — which is the only thing that matters
    when the outputs mean "go ahead" and "you have no evidence".
    """
    a = _appliance("fw09")
    _snapshot(isolated, a, {"gone": _absent(), "empty": _ok(0), "full": _ok(1)},
              sections={"s": {"full": [{"x": 1}]}})
    _schema(isolated, "fortiweb", "7.6", "admin", ["name"])
    cases = [
        ("9.9", "admin", ["x"], am.STATUS_UNMEASURED, "line with no evidence"),
        ("7.6", "nope", ["x"], am.STATUS_UNMEASURED, "endpoint never measured"),
        ("7.6", "gone", ["x"], am.STATUS_ABSENT, "endpoint the line rejects"),
        ("7.6", "empty", ["x"], am.STATUS_FIELDS_UNKNOWN, "exists, no rows seen"),
        ("7.6", "full", ["x"], am.STATUS_OK, "field is present"),
        ("7.6", "full", ["nope"], am.STATUS_UNKNOWN_FIELDS, "field is not present"),
    ]
    for line, key, fields, expected, why in cases:
        got = am.preflight("fortiweb", line, key, fields)["status"]
        assert got == expected, f"{why}: expected {expected}, got {got}"


def test_a_never_measured_endpoint_is_not_ok(app, isolated):
    """Split out from the case table above so this specific collapse — the one
    that reads 'yes, write it' about an endpoint nobody ever probed — has a
    test that fails alone."""
    a = _appliance("fw09")
    _snapshot(isolated, a, {"known": _ok(1)}, sections={"s": {"known": [{"x": 1}]}})
    out = am.preflight("fortiweb", "7.6", "never-probed", ["x"])
    assert out["status"] == am.STATUS_UNMEASURED
    assert out["status"] != am.STATUS_OK
    assert "never measured" in out["reason"]


def test_preflight_for_appliance_without_firmware_is_unmeasured(app, isolated):
    a = _appliance("mystery", firmware="")
    out = am.preflight_for_appliance(a, "admin", ["name"])
    assert out["status"] == am.STATUS_UNMEASURED
    assert "no known firmware" in out["reason"]


# --------------------------------------------------------------------------
# RULE 3 — present-here / unknown-there is UNKNOWN, never a change
# --------------------------------------------------------------------------

def test_endpoint_measured_on_one_line_only_is_not_an_addition(app, isolated):
    a = _appliance("fw09")
    _snapshot(isolated, a, {"only76": _ok(1)}, sections={"s": {"only76": [{"k": 1}]}})
    b = _appliance("fw80", firmware="8.0.1")
    _snapshot(isolated, b, {"other": _ok(1)}, sections={"s": {"other": [{"k": 1}]}},
              firmware="8.0.1")
    d = am.diff("fortiweb", "7.6", "8.0")
    assert d["endpoints_added"] == []
    assert d["endpoints_removed"] == []
    assert {u["endpoint"] for u in d["endpoints_unknown"]} == {"only76", "other"}


def test_an_error_on_the_base_line_is_not_an_addition(app, isolated):
    """``error`` is a statement about the APPLIANCE, never about the firmware.

    Only an explicit ``absent`` on the base line can turn "served on the
    target" into "added by the target". Without that check a transient
    transport failure on one box would be published as a firmware feature —
    which is the same conflation §81 exists to prevent, one layer up.
    """
    a = _appliance("fw09")
    ledger = {f"o{i}": _ok(1) for i in range(90)}
    ledger["flaky"] = _error()
    _snapshot(isolated, a, ledger)
    b = _appliance("fw80", firmware="8.0.1")
    _snapshot(isolated, b, {"flaky": _ok(1)},
              sections={"s": {"flaky": [{"k": 1}]}}, firmware="8.0.1")
    d = am.diff("fortiweb", "7.6", "8.0")
    assert d["endpoints_added"] == [], \
        "an errored read must not be published as a firmware difference"


def test_absent_on_one_line_and_served_on_the_other_IS_a_change(app, isolated):
    a = _appliance("fw09")
    _snapshot(isolated, a, {"newfeat": _absent()})
    b = _appliance("fw80", firmware="8.0.1")
    _snapshot(isolated, b, {"newfeat": _ok(1)},
              sections={"s": {"newfeat": [{"k": 1}]}}, firmware="8.0.1")
    d = am.diff("fortiweb", "7.6", "8.0")
    assert [e["endpoint"] for e in d["endpoints_added"]] == ["newfeat"]
    assert d["endpoints_removed"] == []


# --------------------------------------------------------------------------
# cross-origin comparison — the 56 phantom removals
# --------------------------------------------------------------------------

def test_sweep_vs_schema_is_incomparable_not_a_delta(app, isolated):
    """A sweep field set carries FortiWeb's ``_val`` companions; the harvested
    schema strips them on purpose. Subtracting one from the other reported 56
    removed fields for 7.6 → 8.0 that were nothing but that filter."""
    a = _appliance("fw09")
    _snapshot(isolated, a, {"ntp": _ok(1)},
              sections={"s": {"ntp": [{"ntpsync": "enable", "ntpsync_val": 1,
                                       "sz_ntpserver": 2, "syncinterval": 60,
                                       "mode": "x"}]}})
    _schema(isolated, "fortiweb", "8.0", "ntp", ["mode", "ntpServer", "timeZone",
                                                 "daylightSaving"])
    d = am.diff("fortiweb", "7.6", "8.0")
    assert d["fields_changed"] == [], "cross-origin sets must never be subtracted"
    assert [c["key"] for c in d["fields_incomparable"]] == ["ntp"]
    assert d["totals"]["fields_removed"] == 0


def test_same_origin_delta_is_computed_and_labelled(app, isolated):
    _appliance("fw09")
    _schema(isolated, "fortiweb", "7.6", "admin", ["name", "password"])
    _schema(isolated, "fortiweb", "8.0", "admin",
            ["name", "password", "fortiai", "old-password"])
    d = am.diff("fortiweb", "7.6", "8.0")
    assert len(d["fields_changed"]) == 1
    c = d["fields_changed"][0]
    assert c["origin"] == "schema"
    assert c["added"] == ["fortiai", "old-password"]
    assert c["removed"] == []
    assert d["totals"]["fields_added"] == 2


def test_both_origins_present_compares_each_kind_separately(app, isolated):
    """When both lines have both kinds, each kind is compared to its own kind —
    never sweep-here against schema-there."""
    a = _appliance("fw09")
    _snapshot(isolated, a, {"admin": _ok(1)},
              sections={"s": {"admin": [{"name": 1, "q_ref": 2}]}})
    b = _appliance("fw80", firmware="8.0.1")
    _snapshot(isolated, b, {"admin": _ok(1)},
              sections={"s": {"admin": [{"name": 1, "q_ref": 2, "fortiai": 3}]}},
              firmware="8.0.1")
    _schema(isolated, "fortiweb", "7.6", "admin", ["name"])
    _schema(isolated, "fortiweb", "8.0", "admin", ["name", "fortiai"])
    d = am.diff("fortiweb", "7.6", "8.0")
    origins = sorted(c["origin"] for c in d["fields_changed"])
    assert origins == ["schema", "sweep"]
    for c in d["fields_changed"]:
        assert c["added"] == ["fortiai"]
        assert c["removed"] == []


# --------------------------------------------------------------------------
# witnesses — the appliance TABLE, and only healthy ones
# --------------------------------------------------------------------------

def test_snapshot_of_a_deleted_appliance_is_ignored(app, isolated):
    """Half of ``data/rediscovery/`` belongs to appliances that no longer
    exist. A firmware claim justified by a device nobody can re-probe is a
    claim nobody can reproduce."""
    ghost = isolated["rediscovery"] / "999"
    ghost.mkdir()
    (ghost / "_config.json").write_text(json.dumps({
        "device": "ghost", "appliance_id": 999, "firmware": "9.9.9",
        "generated_at": "2099-01-01T00:00:00",
        "endpoint_status": {"x": _ok(1)}, "sections": {},
    }))
    assert am.build("fortiweb")["lines"] == {}


def test_unhealthy_witness_is_excluded_with_a_reason(app, isolated):
    """fortiweb08: 283/321 errors while the inventory calls it online. Read
    naively it would attribute 283 phantom absences to the 7.6 line."""
    sick = _appliance("fw08")
    ledger = {f"e{i}": _error() for i in range(283)}
    ledger.update({f"o{i}": _absent() for i in range(38)})
    _snapshot(isolated, sick, ledger)
    m = am.build("fortiweb")
    assert m["lines"] == {}
    assert len(m["notes"]) == 1
    assert "unhealthy" in m["notes"][0]["skipped"]
    assert m["notes"][0]["device"] == "fw08"


def test_a_few_errors_do_not_exclude_a_witness(app, isolated):
    """The gate is a ratio, not "any error at all" — a healthy sweep with a
    couple of transient failures is still evidence."""
    a = _appliance("fw09")
    ledger = {f"o{i}": _ok(1) for i in range(90)}
    ledger.update({f"e{i}": _error() for i in range(10)})
    _snapshot(isolated, a, ledger)
    m = am.build("fortiweb")
    assert m["notes"] == []
    assert m["lines"]["7.6"]["counts"]["ok"] == 90


def test_maintenance_and_invalid_hosts_are_not_witnesses(app, isolated):
    a = _appliance("parked", maintenance=True)
    b = _appliance("retired", host="fw7.invalid")
    for ap in (a, b):
        _snapshot(isolated, ap, {"x": _ok(1)}, sections={"s": {"x": [{"k": 1}]}})
    assert am.build("fortiweb")["lines"] == {}


def test_snapshot_without_firmware_is_skipped_with_a_reason(app, isolated):
    a = _appliance("fw09", firmware="")
    _snapshot(isolated, a, {"x": _ok(1)}, firmware="")
    m = am.build("fortiweb")
    assert m["lines"] == {}
    assert "no firmware" in m["notes"][0]["skipped"]


def test_pre_ledger_snapshot_is_skipped_with_a_reason(app, isolated):
    a = _appliance("fw09")
    _snapshot(isolated, a, {})
    m = am.build("fortiweb")
    assert m["lines"] == {}
    assert "pre-ledger" in m["notes"][0]["skipped"]


def test_line_comes_from_the_snapshot_not_the_row(app, isolated):
    """The row can have been upgraded since; the snapshot records the firmware
    the sweep actually measured against."""
    a = _appliance("fw09", firmware="8.0.1")
    _snapshot(isolated, a, {"x": _ok(1)}, firmware="7.6.8")
    assert list(am.build("fortiweb")["lines"]) == ["7.6"]


def test_in_fleet_reflects_the_appliance_rows(app, isolated):
    a = _appliance("fw09")
    _snapshot(isolated, a, {"x": _ok(1)})
    _schema(isolated, "fortiweb", "8.0", "admin", ["name"])
    m = am.build("fortiweb")
    assert m["lines"]["7.6"]["in_fleet"] is True
    assert m["lines"]["8.0"]["in_fleet"] is False, \
        "no appliance runs 8.0 — the page must say the evidence is archived"


# --------------------------------------------------------------------------
# verdict merge
# --------------------------------------------------------------------------

def test_served_by_any_healthy_witness_beats_absent(app, isolated):
    """Absence is a claim about the FIRMWARE, so one device that served the
    endpoint disproves every device that did not."""
    a = _appliance("fw09")
    b = _appliance("fw10")
    _snapshot(isolated, a, {"x": _absent()})
    _snapshot(isolated, b, {"x": _ok(1)}, sections={"s": {"x": [{"k": 1}]}})
    assert am.build("fortiweb")["lines"]["7.6"]["endpoints"]["x"]["verdict"] == "ok"


def test_field_sets_union_across_witnesses_on_a_line(app, isolated):
    a = _appliance("fw09")
    b = _appliance("fw10")
    _snapshot(isolated, a, {"x": _ok(1)}, sections={"s": {"x": [{"a": 1}]}})
    _snapshot(isolated, b, {"x": _ok(1)}, sections={"s": {"x": [{"b": 2}]}})
    assert am.build("fortiweb")["lines"]["7.6"]["endpoints"]["x"]["fields"] == ["a", "b"]


# --------------------------------------------------------------------------
# schema evidence
# --------------------------------------------------------------------------

def test_default_folder_is_not_a_firmware_line(app, isolated):
    """``_default`` is the fallback for lines that have not diverged. Counting
    it as a line invents a firmware no appliance runs."""
    _schema(isolated, "fortiweb", "_default", "dns", ["a"])
    _schema(isolated, "fortiweb", "7.6", "dns", ["a"])
    assert list(am.build("fortiweb")["lines"]) == ["7.6"]


def test_schema_only_line_still_appears(app, isolated):
    """FortiWeb 8.0 has no appliance left to sweep — its only evidence is the
    harvested schema, and dropping it would erase the upgrade target."""
    _schema(isolated, "fortiweb", "8.0", "admin", ["name", "fortiai"])
    m = am.build("fortiweb")
    assert m["lines"]["8.0"]["counts"]["schema_fields"] == 2
    assert m["lines"]["8.0"]["counts"]["swept"] == 0


# --------------------------------------------------------------------------
# store
# --------------------------------------------------------------------------

def test_rebuild_persists_and_load_reads_it_back(app, isolated):
    a = _appliance("fw09")
    _snapshot(isolated, a, {"x": _ok(1)})
    am.rebuild("fortiweb")
    assert os.path.exists(am.matrix_path("fortiweb"))
    assert am.load("fortiweb")["lines"]["7.6"]["counts"]["ok"] == 1


def test_the_store_file_matches_the_mode_of_its_siblings(app, isolated):
    """0644, like every other artifact under ``data/``.

    ``mkstemp`` hands back 0600, so without an explicit ``chmod`` the mode is
    whatever the tempfile module happened to choose — and a mode audit then
    turns up one odd file with no reason attached to it. The matrix holds no
    secret: it is a derived summary of endpoint names and field names.
    """
    a = _appliance("fw09")
    _snapshot(isolated, a, {"x": _ok(1)})
    am.rebuild("fortiweb")
    assert oct(os.stat(am.matrix_path("fortiweb")).st_mode & 0o777) == oct(0o644)


def test_rebuild_over_an_existing_file_is_atomic(app, isolated):
    """A rebuild replaces the file; it never truncates it in place. A reader
    mid-rebuild gets the old matrix, never half of the new one."""
    a = _appliance("fw09")
    _snapshot(isolated, a, {"x": _ok(1)})
    am.rebuild("fortiweb")
    first = io.open(am.matrix_path("fortiweb")).read()
    _snapshot(isolated, a, {"x": _ok(1), "y": _ok(1)})
    am.rebuild("fortiweb")
    second = io.open(am.matrix_path("fortiweb")).read()
    assert first != second
    assert json.loads(second)["lines"]["7.6"]["counts"]["swept"] == 2
    # no .tmp left behind
    assert [f for f in os.listdir(am.MATRIX_ROOT) if f.endswith(".tmp")] == []


def test_load_of_a_foreign_product_file_is_rejected(app, isolated):
    """A file whose ``product`` does not match is not this product's matrix —
    serving it would answer FortiADC questions with FortiWeb evidence."""
    os.makedirs(am.MATRIX_ROOT, exist_ok=True)
    io.open(am.matrix_path("fortiadc"), "w").write(
        json.dumps({"product": "fortiweb", "lines": {"7.6": {}}}))
    out = am.load("fortiadc")
    assert out["product"] == "fortiadc"
    assert out["lines"] == {}


# --------------------------------------------------------------------------
# the page
# --------------------------------------------------------------------------

def _admin(app, client):
    login(client, admin_user_id(app))


@pytest.mark.parametrize("url", ["/web/registry/versions", "/adc/api/versions"])
def test_versions_page_renders_for_both_products(app, client, isolated, url):
    a = _appliance("fw09")
    _snapshot(isolated, a, {"x": _ok(1)})
    _admin(app, client)
    r = client.get(url)
    assert r.status_code == 200
    assert b"API versions" in r.data


def test_versions_page_requires_registry_edit(app, client, isolated):
    uid = make_user(app, username="ro", role="readonly")
    login(client, uid)
    assert client.get("/web/registry/versions").status_code in (302, 403)
    assert client.post("/web/registry/versions/rebuild").status_code in (302, 403)


def test_rebuild_surfaces_excluded_witnesses(app, client, isolated):
    """A device dropped for being unhealthy is the most useful thing on this
    page and the easiest to lose inside a success banner."""
    sick = _appliance("fw08")
    ledger = {f"e{i}": _error() for i in range(283)}
    ledger.update({f"o{i}": _absent() for i in range(38)})
    _snapshot(isolated, sick, ledger)
    _admin(app, client)
    r = client.post("/web/registry/versions/rebuild", follow_redirects=True)
    assert r.status_code == 200
    assert b"fw08 skipped" in r.data


def test_page_ignores_an_unknown_line_in_the_query_string(app, client, isolated):
    """A base/target nobody has measured must not render as an empty diff —
    an empty diff and 'that firmware has never been measured' look identical
    and mean opposite things."""
    a = _appliance("fw09")
    _snapshot(isolated, a, {"x": _ok(1)})
    _schema(isolated, "fortiweb", "8.0", "admin", ["name"])
    _admin(app, client)
    r = client.get("/web/registry/versions?base=7.6&target=99.9")
    assert r.status_code == 200
    assert b"99.9" not in r.data


def test_the_fortiweb_example_appears_only_in_the_fortiweb_adom(app, client, isolated):
    """The motivating example names a product, so it must not render in the
    other ADOM — the same product-separation rule ``test_product_separation``
    enforces for code.

    This also guards a failure that is invisible by construction: the first
    version of the condition lost its quotes and became
    ``{% if product == fortiweb %}`` — an UNDEFINED name, which Jinja renders
    as falsy without raising. The sentence simply vanished from both pages and
    nothing failed.
    """
    a = _appliance("fw09")
    _snapshot(isolated, a, {"x": _ok(1)})
    _admin(app, client)
    web = client.get("/web/registry/versions").get_data(as_text=True)
    adc = client.get("/adc/api/versions").get_data(as_text=True)
    assert "FortiWeb 7.6 and 8.0 are both" in web, \
        "the example vanished — check the condition still compares to a STRING"
    assert "FortiWeb 7.6 and 8.0 are both" not in adc


# --------------------------------------------------------------------------
# the registry loader — the latent collapse this round also closed
# --------------------------------------------------------------------------

def test_reader_filters_by_api_version(session):
    """Until this guard existed the readers filtered on product alone and
    built ``{name: urn}``. A second api_version row for the same name made the
    dict collapse — one row won by arbitrary query order and its URN was
    served to every consumer with no error and no log."""
    from app.models import RegistryEndpoint
    from app.registry import loader as L

    db.session.add(RegistryEndpoint(product="fortiweb", api_version="v2.0",
                                    name="iface", urn="/api/v2.0/cmdb/system/interface"))
    db.session.add(RegistryEndpoint(product="fortiweb", api_version="v3",
                                    name="iface", urn="/api/v3.0/cmdb/system/interface"))
    db.session.commit()
    L.invalidate_cache()
    assert L.load_registry()["iface"] == "/api/v2.0/cmdb/system/interface"
    L.invalidate_cache()


def test_every_product_reader_and_seeder_share_one_api_version_source(app):
    """The two halves disagreed for as long as both existed: every seeder
    scoped by api_version, no reader did. A literal in either place is how
    they drift apart again."""
    from app.registry import loader as L

    src = io.open(L.__file__).read()
    tree = ast.parse(src)
    literals = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.keyword) or node.arg != "api_version":
            continue
        if isinstance(node.value, ast.Constant):
            literals.append(node.value.value)
    assert literals == [], \
        f"api_version passed as a literal instead of API_VERSION[...]: {literals}"
    assert set(L.API_VERSION) == {"fortiweb", "fortiadc", "fortianalyzer",
                                  "fortiauthenticator"}


def test_api_version_is_not_the_firmware_line(app):
    """The distinction the whole round is about: 7.6 and 8.0 are both v2.0."""
    from app.registry import loader as L
    assert L.API_VERSION["fortiweb"] == "v2.0"
    assert am.firmware_line("7.6.8") != am.firmware_line("8.0.3")


# --------------------------------------------------------------------------
# the CLI — stdlib only, and rc separates "no" from "no evidence"
# --------------------------------------------------------------------------

def test_cli_module_imports_no_flask():
    """The CLI must answer on a node whose venv is corrupt and whose database
    is down. A module-level app import defeats the entire reason it exists."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(am.__file__))),
                        "..", "deploy", "satom_cli", "cmd_apiver.py")
    tree = ast.parse(io.open(os.path.normpath(path)).read())
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names += [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.append(node.module.split(".")[0])
    assert "flask" not in names and "app" not in names, names
