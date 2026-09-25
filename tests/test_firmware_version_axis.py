"""Guards for the per-BUILD evidence axis (round of 2026-09-16).

The defect these exist for is silent by construction. ``api_matrix`` keyed its
evidence by firmware LINE (``8.0``) and merged every witness on it with the
rule *"OK from any healthy witness wins"*. So an endpoint served by one build
of a line was attributed to the line, and ``preflight`` — whose caller's next
move is a write to a real appliance — answered **compatible** about a box that
does not serve it. Nothing errors. The page fills, the table renders, the
answer is wrong.

Live grounding (192.0.2.248, measured 2026-09-16, not assumed):
  * fortiweb15 and fortiweb16 run **7.6.8**, fortiweb17 runs **8.0.5**.
    326 endpoints swept on each; 287 served on 7.6.8 and **290** on 8.0.5, so
    the two builds genuinely are not the same API surface.
  * Every FortiWeb line happens to be homogeneous TODAY — one measured build
    each — so the false positive is not currently firing on this fleet. The
    mechanism is what is fixed here, and the fixtures below are what prove it,
    because production data cannot.
  * ``data/api_matrix/fortiadc.json`` still holds an 8.0 line whose two
    witnesses (fortiadc02/03) no longer exist as appliance rows. That is why a
    pre-version matrix is ADAPTED on read and never auto-rebuilt: a rebuild
    filters witnesses through the live table and would delete that evidence as
    a side effect of somebody opening a page.
"""
from __future__ import annotations

import ast
import io
import json
import os
import re

import pytest

from app.extensions import db
from app.models import Appliance
from app.services import api_library as lib
from app.services import api_matrix as am
from app.services import firmware_versions as fv
from app.services import rediscovery
from tests.conftest import admin_user_id, login

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def isolated(app, session, tmp_path, monkeypatch):
    red = tmp_path / "rediscovery"
    sch = tmp_path / "field_schemas"
    mat = tmp_path / "api_matrix"
    for p in (red, sch, mat):
        p.mkdir()
    monkeypatch.setattr(am, "SCHEMA_ROOT", str(sch))
    monkeypatch.setattr(am, "MATRIX_ROOT", str(mat))
    monkeypatch.setenv("SATOM_REDISCOVERY_DIR", str(red))
    return {"rediscovery": red, "field_schemas": sch, "api_matrix": mat,
            "root": tmp_path}


def _ingest(isolated):
    """Store the fixture tree in the API library — what a sweep or a harvest
    does in production. The matrix is read from the library, never the tree."""
    return lib.backfill(str(isolated["root"]))


def _appliance(name, kind="fortiweb", firmware="7.6.8", host=None):
    a = Appliance(name=name, kind=kind, host=host or "%s.test" % name, port=443,
                  username="admin", verify_ssl=False, firmware=firmware)
    a.password = "secret"
    db.session.add(a)
    db.session.commit()
    return a


def _ledger(**verdicts):
    return {name: {"verdict": v, "urn": "cmdb/%s" % name, "section": "S"}
            for name, v in verdicts.items()}


def _archive(isolated, appliance, version, ledger, sections=None,
             generated_at="2099-01-01T00:00:00"):
    """Write a per-build snapshot the way a sweep now does, and ingest it."""
    d = isolated["rediscovery"] / str(appliance.id) / "by-version"
    d.mkdir(parents=True, exist_ok=True)
    (d / ("%s.json" % version)).write_text(json.dumps({
        "device": appliance.name, "appliance_id": appliance.id,
        "generated_at": generated_at, "firmware": version,
        "endpoint_status": ledger, "sections": sections or {},
    }))
    _ingest(isolated)


def _legacy(isolated, appliance, firmware, ledger, sections=None,
            generated_at="2099-01-01T00:00:00"):
    """Write only ``_config.json`` — the shape every snapshot had before."""
    d = isolated["rediscovery"] / str(appliance.id)
    d.mkdir(parents=True, exist_ok=True)
    (d / "_config.json").write_text(json.dumps({
        "device": appliance.name, "appliance_id": appliance.id,
        "generated_at": generated_at, "firmware": firmware,
        "endpoint_status": ledger, "sections": sections or {},
    }))
    _ingest(isolated)


# ===========================================================================
# 1. the version vocabulary
# ===========================================================================

def test_a_version_with_no_patch_is_not_the_patch_zero():
    """RULE 1. ``8.0`` means "we know the line and not the build".

    Widening it to ``8.0.0`` would mint a build nobody runs and then file real
    evidence under it — a column that looks measured and describes nothing.
    """
    assert fv.normalize("8.0") == "8.0"
    assert fv.normalize("8.0") != "8.0.0"
    assert fv.is_line_only("8.0") is True
    assert fv.is_line_only("8.0.3") is False


def test_the_build_is_extracted_from_the_strings_the_fleet_actually_reports():
    # measured on 248: this is the literal shape a FortiWeb vault row carries
    assert fv.normalize("7.6.8,build1128(GA.M)") == "7.6.8"
    assert fv.normalize("FACVMKVM v8.0.3, build0099 (GA)") == "8.0.3"
    assert fv.normalize("8.0.5") == "8.0.5"
    assert fv.normalize("") == ""
    assert fv.normalize(None) == ""
    assert fv.normalize("no digits here") == ""


def test_the_line_is_derived_from_the_version_and_agrees_with_api_matrix():
    """One definition of a line. Two would be how ``8.0`` and ``8.0.0`` end up
    as separate columns describing the same evidence."""
    for raw in ("7.6.8,build1128", "8.0.5", "8.0"):
        assert fv.line_of(raw) == am.firmware_line(raw)


def test_builds_sort_numerically_not_lexically():
    """``8.0.10`` is newer than ``8.0.9``; string order says otherwise, and the
    page's default comparison is oldest → newest."""
    got = sorted(["8.0.9", "8.0.10", "8.0", "7.6.8"], key=fv.sort_key)
    assert got == ["7.6.8", "8.0", "8.0.9", "8.0.10"]


def test_a_line_only_string_sorts_before_every_build_of_its_line():
    """It is the weakest claim anyone can make about 8.0.x, so it reads first."""
    assert fv.sort_key("8.0") < fv.sort_key("8.0.0")


# ===========================================================================
# 2. the store stops destroying evidence
# ===========================================================================

def test_a_second_sweep_at_a_new_build_does_not_overwrite_the_first(isolated, app):
    """THE data-loss fix, stated as the thing that used to happen.

    Before this round the sweep wrote one file per appliance and overwrote it
    every run, so the first sweep after a firmware upgrade destroyed the only
    evidence backing the previous build — and nothing reported a loss.
    """
    a = _appliance("fw1")
    rediscovery.archive_snapshot(a.id, {"firmware": "7.6.8", "endpoint_status": {}})
    rediscovery.archive_snapshot(a.id, {"firmware": "8.0.5", "endpoint_status": {}})
    assert sorted(rediscovery.version_snapshots(a.id)) == ["7.6.8", "8.0.5"]


def test_a_re_sweep_at_the_same_build_replaces_only_its_own_file(isolated, app):
    a = _appliance("fw1")
    rediscovery.archive_snapshot(a.id, {"firmware": "7.6.8", "generated_at": "A"})
    rediscovery.archive_snapshot(a.id, {"firmware": "8.0.5", "generated_at": "A"})
    rediscovery.archive_snapshot(a.id, {"firmware": "7.6.8", "generated_at": "B"})
    snaps = rediscovery.version_snapshots(a.id)
    assert sorted(snaps) == ["7.6.8", "8.0.5"]
    assert json.loads(snaps["7.6.8"].read_text())["generated_at"] == "B"
    assert json.loads(snaps["8.0.5"].read_text())["generated_at"] == "A"


def test_a_snapshot_with_no_firmware_is_never_filed_under_a_guess(isolated, app):
    """It stays reachable as ``_config.json``. Filing it under a version would
    credit one build with evidence measured on an unknown one."""
    a = _appliance("fw1")
    assert rediscovery.archive_snapshot(a.id, {"endpoint_status": {}}) is None
    assert rediscovery.version_snapshots(a.id) == {}


def test_the_backfill_is_idempotent_and_never_downgrades_an_archive_entry(isolated, app):
    a = _appliance("fw1")
    _legacy(isolated, a, "7.6.8", _ledger(x="ok"), generated_at="2020-01-01")
    _archive(isolated, a, "7.6.8", _ledger(x="ok"), generated_at="2030-01-01")
    moved = rediscovery.migrate_version_archive()
    assert moved == []
    kept = json.loads(rediscovery.version_snapshots(a.id)["7.6.8"].read_text())
    assert kept["generated_at"] == "2030-01-01"


def test_the_backfill_files_a_legacy_snapshot_under_its_own_build(isolated, app):
    a = _appliance("fw1")
    _legacy(isolated, a, "8.0.5", _ledger(x="ok"))
    moved = rediscovery.migrate_version_archive()
    assert [m["version"] for m in moved] == ["8.0.5"]
    assert sorted(rediscovery.version_snapshots(a.id)) == ["8.0.5"]


# ===========================================================================
# 3. the matrix: builds, and a rollup that declares itself
# ===========================================================================

def _two_builds_one_line(isolated):
    """One line, two builds, one endpoint served by only ONE of them.

    This is the exact shape production cannot currently show — every FortiWeb
    line on this fleet is homogeneous — and the exact shape the old code
    reported as "the line serves it".
    """
    a = _appliance("boxA", firmware="8.0.3")
    b = _appliance("boxB", firmware="8.0.5")
    _archive(isolated, a, "8.0.3", _ledger(shared="ok", only_on_five="absent"))
    _archive(isolated, b, "8.0.5", _ledger(shared="ok", only_on_five="ok"))
    return a, b


def test_evidence_is_keyed_by_build_not_by_line(isolated, app):
    _two_builds_one_line(isolated)
    m = am.build("fortiweb")
    assert sorted(m["versions"]) == ["8.0.3", "8.0.5"]
    assert m["versions"]["8.0.3"]["endpoints"]["only_on_five"]["verdict"] == am.VERDICT_ABSENT
    assert m["versions"]["8.0.5"]["endpoints"]["only_on_five"]["verdict"] == am.VERDICT_OK


def test_the_rollup_declares_which_builds_it_merged(isolated, app):
    _two_builds_one_line(isolated)
    line = am.build("fortiweb")["lines"]["8.0"]
    assert line["measured_versions"] == ["8.0.3", "8.0.5"]
    assert line["heterogeneous"] is True


def test_an_endpoint_only_some_builds_serve_is_listed_as_partial(isolated, app):
    """The false positive, named. It is counted and listed, never folded into
    "the line serves it"."""
    line = am.build("fortiweb")["lines"]["8.0"] if _two_builds_one_line(isolated) else None
    line = am.build("fortiweb")["lines"]["8.0"]
    names = [p["endpoint"] for p in line["partial_endpoints"]]
    assert names == ["only_on_five"]
    p = line["partial_endpoints"][0]
    assert p["attested_on"] == ["8.0.5"]
    assert p["silent_on"] == ["8.0.3"]
    assert line["counts"]["partial"] == 1


def test_an_endpoint_every_build_serves_is_not_partial(isolated, app):
    _two_builds_one_line(isolated)
    line = am.build("fortiweb")["lines"]["8.0"]
    assert "shared" not in [p["endpoint"] for p in line["partial_endpoints"]]


def test_a_homogeneous_line_is_not_flagged_heterogeneous(isolated, app):
    a = _appliance("boxA", firmware="8.0.5")
    _archive(isolated, a, "8.0.5", _ledger(shared="ok"))
    line = am.build("fortiweb")["lines"]["8.0"]
    assert line["heterogeneous"] is False
    assert line["counts"]["partial"] == 0


def test_a_legacy_config_json_is_still_read_as_its_own_build(isolated, app):
    """The fallback keeps every pre-backfill node working. It is a fallback,
    never a merge."""
    a = _appliance("boxA", firmware="7.6.8")
    _legacy(isolated, a, "7.6.8", _ledger(x="ok"))
    assert sorted(am.build("fortiweb")["versions"]) == ["7.6.8"]


def test_the_archive_wins_over_config_json_for_the_same_build(isolated, app):
    a = _appliance("boxA", firmware="7.6.8")
    _legacy(isolated, a, "7.6.8", _ledger(x="absent"))
    _archive(isolated, a, "7.6.8", _ledger(x="ok"))
    m = am.build("fortiweb")
    assert m["versions"]["7.6.8"]["endpoints"]["x"]["verdict"] == am.VERDICT_OK


def test_field_schemas_reach_a_build_LABELLED_as_line_granular(isolated, app):
    """Dropping them would make every build look field-blind; carrying them
    silently would make a line-granular fact read as a build-granular one."""
    a = _appliance("boxA", firmware="8.0.5")
    _archive(isolated, a, "8.0.5", _ledger(x="ok"))
    d = isolated["field_schemas"] / "fortiweb" / "8.0"
    d.mkdir(parents=True)
    (d / "admin.json").write_text(json.dumps(
        {"object": "admin", "endpoint": "admin", "fields": [{"name": "name"}]}))
    _ingest(isolated)
    rec = am.build("fortiweb")["versions"]["8.0.5"]["objects"]["admin"]
    assert rec["granularity"] == "line"
    assert rec["line"] == "8.0"


# ===========================================================================
# 4. preflight: a build is never answered from its line
# ===========================================================================

def test_preflight_at_a_measured_build_answers_from_that_build(isolated, app):
    _two_builds_one_line(isolated)
    m = am.build("fortiweb")
    r = am.preflight("fortiweb", "8.0.5", "only_on_five", [], matrix=m)
    assert r["status"] != am.STATUS_ABSENT
    assert r["scope_kind"] == "version"


def test_preflight_at_the_OTHER_build_does_not_inherit_its_siblings_answer(isolated, app):
    """The bug, reproduced against the fix. 8.0.3 rejected this URN; the line
    rollup contains an ``ok`` for it because 8.0.5 served it. Answering 8.0.3
    from the rollup is the false positive."""
    _two_builds_one_line(isolated)
    m = am.build("fortiweb")
    r = am.preflight("fortiweb", "8.0.3", "only_on_five", [], matrix=m)
    assert r["status"] == am.STATUS_ABSENT
    assert r["scope_kind"] == "version"


def test_an_unmeasured_build_is_its_own_word_not_plain_unmeasured(isolated, app):
    """``unmeasured`` also covers "this product has no evidence at all", and
    the two demand different next actions."""
    _two_builds_one_line(isolated)
    m = am.build("fortiweb")
    r = am.preflight("fortiweb", "8.0.9", "shared", [], matrix=m)
    assert r["status"] == am.STATUS_VERSION_UNMEASURED
    assert am.STATUS_VERSION_UNMEASURED != am.STATUS_UNMEASURED
    assert r["measured_siblings"] == ["8.0.3", "8.0.5"]


def test_the_unmeasured_build_still_reports_what_the_line_knows(isolated, app):
    """It WARNS, it does not withhold. A refusal that hides what is known is
    how a correct guard gets routed around."""
    _two_builds_one_line(isolated)
    m = am.build("fortiweb")
    r = am.preflight("fortiweb", "8.0.9", "shared", [], matrix=m)
    assert r["line_answer"]["scope_kind"] == "line"
    assert r["line_answer"]["status"] == am.STATUS_FIELDS_UNKNOWN
    assert r["rollup_line"] == "8.0"


def test_resolve_scope_never_falls_back_from_a_build_to_its_line(isolated, app):
    _two_builds_one_line(isolated)
    m = am.build("fortiweb")
    doc, kind = am.resolve_scope(m, "8.0.9")
    assert (doc, kind) == (None, None)
    assert am.resolve_scope(m, "8.0")[1] == "line"
    assert am.resolve_scope(m, "8.0.5")[1] == "version"


def test_a_rollup_answer_says_it_is_a_rollup_and_which_builds_back_it(isolated, app):
    _two_builds_one_line(isolated)
    m = am.build("fortiweb")
    r = am.preflight("fortiweb", "8.0", "only_on_five", [], matrix=m)
    assert r["rollup"] is True
    assert r["rollup_versions"] == ["8.0.3", "8.0.5"]
    assert r["attested_on"] == ["8.0.5"]
    assert r["silent_on"] == ["8.0.3"]
    assert r["partial"] is True


def test_preflight_for_an_appliance_uses_its_full_build(isolated, app):
    """This is the call site the false positive came out of."""
    _two_builds_one_line(isolated)
    am.rebuild("fortiweb")
    box = Appliance.query.filter_by(name="boxA").one()
    r = am.preflight_for_appliance(box, "only_on_five", [])
    assert r["scope"] == "8.0.3"
    assert r["status"] == am.STATUS_ABSENT


def test_an_appliance_with_no_firmware_is_unmeasured_not_compatible(isolated, app):
    box = _appliance("ghost", firmware="")
    r = am.preflight_for_appliance(box, "anything", [])
    assert r["status"] == am.STATUS_UNMEASURED


# ===========================================================================
# 5. a pre-version matrix on disk
# ===========================================================================

def _store_legacy_matrix(isolated, product="fortiadc"):
    doc = {
        "product": product, "built_at": "2026-09-01T00:00:00", "sweepable": False,
        "fleet_lines": ["8.0"], "witnesses": [], "notes": [],
        "lines": {"8.0": {"line": "8.0", "in_fleet": True, "devices": ["gone01"],
                          "endpoints": {"x": {"endpoint": "x", "urn": "cmdb/x",
                                              "verdict": "ok", "fields": ["name"],
                                              "origin": "sweep", "devices": ["gone01"],
                                              "measured_at": ""}},
                          "objects": {},
                          "counts": {"swept": 1, "ok": 1, "absent": 0, "error": 0,
                                     "endpoints_with_fields": 1,
                                     "schema_objects": 0, "schema_fields": 0}}},
    }
    (isolated["api_matrix"] / ("%s.json" % product)).write_text(json.dumps(doc))
    return doc


def test_a_pre_version_matrix_is_imported_as_line_evidence_never_lost(isolated, app):
    """``fortiadc``'s whole 8.0 line lived only in a frozen line-only file whose
    witnesses were deleted. The library imports it as what it is —
    ``legacy_matrix`` evidence at LINE granularity — so it survives, and no
    build is invented for it."""
    _store_legacy_matrix(isolated)
    _ingest(isolated)
    doc = am.load("fortiadc")
    assert doc["lines"]["8.0"]["devices"] == ["gone01"]
    assert doc["lines"]["8.0"]["endpoints"]["x"]["origin"] == "legacy_matrix"
    assert doc["versions"] == {}
    assert "stale_format" not in doc


def test_a_build_question_against_line_only_evidence_is_refused_and_says_why(isolated, app):
    """Line evidence names no build, so it cannot answer for 8.0.3. The line's
    answer travels beside the refusal, labelled."""
    _store_legacy_matrix(isolated)
    _ingest(isolated)
    r = am.preflight("fortiadc", "8.0.3", "x", ["name"])
    assert r["status"] == am.STATUS_VERSION_UNMEASURED
    assert "no evidence of its own" in r["reason"]
    assert r["line_answer"]["status"] == am.STATUS_OK
    assert r["line_answer"]["scope_kind"] == "line"


# ===========================================================================
# 6. declarations: authored, derived, and never confused with measurement
# ===========================================================================

def test_a_declared_build_is_not_a_measured_one(isolated, app):
    """An empty MEASURED row reads as "we asked and there is nothing there",
    which is the opposite of "nobody ever asked"."""
    fv.declare("fortiweb", "8.0.9", note="next GA")
    cat = fv.catalog("fortiweb", measured={})
    assert cat["8.0.9"]["declared"] is True
    assert cat["8.0.9"]["measured"] is False


def test_declaring_is_idempotent_and_updates_the_note(isolated, app):
    ok, _msg, v = fv.declare("fortiweb", "8.0.9 build0999", note="first")
    assert (ok, v) == (True, "8.0.9")
    ok2, _m2, _v2 = fv.declare("fortiweb", "8.0.9", note="second")
    assert ok2 is True
    assert fv.manual("fortiweb")["8.0.9"].note == "second"


def test_a_string_with_no_version_in_it_is_refused(isolated, app):
    ok, msg, v = fv.declare("fortiweb", "the new one")
    assert ok is False and v == ""
    assert "8.0.3" in msg


def test_forgetting_a_derived_build_is_refused_not_silently_accepted(isolated, app):
    """Forgetting a note cannot unmake a fact, and pretending it did would let
    an operator believe a build is gone from the page when it is not."""
    _appliance("boxA", firmware="8.0.5")
    ok, msg = fv.forget("fortiweb", "8.0.5")
    assert ok is False
    assert "not declared by hand" in msg
    assert "8.0.5" in fv.catalog("fortiweb", measured={})


def test_a_build_a_box_runs_is_derived_without_any_row(isolated, app):
    """RULE 3. Two code paths create FirmwareImage rows; hooking both would be
    one refactor away from a version that silently never appears."""
    _appliance("boxA", firmware="8.0.5")
    cat = fv.catalog("fortiweb", measured={})
    assert fv.SOURCE_FLEET in cat["8.0.5"]["sources"]
    assert cat["8.0.5"]["manual"] is False


def test_an_uploaded_image_declares_its_build_with_no_hook(isolated, app):
    from app.models_firmware import FirmwareImage
    db.session.add(FirmwareImage(product="fortiweb", version="8.0.7",
                                 filename="FWB_8.0.7.out", stored_path="/x",
                                 size_bytes=1, sha256="", uploaded_by="t"))
    db.session.commit()
    cat = fv.catalog("fortiweb", measured={})
    assert fv.SOURCE_UPLOAD in cat["8.0.7"]["sources"]


def test_the_overlay_shows_a_declaration_without_a_rebuild(isolated, app):
    """A declaration that needs a Rebuild to become visible is an action that
    appears to do nothing — and making declare TRIGGER a rebuild would let
    typing a version number destroy a stale product's evidence."""
    a = _appliance("boxA", firmware="8.0.5")
    _archive(isolated, a, "8.0.5", _ledger(x="ok"))
    stored = am.rebuild("fortiweb")
    fv.declare("fortiweb", "8.0.9", note="not measured")
    merged = fv.overlay("fortiweb", am.load("fortiweb"))
    assert "8.0.9" not in stored["versions"]
    assert merged["versions"]["8.0.9"]["measured"] is False
    assert merged["versions"]["8.0.9"]["counts"]["swept"] == 0
    assert "8.0.9" in merged["lines"]["8.0"]["declared_versions"]


def test_the_overlay_never_adds_measurements_to_a_measured_build(isolated, app):
    a = _appliance("boxA", firmware="8.0.5")
    _archive(isolated, a, "8.0.5", _ledger(x="ok", y="ok"))
    am.rebuild("fortiweb")
    merged = fv.overlay("fortiweb", am.load("fortiweb"))
    assert merged["versions"]["8.0.5"]["counts"]["swept"] == 2
    assert merged["versions"]["8.0.5"]["measured"] is True


def test_a_line_invented_by_a_declaration_is_explicitly_unmeasured(isolated, app):
    fv.declare("fortiweb", "9.1.0")
    merged = fv.overlay("fortiweb", am.load("fortiweb") or
                        {"product": "fortiweb", "lines": {}, "versions": {}})
    ln = merged["lines"]["9.1"]
    assert ln["measured"] is False
    assert ln["counts"]["swept"] == 0
    assert ln["measured_versions"] == []


# ===========================================================================
# 7. CLI dumps carry the build, and the filter never falls back
# ===========================================================================

def test_a_vault_row_is_labelled_with_its_full_build_not_only_its_line():
    """A dump is captured from ONE box running ONE build. Labelling it ``8.0``
    throws away the only thing that could distinguish 8.0.3's CLI from
    8.0.7's."""
    src = io.open(os.path.join(ROOT, "app/services/cli_coverage.py"),
                  encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "evidence_index")
    body = ast.get_source_segment(src, fn)
    # the literal dict key, not "the word appears somewhere in the function" —
    # the tenth time an assert in this repo was satisfied by the wrong
    # occurrence was a docstring mentioning the key it was guarding.
    assert re.search(r'"version":\s*api_matrix\.firmware_version\(', body)


def test_the_version_filter_is_a_filter_and_never_a_fallback():
    """No dump on 8.0.5 means *no evidence for 8.0.5*, not the 8.0.3 dump
    relabelled. Asserted on the CONDITION, because ``if False and version:``
    still contains the identifier."""
    src = io.open(os.path.join(ROOT, "app/services/cli_coverage.py"),
                  encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "report")
    branch = next(n for n in ast.walk(fn)
                  if isinstance(n, ast.If) and isinstance(n.test, ast.Name)
                  and n.test.id == "version")
    # ``elif line:`` — the line filter must be the ELSE of the version filter,
    # so a version with no dump can never be widened into its line.
    assert branch.orelse and isinstance(branch.orelse[0], ast.If)
    assert branch.orelse[0].test.id == "line"


def test_report_and_provenance_both_accept_the_build(isolated, app):
    from app.services import cli_coverage
    rep = cli_coverage.report("fortiweb", version="8.0.5")
    assert rep["version_filter"] == "8.0.5"
    assert rep["chosen"] is None  # no dump for that build in the test vault
    prov = cli_coverage.provenance("fortiweb", version="8.0.5")
    assert prov.measured is False


# ===========================================================================
# 8. the page
# ===========================================================================

TPL = os.path.join(ROOT, "app/templates/registry/versions.html")


def test_the_page_renders_a_row_per_build_and_no_second_table_of_lines(isolated, client, app):
    """The rollup TABLE was removed on 2026-09-16 at the operator's request:
    with one measured build per line it repeated the build table row for row.

    The half of the old rule that still holds — one row per build — is kept,
    and the half that changed is inverted rather than dropped, so the duplicate
    cannot come back unnoticed. What the table uniquely said is guarded by
    ``test_the_page_names_a_heterogeneous_rollup_and_lists_its_partials``.
    """
    _two_builds_one_line(isolated)
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    body = client.get("/web/registry/versions").get_data(as_text=True)
    assert "evidence held per build" in body
    assert "<code>8.0.3</code>" in body and "<code>8.0.5</code>" in body
    assert "the rollup, and what it merged" not in body
    assert "Firmware lines" not in body, \
        "the duplicated rollup table is back"


def test_the_page_names_a_heterogeneous_rollup_and_lists_its_partials(isolated, client, app):
    """What the removed rollup table uniquely said, and still says.

    Scoped to the disclosure BLOCK: ``"only_on_five" in body`` is answered by
    the endpoint's other appearances on the page, and a mutation proved it —
    the name could be blanked inside the disclosure with the guard still green.
    """
    _two_builds_one_line(isolated)
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    body = client.get("/web/registry/versions").get_data(as_text=True)
    head = body.find("More than one build backs a line")
    assert head != -1, "the page does not disclose that a line merges two builds"
    # Bounded by the next card, so no assertion below can be paid for by the
    # comparison table further down the page.
    stop = body.find('<div class="fw-card', head)
    block = body[head:stop if stop != -1 else len(body)]
    assert "heterogeneous" in block
    assert "Attested by only some builds" in block
    assert "only_on_five" in block, \
        "the endpoint only one build served must be named: %s" % block[:600]


def test_a_homogeneous_line_adds_nothing_to_the_page(isolated, client, app):
    """The premise of the 2026-09-16 removal, pinned.

    The rollup table went away because with ONE measured build per line it
    repeated the build rows. If the line ever starts saying something again on
    a homogeneous fleet, that premise is broken and this fails — which is the
    only way anyone would notice.
    """
    a = _appliance("boxA", firmware="8.0.5")
    _archive(isolated, a, "8.0.5", _ledger(shared="ok"))
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    body = client.get("/web/registry/versions").get_data(as_text=True)
    assert "<code>8.0.5</code>" in body
    assert "heterogeneous" not in body, \
        "one build backs this line — nothing may claim otherwise"
    assert "Attested by only some builds" not in body, \
        "there is no disagreement to disclose on a single-build line"


def test_the_page_marks_a_declared_build_unmeasured(isolated, client, app):
    fv.declare("fortiweb", "8.0.9", note="next GA")
    login(client, admin_user_id(app))
    body = client.get("/web/registry/versions").get_data(as_text=True)
    assert "8.0.9" in body
    assert ("declared &#183; unmeasured" in body or "declared · unmeasured" in body)


def test_declare_and_forget_exist_on_BOTH_mounts_of_the_page():
    """A page mounted twice whose new POST exists on only one mount is the same
    defect as a fix applied to one node: it works where it was tested."""
    for path, prefix in (("app/views/registry.py", "/registry"),
                         ("app/views/adc_api.py", None)):
        src = io.open(os.path.join(ROOT, path), encoding="utf-8").read()
        assert "def api_versions_declare(" in src, path
        assert "def api_versions_forget(" in src, path
        assert "'/versions/declare'" in src, path
        assert "'/versions/forget'" in src, path


def test_the_declare_route_round_trips_through_the_page(isolated, client, app):
    login(client, admin_user_id(app))
    r = client.post("/web/registry/versions/declare",
                    data={"version": "8.0.9", "note": "hello"},
                    follow_redirects=True)
    assert r.status_code == 200
    assert "hello" in r.get_data(as_text=True)
    r = client.post("/web/registry/versions/forget", data={"version": "8.0.9"},
                    follow_redirects=True)
    # The flash banner legitimately says the build's name, so the assertion is
    # on the ROW that carried it. Matching the bare string would be satisfied
    # by the confirmation message — the eleventh time an assert in this repo
    # was satisfied by the wrong occurrence.
    assert "<code>8.0.9</code>" not in r.get_data(as_text=True)


def test_a_pre_version_matrix_renders_as_its_line_on_the_page(isolated, client, app):
    """No "rebuild me" banner any more: the frozen file is imported evidence,
    and the page shows the line it describes."""
    _store_legacy_matrix(isolated, "fortiweb")
    _ingest(isolated)
    login(client, admin_user_id(app))
    body = client.get("/web/registry/versions").get_data(as_text=True)
    assert "before evidence was indexed by build" not in body
    assert "legacy_matrix" in body


def test_loading_the_matrix_never_writes_or_reads_the_export():
    """``load`` must not call ``rebuild`` (a page view would rewrite the file
    the offline CLI trusts) and must not open a file (the export is never the
    source)."""
    src = io.open(os.path.join(ROOT, "app/services/api_matrix.py"),
                  encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "load")
    calls = [n.func.id if isinstance(n.func, ast.Name) else n.func.attr
             for n in ast.walk(fn) if isinstance(n, ast.Call)]
    assert "rebuild" not in calls
    assert "open" not in calls and "_write_json_atomic" not in calls
    assert "build" in calls


def test_the_preflight_legend_documents_the_new_word():
    tpl = io.open(TPL, encoding="utf-8").read()
    assert "version_unmeasured" in tpl
    assert "8.0.4 is not" in tpl or "8.0.4</code> and <code>8.0.7" in tpl


# ===========================================================================
# 9. gaps found by the mutation harness — three survivors, all mine
# ===========================================================================

def test_evidence_alone_is_not_a_declaration(isolated, app):
    """A build we have measured and nobody registered is NOT declared.

    Folding the two would make ``declared`` mean "we have heard of it", which
    is every build — and the word would stop separating "somebody intends to
    run this" from "a sweep tripped over it".
    """
    a = _appliance("boxA", firmware="8.0.5")
    _archive(isolated, a, "8.0.5", _ledger(x="ok"))
    am.rebuild("fortiweb")
    # measured, and derived from the fleet, but the FLEET source is what makes
    # it declared — so strip that by asking about a build no box runs.
    cat = fv.catalog("fortiweb", measured={"9.9.9": True})
    assert cat["9.9.9"]["measured"] is True
    assert cat["9.9.9"]["declared"] is False
    assert cat["9.9.9"]["sources"] == [fv.SOURCE_EVIDENCE]


def test_the_sweep_archives_its_snapshot_after_writing_config_json(isolated, app):
    """Without this call the whole round is inert: ``_config.json`` is still
    overwritten every run, so the first sweep after an upgrade still destroys
    the previous build's evidence. Asserted on the AST, because no test here
    drives a real sweep against a device.
    """
    src = io.open(os.path.join(ROOT, "app/services/rediscovery.py"),
                  encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_sweep")
    body = ast.get_source_segment(src, fn)
    cfg = body.index('_write_json(devdir / "_config.json"')
    call = body.index("archive_snapshot(aid, snapshot)")
    # AFTER the snapshot is on disk: the archive is the history beside the
    # latest, never a replacement for it.
    assert call > cfg
    names = [n.func.id for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
    assert "archive_snapshot" in names


def test_line_only_evidence_answers_for_itself_in_the_library(isolated, app):
    """The library keeps a snapshot that only ever said ``8.0`` as its own
    line-only build, and answers about it from that build alone — never from a
    merge with 8.0.5. In the matrix rollup it names no build, so it never adds
    to ``attested_on``."""
    a = _appliance("boxA", firmware="8.0")
    b = _appliance("boxB", firmware="8.0.5")
    _archive(isolated, a, "8.0", _ledger(only_here="ok"))
    _archive(isolated, b, "8.0.5", _ledger(only_here="absent"))
    at_line = lib.endpoints_at("fortiweb", "8.0")["only_here"]
    assert (at_line["verdict"], at_line["witnesses"]) == ("ok", ["boxA"])
    assert lib.endpoints_at("fortiweb", "8.0.5")["only_here"]["verdict"] == "absent"
    rollup = am.build("fortiweb")["lines"]["8.0"]["endpoints"]["only_here"]
    assert rollup["attested_on"] == [], "line evidence cannot say which build served it"
    assert rollup["silent_on"] == ["8.0.5"]


def test_a_line_only_build_resolves_to_ITSELF_not_to_its_rollup(isolated, app):
    """``8.0`` can be BOTH a build key (evidence whose patch was never
    recorded) and a line key. Resolving it to the rollup would hand back a
    merge of every 8.0.x in answer to a question about the one snapshot that
    only ever said "8.0" — the weakest claim answered with the broadest one.
    """
    a = _appliance("boxA", firmware="8.0")
    b = _appliance("boxB", firmware="8.0.5")
    _archive(isolated, a, "8.0", _ledger(only_here="ok"))
    _archive(isolated, b, "8.0.5", _ledger(only_here="absent"))
    m = am.build("fortiweb")
    assert "8.0" in m["versions"] and "8.0" in m["lines"]
    doc, kind = am.resolve_scope(m, "8.0")
    assert kind == "version"
    assert doc["devices"] == ["boxA"]
    # and the rollup, asked for by nobody here, still merged both
    assert m["lines"]["8.0"]["measured_versions"] == ["8.0", "8.0.5"]
    assert doc["line_only"] is True
    assert list(doc["endpoints"]) == ["only_here"]


def test_line_scoped_evidence_on_the_same_line_only_build_stays_in_the_rollup(isolated, app):
    """One "8.0" row can hold BOTH kinds: a sweep of a box that reported only
    "8.0" (point) and a frozen line matrix (line). Only the point evidence is
    that build's entry; the line evidence stays a rollup fact, never promoted
    into an answer about the one snapshot."""
    a = _appliance("boxA", kind="fortiadc", firmware="8.0")
    _store_legacy_matrix(isolated)          # line-scoped: endpoint "x", gone01
    _archive(isolated, a, "8.0", _ledger(swept="ok"))
    m = am.build("fortiadc")
    entry = m["versions"]["8.0"]
    assert sorted(entry["endpoints"]) == ["swept"]
    assert entry["devices"] == ["boxA"]
    line = m["lines"]["8.0"]
    assert sorted(line["endpoints"]) == ["swept", "x"]
    assert line["endpoints"]["x"]["origin"] == "legacy_matrix"
    assert line["measured_versions"] == ["8.0"]
