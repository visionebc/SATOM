"""Guards for endpoint baselines (services/api_baseline.py).

The baseline replaced four hand-written ``endpoints*.yaml`` seeds. Everything
it can get wrong is silent: a baseline that drops an endpoint nobody measured,
overwrites an operator's fix, accepts a hand-edited artifact or labels an
assumption as a measurement still boots, still renders the Registry page and
still resolves names — to the wrong URN, right before a write to an appliance.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil

import pytest
import sqlalchemy as sa

from app.extensions import db
from app.models import RegistryEndpoint
from app.models_apilib import ApiLibBaseline, ApiLibBaselineEntry
from app.registry import loader
from app.services import api_baseline as ab
from app.services import api_library as lib

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FAC = "fortiauthenticator"


@pytest.fixture()
def ctx(app):
    with app.app_context():
        yield app


def _sweep(product, version, endpoints, device="box1"):
    """Ingest one measured sweep of ``product`` at ``version``."""
    return lib.ingest({
        "product": product, "source": "sweep", "captured_at": "2026-09-26T00:00:00",
        "origin_ref": "test:%s@%s" % (device, version),
        "device": {"appliance_id": None, "name": device, "serial": "", "model": "",
                   "hw_type": "vm", "firmware_raw": version},
        "scope": {"kind": "build", "version": version, "build": ""},
        "healthy": True, "skip_reason": "",
        "endpoints": endpoints,
    })


def _ep(urn, verdict="ok"):
    return {"urn": urn, "section": "s", "verdict": verdict, "rows": 1, "fields": {}}


def _registry(product):
    return {r.name: r for r in RegistryEndpoint.query.filter_by(product=product).all()}


# --------------------------------------------------------------------------
# the shipped artifacts
# --------------------------------------------------------------------------

@pytest.mark.parametrize("product", ["fortiweb", "fortiadc", "fortianalyzer", FAC])
def test_every_registry_product_ships_a_sealed_pinned_baseline(product):
    doc = ab.read_artifact(product)
    assert doc is not None, "no shipped baseline for %s" % product
    assert doc["version"] and doc["version"][0].isdigit(), "baseline not pinned to a build"
    # the protocol is recorded, and it is the loader's — ONE place, not two
    assert doc["api_version"] == loader.API_VERSION[product]
    assert doc["sha256"] == ab.seal(product, doc["version"], doc["api_version"],
                                    doc["entries"])


def test_registry_products_are_exactly_the_loaders():
    assert set(ab.products()) == set(loader.API_VERSION)


def test_a_hand_edited_artifact_is_refused(tmp_path):
    src = ab.artifact_path(FAC)
    dst = tmp_path / ("%s.json" % FAC)
    shutil.copy(src, dst)
    text = dst.read_text()
    edited = text.replace('"/api/v1/localusers/"', '"/api/v1/hand-edited/"', 1)
    assert edited != text
    dst.write_text(edited)
    with pytest.raises(ValueError, match="seal mismatch"):
        ab.read_artifact(FAC, str(tmp_path))
    # and the no-database fallback serves nothing rather than the edited map
    assert ab.artifact_map(FAC, str(tmp_path)) == {}


def test_an_artifact_for_another_product_is_refused(tmp_path):
    shutil.copy(ab.artifact_path(FAC), tmp_path / "fortiadc.json")
    with pytest.raises(ValueError, match="not 'fortiadc'"):
        ab.read_artifact("fortiadc", str(tmp_path))


def test_the_retired_yaml_seeds_are_gone():
    """The whole point: no hand-written, unversioned seed at the repo root."""
    for name in ("endpoints.yaml", "endpoints_fortiadc.yaml",
                 "endpoints_fortianalyzer.yaml", "endpoints_fortiauthenticator.yaml"):
        assert not os.path.exists(os.path.join(_ROOT, name)), name
    dockerfile = open(os.path.join(_ROOT, "Dockerfile"), encoding="utf-8").read()
    assert "endpoints.yaml" not in dockerfile
    src = open(os.path.join(_ROOT, "app", "registry", "loader.py"), encoding="utf-8").read()
    assert "yaml" not in src.replace("endpoints*.yaml", "")


# --------------------------------------------------------------------------
# boot
# --------------------------------------------------------------------------

@pytest.mark.parametrize("product", ["fortiweb", "fortiadc", "fortianalyzer", FAC])
def test_boot_makes_the_registry_serve_the_shipped_baseline(ctx, product):
    shipped = ab.artifact_map(product)
    rows = _registry(product)
    assert {n: r.urn for n, r in rows.items() if r.enabled} == shipped
    b = ab.active(product)
    assert b is not None and b.applied_at is not None
    assert all(r.updated_by == ab.owner_tag(product, b.version) for r in rows.values())


def test_boot_is_idempotent(ctx):
    before = ApiLibBaseline.query.count(), ApiLibBaselineEntry.query.count()
    assert ab.boot() == {}
    assert (ApiLibBaseline.query.count(), ApiLibBaselineEntry.query.count()) == before


def test_boot_upgrades_legacy_seed_rows_without_changing_what_is_served(ctx):
    """An installation from before 2.4 has rows tagged ``seed``: they are the
    baseline's to manage, and adopting them must not change a single URN."""
    for r in RegistryEndpoint.query.filter_by(product=FAC):
        r.updated_by = "seed"
    ab.active(FAC).applied_at = None
    db.session.commit()
    served = dict(loader.load_fac_registry())
    res = ab.boot()[FAC]
    assert res["retagged"] == len(served) and res["corrected"] == 0 and res["added"] == 0
    loader.invalidate_fac_cache()
    assert loader.load_fac_registry() == served


# --------------------------------------------------------------------------
# promotion
# --------------------------------------------------------------------------

def test_an_unmeasured_build_cannot_be_promoted(ctx):
    with pytest.raises(ValueError, match="no measured evidence"):
        ab.plan_promotion(FAC, "9.9.9")


def test_vendor_claims_alone_do_not_make_a_build_promotable(ctx):
    lib.ingest({"product": FAC, "source": "vendor_doc", "captured_at": "2026-01-01",
                "origin_ref": "vendor:test", "device": None,
                "scope": {"kind": "spans", "versions": ["9.9.9"]},
                "healthy": True, "skip_reason": "",
                "endpoints": {"auth_local_users": {"urn": "/api/v1/localusers/",
                                                   "verdict": "ok", "section": "s",
                                                   "spans": [["9.9.9", None]]}},
                "summary": {"max_version": "9.9.9", "min_version": "9.9.9"}})
    with pytest.raises(ValueError, match="no measured evidence"):
        ab.plan_promotion(FAC, "9.9.9")


def _promotion_fixture():
    base = ab.artifact_map(FAC)
    kept, gone = sorted(base)[:2]
    _sweep(FAC, "9.9.1", {
        kept: _ep(base[kept]),                       # served, same URN
        gone: _ep(base[gone], verdict="absent"),     # measured absent
        "auth_brand_new": _ep("/api/v1/brandnew/"),  # new on this build
    })
    return base, kept, gone


def test_plan_promotion_adds_measured_drops_absent_and_carries_the_rest(ctx):
    base, kept, gone = _promotion_fixture()
    plan = ab.plan_promotion(FAC, "9.9.1")
    assert plan["diff"]["added"] == ["auth_brand_new"]
    assert plan["diff"]["removed"] == [gone]
    assert plan["diff"]["urn_changed"] == []
    by = {e["name"]: e for e in plan["entries"]}
    assert by[kept]["provenance"] == "measured" and by[kept]["measured_on"] == "9.9.1"
    # nothing measured about the others on 9.9.1: carried, and labelled so
    others = set(base) - {kept, gone}
    assert others and all(by[n]["provenance"] == "carried" for n in others)
    assert all(by[n]["urn"] == base[n] for n in others)
    # a plan writes nothing
    assert ApiLibBaseline.query.filter_by(product=FAC).count() == 1


def test_promote_reconciles_the_registry_and_spares_operator_rows(ctx):
    base, kept, gone = _promotion_fixture()
    other = sorted(set(base) - {kept, gone})[0]
    op_row = RegistryEndpoint.query.filter_by(product=FAC, name=other).first()
    op_row.urn, op_row.updated_by = "/api/v1/operator-fixed/", "alice"
    db.session.commit()

    res = ab.promote(FAC, "9.9.1", actor="test")
    assert res["created"] is True
    applied = res["applied"]
    assert applied["added"] == 1 and applied["removed"] == 1
    rows = _registry(FAC)
    tag = ab.owner_tag(FAC, "9.9.1")
    assert rows["auth_brand_new"].enabled and rows["auth_brand_new"].updated_by == tag
    # removal is a soft delete, attributed to the baseline
    assert rows[gone].enabled is False and rows[gone].updated_by == tag
    # the operator's fix survives the promotion untouched
    assert rows[other].urn == "/api/v1/operator-fixed/" and rows[other].updated_by == "alice"
    loader.invalidate_fac_cache()
    assert loader.resolve_fac("auth_brand_new") == "/api/v1/brandnew/"
    with pytest.raises(KeyError):
        loader.resolve_fac(gone)


def test_a_urn_move_on_a_newer_build_corrects_the_registry(ctx):
    """The failure the old insert-only seed could never fix: the vendor moves a
    resource, and the registry kept serving the old path forever."""
    base = ab.artifact_map(FAC)
    name = sorted(base)[0]
    _sweep(FAC, "9.9.2", {name: _ep("/api/v2/moved/")})
    res = ab.promote(FAC, "9.9.2", actor="test")
    assert res["diff"]["urn_changed"] == [{"name": name, "from": base[name],
                                           "to": "/api/v2/moved/"}]
    assert res["applied"]["corrected"] == 1
    assert _registry(FAC)[name].urn == "/api/v2/moved/"


def test_re_promoting_an_old_baseline_reactivates_it_without_a_duplicate(ctx):
    base = ab.artifact_map(FAC)
    name = sorted(base)[0]
    _sweep(FAC, "9.9.2", {name: _ep("/api/v2/moved/")})
    first = ab.active(FAC)
    ab.promote(FAC, "9.9.2", actor="test")
    assert ab.active(FAC).id != first.id
    # an identical plan is reported as such and writes nothing
    assert ab.plan_promotion(FAC, "9.9.2")["identical"] is True
    n = ApiLibBaseline.query.filter_by(product=FAC).count()
    ab.promote(FAC, "9.9.2", actor="test")
    assert ApiLibBaseline.query.filter_by(product=FAC).count() == n


def test_contradicted_entries_leave_on_the_next_promotion_that_measures_them(ctx):
    doc = ab.read_artifact("fortiweb")
    contra = [e for e in doc["entries"] if e["provenance"] == ab.PROV_CONTRADICTED]
    if not contra:
        pytest.skip("the shipped FortiWeb baseline has no contradicted entries")
    victim = contra[0]
    _sweep("fortiweb", "9.9.3", {victim["name"]: _ep(victim["urn"], verdict="absent"),
                                 "server_policy": _ep(ab.artifact_map("fortiweb")["server_policy"])})
    plan = ab.plan_promotion("fortiweb", "9.9.3")
    assert victim["name"] in plan["diff"]["removed"]
    # unmeasured contradicted entries keep their label instead of being laundered
    left = {e["name"]: e for e in plan["entries"]}
    for e in contra[1:]:
        assert left[e["name"]]["provenance"] == ab.PROV_CONTRADICTED


# --------------------------------------------------------------------------
# adoption
# --------------------------------------------------------------------------

def test_adoption_is_first_baseline_only(ctx):
    with pytest.raises(ValueError, match="already has a baseline"):
        ab.adopt(FAC, "8.0.3", {"x": "/api/v1/x/"})


def test_classify_legacy_labels_every_entry_against_the_evidence(ctx):
    _sweep(FAC, "9.9.4", {"a": _ep("/api/v1/a/"), "b": _ep("/api/v1/b/", verdict="absent")})
    _sweep(FAC, "9.9.5", {"c": _ep("/api/v1/c/")}, device="box2")
    v, entries, conflicts = ab.classify_legacy(FAC, "9.9.4", {
        "a": "/api/v1/a/", "b": "/api/v1/b/", "c": "/api/v1/c/", "d": "/api/v1/d/"})
    prov = {e["name"]: (e["provenance"], e["measured_on"]) for e in entries}
    assert prov == {"a": ("measured", "9.9.4"), "b": ("contradicted", "9.9.4"),
                    "c": ("carried", "9.9.5"), "d": ("legacy", "")}
    assert conflicts == []
    # adoption never drops a name: every map entry is in the baseline
    assert len(entries) == 4


def test_classify_legacy_reports_a_urn_the_evidence_contradicts(ctx):
    _sweep(FAC, "9.9.4", {"a": _ep("/api/v1/real/")})
    _v, entries, conflicts = ab.classify_legacy(FAC, "9.9.4", {"a": "/api/v1/old/"})
    assert conflicts == [{"name": "a", "map": "/api/v1/old/",
                          "evidence": "/api/v1/real/", "on": "9.9.4"}]
    assert entries[0]["provenance"] == "legacy"  # not "measured": it was not


# --------------------------------------------------------------------------
# export round-trip
# --------------------------------------------------------------------------

def test_export_round_trips_through_the_seal(ctx, tmp_path):
    path = ab.export(FAC, str(tmp_path))
    doc = ab.read_artifact(FAC, str(tmp_path))
    assert doc["sha256"] == ab.active(FAC).sha256
    # one entry per line: a promotion reads as a reviewable diff
    lines = open(path, encoding="utf-8").read().splitlines()
    assert sum(1 for ln in lines if ln.strip().startswith('{"name"')) == len(doc["entries"])


# --------------------------------------------------------------------------
# per-build resolution
# --------------------------------------------------------------------------

def test_resolve_at_authority_order(ctx):
    base = ab.artifact_map(FAC)
    names = sorted(base)
    measured, absent, override, disabled, assumed = names[:5]
    _sweep(FAC, "9.9.6", {measured: _ep("/api/v1/measured-here/"),
                          absent: _ep(base[absent], verdict="absent")})
    rows = _registry(FAC)
    rows[override].urn, rows[override].updated_by = "/api/v1/op/", "alice"
    rows[disabled].enabled, rows[disabled].updated_by = False, "bob"
    db.session.commit()

    r = lambda n, v="9.9.6": ab.resolve_at(FAC, n, v)  # noqa: E731
    assert (r(measured)["status"], r(measured)["urn"]) == ("measured", "/api/v1/measured-here/")
    assert (r(absent)["status"], r(absent)["urn"]) == ("absent", None)
    assert (r(override)["status"], r(override)["urn"]) == ("override", "/api/v1/op/")
    assert (r(disabled)["status"], r(disabled)["urn"]) == ("disabled", None)
    # an unmeasured build falls back to the baseline — and says it is an assumption
    got = r(assumed, "9.9.7")
    assert (got["status"], got["urn"]) == ("baseline", base[assumed])
    assert r("no_such_endpoint")["status"] == "absent"


# --------------------------------------------------------------------------
# drift check
# --------------------------------------------------------------------------

def test_check_is_clean_after_boot_and_reports_owned_drift(ctx):
    assert ab.check(FAC)["ok"] is True
    row = RegistryEndpoint.query.filter_by(product=FAC).order_by(RegistryEndpoint.name).first()
    row.urn = "/api/v1/drifted/"      # still baseline-owned: this is drift, not a fix
    db.session.commit()
    rep = ab.check(FAC)
    assert rep["ok"] is False and rep["registry"]["wrong_urn"] == [row.name]


def test_check_lists_operator_rows_without_calling_them_drift(ctx):
    row = RegistryEndpoint.query.filter_by(product=FAC).order_by(RegistryEndpoint.name).first()
    row.urn, row.updated_by = "/api/v1/op/", "alice"
    db.session.commit()
    rep = ab.check(FAC)
    assert rep["ok"] is True
    assert [o["name"] for o in rep["registry"]["overrides"]] == [row.name]


# --------------------------------------------------------------------------
# no-database fallback + fingerprinting
# --------------------------------------------------------------------------

def test_loader_without_a_database_serves_the_shipped_baseline():
    assert loader._shipped_registry() == ab.artifact_map("fortiweb")
    assert loader._fac_shipped_registry() == ab.artifact_map(FAC)


def test_fingerprinting_reads_the_registry_not_a_file(ctx):
    from app.services import device_identity as di
    keys = di._catalog_keys()
    assert set(keys) == set(ab.products())
    assert all(keys[p] for p in keys)
    snap = {"sections": {"x": {n: {} for n in sorted(keys[FAC])[:10]}}}
    assert di.fingerprint_product(snap) == FAC


# --------------------------------------------------------------------------
# migration + CLI wiring
# --------------------------------------------------------------------------

def test_migration_chains_after_apilib01_and_matches_the_models():
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = os.path.join(_ROOT, "migrations", "versions", "apibl01_api_baselines.py")
    spec = importlib.util.spec_from_file_location("apibl01", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.revision == "apibl01" and mod.down_revision == "apilib01"
    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()
            mod.upgrade()   # idempotent: create_all may have been first
        insp = sa.inspect(conn)
        for t in ("api_lib_baseline", "api_lib_baseline_entry"):
            assert ({c["name"] for c in insp.get_columns(t)}
                    == set(db.metadata.tables[t].columns.keys())), t


def test_cli_promote_is_a_dry_run_without_apply(ctx):
    _promotion_fixture()
    runner = ctx.test_cli_runner()
    res = runner.invoke(args=["apilib", "baseline", "promote", "--product", FAC,
                              "--build", "9.9.1"])
    assert res.exit_code == 0, res.output
    assert "+ auth_brand_new" in res.output and "dry run" in res.output
    assert ApiLibBaseline.query.filter_by(product=FAC).count() == 1


def test_cli_check_exits_nonzero_on_drift(ctx):
    runner = ctx.test_cli_runner()
    assert runner.invoke(args=["apilib", "baseline", "check", "--product", FAC]).exit_code == 0
    row = RegistryEndpoint.query.filter_by(product=FAC).first()
    row.urn = "/api/v1/drifted/"
    db.session.commit()
    res = runner.invoke(args=["apilib", "baseline", "check", "--product", FAC])
    assert res.exit_code == 1
    assert json.loads(res.output)[0]["registry"]["wrong_urn"] == [row.name]
