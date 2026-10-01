"""Guards for API packs (services/api_pack.py, docs/api-library.md §11).

A pack is published. Every test here pins a way it could publish something it
must not (a configuration value, a device name, a serial), import something it
must not (an unsigned or altered pack), or overwrite what the node measured
itself.
"""
from __future__ import annotations

import base64
import gzip
import json
import os
import tarfile

import pytest

from app.extensions import db
from app.models_apilib import (ApiLibBuild, ApiLibEndpoint, ApiLibEndpointFact,
                               ApiLibEvidence, ApiLibField, ApiLibFieldFact, ApiLibSpan)
from app.services import api_library as lib
from app.services import api_pack as ap
from app.services import release_notes as rn

SECRET = "S3cret-config-value"
DEVICE = "lab-fwb-01"
SERIAL = "FVVM01TESTSERIAL"


@pytest.fixture()
def env(app, tmp_path, monkeypatch):
    from app.services import field_catalog
    schemas = tmp_path / "field_schemas"
    (schemas / "fortiweb" / "7.6").mkdir(parents=True)
    (schemas / "fortiweb" / "7.6" / "admin.json").write_text(json.dumps(
        {"object": "admin", "fields": [{"name": "name", "type": "text"}],
         "source": "live:fw1@7.6"}))
    (schemas / "fortiweb" / "7.6" / "_coverage.json").write_text(json.dumps(
        {"appliance": "fw1", "covered": 1}))
    monkeypatch.setattr(field_catalog, "SCHEMA_ROOT", str(schemas))
    app.config["API_PACK_DIR"] = str(tmp_path / "apipacks")
    app.config["FORTIWEB_FIELD_OVERLAY"] = str(tmp_path / "overlay.json")
    seed = os.urandom(32)
    key = tmp_path / "test.key"
    key.write_text("satom-ed25519-seed %s\n" % base64.b64encode(seed).decode())
    trust = tmp_path / "trust"
    trust.mkdir()
    (trust / "test.pub").write_text(
        ap.up.format_public_key(ap.up.ed25519_public_from_seed(seed), "test") + "\n")
    monkeypatch.setattr(ap.up, "trust_store_problem", lambda _d=None: None)
    with app.app_context():
        yield {"tmp": tmp_path, "key": str(key), "trust": str(trust), "schemas": schemas}


def _sweep(version="7.6.8", device=DEVICE, appliance_id=9, serial=SERIAL):
    snap = {"firmware": version, "generated_at": "2026-09-15T10:00:00",
            "endpoint_status": {"system_admin": {"urn": "/api/v2.0/cmdb/system/admin",
                                                 "section": "System", "verdict": "ok",
                                                 "rows": 1}},
            "sections": {"System": {"system_admin": [
                {"name": "admin", "password": SECRET, "trusthost": "192.0.2.7/32"}]}}}
    dev = {"appliance_id": appliance_id, "name": device, "serial": serial,
           "model": "FortiWeb-VM", "hw_type": "vm", "firmware_raw": version}
    doc = lib.evidence_from_sweep("fortiweb", snap, dev, "rediscovery:%d@%s" % (appliance_id, version))
    return lib.ingest(doc, raw=json.dumps(snap).encode())


def _schema_with_positional_witness():
    return lib.ingest({
        "product": "fortiweb", "source": "schema", "captured_at": "2026-06-28",
        "origin_ref": "field_schemas:fortiweb/8.0", "device": None,
        "scope": {"kind": "line", "line": "8.0"}, "healthy": True, "skip_reason": "",
        "endpoints": {"system_dns": {"urn": "", "section": "", "verdict": "ok",
                                     "rows": None, "fields": {"primary": {"type": "str"}},
                                     "witnesses": ["fw1"]}},
        "summary": {"objects": {"dns": {"source": "live:fw1@8.0"}}}})


def _release_notes(env, versions=("7.6.8",), content="full vendor prose"):
    from app.services import release_corpus
    rn.save_db(rn.ReleaseNotesDB(
        generated_at="2026-09-14", versions=list(versions),
        issues=[rn.ReleaseIssue(product="fortiweb", version=v, status="known",
                                bug_id="1%s" % i, description="desc %s" % v)
                for i, v in enumerate(versions)],
        sections=[rn.ReleaseSection(product="fortiweb", version=v, section="whats-new",
                                    title="What's new", content=content)
                  for v in versions]), root=release_corpus.root())


def _payloads(path) -> str:
    out = []
    with tarfile.open(path) as tf:
        for m in tf.getmembers():
            if m.name.endswith(".json.gz"):
                out.append(gzip.decompress(tf.extractfile(m).read()).decode("utf-8"))
    return "\n".join(out)


def _export(env, version="1.0.0", **kw):
    return ap.export_pack(env["tmp"] / "out", version, sign_key=env["key"], **kw)


def _wipe_library():
    for model in (ApiLibSpan, ApiLibFieldFact, ApiLibField, ApiLibEndpointFact,
                  ApiLibEndpoint, ApiLibEvidence, ApiLibBuild):
        db.session.query(model).delete()
    db.session.commit()


# --------------------------------------------------------------------------
# export: nothing of ours leaves
# --------------------------------------------------------------------------

def test_a_sweep_ships_field_names_and_types_never_a_configuration_value(env):
    _sweep()
    res = _export(env)
    text = _payloads(res["path"])
    assert SECRET not in text and "192.0.2.7" not in text
    assert '"password": {"type": "str"}' in text          # the NAME survives
    assert DEVICE not in text and SERIAL not in text
    assert ap.WITNESS_PREFIX in text


def test_a_witness_known_only_by_position_is_pseudonymised(env):
    """Regression: the first real export leaked ``fw1`` — a deleted box named
    only inside a schema document, so no deny-list knew it."""
    _schema_with_positional_witness()
    text = _payloads(_export(env)["path"])
    assert '"fw1"' not in text and "live:fw1@" not in text and "fw1@" not in text


def test_the_same_device_gets_the_same_pseudonym_in_every_pack(env):
    _sweep()
    a = _payloads(_export(env, "1.0.0")["path"])
    b = _payloads(_export(env, "1.0.1")["path"])
    import re
    assert set(re.findall(r"witness-[0-9a-f]{10}", a)) == set(re.findall(r"witness-[0-9a-f]{10}", b))


def test_the_export_is_refused_and_nothing_written_when_the_scrub_misses(env, monkeypatch):
    _schema_with_positional_witness()
    monkeypatch.setattr(ap._Identity, "_slot", lambda self, k, v, p: v)
    with pytest.raises(ap.PackError, match="identifying data survived"):
        _export(env)
    assert not list((env["tmp"] / "out").glob("*.tar.gz"))


def test_a_row_whose_blob_no_longer_reproduces_its_hash_is_skipped_not_shipped(env):
    eid = _sweep()["evidence_id"]
    ev = db.session.get(ApiLibEvidence, eid)
    snap = json.loads(gzip.decompress(ev.raw_gz))
    snap["endpoint_status"]["system_admin"]["verdict"] = "absent"
    ev.raw_gz = gzip.compress(json.dumps(snap).encode())
    db.session.commit()
    _release_notes(env)
    res = _export(env)
    assert any(s.get("evidence_id") == eid and "hash" in s["reason"] for s in res["skipped"])
    assert res["by_section"]["library"] == 0


def test_evidence_imported_from_a_pack_is_never_re_exported(env):
    _sweep()
    p = _export(env)["path"]
    _wipe_library()
    ap.import_pack(p, trust_dir=env["trust"])
    res = _export(env, "1.0.1")
    assert res["by_section"]["library"] == 0


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------

def test_an_unsigned_pack_is_refused(env):
    _sweep()
    p = ap.export_pack(env["tmp"] / "out", "1.0.0")
    with pytest.raises(ap.PackError, match="unsigned"):
        ap.inspect_pack(p["path"], trust_dir=env["trust"])


def test_an_altered_pack_is_refused(env):
    _sweep()
    p = _export(env)["path"]
    work = env["tmp"] / "alter"
    with tarfile.open(p) as tf:
        tf.extractall(work)
    top = next(work.iterdir())
    victim = next(top.rglob("library/*/*.json.gz"))
    doc = json.loads(gzip.decompress(victim.read_bytes()))
    doc["endpoints"]["system_admin"]["verdict"] = "absent"
    victim.write_bytes(gzip.compress(json.dumps(doc).encode()))
    with tarfile.open(p, "w:gz") as tf:
        tf.add(top, arcname=top.name)
    with pytest.raises(ap.PackError, match="sha256 mismatch"):
        ap.inspect_pack(p, trust_dir=env["trust"])


# --------------------------------------------------------------------------
# import: adds, never overwrites
# --------------------------------------------------------------------------

def test_a_fresh_node_imports_everything_and_a_second_import_is_a_no_op(env):
    _sweep()
    _release_notes(env)
    p = _export(env)["path"]
    _wipe_library()
    (env["tmp"] / "field_schemas" / "fortiweb" / "7.6" / "admin.json").unlink()
    from app.services import release_corpus
    os.remove(rn.db_path(release_corpus.root()))

    first = ap.import_pack(p, trust_dir=env["trust"])
    assert first["errors"] == 0 and first["imported"] >= 3
    ev = ApiLibEvidence.query.one()
    assert ev.origin_ref.startswith(ap.ORIGIN_PREFIX) and ev.device_serial == ""
    assert ApiLibEndpointFact.query.count() == 1       # folded into facts, not just stored
    corpus = rn.load_db(root=release_corpus.root())
    assert corpus.sections[0].content == "full vendor prose"
    assert (env["tmp"] / "field_schemas" / "fortiweb" / "7.6" / "admin.json").exists()

    second = ap.import_pack(p, trust_dir=env["trust"])
    assert second["imported"] == 0
    assert {i["state"] for i in second["items"]} <= {ap.ST_PRESENT}


def test_a_pack_sweep_of_a_build_this_node_measured_itself_is_skipped(env):
    _sweep()
    p = _export(env)["path"]
    _wipe_library()
    _sweep(device="customer-box", appliance_id=1, serial="")    # the node's own sweep
    res = ap.import_pack(p, trust_dir=env["trust"], sections=["library"])
    assert [i["state"] for i in res["items"]] == [ap.ST_LOCAL]
    assert ApiLibEvidence.query.count() == 1


def test_release_notes_add_missing_versions_and_never_replace_local_ones(env):
    _release_notes(env, versions=("7.6.7", "7.6.8"), content="from the pack")
    p = _export(env)["path"]
    from app.services import release_corpus
    _release_notes(env, versions=("7.6.8",), content="scanned locally")
    res = ap.import_pack(p, trust_dir=env["trust"], sections=["docs"])
    rec = next(i for i in res["items"] if i["id"].endswith("release-notes/fortiweb"))
    assert rec["result"]["versions"] == ["7.6.7"]
    corpus = rn.load_db(root=release_corpus.root())
    by_v = {s.version: s.content for s in corpus.sections}
    assert by_v == {"7.6.7": "from the pack", "7.6.8": "scanned locally"}


def test_selection_by_item_imports_only_that_item(env):
    _sweep()
    _release_notes(env)
    p = _export(env)["path"]
    _wipe_library()
    items = ap.inspect_pack(p, trust_dir=env["trust"])["items"]
    lib_id = next(i["id"] for i in items if i["section"] == "library")
    res = ap.import_pack(p, trust_dir=env["trust"], ids=[lib_id])
    assert [i["id"] for i in res["items"]] == [lib_id]
    with pytest.raises(ap.PackError, match="not in this pack"):
        ap.import_pack(p, trust_dir=env["trust"], ids=["library/nope"])
