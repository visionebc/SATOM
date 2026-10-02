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


# --------------------------------------------------------------------------
# where packs come from: shipped with the release, or uploaded
# --------------------------------------------------------------------------

@pytest.fixture()
def shipped(env, app):
    """A signed pack in the release's api-packs/."""
    _sweep()
    _release_notes(env)
    built = _export(env, "9.9.9")["path"]
    d = env["tmp"] / "api-packs"
    d.mkdir()
    os.replace(built, d / "satom-apipack-9.9.9.tar.gz")
    app.config["API_PACK_SHIPPED_DIR"] = str(d)
    app.config["API_PACK_UPLOAD_DIR"] = str(env["tmp"] / "uploads")
    return d / "satom-apipack-9.9.9.tar.gz"


def test_the_release_pack_and_uploads_are_listed_by_source(env, shipped):
    import io
    ap.save_upload(io.BytesIO(shipped.read_bytes()), "satom-apipack-9.9.8.tar.gz")
    got = {(p["source"], p["name"]) for p in ap.list_packs()}
    assert got == {("shipped", "satom-apipack-9.9.9.tar.gz"),
                   ("uploaded", "satom-apipack-9.9.8.tar.gz")}
    assert ap.resolve_pack("shipped", "satom-apipack-9.9.9.tar.gz") == shipped


@pytest.mark.parametrize("name", ["../../srv/x.tar.gz", "/srv/x", "evil.tar.gz",
                                  "satom-update-1.0.0.tar.gz", "satom-apipack-x/../y.tar.gz"])
def test_a_name_that_is_not_a_pack_never_reaches_the_filesystem(env, shipped, name):
    with pytest.raises(ap.PackError, match="not an API pack name"):
        ap.resolve_pack("shipped", name)


def test_an_unknown_source_is_refused(env, shipped):
    with pytest.raises(ap.PackError, match="unknown pack source"):
        ap.resolve_pack("/srv", shipped.name)


def test_an_oversized_or_misnamed_upload_leaves_nothing_behind(env, shipped, monkeypatch):
    import io
    with pytest.raises(ap.PackError, match="not an API pack name"):
        ap.save_upload(io.BytesIO(b"x"), "notes.txt")
    monkeypatch.setattr(ap, "MAX_UPLOAD_BYTES", 10)
    with pytest.raises(ap.PackError, match="larger than"):
        ap.save_upload(io.BytesIO(b"x" * 64), "satom-apipack-1.0.0.tar.gz")
    assert list(ap.upload_dir().iterdir()) == []


def test_uploads_keep_only_the_newest(env, shipped, monkeypatch):
    import io
    monkeypatch.setattr(ap, "KEEP_UPLOADS", 2)
    for i in range(4):
        ap.save_upload(io.BytesIO(b"x"), "satom-apipack-1.0.%d.tar.gz" % i)
        os.utime(ap.upload_dir() / ("satom-apipack-1.0.%d.tar.gz" % i), (i + 1, i + 1))
    assert sorted(p.name for p in ap.upload_dir().iterdir()) == [
        "satom-apipack-1.0.2.tar.gz", "satom-apipack-1.0.3.tar.gz"]


def test_import_reports_progress_per_item_and_logs_the_run(env, shipped):
    _wipe_library()
    seen = []
    res = ap.import_pack(shipped, trust_dir=env["trust"], actor="ops",
                         progress=lambda d, t, i: seen.append((d, t, i)))
    total = len(res["items"])
    assert seen[0] == (0, total, res["items"][0]["id"])
    assert seen[-1] == (total, total, None)
    assert len(seen) == total + 1
    hist = ap.import_history()
    assert hist[0]["version"] == "9.9.9" and hist[0]["actor"] == "ops"
    assert hist[0]["imported"] == res["imported"] > 0


# --------------------------------------------------------------------------
# Software Update: API library packs section
# --------------------------------------------------------------------------

@pytest.fixture()
def page(env, shipped, app, client, monkeypatch, tmp_path):
    from conftest import admin_user_id, login
    from app.services import jobs as jobsvc
    monkeypatch.setattr(ap, "TRUST_DIR", env["trust"])
    monkeypatch.setenv("SATOM_JOBS_DIR", str(tmp_path / "jobs"))
    # The worker runs inline, so the test reads a finished job; an exception
    # ends the job the way run_async's thread does.
    def inline(a, jid, w):
        try:
            w(a, jid)
        except Exception as exc:  # noqa: BLE001
            jobsvc.finish_error(jid, "%s: %s" % (type(exc).__name__, exc))
    monkeypatch.setattr(jobsvc, "run_async", inline)
    login(client, admin_user_id(app))
    return client


def _inspect(page, shipped):
    return page.get("/self-update/apipack/inspect?source=shipped&name=" + shipped.name)


def test_the_page_inspects_the_shipped_pack(page, shipped):
    r = _inspect(page, shipped)
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()
    assert d["version"] == "9.9.9" and d["refusal"] == ""
    # On the node it was built on nothing is new: its own sweep is "local".
    assert {i["state"] for i in d["items"]} <= {"present", "local"}
    assert any(i["state"] == "local" for i in d["items"])


def test_a_bad_pack_name_is_a_400_with_the_reason(page):
    r = page.get("/self-update/apipack/inspect?source=shipped&name=../../srv/x")
    assert r.status_code == 400 and "not an API pack name" in r.get_json()["error"]


def test_the_page_imports_the_ticked_items_as_a_job(page, shipped):
    from app.services import jobs as jobsvc
    _wipe_library()
    items = _inspect(page, shipped).get_json()["items"]
    lib_id = next(i["id"] for i in items if i["section"] == "library")
    r = page.post("/self-update/apipack/import",
                  data={"source": "shipped", "name": shipped.name, "ids": [lib_id]})
    assert r.status_code == 202, r.get_data(as_text=True)
    job = jobsvc.get_job(r.get_json()["job_id"])
    assert job["status"] == "success", job
    assert [i["id"] for i in job["result"]["items"]] == [lib_id]
    assert job["result"]["imported"] == 1
    assert ApiLibEvidence.query.count() == 1


def test_a_failed_item_turns_the_job_red_but_keeps_the_results(page, shipped, monkeypatch):
    from app.services import jobs as jobsvc
    _wipe_library()

    def boom(*a, **k):
        raise RuntimeError("disk full")
    monkeypatch.setattr(ap, "_import_one", boom)
    items = _inspect(page, shipped).get_json()["items"]
    r = page.post("/self-update/apipack/import", data={
        "source": "shipped", "name": shipped.name,
        "ids": [i["id"] for i in items if i["state"] == "new"][:1]})
    job = jobsvc.get_job(r.get_json()["job_id"])
    assert job["status"] == "error" and "1 of 1 item(s) failed" in job["error"]
    assert job["result"]["items"][0]["error"].startswith("RuntimeError")


def test_the_standby_refuses_to_import(page, shipped, monkeypatch):
    from app.services import self_update as su
    monkeypatch.setattr(su, "node_role", lambda: "standby")
    r = page.post("/self-update/apipack/import",
                  data={"source": "shipped", "name": shipped.name, "ids": ["x"]})
    assert r.status_code == 409 and "PRIMARY" in r.get_json()["error"]
    assert "STANDBY" in _inspect(page, shipped).get_json()["refusal"]


def test_an_import_with_nothing_ticked_is_refused(page, shipped):
    r = page.post("/self-update/apipack/import", data={"source": "shipped", "name": shipped.name})
    assert r.status_code == 400


def test_upload_then_delete_through_the_page(page, shipped):
    import io
    r = page.post("/self-update/apipack/upload", data={
        "apipack": (io.BytesIO(shipped.read_bytes()), "satom-apipack-9.9.7.tar.gz")},
        content_type="multipart/form-data")
    assert r.status_code == 302 and "apipack=uploaded" in r.headers["Location"]
    assert (ap.upload_dir() / "satom-apipack-9.9.7.tar.gz").exists()
    r = page.post("/self-update/apipack/delete", data={"name": "satom-apipack-9.9.7.tar.gz"})
    assert r.status_code == 302
    assert not (ap.upload_dir() / "satom-apipack-9.9.7.tar.gz").exists()


def test_the_section_is_on_the_update_page_and_wired_to_its_routes():
    from pathlib import Path
    tpl = (Path(__file__).resolve().parents[1]
           / "app/templates/self_update/index.html").read_text()
    for needle in ('id="api-packs"', "self_update.apipack_inspect",
                   "self_update.apipack_import", "self_update.apipack_upload",
                   "data-apk-filter", "apkFollow(d.job_id)", "'/jobs/'"):
        assert needle in tpl, needle
    import inspect
    from app.views import self_update as view
    assert "api_packs=_api_pack_state()" in inspect.getsource(view.index)


# --------------------------------------------------------------------------
# the installer imports the release's pack
# --------------------------------------------------------------------------

def _installer_block():
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "installers/install-satom.sh").read_text()
    start = src.index("# [SATOM-APIPACK]")
    return src, src[start:src.index("\nelse\n", start)]


def test_the_installer_imports_the_shipped_pack_after_the_health_check():
    src, block = _installer_block()
    assert src.index("# [SATOM-APIPACK]") > src.index('if [ "$HEALTH" = ok ]; then')
    assert "execute apipack import" in block
    assert '"$ROLE" != "secondary"' in block, "a secondary's database is read-only"
    assert "SATOM_API_PACK" in block and "SATOM_API_PACK_PRODUCTS" in block


def test_the_installer_pack_step_never_prompts_and_never_fails_the_install():
    _, block = _installer_block()
    code = "\n".join(l for l in block.splitlines() if not l.strip().startswith("#"))
    assert "ask " not in code and "read " not in code, \
        "a new prompt shifts every existing answer file by one line"
    assert "die " not in code, "the install is complete here; a pack is a warning"


def test_the_repository_carries_the_api_packs_folder():
    from pathlib import Path
    readme = Path(__file__).resolve().parents[1] / "api-packs" / "README.md"
    assert readme.is_file()
    assert "satom execute apipack import" in readme.read_text()


# --------------------------------------------------------------------------
# api-packs/ keeps every release's pack (2026-10-02)
# --------------------------------------------------------------------------

def test_shipped_packs_are_ordered_by_version_not_by_mtime(env, shipped):
    import shutil as _sh
    for v in ("9.9.10", "9.9.2"):
        _sh.copy(shipped, shipped.parent / ("satom-apipack-%s.tar.gz" % v))
    for p in shipped.parent.iterdir():
        os.utime(p, (1, 1))     # a checkout gives every file the same mtime
    got = [p["version"] for p in ap.list_packs() if p["source"] == "shipped"]
    assert got == ["9.9.10", "9.9.9", "9.9.2"], "9.9.10 sorts after 9.9.9 as text"


def test_the_newest_shipped_pack_is_pending_until_a_full_import(env, shipped):
    import shutil as _sh
    newest = shipped.parent / "satom-apipack-9.9.10.tar.gz"
    _sh.copy(shipped, newest)
    assert ap.pending_shipped()["name"] == newest.name
    _wipe_library()
    ap.import_pack(newest, trust_dir=env["trust"])
    assert ap.pending_shipped() is None
    # A full pass where everything is already present still counts: otherwise
    # the notice could never go away on the node that built the pack.
    _sh.rmtree(ap.pack_dir() / "imports")
    res = ap.import_pack(newest, trust_dir=env["trust"])
    assert res["imported"] == 0
    assert ap.pending_shipped() is None


def test_the_page_shows_the_pending_notice(page, shipped):
    html = page.get("/self-update/").get_data(as_text=True)
    assert 'id="apk-pending"' in html and shipped.name in html


def test_the_repository_keeps_every_release_pack():
    from pathlib import Path
    d = Path(__file__).resolve().parents[1] / "api-packs"
    packs = sorted(p.name for p in d.glob("satom-apipack-*.tar.gz"))
    assert len(packs) >= 2, "api-packs/ must keep older releases' packs, not replace them"
    for p in packs:
        assert (d / (p + ".sha256")).is_file(), "%s has no .sha256" % p
