"""Guards for the local versioned SoT store (services.sot_store) and the git
retirement it replaces (2026-08-05).

The class of failure these exist to stop: the git-backed reports/ history grew
without bound at fleet scale (a repo receiving 90+ MB hourly), so it was
replaced with a content-addressed local store. If the dedup breaks the store
inherits the same unbounded growth; if the recording breaks the product loses
version history SILENTLY (a sync still succeeds — run.detail is the only
witness); if the seed/check lists still demand the retired git_bundle action,
every fresh install shows a permanent red no operator can clear.
"""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _snap(n=1, extra=None):
    body = {
        "device": "fwx", "appliance_id": 1,
        "generated_at": f"2026-08-05T00:0{n}:00",
        "total_objects": 2, "section_count": 1,
        "sections": {"system": {"interface": [
            {"name": "port1", "ip": f"10.0.0.{n}/24"},
            {"name": "port2", "ip": "192.0.2.1/24"},
        ]}},
        "errors": [],
    }
    if extra:
        body["sections"]["system"]["interface"].append(extra)
    return body


# ── identity / dedup ─────────────────────────────────────────────────────────

def test_unchanged_snapshot_mints_no_new_version(app):
    from app.services import sot_store
    with app.app_context():
        r1 = sot_store.record("fwx", _snap(1))
        assert r1["changed"] is True
        # Same config, different volatile fields: MUST dedup — this is the
        # property that keeps the store from growing with time.
        again = _snap(1)
        again["generated_at"] = "2026-09-01T10:00:00"
        again["errors"] = [{"endpoint": "x", "error": "transient"}]
        r2 = sot_store.record("fwx", again)
        assert r2["changed"] is False
        assert r2["version_id"] == r1["version_id"]
        assert len(sot_store.history("fwx")) == 1


def test_changed_snapshot_mints_a_new_version_and_blob(app):
    from app.services import sot_store
    with app.app_context():
        r1 = sot_store.record("fwx", _snap(1))
        r2 = sot_store.record("fwx", _snap(2))
        assert r2["changed"] is True and r2["version_id"] != r1["version_id"]
        hist = sot_store.history("fwx")
        assert len(hist) == 2
        # Both blobs exist and round-trip.
        loaded = sot_store.load(r1["version_id"])
        assert loaded["sections"]["system"]["interface"][0]["ip"] == "192.0.2.1/24"


def test_blob_is_gzip_canonical_json(app):
    from app.services import sot_store
    with app.app_context():
        r = sot_store.record("fwx", _snap(1))
        blob = sot_store._blob_path(r["sha256"])
        raw = gzip.open(blob, "rb").read()
        body = json.loads(raw)
        # Volatile keys are OUT of the stored identity.
        assert "generated_at" not in body and "errors" not in body


# ── diff ─────────────────────────────────────────────────────────────────────

def test_diff_reports_added_removed_changed(app):
    from app.services import sot_store
    with app.app_context():
        a = sot_store.record("fwx", _snap(1))
        newer = _snap(1, extra={"name": "port9", "ip": "192.0.2.9/24"})
        newer["sections"]["system"]["interface"][0]["ip"] = "192.0.2.99/24"
        b = sot_store.record("fwx", newer)
        d = sot_store.diff(a["version_id"], b["version_id"])
        assert d["ok"]
        assert any("port9" in p for p in d["added"])
        assert any("port1" in p for p in d["changed"])
        assert not d["removed"]
        det = {c["path"]: c for c in d["changed_detail"]}
        path = next(p for p in det if "port1" in p)
        assert {"field": "ip", "a": "192.0.2.1/24", "b": "192.0.2.99/24"} in \
            det[path]["fields"]


def test_diff_identical_versions(app):
    from app.services import sot_store
    with app.app_context():
        a = sot_store.record("fwx", _snap(1))
        b = sot_store.record("fwx", _snap(2))
        d = sot_store.diff(a["version_id"], a["version_id"])
        assert d["ok"] and d["identical"]
        d2 = sot_store.diff(a["version_id"], b["version_id"])
        assert d2["ok"] and not d2["identical"]


# ── retention ────────────────────────────────────────────────────────────────

def test_prune_keeps_newest_and_deletes_orphan_blobs(app, monkeypatch):
    from app.services import sot_store
    monkeypatch.setattr(sot_store, "_retention", lambda: (2, 0))
    with app.app_context():
        for n in range(1, 5):
            sot_store.record("fwx", _snap(n))
        hist = sot_store.history("fwx")
        assert len(hist) == 2, "retention must cap the version count"
        live = {h["sha256"] for h in hist}
        objects = sot_store.store_dir() / "objects"
        on_disk = {f.name[:-8] for f in objects.glob("*/*.json.gz")}
        assert on_disk == live, "orphan blobs must be deleted with their rows"


# ── integration: the harvest records automatically ───────────────────────────

def test_persist_snapshot_records_a_sot_version(app, tmp_path, monkeypatch):
    from app.models import Appliance, db
    from app.services import device_sync as dsync
    from app.services import sot_store
    monkeypatch.setenv("FORTINET_REPORTS_DIR", str(tmp_path))
    with app.app_context():
        a = Appliance(name="fw-sot", host="192.0.2.10", username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        run = dsync.persist_snapshot(a, _snap(1), source="import",
                                     publish=False, trigger="manual")
        assert run.status == "ok"
        assert "sot: new version" in (run.detail or "")
        assert len(sot_store.history("fw-sot")) == 1


def test_device_sync_no_longer_publishes_to_git():
    """Structural: the sync path must not commit reports/ to git any more —
    that is the unbounded-growth path this whole change retires."""
    src = (REPO / "app" / "services" / "device_sync.py").read_text()
    assert "git_publish" not in src


def test_reports_tree_lives_under_data(tmp_path, monkeypatch):
    from app.services import device_sync as dsync
    # Point the resolver's ROOT at a sandbox: calling it against the real
    # repo root would mkdir data/reports on a live node (it did, once).
    monkeypatch.setattr(dsync, "_repo_root", lambda: tmp_path)
    monkeypatch.delenv("FORTINET_REPORTS_DIR", raising=False)
    d = dsync._reports_dir()
    assert d == tmp_path / "data" / "reports"


# ── the retirement is coherent across surfaces ───────────────────────────────

def test_seed_and_checks_no_longer_demand_git_bundle():
    sys.path.insert(0, str(REPO / "deploy"))
    from satom_cli import cmd_checks, cmd_fix
    assert "git_bundle" not in cmd_checks.MIN_ACTIONS
    assert "git_bundle" not in {row[0] for row in cmd_fix.SEED_PLAN}
    assert "satom-git-publish.timer" not in cmd_checks.REQUIRED_UNITS


def test_installer_does_not_arm_the_retired_publisher():
    src = (REPO / "installers" / "install-satom.sh").read_text()
    assert "systemctl enable --now satom-git-publish.timer" not in src


def test_bundle_carries_the_sot_store(app, tmp_path, monkeypatch):
    """The pg_dump only carries the version INDEX — a bundle without the blobs
    restores history rows that point at nothing."""
    from app.services import system_backup as sb
    from app.services import sot_store
    with app.app_context():
        sot_store.record("fwx", _snap(1))
        # No Postgres in the suite: fake the dump step (writing the file the
        # real pg_dump would), keep the tar logic.
        def _fake_run(cmd, conn, timeout=600):
            for i, tok in enumerate(cmd):
                if tok == "-f":
                    Path(cmd[i + 1]).write_bytes(b"FAKEDUMP")
            return type("R", (), {"returncode": 0, "stderr": ""})()
        monkeypatch.setattr(sb, "_run", _fake_run)
        monkeypatch.setattr(sb, "backups_dir", lambda: tmp_path)
        monkeypatch.setattr(sb, "_conn_from_app", lambda: {
            "host": "x", "port": "5432", "user": "u", "password": "",
            "dbname": "d"})
        import tarfile

        # pg_dump is faked, so db.dump never appears; create_backup only tars
        # what exists — seed a stand-in so the bundle is non-trivial.
        res = sb.create_backup(include_reports=True, label="test")
        assert res["ok"], res
        with tarfile.open(res["path"], "r:gz") as tar:
            names = tar.getnames()
        assert any("/sot/objects/" in n for n in names), names


# ── page routes (auth'd) ─────────────────────────────────────────────────────

def test_system_backup_page_renders_sot_card(app, client):
    from conftest import admin_user_id, login
    from app.services import sot_store
    with app.app_context():
        sot_store.record("fwx", _snap(1))
    login(client, admin_user_id(app))
    r = client.get("/system-backup/")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "Versioned SoT store" in html
    assert "Device config versions (SoT store)" in html
    # The git-SoT surfaces are gone from the page.
    assert "Git source of truth" not in html
    assert "Publish device JSON to git" not in html


def test_compare_route_diffs_two_versions(app, client):
    from conftest import admin_user_id, login
    from app.services import sot_store
    with app.app_context():
        a = sot_store.record("fwx", _snap(1))
        b = sot_store.record("fwx", _snap(2))
    login(client, admin_user_id(app))
    r = client.get(f"/system-backup/compare?ref_a={a['version_id']}"
                   f"&ref_b={b['version_id']}")
    assert r.status_code == 200
    assert "changed" in r.get_data(as_text=True)
