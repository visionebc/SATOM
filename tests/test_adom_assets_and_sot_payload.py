"""The change log became permanent and the payload learned to leave.

Why this file exists
--------------------
Nothing failed before this change either. ``prune()`` deleted index rows and
that was the documented behaviour; the page rendered; the suite was green. What
was wrong is that the row IS the change log — the list an operator walks back
through to find the value a parameter used to have — and the local-retention
policy the operator asked for (one day) would have destroyed it inside a day
while every byte sat safely on the backup server, unreachable, because
``load()`` and ``diff()`` only ever opened the local file.

So the guards below are about the SEPARATION of two lifetimes, and about the
one ordering the whole feature rests on: **confirm off-box, then delete.** A
listing that fails must read as "nothing is off-box" and evacuate nothing —
never as permission to delete.

Every stub here is placed at the SFTP boundary (``backup_server.dir_inventory``
/ ``fetch_file`` / ``system_inventory``), never on the functions under test.
Patching ``sot_store.remote_blob_names`` would have tested the stub.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
from datetime import datetime, timedelta

import pytest

from tests.conftest import admin_user_id, login

ROOT = pathlib.Path(__file__).resolve().parents[1]


# --------------------------------------------------------------- helpers --

def _snap(marker: str = "a", *, sections=None) -> dict:
    """A snapshot whose identity moves when *marker* moves."""
    return {
        "device": "dev1", "generated_at": "2026-01-01T00:00:00",
        "total_objects": 1, "section_count": 1,
        "sections": sections or {"System": {"global": [{"name": marker}]}},
    }


def _blob_name(store, version_id: int) -> str:
    row = store.db_get(version_id)
    return f"{row.sha256}.json.gz"


def _fake_server(monkeypatch, *, names=(), payloads=None, reachable=True):
    """Stub the SFTP boundary. *names* is what the server holds."""
    from app.services import backup_server, settings_store

    monkeypatch.setattr(settings_store, "backup_server",
                        lambda reveal_secret=False: {
                            "configured": True, "host": "fm.example",
                            "system_path": "/system", "config_path": "/configs",
                            "firmware_path": "/firmware", "port": 22,
                            "username": "bk", "password": "", "password_enc": ""},
                        raising=False)

    def _dir_inventory(path):
        return {"configured": True, "reachable": reachable, "host": "fm.example",
                "path": path, "error": "",
                "files": [{"name": n, "size": 1, "mtime": "2026-01-01 00:00"}
                          for n in names] if reachable else []}

    def _fetch_file(path, filename):
        if payloads is None or filename not in payloads:
            raise IOError("no such file")
        return payloads[filename]

    monkeypatch.setattr(backup_server, "dir_inventory", _dir_inventory)
    monkeypatch.setattr(backup_server, "fetch_file", _fetch_file)


def _record_series(store, device: str, markers, *, age_days=None):
    """Record one version per marker, optionally back-dating each."""
    from app.extensions import db
    from app.models_sot import SotVersion
    ids = []
    for i, m in enumerate(markers):
        res = store.record(device, _snap(m))
        ids.append(res["version_id"])
        if age_days:
            row = db.session.get(SotVersion, res["version_id"])
            row.taken_at = datetime.utcnow() - timedelta(days=age_days[i])
    db.session.commit()
    return ids


# ================================================================= PHASE 1 ==
#                       the index is permanent, the payload is not

def test_prune_never_deletes_an_index_row(app, monkeypatch):
    """THE regression guard for the whole change.

    Retention set as tight as it goes, every blob confirmed off-box, prune run:
    the payload must leave and the change log must be intact. A prune that
    removes rows deletes the history it was asked to make retrievable.
    """
    from app.services import settings_store, sot_store
    from app.models_sot import SotVersion
    with app.app_context():
        ids = _record_series(sot_store, "dev1", "abcde",
                             age_days=[40, 30, 20, 10, 0])
        names = [_blob_name(sot_store, i) for i in ids]
        _fake_server(monkeypatch, names=names)
        settings_store.save_sot_local_policy(1, 1)
        sot_store.prune("dev1")
        assert SotVersion.query.filter_by(device="dev1").count() == 5, \
            "prune deleted index rows — that IS the change log"


def test_an_unreachable_server_evacuates_nothing(app, monkeypatch):
    """The single ordering the feature rests on. A failed listing must read as
    "nothing is off-box", never as permission to delete."""
    from app.services import settings_store, sot_store
    with app.app_context():
        ids = _record_series(sot_store, "dev1", "abcd", age_days=[40, 30, 20, 0])
        _fake_server(monkeypatch, names=[_blob_name(sot_store, i) for i in ids],
                     reachable=False)
        settings_store.save_sot_local_policy(1, 1)
        res = sot_store.evacuate("dev1")
        assert res["evacuated"] == 0, "deleted payload the server never confirmed"
        for i in ids:
            assert sot_store.load(i) is not None, "a snapshot was lost"


def test_a_blob_the_server_does_not_hold_is_kept(app, monkeypatch):
    """Per-blob, not per-server: the listing succeeded, this ONE file is
    missing from it. Deleting it would be data loss with a green connection."""
    from app.services import settings_store, sot_store
    with app.app_context():
        ids = _record_series(sot_store, "dev1", "abcd", age_days=[40, 30, 20, 0])
        names = [_blob_name(sot_store, i) for i in ids]
        _fake_server(monkeypatch, names=names[1:])       # the oldest is absent
        settings_store.save_sot_local_policy(1, 1)
        res = sot_store.evacuate("dev1")
        assert res["kept"] >= 1
        assert sot_store._blob_path(sot_store.db_get(ids[0]).sha256).exists(), \
            "a blob the server does not hold was deleted anyway"


def test_evacuation_frees_the_disk_and_stamps_the_row(app, monkeypatch):
    from app.services import settings_store, sot_store
    with app.app_context():
        ids = _record_series(sot_store, "dev1", "abcd", age_days=[40, 30, 20, 0])
        _fake_server(monkeypatch, names=[_blob_name(sot_store, i) for i in ids])
        settings_store.save_sot_local_policy(1, 1)
        res = sot_store.evacuate("dev1")
        assert res["evacuated"] >= 2 and res["bytes_freed"] > 0
        oldest = sot_store.db_get(ids[0])
        assert oldest.evacuated_at is not None, \
            "the payload left and the row still claims it is local"
        assert not sot_store._blob_path(oldest.sha256).exists()


def test_the_newest_versions_stay_local_whatever_their_age(app, monkeypatch):
    """Default 2, not 1: a diff needs a version AND the one before it, and
    "what changed in the last harvest" is the most used view in the product."""
    from app.services import settings_store, sot_store
    with app.app_context():
        ids = _record_series(sot_store, "dev1", "abcd", age_days=[40, 30, 20, 10])
        _fake_server(monkeypatch, names=[_blob_name(sot_store, i) for i in ids])
        settings_store.save_sot_local_policy(2, 1)
        sot_store.evacuate("dev1")
        for keep in ids[-2:]:
            assert sot_store._blob_path(sot_store.db_get(keep).sha256).exists(), \
                "the newest payload was evacuated despite the version floor"


def test_an_evacuated_version_still_opens(app, monkeypatch):
    """Without the fetch-back the policy amputates history silently: the row
    lists the version, the page offers to open it, and the answer is nothing."""
    from app.services import settings_store, sot_store
    with app.app_context():
        ids = _record_series(sot_store, "dev1", "abcd", age_days=[40, 30, 20, 0])
        blobs = {}
        for i in ids:
            sha = sot_store.db_get(i).sha256
            blobs[f"{sha}.json.gz"] = sot_store._blob_path(sha).read_bytes()
        _fake_server(monkeypatch, names=list(blobs), payloads=blobs)
        settings_store.save_sot_local_policy(1, 1)
        sot_store.evacuate("dev1")
        assert sot_store.db_get(ids[0]).evacuated_at is not None
        snap = sot_store.load(ids[0])
        assert snap and snap["sections"]["System"]["global"][0]["name"] == "a", \
            "an evacuated version could not be read back"


def test_a_diff_spans_an_evacuated_version(app, monkeypatch):
    from app.services import settings_store, sot_store
    with app.app_context():
        ids = _record_series(sot_store, "dev1", "abcd", age_days=[40, 30, 20, 0])
        blobs = {}
        for i in ids:
            sha = sot_store.db_get(i).sha256
            blobs[f"{sha}.json.gz"] = sot_store._blob_path(sha).read_bytes()
        _fake_server(monkeypatch, names=list(blobs), payloads=blobs)
        settings_store.save_sot_local_policy(1, 1)
        sot_store.evacuate("dev1")
        d = sot_store.diff(ids[0], ids[-1])
        assert d["ok"] is True and "blob missing" not in str(d.get("error", "")), \
            "diff against an evacuated version reports the blob as lost: %r" % d


def test_a_server_that_returns_the_wrong_bytes_is_refused(app, monkeypatch):
    """The filename is the hash. Adopting unverified bytes under that name
    would poison the content-addressed store for every version sharing it."""
    from app.services import settings_store, sot_store
    with app.app_context():
        ids = _record_series(sot_store, "dev1", "abcd", age_days=[40, 30, 20, 0])
        sha = sot_store.db_get(ids[0]).sha256
        names = [_blob_name(sot_store, i) for i in ids]
        poison = {f"{sha}.json.gz": gzip.compress(b'{"sections": {"evil": 1}}')}
        _fake_server(monkeypatch, names=names, payloads=poison)
        settings_store.save_sot_local_policy(1, 1)
        sot_store.evacuate("dev1")
        assert sot_store.load(ids[0]) is None, \
            "bytes that do not hash to their own name were adopted"
        assert not sot_store._blob_path(sha).exists(), \
            "the poisoned payload was written into the store"


def test_a_returning_configuration_clears_the_evacuated_flag(app, monkeypatch):
    """A device that reverts re-writes a blob that had left. A row still
    flagged evacuated sends the next read to the network for a local file."""
    from app.services import settings_store, sot_store
    with app.app_context():
        ids = _record_series(sot_store, "dev1", "abcd", age_days=[40, 30, 20, 0])
        _fake_server(monkeypatch, names=[_blob_name(sot_store, i) for i in ids])
        settings_store.save_sot_local_policy(1, 1)
        sot_store.evacuate("dev1")
        assert sot_store.db_get(ids[0]).evacuated_at is not None
        sot_store.record("dev1", _snap("a"))           # back to the old config
        assert sot_store.db_get(ids[0]).evacuated_at is None, \
            "the payload is local again and the row still says it is off-box"


def test_a_failed_push_evacuates_nothing(app, monkeypatch):
    from app.services import sot_store
    with app.app_context():
        _record_series(sot_store, "dev1", "abc", age_days=[40, 30, 0])
        monkeypatch.setattr(sot_store, "push_to_backup_server",
                            lambda: {"ok": False, "detail": "server down"})
        called = []
        monkeypatch.setattr(sot_store, "evacuate",
                            lambda *a, **k: called.append(1) or {})
        res = sot_store.offload()
        assert res["ok"] is False and not called, \
            "payload was evacuated after a push that failed"


# ----------------------------------------------- the policy is per ADOM --

def test_each_adom_gets_its_own_policy(app):
    """A FortiAnalyzer snapshot is ~6 MB raw where a FortiWeb's is ~0.5 MB.
    One number for all four is a number that fits none of them."""
    from app.services import settings_store, sot_store
    with app.app_context():
        settings_store.save_sot_local_policy(9, 9, "")
        settings_store.save_sot_local_policy(3, 2, "fortianalyzer")
        assert sot_store._retention("fortianalyzer") == (3, 2)
        assert sot_store._retention("fortiweb") == (9, 9), \
            "an ADOM without its own rule stopped inheriting the house rule"


def test_the_answer_says_which_level_produced_it(app):
    """"2 because you set it" and "2 because nobody set anything" lead to
    different next actions, so the page must be able to tell them apart."""
    from app.services import settings_store
    with app.app_context():
        assert settings_store.sot_local_policy("fortiweb")["versions_source"] == "default"
        settings_store.save_sot_local_policy(7, 7, "")
        assert settings_store.sot_local_policy("fortiweb")["versions_source"] == "house"
        settings_store.save_sot_local_policy(4, 4, "fortiweb")
        assert settings_store.sot_local_policy("fortiweb")["versions_source"] == "adom"


def test_clearing_an_adom_override_restores_inheritance(app):
    """The only way to undo a per-ADOM rule. Without it an override is
    permanent and the house rule silently stops applying forever."""
    from app.services import settings_store, sot_store
    with app.app_context():
        settings_store.save_sot_local_policy(9, 9, "")
        settings_store.save_sot_local_policy(3, 3, "fortiadc")
        assert sot_store._retention("fortiadc") == (3, 3)
        settings_store.save_sot_local_policy("", "", "fortiadc")
        assert sot_store._retention("fortiadc") == (9, 9), \
            "an emptied override did not fall back to the house rule"


@pytest.mark.parametrize("bad", ["0", "-4", "keep them all"])
def test_the_save_refuses_to_store_a_meaningless_local_policy(app, bad):
    """Layer one, on the way IN. Zero down this path evacuates the newest
    payload too, so the very next diff goes to the network for a config
    harvested a minute ago."""
    from app.services import settings_store, sot_store
    with app.app_context():
        settings_store.save_sot_local_policy(bad, bad, "fortiweb")
        assert settings_store.get_str("sot.local_versions.fortiweb", "") not in ("0", "-4"), \
            "a value no prune can honour was written to the store"
        assert sot_store._retention("fortiweb") == (sot_store.DEFAULT_LOCAL_VERSIONS,
                                                    sot_store.DEFAULT_LOCAL_DAYS)


def test_the_read_refuses_a_stored_zero_it_did_not_write(app):
    """Layer two, on the way OUT, guarded separately ON PURPOSE.

    The two layers protect the same thing, so a mutation of either one alone
    is invisible — which means a silent break of one leaves no test to notice,
    and the second break is the fatal one. A row can reach the table from a
    restore, a migration or psql without passing the save at all.
    """
    from app.services import settings_store, sot_store
    with app.app_context():
        settings_store.set_str("sot.local_versions.fortiweb", "0")
        settings_store.set_str("sot.local_days.fortiweb", "0")
        assert sot_store._retention("fortiweb") == (sot_store.DEFAULT_LOCAL_VERSIONS,
                                                    sot_store.DEFAULT_LOCAL_DAYS), \
            "a stored 0 was honoured as a policy: everything would be evacuated"


def test_no_setting_can_shorten_the_change_log_without_archiving_it(app, client):
    """AMENDED 2026-08-30, and the amendment is the point.

    This guard used to demand the pane state the log was kept forever with no
    setting at all. The operator then asked for the missing half — keep a
    window here, put the rest on the backup server — so the absolute claim is
    no longer true and pinning it would have frozen the product against its
    own operator. What still must hold is the SAFETY of the shortening: a row
    may only leave after the same rows have been written off-box and listed
    back. The claim moved; the invariant did not.

    The retired field names stay in the list: they belonged to a knob that
    deleted rows with nothing written anywhere, which is what must not return.
    """
    login(client, admin_user_id(app))
    html = client.get("/settings/").get_data(as_text=True)
    marker = '<div class="tab-pane fade" id="tab-sot">'
    assert marker in html
    pane = html.split(marker, 1)[1].split('class="tab-pane', 1)[0]
    assert "never thrown away" in pane, \
        "the pane no longer states that the change log is moved, not discarded"
    assert "listed back at the exact size" in pane, \
        "the pane no longer states what authorises deleting a row"
    for gone in ('name="index_versions"', 'name="index_days"',
                 'name="retention_versions"'):
        assert gone not in pane, "%s is back on the form" % gone


def test_an_unknown_adom_writes_nothing(app, client):
    """A key nothing reads is a policy that looks saved and governs nothing —
    exactly how the old retention knob failed for three weeks."""
    from app.services import settings_store
    login(client, admin_user_id(app))
    r = client.post("/settings/sot", data={"product": "fortimadeup",
                                           "keep_versions": "5", "keep_days": "5"})
    assert r.status_code in (302, 303)
    with app.app_context():
        assert settings_store.get_str("sot.local_versions.fortimadeup", "") == "", \
            "a policy was stored under an ADOM that does not exist"


# ------------------------------------------------- versions know their ADOM --

def test_a_new_version_is_filed_under_its_adom(app):
    from app.models import Appliance
    from app.extensions import db
    from app.services import sot_store
    with app.app_context():
        db.session.add(Appliance(name="adc9", kind="fortiadc", host="192.0.2.9",
                                 username="u", password_enc="x"))
        db.session.commit()
        res = sot_store.record("adc9", _snap("a"))
        assert sot_store.db_get(res["version_id"]).product == "fortiadc"


def test_the_backfill_leaves_an_already_filed_version_alone(app):
    """Idempotence with teeth: re-running it must not re-file a row under a
    different answer than the one record() gave it."""
    from app.models import Appliance
    from app.extensions import db
    from app.services import sot_store
    with app.app_context():
        db.session.add(Appliance(name="adc9", kind="fortiadc", host="192.0.2.9",
                                 username="u", password_enc="x"))
        db.session.commit()
        vid = sot_store.record("adc9", _snap("a"))["version_id"]
        # Layer one: a fully stamped device is not even a candidate.
        assert sot_store.backfill_products()["devices"] == 0
        assert sot_store.db_get(vid).product == "fortiadc"


def test_the_backfill_only_touches_the_unstamped_rows_of_a_mixed_device(app):
    """Layer two, guarded separately.

    Selecting the device and updating its rows are two filters that protect
    the same thing, so a break in either is invisible on its own. Here the
    device IS a candidate (it has an unstamped row) and the already-stamped
    row beside it must survive untouched — including when its value differs
    from the one the resolver would produce, which is the only way to tell
    "left alone" apart from "rewritten to the same answer".
    """
    from app.models import Appliance
    from app.extensions import db
    from app.services import sot_store
    with app.app_context():
        db.session.add(Appliance(name="adc9", kind="fortiadc", host="192.0.2.9",
                                 username="u", password_enc="x"))
        db.session.commit()
        old = sot_store.record("adc9", _snap("a"))["version_id"]
        new = sot_store.record("adc9", _snap("b"))["version_id"]
        sot_store.db_get(old).product = "fortianalyzer"   # a deliberate mismatch
        sot_store.db_get(new).product = ""
        db.session.commit()
        sot_store.backfill_products()
        assert sot_store.db_get(new).product == "fortiadc"
        assert sot_store.db_get(old).product == "fortianalyzer", \
            "the backfill overwrote a row that was already filed"


# ================================================================= PHASE 2 ==
#                            identity survives de-registration

def test_the_identity_table_has_no_foreign_key_to_appliances(app):
    """A ForeignKey here would cascade this row away with the device — the
    exact failure the table exists to prevent."""
    from app.models_identity import DeviceIdentity
    for col in DeviceIdentity.__table__.columns:
        assert not col.foreign_keys, \
            "%s has a foreign key; de-registering a device would erase it" % col.name


def test_the_probe_carries_the_serial_and_records_it(app, monkeypatch):
    from app.extensions import db
    from app.models import Appliance
    from app.services import device_identity, firmware_probe
    with app.app_context():
        a = Appliance(name="fw90", kind="fortiweb", host="192.0.2.90",
                      username="u", password_enc="x")
        db.session.add(a)
        db.session.commit()
        monkeypatch.setattr(firmware_probe, "read", lambda _a: {
            "ok": True, "firmware": "FortiWeb-KVM 7.6.8", "model": "FortiWeb-KVM",
            "hw_type": "vm", "hostname": "fw90", "serial": "FVVM0ABCDEF01234",
            "error": "", "detail": ""})
        res = firmware_probe.refresh(a)
        assert res["serial"] == "FVVM0ABCDEF01234"
        assert a.serial == "FVVM0ABCDEF01234" and a.serial_checked_at is not None
        ident = device_identity.for_slug("fw90")
        assert ident is not None and ident.serial == "FVVM0ABCDEF01234"


def test_the_fortiweb_reader_reads_the_serial_off_the_status_payload(app):
    """The guard above stubs ``read``, so it proves ``refresh`` persists what
    it is handed and nothing about the READER. Deleting the serial from
    ``_read_fortiweb`` survived it — this one exercises the parser itself
    against the payload shape measured on the live boxes."""
    from app.services import firmware_probe

    class _Client:
        def status_check(self):
            return {"results": {"firmwareVersion": "FortiWeb-KVM 7.6.8,build1128",
                                "platformName": "FortiWeb-KVM",
                                "serialNumber": "FVVM0ABCDEF01234",
                                "hostName": "fw95"}}

    class _App:
        kind = "fortiweb"
        def build_client(self, timeout=15.0):
            return _Client()

    res = firmware_probe.read(_App())
    assert res["ok"] and res["serial"] == "FVVM0ABCDEF01234", \
        "the reader dropped the serial the status payload carried: %r" % res


def test_a_payload_without_a_serial_never_erases_one(app, monkeypatch):
    """The four kinds answer with different payloads. "This payload did not
    say" is not "this box has no serial"."""
    from app.extensions import db
    from app.models import Appliance
    from app.services import firmware_probe
    with app.app_context():
        a = Appliance(name="fw91", kind="fortiweb", host="192.0.2.91",
                      username="u", password_enc="x", serial="KNOWN123")
        db.session.add(a)
        db.session.commit()
        monkeypatch.setattr(firmware_probe, "read", lambda _a: {
            "ok": True, "firmware": "7.6.8", "model": None, "hw_type": None,
            "hostname": "", "serial": "", "error": "", "detail": ""})
        firmware_probe.refresh(a)
        assert a.serial == "KNOWN123", "a silent payload erased a known serial"


def test_de_registering_a_device_keeps_its_identity(app, client):
    """Its backups are still on the server, and this row is the only thing
    that can still say whose they were."""
    from app.extensions import db
    from app.models import Appliance
    from app.services import device_identity
    with app.app_context():
        a = Appliance(name="fw92", kind="fortiweb", host="192.0.2.92",
                      username="u", password_enc="x")
        db.session.add(a)
        db.session.commit()
        device_identity.observe(a, serial="SER92")
        aid = a.id
    login(client, admin_user_id(app))
    client.post("/appliances/%d/delete" % aid)
    with app.app_context():
        ident = device_identity.for_slug("fw92")
        assert ident is not None, "the identity died with the appliance row"
        assert ident.retired and ident.serial == "SER92"
        assert Appliance.query.filter_by(name="fw92").first() is None


def test_a_hardware_scanned_appliance_can_be_de_registered(app, client):
    """Pre-existing defect, found while removing the DMZ FortiADCs.

    ``Appliance.hardware`` had no cascade, so the ORM's default on delete was
    to NULL ``device_hardware.appliance_id`` — a NOT NULL column — and the
    delete raised NotNullViolation. It depended entirely on whether a hardware
    scan had ever run against that device, which is why two of the three ADCs
    deleted cleanly and the third did not.
    """
    from app.extensions import db
    from app.models import Appliance, DeviceHardware
    with app.app_context():
        a = Appliance(name="fw96", kind="fortiweb", host="192.0.2.96",
                      username="u", password_enc="x")
        db.session.add(a)
        db.session.commit()
        db.session.add(DeviceHardware(appliance_id=a.id, cpu_count=4))
        db.session.commit()
        aid = a.id
    login(client, admin_user_id(app))
    r = client.post("/appliances/%d/delete" % aid)
    assert r.status_code in (302, 303)
    with app.app_context():
        assert Appliance.query.filter_by(name="fw96").first() is None, \
            "a hardware-scanned appliance could not be de-registered"
        assert DeviceHardware.query.filter_by(appliance_id=aid).first() is None


def test_a_rename_keeps_the_old_name_readable(app):
    from app.extensions import db
    from app.models import Appliance
    from app.services import device_identity
    with app.app_context():
        a = Appliance(name="fw93", kind="fortiweb", host="192.0.2.93",
                      username="u", password_enc="x")
        db.session.add(a)
        db.session.commit()
        device_identity.observe(a, serial="SER93")
        a.name = "fw93"           # slug is the key; the display name follows
        device_identity.observe(a, serial="SER93")
        ident = device_identity.for_slug("fw93")
        assert ident.name_history == ["fw93"]


def test_one_serial_groups_the_chassis_with_its_adom_rows(app):
    """A FortiWeb backup is of the CHASSIS. The chassis and its per-ADOM rows
    report the same serial, and that grouping is what makes the file legible."""
    from app.extensions import db
    from app.models import Appliance
    from app.services import device_identity
    with app.app_context():
        for name in ("fw94", "fw94@adom_prod", "fw94@adom_dev"):
            a = Appliance(name=name, kind="fortiweb", host="192.0.2.94",
                          username="u", password_enc="x")
            db.session.add(a)
            db.session.commit()
            device_identity.observe(a, serial="CHASSIS94")
        groups = [g for g in device_identity.serial_groups("fortiweb")
                  if g["serial"] == "CHASSIS94"]
        assert len(groups) == 1 and len(groups[0]["rows"]) == 3, \
            "the chassis and its ADOM rows did not group under one serial"


def test_an_unidentifiable_snapshot_is_left_unassigned(app):
    """Filing it under the most popular family would put it in an ADOM it
    never belonged to. Unassigned is visible and askable; wrong is neither."""
    from app.services import device_identity
    with app.app_context():
        assert device_identity.fingerprint_product({}) == ""
        assert device_identity.fingerprint_product(
            {"sections": {"X": {"totally_made_up_endpoint": []}}}) == ""


def test_a_real_snapshot_is_fingerprinted_to_its_family(app):
    from app.services import device_identity
    with app.app_context():
        keys = sorted(device_identity._catalog_keys()["fortiadc"])[:20]
        assert keys, "the FortiADC endpoint catalog did not load"
        snap = {"sections": {"S": {k: [] for k in keys}}}
        assert device_identity.fingerprint_product(snap) == "fortiadc"


# ================================================================= PHASE 3 ==
#                       the bundle lives off the node it backs up

def _clean_bundles(system_backup):
    """The bundle store is isolated from production but SHARED across the run
    (one module-level tmpdir), so a test that does not clear it inherits the
    previous one's files and asserts against them."""
    d = system_backup.backups_dir()
    for f in d.glob("fmw-backup-*"):
        f.unlink()
    return d


def _bundle(app_ctx_dir, name: str, data: bytes):
    p = app_ctx_dir / name
    p.write_bytes(data)
    return p


def test_a_bundle_leaves_only_when_the_server_holds_it_at_the_same_size(app, monkeypatch):
    """Name alone would accept a truncated upload — the very failure
    push_bundle guards at write time, pointless to re-open at delete time."""
    from app.services import backup_server, system_backup
    with app.app_context():
        d = _clean_bundles(system_backup)
        _bundle(d, "fmw-backup-20260101-000000.tar.gz", b"x" * 100)
        _bundle(d, "fmw-backup-20260102-000000.tar.gz", b"y" * 200)
        monkeypatch.setattr(backup_server, "system_inventory", lambda: {
            "reachable": True, "files": [
                {"name": "fmw-backup-20260101-000000.tar.gz", "size": 100},
                {"name": "fmw-backup-20260102-000000.tar.gz", "size": 7}]})
        res = system_backup.evict_local_bundles(keep=0)
        assert res["removed"] == ["fmw-backup-20260101-000000.tar.gz"]
        assert res["unverified"] == ["fmw-backup-20260102-000000.tar.gz"]
        assert (d / "fmw-backup-20260102-000000.tar.gz").exists(), \
            "a bundle whose remote size differs was deleted"


def test_an_unreachable_server_evicts_no_bundle(app, monkeypatch):
    from app.services import backup_server, system_backup
    with app.app_context():
        d = _clean_bundles(system_backup)
        _bundle(d, "fmw-backup-20260103-000000.tar.gz", b"z" * 50)
        # The listing CARRIES files while reporting itself unreachable — a
        # stub that also returned an empty list would pass with the reachable
        # check deleted, which is how this guard first let that mutation live.
        monkeypatch.setattr(backup_server, "system_inventory",
                            lambda: {"reachable": False, "files": [
                                {"name": "fmw-backup-20260103-000000.tar.gz",
                                 "size": 50}]})
        res = system_backup.evict_local_bundles(keep=0)
        assert res["removed"] == [] and res["remote_known"] == 0
        assert (d / "fmw-backup-20260103-000000.tar.gz").exists()


def test_the_newest_bundles_are_exempt_from_eviction(app, monkeypatch):
    from app.services import backup_server, system_backup
    with app.app_context():
        d = _clean_bundles(system_backup)
        for n in ("20260101", "20260102", "20260103"):
            _bundle(d, f"fmw-backup-{n}-000000.tar.gz", b"x" * 10)
        monkeypatch.setattr(backup_server, "system_inventory", lambda: {
            "reachable": True,
            "files": [{"name": f"fmw-backup-{n}-000000.tar.gz", "size": 10}
                      for n in ("20260101", "20260102", "20260103")]})
        res = system_backup.evict_local_bundles(keep=2)
        assert res["kept"] == ["fmw-backup-20260103-000000.tar.gz",
                               "fmw-backup-20260102-000000.tar.gz"]
        assert res["removed"] == ["fmw-backup-20260101-000000.tar.gz"]


def test_keeping_none_is_a_real_setting_not_an_unset_one(app):
    """0 is the recommended value here. Collapsing it into "unset" the way
    every other knob in the module does would make the default unreachable."""
    from app.services import settings_store
    with app.app_context():
        assert settings_store.bundle_local_keep()["configured"] is False
        settings_store.save_bundle_local_keep(0)
        cfg = settings_store.bundle_local_keep()
        assert cfg["keep"] == 0 and cfg["configured"] is True


def test_a_short_fetch_is_refused(app, monkeypatch):
    """A half-fetched file under the real name is a bundle that restores into
    a broken database."""
    from app.services import backup_server, settings_store, system_backup
    with app.app_context():
        monkeypatch.setattr(settings_store, "backup_server",
                            lambda reveal_secret=False: {
                                "configured": True, "system_path": "/system"},
                            raising=False)
        monkeypatch.setattr(backup_server, "system_inventory", lambda: {
            "reachable": True,
            "files": [{"name": "fmw-backup-20260104-000000.tar.gz", "size": 500}]})
        monkeypatch.setattr(backup_server, "fetch_file", lambda p, f: b"short")
        res = system_backup.ensure_local("fmw-backup-20260104-000000.tar.gz")
        assert res["ok"] is False and "size mismatch" in res["detail"]
        assert not (system_backup.backups_dir()
                    / "fmw-backup-20260104-000000.tar.gz").exists()


def test_restoring_an_off_box_bundle_fetches_it_back(app, monkeypatch):
    """Otherwise the default policy makes every bundle unrestorable the moment
    it works: the page lists it and restore answers "unknown backup"."""
    from app.services import system_backup
    calls = []
    with app.app_context():
        monkeypatch.setattr(system_backup, "ensure_local",
                            lambda n: calls.append(n) or {"ok": False,
                                                          "detail": "offline"})
        res = system_backup.restore_backup("fmw-backup-20260105-000000.tar.gz")
        assert calls == ["fmw-backup-20260105-000000.tar.gz"], \
            "restore did not try to fetch a bundle that is only off-box"
        assert res["ok"] is False


def test_the_local_listing_stays_local(app, monkeypatch):
    """``/healthz/backups`` publishes it and the peer comparison means "what
    does each node physically hold" — folding the shared off-box copy in makes
    two empty nodes look identical to two full ones."""
    from app.services import backup_server, system_backup
    with app.app_context():
        _clean_bundles(system_backup)
        monkeypatch.setattr(backup_server, "system_inventory", lambda: {
            "reachable": True,
            "files": [{"name": "fmw-backup-20260106-000000.tar.gz", "size": 9}]})
        assert system_backup.list_backups() == []
        rows = system_backup.all_bundles()
        assert len(rows) == 1 and rows[0]["off_box"] and not rows[0]["local"]


# ================================================================= PHASE 4 ==
#                        every ADOM can see what it holds

def test_the_menu_entry_is_in_every_admin_block(app):
    """The admin blocks in base.html have drifted before — two are even titled
    differently — and an entry added to Global and forgotten in the other four
    is invisible without failing."""
    base = (ROOT / "app" / "templates" / "base.html").read_text()
    assert base.count('partials/nav_adom_assets.html') == \
        base.count('partials/nav_cr_types.html'), \
        "Stored Assets is missing from an Administration block"
    assert base.count('partials/nav_adom_assets.html') == 5


def test_never_pushed_is_not_the_same_state_as_stale(app):
    """"This device has never pushed" and "this device stopped pushing" need
    different actions; one orange badge for both hides which you are seeing."""
    from app.services.adom_assets import grade
    assert grade(None, False)[0] == "never"
    assert grade(0, True)[0] == "ok"
    assert grade(20, True)[0] == "warn"
    assert grade(400, True)[0] == "crit"
    assert grade(None, True)[0] == "unknown"


def test_an_unreachable_server_reads_as_unknown_not_as_no_backups(app, monkeypatch):
    from app.services import adom_assets, backup_server
    with app.app_context():
        monkeypatch.setattr(backup_server, "inventory",
                            lambda: {"configured": True, "reachable": False,
                                     "host": "fm.example", "error": "timeout",
                                     "devices": [], "firmware": []})
        data = adom_assets.collect("")
        assert data["server"]["reachable"] is False
        assert data["server"]["error"] == "timeout"


def test_a_folder_no_device_claims_is_still_shown(app, monkeypatch):
    """Four FortiWebs' worth of history was invisible for exactly this reason:
    no page had a row to hang an unowned folder on."""
    from app.services import adom_assets, backup_server
    with app.app_context():
        monkeypatch.setattr(backup_server, "inventory", lambda: {
            "configured": True, "reachable": True, "host": "fm.example",
            "error": "", "firmware": [],
            "devices": [{"device": "ghost01", "count": 3,
                         "latest": "2026-01-01 00:00", "files": []}]})
        data = adom_assets.collect("")
        assert [u["slug"] for u in data["unclaimed"]] == ["ghost01"]


def test_a_retired_device_is_listed_with_its_backups(app, monkeypatch):
    from app.extensions import db
    from app.models_identity import DeviceIdentity
    from app.services import adom_assets, backup_server
    with app.app_context():
        db.session.add(DeviceIdentity(slug="oldfw", name="oldfw",
                                      product="fortiweb", serial="SEROLD",
                                      names='["oldfw"]',
                                      retired_at=datetime.utcnow()))
        db.session.commit()
        monkeypatch.setattr(backup_server, "inventory", lambda: {
            "configured": True, "reachable": True, "host": "fm.example",
            "error": "", "firmware": [],
            "devices": [{"device": "oldfw", "count": 21,
                         "latest": "2026-01-01 00:00", "files": []}]})
        data = adom_assets.collect("fortiweb")
        row = [r for r in data["rows"] if r["slug"] == "oldfw"][0]
        assert row["retired"] and row["backups"] == 21 and row["serial"] == "SEROLD"


def test_deleting_a_backup_needs_the_word(app, client, monkeypatch):
    """The appliance authored that file. An unconfirmed POST must destroy
    nothing, and there is deliberately no bulk delete at all."""
    from app.services import backup_server
    called = []
    monkeypatch.setattr(backup_server, "delete_device_file",
                        lambda d, f: called.append((d, f)) or {"ok": True,
                                                               "detail": "x"})
    login(client, admin_user_id(app))
    r = client.post("/adom-assets/delete-backup",
                    data={"device": "fw1", "filename": "a.zip"})
    assert r.status_code in (302, 303) and not called, \
        "a backup was deleted without confirmation"
    client.post("/adom-assets/delete-backup",
                data={"device": "fw1", "filename": "a.zip", "confirm": "DELETE"})
    assert called == [("fw1", "a.zip")]


def test_the_page_script_lives_in_a_block_the_parent_declares(app):
    """A block base.html does not declare is discarded SILENTLY by Jinja — no
    error, no log line — and the feature never reaches the browser. That is
    how the firmware page's install-kind script sat dead for 23 days."""
    tpl = (ROOT / "app" / "templates" / "adom_assets" / "index.html").read_text()
    base = (ROOT / "app" / "templates" / "base.html").read_text()
    import re
    blocks = set(re.findall(r"{%\s*block\s+(\w+)", tpl))
    declared = set(re.findall(r"{%\s*block\s+(\w+)", base))
    orphans = blocks - declared
    assert not orphans, "block(s) the parent never renders: %s" % orphans
    assert "js-del-backup" in tpl and "onsubmit=" not in tpl, \
        "an inline handler is back; a nonce'd CSP drops it silently"


def test_the_page_renders_for_an_admin(app, client, monkeypatch):
    from app.services import backup_server
    monkeypatch.setattr(backup_server, "inventory", lambda: {
        "configured": True, "reachable": True, "host": "fm.example",
        "error": "", "devices": [], "firmware": []})
    login(client, admin_user_id(app))
    r = client.get("/adom-assets/")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "Stored Assets" in html
    # SATOM is a light product: a dark-theme literal here renders a state
    # badge at ~1.4:1 and "never pushed" becomes unreadable.
    for dark in ("#080d1a", "backdrop-filter", "rgba(30,41,59"):
        assert dark not in html, "dark-theme chrome leaked onto a light page"
