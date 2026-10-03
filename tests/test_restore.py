"""Restore feature — loader.resolve, backup service endpoints, ConfigBackup vault, restore client + route."""
from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
# 1) loader.resolve(name) -> path  (everything must come from the API library) #
# --------------------------------------------------------------------------- #
def test_resolve_returns_real_backuprestore_path():
    from app.registry import loader
    assert loader.resolve("system_restore") == "/api/v2.0/system/maintenance.backuprestore"


def test_resolve_returns_real_localbackup_list_path():
    from app.registry import loader
    assert loader.resolve("local_backup_list") == "/api/v2.0/system/maintenance.localbackup.list"


def test_resolve_unknown_name_raises_keyerror():
    from app.registry import loader
    with pytest.raises(KeyError):
        loader.resolve("does_not_exist_key")


# --------------------------------------------------------------------------- #
# Fakes: a duck-typed FortiWeb client that records calls (no network)          #
# --------------------------------------------------------------------------- #
class _FakeResp:
    def __init__(self, status=200, json_body=None, content=b""):
        self.status_code = status
        self._j = json_body if json_body is not None else {}
        self.content = content
        self.text = ""
        self.headers = {}

    def json(self):
        return self._j

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")


class _FakeClient:
    def __init__(self, list_body=None, dl_content=b"CONFIG-BYTES"):
        self.calls = []
        self._list_body = list_body if list_body is not None else {"results": []}
        self._dl = dl_content

    def get(self, path):
        self.calls.append(("GET", path))
        if "download" in path:
            return _FakeResp(content=self._dl)
        return _FakeResp(json_body=self._list_body)

    def upload(self, path, files, data=None, timeout=None):
        self.calls.append(("UPLOAD", path, files, data))
        return _FakeResp(json_body={"results": {"status": "ok"}})


# --------------------------------------------------------------------------- #
# 2) backup service — resolver-driven, no hardcoded paths                      #
# --------------------------------------------------------------------------- #
def test_list_backups_uses_resolver_endpoint():
    from app.services import backup
    from app.registry import loader
    c = _FakeClient(list_body={"results": [{"name": "b1"}, {"name": "b2"}]})
    rows = backup.list_backups(c)
    assert ("GET", loader.resolve("local_backup_list")) in c.calls
    assert [r["name"] for r in rows] == ["b1", "b2"]


def test_download_backup_uses_resolver_and_returns_bytes():
    from app.services import backup
    from app.registry import loader
    c = _FakeClient()
    data = backup.download_backup(c, "b1")
    assert data == b"CONFIG-BYTES"
    assert any(call[0] == "GET" and loader.resolve("local_backup_download") in call[1]
               for call in c.calls)


def test_restore_dry_run_does_not_upload():
    from app.services import backup
    c = _FakeClient()
    plan = backup.restore(c, b"config data", "cfg.conf", dry_run=True)
    assert plan["dry_run"] is True
    assert plan["ok"] is True
    assert not any(call[0] == "UPLOAD" for call in c.calls)


def test_restore_real_uploads_to_backuprestore_with_field():
    from app.services import backup
    from app.registry import loader
    c = _FakeClient()
    plan = backup.restore(c, b"config data", "cfg.conf", dry_run=False)
    ups = [call for call in c.calls if call[0] == "UPLOAD"]
    assert len(ups) == 1
    _, path, files, _data = ups[0]
    assert path == loader.resolve("system_restore")
    assert backup.RESTORE_FILE_FIELD in files
    assert plan["dry_run"] is False


def test_restore_rejects_empty_file():
    from app.services import backup
    c = _FakeClient()
    with pytest.raises(ValueError):
        backup.restore(c, b"", "cfg.conf", dry_run=True)


# --------------------------------------------------------------------------- #
# 3) ConfigBackup vault model + store                                          #
# --------------------------------------------------------------------------- #
def test_config_backup_model_round_trips(app):
    import hashlib
    from app.extensions import db
    from app.models_backup import ConfigBackup
    with app.app_context():
        cb = ConfigBackup(appliance_id=1, appliance_name="fw3", filename="c.conf",
                          stored_path="/tmp/c.conf", size_bytes=5,
                          sha256=hashlib.sha256(b"hello").hexdigest(),
                          source="upload", created_by="admin")
        db.session.add(cb)
        db.session.commit()
        got = ConfigBackup.query.one()
        assert got.appliance_name == "fw3"
        assert got.source == "upload"
        assert got.encrypted is False
        assert got.created_at is not None


def test_store_bytes_writes_file_and_row(app):
    import os
    from app.services import backup
    from app.models_backup import ConfigBackup
    with app.app_context():
        cb = backup.store_bytes(appliance_id=7, appliance_name="fw3",
                                data=b"FULL-CONFIG", filename="fw3.conf",
                                source="upload", created_by="admin", firmware="7.6.8")
        assert os.path.exists(cb.stored_path)
        assert open(cb.stored_path, "rb").read() == b"FULL-CONFIG"
        assert ConfigBackup.query.count() == 1
        # sha recorded matches file
        assert backup.read_vault_bytes(cb) == b"FULL-CONFIG"


def test_encrypted_detection_flags_fortiweb_header(app):
    from app.services import backup
    with app.app_context():
        # FortiWeb encrypted backups are not plaintext '#config' — flagged encrypted
        cb = backup.store_bytes(appliance_id=1, appliance_name="fw3",
                                data=b"\x00\x01\x02binarygibberish", filename="enc.conf",
                                source="upload", created_by="admin")
        assert cb.encrypted is True
        plain = backup.store_bytes(appliance_id=1, appliance_name="fw3",
                                   data=b"#config-version=FWB\nconfig system", filename="p.conf",
                                   source="upload", created_by="admin")
        assert plain.encrypted is False


# --------------------------------------------------------------------------- #
# 4) restore routes — admin-only (USER_MANAGE), vault upload, dry-run restore  #
# --------------------------------------------------------------------------- #
import io  # noqa: E402
from tests.conftest import login, make_user, profile_id  # noqa: E402


def _appliance(app):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw3", kind="fortiweb", host="192.0.2.99",
                      port=443, username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a)
        db.session.commit()
        return a.id


def _admin(app):
    return make_user(app, "radmin", role="admin", profile_id=profile_id(app, "admin"))


def _readonly(app):
    return make_user(app, "rro", role="readonly", profile_id=profile_id(app, "readonly"))


def test_restore_page_admin_200_readonly_403(app, client):
    aid = _appliance(app)
    login(client, _readonly(app))
    assert client.get(f"/appliances/{aid}/restore").status_code == 403
    login(client, _admin(app))
    assert client.get(f"/appliances/{aid}/restore").status_code == 200


def test_restore_upload_creates_vault_row(app, client):
    aid = _appliance(app)
    login(client, _admin(app))
    resp = client.post(
        f"/appliances/{aid}/restore/upload",
        data={"config_file": (io.BytesIO(b"#config-version=FWB\nconfig system"), "fw3.conf")},
        content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200
    from app.models_backup import ConfigBackup
    with app.app_context():
        rows = ConfigBackup.query.filter_by(appliance_id=aid).all()
        assert len(rows) == 1
        assert rows[0].filename == "fw3.conf"
        assert rows[0].encrypted is False


def test_restore_upload_blocked_for_readonly(app, client):
    aid = _appliance(app)
    login(client, _readonly(app))
    resp = client.post(
        f"/appliances/{aid}/restore/upload",
        data={"config_file": (io.BytesIO(b"x"), "fw3.conf")},
        content_type="multipart/form-data")
    assert resp.status_code == 403
    from app.models_backup import ConfigBackup
    with app.app_context():
        assert ConfigBackup.query.count() == 0


def test_restore_run_dry_run_from_upload_no_device(app, client):
    aid = _appliance(app)
    login(client, _admin(app))
    resp = client.post(
        f"/appliances/{aid}/restore/run",
        data={"dry_run": "on",
              "config_file": (io.BytesIO(b"#config stuff"), "fw3.conf")},
        content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200
    assert b"DRY RUN" in resp.data


def test_restore_download_returns_stored_bytes(app, client):
    aid = _appliance(app)
    login(client, _admin(app))
    client.post(
        f"/appliances/{aid}/restore/upload",
        data={"config_file": (io.BytesIO(b"CONFDATA"), "fw3.conf")},
        content_type="multipart/form-data", follow_redirects=True)
    from app.models_backup import ConfigBackup
    with app.app_context():
        bid = ConfigBackup.query.filter_by(appliance_id=aid).one().id
    resp = client.get(f"/appliances/{aid}/restore/{bid}/download")
    assert resp.status_code == 200
    assert resp.data == b"CONFDATA"


# --------------------------------------------------------------------------- #
# 5) owner decisions 2026-10-03: restore = users.manage AND backups.restore;   #
#    a live restore aborts when the pre-restore backup fails (audited override)#
# --------------------------------------------------------------------------- #
def _custom(app, name, keys):
    from app.models import Profile, User, db
    with app.app_context():
        p = Profile(name=f"p-{name}", is_system=False)
        p.permission_set = set(keys)
        db.session.add(p)
        db.session.commit()
        u = User(username=name, role="readonly", is_active=True, profile_id=p.id)
        u.set_password("pw")
        db.session.add(u)
        db.session.commit()
        return u.id


def test_restore_needs_users_manage_and_backups_restore(app, client):
    aid = _appliance(app)
    base = {"appliances.view"}
    login(client, _custom(app, "only-users", base | {"users.manage"}))
    assert client.get(f"/appliances/{aid}/restore").status_code == 403
    assert client.post(f"/appliances/{aid}/restore/run", data={"dry_run": "on"}).status_code == 403
    login(client, _custom(app, "only-restore", base | {"backups.restore"}))
    assert client.get(f"/appliances/{aid}/restore").status_code == 403
    login(client, _custom(app, "both", base | {"users.manage", "backups.restore"}))
    assert client.get(f"/appliances/{aid}/restore").status_code == 200
    det = client.get(f"/appliances/{aid}").get_data(as_text=True)
    assert f"/appliances/{aid}/restore" in det


class _NoDeviceClient:
    pass


def _live(client, aid, **extra):
    data = {"confirm_name": "fw3",
            "config_file": (io.BytesIO(b"#config-version=FWB\nconfig system"), "fw3.conf")}
    data.update(extra)
    return client.post(f"/appliances/{aid}/restore/run", data=data,
                       content_type="multipart/form-data", follow_redirects=True)


def _rig(monkeypatch, *, pre_fails):
    from app.models import Appliance
    from app.services import backup as backup_svc
    sent = []
    monkeypatch.setattr(Appliance, "build_client", lambda self, timeout=0: _NoDeviceClient())

    def _pre(*a, **k):
        if pre_fails:
            raise RuntimeError("errcode -901")
        from types import SimpleNamespace
        return SimpleNamespace(filename="pre.conf")
    monkeypatch.setattr(backup_svc, "fetch_device_backup", _pre)

    def _restore(client, data, filename, password=None, dry_run=True):
        sent.append(filename)
        return {"dry_run": dry_run, "filename": filename, "size": len(data),
                "endpoint": "x", "encrypted": False, "ok": True, "message": "ok"}
    monkeypatch.setattr(backup_svc, "restore", _restore)
    return sent


def test_live_restore_aborts_when_the_pre_restore_backup_fails(app, client, monkeypatch):
    from app.models import AuditLog
    aid = _appliance(app)
    sent = _rig(monkeypatch, pre_fails=True)
    login(client, _admin(app))
    body = _live(client, aid).get_data(as_text=True)
    assert sent == [], "the restore was sent without its rollback copy"
    assert "Live restore aborted" in body
    with app.app_context():
        row = AuditLog.query.filter_by(action="appliance.restore").one()
        assert "refused" in row.extra and "-901" in row.extra


def test_live_restore_without_pre_backup_needs_the_box_and_is_audited(app, client, monkeypatch):
    from app.models import AuditLog
    aid = _appliance(app)
    sent = _rig(monkeypatch, pre_fails=True)
    login(client, _admin(app))
    body = _live(client, aid, skip_pre_backup="on").get_data(as_text=True)
    assert sent == ["fw3.conf"]
    assert "LIVE RESTORE" in body
    with app.app_context():
        row = AuditLog.query.filter_by(action="appliance.restore").one()
        assert "'without_pre_backup': True" in row.extra


def test_live_restore_with_a_pre_backup_proceeds(app, client, monkeypatch):
    aid = _appliance(app)
    sent = _rig(monkeypatch, pre_fails=False)
    login(client, _admin(app))
    body = _live(client, aid).get_data(as_text=True)
    assert sent == ["fw3.conf"] and "pre.conf" in body
