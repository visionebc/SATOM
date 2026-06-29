"""Firmware repository — model + admin-gated routes (upload/list/download/delete)."""
from __future__ import annotations

import hashlib
import io
import os

from tests.conftest import login, make_user, profile_id


def _admin(app):
    return make_user(app, "fwadmin", role="admin", profile_id=profile_id(app, "admin"))


def _readonly(app):
    return make_user(app, "fwro", role="readonly", profile_id=profile_id(app, "readonly"))


def _upload(client, name="a.out", body=b"DATA", version="7.6.4", product="fortiweb"):
    return client.post(
        "/firmware/upload",
        data={"version": version, "product": product,
              "image": (io.BytesIO(body), name)},
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def test_firmware_table_round_trips(app):
    from app.extensions import db
    from app.models_firmware import FirmwareImage
    with app.app_context():
        fw = FirmwareImage(product="fortiweb", version="7.6.4", filename="x.out",
                           stored_path="/tmp/x.out", size_bytes=3, sha256="ab",
                           uploaded_by="admin")
        db.session.add(fw)
        db.session.commit()
        got = FirmwareImage.query.one()
        assert got.product == "fortiweb"
        assert got.version == "7.6.4"
        assert got.created_at is not None


def test_index_admin_200_readonly_403(app, client):
    login(client, _admin(app))
    assert client.get("/firmware/").status_code == 200
    login(client, _readonly(app))
    assert client.get("/firmware/").status_code == 403


def test_upload_out_creates_row_file_and_sha(app, client):
    login(client, _admin(app))
    resp = _upload(client, name="FWB_VM-v7.out", body=b"FWDATA123")
    assert resp.status_code == 200
    from app.models_firmware import FirmwareImage
    with app.app_context():
        fw = FirmwareImage.query.one()
        assert fw.filename == "FWB_VM-v7.out"
        assert fw.size_bytes == 9
        assert fw.sha256 == hashlib.sha256(b"FWDATA123").hexdigest()
        assert os.path.exists(fw.stored_path)


def test_upload_rejects_non_out(app, client):
    login(client, _admin(app))
    _upload(client, name="notes.txt", body=b"x")
    from app.models_firmware import FirmwareImage
    with app.app_context():
        assert FirmwareImage.query.count() == 0


def test_upload_requires_version(app, client):
    login(client, _admin(app))
    _upload(client, name="a.out", body=b"x", version="")
    from app.models_firmware import FirmwareImage
    with app.app_context():
        assert FirmwareImage.query.count() == 0


def test_download_returns_bytes(app, client):
    login(client, _admin(app))
    _upload(client, name="a.out", body=b"BYTES", version="1")
    from app.models_firmware import FirmwareImage
    with app.app_context():
        fwid = FirmwareImage.query.one().id
    resp = client.get(f"/firmware/{fwid}/download")
    assert resp.status_code == 200
    assert resp.data == b"BYTES"


def test_delete_removes_row_and_file(app, client):
    login(client, _admin(app))
    _upload(client, name="a.out", body=b"Z", version="1")
    from app.models_firmware import FirmwareImage
    with app.app_context():
        fw = FirmwareImage.query.one()
        fwid, path = fw.id, fw.stored_path
    client.post(f"/firmware/{fwid}/delete", follow_redirects=True)
    with app.app_context():
        assert FirmwareImage.query.count() == 0
    assert not os.path.exists(path)


def test_upload_blocked_for_readonly(app, client):
    login(client, _readonly(app))
    resp = client.post(
        "/firmware/upload",
        data={"version": "1", "image": (io.BytesIO(b"Z"), "a.out")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 403
    from app.models_firmware import FirmwareImage
    with app.app_context():
        assert FirmwareImage.query.count() == 0
