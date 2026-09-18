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

# ─────────────────────────────────────────────────────────────────────────────
# Filename-derived version/build (Infrastructure -> Firmware, upload form)
#
# Fortinet's own naming carries both tokens, so an operator re-typing them is
# only a chance to get them wrong — row 21 of the live store shipped with an
# empty build while its filename said ``build0116``. The rule that has to hold
# in BOTH directions: derive what was left blank, and NEVER overrule what was
# typed (a wrong version files an image under a release nobody chose).
# ─────────────────────────────────────────────────────────────────────────────

def _upload_raw(client, name, version="", build="", body=b"DATA"):
    data = {"product": "fortiweb", "image": (io.BytesIO(body), name)}
    if version:
        data["version"] = version
    if build:
        data["build"] = build
    return client.post("/firmware/upload", data=data,
                       content_type="multipart/form-data", follow_redirects=True)


def test_upload_derives_dotted_version_and_build(app, client):
    login(client, _admin(app))
    _upload_raw(client, "FWB_KVM-v7.6.8.M-build1128-FORTINET.out")
    from app.models_firmware import FirmwareImage
    with app.app_context():
        fw = FirmwareImage.query.one()
        assert fw.version == "7.6.8"
        assert fw.build == "1128"


def test_upload_derives_packed_version(app, client):
    """The older short form (``v750``) is the same one backup-server images use."""
    login(client, _admin(app))
    _upload_raw(client, "FWB_KVM-v750-build0387-FORTINET.out")
    from app.models_firmware import FirmwareImage
    with app.app_context():
        fw = FirmwareImage.query.one()
        assert fw.version == "7.5.0"
        assert fw.build == "0387"


def test_typed_version_and_build_beat_the_filename(app, client):
    login(client, _admin(app))
    _upload_raw(client, "FWB_KVM-v7.6.8.M-build1128-FORTINET.out",
                version="8.0.0", build="9")
    from app.models_firmware import FirmwareImage
    with app.app_context():
        fw = FirmwareImage.query.one()
        assert fw.version == "8.0.0"
        assert fw.build == "9"


def test_typed_version_still_lets_build_be_derived(app, client):
    """Half-filled is the common case: the two fields are derived independently."""
    login(client, _admin(app))
    _upload_raw(client, "FWB_KVM-v7.6.8.M-build1128-FORTINET.out", version="8.0.0")
    from app.models_firmware import FirmwareImage
    with app.app_context():
        fw = FirmwareImage.query.one()
        assert fw.version == "8.0.0"
        assert fw.build == "1128"


def test_unparseable_name_invents_nothing(app, client):
    """No ``v...`` token: build stays empty rather than guessed."""
    login(client, _admin(app))
    _upload_raw(client, "firmware.out", version="7.6.4")
    from app.models_firmware import FirmwareImage
    with app.app_context():
        fw = FirmwareImage.query.one()
        assert fw.version == "7.6.4"
        assert not fw.build


def test_unparseable_name_without_version_is_still_rejected(app, client):
    """Deriving must not weaken the required-version check into a silent blank."""
    login(client, _admin(app))
    _upload_raw(client, "firmware.out")
    from app.models_firmware import FirmwareImage
    with app.app_context():
        assert FirmwareImage.query.count() == 0


def test_resumable_begin_derives_version_too(app, client):
    """The chunked path is the one the browser actually uses for big images —
    it must not reject a blank version the multipart path would have filled."""
    login(client, _admin(app))
    resp = client.post("/firmware/upload/begin", json={
        "filename": "FWB_KVM-v8.0.5.F-build0110-FORTINET.out", "size": 4,
    })
    assert resp.status_code == 200, resp.get_data(as_text=True)
    upload_id = resp.get_json()["upload_id"]
    from app.views import firmware as fwv
    with app.app_context():
        import json as _j
        with open(fwv._meta_file(fwv._upload_dir(upload_id)), encoding="utf-8") as fh:
            meta = _j.load(fh)
    assert meta["version"] == "8.0.5"
    assert meta["build"] == "0110"


def test_parse_name_endpoint_matches_the_upload_handlers(app, client):
    login(client, _admin(app))
    got = client.get("/firmware/parse-name",
                     query_string={"filename": "FWB_KVM-v7.6.8.M-build1128-FORTINET.out"})
    assert got.status_code == 200
    assert got.get_json() == {"version": "7.6.8", "build": "1128"}
    empty = client.get("/firmware/parse-name", query_string={"filename": "firmware.out"})
    assert empty.get_json() == {"version": "", "build": ""}


def test_parse_name_is_admin_gated(app, client):
    login(client, _readonly(app))
    assert client.get("/firmware/parse-name",
                      query_string={"filename": "a.out"}).status_code == 403


def test_upload_form_wires_the_autofill(app, client):
    """The fields must carry the ids the script writes to, the script must ask
    the SERVER (not a second regex), and it must refuse to clobber a typed
    value — checked on the page the server actually renders."""
    login(client, _admin(app))
    html = client.get("/firmware/").get_data(as_text=True)
    assert 'id="fwVersion"' in html
    assert 'id="fwBuild"' in html
    assert "/firmware/parse-name?filename=" in html
    assert "fwAuto !== '1'" in html


def _wait_job(jid, timeout=15.0):
    """Bounded wait for a background job to settle. Never a bare sleep: the
    finalize thread is real here, and a fixed nap either wastes time or asserts
    against a job that has not finished."""
    import time
    from app.services import jobs as jobsvc
    end = time.time() + timeout
    while time.time() < end:
        st = jobsvc.get_job(jid) or {}
        if st.get("status") in ("success", "error", "cancelled"):
            return st
        time.sleep(0.05)
    return jobsvc.get_job(jid) or {}


def test_finalize_job_says_which_page_to_refresh(app, client):
    """A finished upload must tell the browser WHICH page to refresh, using the
    URL this app actually serves the firmware page on.

    The client only refreshes when the job names its page, and its historical
    fallback ("/firmware") stopped matching the real path the day this area
    moved under the /web ADOM prefix. A job that omits the path therefore leaves
    the stored-firmware table showing everything except the image just uploaded.
    """
    login(client, _admin(app))
    resp = client.post(
        "/firmware/upload",
        data={"version": "7.6.4", "product": "fortiweb",
              "image": (io.BytesIO(b"FWDATA123"), "a.out")},
        content_type="multipart/form-data",
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert resp.status_code == 202, resp.get_data(as_text=True)
    st = _wait_job(resp.get_json()["job_id"])
    assert st.get("status") == "success", st
    res = st.get("result") or {}
    assert res.get("reload") is True
    with app.test_request_context():
        from flask import url_for
        want = url_for("firmware.index")
    assert res.get("reload_path") == want
    # ...and that path is a page, not a string that merely looks like one.
    assert client.get(res["reload_path"]).status_code == 200


def test_resumable_finish_also_says_which_page_to_refresh(app, client):
    """The chunked path is the one the browser uses for real (600 MB) images.
    It hands off to the same finalize job, so it must carry the same refresh
    target -- the two upload paths have drifted apart before."""
    login(client, _admin(app))
    begin = client.post("/firmware/upload/begin",
                        json={"filename": "b.out", "version": "7.6.4", "size": 4})
    assert begin.status_code == 200, begin.get_data(as_text=True)
    uid = begin.get_json()["upload_id"]
    assert client.post("/firmware/upload/chunk",
                       query_string={"upload_id": uid, "offset": 0},
                       data=b"DATA",
                       content_type="application/octet-stream").status_code == 200
    fin = client.post("/firmware/upload/finish", query_string={"upload_id": uid})
    assert fin.status_code == 202, fin.get_data(as_text=True)
    st = _wait_job(fin.get_json()["job_id"])
    assert st.get("status") == "success", st
    with app.test_request_context():
        from flask import url_for
        want = url_for("firmware.index")
    assert (st.get("result") or {}).get("reload_path") == want


def test_jobs_js_refresh_gate_normalises_the_adom_prefix(app):
    """The refresh must fire on the page the job names, compared on normalised
    paths -- and on nothing else.

    Two failure modes this pins, both of which have already happened here:
    gating on a prefix-at-position-0 match against a hardcoded top-level path
    (never true under /web, so the refresh silently never ran), and refreshing
    whatever page the user happens to be on (which would discard a form they
    are filling in while an upload finishes in the background).
    """
    import os as _os
    with open(_os.path.join(app.static_folder, "js", "jobs.js"),
              encoding="utf-8") as fh:
        js = fh.read()
    assert "function samePage(" in js
    assert "/^\\/web(?=\\/|$)/" in js          # the ADOM prefix is normalised away
    assert "res.reload && samePage(res.reload_path)" in js
    # A job with no page named must refresh nothing: no fallback target.
    assert "res.reload_path ||" not in js
    # ...and no surviving prefix-at-0 test against a hardcoded page path.
    assert "location.pathname.indexOf('/firmware')" not in js
    assert "location.pathname.indexOf(res.reload_path" not in js
