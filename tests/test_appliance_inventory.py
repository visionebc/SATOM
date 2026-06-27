"""Tests for the appliance physical-inventory feature: hw_type/model,
datasheet PDF upload/serve, documented interfaces, and the read-only
architecture device endpoint."""
import io

import pytest
from sqlalchemy import inspect

from app.extensions import db
from app.models import Appliance, ApplianceInterface
from app.services import datasheets


@pytest.fixture
def logged_in(client, app):
    """Admin test client with the FortiWeb product selected (shares the app/client
    fixtures from tests/conftest.py)."""
    from app.models import User
    with app.app_context():
        uid = User.query.filter_by(username="admin").first().id
    with client.session_transaction() as sess:
        sess["_user_id"] = str(uid)
        sess["_fresh"] = True
        sess["product"] = "fortiweb"
    return client


def _make_appliance(app, **kw):
    with app.app_context():
        a = Appliance(
            name=kw.get("name", "fw-test"),
            kind=kw.get("kind", "fortiweb"),
            host=kw.get("host", "192.0.2.99"),
            port=kw.get("port", 443),
            username=kw.get("username", "admin"),
            verify_ssl=False,
            password_enc="placeholder",
            hw_type=kw.get("hw_type", "unknown"),
            model=kw.get("model"),
        )
        a.set_password("secret")
        db.session.add(a)
        db.session.commit()
        return a.id


# --- schema / migration -----------------------------------------------------

def test_schema_has_new_columns_and_table(app):
    with app.app_context():
        insp = inspect(db.engine)
        cols = {c["name"] for c in insp.get_columns("appliances")}
        assert {"hw_type", "model", "datasheet_filename"} <= cols
        assert insp.has_table("appliance_interfaces")


# --- create -----------------------------------------------------------------

def test_create_appliance_records_hw_fields(app, logged_in):
    resp = logged_in.post("/appliances/", data={
        "name": "fw-create", "kind": "fortiweb", "host": "192.0.2.50",
        "port": "443", "username": "admin", "password": "pw",
        "hw_type": "hardware", "model": "FortiWeb 600F",
    }, follow_redirects=False)
    assert resp.status_code in (302, 303)
    with app.app_context():
        a = Appliance.query.filter_by(name="fw-create").first()
        assert a is not None
        assert a.hw_type == "hardware"
        assert a.model == "FortiWeb 600F"


def test_create_rejects_bogus_hw_type(app, logged_in):
    logged_in.post("/appliances/", data={
        "name": "fw-bogus", "kind": "fortiweb", "host": "192.0.2.51",
        "username": "admin", "password": "pw", "hw_type": "banana",
    })
    with app.app_context():
        a = Appliance.query.filter_by(name="fw-bogus").first()
        assert a.hw_type == "unknown"  # invalid value normalised


# --- interfaces (replace-all) ----------------------------------------------

def test_edit_replaces_interfaces(app, logged_in):
    aid = _make_appliance(app, name="fw-iface")
    logged_in.post(f"/appliances/{aid}/edit", data={
        "name": "fw-iface", "host": "192.0.2.99", "username": "admin",
        "hw_type": "vm", "model": "VM-04",
        "if_name": ["port1", "port2", ""],   # blank row must be ignored
        "if_type": ["10G SFP+", "1G copper", "1G"],
        "if_connected": ["Core-SW-A / Gi1/0/1", "Core-SW-B / Gi1/0/2", "x"],
        "if_ip": ["192.0.2.99", "", ""],
        "if_notes": ["uplink", "", ""],
    })
    with app.app_context():
        a = Appliance.query.get(aid)
        assert a.hw_type == "vm" and a.model == "VM-04"
        names = sorted(i.name for i in a.interfaces)
        assert names == ["port1", "port2"]
        p1 = next(i for i in a.interfaces if i.name == "port1")
        assert p1.if_type == "10G SFP+"
        assert p1.connected_to == "Core-SW-A / Gi1/0/1"
        assert p1.ip_address == "192.0.2.99"

    # Second edit with fewer rows replaces (does not append).
    logged_in.post(f"/appliances/{aid}/edit", data={
        "name": "fw-iface", "host": "192.0.2.99", "username": "admin",
        "if_name": ["mgmt"], "if_type": ["1G"], "if_connected": ["jump"],
        "if_ip": [""], "if_notes": [""],
    })
    with app.app_context():
        a = Appliance.query.get(aid)
        assert [i.name for i in a.interfaces] == ["mgmt"]


def test_delete_cascades_interfaces(app, logged_in):
    aid = _make_appliance(app, name="fw-del")
    with app.app_context():
        db.session.add(ApplianceInterface(appliance_id=aid, name="port1"))
        db.session.commit()
    logged_in.post(f"/appliances/{aid}/delete")
    with app.app_context():
        assert Appliance.query.get(aid) is None
        assert ApplianceInterface.query.filter_by(appliance_id=aid).count() == 0


# --- datasheet upload / serve / remove -------------------------------------

_PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


def test_datasheet_upload_serve_and_remove(app, logged_in):
    aid = _make_appliance(app, name="fw-ds")
    # upload
    logged_in.post(f"/appliances/{aid}/edit", data={
        "name": "fw-ds", "host": "192.0.2.99", "username": "admin",
        "datasheet": (io.BytesIO(_PDF), "spec.pdf"),
    }, content_type="multipart/form-data")
    with app.app_context():
        a = Appliance.query.get(aid)
        assert a.datasheet_filename == "spec.pdf"
    # serve
    r = logged_in.get(f"/appliances/{aid}/datasheet")
    assert r.status_code == 200
    assert r.mimetype == "application/pdf"
    assert r.data.startswith(b"%PDF-")
    # remove
    logged_in.post(f"/appliances/{aid}/edit", data={
        "name": "fw-ds", "host": "192.0.2.99", "username": "admin",
        "datasheet_remove": "on",
    }, content_type="multipart/form-data")
    with app.app_context():
        assert Appliance.query.get(aid).datasheet_filename is None
    assert logged_in.get(f"/appliances/{aid}/datasheet").status_code == 404


def test_datasheet_rejects_non_pdf(app, logged_in):
    aid = _make_appliance(app, name="fw-bad")
    logged_in.post(f"/appliances/{aid}/edit", data={
        "name": "fw-bad", "host": "192.0.2.99", "username": "admin",
        "datasheet": (io.BytesIO(b"not a pdf"), "evil.txt"),
    }, content_type="multipart/form-data", follow_redirects=False)
    with app.app_context():
        assert Appliance.query.get(aid).datasheet_filename is None


def test_datasheets_service_validation(app):
    with app.app_context():
        class _F:
            filename = "x.pdf"
            def read(self):
                return b"not pdf bytes"
        try:
            datasheets.save(1, _F())
            assert False, "should reject non-PDF content"
        except ValueError:
            pass


# --- read-only architecture device endpoint --------------------------------

def test_architecture_device_endpoint(app, logged_in):
    aid = _make_appliance(app, name="fw-arch", hw_type="hardware", model="600F")
    with app.app_context():
        db.session.add(ApplianceInterface(
            appliance_id=aid, name="port1", if_type="10G",
            connected_to="SW/1", ip_address="192.0.2.99", sort_order=0))
        db.session.commit()
    r = logged_in.get(f"/architecture/device/{aid}")
    assert r.status_code == 200
    d = r.get_json()
    assert d["name"] == "fw-arch"
    assert d["hw_type"] == "hardware"
    assert d["model"] == "600F"
    assert d["detail_url"].endswith(f"/appliances/{aid}")
    assert d["datasheet_url"] is None  # none uploaded
    assert len(d["interfaces"]) == 1
    assert d["interfaces"][0]["name"] == "port1"


def test_architecture_device_404(logged_in):
    assert logged_in.get("/architecture/device/999999").status_code == 404


# --- template rendering (catches Jinja errors) -----------------------------

def test_detail_and_architecture_pages_render(app, logged_in):
    aid = _make_appliance(app, name="fw-render", hw_type="vm", model="VM-08")
    with app.app_context():
        db.session.add(ApplianceInterface(appliance_id=aid, name="port1", if_type="1G"))
        db.session.commit()
    r1 = logged_in.get(f"/appliances/{aid}")
    assert r1.status_code == 200
    assert b"Physical / Interfaces" in r1.data
    r2 = logged_in.get("/architecture/")
    assert r2.status_code == 200
    assert b"deviceModal" in r2.data
