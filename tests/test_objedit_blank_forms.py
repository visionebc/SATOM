"""Blank create/add-row forms must never be empty for objects the device
refuses name-only — the 2026-07-06 bugs: a custom HTTPS Service created with
just a name answered HTTP 500 (errcode -56, port missing) because the create
form rendered NO port field, and a fresh Protected Hostnames object showed an
add-row form with ZERO inputs ("no changes to save")."""
from __future__ import annotations

from tests.conftest import admin_user_id, login


def _make_appliance(app):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw1", kind="fortiweb", host="192.0.2.99",
                      port=443, username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a); db.session.commit()
        return a.id


# ── unit: the seeded blank row template ─────────────────────────────────────
def test_blank_row_sample_seeds_host_list():
    from app.services import objform
    s = objform.blank_row_sample("server-policy/allow-hosts/host-list")
    assert "host" in s
    # device defaults drive widget inference (enable/disable → toggle)
    assert s.get("include-subdomains") == "disable"
    assert s.get("action") == "allow"


def test_create_fields_service_custom_port_required():
    from app.services.fortiweb_field_schema import CREATE_FIELDS
    entries = CREATE_FIELDS["server-policy/service.custom"]
    keys = {f["key"] for f in entries}
    assert "port" in keys
    assert "type" not in keys  # not a wire field — verified live on fw6 7.6.8
    assert any(f["key"] == "port" and f.get("required") for f in entries)


# ── unit: device HTTP-500 bodies surface their errcode/message ──────────────
def test_response_ok_parses_error_body_on_500():
    from app.services.fortiweb_ops import FortiWebOps

    class _Resp:
        status_code = 500
        def json(self):
            return {"results": {"errcode": -56,
                                "message": "Empty value isn't allowed."}}

    ok, err = FortiWebOps._response_ok(_Resp())
    assert not ok
    assert "-56" in err and "Empty value isn't allowed." in err


def test_response_ok_plain_500_still_reported():
    from app.services.fortiweb_ops import FortiWebOps

    class _Resp:
        status_code = 500
        def json(self):
            raise ValueError("not json")

    ok, err = FortiWebOps._response_ok(_Resp())
    assert not ok and err == "HTTP 500"


# ── routes: create form + required-field enforcement ────────────────────────
def test_create_form_renders_port_field(client, app):
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    r = client.get(f"/objedit/{aid}/edit?collection=server-policy/service.custom"
                   f"&create=1&title=Service")
    assert r.status_code == 200
    h = r.get_data(as_text=True)
    assert 'data-key="port"' in h


def test_create_object_rejects_missing_port(client, app):
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    r = client.post(f"/objedit/{aid}/create-object", json={
        "collection": "server-policy/service.custom", "mkey": "svc-x",
        "fields": {},
    })
    assert r.status_code == 400
    assert "Port" in (r.get_json() or {}).get("error", "")


def test_create_object_with_port_dryrun_ok(client, app):
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    r = client.post(f"/objedit/{aid}/create-object", json={
        "collection": "server-policy/service.custom", "mkey": "svc-x",
        "fields": {"port": "8443"},
    })
    j = r.get_json()
    assert r.status_code == 200 and j["ok"] and j["dry_run"], j
    assert j["request"]["body"]["data"]["port"] == "8443"
    assert j["request"]["body"]["data"]["name"] == "svc-x"


def test_host_list_add_row_form_has_fields(client, app):
    """A brand-new Protected Hostnames object (no rows, dead device, no cache)
    still renders host/action inputs in the add-row form via the seed."""
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    r = client.get(f"/objedit/{aid}/edit?collection=server-policy/allow-hosts"
                   f"&mkey=ph-new&title=Protected+Hostnames")
    assert r.status_code == 200
    h = r.get_data(as_text=True)
    assert "Add" in h and 'data-key="host"' in h
