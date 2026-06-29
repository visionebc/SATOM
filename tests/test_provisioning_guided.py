"""Guided-provisioning: catalog reconciliation, typed build, JSON fallback, render."""
from __future__ import annotations

from app.services import provisioning as prov


def test_all_16_base_specs_resolve_against_registry():
    """Every curated base spec's endpoint must exist in the registry so it is
    offered in available_specs() (regression: static_route/snmp_*/admin were
    silently dropped because their endpoint names didn't match registry keys)."""
    available = {s.key for s in prov.available_specs()}
    base = {s.key for s in prov.PROVISION_CATALOG}
    missing = sorted(base - available)
    assert missing == [], f"base specs dropped by registry mismatch: {missing}"
    assert len(prov.available_specs()) >= 16


from tests.conftest import login, admin_user_id


def _admin(app, client):
    login(client, admin_user_id(app))


def test_new_form_renders_typed_inputs(app, client):
    _admin(app, client)
    r = client.get("/provisioning/new")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "window.__FIELD_SCHEMAS" in body      # schemas embedded for the active line
    assert 'name="line"' in body                  # line selector present


def test_typed_post_builds_item_data_via_schema(app, client):
    _admin(app, client)
    # one DNS row authored with typed fields f_0_primary / f_0_domain (no raw JSON)
    r = client.post("/provisioning/new", data={
        "name": "guided-dns", "line": "8.0", "rows": "0",
        "key_0": "dns", "mkey_0": "", "data_0": "{}",
        "f_0_primary": "192.0.2.3", "f_0_secondary": "", "f_0_domain": "example.net",
    }, follow_redirects=True)
    assert r.status_code == 200
    from app.services.templates import list_templates
    from app.models import Template
    with app.app_context():
        prof = [t for t in list_templates(Template.KIND_SYSTEM) if t.name == "guided-dns"][0]
        item = prof.body_dict["items"][0]
        assert item["endpoint"] == "dns"
        assert item["data"] == {"primary": "192.0.2.3", "domain": "example.net"}
        assert prof.body_dict["line"] == "8.0"


def test_json_fallback_still_works_for_schemaless_object(app, client):
    _admin(app, client)
    # 'global' has no seed schema yet -> raw JSON path must still work
    r = client.post("/provisioning/new", data={
        "name": "raw-global", "line": "8.0", "rows": "0",
        "key_0": "global", "mkey_0": "", "data_0": '{"hostname": "fw-test"}',
    }, follow_redirects=True)
    assert r.status_code == 200
    from app.services.templates import list_templates
    from app.models import Template
    with app.app_context():
        prof = [t for t in list_templates(Template.KIND_SYSTEM) if t.name == "raw-global"][0]
        assert prof.body_dict["items"][0]["data"] == {"hostname": "fw-test"}


def test_typed_post_missing_required_reflashes(app, client):
    _admin(app, client)
    r = client.post("/provisioning/new", data={
        "name": "bad-dns", "line": "8.0", "rows": "0",
        "key_0": "dns", "data_0": "{}", "f_0_primary": "",  # required primary empty
    }, follow_redirects=True)
    assert r.status_code == 200
    assert "is required" in r.get_data(as_text=True)


def test_form_embeds_schema_for_dns_and_advanced_toggle(app, client):
    _admin(app, client)
    body = client.get("/provisioning/new").get_data(as_text=True)
    assert "window.__FIELD_SCHEMAS" in body and "window.__SCHEMA_LINE" in body
    assert '"primary"' in body            # dns schema embedded
    assert "Advanced (JSON)" in body      # per-row fallback toggle label
    assert "prov-fields" in body          # typed-field container
