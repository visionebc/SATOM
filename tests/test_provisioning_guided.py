"""System-profile builder: standalone element format.

The builder mirrors the desktop: the Element picker offers EVERY config (cmdb)
object grouped by GUI section; per element the operator sets singleton/mkey and
types the JSON values. No firmware-line / typed-schema layer.
"""
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


def test_catalog_offers_far_more_than_the_curated_baselines():
    """all_specs() = every cmdb object, so the picker is not limited to the ~16
    curated baselines (the whole point of matching the standalone)."""
    all_keys = {s.key for s in prov.all_specs()}
    curated = {s.key for s in prov.PROVISION_CATALOG}
    assert curated <= all_keys
    assert len(all_keys) > len(curated)


from tests.conftest import login, admin_user_id


def _admin(app, client):
    login(client, admin_user_id(app))


def test_new_form_offers_objects_grouped_by_section(app, client):
    _admin(app, client)
    r = client.get("/provisioning/new")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "<optgroup" in body            # objects grouped by GUI section
    assert "Add element" in body
    # the rejected typed-schema / firmware-line layer is gone
    assert "__FIELD_SCHEMAS" not in body
    assert 'name="line"' not in body


def test_json_post_builds_item_data(app, client):
    _admin(app, client)
    r = client.post("/provisioning/new", data={
        "name": "json-dns", "rows": "0",
        "key_0": "dns", "mkey_0": "", "data_0": '{"primary": "192.0.2.3", "domain": "example.net"}',
    }, follow_redirects=True)
    assert r.status_code == 200
    from app.services.templates import list_templates
    from app.models import Template
    with app.app_context():
        prof = [t for t in list_templates(Template.KIND_SYSTEM) if t.name == "json-dns"][0]
        item = prof.body_dict["items"][0]
        assert item["endpoint"] == "dns"
        assert item["data"] == {"primary": "192.0.2.3", "domain": "example.net"}


def test_non_curated_object_is_provisionable(app, client):
    """An object outside the curated baseline list (key == registry endpoint)
    still builds: the catalog is the whole registry, not just the 16."""
    _admin(app, client)
    curated = {s.key for s in prov.PROVISION_CATALOG}
    extra = next(s for s in prov.all_specs() if s.key not in curated)
    r = client.post("/provisioning/new", data={
        "name": "raw-any", "rows": "0",
        "key_0": extra.key, "mkey_0": "", "data_0": '{"comment": "x"}',
    }, follow_redirects=True)
    assert r.status_code == 200
    from app.services.templates import list_templates
    from app.models import Template
    with app.app_context():
        prof = [t for t in list_templates(Template.KIND_SYSTEM) if t.name == "raw-any"][0]
        item = prof.body_dict["items"][0]
        assert item["endpoint"] == extra.endpoint
        assert item["data"] == {"comment": "x"}


def test_bad_json_reflashes_with_input_kept(app, client):
    _admin(app, client)
    r = client.post("/provisioning/new", data={
        "name": "bad-json", "rows": "0",
        "key_0": "global", "data_0": "{not json",
    }, follow_redirects=True)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "not valid JSON" in body


def test_unknown_key_reflashes(app, client):
    _admin(app, client)
    r = client.post("/provisioning/new", data={
        "name": "bad-key", "rows": "0",
        "key_0": "definitely_not_an_endpoint", "data_0": "{}",
    }, follow_redirects=True)
    assert r.status_code == 200
    assert "Unknown provisioning element" in r.get_data(as_text=True)
