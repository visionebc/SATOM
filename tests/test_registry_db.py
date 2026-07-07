"""DB-backed endpoint registry: seed, loader, editor, and drift guards.

Covers the 2026-07-05 migration of the registry from a read-only
``endpoints.yaml`` to the ``registry_endpoints`` table:

* boot seed is INSERT-ONLY (operator edits / soft-deletes always survive);
* ``loader.resolve`` reads the DB (YAML is only the fallback);
* the editor is gated on ``registry_edit`` and audited;
* the Structure dependency tree must stay fully resolvable against the
  registry (the Registry <-> dependencies.py drift guard).
"""
from __future__ import annotations

import pytest

from tests.conftest import admin_user_id, login, make_user


def _yaml_count():
    from app.registry.loader import _yaml_registry
    return len(_yaml_registry())


# ---------------------------------------------------------------------------
# seed
# ---------------------------------------------------------------------------

def test_boot_seed_populates_registry_table(app):
    from app.models import RegistryEndpoint

    with app.app_context():
        assert RegistryEndpoint.query.filter_by(product="fortiweb").count() == _yaml_count()
        row = RegistryEndpoint.query.filter_by(name="server_policy").first()
        assert row is not None
        assert row.urn.startswith("/api/")
        assert row.product == "fortiweb"
        assert row.api_version == "v2.0"
        assert row.enabled is True


def test_seed_is_insert_only(app):
    """A re-seed never overwrites an operator edit nor resurrects a disable."""
    from app.extensions import db
    from app.models import RegistryEndpoint
    from app.registry import loader

    with app.app_context():
        edited = RegistryEndpoint.query.filter_by(name="server_policy").first()
        edited.urn = "/api/v2.0/custom/edited-by-operator"
        disabled = RegistryEndpoint.query.filter_by(name="vip").first()
        disabled.enabled = False
        db.session.commit()

        added = loader.seed_from_yaml()
        assert added == 0  # nothing new to add

        assert RegistryEndpoint.query.filter_by(name="server_policy").first().urn \
            == "/api/v2.0/custom/edited-by-operator"
        assert RegistryEndpoint.query.filter_by(name="vip").first().enabled is False


# ---------------------------------------------------------------------------
# loader
# ---------------------------------------------------------------------------

def test_resolve_reads_the_db_not_the_yaml(app):
    from app.extensions import db
    from app.models import RegistryEndpoint
    from app.registry import loader

    with app.app_context():
        row = RegistryEndpoint.query.filter_by(name="server_policy").first()
        row.urn = "/api/v2.0/cmdb/server-policy/renamed"
        db.session.commit()
        loader.invalidate_cache()

        assert loader.resolve("server_policy") == "/api/v2.0/cmdb/server-policy/renamed"


def test_soft_deleted_endpoint_fails_loudly(app):
    from app.extensions import db
    from app.models import RegistryEndpoint
    from app.registry import loader

    with app.app_context():
        row = RegistryEndpoint.query.filter_by(name="server_policy").first()
        row.enabled = False
        db.session.commit()
        loader.invalidate_cache()

        assert "server_policy" not in loader.load_registry()
        with pytest.raises(KeyError):
            loader.resolve("server_policy")


def test_operator_created_endpoint_resolves(app):
    from app.extensions import db
    from app.models import RegistryEndpoint
    from app.registry import loader

    with app.app_context():
        db.session.add(RegistryEndpoint(
            name="my_custom_ep", urn="/api/v2.0/cmdb/custom/thing", updated_by="op"))
        db.session.commit()
        loader.invalidate_cache()
        assert loader.resolve("my_custom_ep") == "/api/v2.0/cmdb/custom/thing"


# ---------------------------------------------------------------------------
# editor routes
# ---------------------------------------------------------------------------

def test_editor_requires_registry_edit_permission(app, client):
    uid = make_user(app, username="ro", role="readonly")
    login(client, uid)
    resp = client.post("/registry/save", data={
        "name": "hax", "urn": "/api/v2.0/x"})
    assert resp.status_code == 403


def test_admin_creates_updates_and_toggles_endpoint(app, client):
    from app.models import AuditLog, RegistryEndpoint

    login(client, admin_user_id(app))

    # create
    resp = client.post("/registry/save", data={
        "name": "test_editor_ep", "urn": "/api/v2.0/cmdb/test/editor"},
        follow_redirects=False)
    assert resp.status_code == 302
    with app.app_context():
        row = RegistryEndpoint.query.filter_by(name="test_editor_ep").first()
        assert row is not None and row.enabled
        rid = row.id
        assert AuditLog.query.filter_by(action="registry.endpoint_create",
                                        target="test_editor_ep").count() == 1

    # update
    client.post("/registry/save", data={
        "id": rid, "name": "test_editor_ep", "urn": "/api/v2.0/cmdb/test/edited"})
    with app.app_context():
        assert RegistryEndpoint.query.get(rid).urn == "/api/v2.0/cmdb/test/edited"

    # toggle off → resolve fails; toggle on → resolves again
    from app.registry import loader
    client.post(f"/registry/toggle/{rid}")
    with app.app_context():
        assert RegistryEndpoint.query.get(rid).enabled is False
        assert "test_editor_ep" not in loader.load_registry()
    client.post(f"/registry/toggle/{rid}")
    with app.app_context():
        assert loader.resolve("test_editor_ep") == "/api/v2.0/cmdb/test/edited"


def test_save_rejects_bad_input_and_duplicates(app, client):
    from app.models import RegistryEndpoint

    login(client, admin_user_id(app))

    # relative URN rejected
    client.post("/registry/save", data={"name": "bad_urn", "urn": "cmdb/no-slash"})
    # bad name rejected
    client.post("/registry/save", data={"name": "bad name!", "urn": "/api/v2.0/x"})
    # duplicate of a seeded name rejected
    client.post("/registry/save", data={"name": "server_policy", "urn": "/api/v2.0/dup"})

    with app.app_context():
        assert RegistryEndpoint.query.filter_by(name="bad_urn").count() == 0
        assert RegistryEndpoint.query.filter_by(name="bad name!").count() == 0
        assert RegistryEndpoint.query.filter_by(name="server_policy").count() == 1


def test_registry_page_shows_editor_only_to_editors(app, client):
    login(client, admin_user_id(app))
    html = client.get("/registry/").data.decode()
    assert 'id="endpointModal"' in html and "New Endpoint" in html

    uid = make_user(app, username="viewer", role="readonly")
    login(client, uid)
    html = client.get("/registry/").data.decode()
    assert 'id="endpointModal"' not in html


def test_section_page_renders_unified_template(app, client):
    login(client, admin_user_id(app))
    resp = client.get("/registry/System")
    assert resp.status_code == 200
    assert b"Sections" in resp.data  # index template sidebar, not the old bare table


# ---------------------------------------------------------------------------
# drift guard: Structure tree ↔ registry
# ---------------------------------------------------------------------------

def test_structure_tree_fully_backed_by_registry(app):
    """Every fetchable node of the dependency tree must resolve against the
    registry. This is the guard against endpoints.yaml/DB ↔ dependencies.py
    drift — a rename that breaks the Structure page breaks the build here."""
    from app.services import structure

    with app.app_context():
        tree = structure.load_catalog({}).tree()
        matched, fetchable, missing = structure.coverage(tree)
        assert missing == [] or missing == 0, f"structure nodes missing from registry: {missing}"
        assert matched == fetchable
