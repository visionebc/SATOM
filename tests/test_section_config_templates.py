"""Config-section template library is scoped to the SELECTED object type.

A section's ``config:<section>`` templates all share ONE kind, so without
scoping the System section shows its NTP template while you are editing Global /
Hostname (the reported bug). ``list_config_templates(kind, collection)`` keeps
only templates captured from the object type currently being viewed (plus
freeform templates that declare no endpoint — never hide an authored one).
"""
from __future__ import annotations

import json


def _tpl(kind, name, endpoint):
    """A saved template whose body declares (or not) a captured endpoint."""
    from app.models import Template, db
    body = {}
    if endpoint is not None:
        body = {"subobjects": [{"action": "update", "endpoint": endpoint,
                                "mkey": "", "data": {"data": {"x": 1}}}]}
    t = Template(kind=kind, name=name, version=1, body=json.dumps(body),
                 status="pending")
    db.session.add(t)
    db.session.commit()
    return t.id


def test_scopes_section_templates_to_selected_type(session):
    from app.services.templates import list_config_templates
    g = _tpl("config:system", "hostname-baseline", "/api/v2.0/cmdb/system/global")
    n = _tpl("config:system", "ntp-baseline", "/api/v2.0/cmdb/system/ntp")

    ids = {t.id for t in list_config_templates("config:system", "system/global")}
    assert g in ids
    assert n not in ids          # the reported bug: NTP must NOT show under Global


def test_matches_full_rest_path_endpoint_form(session):
    from app.services.templates import list_config_templates
    n = _tpl("config:system", "ntp-baseline", "/api/v2.0/cmdb/system/ntp")
    ids = {t.id for t in list_config_templates("config:system", "system/ntp")}
    assert n in ids              # save-time full path normalises to the same collection


def test_no_collection_returns_whole_section(session):
    from app.services.templates import list_config_templates
    g = _tpl("config:system", "hostname-baseline", "/api/v2.0/cmdb/system/global")
    n = _tpl("config:system", "ntp-baseline", "/api/v2.0/cmdb/system/ntp")
    ids = {t.id for t in list_config_templates("config:system")}
    assert {g, n} <= ids


def test_freeform_no_endpoint_is_never_hidden(session):
    from app.services.templates import list_config_templates
    f = _tpl("config:system", "freeform", None)   # body {} -> no endpoint
    ids = {t.id for t in list_config_templates("config:system", "system/ntp")}
    assert f in ids


def test_section_page_hides_other_object_types_templates(client, app, monkeypatch):
    """End-to-end (the reported bug): the System section page, viewing
    Global / Hostname, must show its own template but NOT the NTP template."""
    import json
    from tests.conftest import login, admin_user_id
    from app.models import Appliance, Template, db
    from app.services import objform
    import app.views.section_config as sc

    with app.app_context():
        a = Appliance(name="fw-test", kind="fortiweb", host="127.0.0.1",
                      port=443, username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a)
        for nm, coll in (("hostname-baseline", "system/global"),
                         ("ntp-baseline", "system/ntp")):
            db.session.add(Template(
                kind="config:system", name=nm, version=1, status="pending",
                body=json.dumps({"subobjects": [{
                    "action": "update", "endpoint": objform.rest_path(coll),
                    "mkey": "", "data": {"data": {}}}]})))
        db.session.commit()
        aid, uid = a.id, admin_user_id(app)

    # Keep it offline: no live device read (the box is fake).
    monkeypatch.setattr(sc.read_layer, "read_objects", lambda *a, **k: ([], {}))
    monkeypatch.setattr(sc.read_layer, "has_any_cache", lambda *a, **k: True)

    login(client, uid, product="fortiweb")
    with client.session_transaction() as s:
        s["appliance_id"] = str(aid)
    resp = client.get("/configuration/system?type=global")
    html = resp.get_data(as_text=True)

    assert resp.status_code == 200
    assert "hostname-baseline" in html      # the Global type's own template shows
    assert "ntp-baseline" not in html       # the NTP template is hidden here
