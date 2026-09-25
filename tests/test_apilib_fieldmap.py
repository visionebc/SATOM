"""The operator-authored rename map (``/web/registry/field-map``).

What fails silently here: a mapping that is DELETED takes the record of what
was believed with it (the library's rule is that no path deletes a row); a
retired mapping that is still honoured keeps turning a real loss into a
"rename"; and a form that writes without an audit row leaves nobody to ask.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import admin_user_id, login, make_user, profile_id

URL = "/web/registry/field-map/"
TEMPLATE = Path(__file__).resolve().parents[1] / "app" / "templates" / "registry" / "field_map.html"


def _admin(app, client):
    login(client, admin_user_id(app))
    return client


def _add(client, **kw):
    form = {"product": "fortiweb", "endpoint": "widget", "from_field": "legacy",
            "to_field": "modern", "from_version": "7.6.8", "to_version": "8.0.5",
            "note": "release notes 8.0.5"}
    form.update(kw)
    return client.post(URL + "add", data=form)


def _rows(app):
    from app.models_apilib import ApiLibFieldMap
    with app.app_context():
        return [(m.id, m.from_field, m.to_field, m.retired_at, m.created_by, m.retired_by)
                for m in ApiLibFieldMap.query.order_by(ApiLibFieldMap.id).all()]


def _audit(app, action):
    from app.models import AuditLog
    with app.app_context():
        return AuditLog.query.filter_by(action=action).count()


def test_the_page_lives_under_the_web_registry(app):
    rules = {r.endpoint: str(r) for r in app.url_map.iter_rules()}
    assert rules["apilib_fieldmap.index"] == URL
    assert rules["apilib_fieldmap.retire"] == URL + "<int:map_id>/retire"


def test_the_page_needs_the_registry_edit_permission(app, client):
    uid = make_user(app, username="ro", role="readonly",
                    profile_id=profile_id(app, "readonly"))
    login(client, uid)
    assert client.get(URL).status_code == 403
    assert client.post(URL + "add", data={}).status_code == 403
    assert client.post(URL + "1/retire").status_code == 403


def test_the_admin_sees_the_page_with_a_csrf_form(app, client):
    r = _admin(app, client).get(URL)
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert 'name="csrf_token"' in html
    assert "API field renames" in html


def test_adding_a_mapping_stores_the_author_and_audits_it(app, client):
    _admin(app, client)
    r = _add(client)
    assert r.status_code == 302
    rows = _rows(app)
    assert len(rows) == 1
    _id, frm, to, retired, by, _rb = rows[0]
    assert (frm, to, retired, by) == ("legacy", "modern", None, "admin")
    assert _audit(app, "apilib.field_map_add") == 1


def test_the_new_mapping_is_honoured_by_the_library(app, client):
    from app.services import api_library as lib
    from app.services import version_compat as vc
    _admin(app, client)
    _add(client)
    with app.app_context():
        for v, fields in (("7.6.8", {"legacy": {}, "k": {}}), ("8.0.5", {"modern": {}, "k": {}})):
            lib.ingest({"product": "fortiweb", "source": "sweep", "captured_at": "2026-01-01",
                        "origin_ref": "t@" + v, "device": None,
                        "scope": {"kind": "build", "version": v, "build": ""},
                        "healthy": True, "skip_reason": "",
                        "endpoints": {"widget": {"urn": "/u", "section": "s", "verdict": "ok",
                                                 "rows": None, "fields": fields}}})
        r = vc.compare_object("fortiweb", "8.0.5", "widget", ["legacy", "k"],
                              source_version="7.6.8")
        assert r["renamed"] and r["dropped"] == []


@pytest.mark.parametrize("bad", [
    {"product": "fortinope"},
    {"to_field": "legacy"},                       # same name twice
    {"endpoint": "bad name!"},
    {"from_version": "banana"},
    {"from_version": "8.0.5", "to_version": "7.6.8"},  # rename runs backwards
    {"note": "x" * 501},
])
def test_invalid_input_is_refused_and_writes_nothing(app, client, bad):
    _admin(app, client)
    r = _add(client, **bad)
    assert r.status_code == 302
    assert _rows(app) == []
    assert _audit(app, "apilib.field_map_add") == 0


def test_the_same_mapping_twice_is_refused(app, client):
    _admin(app, client)
    _add(client)
    _add(client)
    assert len(_rows(app)) == 1


def test_retire_never_deletes_and_is_audited(app, client):
    _admin(app, client)
    _add(client)
    mid = _rows(app)[0][0]
    r = client.post(URL + "%d/retire" % mid, json={})
    assert r.status_code == 200 and r.get_json()["ok"] is True
    rows = _rows(app)
    assert len(rows) == 1                     # still there
    assert rows[0][3] is not None and rows[0][5] == "admin"
    assert _audit(app, "apilib.field_map_retire") == 1
    again = client.post(URL + "%d/retire" % mid, json={})
    assert again.status_code == 409
    assert client.post(URL + "9999/retire", json={}).status_code == 404


def test_a_retired_mapping_can_be_added_again_as_a_new_row(app, client):
    _admin(app, client)
    _add(client)
    client.post(URL + "%d/retire" % _rows(app)[0][0], json={})
    _add(client)
    rows = _rows(app)
    assert len(rows) == 2 and rows[0][3] is not None and rows[1][3] is None


def test_retired_rows_are_listed_only_on_request(app, client):
    _admin(app, client)
    _add(client, note="first-note")
    client.post(URL + "%d/retire" % _rows(app)[0][0], json={})
    assert "first-note" not in client.get(URL).get_data(as_text=True)
    page = client.get(URL + "?retired=1").get_data(as_text=True)
    assert "legacy" in page and "Retired" in page


def test_retire_is_refused_without_a_csrf_token(app, client):
    """The fetch sends X-CSRF-Token; a POST without it must not retire."""
    _admin(app, client)
    _add(client)
    mid = _rows(app)[0][0]
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        r = client.post(URL + "%d/retire" % mid, json={})
        assert r.status_code in (400, 302)
        assert _rows(app)[0][3] is None
        html = client.get(URL).get_data(as_text=True)
        token = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
        ok = client.post(URL + "%d/retire" % mid, json={},
                         headers={"X-CSRF-Token": token})
        assert ok.status_code == 200
    finally:
        app.config["WTF_CSRF_ENABLED"] = False
    assert _rows(app)[0][3] is not None


def test_the_template_sends_the_csrf_header_and_stays_light():
    src = TEMPLATE.read_text()
    assert "'X-CSRF-Token'" in src
    assert "fw-card" in src
    for dark in ("backdrop-filter", "glass", "#0f172a", "rgba(15,23,42"):
        assert dark not in src


def test_the_page_is_on_the_concept_map():
    from app.services import concept_map
    assert any(p["endpoint"] == "apilib_fieldmap.index" for p in concept_map.PAGES)
