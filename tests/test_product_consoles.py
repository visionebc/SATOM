"""The FortiADC / FortiAnalyzer / FortiAuthenticator API consoles and catalogs.

Documentation Center audit, 2026-10-03 (PR-02, PR-08, PR-09, PR-15..PR-22).

* One write policy for the three consoles: a mutating call is a DRY RUN
  (method, path, body) until ``apply`` is explicit; every applied write is
  audited, including the ones the device refused; reads are not audited.
* The ADC console accepts only known HTTP methods: a translated option label
  ("ELIMINAR") used to skip the write gate and reach the device.
* The FAZ console reports the JSON-RPC status code, not a constant 200.
* The FAZ and FAC catalog editors write through ``registry_write``; a FAC
  re-point no longer re-enables a disabled row, and enabled rows can be
  disabled from the page.
* The ADC menu and editor allow-list follow the loader's catalog in every
  worker, not only in the one that served the edit.
"""
from __future__ import annotations

import ast
import json

import pytest

from conftest import admin_user_id, login


def _appl(app, kind, name):
    from app.extensions import db
    from app.models import Appliance
    with app.app_context():
        a = Appliance(name=name, kind=kind, host=name + ".invalid", port=443,
                      username="u", verify_ssl=False)
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        return a.id


def _audits(app, action):
    from app.models import AuditLog
    with app.app_context():
        # extra is stored as a Python literal (see drift_attribution._extra)
        return [(r.target, ast.literal_eval(r.extra or "{}"))
                for r in AuditLog.query.filter_by(action=action).all()]


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


# --------------------------------------------------------------------------- #
#  FortiADC console                                                           #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def adc(app, client, monkeypatch):
    from app.views import adc_api
    calls = []

    from app.clients.fortiadc import FortiADCClient

    class _Client:
        _device_error = staticmethod(FortiADCClient._device_error)

        def __init__(self, appliance):
            pass

        def api_call(self, method, path, body=None):
            calls.append((method, path, body))
            if path.endswith("/refuse"):
                return _Resp(400, {"errcode": "bad"})
            return _Resp(200, {"payload": 0})

    monkeypatch.setattr(adc_api, "FortiADCClient", _Client)
    aid = _appl(app, "fortiadc", "adc01")
    login(client, admin_user_id(app), product="fortiadc")
    return client, aid, calls


def test_adc_write_without_apply_is_a_dry_run(app, adc):
    client, aid, calls = adc
    r = client.post("/adc/api/execute", data={
        "appliance_id": aid, "endpoint": "/api/load_balance_pool",
        "method": "POST", "body": '{"mkey": "p1"}'})
    j = r.get_json()
    assert j["ok"] is True and j["dry_run"] is True
    assert j["request"] == {"method": "POST", "path": "/api/load_balance_pool",
                            "body": {"mkey": "p1"}}
    assert calls == [], "a dry run must not reach the device"
    assert _audits(app, "adc_api.execute") == []


def test_adc_write_with_apply_executes_and_is_audited(app, adc):
    client, aid, calls = adc
    r = client.post("/adc/api/execute", data={
        "appliance_id": aid, "endpoint": "/api/load_balance_pool",
        "method": "POST", "body": '{"mkey": "p1"}', "apply": "1"})
    j = r.get_json()
    assert j["ok"] is True and j["dry_run"] is False and j["status"] == 200
    assert ("POST", "/api/load_balance_pool", {"mkey": "p1"}) in calls
    rows = _audits(app, "adc_api.execute")
    assert len(rows) == 1
    assert rows[0][1]["method"] == "POST" and rows[0][1]["error"] is None


def test_adc_refused_write_is_audited_with_its_error(app, adc):
    client, aid, _calls = adc
    j = client.post("/adc/api/execute", data={
        "appliance_id": aid, "endpoint": "/api/refuse", "method": "DELETE",
        "apply": "1"}).get_json()
    assert j["status"] == 400
    rows = _audits(app, "adc_api.execute")
    assert len(rows) == 1 and rows[0][1]["error"].startswith("HTTP 400")


def test_adc_read_is_not_audited(app, adc):
    client, aid, calls = adc
    j = client.post("/adc/api/execute", data={
        "appliance_id": aid, "endpoint": "/api/system_global",
        "method": "GET"}).get_json()
    assert j["ok"] is True and j["status"] == 200
    assert ("GET", "/api/system_global", None) in calls
    assert _audits(app, "adc_api.execute") == []


@pytest.mark.parametrize("verb", ["ELIMINAR", "SUPPRIMER", "TRACE"])
def test_adc_unknown_method_never_reaches_the_device(app, adc, verb):
    client, aid, calls = adc
    j = client.post("/adc/api/execute", data={
        "appliance_id": aid, "endpoint": "/api/load_balance_pool",
        "method": verb, "apply": "1"}).get_json()
    assert j["ok"] is False and "Unknown HTTP method" in j["error"]
    assert calls == []


def test_adc_method_selector_sends_wire_verbs(app, adc):
    """value= is the verb, never the (translatable) label; PATCH is offered."""
    client, _aid, _calls = adc
    html = client.get("/adc/api/").get_data(as_text=True)
    for m in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        assert f'<option value="{m}"' in html, m
    assert 'id="adc-apply"' in html


# --------------------------------------------------------------------------- #
#  FortiAnalyzer console                                                      #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def faz(app, client, monkeypatch):
    from app.views import faz_api
    calls = []

    class _Client:
        _unwrap = staticmethod(faz_api.FortiAnalyzerClient._unwrap)

        def __init__(self, appliance):
            pass

        def api_call(self, verb, path, data=None):
            calls.append((verb, path, data))
            code = -6 if path.endswith("/refuse") else 0
            return {"id": 1, "result": [{"status": {"code": code,
                                                    "message": "x"},
                                         "url": path}]}

        def logout(self):
            pass

    monkeypatch.setattr(faz_api, "FortiAnalyzerClient", _Client)
    aid = _appl(app, "fortianalyzer", "faz01")
    login(client, admin_user_id(app), product="fortianalyzer")
    return client, aid, calls


def test_faz_write_without_apply_is_a_dry_run(app, faz):
    client, aid, calls = faz
    j = client.post("/faz/api/execute", data={
        "appliance_id": aid, "endpoint": "/dvmdb/adom/root",
        "method": "set", "body": '{"desc": "x"}'}).get_json()
    assert j["ok"] is True and j["dry_run"] is True
    assert j["request"]["method"] == "set"
    assert calls == []
    assert _audits(app, "faz_api.execute") == []


def test_faz_status_is_the_json_rpc_code(app, faz):
    client, aid, _calls = faz
    j = client.post("/faz/api/execute", data={
        "appliance_id": aid, "endpoint": "/dvmdb/refuse", "method": "set",
        "apply": "1"}).get_json()
    assert j["ok"] is True and j["dry_run"] is False
    assert j["status"] == -6 and "device code -6" in j["device_error"]
    rows = _audits(app, "faz_api.execute")
    assert len(rows) == 1 and "device code -6" in rows[0][1]["error"]


def test_faz_read_succeeds_and_is_not_audited(app, faz):
    client, aid, calls = faz
    j = client.post("/faz/api/execute", data={
        "appliance_id": aid, "endpoint": "/sys/status",
        "method": "get"}).get_json()
    assert j["status"] == 0 and j["device_error"] is None
    assert ("get", "/sys/status", None) in calls
    assert _audits(app, "faz_api.execute") == []


# --------------------------------------------------------------------------- #
#  Catalog editors through registry_write                                     #
# --------------------------------------------------------------------------- #

def _row(app, product, name):
    from app.models import RegistryEndpoint
    with app.app_context():
        r = RegistryEndpoint.query.filter_by(product=product, name=name).first()
        return None if r is None else (r.id, r.urn, r.enabled)


def test_faz_editor_refuses_a_duplicate_name(app, client):
    from app.extensions import db
    from app.models import RegistryEndpoint
    with app.app_context():
        db.session.add(RegistryEndpoint(product="fortianalyzer",
                                        api_version="jsonrpc",
                                        name="pr15_dup", urn="/a"))
        db.session.commit()
    from app.registry import loader
    with app.app_context():
        loader.load_faz_registry()      # prime the per-process cache
    login(client, admin_user_id(app), product="fortianalyzer")
    client.post("/faz/api/registry/save",
                data={"name": "pr15_dup", "urn": "/b"})
    assert _row(app, "fortianalyzer", "pr15_dup")[1] == "/a"
    client.post("/faz/api/registry/save",
                data={"name": "pr15_new", "urn": "/dvmdb/x"})
    assert _row(app, "fortianalyzer", "pr15_new")[1] == "/dvmdb/x"
    with app.app_context():
        # the writer dropped the FAZ cache: the new name resolves at once
        assert loader.load_faz_registry().get("pr15_new") == "/dvmdb/x"


def test_registry_write_validates_fac_urns_under_the_api_root(app):
    from app.services import registry_write
    with app.app_context():
        assert registry_write.validate("fortiauthenticator", "x", "/admin/")
        assert not registry_write.validate("fortiauthenticator", "x",
                                           "/api/v1/localusers/")
        ok, _m, _r = registry_write.save_endpoint(
            product="fortiauthenticator", name="pr15_fac", urn="/login/")
        assert ok is False
        assert registry_write.default_api_version("fortianalyzer") == "jsonrpc"


def test_fac_repoint_keeps_a_disabled_row_disabled(app, client):
    from app.extensions import db
    from app.models import RegistryEndpoint
    with app.app_context():
        db.session.add(RegistryEndpoint(product="fortiauthenticator",
                                        api_version="v1", name="pr16_off",
                                        urn="/api/v1/old/", enabled=False))
        db.session.commit()
    login(client, admin_user_id(app), product="fortiauthenticator")
    client.post("/fac/api/endpoint/save",
                data={"name": "pr16_off", "urn": "/api/v1/new/"})
    _id, urn, enabled = _row(app, "fortiauthenticator", "pr16_off")
    assert urn == "/api/v1/new/" and enabled is False
    rows = _audits(app, "fac_api.registry_save")
    assert rows and rows[-1][1]["enabled"] is False


def test_fac_page_offers_disable_and_gates_write_methods(app, client):
    """Enabled rows get a Disable form; a user without execute_write sees
    the non-GET methods disabled."""
    from app.extensions import db
    from app.models import RegistryEndpoint
    from conftest import make_user, profile_id
    with app.app_context():
        db.session.add(RegistryEndpoint(product="fortiauthenticator",
                                        api_version="v1", name="pr17_on",
                                        urn="/api/v1/pr17/", enabled=True))
        db.session.commit()
    rid = _row(app, "fortiauthenticator", "pr17_on")[0]
    _appl(app, "fortiauthenticator", "fac01")
    login(client, admin_user_id(app), product="fortiauthenticator")
    html = client.get("/fac/api/").get_data(as_text=True)
    assert f'/fac/api/endpoint/toggle/{rid}"' in html
    assert '<option value="DELETE">' in html

    ro = make_user(app, "ro17", role="readonly",
                   profile_id=profile_id(app, "readonly"))
    login(client, ro, product="fortiauthenticator")
    html = client.get("/fac/api/").get_data(as_text=True)
    assert '<option value="DELETE" disabled>' in html
    assert '<option value="GET">' in html
    assert "/fac/api/endpoint/toggle/" not in html


# --------------------------------------------------------------------------- #
#  ADC caches follow the loader in every worker                               #
# --------------------------------------------------------------------------- #

def test_adc_menu_and_editor_follow_a_new_loader_map(app, monkeypatch):
    """Another worker's edit reaches this one as a NEW loader map (TTL
    refresh); no invalidate() is ever called here."""
    from app.registry import loader
    from app.services import adc_menu, adc_objform
    with app.app_context():
        reg1 = dict(loader.load_adc_registry())
        assert "load_balance_pool" in reg1
        monkeypatch.setattr(loader, "load_adc_registry", lambda: reg1)
        tabs = {t.logical for g in adc_menu.menu() for i in g.items for t in i.tabs}
        assert "load_balance_pool" in tabs
        assert adc_objform.is_known("load_balance_pool")

        reg2 = {k: v for k, v in reg1.items() if k != "load_balance_pool"}
        monkeypatch.setattr(loader, "load_adc_registry", lambda: reg2)
        tabs = {t.logical for g in adc_menu.menu() for i in g.items for t in i.tabs}
        assert "load_balance_pool" not in tabs
        assert not adc_objform.is_known("load_balance_pool")
    adc_menu.invalidate()
    adc_objform.invalidate()


def test_loader_invalidation_drops_the_editor_views(app):
    from app.registry import loader
    from app.services import adc_objform
    with app.app_context():
        adc_objform.is_known("load_balance_pool")
        assert adc_objform._views is not None
        loader.invalidate_adc_cache()
        assert adc_objform._views is None


# --------------------------------------------------------------------------- #
#  ADC object editor: first child row of an empty table                       #
# --------------------------------------------------------------------------- #

def test_empty_pool_offers_the_required_member_fields(app, client, monkeypatch):
    """The add-row form of an EMPTY pool used to offer only ``mkey``; saving
    then failed "Missing required field(s): real_server_id"."""
    from app.views import adc

    class _Client:
        def __init__(self, appliance):
            pass

        def get_object(self, logical, mkey):
            return {"mkey": mkey, "type": "ipv4"}

        def list_with_error(self, logical, **kw):
            return [], None

    monkeypatch.setattr(adc, "FortiADCClient", _Client)
    _appl(app, "fortiadc", "adc01")
    login(client, admin_user_id(app), product="fortiadc")
    html = client.get("/adc/obj/load_balance_pool?mkey=p1").get_data(as_text=True)
    new_row = html[html.index('class="adc-row-scope adc-row-new'):]
    new_row = new_row[:new_row.index("</details>")]
    assert 'data-key="real_server_id"' in new_row
    assert "No field template is known" not in html


# --------------------------------------------------------------------------- #
#  ADOM gates, sidebar rules, ADC Signatures                                  #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("product, url, home", [
    ("fortiadc", "/firmware/", "/adc/"),
    ("fortiauthenticator", "/firmware/", "/fac/"),
    ("fortiauthenticator", "/backups/", "/fac/"),
])
def test_adom_gate_no_longer_admits_unlinked_pages(app, client, product, url, home):
    login(client, admin_user_id(app), product=product)
    r = client.get(url)
    assert r.status_code in (301, 302) and r.headers["Location"].endswith(home), (
        product, url, r.status_code, r.headers.get("Location"))


def test_fortianalyzer_still_reaches_its_firmware_page(app, client):
    login(client, admin_user_id(app), product="fortianalyzer")
    assert client.get("/firmware/").status_code == 200


def _sidebar(html):
    return html[html.index('class="fw-nav-top"'):html.index("<!-- MAIN CONTENT -->")]


@pytest.mark.parametrize("product, home, api", [
    ("fortiadc", "/adc/", "/adc/api/"),
    ("fortianalyzer", "/faz/", "/faz/api/"),
    ("fortiauthenticator", "/fac/", "/fac/api/"),
])
def test_one_sidebar_rule_for_the_three_api_consoles(app, client, product, home, api):
    """registry.view (the console's own gate) draws the link; nothing else."""
    from conftest import make_user, profile_id
    ro = make_user(app, "ro-" + product[:8], role="readonly",
                   profile_id=profile_id(app, "readonly"))
    login(client, ro, product=product)
    side = _sidebar(client.get(home, follow_redirects=True).get_data(as_text=True))
    assert f'href="{api}"' in side, product

    from test_access_gates_audit import _zero_key_user
    login(client, _zero_key_user(app, "nk-" + product[:8], keys=("view",)),
          product=product)
    side = _sidebar(client.get(home, follow_redirects=True).get_data(as_text=True))
    assert f'href="{api}"' not in side, product


def test_adc_signatures_open_to_protection_view(app, client, monkeypatch):
    from app.views import adc
    from conftest import make_user, profile_id

    class _Client:
        def __init__(self, appliance):
            pass

        def list_with_error(self, logical, **kw):
            return [{"mkey": "sig-default", "status": "enable"}], None

    monkeypatch.setattr(adc, "FortiADCClient", _Client)
    _appl(app, "fortiadc", "adc01")
    ro = make_user(app, "ro-sig", role="readonly",
                   profile_id=profile_id(app, "readonly"))
    login(client, ro, product="fortiadc")
    r = client.get("/adc/signatures")
    assert r.status_code == 200 and "sig-default" in r.get_data(as_text=True)
    side = _sidebar(client.get("/adc/").get_data(as_text=True))
    assert 'href="/adc/signatures"' in side

    from test_access_gates_audit import _zero_key_user
    login(client, _zero_key_user(app, "nk-sig", keys=("view",)), product="fortiadc")
    assert client.get("/adc/signatures").status_code == 403


# --------------------------------------------------------------------------- #
#  FortiAnalyzer Device Manager: the ADOM is sent, not assumed               #
# --------------------------------------------------------------------------- #

def test_faz_device_action_targets_the_chosen_adom(app, client):
    _appl(app, "fortianalyzer", "faz01")
    login(client, admin_user_id(app), product="fortianalyzer")
    j = client.post("/faz/device-action", json={
        "action": "authorize", "names": ["fgt1"], "adom": "FortiGate"}).get_json()
    assert j["ok"] is True and j["dry_run"] is True
    assert j["request"]["body"]["adom"] == "FortiGate"
    r = client.post("/faz/device-action", json={
        "action": "delete", "names": ["fgt1"], "adom": "../x y"})
    assert r.status_code == 400


def test_faz_device_toolbar_sends_the_adom():
    import os
    src = open(os.path.join(os.path.dirname(__file__), "..", "app", "templates",
                            "faz", "section.html")).read()
    assert 'id="fazdev-adom"' in src
    assert "adom: ((document.getElementById('fazdev-adom')" in src


def test_adc_naming_patterns_are_marked_reference_only(app, client):
    login(client, admin_user_id(app), product="fortiadc")
    html = client.get("/naming/?product=fortiadc").get_data(as_text=True)
    assert "Reference only." in html
    login(client, admin_user_id(app), product="fortiweb")
    html = client.get("/naming/?product=fortiweb").get_data(as_text=True)
    assert "Reference only." not in html
