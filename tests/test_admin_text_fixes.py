"""Administration UI/text fixes from the Documentation Center audit,
2026-10-03 (AD-01, AD-26, AD-28, AD-29, AD-30, AD-31, AD-34, AD-44, AD-45,
AD-49, AD-50, AD-51, AD-53, AD-57, AD-58, AD-60, AD-64)."""
from __future__ import annotations

from pathlib import Path

import pytest

from conftest import admin_user_id, login, make_user

ROOT = Path(__file__).resolve().parent.parent


def _tpl(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _custom(app, name, keys):
    from app.models import Profile, db
    with app.app_context():
        p = Profile(name=f"p-{name}", is_system=False)
        p.permission_set = set(keys)
        db.session.add(p)
        db.session.commit()
        pid = p.id
    return make_user(app, name, profile_id=pid)


# AD-01
def test_profiles_tab_needs_profiles_manage(app, client):
    uid = _custom(app, "usersonly", {"users.manage", "monitoring.view"})
    login(client, uid)
    html = client.get("/settings/").get_data(as_text=True)
    assert 'id="tab-profiles"' not in html and 'data-bs-target="#tab-profiles"' not in html
    login(client, admin_user_id(app))
    html = client.get("/settings/").get_data(as_text=True)
    assert 'id="tab-profiles"' in html and 'data-bs-target="#tab-profiles"' in html


# AD-26, AD-53, AD-60
def test_settings_page_texts(app, client):
    login(client, admin_user_id(app))
    html = client.get("/settings/").get_data(as_text=True)
    assert 'name="default_profile"' in html and 'placeholder="readonly"' in html
    assert 'name="favicon" class="form-control" accept=".png,.jpg,.jpeg,.webp,.gif,.ico,.svg"' in html
    assert 'name="logo" class="form-control" accept=".png,.jpg,.jpeg,.webp,.gif,.ico,.svg"' in html
    assert "Security Status" not in html and "All user actions logged" not in html


# AD-28
def test_cert_manager_new_page_follows_the_protocol(app, client, monkeypatch):
    from app.services import settings_store as store
    login(client, admin_user_id(app))
    monkeypatch.setattr(store, "cert_manager_protocol", lambda: "acme")
    html = client.get("/cert-manager/new").get_data(as_text=True)
    assert "(ACME)" in html and "Target appliance" in html
    assert "Target FortiWeb" not in html
    monkeypatch.setattr(store, "cert_manager_protocol", lambda: "adcs")
    assert "(ADCS)" in client.get("/cert-manager/new").get_data(as_text=True)


# AD-29
def test_the_adcs_request_id_is_read_from_the_signer_output():
    from app.services.cert_manager import ca_request_id_from_log
    assert ca_request_id_from_log("[*] Successfully requested certificate\n[*] Request ID is 42\n") == "42"
    assert ca_request_id_from_log('RequestId: "1234"') == "1234"
    assert ca_request_id_from_log("no id here") == ""


def test_issuance_stores_the_request_id(app, monkeypatch):
    from datetime import datetime, timedelta
    from app.models import ManagedCertificate
    from app.services import cert_manager as cm, settings_store as store
    monkeypatch.setattr(store, "cert_class_config", lambda c: {"template": "WebServer"})
    monkeypatch.setattr(cm, "generate_csr", lambda *a, **k: ("CSR", "KEY"))
    monkeypatch.setattr(cm, "sign_csr", lambda c, csr: ("PEM", "$ certipy req\n[*] Request ID is 77"))
    monkeypatch.setattr(cm, "parse_certificate", lambda pem: {
        "serial": "ab", "issued_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(days=90), "sans": []})
    with app.app_context():
        r = cm.create_certificate(None, "www.example.com", "server", deploy=False)
        row = ManagedCertificate.query.get(r["cert_id"])
        assert row.ca_request_id == "77"


# AD-30
def test_expiring_is_not_a_status_nobody_assigns():
    from app.models import ManagedCertificate
    assert "expiring" not in ManagedCertificate.STATUSES
    assert "c.status == 'expiring'" not in _tpl("app/templates/cert_manager/index.html")


# AD-31
def test_certificate_manager_link_only_for_user_manage(app, client):
    uid = make_user(app, "ro", role="readonly")
    login(client, uid, product="global")
    assert "/cert-manager/" not in client.get("/").get_data(as_text=True)
    login(client, admin_user_id(app), product="global")
    assert "/cert-manager/" in client.get("/").get_data(as_text=True)


# AD-34, AD-44, AD-64
def test_wording_matches_the_controls():
    assert "Tick 'Verify SSL Certificate'" in _tpl("app/services/trust_store.py")
    assert "SoT & Backup" not in _tpl("app/services/backup_server.py")
    assert "SoT &amp; Backup" not in _tpl("app/templates/system_backup/index.html")
    assert "MODE === 'ha' ? 'WAL replication + staged deploy' : 'no replication'" in \
        _tpl("app/templates/high_availability/index.html")


# AD-45
@pytest.mark.parametrize("rel", [
    "app/templates/settings/index.html", "app/templates/settings/_ai.html",
    "app/templates/system_backup/index.html", "app/services/thresholds.py",
])
def test_shipped_text_names_no_deployment(rel):
    text = _tpl(rel)
    for marker in ("visionebc", "backup-server", "192.0.2.34", "fortiweb08", "fw6 ", "id11", "id12",
                   "(id5", "Primary 248"):
        assert marker not in text, (rel, marker)


# AD-49, AD-51
def test_api_token_page_hints_and_confirms(app, client):
    login(client, admin_user_id(app))
    from app.extensions import db
    from app.models_api_token import ApiToken
    with app.app_context():
        t = ApiToken(name="tk1", public_id="pubx", token_hash="h", owner_user_id=admin_user_id(app),
                     product="fortiweb")
        db.session.add(t)
        db.session.commit()
    html = client.get("/api-tokens/").get_data(as_text=True)
    assert "all unchecked = no restriction" not in html
    assert "Revoke token &#39;tk1&#39;?" in html or "Revoke token 'tk1'?" in html
    assert "Delete token &#39;tk1&#39;?" in html or "Delete token 'tk1'?" in html


# AD-50
@pytest.mark.parametrize("product", ["fortianalyzer", "fortiauthenticator", "fortiadc", "global"])
def test_api_tokens_link_in_every_adom_with_tokens(app, client, product):
    login(client, admin_user_id(app), product=product)
    html = client.get("/settings/").get_data(as_text=True)
    assert 'href="/api-tokens/"' in html, product


# AD-57, AD-58
def test_dns_tool_save_lands_on_its_tab_and_dead_routes_are_gone(app, client):
    login(client, admin_user_id(app))
    r = client.post("/settings/dns-tool", data={"dns_name": ["a"], "dns_server": ["1.1.1.1"]})
    assert r.status_code == 302 and r.headers["Location"].endswith("#tab-dnstool")
    assert client.post("/settings/naming", data={}).status_code in (404, 405)
    assert client.post("/settings/segments", data={}).status_code in (404, 405)
