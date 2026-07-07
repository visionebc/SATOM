"""Web Protection FortiWeb-parity guards.

1. The wp_menu tree resolves every tab (incl. the 7.6.4 tabs added 2026-07-06:
   CORS → Allowed Origin, DLP → DLP Policy) and carries FortiWeb list columns.
2. Tab order is FortiWeb's own (dependencies first — Rule before Policy).
3. Template-managed WPPs: a profile named by an APPROVED web-protection-profile
   template is read-only through objedit (403), everywhere except the
   Administrator → WPP Templates flow.
"""
from __future__ import annotations

from tests.conftest import admin_user_id, login


def _menu(app):
    from app.services import wp_menu
    with app.app_context():
        wp_menu._registry_index.cache_clear()
        wp_menu.menu.cache_clear()
        return wp_menu.menu()


def _tabs(groups, item_key):
    for g in groups:
        for it in g.items:
            if it.key == item_key:
                return [t.label for t in it.tabs]
    return []


def test_menu_carries_new_fortiweb_tabs(app):
    groups = _menu(app)
    assert _tabs(groups, "cors") == ["Allowed Origin", "CORS Protection Rule",
                                     "CORS Protection Policy"]
    assert _tabs(groups, "dlp") == ["DLP Dictionary", "DLP Sensor", "DLP Rule",
                                    "DLP Policy", "DLP Exception"]


def test_menu_tab_order_is_dependencies_first(app):
    groups = _menu(app)
    assert _tabs(groups, "websocket") == ["WebSocket Security Rule",
                                          "WebSocket Security Policy"]
    assert _tabs(groups, "grpc")[0] == "gRPC IDL File"
    assert _tabs(groups, "url-access") == ["URL Access Parameter",
                                           "URL Access Rule",
                                           "URL Access Policy"]
    assert _tabs(groups, "custom-policy") == ["Custom Rule", "Custom Policy"]


def test_menu_tabs_carry_columns(app):
    groups = _menu(app)
    for g in groups:
        for it in g.items:
            for t in it.tabs:
                # Every tab resolved against the registry; most carry columns
                # (a couple of name-only lists are allowed: IDL file, params…).
                assert t.collection.startswith("waf/")
    # Spot-check a fw6-verified column set.
    ua = [t for g in groups for it in g.items for t in it.tabs
          if it.key == "url-access" and t.label == "URL Access Rule"][0]
    assert [c.key for c in ua.columns] == ["host", "action", "severity",
                                           "trigger"]


def _mk_appliance(app):
    from app.extensions import db
    from app.models import Appliance
    with app.app_context():
        a = Appliance(name="fwtest", kind="fortiweb", host="192.0.2.10",
                      port=443, username="admin", password_enc="x",
                      verify_ssl=False)
        db.session.add(a)
        db.session.commit()
        return a.id


def _mk_approved_wpp_template(app, name):
    from app.models import Template
    from app.services import templates as lib
    with app.app_context():
        row = lib.save_template(Template.KIND_WEB_PROTECTION, name,
                                {"data": {"data": {"name": name}}},
                                author="admin")
        lib.approve_template(row.id, reviewer="admin")
        return row.id


def test_managed_wpp_names_from_approved_templates(app):
    from app.services.templates import managed_wpp_names
    _mk_approved_wpp_template(app, "WPP-Gold")
    with app.app_context():
        assert "WPP-Gold" in managed_wpp_names()


def test_objedit_blocks_writes_to_template_managed_wpp(app, client):
    aid = _mk_appliance(app)
    _mk_approved_wpp_template(app, "WPP-Gold")
    login(client, admin_user_id(app))
    coll = "waf/web-protection-profile.inline-protection"
    r = client.post(f"/objedit/{aid}/save-object",
                    json={"collection": coll, "mkey": "WPP-Gold",
                          "fields": {"comment": "x"}})
    assert r.status_code == 403
    assert "template-managed" in (r.get_json() or {}).get("error", "").lower()
    r2 = client.post(f"/objedit/{aid}/delete-object",
                     json={"collection": coll, "mkey": "WPP-Gold"})
    assert r2.status_code == 403


def test_objedit_allows_unmanaged_wpp_dry_run_path(app, client):
    """An unmanaged profile passes the lock (may still fail later on device
    reachability — the lock check happens before any device contact)."""
    aid = _mk_appliance(app)
    login(client, admin_user_id(app))
    coll = "waf/web-protection-profile.inline-protection"
    r = client.post(f"/objedit/{aid}/save-object",
                    json={"collection": coll, "mkey": "WPP-Free",
                          "fields": {"comment": "x"}})
    assert r.status_code != 403
