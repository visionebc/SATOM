"""DNS & LB Lookup tool — parsing, server-list settings, matching, routes."""
from __future__ import annotations

import json

import pytest

from app.services import dns_tool
from tests.conftest import admin_user_id, login


# ---------------------------------------------------------------- parsing

def test_parse_entry_type_suffix():
    assert dns_tool.parse_entry("foo.bar CNAME") == ("foo.bar", "CNAME")
    assert dns_tool.parse_entry("foo.bar") == ("foo.bar", None)
    # an unknown trailing token is part of the query, not a record type
    assert dns_tool.parse_entry("foo bar") == ("foo bar", None)


def test_resolve_wildcard_uses_first_label():
    assert dns_tool.resolve_wildcard("*.test.admin.ch") == "test.test.admin.ch"
    assert dns_tool.resolve_wildcard("plain.host") == "plain.host"


def test_clean_entry_strips_shell_metachars():
    cleaned = dns_tool.clean_entry("  app.x.mx;`rm`$(x)|&<> ")
    assert not set(";`$()|&<>'\"") & set(cleaned)
    assert "app.x.mx" in cleaned


def test_app_id_extraction():
    assert dns_tool._app_id("AppID: WEB-1234 production") == "WEB-1234"
    assert dns_tool._app_id("legacy app-id=shop42") == "shop42"
    assert dns_tool._app_id("[APP-77] storefront") == "APP-77"
    assert dns_tool._app_id("no tag here") == ""
    assert dns_tool._app_id("") == ""


# ---------------------------------------------------------------- matching

def _rows():
    return [
        {"gateway": "fw1", "policy": "pol-shop",
         "members": "192.0.2.5:80, 192.0.2.6:80"},
        {"gateway": "fw2", "policy": "pol-api", "members": "192.0.2.9:8443"},
    ]


def test_match_rows_substring_default():
    hits = dns_tool.match_rows(_rows(), "192.0.2.5", "192.0.2.5")
    assert [h["policy"] for h in hits] == ["pol-shop"]


def test_match_rows_exact_uses_comma_tokens():
    hits = dns_tool.match_rows(_rows(), "192.0.2.6:80", "192.0.2.6:80", exact=True)
    assert [h["policy"] for h in hits] == ["pol-shop"]
    # exact means the whole token — a bare IP no longer matches ip:port
    assert dns_tool.match_rows(_rows(), "192.0.2.6", "192.0.2.6", exact=True) == []


# ------------------------------------------------------- server-list config

def test_servers_default_then_round_trip(app):
    with app.app_context():
        assert dns_tool.dns_servers() == [dict(s) for s in dns_tool.DEFAULT_SERVERS]
        saved = dns_tool.save_dns_servers([
            {"name": "BV", "server": "192.0.2.1", "enabled": True},
            {"name": "", "server": "dropped.example"},          # blank name → dropped
            {"name": "Extern", "server": "dns2.example.com", "enabled": False},
        ])
        assert [s["name"] for s in saved] == ["BV", "Extern"]
        stored = dns_tool.dns_servers()
        assert stored[0]["server"] == "192.0.2.1"
        assert stored[1]["enabled"] is False


def test_save_rejects_hostile_server(app):
    with app.app_context():
        with pytest.raises(ValueError):
            dns_tool.save_dns_servers([{"name": "x", "server": "evil;host"}])


# ---------------------------------------------------------------- routes

def test_page_renders_in_every_adom(app, client):
    uid = admin_user_id(app)
    for product in ("global", "fortiweb", "fortiadc"):
        login(client, uid, product=product)
        r = client.get("/dns-lookup/")
        assert r.status_code == 200, (product, r.status_code)
        assert b"DNS &amp; LB Lookup" in r.data


def test_lookup_post_uses_configured_servers(app, client, monkeypatch):
    uid = admin_user_id(app)
    login(client, uid, product="global")
    # Configure a server explicitly. The test used to lean on a shipped
    # default -- which made it assert the opposite of its own name, and made
    # it fail the moment that default was removed for naming somebody else's
    # resolver. A test for CONFIGURED servers has to configure one.
    with app.app_context():
        from app.models import AppSetting
        from app.extensions import db
        AppSetting.set(dns_tool.SERVERS_KEY, json.dumps(
            [{"name": "Test", "server": "192.0.2.53", "enabled": True}]))
        db.session.commit()
    monkeypatch.setattr(dns_tool, "dig_lookup",
                        lambda entry, server, show_ttl=False: ["192.0.2.7"])
    r = client.post("/dns-lookup/", data={"entries": "apps.example.net"})
    assert r.status_code == 200
    assert b"192.0.2.7" in r.data


def test_settings_save_route_round_trip(app, client):
    uid = admin_user_id(app)
    login(client, uid, product="global")
    r = client.post("/settings/dns-tool", data={
        "dns_name": ["AdGuard", "Extern", ""],
        "dns_server": ["192.0.2.3", "8.8.8.8", ""],
        "dns_enabled": ["0"],
    })
    assert r.status_code == 302
    with app.app_context():
        stored = dns_tool.dns_servers()
        assert [s["name"] for s in stored] == ["AdGuard", "Extern"]
        assert stored[0]["enabled"] is True
        assert stored[1]["enabled"] is False
