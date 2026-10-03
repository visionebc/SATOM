"""Read routes that answered any signed-in user now name the permission they need.

Documentation Center audit, 2026-10-03 (AD-15, AD-20, MO-06, TR-06, TR-07,
PR-03, DV-05, DV-06, DV-38). Each of these routes carried only
``@login_required``: a custom profile holding no read key at all -- or only
``users.manage`` -- could open the audit trail, every monitoring page, the API
consoles and the appliance inventory. The seeded profiles are unchanged:
readonly, operator and admin all hold every key these gates ask for.

Two layers of proof:

* the STAMP -- every route of the listed modules carries
  ``__required_permission__`` (the attribute the Concept Map filters on), so a
  route added later without a gate fails here instead of shipping open;
* the BEHAVIOUR -- a zero-key user gets 403 and the seeded readonly does not.
"""
from __future__ import annotations


import pytest

from conftest import login, make_user, profile_id

# module -> permission every route must carry (None = "some gate", the module
# already mixes stricter ones such as config_write on its writes).
GATED_MODULES = {
    "app.views.audit": "audit.view",
    "app.views.monitoring": None,
    "app.views.metrics": "view",
    "app.views.monitor_probes": None,
    "app.views.monitor_analytics": None,
    "app.views.monitor_reports": None,
    "app.views.search": "view",
    "app.views.architecture": None,   # reads are view; the SSH MAC fetch is config_write
    "app.views.metrics_admin": None,
    "app.views.analysis": None,
    "app.views.api_explorer": None,
    "app.views.adc_api": None,
    "app.views.faz_api": None,
    "app.views.fac_api": None,
    "app.views.device_provision": None,
    # Device-content reads (2026-10-03, found by a production smoke with a
    # zero-key profile): login-only routes that served device configuration.
    "app.views.workspace": None,
    "app.views.web_protection": None,
    "app.views.waf": None,
    "app.views.exceptions": None,
    "app.views.artifacts": None,
    "app.views.server_objects": None,
    "app.views.objedit": None,
    "app.views.spo_wizard": None,
    "app.views.fleet_objects": None,
    "app.views.attack_search": None,
    "app.views.adc": None,
    "app.views.faz": None,
    "app.views.fac": None,
    "app.views.registry": None,
    "app.views.sentinel": None,
    "app.views.dns_tool": None,
    "app.views.txn_trace": None,
    "app.views.cert_inspect": None,
}

# Node-to-node endpoints authenticated by the HA peer gate, not by a session.
# The Sentinel blocklist feed is fetched by firewalls: no session, token-gated.
PEER_ENDPOINTS = {"metrics_admin.peer_ingest", "metrics_admin.peer_store",
                  "sentinel.blocklist_feed"}


def _zero_key_user(app, name="nokeys", keys=()):
    from app.extensions import db
    from app.models import Profile, User
    with app.app_context():
        p = Profile(name=f"p-{name}", is_system=False)
        p.permission_set = set(keys)
        db.session.add(p)
        db.session.commit()
        u = User(username=name, role="readonly", is_active=True, profile_id=p.id)
        u.set_password("pw")
        db.session.add(u)
        db.session.commit()
        return u.id


def _appliance(app):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw1", kind="fortiweb", host="192.0.2.99", port=443,
                      username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a)
        db.session.commit()
        return a.id


def test_every_route_of_the_read_modules_names_its_permission(app):
    missing = []
    for rule in app.url_map.iter_rules():
        view = app.view_functions.get(rule.endpoint)
        mod = getattr(view, "__module__", "")
        if mod not in GATED_MODULES or rule.endpoint in PEER_ENDPOINTS:
            continue
        perm = getattr(view, "__required_permission__", None)
        want = GATED_MODULES[mod]
        if perm is None or (want and perm != want):
            missing.append(f"{rule.endpoint} {rule.rule} -> {perm!r}")
    assert not missing, "routes without their gate:\n" + "\n".join(missing)


@pytest.mark.parametrize("endpoint, perm", [
    ("settings.sentinel_section", "view"),
    ("settings.sentinel_demo", "view"),
    ("appliances.index", "appliances.view"),
    ("appliances.detail", "appliances.view"),
    ("appliances.member_roles", "appliances.view"),
    ("appliances.datasheet", "appliances.view"),
    ("appliances.test_connection", "appliances.view"),
    ("appliances.flash_reports", "appliances.view"),
    ("appliances.flash_report_view", "appliances.view"),
    ("api.list_appliances", "appliances.view"),
    ("api.test_appliance", "appliances.view"),
    ("api.fortiweb_proxy", "registry.view"),
    ("api.fortiadc_proxy", "registry.view"),
    # DV-05: flashing firmware and failing a cluster over are APPLIANCE
    # actions, not "any edit key" (coarse config_write).
    ("appliances.upgrade", "appliances.apply"),
    ("appliances.upgrade_push", "appliances.apply"),
    ("appliances.upgrade_advisory", "appliances.apply"),
    ("appliances.downgrade", "appliances.apply"),
    ("appliances.downgrade_push", "appliances.apply"),
    ("appliances.failover", "appliances.apply"),
    ("appliances.failover_preflight", "appliances.apply"),
    ("appliances.failover_run", "appliances.apply"),
    ("appliances.failover_schedule", "appliances.apply"),
    # MO-14: the MAC fetch logs in to the device over SSH and writes the
    # interface inventory — same gate as the Device health hardware scan.
    ("architecture.device_macs", "config_write"),
    ("architecture.device_detail", "view"),
    ("architecture.index", "view"),
])
def test_named_routes_carry_their_gate(app, endpoint, perm):
    view = app.view_functions[endpoint]
    assert getattr(view, "__required_permission__", None) == perm


ZERO_KEY_403 = [
    "/audit/", "/monitoring/", "/metrics/", "/search/", "/architecture/",
    "/analysis/", "/monitoring/analytics/", "/monitoring/reports/",
    "/monitoring/collection/", "/api-explorer/", "/adc/api/", "/faz/api/",
    "/fac/api/", "/device-provisioning/", "/settings/sentinel",
    "/appliances/", "/api/appliances",
]


@pytest.mark.parametrize("url", ZERO_KEY_403)
def test_a_profile_without_read_keys_is_refused(app, client, url):
    login(client, _zero_key_user(app))
    assert client.get(url).status_code == 403, url


@pytest.mark.parametrize("url", ["/audit/", "/monitoring/", "/appliances/",
                                 "/settings/sentinel", "/search/"])
def test_the_seeded_readonly_profile_keeps_its_reads(app, client, url):
    ro = make_user(app, "ro", role="readonly", profile_id=profile_id(app, "readonly"))
    login(client, ro)
    assert client.get(url).status_code != 403, url


def test_users_manage_alone_does_not_open_the_audit_trail(app, client):
    """users.manage was the menu's condition; the page now asks audit.view."""
    uid = _zero_key_user(app, "useradmin", keys={"users.manage", "monitoring.view"})
    login(client, uid)
    assert client.get("/audit/").status_code == 403
    page = client.get("/monitoring/").get_data(as_text=True)
    assert 'href="/audit/"' not in page, "the menu still links a page that answers 403"


def test_the_admin_menu_still_links_the_audit_log(app, client):
    from conftest import admin_user_id
    login(client, admin_user_id(app))
    page = client.get("/monitoring/").get_data(as_text=True)
    assert 'href="/audit/"' in page


def test_an_edit_key_alone_can_no_longer_flash_firmware(app, client):
    """protection.edit derives config_write; it must not reach the flash path."""
    aid = _appliance(app)
    login(client, _zero_key_user(app, "editor", keys={"protection.edit", "appliances.view"}))
    assert client.post(f"/appliances/{aid}/upgrade").status_code == 403
    assert client.post(f"/appliances/{aid}/failover").status_code == 403


def test_the_operator_still_passes_the_flash_gate(app, client):
    aid = _appliance(app)
    op = make_user(app, "op", role="operator", profile_id=profile_id(app, "operator"))
    login(client, op)
    assert client.get(f"/appliances/{aid}/upgrade").status_code != 403


@pytest.mark.parametrize("path", ["/web/workspace/{aid}", "/web/server-objects/",
                                  "/registry/", "/adc/", "/sentinel/"])
def test_device_content_pages_refuse_a_profile_without_keys(app, client, path):
    """A custom profile with no keys was served device configuration."""
    aid = _appliance(app)
    login(client, _zero_key_user(app, "nokeys-content"))
    r = client.get(path.format(aid=aid))
    assert r.status_code == 403, (path, r.status_code)
    # the seeded readonly profile still opens it (holds every *.view key)
    client.get("/auth/logout")
    login(client, make_user(app, username="ro-content", role="readonly"))
    r = client.get(path.format(aid=aid), follow_redirects=True)
    assert r.status_code == 200, (path, r.status_code)
