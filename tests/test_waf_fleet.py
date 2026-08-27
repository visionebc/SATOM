"""Guards: the fleet-wide WAF pages.

Three properties this area has to hold, and each of them is a mistake this
codebase has already paid for once:

1. **The universe is what this console may see.** ``/waf/*`` is fleet-wide by
   design (like Fleet Objects), but "fleet" means the rows
   ``visible_appliances()`` returns — the FortiWeb ADOM, minus maintenance for
   an operator without the permission, and never another product's device.
   Guards are written against the ROUTE, not the service: on ``/artifacts/*``
   the services computed correctly for the whole time the defect was live and
   it was the PAGE that leaked (safeguards §122).

2. **Absence is not zero.** A device with no snapshot must be visible as
   "never harvested" and must not be folded into the denominators as a device
   with zero policies. Same rule as ``satom_scrape_up 0``.

3. **A slot a profile does not HAVE is not an unfilled slot.** The offline
   collection carries ~38 of the 41 protections; counting the missing ones as
   "off" invents a fleet-wide gap that no operator can close.
"""
from __future__ import annotations

import csv
import io

import pytest

from tests.conftest import admin_user_id, login, make_user, profile_id

CHASSIS = "192.0.2.1"
OTHER = "192.0.2.2"

# A profile with EVERY protection slot present, so a test can turn exactly the
# ones it cares about on and trust that the rest read as deliberate "off".
def _profile(name, on=(), *, predefined=False, kind="inline", slots=None,
             signature="Standard Protection"):
    from app.services.waf_fleet import PROTECTIONS

    keys = slots if slots is not None else [k for k, _l, _g in PROTECTIONS]
    row = {"name": name, "can_view": 1 if predefined else 0, "comment": ""}
    for key in keys:
        row[key] = ""
    for key in on:
        row[key] = "ref-" + key
    if "signature-rule" in row:
        row["signature-rule"] = signature if "signature-rule" in on or signature else ""
    return row


def _policy(name, **kw):
    row = {
        "name": name, "status": "enable", "monitor-mode": "disable",
        "service": "HTTP", "deployment-mode": "server-pool",
        "vserver": "vs-" + name, "server-pool": "pool-" + name,
        "web-protection-profile": "", "ssl": "disable", "certificate": "",
        "tls-v10": "disable", "tls-v11": "disable", "comment": "",
    }
    row.update(kw)
    return row


def _snapshot(policies=(), inline=(), offline=(), extras=None):
    sections = {
        "Server Policy": {"server_policy": list(policies)},
        "Server Objects": {"vserver": [{"name": "vs"} for _ in policies],
                           "server_pool": [{"name": "p"} for _ in policies]},
        "Web Protection": {"webprotection_profile_inline": list(inline),
                           "webprotection_profile_offline": list(offline),
                           "signature": [], "custom_rule": []},
        "System": {"certificate": []},
    }
    if extras:
        sections.update(extras)
    return {"sections": sections, "total_objects": len(policies)}


@pytest.fixture()
def ctx(app):
    with app.app_context():
        from app import db
        yield db


def _appl(name, host=CHASSIS, vdom="root", kind="fortiweb", maintenance=False):
    from app import db
    from app.models import Appliance

    row = Appliance(name=name, kind=kind, host=host, port=443, username="u",
                    password_enc="x", vdom=vdom, maintenance=maintenance)
    db.session.add(row)
    db.session.commit()
    return row


def _record(appliance, snapshot):
    from app.services import sot_store
    from app.services.device_sync import slugify

    return sot_store.record(slugify(appliance.name), snapshot, source="test")


# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------
def test_an_empty_or_disabled_slot_is_off_and_a_named_reference_is_on(ctx):
    from app.services.waf_fleet import extract

    prof = _profile("wpp-a", on=("signature-rule", "bot-mitigate-policy"))
    prof["ip-intelligence"] = "disable"
    prof["csrf-protection"] = ""
    data = extract(_snapshot([_policy("p1", **{"web-protection-profile": "wpp-a"})],
                             inline=[prof]))
    filled = set(data["profiles"][0]["filled"])
    assert "signature-rule" in filled and "bot-mitigate-policy" in filled
    assert "ip-intelligence" not in filled, "'disable' is an empty slot"
    assert "csrf-protection" not in filled


def test_a_slot_the_profile_has_no_key_for_is_not_counted_as_off(ctx):
    """The offline profile has no ``csrf-protection`` field at all."""
    from app.services.waf_fleet import extract

    slim = _profile("wpp-off", on=("signature-rule",), kind="offline",
                    slots=["signature-rule", "bot-mitigate-policy"])
    data = extract(_snapshot(inline=[], offline=[slim]))
    prof = data["profiles"][0]
    assert set(prof["applicable"]) == {"signature-rule", "bot-mitigate-policy"}
    assert "csrf-protection" not in prof["applicable"], \
        "a field the collection does not have is not an unfilled slot"
    assert prof["n_applicable"] == 2


def test_posture_precedence_puts_each_policy_in_exactly_one_bucket(ctx):
    from app.services.waf_fleet import P_BLOCKING, P_DETECTION, P_DISABLED, \
        P_NOPROFILE, extract

    prof = _profile("wpp-a", on=("signature-rule",))
    rows = extract(_snapshot([
        _policy("ok", **{"web-protection-profile": "wpp-a"}),
        _policy("mon", **{"web-protection-profile": "wpp-a",
                          "monitor-mode": "enable"}),
        _policy("bare"),
        _policy("off", status="disable"),
    ], inline=[prof]))["policies"]
    got = {p["name"]: p["posture"] for p in rows}
    assert got == {"ok": P_BLOCKING, "mon": P_DETECTION,
                   "bare": P_NOPROFILE, "off": P_DISABLED}


def test_the_unbucketed_totals_expose_what_the_doughnut_hides(ctx):
    """A disabled policy that ALSO has no profile occupies one bucket."""
    from app.services.waf_fleet import P_DISABLED, extract, stats

    rows = extract(_snapshot([_policy("dead", status="disable",
                                      **{"monitor-mode": "enable"})]))
    universe = {"devices": [], "policies": [dict(p, scope="s") for p in rows["policies"]],
                "profiles": [], "reporting": [], "chassis": 0, "adoms": 0,
                "generated_at": ""}
    s = stats(universe)
    assert s["posture"][P_DISABLED] == 1
    assert sum(s["posture"].values()) == 1, "buckets must partition the policies"
    # ...and the conditions it swallowed are still reported on their own.
    assert s["disabled_any"] == 1
    assert s["detection_any"] == 1
    assert s["no_profile_any"] == 1


def test_weak_tls_is_only_asked_of_a_policy_that_terminates_tls(ctx):
    from app.services.waf_fleet import extract

    rows = extract(_snapshot([
        _policy("plain", **{"tls-v10": "enable", "tls-v11": "enable"}),
        _policy("secure", ssl="enable", **{"tls-v10": "enable"}),
    ]))["policies"]
    got = {p["name"]: p["weak_tls"] for p in rows}
    assert got["plain"] == [], \
        "a plain-HTTP policy is not running deprecated TLS — it runs none"
    assert got["secure"] == ["TLS 1.0"]


def test_a_missing_certificate_is_only_a_finding_where_tls_is_on(ctx):
    from app.services.waf_fleet import extract, stats

    rows = extract(_snapshot([
        _policy("plain"),
        _policy("secure", ssl="enable"),
    ]))["policies"]
    universe = {"devices": [], "policies": [dict(p, scope="s") for p in rows],
                "profiles": [], "reporting": [], "chassis": 0, "adoms": 0,
                "generated_at": ""}
    assert stats(universe)["no_cert"] == 1


def test_a_dangling_profile_reference_is_not_the_same_as_no_profile(ctx):
    from app.services.waf_fleet import P_NOPROFILE, extract, stats

    rows = extract(_snapshot([
        _policy("ghost", **{"web-protection-profile": "wpp-gone"}),
    ], inline=[]))["policies"]
    assert rows[0]["wpp_resolved"] is False
    assert rows[0]["posture"] != P_NOPROFILE, \
        "it names a profile; the profile is what is missing"
    universe = {"devices": [], "policies": [dict(p, scope="s") for p in rows],
                "profiles": [], "reporting": [], "chassis": 0, "adoms": 0,
                "generated_at": ""}
    s = stats(universe)
    assert s["dangling"] == 1
    assert s["no_profile_any"] == 0


def test_profile_usage_counts_policies_and_orphans_ignore_predefined(ctx):
    from app.services.waf_fleet import extract, stats

    used = _profile("wpp-used", on=("signature-rule",))
    spare = _profile("wpp-spare", on=("signature-rule",))
    stock = _profile("Inline Standard Protection", on=("signature-rule",),
                     predefined=True)
    data = extract(_snapshot([_policy("p", **{"web-protection-profile": "wpp-used"})],
                             inline=[used, spare, stock]))
    by_name = {p["name"]: p for p in data["profiles"]}
    assert by_name["wpp-used"]["used_by"] == 1
    assert by_name["wpp-spare"]["used_by"] == 0
    assert by_name["Inline Standard Protection"]["predefined"] is True

    universe = {"devices": [],
                "policies": [dict(p, scope="s") for p in data["policies"]],
                "profiles": [dict(p, scope="s") for p in data["profiles"]],
                "reporting": [], "chassis": 0, "adoms": 0, "generated_at": ""}
    assert stats(universe)["orphan_profiles"] == 1, \
        "the vendor's unused baselines are not the operator's dead config"


def test_coverage_denominator_is_the_policys_own_profile(ctx):
    from app.services.waf_fleet import extract, stats

    rich = _profile("wpp-rich", on=("signature-rule",))
    slim = _profile("wpp-slim", on=("signature-rule",), kind="offline",
                    slots=["signature-rule"])
    data = extract(_snapshot([
        _policy("a", **{"web-protection-profile": "wpp-rich"}),
        _policy("b", **{"web-protection-profile": "wpp-slim"}),
        # A policy whose profile is not in the snapshot at all. Its slots are
        # UNKNOWN, and unknown is not "all of them": guessing a denominator
        # here dilutes every percentage on the coverage page with a profile
        # nobody can read.
        _policy("c", **{"web-protection-profile": "wpp-gone"}),
    ], inline=[rich], offline=[slim]))
    universe = {"devices": [],
                "policies": [dict(p, scope="s") for p in data["policies"]],
                "profiles": [dict(p, scope="s") for p in data["profiles"]],
                "reporting": [], "chassis": 0, "adoms": 0, "generated_at": ""}
    cov = {c["key"]: c for c in stats(universe)["coverage"]}
    assert cov["signature-rule"]["applicable"] == 2, \
        "two readable profiles carry the slot; the third policy has none to read"
    assert cov["csrf-protection"]["applicable"] == 1, \
        "the offline profile has no CSRF slot, so it is not in that denominator"


def test_the_applicable_index_is_keyed_by_scope_not_by_name_alone(ctx):
    from app.services.waf_fleet import _applicable_index

    a = dict(_profile("wpp-x"), scope="dev-a / root", kind="inline",
             applicable=["signature-rule", "csrf-protection"])
    b = dict(_profile("wpp-x"), scope="dev-b / root", kind="inline",
             applicable=["signature-rule"])
    index = _applicable_index([a, b])
    assert index[("dev-a / root", "wpp-x")] == ("signature-rule", "csrf-protection")
    assert index[("dev-b / root", "wpp-x")] == ("signature-rule",), \
        "two boxes may own a profile of the same name; they are different objects"


# ---------------------------------------------------------------------------
# routes — the pages, not the services
# ---------------------------------------------------------------------------
@pytest.fixture()
def fleet(ctx):
    """Two FortiWebs, one FortiADC, one FortiWeb in maintenance, one never
    harvested. Deliberately asymmetric where the asymmetry is the point."""
    prof = _profile("wpp-web1", on=("signature-rule", "bot-mitigate-policy"))
    web1 = _appl("web1")
    _record(web1, _snapshot([
        _policy("pol-blocking", **{"web-protection-profile": "wpp-web1"}),
        _policy("pol-monitor", **{"web-protection-profile": "wpp-web1",
                                  "monitor-mode": "enable"}),
        _policy("pol-tls", ssl="enable", certificate="crt",
                **{"web-protection-profile": "wpp-web1", "tls-v10": "enable"}),
    ], inline=[prof, _profile("wpp-unused", on=("signature-rule",))]))

    web2 = _appl("web2", host=OTHER)
    _record(web2, _snapshot([_policy("pol-bare")],
                            inline=[_profile("wpp-web2", on=("signature-rule",))]))

    adc = _appl("adc1", host="192.0.2.3", kind="fortiadc", vdom=None)
    _record(adc, _snapshot([_policy("adc-secret-policy")]))

    hidden = _appl("web-maint", host="192.0.2.4", maintenance=True)
    _record(hidden, _snapshot([_policy("pol-in-maintenance")]))

    _appl("web-never", host="192.0.2.5")     # registered, never harvested
    return {"web1": web1.id, "web2": web2.id, "adc": adc.id}


def _get(client, url, uid, product="fortiweb"):
    """Log in as *uid* and GET *url*.

    The session is CLEARED first. ``conftest.login`` only writes ``_user_id``
    over whatever is already there, and flask-login keeps serving the previous
    identity — so a test that switches user mid-body silently re-asserts the
    first one. That is how the control half of a permission guard passes for
    the wrong reason.
    """
    with client.session_transaction() as sess:
        sess.clear()
    login(client, uid, product=product)
    return client.get(url)


def test_the_pages_never_show_another_products_device(app, client, fleet):
    uid = admin_user_id(app)
    for url in ("/waf/", "/waf/inventory", "/waf/profiles", "/waf/coverage"):
        html = _get(client, url, uid).get_data(as_text=True)
        assert "adc1" not in html, url
        assert "adc-secret-policy" not in html, url


def test_the_global_console_counts_only_the_fortiwebs(app, client, fleet):
    """The guard above cannot see the ``kind`` filter and this one is why.

    In a FortiWeb session ``visible_appliances()`` already drops FortiADC, so
    deleting the explicit ``kind == 'fortiweb'`` narrowing changes nothing
    there. GLOBAL is the console where the fleet really is every product, and
    it is the console this page is offered in — a "WAF inventory" that counts a
    load balancer's policies is answering a question nobody asked.
    """
    uid = admin_user_id(app)
    for url in ("/waf/", "/waf/inventory", "/waf/coverage"):
        html = _get(client, url, uid, product="global").get_data(as_text=True)
        assert "adc-secret-policy" not in html, url
        assert "adc1" not in html, url
    data = _get(client, "/waf/api/summary.json", uid, product="global").get_json()
    # web1 (3) + web2 (1) + web-maint (1, and this admin may see it) = 5.
    # The FortiADC's policy would make it 6; a load balancer's rule is not a
    # WAF policy and must not be counted as one.
    assert data["stats"]["policies"] == 5


# NOTE — the guard below and its control are two tests, not two halves of
# one: ``conftest.login`` writes ``_user_id`` over the existing session and
# flask-login keeps serving the FIRST identity, so a body that switches user
# silently re-asserts the same one. (Every multi-user guard in this suite —
# tests/test_maintenance_mode.py — is split the same way.)
def test_a_maintenance_device_is_hidden_from_an_operator_without_the_permission(
        app, client, fleet):
    ro = make_user(app, username="ro", role="readonly",
                   profile_id=profile_id(app, "readonly"))
    html = _get(client, "/waf/inventory", ro).get_data(as_text=True)
    assert "pol-in-maintenance" not in html
    assert "web-maint" not in html


def test_the_same_maintenance_device_is_shown_to_an_admin(app, client, fleet):
    """Control: the row exists, and only the permission was hiding it."""
    html = _get(client, "/waf/inventory", admin_user_id(app)).get_data(as_text=True)
    assert "pol-in-maintenance" in html


def test_a_device_that_never_reported_is_named_not_counted_as_zero(app, client, fleet):
    html = _get(client, "/waf/", admin_user_id(app)).get_data(as_text=True)
    assert "web-never" in html
    assert "never harvested" in html
    # ...and the page says how many scopes actually contributed.
    assert "reporting" in html


def test_the_inventory_filters_narrow_the_table(app, client, fleet):
    uid = admin_user_id(app)
    everything = _get(client, "/waf/inventory", uid).get_data(as_text=True)
    assert "pol-blocking" in everything and "pol-monitor" in everything

    only_mon = _get(client, "/waf/inventory?posture=detection", uid).get_data(as_text=True)
    assert "pol-monitor" in only_mon
    assert ">pol-blocking<" not in only_mon

    weak = _get(client, "/waf/inventory?tls=weak", uid).get_data(as_text=True)
    assert "pol-tls" in weak
    assert ">pol-bare<" not in weak

    scoped = _get(client, "/waf/inventory?scope=web2+%2F+root", uid).get_data(as_text=True)
    assert "pol-bare" in scoped
    assert ">pol-blocking<" not in scoped


def test_the_csv_carries_exactly_the_filtered_rows(app, client, fleet):
    uid = admin_user_id(app)
    res = _get(client, "/waf/inventory?posture=detection&format=csv", uid)
    assert res.mimetype == "text/csv"
    rows = list(csv.reader(io.StringIO(res.get_data(as_text=True))))
    body = [r for r in rows[1:] if r]
    assert len(body) == 1 and "pol-monitor" in body[0]


def test_the_overview_names_the_monitor_mode_policies_and_links_to_them(
        app, client, fleet):
    html = _get(client, "/waf/", admin_user_id(app)).get_data(as_text=True)
    assert "monitor mode" in html
    assert "posture=detection" in html, \
        "a count with no way to reach the rows is a number to reproduce by hand"


def test_the_all_clear_message_only_appears_when_there_is_nothing_to_fix(
        app, client, ctx):
    clean = _appl("web-clean")
    _record(clean, _snapshot(
        [_policy("pol-ok", **{"web-protection-profile": "wpp-ok"})],
        inline=[_profile("wpp-ok", on=("signature-rule",))]))
    html = _get(client, "/waf/", admin_user_id(app)).get_data(as_text=True)
    assert "No monitor-mode policies" in html


def test_the_coverage_matrix_marks_not_applicable_apart_from_zero(app, client, ctx):
    """A scope whose profile lacks a slot gets a dash, never a red zero."""
    slim = _appl("web-slim")
    _record(slim, _snapshot(
        [_policy("pol-slim", **{"web-protection-profile": "wpp-slim"})],
        offline=[_profile("wpp-slim", on=("signature-rule",), kind="offline",
                          slots=["signature-rule", "bot-mitigate-policy"])]))
    html = _get(client, "/waf/coverage", admin_user_id(app)).get_data(as_text=True)
    assert "waf-cell-na" in html, "the missing slots must render as not-applicable"
    assert "waf-cell-full" in html, "control: the slot it DOES have is counted"


def test_an_adom_that_cannot_reach_the_pages_is_redirected(app, client, fleet):
    uid = admin_user_id(app)
    for product in ("fortiadc", "fortianalyzer", "fortiauthenticator"):
        res = _get(client, "/waf/", uid, product=product)
        assert res.status_code == 302, product


def test_the_submenu_is_offered_in_the_two_consoles_that_can_reach_it(
        app, client, fleet):
    uid = admin_user_id(app)
    for product in ("global", "fortiweb"):
        html = _get(client, "/waf/", uid, product=product).get_data(as_text=True)
        assert 'data-nav-subgroup="WAF"' in html, product
        assert "/waf/inventory" in html, product


def test_the_json_feed_and_the_page_report_the_same_totals(app, client, fleet):
    uid = admin_user_id(app)
    data = _get(client, "/waf/api/summary.json", uid).get_json()
    assert sum(b["value"] for b in data["posture"]) == data["stats"]["policies"]
    assert data["stats"]["reporting"] < data["stats"]["scopes"], \
        "the never-harvested device is in the scope count and out of the data"
