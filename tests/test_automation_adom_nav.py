"""The Automation section belongs to EVERY ADOM, and each ADOM shows only its own.

Until 2026-08-10 the Automation nav group existed in exactly ONE branch of
``base.html`` — FortiWeb. Nothing failed: the pages answered by URL, the Global
console and the FortiADC / FortiAnalyzer / FortiAuthenticator consoles simply
had no way to navigate to them. That is the defect class this repo keeps
meeting — a claim that is quietly false rather than an error that fires.

Three separate holes had to close together, and each of them is silent:

1. **Nav.** One author for the group (``partials/nav_automation.html``), so an
   entry added to it lands in every ADOM in the same commit. Four copies is how
   the Monitoring group drifted before it became a partial.
2. **Routing.** ``scheduled_actions`` sat in ``fortiweb_scoped`` and in none of
   the per-ADOM allowlists, so the links this file now guarantees would have
   REDIRECTED to the ADOM home — a live-looking menu entry that goes nowhere.
   Same fix, same reason, as ``change_requests`` on 2026-08-09.
3. **Rows.** The list was ADOM-scoped; the five by-id routes were not, and the
   editor's catalog and device roster were hardcoded to FortiWeb. A page that
   hides a row and then serves it one URL away is not scoped, it is decorated.

``System Provisioning`` is deliberately FortiWeb-only: it composes FortiWeb
``cmdb`` objects out of a registry stamped ``product='fortiweb'``. Its absence
elsewhere is an assertion here, not an omission.
"""
from __future__ import annotations

import io
import re

import pytest

from conftest import admin_user_id, login

BASE = "app/templates/base.html"
PARTIAL = "app/templates/partials/nav_automation.html"

#: Every ADOM whose console this test drives. Derived from the scoping module
#: rather than typed out: a hardcoded list is how FortiAuthenticator spent a day
#: unofferable in "New appliance" with nothing raising.
def _adom_keys():
    from app.services.product_scope import GLOBAL, concrete_products
    return sorted(concrete_products() | {GLOBAL})


HOME = {
    "global": "/",
    "fortiweb": "/web/",
    "fortiadc": "/adc/",
    "fortianalyzer": "/faz/",
    "fortiauthenticator": "/fac/",
}

#: In EVERY ADOM. Each one scopes its own rows (ScheduledAction.product,
#: ProvisionRun.product, the devices a CR names).
# "Scheduled Actions" was renamed to "System Automations" on 2026-09-09
# when the surface split in two. The label is the ONE thing this guard
# checks, so leaving the old string here does not merely fail — it makes
# the guard stop covering the menu it exists for.
UNIVERSAL = ("System Automations", "Device Provisioning", "Change Requests")


def _group(client, adom):
    """The Automation group's markup as rendered in *adom*'s sidebar."""
    r = client.get(HOME[adom] + "?_adom=" + adom, follow_redirects=True)
    assert r.status_code == 200, f"{adom} home returned {r.status_code}"
    html = r.get_data(as_text=True)
    m = re.search(r'data-nav-group="Automation".*?(?=data-nav-group=|</nav)',
                  html, re.S)
    assert m, f"no Automation group in the {adom} sidebar"
    return m.group(0)


def _labels(markup):
    return re.findall(r"<span>([^<]+)</span></a>", markup)


# ── the group renders in every ADOM ─────────────────────────────────────────
@pytest.mark.parametrize("adom", _adom_keys())
def test_automation_group_renders_in_every_adom(app, client, adom):
    login(client, admin_user_id(app), product=adom)
    assert _labels(_group(client, adom))


@pytest.mark.parametrize("adom", _adom_keys())
def test_universal_entries_present_in_every_adom(app, client, adom):
    login(client, admin_user_id(app), product=adom)
    labels = _labels(_group(client, adom))
    for want in UNIVERSAL:
        assert want in labels, f"{want} missing from the {adom} Automation menu"


@pytest.mark.parametrize("adom", _adom_keys())
def test_system_provisioning_is_fortiweb_only(app, client, adom):
    """It builds FortiWeb cmdb objects; offering it elsewhere aims FortiWeb
    configuration at a box that has none of those objects."""
    login(client, admin_user_id(app), product=adom)
    labels = _labels(_group(client, adom))
    assert ("System Provisioning" in labels) is (adom == "fortiweb"), \
        f"System Provisioning visibility is wrong in {adom}"


@pytest.mark.parametrize("adom", _adom_keys())
def test_every_link_pins_its_own_adom(app, client, adom):
    """``_adom=`` makes a HARD navigation deterministic. Without it a fresh tab
    falls back to the session cookie and lands in whatever ADOM another tab
    chose last — the link would open the right page in the wrong fleet."""
    login(client, admin_user_id(app), product=adom)
    hrefs = re.findall(r'href="([^"]+)"', _group(client, adom))
    assert hrefs
    for href in hrefs:
        assert f"_adom={adom}" in href, f"{href} does not pin {adom}"


# ── one author ──────────────────────────────────────────────────────────────
def test_the_group_has_exactly_one_author():
    """base.html may only INCLUDE the partial. A second inline copy is how a
    menu entry gets added to one ADOM and forgotten in the other four."""
    with io.open(BASE, encoding="utf-8") as fh:
        base = fh.read()
    assert 'data-nav-group="Automation"' not in base, \
        "base.html defines the Automation group inline again"
    assert base.count("partials/nav_automation.html") == len(_adom_keys()) + 1, \
        "every ADOM branch (plus the placeholder branch) must include the partial"


def test_partial_defines_the_group_once():
    with io.open(PARTIAL, encoding="utf-8") as fh:
        assert fh.read().count('data-nav-group="Automation"') == 1


# ── the links actually resolve (a redirect is a dead menu entry) ────────────
@pytest.mark.parametrize("adom", _adom_keys())
def test_scheduled_actions_is_reachable_from_every_adom(app, client, adom):
    login(client, admin_user_id(app), product=adom)
    r = client.get(f"/scheduled-actions/?_adom={adom}", follow_redirects=False)
    assert r.status_code == 200, \
        (f"{adom} bounced off System Automations "
         f"({r.status_code} -> {r.headers.get('Location')})")


@pytest.mark.parametrize("adom", _adom_keys())
def test_system_provisioning_bounces_where_it_is_not_offered(app, client, adom):
    """The menu and the router must agree. An entry the router refuses is a
    broken link; a page the router allows but the menu hides is a secret."""
    login(client, admin_user_id(app), product=adom)
    r = client.get(f"/provisioning/?_adom={adom}", follow_redirects=False)
    if adom in ("fortiweb", "global"):
        assert r.status_code == 200
    else:
        assert r.status_code in (302, 301), \
            f"{adom} reached System Provisioning ({r.status_code})"


# ── rows: each ADOM sees only its own ───────────────────────────────────────
def _action(app, name, product):
    from app.extensions import db
    from app.models import ScheduledAction

    with app.app_context():
        a = ScheduledAction(name=name, action="cert_scan", scope="admin",
                            product=product, targets="[]", params="{}",
                            schedule_kind="daily",
                            schedule='{"time": "03:00"}',
                            enabled=True, created_by="admin")
        db.session.add(a)
        db.session.commit()
        return a.id


BY_ID_GET = ("/scheduled-actions/{id}/edit", "/scheduled-actions/{id}/history")
BY_ID_POST = ("/scheduled-actions/{id}/toggle", "/scheduled-actions/{id}/delete",
              "/scheduled-actions/{id}/run-now")


@pytest.mark.parametrize("path", BY_ID_GET)
def test_foreign_action_is_404_not_200_on_read(app, client, path):
    aid = _action(app, "fwb-only", "fortiweb")
    login(client, admin_user_id(app), product="fortianalyzer")
    r = client.get(path.format(id=aid) + "?_adom=fortianalyzer")
    assert r.status_code == 404, \
        f"{path} served a FortiWeb action to the FortiAnalyzer ADOM"


@pytest.mark.parametrize("path", BY_ID_POST)
def test_foreign_action_is_404_not_200_on_write(app, client, path):
    """404, never 403: confirming the row exists is itself a leak."""
    aid = _action(app, "fwb-only", "fortiweb")
    login(client, admin_user_id(app), product="fortianalyzer")
    r = client.post(path.format(id=aid) + "?_adom=fortianalyzer")
    assert r.status_code == 404, f"{path} mutated another ADOM's action"


def test_own_action_is_reachable_in_its_adom(app, client):
    """The guard must be a filter, not a wall — the scoped loader has to still
    FIND the row it owns, or every by-id route 404s for everyone."""
    aid = _action(app, "faz-own", "fortianalyzer")
    login(client, admin_user_id(app), product="fortianalyzer")
    r = client.get(f"/scheduled-actions/{aid}/edit?_adom=fortianalyzer")
    assert r.status_code == 200


def test_the_list_is_scoped_too(app, client):
    _action(app, "fwb-only", "fortiweb")
    _action(app, "faz-own", "fortianalyzer")
    login(client, admin_user_id(app), product="fortianalyzer")
    body = client.get("/scheduled-actions/?_adom=fortianalyzer").get_data(as_text=True)
    assert "faz-own" in body
    assert "fwb-only" not in body


# ── the editor offers only what this ADOM can actually run ──────────────────
def _catalog(client, adom):
    r = client.get(f"/scheduled-actions/new?_adom={adom}")
    assert r.status_code == 200, adom
    return set(re.findall(r'<option value="([a-z0-9_]+)"[^>]*data-scope=',
                          r.get_data(as_text=True)))


@pytest.mark.parametrize("adom", sorted(k for k in HOME if k != "global"))
def test_catalog_offers_only_actions_this_adom_can_fire(app, client, adom):
    """An action declares the appliance kinds it targets. Offering a
    FortiWeb-only action inside the FAZ ADOM does not fail — it builds a job
    whose entire target set is invisible there, and a job that runs against
    nothing reports success."""
    from app.services import scheduled_actions as sa

    login(client, admin_user_id(app), product=adom)
    offered = _catalog(client, adom)
    assert offered, f"{adom} offered no actions at all"
    for key in offered:
        assert adom in (sa.ALL_ACTIONS[key].products or ()), \
            f"{adom} was offered {key}, which does not target it"


def test_global_offers_the_whole_catalog(app, client):
    from app.services import scheduled_actions as sa

    login(client, admin_user_id(app), product="global")
    assert len(_catalog(client, "global")) >= len(
        [s for s in sa.ADMIN_ACTIONS if s.scope == "admin"])


#: A REAL catalog key that only targets FortiWeb, and a REAL one that targets
#: every product. Asserted below to be exactly that: a refusal test whose input
#: is invalid for some OTHER reason passes with the guard deleted.
FWB_ONLY = "backup"
EVERY_PRODUCT = "device_sync"


def test_the_fixture_keys_are_real_and_say_what_this_file_claims():
    from app.services import scheduled_actions as sa

    assert sa.ALL_ACTIONS[FWB_ONLY].products == ("fortiweb",)
    assert "fortianalyzer" in sa.ALL_ACTIONS[EVERY_PRODUCT].products


def test_posting_a_foreign_action_is_refused(app, client):
    """The form is a hint; this is the rule. Without the server-side check the
    posted ``action`` field is a one-field ADOM jump."""
    from app.models import ScheduledAction

    login(client, admin_user_id(app), product="fortianalyzer")
    client.post("/scheduled-actions/new?_adom=fortianalyzer", data={
        "name": "smuggled", "action": FWB_ONLY,
        "schedule_kind": "daily", "daily_time": "03:00"})
    with app.app_context():
        assert ScheduledAction.query.filter_by(name="smuggled").first() is None


def test_posting_an_action_this_adom_owns_still_saves(app, client):
    """The action guard is a filter, not a wall — without this the ADOM check
    could reject everything and every test above would still be green."""
    from app.models import ScheduledAction

    login(client, admin_user_id(app), product="fortianalyzer")
    client.post("/scheduled-actions/new?_adom=fortianalyzer", data={
        "name": "faz-legit", "action": EVERY_PRODUCT,
        "schedule_kind": "daily", "daily_time": "03:00"})
    with app.app_context():
        row = ScheduledAction.query.filter_by(name="faz-legit").first()
        assert row is not None
        assert row.product == "fortianalyzer", "saved into the wrong ADOM"


# ── the device roster follows the ADOM ──────────────────────────────────────
def _appliance(app, name, kind, host):
    from app.extensions import db
    from app.models import Appliance

    with app.app_context():
        a = Appliance(name=name, kind=kind, host=host, port=443,
                      username="u", password_enc="placeholder")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        return a.id


def test_target_roster_is_not_hardcoded_to_fortiweb(app, client):
    """``.filter_by(kind='fortiweb')`` rendered an EMPTY device list in every
    other ADOM: no error, no message, a form that silently could not target
    anything."""
    _appliance(app, "t-fwb", "fortiweb", "192.0.2.1")
    _appliance(app, "t-faz", "fortianalyzer", "192.0.2.2")
    login(client, admin_user_id(app), product="fortianalyzer")
    body = client.get("/scheduled-actions/new?_adom=fortianalyzer").get_data(as_text=True)
    sel = re.search(r'id="targetsSelect".*?</select>', body, re.S)
    assert sel, "no target picker rendered"
    assert "t-faz" in sel.group(0)
    assert "t-fwb" not in sel.group(0)


def test_targets_of_a_kind_the_action_cannot_reach_are_refused(app, client):
    """The Global console legitimately lists EVERY product's boxes, so the
    mismatch is one click away there: a FortiWeb-only action aimed at a
    FortiAnalyzer. It would not raise — it would build a job with no transport
    for its own target and report success."""
    from app.models import ScheduledAction

    faz = _appliance(app, "g-faz", "fortianalyzer", "192.0.2.2")
    login(client, admin_user_id(app), product="global")
    client.post("/scheduled-actions/new?_adom=global", data={
        "name": "wrong-kind", "action": FWB_ONLY,
        "targets": str(faz),
        "schedule_kind": "daily", "daily_time": "03:00"})
    with app.app_context():
        assert ScheduledAction.query.filter_by(name="wrong-kind").first() is None


def test_targets_of_the_right_kind_still_save(app, client):
    """The kind check is a filter, not a wall."""
    from app.models import ScheduledAction

    fwb = _appliance(app, "g-fwb", "fortiweb", "192.0.2.1")
    login(client, admin_user_id(app), product="global")
    client.post("/scheduled-actions/new?_adom=global", data={
        "name": "right-kind", "action": FWB_ONLY,
        "targets": str(fwb),
        "schedule_kind": "daily", "daily_time": "03:00"})
    with app.app_context():
        assert ScheduledAction.query.filter_by(name="right-kind").first() is not None
