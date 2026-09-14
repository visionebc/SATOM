"""One-click maintenance mode from the inventory row and the device page.

Maintenance mode is a VISIBILITY-SECURITY flag: setting it makes a device
vanish for operators and read-only users and takes it out of the scheduled
probe/metric sweeps. Until now it could only be changed through the full edit
form. Putting the same verb on a table row and on the device header creates a
SECOND and a THIRD writer of one fact, so this file guards the relationship
between them — same permission pair, same monitoring re-provision, same
destination whitelist — not just "the button is there".

The failure mode is silent in both directions: a device hidden from a whole
class of users with nothing red, or a device brought back that no longer
collects anything.
"""
from __future__ import annotations

import re

import pytest

from tests.conftest import login, make_user, profile_id, admin_user_id

MAINT_FORM_RE = re.compile(r'action="[^"]*/maintenance"')


def _make_appliance(app, name="fw-toggle", maintenance=False, kind="fortiweb"):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name=name, kind=kind, host="192.0.2.99", port=443,
                      username="admin", verify_ssl=False)
        a.password = "secret"
        a.maintenance = maintenance
        db.session.add(a)
        db.session.commit()
        return a.id


def _maintenance_of(app, aid):
    from app.models import Appliance
    with app.app_context():
        return bool(Appliance.query.get(aid).maintenance)


def _audit_count(app, action="appliance.maintenance"):
    from app.models import AuditLog
    with app.app_context():
        return AuditLog.query.filter_by(action=action).count()


@pytest.fixture()
def admin(app, client):
    uid = admin_user_id(app)
    login(client, uid)
    return uid


@pytest.fixture()
def operator(app, client):
    """config_write WITHOUT appliances.view_maintenance — the interesting gap."""
    uid = make_user(app, "op", role="operator",
                    profile_id=profile_id(app, "operator"))
    login(client, uid)
    return uid


# --- the premise this file rests on -----------------------------------------

def test_operator_has_config_write_but_not_view_maintenance(app):
    """If this ever stops being true the 403 guards below become vacuous —
    they would pass because the user was rejected one gate earlier."""
    from app.models import User
    uid = make_user(app, "op2", role="operator",
                    profile_id=profile_id(app, "operator"))
    with app.app_context():
        u = User.query.get(uid)
        assert u.can("config_write")
        assert not u.can("appliances.view_maintenance")


# --- route behaviour --------------------------------------------------------

def test_route_is_post_only(client, app, admin):
    aid = _make_appliance(app)
    assert client.get(f"/appliances/{aid}/maintenance").status_code == 405


def test_admin_enters_maintenance(client, app, admin):
    aid = _make_appliance(app)
    r = client.post(f"/appliances/{aid}/maintenance",
                    data={"maintenance": "on", "back": "index"})
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/appliances/")
    assert _maintenance_of(app, aid) is True
    assert _audit_count(app) == 1


def test_admin_leaves_maintenance_and_lands_on_the_device(client, app, admin):
    aid = _make_appliance(app, maintenance=True)
    r = client.post(f"/appliances/{aid}/maintenance",
                    data={"maintenance": "off", "back": "detail"})
    assert r.status_code == 302
    assert r.headers["Location"].endswith(f"/appliances/{aid}")
    assert _maintenance_of(app, aid) is False


def test_the_device_page_still_opens_after_entering_maintenance(client, app, admin):
    """The admin who just hid the device holds the permission, so the redirect
    must not land on a 404 — that would read as "the button deleted it"."""
    aid = _make_appliance(app)
    client.post(f"/appliances/{aid}/maintenance",
                data={"maintenance": "on", "back": "detail"})
    assert client.get(f"/appliances/{aid}").status_code == 200


# --- the desired state is posted, never a blind flip ------------------------

def test_reposting_the_current_state_is_a_no_op(client, app, admin):
    aid = _make_appliance(app, maintenance=True)
    r = client.post(f"/appliances/{aid}/maintenance",
                    data={"maintenance": "on", "back": "index"})
    assert r.status_code == 302
    assert _maintenance_of(app, aid) is True
    assert _audit_count(app) == 0          # no write => no audit row


def test_form_posts_the_desired_state_not_a_toggle(client, app, admin):
    """A stale tab must not be able to flip a row the other way. The hidden
    field carries the state the operator SAW, so a re-post is the no-op above
    instead of an invisible state change."""
    off = _make_appliance(app, "fw-off")
    on = _make_appliance(app, "fw-on", maintenance=True)
    html = client.get("/appliances/").get_data(as_text=True)
    rows = {}
    for chunk in html.split("<form")[1:]:
        m = re.search(r'/appliances/(\d+)/maintenance"', chunk)
        if not m:
            continue
        v = re.search(r'name="maintenance" value="(\w+)"', chunk)
        rows[int(m.group(1))] = v.group(1)
    assert rows[off] == "on"               # not in maintenance -> offers "on"
    assert rows[on] == "off"


# --- permissions ------------------------------------------------------------

def test_config_write_without_view_maintenance_is_refused(client, app, operator):
    aid = _make_appliance(app)
    r = client.post(f"/appliances/{aid}/maintenance",
                    data={"maintenance": "on", "back": "index"})
    assert r.status_code == 403
    assert _maintenance_of(app, aid) is False


def test_readonly_is_refused(client, app):
    aid = _make_appliance(app)
    uid = make_user(app, "ro", role="readonly",
                    profile_id=profile_id(app, "readonly"))
    login(client, uid)
    r = client.post(f"/appliances/{aid}/maintenance",
                    data={"maintenance": "on", "back": "index"})
    assert r.status_code in (302, 403)     # denied by the coarse gate
    assert _maintenance_of(app, aid) is False


def test_a_hidden_device_is_still_a_404_for_the_route(client, app, operator):
    """Not 403: confirming the row exists is the leak maintenance mode closes."""
    aid = _make_appliance(app, maintenance=True)
    r = client.post(f"/appliances/{aid}/maintenance",
                    data={"maintenance": "off", "back": "index"})
    assert r.status_code == 404
    assert _maintenance_of(app, aid) is True


# --- the destination is whitelisted, never attacker-supplied ----------------

@pytest.mark.parametrize("back", ["https://evil.example/x", "//evil.example",
                                  "/settings/users", "", "DETAIL"])
def test_back_falls_back_to_the_inventory(client, app, admin, back):
    aid = _make_appliance(app)
    r = client.post(f"/appliances/{aid}/maintenance",
                    data={"maintenance": "on", "back": back})
    assert r.headers["Location"].endswith("/appliances/")


# --- the reason this is not just a checkbox ---------------------------------

def test_clearing_maintenance_reprovisions_monitoring(client, app, admin, monkeypatch):
    """``edit_save`` re-provisions after an edit precisely because clearing the
    flag can make a device collectable that was not. A second writer that skips
    it leaves the device visible and silently uncollected."""
    import app.views.appliances as view
    seen = []
    monkeypatch.setattr(view, "_provision_monitoring",
                        lambda a: seen.append(a.id) or {"targets": 0})
    aid = _make_appliance(app, maintenance=True)
    client.post(f"/appliances/{aid}/maintenance",
                data={"maintenance": "off", "back": "index"})
    assert seen == [aid]


def test_a_no_op_does_not_reprovision(client, app, admin, monkeypatch):
    import app.views.appliances as view
    seen = []
    monkeypatch.setattr(view, "_provision_monitoring",
                        lambda a: seen.append(a.id) or {"targets": 0})
    aid = _make_appliance(app, maintenance=True)
    client.post(f"/appliances/{aid}/maintenance",
                data={"maintenance": "on", "back": "index"})
    assert seen == []


# --- rendering: inventory row + device page ---------------------------------

def test_inventory_row_offers_the_verb_to_an_admin(client, app, admin):
    aid = _make_appliance(app)
    html = client.get("/appliances/").get_data(as_text=True)
    assert f'/appliances/{aid}/maintenance"' in html


def test_inventory_row_hides_the_verb_without_the_permission(client, app, operator):
    _make_appliance(app)
    html = client.get("/appliances/").get_data(as_text=True)
    assert not MAINT_FORM_RE.search(html)


def test_device_page_offers_the_verb_to_an_admin(client, app, admin):
    aid = _make_appliance(app)
    html = client.get(f"/appliances/{aid}").get_data(as_text=True)
    assert f'/appliances/{aid}/maintenance"' in html


def test_device_page_hides_the_verb_without_the_permission(client, app, operator):
    aid = _make_appliance(app)
    html = client.get(f"/appliances/{aid}").get_data(as_text=True)
    assert not MAINT_FORM_RE.search(html)


def test_device_page_offers_it_for_a_kind_with_no_appliance_actions_card(
        client, app, admin):
    """The "Appliance Actions" card renders only for fortiweb/fortiadc. Putting
    the verb in the page header — which every kind gets — is why a
    FortiAuthenticator row can be maintained from its own page instead of only
    from the table."""
    aid = _make_appliance(app, "fac-1", kind="fortiauthenticator")
    # A FortiAuthenticator row is invisible from the FortiWeb ADOM by design,
    # so sit in its own ADOM — otherwise this asserts against a 404 page, which
    # also happens not to contain the button.
    login(client, admin, product="fortiauthenticator")
    html = client.get(f"/appliances/{aid}").get_data(as_text=True)
    assert "fac-1" in html
    assert "Appliance Actions" not in html
    assert f'/appliances/{aid}/maintenance"' in html


def test_the_form_carries_a_csrf_token(client, app, admin):
    """CSRF is disabled in the test config, so posting proves nothing — the
    markup is the only place this can be checked."""
    aid = _make_appliance(app)
    html = client.get(f"/appliances/{aid}").get_data(as_text=True)
    form = [c for c in html.split("<form") if "/maintenance" in c[:400]][0]
    assert 'name="csrf_token"' in form[:800]


def test_only_entering_maintenance_asks_for_confirmation(client, app, admin):
    """Hiding a device from a whole class of users deserves one dialog; giving
    it back is the undo and must not."""
    off = _make_appliance(app, "fw-off")
    on = _make_appliance(app, "fw-on", maintenance=True)
    html = client.get("/appliances/").get_data(as_text=True)
    chunks = {}
    for chunk in html.split("<form")[1:]:
        m = re.search(r'/appliances/(\d+)/maintenance"', chunk)
        if m:
            chunks[int(m.group(1))] = chunk.split("</form>")[0]
    assert "data-fw-confirm-form" in chunks[off]
    assert "data-fw-confirm-form" not in chunks[on]


# --- one author -------------------------------------------------------------

def test_the_markup_has_exactly_one_author():
    """The two pages must IMPORT the macro, not each grow their own copy. Two
    copies is how this repo's sidebar groups and status badges drifted."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1] / "app" / "templates"
    authors = [p for p in root.rglob("*.html")
               if "appliances.set_maintenance" in p.read_text(encoding="utf-8")]
    assert [p.name for p in authors] == ["_maintenance_toggle.html"]
    for page in ("appliances/index.html", "appliances/detail.html"):
        src = (root / page).read_text(encoding="utf-8")
        assert "import maintenance_toggle with context" in src
        assert "maintenance_toggle(" in src
