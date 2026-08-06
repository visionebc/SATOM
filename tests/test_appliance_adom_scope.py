"""The appliance roster is per-ADOM — list, form AND by-id.

Three defects this file exists to keep closed (all found together on
2026-08-06, none of which raised):

1. ``fortiauthenticator`` was missing from the "New appliance" platform
   select. It had been a real product for a day; the select was a hardcoded
   four-line list that nobody updated. Nothing failed — the option was simply
   absent, so the ADOM could not onboard its own devices from the UI.
2. The select offered EVERY platform inside every ADOM. Choosing a foreign one
   saved a device the creating session could not see, which reads as a save
   that silently did nothing.
3. ``visible_appliance_or_404`` never applied the product filter, so every
   by-id route (detail, edit, delete, backups, console) answered 200 for
   another product's device to anyone who knew the id. The list was scoped;
   the URL one click away was not.

The roster is therefore DERIVED from the ADOM registry, and the guards below
are what keeps a fifth product from repeating (1).
"""
from __future__ import annotations

import re

import pytest

from conftest import admin_user_id, login

KIND_SELECT = re.compile(r'<select[^>]*name="kind"[^>]*required>(.*?)</select>', re.S)
TEMPLATES = (
    "app/templates/appliances/index.html",
    "app/templates/appliances/edit.html",
    # Same generator, different page: provisioning also decides what kind of
    # appliance gets registered at the end of a run.
    "app/templates/provisioning/device_index.html",
)


def _mk(app, name, kind, host):
    from app.extensions import db
    from app.models import Appliance

    with app.app_context():
        a = Appliance(name=name, kind=kind, host=host, port=443,
                      username="u", password_enc="placeholder")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        return a.id


def _fleet(app):
    """One device per product ADOM."""
    return {
        "fortiweb": _mk(app, "t-fwb", "fortiweb", "192.0.2.1"),
        "fortiadc": _mk(app, "t-adc", "fortiadc", "192.0.2.2"),
        "fortianalyzer": _mk(app, "t-faz", "fortianalyzer", "192.0.2.3"),
        "fortiauthenticator": _mk(app, "t-fac", "fortiauthenticator", "192.0.2.4"),
    }


def _options(client, adom):
    r = client.get("/appliances/", headers={"X-ADOM": adom})
    assert r.status_code == 200, adom
    m = KIND_SELECT.search(r.get_data(as_text=True))
    assert m, f"no create form rendered in {adom}"
    return [v for v in re.findall(r'value="([^"]*)"', m.group(1)) if v]


# ── the roster itself ───────────────────────────────────────────────────────
def test_device_products_is_never_empty(app):
    """Anti-vacuity: every assertion below is trivially true against an empty
    roster, and an empty roster renders a form with no platform to pick."""
    from app.services import product_scope as ps

    with app.app_context():
        assert len(ps.device_products()) >= 2


def test_every_active_product_adom_is_offerable(app):
    """The bug of record: a product that exists but cannot be chosen."""
    from app.branding import all_adoms
    from app.services import product_scope as ps

    with app.app_context():
        expected = {str(r["key"]).lower() for r in all_adoms()
                    if r.get("active", True) and r["key"] != "global"}
        assert {k for k, _ in ps.device_products()} == expected
        assert "fortiauthenticator" in expected


# ── the form ────────────────────────────────────────────────────────────────
def test_global_offers_every_platform(app, client):
    _fleet(app)
    login(client, admin_user_id(app), product="global")
    assert set(_options(client, "global")) == {
        "fortiweb", "fortiadc", "fortianalyzer", "fortiauthenticator"}


@pytest.mark.parametrize("adom", ["fortiweb", "fortiadc", "fortianalyzer",
                                  "fortiauthenticator"])
def test_a_product_adom_offers_only_itself(app, client, adom):
    _fleet(app)
    login(client, admin_user_id(app), product=adom)
    assert _options(client, adom) == [adom]


@pytest.mark.parametrize("path", TEMPLATES)
def test_no_template_hardcodes_a_platform_option(path):
    """A hardcoded ``<option value="fortiweb">`` is exactly how the roster went
    stale. Anchored on the emitted markup, not on the word: the templates
    legitimately mention products in prose and in ``{% if %}`` guards."""
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    for kind in ("fortiweb", "fortiadc", "fortianalyzer", "fortiauthenticator"):
        assert f'<option value="{kind}"' not in src, f"{path} hardcodes {kind}"


# ── the server side ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("adom", ["fortiweb", "fortiadc", "fortianalyzer",
                                  "fortiauthenticator"])
def test_may_assign_kind_refuses_a_foreign_platform(app, adom):
    from app.services import product_scope as ps

    with app.test_request_context(headers={"X-ADOM": adom}):
        assert ps.may_assign_kind(adom) is True
        for other in ("fortiweb", "fortiadc", "fortianalyzer",
                      "fortiauthenticator"):
            if other != adom:
                assert ps.may_assign_kind(other) is False, other
        assert ps.may_assign_kind("") is False


def test_global_may_assign_any_product(app):
    from app.services import product_scope as ps

    with app.test_request_context(headers={"X-ADOM": "global"}):
        for k, _ in ps.device_products():
            assert ps.may_assign_kind(k) is True


def test_creating_a_foreign_platform_is_refused_and_says_so(app, client):
    """The form is a hint; this is the rule. A posted ``kind`` field would
    otherwise be a one-field ADOM jump."""
    from app.models import Appliance

    login(client, admin_user_id(app), product="fortiweb")
    r = client.post("/appliances/", headers={"X-ADOM": "fortiweb"}, data={
        "name": "probe", "kind": "fortianalyzer", "host": "192.0.2.9",
        "port": "443", "username": "u", "password": "p"})
    assert r.status_code == 302
    with app.app_context():
        assert Appliance.query.filter_by(name="probe").first() is None
    with client.session_transaction() as sess:
        flashes = [m for _, m in sess.get("_flashes", [])]
    assert any("only add" in m for m in flashes), flashes


def test_creating_its_own_platform_still_works(app, client):
    from app.models import Appliance

    login(client, admin_user_id(app), product="fortiauthenticator")
    r = client.post("/appliances/",
                    headers={"X-ADOM": "fortiauthenticator"}, data={
                        "name": "fac-new", "kind": "fortiauthenticator",
                        "host": "192.0.2.8", "port": "443",
                        "username": "u", "password": "p"})
    assert r.status_code == 302
    with app.app_context():
        row = Appliance.query.filter_by(name="fac-new").first()
        assert row is not None and row.kind == "fortiauthenticator"


# ── the by-id loader (the leak) ─────────────────────────────────────────────
@pytest.mark.parametrize("adom", ["fortiweb", "fortiadc", "fortianalyzer",
                                  "fortiauthenticator"])
def test_detail_by_id_404s_across_adoms(app, client, adom):
    ids = _fleet(app)
    login(client, admin_user_id(app), product=adom)
    for kind, aid in ids.items():
        got = client.get(f"/appliances/{aid}", headers={"X-ADOM": adom})
        want = 200 if kind == adom else 404
        assert got.status_code == want, f"{adom} -> {kind} was {got.status_code}"


def test_global_still_reaches_every_device(app, client):
    ids = _fleet(app)
    login(client, admin_user_id(app), product="global")
    for aid in ids.values():
        assert client.get(f"/appliances/{aid}",
                          headers={"X-ADOM": "global"}).status_code == 200


def test_editing_cannot_move_a_device_to_another_adom(app, client):
    from app.models import Appliance

    ids = _fleet(app)
    login(client, admin_user_id(app), product="fortiweb")
    r = client.post(f"/appliances/{ids['fortiweb']}/edit",
                    headers={"X-ADOM": "fortiweb"},
                    data={"name": "t-fwb", "kind": "fortiadc",
                          "host": "192.0.2.1", "port": "443", "username": "u"})
    assert r.status_code == 302
    with app.app_context():
        assert Appliance.query.get(ids["fortiweb"]).kind == "fortiweb"
