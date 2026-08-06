"""FortiAuthenticator wiring — the guards for a product that was promoted but
not connected.

FortiAuthenticator became a real (non-placeholder) product ADOM on 2026-08-05.
Everything that decided behaviour by LISTING the products it knew about kept
the old list, and none of those failures raise:

* ``views.product._home_for`` had branches for global/fortiadc/fortianalyzer, a
  placeholder check, then ``return redirect(url_for('fortiweb_home'))``. Once
  FAC stopped being a placeholder it fell straight through that last line:
  choosing FortiAuthenticator opened the **FortiWeb** console, with the FortiWeb
  sidebar, against FortiWeb devices;
* the Global home built exactly two lists and rendered exactly two stat-cards,
  so the console whose entire job is to span the fleet showed neither the FAC
  ADOM nor ``fac01``;
* Settings -> ADOMs would happily delete an ADOM row that still owned
  registered appliances, silently un-managing every one of them;
* the top-bar Search icon and the sidebar Device link were gated on literal
  product tuples that never learned the fourth key.

Every guard below is written against BEHAVIOUR (a request, a redirect, a
rendered page) except the last two, which are deliberately structural: they
fail if the derived rendering is replaced by literal per-product markup again.
Those are anchored to the exact artefacts that were hardcoded — a product logo
path, a per-product device endpoint, a bare product-key constant — and they
strip comments/docstrings before asserting, so they cannot pass or fail on
their own explanation.
"""
from __future__ import annotations

import ast
import os
import re

import pytest
from flask import template_rendered

from conftest import admin_user_id, login

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VIEW = os.path.join(REPO, "app", "views", "global_home.py")
TEMPLATE = os.path.join(REPO, "app", "templates", "global_home", "index.html")

# The rendered text that exists once per ADOM stat-card and nowhere else on the
# page. Counting it counts cards without asserting a single product name.
CARD_MARKER = "appliance(s) ·"

ADOM_KEYS = {"fortiweb", "fortiadc", "fortianalyzer", "fortiauthenticator"}

# The ADOM stat-card anchor, and ONLY it: the same /product/enter/<key> href is
# emitted once per ADOM by the sidebar in base.html, so the card's class
# attribute has to be part of the match or the guard can never fail.
CARD_LINK = re.compile(
    r'class="fw-card d-block h-100 text-decoration-none"[^>]*?'
    r'href="/product/enter/([a-z0-9_-]+)"', re.S)


# --------------------------------------------------------------------------- #
#  helpers                                                                    #
# --------------------------------------------------------------------------- #

def _mk(app, name, kind, host):
    """Register one appliance. ``password_enc`` is NOT NULL, so the constructor
    alone is not enough — the ``password`` setter is what encrypts and fills
    it."""
    from app.extensions import db
    from app.models import Appliance

    with app.app_context():
        a = Appliance(name=name, kind=kind, host=host, port=443,
                      username="u", password_enc="placeholder")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        return a.id


def _device_adoms(app):
    """The live roster of product ADOMs — read from the registry, never listed
    here, so a product added tomorrow is covered by these tests tomorrow.

    ``invalidate()`` first: the branding cache is a MODULE global with a 15 s
    TTL while every test gets its own database, so without it a test can read
    the previous test's registry.
    """
    from app import branding
    from app.services.product_scope import device_products

    with app.app_context():
        branding.invalidate()
        return list(device_products())


def _global_home(app, client):
    """GET the Global home as an admin.

    Returns ``(response, payload)`` where payload is PLAIN data snapshotted
    inside the render — ORM instances handed out by the signal would be
    detached by the time the assertions run.
    """
    payload: dict = {"names": set(), "adom_keys": [], "fleet_names": []}

    def _record(sender, template, context, **extra):
        if getattr(template, "name", "") != "global_home/index.html":
            return
        payload["names"] = set(context.keys())
        payload["adom_keys"] = [c["key"] for c in context.get("adoms") or []]
        payload["fleet_names"] = [a.name for a in context.get("fleet") or []]

    template_rendered.connect(_record, app)
    try:
        resp = client.get("/")
    finally:
        template_rendered.disconnect(_record, app)
    return resp, payload


def _strip_template_comments(src: str) -> str:
    """Jinja and HTML comments out. A guard that reads its own explanation is
    not a guard — this repo has a documented history of exactly that."""
    src = re.sub(r"\{#.*?#\}", " ", src, flags=re.S)
    src = re.sub(r"<!--.*?-->", " ", src, flags=re.S)
    return src


class _DropAssign(ast.NodeTransformer):
    """Remove whole assignments by target name (used to exempt the one
    documented per-ADOM mapping from the literal scan)."""

    def __init__(self, names):
        self.names = set(names)

    def visit_Assign(self, node):
        if any(isinstance(t, ast.Name) and t.id in self.names
               for t in node.targets):
            return None
        return node


def _string_literals(path: str, exempt=()) -> set:
    """Every string constant in a module. Parsed with ``ast``, so ``#``
    comments are gone by construction; docstrings survive as whole strings and
    can never equal a bare product key."""
    with open(path, encoding="utf-8") as fh:
        tree = _DropAssign(exempt).visit(ast.parse(fh.read()))
    return {n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)}


# --------------------------------------------------------------------------- #
#  1. the product gate lands each ADOM in its OWN home                        #
# --------------------------------------------------------------------------- #

def test_entering_fortiauthenticator_lands_on_the_fac_index(app, client):
    """The headline bug: FAC fell through ``_home_for`` to the FortiWeb home.

    Exercised through the real route so the fix is proven end to end, not by
    reading the source of the function that decides it.
    """
    login(client, admin_user_id(app), product="global")
    r = client.get("/product/enter/fortiauthenticator")
    assert r.status_code in (301, 302, 303, 307, 308)
    assert r.headers["Location"].endswith("/fac/"), r.headers["Location"]


def test_no_product_adom_falls_through_to_the_fortiweb_home(app, client):
    """The bug CLASS, over the live roster: only FortiWeb may land on the
    FortiWeb home. Any other product ADOM that does has no branch of its own
    and is silently borrowing another product's console."""
    from flask import url_for

    with app.test_request_context():
        fw_home = url_for("fortiweb_home")
    login(client, admin_user_id(app), product="global")

    landed = {}
    for key, _name in _device_adoms(app):
        r = client.get("/product/enter/%s" % key)
        assert r.status_code in (301, 302, 303, 307, 308), key
        landed[key] = r.headers["Location"]

    strays = {k: v for k, v in landed.items()
              if k != "fortiweb" and v.endswith(fw_home)}
    assert not strays, (
        "these ADOMs open the FortiWeb console instead of their own: %r" % strays)


# --------------------------------------------------------------------------- #
#  2. the Global home covers EVERY ADOM, by count                             #
# --------------------------------------------------------------------------- #

def test_global_home_has_a_card_for_every_active_device_adom(app, client):
    """Counted, never named: the payload must carry one card per ACTIVE
    non-global ADOM in the registry, in registry order, and the render must
    contain that many cards. A fifth product is covered the day it is added."""
    expected = [k for k, _n in _device_adoms(app)]
    assert len(expected) >= 4, "the registry lost a product ADOM"

    login(client, admin_user_id(app), product="global")
    resp, payload = _global_home(app, client)
    assert resp.status_code == 200

    assert "adoms" in payload["names"], \
        "the Global home payload carries no ADOM roster"
    assert payload["adom_keys"] == expected

    html = resp.get_data(as_text=True)
    assert html.count(CARD_MARKER) == len(expected), (
        "%d ADOM stat-card(s) rendered for %d registered ADOM(s)"
        % (html.count(CARD_MARKER), len(expected)))


def test_every_active_adom_card_links_into_its_own_adom(app, client):
    """Each card must link into its own ADOM, in registry order.

    Matched on the CARD anchor specifically. ``/product/enter/<key>`` also
    appears once per ADOM in base.html's sidebar list, so an unanchored
    substring search passes on a page with no cards at all — a guard that
    cannot fail. The card's own class attribute is the anchor.
    """
    login(client, admin_user_id(app), product="global")
    resp, _payload = _global_home(app, client)
    linked = CARD_LINK.findall(resp.get_data(as_text=True))
    assert linked == [k for k, _n in _device_adoms(app)], linked


# --------------------------------------------------------------------------- #
#  3. a FortiAuthenticator box shows up in the fleet listing                   #
# --------------------------------------------------------------------------- #

def test_a_fortiauthenticator_appliance_appears_in_the_global_fleet(app, client):
    """``fac01`` was invisible on the Global home: the fleet table iterated
    ``fw_fleet + adc_fleet`` and a FAC device is in neither."""
    _mk(app, "t-fac01", "fortiauthenticator", "192.0.2.4")
    login(client, admin_user_id(app), product="global")
    resp, payload = _global_home(app, client)
    assert resp.status_code == 200

    assert "t-fac01" in payload["fleet_names"], \
        "the FAC appliance is missing from the Global fleet payload"
    assert "t-fac01" in resp.get_data(as_text=True), \
        "the FAC appliance is missing from the rendered Global fleet table"


def test_the_global_fleet_lists_one_row_per_visible_appliance(app, client):
    """Grouping by product must not DROP a product. One device per ADOM in,
    the same number of rows out — asserted as a count, not as four names."""
    roster = _device_adoms(app)
    for i, (key, _name) in enumerate(roster):
        _mk(app, "t-fleet-%d" % i, key, "10.9.8.%d" % (i + 1))

    login(client, admin_user_id(app), product="global")
    resp, payload = _global_home(app, client)
    assert resp.status_code == 200
    assert len(payload["fleet_names"]) == len(roster)


# --------------------------------------------------------------------------- #
#  4. an ADOM that owns appliances is not deletable                            #
# --------------------------------------------------------------------------- #

def test_an_adom_with_registered_appliances_cannot_be_deleted(app, client):
    """An appliance's ``kind`` IS an ADOM key. Deleting the row leaves the
    devices in the table with no console able to see them, and nothing raises —
    so the guard has to refuse the delete, not warn about it."""
    from app.models_adom import Adom

    _mk(app, "t-fac-guard", "fortiauthenticator", "192.0.2.5")
    login(client, admin_user_id(app), product="global")

    r = client.post("/settings/adoms/fortiauthenticator/delete")
    assert r.status_code in (301, 302, 303), r.status_code
    with app.app_context():
        assert Adom.query.filter_by(key="fortiauthenticator").first() is not None, \
            "an ADOM with registered appliances was deleted"


def test_an_adom_with_no_appliances_is_still_deletable(app, client):
    """The counterweight: the guard must be a rule about DATA, not a blanket
    refusal. Without this, a guard that rejected every key would pass the test
    above and quietly make the ADOM console read-only."""
    from app import branding
    from app.extensions import db
    from app.models_adom import Adom

    with app.app_context():
        db.session.add(Adom(key="spareadom", name="Spare", sort_order=99))
        db.session.commit()
        branding.invalidate()

    login(client, admin_user_id(app), product="global")
    r = client.post("/settings/adoms/spareadom/delete")
    assert r.status_code in (301, 302, 303)
    with app.app_context():
        branding.invalidate()
        assert Adom.query.filter_by(key="spareadom").first() is None


# --------------------------------------------------------------------------- #
#  5. the FAC ADOM's own chrome                                                #
# --------------------------------------------------------------------------- #

def _fac_page(app, client):
    """A shared page rendered INSIDE the FAC ADOM. ``X-ADOM`` picks the ADOM
    per request, so there is no session juggling and no dashboard call out to a
    real FortiAuthenticator unit."""
    login(client, admin_user_id(app), product="global")
    r = client.get("/appliances/", headers={"X-ADOM": "fortiauthenticator"})
    assert r.status_code == 200
    return r.get_data(as_text=True)


def test_the_fac_sidebar_device_link_points_at_the_fac_area(app, client):
    """``nav_device_context`` branched on two products then fell through to
    Architecture, so the FAC Device picker's no-JS href left the ADOM."""
    html = _fac_page(app, client)
    m = re.search(r'href="([^"]+)"[^>]*data-bs-target="#deviceSwitchModal"', html)
    assert m, "the Device context block did not render in the FAC ADOM"
    assert m.group(1) == "/fac/", m.group(1)


def test_the_fac_adom_gets_the_topbar_search_icon(app, client):
    """``search`` is inside ``fac_bps``: the page was reachable, the icon that
    reaches it was not."""
    assert 'title="Search (/)"' in _fac_page(app, client)


def test_the_fac_adom_cannot_reach_lua_studio(app, client):
    """FortiAuthenticator has no scripting object (nothing in
    ``endpoints_fortiauthenticator.yaml``), so ``LuaScript.TARGETS`` cannot
    list it and the studio would open with zero valid targets. The ADOM must
    not reach the page at all."""
    login(client, admin_user_id(app), product="global")
    r = client.get("/lua/", headers={"X-ADOM": "fortiauthenticator"})
    assert r.status_code in (301, 302, 303), r.status_code
    assert r.headers["Location"].endswith("/fac/"), r.headers["Location"]


def test_lua_studio_reach_matches_lua_script_targets():
    """The two halves of one decision, kept in step: an ADOM allowed to reach
    the studio must be a valid ``LuaScript`` target, and vice versa.

    Read from the gate source because the allow-lists are locals inside the app
    factory; the ``{...}`` block is the exact artefact and ``#`` comment lines
    are stripped before the membership test, so the explanatory comment that
    now says "NOT lua_studio" cannot satisfy it.

    ``faz_bps`` is knowingly excluded: FortiAnalyzer has the SAME open drift
    (it reaches the studio and is not a target) and resolving it is a
    FortiAnalyzer decision, not part of the FAC wiring.
    """
    from app.models import LuaScript

    with open(os.path.join(REPO, "app", "__init__.py"), encoding="utf-8") as fh:
        src = fh.read()
    for marker, key in (("adc_bps", "fortiadc"), ("fac_bps", "fortiauthenticator")):
        block = src.split(marker + " = {", 1)[1].split("}", 1)[0]
        block = re.sub(r"#[^\n]*", "", block)      # a comment is not code
        reaches = "'lua_studio'" in block
        assert reaches == (key in LuaScript.TARGETS), (
            "%s reaches lua_studio=%r but LuaScript.TARGETS=%r"
            % (marker, reaches, tuple(LuaScript.TARGETS)))


# --------------------------------------------------------------------------- #
#  6. structural: the Global home must stay derived                            #
# --------------------------------------------------------------------------- #

def test_the_global_home_view_names_no_product_but_the_legacy_default():
    """Anchored to the EXACT artefact: a bare product-key string constant.

    ``ast`` is used rather than a text scan so ``#`` comments and this file's
    own prose can never satisfy or break the assertion, and the one documented
    per-ADOM mapping (``_ADOM_BLUEPRINT``, which resolves a product's device
    blueprint and genuinely cannot be derived) is dropped from the tree first.

    ``'fortiweb'`` alone is allowed: it is the value legacy NULL/'' kinds carry,
    the same exception ``services/product_scope.py`` documents.
    """
    named = _string_literals(VIEW, exempt=("_ADOM_BLUEPRINT",)) & ADOM_KEYS
    assert named <= {"fortiweb"}, (
        "app/views/global_home.py hardcodes product key(s) %r — the ADOM "
        "roster must come from product_scope.device_products()"
        % sorted(named - {"fortiweb"}))


def test_the_global_home_template_hardcodes_no_product_branding():
    """The template's exact artefacts were a per-product logo path and a
    per-product device endpoint. Comments are stripped first: this repo has a
    documented history of guards that matched their own explanation."""
    with open(TEMPLATE, encoding="utf-8") as fh:
        body = _strip_template_comments(fh.read())

    marks = set(re.findall(r"img/[a-z0-9_-]+-mark\.svg", body))
    assert marks <= {"img/global-mark.svg"}, (
        "hardcoded product logo(s) %r — the mark belongs to the registry row"
        % sorted(marks - {"img/global-mark.svg"}))

    endpoints = set(re.findall(r"\b(?:adc|faz|fac)\.use_device\b", body))
    assert not endpoints, (
        "hardcoded per-product device endpoint(s) %r — resolve them through "
        "kind_meta instead" % sorted(endpoints))


@pytest.mark.parametrize("name", ["fw_fleet", "adc_fleet"])
def test_the_two_adom_render_variables_are_gone(app, client, name):
    """The two-product payload itself. If either name comes back, the template
    is being fed a fixed pair of products again — whatever it renders."""
    login(client, admin_user_id(app), product="global")
    _resp, payload = _global_home(app, client)
    assert name not in payload["names"]
