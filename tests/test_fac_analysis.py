"""Guards for the product scoping of Analysis, Reports and Analytics.

The defect these exist for is not a crash. Every route returned 200, every
template rendered, and the FortiAuthenticator ADOM showed a full FortiWeb WAF
dashboard, a report section computed over FortiWeb's fleet, and four analytics
panels whose series its devices can never emit. Nothing failed — the pages just
answered questions about a different product, and an empty panel reads as
"quiet", not as "not applicable".

So the guards here are about *what a page is allowed to claim*, and every one
of them was verified to bite by reintroducing the behaviour it forbids.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.models import Appliance, MonitorProbe
from app.services import deep_monitor as dm
from app.services import analysis_fac, monitor_reports as mr
from app.views import analysis as analysis_view
from tests.conftest import login

ADOMS = ("global", "fortiweb", "fortiadc", "fortianalyzer",
         "fortiauthenticator")


def _fac(app, name="fac-t1"):
    """Create a FortiAuthenticator row; return its id.

    The ``app`` fixture does NOT push a context, so an ORM object would be
    detached the moment the ``with`` block closes.
    """
    from app.extensions import db
    with app.app_context():
        a = Appliance(name=name, host="192.0.2.31", kind="fortiauthenticator",
                      username="admin")
        a.password = "pw"      # setter encrypts; both columns are NOT NULL
        db.session.add(a)
        db.session.commit()
        return a.id


# --------------------------------------------------------------------------- #
#  1. Page dispatch                                                            #
# --------------------------------------------------------------------------- #
def test_every_adom_has_an_explicit_analysis_page():
    """No ADOM may reach its page through an ``else``.

    The original code was ``if product == 'fortianalyzer': faz else: index``,
    so FortiADC and then FortiAuthenticator inherited the FortiWeb dashboard by
    default. A map with no fallthrough means the next product added is a
    deliberate decision, not a silent inheritance.
    """
    from app.services.product_scope import concrete_products, GLOBAL

    for product in concrete_products():
        assert product in analysis_view.ANALYSIS_PAGES, (
            "ADOM %r has no Analysis page mapped; without an entry it would "
            "fall through to whatever the default is" % product)
    # Global and the no-context case must resolve to the WIDEST page, never to
    # the refusal — failing closed would blind the one view meant to see all.
    for key in (GLOBAL, ""):
        assert analysis_view.ANALYSIS_PAGES.get(key) == "analysis/index.html"


def test_fortiauthenticator_does_not_get_the_fortiweb_page():
    assert (analysis_view.ANALYSIS_PAGES["fortiauthenticator"]
            == "analysis/fac.html")
    assert (analysis_view.ANALYSIS_PAGES["fortiauthenticator"]
            != analysis_view.ANALYSIS_PAGES["fortiweb"])


def test_an_unmapped_product_is_refused_not_handed_the_fortiweb_page(
        client, app, monkeypatch):
    """The structural half: an ADOM nobody wrote a page for gets told so."""
    monkeypatch.setitem(analysis_view.ANALYSIS_PAGES, "fortiweb", None)
    analysis_view.ANALYSIS_PAGES.pop("fortiweb", None)
    login(client, 1, product="fortiweb")
    body = client.get("/analysis/",
                      headers={"X-ADOM": "fortiweb"}).get_data(as_text=True)
    assert "No analysis page is built" in body


@pytest.mark.parametrize("adom,marker", [
    ("fortiauthenticator", "Analysis — identity"),
    ("fortianalyzer", "Analysis — FortiAnalyzer"),
])
def test_the_right_template_answers_in_each_adom(client, app, adom, marker):
    _fac(app)
    login(client, 1, product=adom)
    body = client.get("/analysis/",
                      headers={"X-ADOM": adom}).get_data(as_text=True)
    assert marker in body


def test_the_fac_page_carries_no_waf_vocabulary(client, app):
    """The concrete symptom the user reported: WAF terms on an identity page."""
    _fac(app)
    login(client, 1, product="fortiauthenticator")
    body = client.get("/analysis/",
                      headers={"X-ADOM": "fortiauthenticator"}
                      ).get_data(as_text=True)
    for term in ("Web Protection Profile", "web-protection-profile",
                 "Server Policy", "Signature exception"):
        assert term not in body, "FortiWeb vocabulary %r on the FAC page" % term


# --------------------------------------------------------------------------- #
#  2. DB-first contract                                                        #
# --------------------------------------------------------------------------- #
def test_rendering_the_fac_analysis_never_opens_a_connection(app, monkeypatch):
    """Same contract as ``services.analysis``: the page opens with the unit off.

    Monkeypatched to EXPLODE rather than to a stub — a stub that returns empty
    would let a live call slip through looking like a device with no data.
    """
    _fac(app)

    def boom(*_a, **_k):
        raise AssertionError("analysis_fac contacted an appliance")

    import app.clients.fortiauthenticator as fac_client
    monkeypatch.setattr(fac_client, "FortiAuthenticatorClient", boom)
    with app.test_request_context("/analysis/"):
        out = analysis_fac.analyze({})
    assert out["product"] == "fortiauthenticator"


# --------------------------------------------------------------------------- #
#  3. Inventory: derived, and honest about absence                             #
# --------------------------------------------------------------------------- #
def test_inventory_rows_come_from_the_registry_not_a_hand_written_list(app):
    """A list written here would be a copy, and the first endpoint a release
    adds would be missing from the page with nothing failing to say so."""
    from app.registry import loader

    aid = _fac(app)
    with app.app_context():
        rows = analysis_fac.inventory([Appliance.query.get(aid)])["rows"]
        reg = set(loader.load_fac_registry())
    got = {r["endpoint"] for r in rows}
    assert got, "inventory produced no rows at all"
    assert got <= reg, "inventory invented endpoints the registry does not know"
    # And it really is derived: every countable, non-excluded registry entry is
    # present. A hardcoded subset would fail here the moment the registry grew.
    want = {n for n in reg
            if n not in analysis_fac._FAC_SOT_EXCLUDE
            and n.startswith(analysis_fac._COUNTABLE_PREFIX)}
    assert got == want


def test_not_harvested_is_distinguishable_from_zero(app):
    """They render identically as ``0`` and demand opposite actions: fix the
    sweep, or nothing at all."""
    aid = _fac(app)
    with app.app_context():
        rows = analysis_fac.inventory([Appliance.query.get(aid)])["rows"]
    assert rows
    for row in rows:
        for per in row["devices"]:
            # Nothing was ingested in this test, so every row must say so
            # rather than report a confident zero.
            assert per["harvested"] is False
            assert "harvested" in per


# --------------------------------------------------------------------------- #
#  4. Entitlement: never graded twice, never a fabricated zero                 #
# --------------------------------------------------------------------------- #
def test_entitlement_reports_unavailable_rather_than_zeros(app, monkeypatch):
    aid = _fac(app)
    from app.services import vm_store
    monkeypatch.setattr(vm_store, "health",
                        lambda: {"up": False, "detail": "store down"})
    with app.app_context():
        out = analysis_fac.entitlement([Appliance.query.get(aid)])
    assert out["available"] is False
    assert out["rows"] == []
    assert "store down" in out["detail"]


def test_a_capacity_row_with_no_probe_is_unmonitored_not_ok(app, monkeypatch):
    """Lost coverage must not read as health (§9b)."""
    aid = _fac(app)
    from app.services import vm_store
    monkeypatch.setattr(vm_store, "health", lambda: {"up": True})

    def fake_query(expr, ts=None, timeout=15.0):
        value = {"satom_fac_licence_used": "2",
                 "satom_fac_licence_total": "5",
                 "satom_fac_licence_pct": "40"}.get(expr.split("{")[0])
        if value is None:
            return {"data": {"result": []}}
        return {"data": {"result": [{
            "metric": {"device": "fac-t1", "kind": "fortiauthenticator",
                       "resource": "users"},
            "value": [0, value]}]}}

    monkeypatch.setattr(vm_store, "query", fake_query)
    with app.app_context():
        rows = analysis_fac.entitlement([Appliance.query.get(aid)])["rows"]
    assert len(rows) == 1
    assert rows[0]["probe_status"] == "unmonitored"
    assert rows[0]["used"] == 2.0 and rows[0]["free"] == 3.0


def test_an_uncapped_counter_reports_no_percentage(app, monkeypatch):
    """A counter with no ceiling must not print 0 %, which looks like room."""
    aid = _fac(app)
    from app.services import vm_store
    monkeypatch.setattr(vm_store, "health", lambda: {"up": True})

    def fake_query(expr, ts=None, timeout=15.0):
        base = expr.split("{")[0]
        if base not in ("satom_fac_token_used", "satom_fac_token_total"):
            return {"data": {"result": []}}
        return {"data": {"result": [{
            "metric": {"device": "fac-t1", "kind": "fortiauthenticator",
                       "pool": "ftk"},
            "value": [0, "0"]}]}}

    monkeypatch.setattr(vm_store, "query", fake_query)
    with app.app_context():
        rows = analysis_fac.entitlement([Appliance.query.get(aid)])["rows"]
    assert len(rows) == 1
    assert rows[0]["capped"] is False
    assert rows[0]["pct"] is None


# --------------------------------------------------------------------------- #
#  5. Posture: no verdict from a field nobody looked at                        #
# --------------------------------------------------------------------------- #
def test_posture_stays_silent_on_settings_that_are_not_cached(app):
    aid = _fac(app)
    with app.app_context():
        out = analysis_fac.posture([Appliance.query.get(aid)])
    assert out["findings"] == []
    assert {u["source"] for u in out["unread"]} == set(
        analysis_fac._POSTURE_SOURCES)


def test_lockout_findings_only_fire_on_fields_that_exist():
    # Present and off -> a warning.
    got = analysis_fac._lockout_findings("d", {"failed_login_lockout": False})
    assert got and got[0][0] == "warn"
    # Absent entirely -> nothing. A default assumed here would be a confident
    # verdict about a setting nobody read.
    assert analysis_fac._lockout_findings("d", {"something_else": 1}) == []


# --------------------------------------------------------------------------- #
#  6. Reports: the fleet section is scoped to the ADOM that names it           #
# --------------------------------------------------------------------------- #
def test_a_product_report_asks_only_for_its_own_products_metrics():
    fw = {k for k, _l, _u, _b in mr.fleet_queries("fortiweb")}
    fac = {k for k, _l, _u, _b in mr.fleet_queries("fortiauthenticator")}
    assert "throughput_bps" in fw and "policy_conn_per_sec" in fw
    # The bug: these were unconditional, so an identity report carried two
    # sections that product cannot produce.
    assert "throughput_bps" not in fac and "policy_conn_per_sec" not in fac
    assert "licence_pct" in fac and "licence_pct" not in fw
    # Both share the box metrics.
    assert {"cpu_pct", "mem_pct"} <= fw & fac


def test_global_gets_the_union_not_the_intersection():
    g = {k for k, _l, _u, _b in mr.fleet_queries("")}
    for product, rows in mr.FLEET_QUERIES_BY_PRODUCT.items():
        for key, *_ in rows:
            assert key in g, ("Global lost %r (from %s); the manager-wide view "
                              "must not shrink to the intersection"
                              % (key, product))


def test_every_fleet_query_is_label_scoped_for_a_product():
    """Half the fix is the metric set; the other half is the matcher. Without
    it a FortiAuthenticator report is computed over FortiWeb's series — a
    document that names one ADOM and describes another."""
    assert mr._sel("satom_box_cpu_pct", "fortiweb") == \
        'satom_box_cpu_pct{kind="fortiweb"}'
    assert mr._sel("satom_box_cpu_pct", "") == "satom_box_cpu_pct"


def test_the_policy_rollup_is_skipped_where_it_cannot_apply(app, monkeypatch):
    """"0 policies down" on an identity product reads as a clean bill of health
    for a check that never applied."""
    from app.services import vm_store
    monkeypatch.setattr(vm_store, "health", lambda: {"up": True})
    asked = []

    def fake_query(expr, ts=None, timeout=15.0):
        asked.append(expr)
        return {"data": {"result": []}}

    monkeypatch.setattr(vm_store, "query", fake_query)
    end = datetime.utcnow()
    out = mr.fleet_section(end - timedelta(hours=1), end,
                           product="fortiauthenticator")
    assert out["policy_scope"] is False
    assert not any("satom_policy_up" in e for e in asked)
    # ...and every query it DID ask was scoped.
    assert all('kind="fortiauthenticator"' in e for e in asked)

    asked.clear()
    out = mr.fleet_section(end - timedelta(hours=1), end, product="fortiweb")
    assert out["policy_scope"] is True
    assert any("satom_policy_up" in e for e in asked)


# --------------------------------------------------------------------------- #
#  7. Analytics: no built-in board may show a product a panel it cannot fill   #
# --------------------------------------------------------------------------- #
def _builtin_boards(app):
    """Boards + panels, materialised inside a context.

    ``board.panels`` is a lazy relationship: returning ORM rows would blow up
    the moment a test walked them outside the ``with``.
    """
    from app.models_analytics import MonitorDashboard
    out = []
    with app.app_context():
        for b in MonitorDashboard.query.filter_by(builtin=True).all():
            out.append({
                "slug": b.slug, "product": b.product or "",
                "panels": [{"title": p.title,
                            "rule_kind": (p.rule_kind or ""),
                            "vm_expr": (p.vm_expr or "")}
                           for p in b.panels],
            })
    return out


def test_no_builtin_board_offers_a_panel_the_adom_cannot_produce(app):
    """The general guard, derived from ``KIND_PRODUCTS`` rather than a list.

    A built-in seeded with product "" is visible in EVERY ADOM. If any of its
    rule panels names a probe kind that ADOM's product does not support, that
    panel can only ever render empty — which is exactly the reported bug, and
    exactly what a future product would inherit again.
    """
    from app.services.product_scope import concrete_products

    problems = []
    for board in _builtin_boards(app):
        scoped = board["product"]
        for panel in board["panels"]:
            kind = panel["rule_kind"].strip()
            if not kind:
                continue
            supported = dm.KIND_PRODUCTS.get(kind)
            if not supported:      # e.g. "https" — product-agnostic
                continue
            audience = [scoped] if scoped else list(concrete_products())
            for product in audience:
                if product not in supported:
                    problems.append("%s/%s: kind %r not supported by %s"
                                    % (board["slug"], panel["title"], kind,
                                       product))
    assert not problems, "; ".join(problems)


def test_the_fortiweb_only_boards_are_scoped_to_fortiweb(app):
    by_slug = {b["slug"]: b for b in _builtin_boards(app)}
    for slug in ("traffic", "service-health"):
        assert by_slug[slug]["product"] == "fortiweb", (
            "%s is FortiWeb-only telemetry; seeded Global it appears in every "
            "ADOM as empty panels" % slug)


def test_fortiauthenticator_gets_boards_of_its_own(app):
    by_slug = {b["slug"]: b for b in _builtin_boards(app)}
    fac = [b for b in by_slug.values()
           if b["product"] == "fortiauthenticator"]
    assert fac, "the FAC ADOM would have only the cross-product boards"
    kinds = {p["rule_kind"] for b in fac for p in b["panels"] if p["rule_kind"]}
    assert {"licence", "tokens"} & kinds


def test_the_cross_product_boards_really_are_cross_product(app):
    """fleet-metrics / fleet-overview stay Global, so they must only use
    signals every product with a box collector emits."""
    by_slug = {b["slug"]: b for b in _builtin_boards(app)}
    for slug in ("fleet-metrics", "fleet-overview"):
        board = by_slug[slug]
        assert board["product"] == "", "%s must stay Global" % slug
        for panel in board["panels"]:
            expr = panel["vm_expr"]
            for fw_only in ("satom_total_throughput_bps",
                            "satom_policy_conn_per_sec", "satom_policy_up"):
                assert fw_only not in expr, (
                    "%s/%s uses the FortiWeb-only series %s on a board every "
                    "ADOM can see" % (slug, panel["title"], fw_only))
