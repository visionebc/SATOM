"""Guards for the 2026-08-05 Monitoring restructure.

Four separate defects, one test module, because they share the same failure
shape: **a panel that cannot report bad news, and a page that says nothing when
it has the data.** Nothing crashes in any of them — the console simply makes a
false statement, which is exactly the class that ships.

1. ``satom-metrics`` was absent from ``MONITORED_UNITS``. Analytics boards and
   the Collection page read from that store, so it could be dead while every
   light on Services & redundancy stayed green.
2. Collection sat under Monitoring next to six pages that *display* a
   measurement, while it *configures* how measurement happens.
3. Device HA clusters printed "No HA clusters registered" on a fleet whose
   harvest had ``system_ha`` cached for every box: the panel read
   ``Appliance.members``, a table written only by the appliance form.
4. Fleet health carried both the appliances and the manager's own health, so it
   had to hide half of itself in every product ADOM.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from app.models import Appliance, User, db
from app.models_cache import DeviceObject
from tests.conftest import login

ADOMS = ["fortiweb", "fortiadc", "fortianalyzer"]
ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE_HTML = ROOT / "app" / "templates" / "base.html"
NAV_MON = ROOT / "app" / "templates" / "partials" / "nav_monitoring.html"
NAV_COL = ROOT / "app" / "templates" / "partials" / "nav_collection.html"
COLLECTION_HTML = ROOT / "app" / "templates" / "monitoring" / "collection.html"


@pytest.fixture()
def admin_id(app):
    with app.app_context():
        u = User.query.filter_by(role="admin").first()
        if u is None:
            u = User(username="splitadmin", role="admin", is_active=True)
            u.set_password("x" * 12)
            db.session.add(u)
            db.session.commit()
        return u.id


def _appliance(kind="fortiweb", name="box", host="192.0.2.75"):
    a = Appliance(name=name, host=host, kind=kind, username="admin")
    a.password = "pw"          # NOT NULL; the setter encrypts
    db.session.add(a)
    db.session.flush()
    return a


def _cache_ha(appliance_id, payload):
    db.session.add(DeviceObject(appliance_id=appliance_id, layer="config",
                                section="system", logical_name="system_ha",
                                payload=payload, depth=0, idx=0))
    db.session.commit()


# ---------------------------------------------------------------------------
# 1. the metrics store is monitored (and units inactive BY DESIGN are not)
# ---------------------------------------------------------------------------

def test_the_metrics_store_unit_is_monitored():
    """Analytics and Collection read from it; a dead store must not read green."""
    from app.services.system_health import MONITORED_UNITS
    assert "satom-metrics.service" in MONITORED_UNITS


def test_role_guarded_and_retired_units_are_not_monitored():
    """``satom-ha-datasync`` is inert on the primary by design and
    ``satom-git-publish`` was retired with the git SoT. Listing either shows a
    permanent red for correct behaviour, and a check that always complains is a
    check the operator skips -- removed from ``get system health`` twice
    already."""
    from app.services.system_health import MONITORED_UNITS
    for unit in ("satom-ha-datasync.timer", "satom-ha-datasync.service",
                 "satom-git-publish.timer", "satom-git-publish.service"):
        assert unit not in MONITORED_UNITS, unit


def test_a_unit_that_is_not_installed_is_neutral_not_failed(monkeypatch):
    """``systemctl is-active`` says ``inactive`` for a unit that does not exist,
    which is indistinguishable from one that exists and stopped. A standalone
    box with no nftables package is fine; a node whose store died is not."""
    import subprocess
    from app.services import system_health as sh

    class R:
        def __init__(self, out):
            self.stdout = out

    def fake_run(cmd, **kw):
        if "show" in cmd:
            return R("not-found\n")
        return R("inactive\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    row = sh.service_status(("nope.service",))[0]
    assert row["ok"] is None, "a missing unit must not be graded as failed"
    assert row["installed"] is False
    assert "not installed" in row["state"]


def test_an_installed_but_dead_unit_is_still_red(monkeypatch):
    """The neutral path above must not swallow a real failure."""
    import subprocess
    from app.services import system_health as sh

    class R:
        def __init__(self, out):
            self.stdout = out

    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: R("loaded\n" if "show" in cmd else "failed\n"))
    row = sh.service_status(("satom-metrics.service",))[0]
    assert row["ok"] is False and row["installed"] is True


# ---------------------------------------------------------------------------
# 2. Collection lives under Administrator, in EVERY ADOM, from ONE definition
# ---------------------------------------------------------------------------

def _admin_group_bodies(text: str) -> list[str]:
    """Slice base.html into the body of each Administrator/Administration group."""
    out = []
    for m in re.finditer(r"<span>Administrat(?:or|ion)</span>", text):
        tail = text[m.end():]
        start = tail.index('<div class="fw-nav-group-body">')
        # the group body ends at the next section header or context boundary
        end = len(tail)
        for stop in ("fw-nav-section fw-nav-toggle", "fw-nav-context-label",
                     "{% elif product.key", "{% endif %}\n    </nav>"):
            i = tail.find(stop, start)
            if i != -1:
                end = min(end, i)
        out.append(tail[start:end])
    return out


def test_every_administrator_group_offers_collection():
    """FIVE Administrator blocks, already drifted once (one is even titled
    "Administration"). A shared partial is the only thing that stops an entry
    from being added to Global and forgotten in the others.

    The real promise is the loop below — every block includes the partial. The
    exact count is a NON-VACUITY guard: without it, an extractor that stopped
    matching would make this test pass over zero blocks. Bump it (and only it)
    when an ADOM gains its own Administrator group; it went 4 -> 5 on
    2026-08-05 when FortiAuthenticator stopped being a placeholder.
    """
    bodies = _admin_group_bodies(BASE_HTML.read_text())
    assert len(bodies) == 5, "expected 5 Administrator groups, got %d" % len(bodies)
    for i, b in enumerate(bodies):
        assert "partials/nav_collection.html" in b, \
            "Administrator group #%d does not include the Collection partial" % i


def test_collection_is_defined_once():
    """One href for the page across the whole nav — not four hand-typed copies."""
    text = BASE_HTML.read_text() + NAV_MON.read_text()
    assert "metrics_admin.index" not in text, \
        "Collection must be reached through partials/nav_collection.html only"
    assert "metrics_admin.index" in NAV_COL.read_text()


def test_monitoring_submenu_no_longer_carries_collection():
    nav = NAV_MON.read_text()
    assert ">Collection<" not in nav
    assert "metrics_admin" not in nav, \
        "the Monitoring subgroup must not re-open on the Collection page"


def test_collection_toggle_is_a_button_not_a_link():
    """It POSTs and changes state. ``btn-link`` renders as navigation, and the
    row already has a real button (save) two cells over."""
    html = COLLECTION_HTML.read_text()
    assert "btn btn-link" not in html
    m = re.search(r'<button[^>]*form="tg-\{\{ t\.id \}\}"', html)
    assert m, "the enable/disable toggle must be a <button> bound to the tg- form"
    assert "btn-outline-light" in m.group(0) or "btn-outline-light" in html


def test_collection_page_renders_the_button(client, admin_id, app):
    login(client, admin_id, product="global")
    with app.app_context():
        _appliance()
        db.session.commit()
    body = client.get("/monitoring/collection/",
                      headers={"X-ADOM": "global"}).get_data(as_text=True)
    assert body.count("</button>") >= 1
    assert 'class="btn btn-link' not in body


# ---------------------------------------------------------------------------
# 3. Device HA posture comes from the HARVEST, not from hand entry
# ---------------------------------------------------------------------------

def test_a_harvested_standalone_device_is_reported_as_standalone(app):
    """The whole point: ``Appliance.ha_mode`` is NULL on every device in a real
    fleet because only the appliance form writes it, yet the hourly sweep has
    ``system_ha`` cached for all of them."""
    from app.services import ha_inventory
    with app.app_context():
        a = _appliance(name="fwb-standalone")
        _cache_ha(a.id, {"mode": "standalone", "hbdev": "", "group-name": ""})
        p = ha_inventory.posture(a)
        assert p["status"] == "standalone"
        assert p["source"] == "cache"
        assert p["raw_mode"] == "standalone"


def test_a_harvested_cluster_is_reported_with_its_evidence(app):
    from app.services import ha_inventory
    with app.app_context():
        a = _appliance(name="fwb-ha", host="192.0.2.79")
        _cache_ha(a.id, {"mode": "active-passive", "hbdev": "port3",
                         "group-name": "edge-ha", "priority": 5})
        p = ha_inventory.posture(a)
        assert p["status"] == "clustered"
        assert p["mode"] == "active-passive"
        assert p["evidence"], "a clustered verdict must say why"
        assert any("port3" in e for e in p["evidence"])


def test_a_device_with_no_harvested_ha_is_unknown_never_standalone(app):
    """'We have measured nothing' and 'this box is standalone' are different
    statements. Merging them is the 2026-07-28 Fleet-health-badge bug."""
    from app.services import ha_inventory
    with app.app_context():
        a = _appliance(name="fwb-nocache", host="192.0.2.81")
        db.session.commit()
        p = ha_inventory.posture(a)
        assert p["status"] == "unknown"
        assert p["source"] == "none"


def test_fortianalyzer_int_mode_is_not_translated_into_a_confident_label(app):
    """FortiAnalyzer returns ``mode`` as an int and the enum could not be
    verified against a live device. Guessing it would print 'primary' for a box
    that is standalone, so the verdict comes from peer evidence and the raw
    value is carried through verbatim."""
    from app.services import ha_inventory
    with app.app_context():
        a = _appliance(kind="fortianalyzer", name="faz-x", host="192.0.2.12")
        _cache_ha(a.id, {"mode": 1, "peer": None, "hb-interface": "", "vip": None})
        p = ha_inventory.posture(a)
        assert p["status"] == "standalone", "no peer evidence -> not a cluster"
        assert p["raw_mode"] == "1", "the device's own value must be shown"
        assert "primary" not in p["mode"] and "secondary" not in p["mode"]


def test_fortianalyzer_with_a_peer_is_clustered(app):
    from app.services import ha_inventory
    with app.app_context():
        a = _appliance(kind="fortianalyzer", name="faz-ha", host="192.0.2.13")
        _cache_ha(a.id, {"mode": 1, "peer": "192.0.2.14", "hb-interface": "port2"})
        p = ha_inventory.posture(a)
        assert p["status"] == "clustered"
        assert p["evidence"]


def test_retired_placeholders_are_excluded_from_the_rollup(app):
    """A row whose host is parked on the reserved ``.invalid`` TLD names no real
    box; counting it as 'unknown' keeps the panel permanently amber for history
    rows."""
    from app.services import ha_inventory
    with app.app_context():
        live = _appliance(name="live-box", host="192.0.2.75")
        _cache_ha(live.id, {"mode": "standalone"})
        _appliance(name="retired-box", host="retired-fw6.invalid")
        db.session.commit()
        roll = ha_inventory.fleet(Appliance.query.all())
        names = [d["name"] for d in roll["devices"]]
        assert "live-box" in names
        assert "retired-box" not in names


def test_the_device_feed_carries_the_posture_in_every_adom(app, client, admin_id):
    """HA posture rides ``/monitoring/data`` -- the DEVICE feed -- not the
    manager feed, and it is scoped by ``visible_appliances``.

    It shipped on the manager feed and was rendered on SATOM health, where a
    device counter reads as a claim about the installation: ``0 clustered ·
    1 standalone`` on a two-node streaming pair. It also came from an unscoped
    ``Appliance.query``, so a FortiWeb ADOM would have listed the FortiADCs.
    """
    with app.app_context():
        w = _appliance(kind="fortiweb", name="fwb-d", host="192.0.2.75")
        c = _appliance(kind="fortiadc", name="adc-d", host="192.0.2.76")
        _cache_ha(w.id, {"mode": "standalone"})
        _cache_ha(c.id, {"mode": "standalone"})
        db.session.commit()

    login(client, admin_id, product="global")
    ha = client.get("/monitoring/data",
                    headers={"X-ADOM": "global"}).get_json().get("ha") or {}
    assert {p["name"] for p in ha["posture"]} == {"fwb-d", "adc-d"}
    assert ha["counts"]["standalone"] == 2

    login(client, admin_id, product="fortiweb")
    ha = client.get("/monitoring/data",
                    headers={"X-ADOM": "fortiweb"}).get_json().get("ha") or {}
    assert [p["name"] for p in ha["posture"]] == ["fwb-d"], \
        "a product ADOM must not see another product's boxes"


def test_the_manager_feed_no_longer_carries_device_data(app):
    """SATOM health answers "is this INSTALLATION healthy?". Appliance rows on
    that feed are what produced the false reading."""
    from app.services import system_health
    with app.app_context():
        a = _appliance(name="fwb-r")
        _cache_ha(a.id, {"mode": "standalone"})
        red = system_health.redundancy()
        for leaked in ("device_posture", "device_counts", "device_clusters",
                       "device_standalone"):
            assert leaked not in red, "%s belongs to the device feed" % leaked
        assert "manager_posture" in red


def test_manager_posture_reports_a_streaming_pair_as_clustered():
    """The headline the SATOM page owes its reader: two nodes with a live
    replica is a cluster, and the evidence says why."""
    from app.services import ha_inventory
    p = ha_inventory.manager_posture(
        {"instances": 2, "mode": "ha", "standby": True, "streaming": True,
         "this_role": "primary", "split_brain": False})
    assert p["status"] == "clustered"
    assert p["role"] == "primary"
    assert any("streaming" in e for e in p["evidence"])


def test_manager_posture_prefers_evidence_over_the_admin_switch():
    """``mode`` is an operator-set switch. A node left on 'standalone' while a
    replica streams is still a pair -- reading the switch would report the
    installation as single-node while its peer was serving."""
    from app.services import ha_inventory
    p = ha_inventory.manager_posture(
        {"instances": 2, "mode": "standalone", "standby": True,
         "streaming": True, "this_role": "primary"})
    assert p["status"] == "clustered"


def test_manager_posture_calls_a_single_node_standalone():
    from app.services import ha_inventory
    p = ha_inventory.manager_posture(
        {"instances": 1, "mode": "standalone", "standby": False,
         "streaming": False, "this_role": "primary"})
    assert p["status"] == "standalone"
    assert p["evidence"], "an unexplained status is one the operator ignores"


def test_manager_posture_of_a_failed_probe_is_unknown_not_standalone():
    """Same rule the device rows follow: "we could not measure this" and "this
    is a single node" are different statements (the 2026-07-28 badge lesson)."""
    from app.services import ha_inventory
    assert ha_inventory.manager_posture({})["status"] == "unknown"
    assert ha_inventory.manager_posture(
        {"instances": 0, "standby": False})["status"] == "unknown"


def _executable(text: str) -> str:
    """Template text with Jinja and JS line comments removed.

    A guard that greps raw source matches the comment EXPLAINING the guard --
    the ninth time that has happened in this repo. Anchor on what actually runs.
    """
    text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    return "\n".join(l for l in text.split("\n")
                     if not l.lstrip().startswith("//"))


def test_the_panel_no_longer_claims_no_clusters_registered():
    """The literal string that started this: it appeared whenever the manual
    members table was empty, which was always."""
    satom = _executable((ROOT / "app" / "templates" / "monitoring" / "satom.html").read_text())
    index = _executable((ROOT / "app" / "templates" / "monitoring" / "index.html").read_text())
    assert "No HA clusters registered" not in satom
    assert "No HA clusters registered" not in index
    assert "ha.posture" in index, "Device health must render the posture rows"


def test_the_device_posture_panel_is_not_on_the_installation_page():
    """The whole defect in one assertion.

    SATOM health is headed "this installation". A device HA counter there is
    read as a statement about SATOM -- ``0 clustered · 1 standalone`` on a
    two-node pair. The rows belong with the appliances; the manager states its
    own posture instead.
    """
    satom = _executable((ROOT / "app" / "templates" / "monitoring" / "satom.html").read_text())
    index = _executable((ROOT / "app" / "templates" / "monitoring" / "index.html").read_text())
    assert "Device HA posture" not in satom
    assert "device_posture" not in satom
    assert "Device HA posture" in index
    assert "Manager redundancy" in satom
    assert "manager_posture" in satom, \
        "the installation page must state ITS OWN posture, not only a note"


def test_the_ha_pill_uses_the_products_own_badge_vocabulary():
    """One badge set across the console. The pill was a local palette
    (``.ha-clustered`` etc.) that no other status in the product used."""
    satom = _executable((ROOT / "app" / "templates" / "monitoring" / "satom.html").read_text())
    index = _executable((ROOT / "app" / "templates" / "monitoring" / "index.html").read_text())
    for name, tpl in (("satom.html", satom), ("index.html", index)):
        assert "fw-badge-success" in tpl, "%s: clustered pill" % name
        assert "fw-badge-secondary" in tpl, "%s: standalone pill" % name
        assert "ha-clustered" not in tpl, "%s: local palette is gone" % name
        assert "ha-standalone" not in tpl, "%s: local palette is gone" % name


def test_the_comment_stripper_would_still_catch_a_real_regression():
    """Without this, narrowing ``_executable`` until it strips everything would
    leave the guard above green while the panel printed the old claim."""
    assert "No HA clusters registered" in _executable(
        'var x = "No HA clusters registered";')
    assert "gone" not in _executable("// gone\n{# gone #}\nvar y = 1;")


# ---------------------------------------------------------------------------
# 4. Fleet health split: SATOM health (this install) vs Device health
# ---------------------------------------------------------------------------

MANAGER_SECTIONS = ("Infrastructure health", "Encryption in transit")


def test_satom_health_carries_the_manager_sections(client, admin_id):
    login(client, admin_id, product="global")
    body = client.get("/monitoring/satom",
                      headers={"X-ADOM": "global"}).get_data(as_text=True)
    for s in MANAGER_SECTIONS:
        assert s in body


def test_device_health_never_carries_the_manager_sections(client, admin_id):
    """Even in Global. The split is the point: one page, one question."""
    login(client, admin_id, product="global")
    body = client.get("/monitoring/",
                      headers={"X-ADOM": "global"}).get_data(as_text=True)
    for s in MANAGER_SECTIONS:
        assert s not in body
    assert 'id="monDevices"' in body


@pytest.mark.parametrize("adom", ADOMS)
def test_satom_health_is_not_reachable_from_a_product_adom(client, admin_id, adom):
    login(client, admin_id, product=adom)
    r = client.get("/monitoring/satom", headers={"X-ADOM": adom})
    assert r.status_code == 302, "must bounce, not render"
    assert "/monitoring/" in (r.headers.get("Location") or "")


@pytest.mark.parametrize("adom", ADOMS)
def test_satom_data_is_global_only(client, admin_id, adom):
    """Enforced on the route, not hidden in the template: these keys name node
    hostnames and infrastructure addresses."""
    login(client, admin_id, product=adom)
    assert client.get("/monitoring/satom-data",
                      headers={"X-ADOM": adom}).status_code == 403


def test_satom_data_has_the_manager_keys_and_no_device_cards(client, admin_id):
    login(client, admin_id, product="global")
    d = client.get("/monitoring/satom-data",
                   headers={"X-ADOM": "global"}).get_json()
    for k in ("system", "services", "db", "redundancy"):
        assert k in d
    assert "devices" not in d, \
        "the manager feed must not pay for the per-device capacity roll-up"


def test_the_nav_offers_both_halves_in_global(client, admin_id):
    login(client, admin_id, product="global")
    body = client.get("/monitoring/",
                      headers={"X-ADOM": "global"}).get_data(as_text=True)
    assert "SATOM health" in body and "Device health" in body


@pytest.mark.parametrize("adom", ADOMS)
def test_the_nav_hides_satom_health_outside_global(client, admin_id, adom):
    login(client, admin_id, product=adom)
    body = client.get("/monitoring/", headers={"X-ADOM": adom}).get_data(as_text=True)
    assert "SATOM health" not in body
    assert "Device health" in body


# ---------------------------------------------------------------------------
# Analysis belongs to Monitoring (2026-08-06)
#
# It used to be a bare Fleet item written out FIVE times in base.html -- once
# per ADOM block -- which is the precise drift partials/nav_monitoring.html
# exists to prevent (the same thing had already happened to Metrics).  Five
# copies means an edit lands in one ADOM and is forgotten in the other four,
# and nothing fails when that happens: the entry is simply missing.
# ---------------------------------------------------------------------------


def test_analysis_lives_in_the_monitoring_submenu():
    nav = NAV_MON.read_text()
    assert "url_for('analysis.index'" in nav, \
        "Analysis must be an entry of the Monitoring submenu partial"
    assert "_adom=product.key" in nav.split("analysis.index", 1)[1][:60], \
        "a hard (non-Turbo) navigation cannot carry X-ADOM -- pin it on the URL"


def test_base_html_carries_no_second_analysis_nav_entry():
    """One definition, five call sites.  A bare entry in base.html would be a
    sixth copy that only one ADOM gets."""
    base = BASE_HTML.read_text()
    assert ">Analysis</span></a>" not in base, \
        "Analysis must be reached through partials/nav_monitoring.html only"
    assert "url_for('analysis.index')" not in base


def test_the_monitoring_submenu_reopens_on_the_analysis_page():
    """Every other page in this group re-opens the submenu it belongs to.  A
    page that collapses its own menu reads as if it lived somewhere else."""
    nav = NAV_MON.read_text()
    open_list = nav.split('data-nav-subgroup="Monitoring"', 1)[0]
    assert "'analysis'" in open_list
