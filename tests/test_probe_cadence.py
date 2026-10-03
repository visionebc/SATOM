"""Probe cadence + collapsible device cards.

Two guards that protect one another:

1. ``due_probes`` fires a probe only when the WHOLE ``interval_min`` has elapsed
   *and* a sweep tick happens, so the effective cadence is
   ``tick * ceil(interval / tick)``. An interval that is not a multiple of the
   sweep tick silently runs slower than the row claims -- a 5-minute probe under
   a 3-minute sweep is really a 6-minute probe, and no UI says so. Everything
   discovery creates must therefore be a multiple of the tick.

2. The device cards on both probe pages are collapsible, and ``renderDevices``
   replaces ``innerHTML`` on every poll. Collapse state kept in the DOM would be
   wiped every refresh cycle, silently re-expanding every card. It must be
   persisted outside the DOM.
"""
from __future__ import annotations

import io
import os
import re
from datetime import datetime, timedelta

import pytest

from app.services import deep_monitor as dm

TEMPLATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "app", "templates", "monitoring", "_probe_page.html")


# --------------------------------------------------------------- cadence ---

def test_default_interval_is_the_sweep_tick():
    assert dm.DEFAULT_PROBE_INTERVAL_MIN == 3


def test_slow_interval_is_a_multiple_of_the_default():
    # 15 % 3 == 0: the coarse probes still land on a tick instead of drifting.
    assert dm.SLOW_PROBE_INTERVAL_MIN % dm.DEFAULT_PROBE_INTERVAL_MIN == 0


def test_rest_discovery_defaults_to_the_tick():
    """``discover_api_probes`` must not hardcode a non-multiple interval."""
    import inspect
    src = inspect.getsource(dm.discover_api_probes)
    m = re.search(r"interval:\s*int\s*=\s*([A-Za-z_0-9]+)", src)
    assert m, "discover_api_probes lost its interval default"
    assert m.group(1) == "DEFAULT_PROBE_INTERVAL_MIN", (
        "REST telemetry probes must default to the sweep tick, got %r" % m.group(1))


def test_box_discovery_uses_the_named_constants():
    import inspect
    src = inspect.getsource(dm.ensure_baseline)
    assert "DEFAULT_PROBE_INTERVAL_MIN" in src
    assert "SLOW_PROBE_INTERVAL_MIN" in src
    # A bare literal 5 would drift under a 3-minute sweep.
    assert not re.search(r'· CPU[^)]*,\s*5\)', src)
    assert not re.search(r'· memory[^)]*,\s*5\)', src)


def test_due_probes_needs_the_whole_interval(app, monkeypatch):
    """The drift is real: a probe is NOT due until its full interval elapsed.

    This is what makes a non-multiple interval slower than advertised, so pin
    the behaviour the cadence rule is derived from.
    """
    from app.models import MonitorProbe, db

    with app.app_context():
        p = MonitorProbe(appliance_id=None, kind="cpu", name="cadence-probe",
                         enabled=True, interval_min=3)
        p.last_run_at = datetime.utcnow() - timedelta(minutes=2, seconds=30)
        db.session.add(p)
        db.session.commit()
        assert p not in dm.due_probes()

        p.last_run_at = datetime.utcnow() - timedelta(minutes=3, seconds=1)
        db.session.commit()
        assert p in dm.due_probes()

        db.session.delete(p)
        db.session.commit()


# ----------------------------------------------------- collapsible cards ---

@pytest.fixture(scope="module")
def tpl() -> str:
    return io.open(TEMPLATE, encoding="utf-8").read()


def test_device_cards_are_collapsible(tpl):
    assert "dp-dev-toggle" in tpl
    assert "dp-dev-body" in tpl
    assert "is-collapsed" in tpl


def test_collapse_state_is_not_kept_in_the_dom(tpl):
    """renderDevices() rewrites innerHTML every poll -- DOM state would reset."""
    assert "localStorage.getItem(OPEN_KEY" in tpl
    assert "localStorage.setItem(OPEN_KEY" in tpl
    # Keyed per page so Deep monitors and Service Monitor do not share state.
    assert "'satom.probecards.open.' + BASE" in tpl


def test_cards_are_collapsed_by_default(tpl):
    """A fleet page that opens with ~100 expanded cards shows nothing.

    The store holds the OPEN set, so an operator who has never touched the
    page has an empty set and therefore every card folded.
    """
    assert "var collapsed = !OPEN.has(String(dev.id));" in tpl
    # The old key must NOT come back: it stored the inverse set, so reusing the
    # name would read a saved closed-set as an open-set.
    assert "probecards.collapsed" not in tpl


def test_folded_cards_tile_and_an_open_one_takes_the_row(tpl):
    """Density is the point: ~100 folded tiles must fit, not stack."""
    assert "grid-template-columns:repeat(auto-fill, minmax(258px,1fr))" in tpl
    assert ".dp-dev-card:not(.is-collapsed) { grid-column:1 / -1;" in tpl
    assert ".dp-dev-card.is-collapsed .dp-dev-sub { display:none; }" in tpl


def test_probe_page_uses_the_light_chrome(tpl):
    """SATOM has no dark mode (static/css/fortiweb.css: .fw-card is #FFFFFF).

    The fleet's dark glassmorphism palette renders as a grey slab here and
    makes the light-on-light pills vanish -- reported 2026-07-28.
    """
    assert "background:#fff; border:1px solid var(--fw-border)" in tpl
    assert "box-shadow:var(--fw-card-shadow)" in tpl
    for dark in ("rgba(30,41,59,",     # slate-800 card gradient
                 "rgba(15,23,42,",     # slate-900
                 "backdrop-filter",    # glassmorphism blur
                 "#cbd5e1",            # slate-300 body text
                 "#93c5fd", "#6ee7b7", "#fcd34d", "#fca5a5", "#c4b5fd"):
        assert dark not in tpl, "dark-theme value %s leaked back in" % dark


def test_collapse_toggle_is_keyboard_reachable(tpl):
    assert 'role="button" tabindex="0"' in tpl
    assert "aria-expanded" in tpl
    assert "'keydown'" in tpl


def test_collapsed_card_still_shows_a_headline_number(tpl):
    """Collapsing must not equal hiding the device."""
    assert "dp-hchip" in tpl
    assert ".dp-dev-card:not(.is-collapsed) .dp-hchip { display:none; }" in tpl


def test_no_inline_event_handlers_added(tpl):
    """CSP: the app binds via delegation, never via on* attributes."""
    assert not re.search(r'\bonclick\s*=\s*"', tpl)
    assert not re.search(r'\bonkeydown\s*=\s*"', tpl)


# ------------------------------------------------------- rendered output ---

@pytest.mark.parametrize("url", ["/monitoring/deep/", "/monitoring/services/"])
def test_probe_page_renders_collapsible_cards(client, url):
    """The markup has to survive Jinja, not just exist in the template file."""
    from tests.conftest import admin_user_id, login

    login(client, admin_user_id(client.application))
    r = client.get(url)
    assert r.status_code == 200, r.status_code
    html = r.get_data(as_text=True)
    for token in ("dp-dev-toggle", "dp-dev-body", "is-collapsed",
                  "satom.probecards.open", "dp-caret", "dp-hchip"):
        assert token in html, "%s missing from %s" % (token, url)
    assert "function toggleDev(" in html


# ------------------------------------------- one cadence, stated one way ---

def test_sweep_cadence_is_stated_as_three_minutes_everywhere():
    """The seed plan sweeps every 3 minutes; the action summary and the
    Service Monitor docstring used to say five."""
    from app.services import scheduled_actions as sa
    from app.views import service_monitor

    summary = sa.ALL_ACTIONS["deep_monitor"].summary
    assert "EVERY 3 MINUTES" in summary
    assert "EVERY 5 MINUTES" not in summary
    assert "every three minutes" in service_monitor.__doc__
    assert "every five minutes" not in service_monitor.__doc__


def test_new_probe_defaults_to_the_sweep_tick(app):
    from app.models import MonitorProbe, db

    with app.app_context():
        p = MonitorProbe(kind="cpu", name="fresh", enabled=True)
        db.session.add(p)
        db.session.commit()
        assert p.interval_min == dm.DEFAULT_PROBE_INTERVAL_MIN


@pytest.mark.parametrize("url", ["/monitoring/deep/", "/monitoring/services/"])
def test_add_form_interval_defaults_to_the_sweep_tick(client, url):
    from tests.conftest import admin_user_id, login

    login(client, admin_user_id(client.application))
    html = client.get(url).get_data(as_text=True)
    m = re.search(r'name="interval_min" id="dpFint" value="(\d+)"', html)
    assert m, "interval input missing"
    assert int(m.group(1)) == dm.DEFAULT_PROBE_INTERVAL_MIN


def test_create_without_interval_uses_the_sweep_tick(client, app):
    from app.models import MonitorProbe
    from tests.conftest import admin_user_id, login

    login(client, admin_user_id(app), product="global")
    r = client.post("/monitoring/deep/probe",
                    data={"kind": "https", "name": "vip", "interval_min": "0",
                          "url": "https://192.0.2.9/"})
    assert r.status_code == 200
    pid = r.get_json()["probe"]["id"]
    with app.app_context():
        assert MonitorProbe.query.get(pid).interval_min == dm.DEFAULT_PROBE_INTERVAL_MIN


def test_https_discovery_creates_probes_on_the_tick(app):
    from app.models import Appliance, MonitorProbe, db

    with app.app_context():
        a = Appliance(name="fwcad", host="192.0.2.5", kind="fortiweb",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        orig = dm.resolve_targets_from_cache
        dm.resolve_targets_from_cache = lambda ap, session=None: [
            {"url": "https://192.0.2.90/", "policy": "pol", "enabled": True,
             "note": ""}]
        try:
            assert dm.discover_https_probes(a)["created"] == 1
        finally:
            dm.resolve_targets_from_cache = orig
        p = MonitorProbe.query.filter_by(appliance_id=a.id).one()
        assert p.interval_min == dm.DEFAULT_PROBE_INTERVAL_MIN


# ------------------------------------ product notes follow KIND_PRODUCTS ---

_LABEL = {"fortiweb": "FortiWeb", "fortiadc": "FortiADC",
          "fortianalyzer": "FortiAnalyzer",
          "fortiauthenticator": "FortiAuthenticator"}


def test_cpu_note_names_every_product_the_kind_is_offered_on(tpl):
    i = tpl.index("<code>get system performance</code>")
    note = tpl[i:tpl.index("</div>", i)]
    for product in dm.KIND_PRODUCTS["cpu"]:
        assert _LABEL[product] in note, "%s missing from the CPU note" % product


def test_rest_discovery_note_is_not_fortiweb_only(tpl):
    i = tpl.index("<b>{{ _('REST telemetry') }}</b>")
    note = tpl[i:tpl.index("</label>", i)]
    assert "FortiWeb only" not in note
    products = {p for k in dm.API_KINDS for p in dm.KIND_PRODUCTS[k]}
    for product in products:
        assert _LABEL[product] in note
