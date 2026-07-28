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
    assert "localStorage.getItem(COLL_KEY" in tpl
    assert "localStorage.setItem(COLL_KEY" in tpl
    # Keyed per page so Deep monitors and Service Monitor do not share state.
    assert "'satom.probecards.collapsed.' + BASE" in tpl


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
                  "satom.probecards.collapsed", "dp-caret", "dp-hchip"):
        assert token in html, "%s missing from %s" % (token, url)
    assert "function toggleDev(" in html
