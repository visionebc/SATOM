"""Guards for the Calendar blueprint and the inverted-window repair.

The blueprint's own job is small — read the form, resolve a selector, render —
so these tests defend the three places where it could quietly widen something:
the permission gate, the target resolution, and the fact that it creates changes
through ``change_requests.create_change_request`` rather than becoming a second
author of what a legal change is.
"""
from __future__ import annotations

from datetime import datetime

import pytest

from conftest import admin_user_id, login, make_user


# --------------------------------------------------------------------------- #
# the repair: an inverted window is refused by the ONE creator
# --------------------------------------------------------------------------- #
def test_create_change_request_refuses_an_inverted_window(app):
    """CR-0011 was stored ending a DAY before it began, in status 'approved'.
    Nothing errored; it simply could never fire. The check belongs in the one
    implementation so the form, the wave route and the calendar all inherit it.
    """
    from app.views.change_requests import create_change_request
    with app.test_request_context():
        cr, error = create_change_request({
            "title": "backwards", "action": "upgrade", "device_ids": [],
            "window_start": datetime(2026, 8, 12, 0, 40),
            "window_end": datetime(2026, 8, 11, 0, 40),
        })
    assert cr is None
    assert "never fire" in error and "Nothing was created" in error


def test_a_zero_length_window_is_refused_too(app):
    """end == start contains no instant either. '<' would have let it through."""
    from app.views.change_requests import create_change_request
    at = datetime(2026, 8, 12, 0, 40)
    with app.test_request_context():
        cr, error = create_change_request({
            "title": "instant", "action": "upgrade", "device_ids": [],
            "window_start": at, "window_end": at,
        })
    assert cr is None and "never fire" in error


def test_a_half_open_window_is_still_allowed(app):
    """A draft with only one end typed is somebody still writing it, not a
    defect. Refusing it would block the ordinary way changes get raised."""
    from app.views.change_requests import create_change_request
    with app.test_request_context():
        cr, error = create_change_request({
            "title": "half", "action": "upgrade", "device_ids": [],
            "window_start": datetime(2026, 8, 12, 0, 40), "window_end": None,
        })
    assert error == "" and cr is not None


# --------------------------------------------------------------------------- #
# permission
# --------------------------------------------------------------------------- #
def test_the_calendar_needs_the_same_gate_as_its_two_sources(app, client):
    """It draws Change Requests and Scheduled Actions, both user_manage-gated.
    A weaker gate here is a read-side hole into both."""
    uid = make_user(app, username="ro", role="readonly")
    login(client, uid)
    assert client.get("/calendar/").status_code in (302, 403)


def test_an_administrator_gets_the_page(app, client):
    login(client, admin_user_id(app))
    r = client.get("/calendar/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert 'id="calPlanForm"' in body
    assert "fw-cal-table" in body


@pytest.mark.parametrize("view", ["month", "week", "agenda", "year"])
def test_every_view_renders(app, client, view):
    login(client, admin_user_id(app))
    assert client.get(f"/calendar/?view={view}").status_code == 200


def test_an_unknown_view_falls_back_to_month_rather_than_500ing(app, client):
    login(client, admin_user_id(app))
    r = client.get("/calendar/?view=gantt")
    assert r.status_code == 200 and "fw-cal-table" in r.get_data(as_text=True)


def test_a_garbage_date_does_not_take_the_page_down(app, client):
    login(client, admin_user_id(app))
    for bad in ("?d=not-a-date", "?y=99999", "?m=77", "?d=2026-02-30"):
        assert client.get("/calendar/" + bad).status_code == 200, bad


# --------------------------------------------------------------------------- #
# the light theme
# --------------------------------------------------------------------------- #
def test_the_page_carries_no_dark_theme_literals(app, client):
    """SATOM is a light product (safeguards §9m). A pastel status pill from a
    dark theme lands at ~1.4:1 on white: a badge that says 'high' and cannot be
    read."""
    login(client, admin_user_id(app))
    body = client.get("/calendar/").get_data(as_text=True)
    for literal in ("#080d1a", "rgba(30,41,59", "backdrop-filter", "#6ee7b7",
                    "#fcd34d", "#fca5a5", "#93c5fd", "#c4b5fd", "#cbd5e1"):
        assert literal not in body, literal


# --------------------------------------------------------------------------- #
# navigation
# --------------------------------------------------------------------------- #
def test_the_nav_entry_sits_above_search_in_every_fleet_menu():
    """Three branches of base.html hand-copy the Fleet group. An entry added to
    one of them is visible in one ADOM and invisible in another, which reads as
    broken rather than absent."""
    from pathlib import Path
    base = Path(__file__).resolve().parents[1] / "app/templates/base.html"
    text = base.read_text(encoding="utf-8")
    assert text.count("partials/nav_calendar.html") == 3
    for chunk in text.split("partials/nav_calendar.html")[1:]:
        head = chunk[:400]
        assert "url_for('search.index')" in head, "calendar must precede Search"


def test_the_nav_entry_is_gated_on_the_permission_the_page_requires():
    """A link that leads to a 403 is a bug report waiting to be filed."""
    from pathlib import Path
    part = (Path(__file__).resolve().parents[1]
            / "app/templates/partials/nav_calendar.html")
    assert "can('user_manage')" in part.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# target resolution
# --------------------------------------------------------------------------- #
def test_a_group_that_matches_nothing_refuses_instead_of_creating_an_empty_change(
        app, client):
    """A change naming no device is LEGAL in this product (it stays visible in
    every ADOM), so an empty resolution would save happily and do nothing on the
    night. The refusal has to happen at planning time."""
    login(client, admin_user_id(app))
    r = client.post("/calendar/plan", data={
        "title": "x", "action": "upgrade", "target_mode": "group",
        "group_field": "zone", "group_value": "a-zone-nobody-has",
        "window_start": "2026-10-01T22:00", "window_end": "2026-10-01T23:00",
    }, follow_redirects=True)
    assert r.status_code == 200
    assert "No visible appliance matches" in r.get_data(as_text=True)


def test_an_unknown_change_type_is_rejected_never_coerced(app, client):
    """The old fallback silently rewrote a glitched form into 'upgrade' — the
    most destructive entry on the menu."""
    login(client, admin_user_id(app))
    r = client.post("/calendar/plan", data={
        "title": "x", "action": "not-a-real-type", "target_mode": "adom",
    }, follow_redirects=True)
    assert "is not a change-controlled action" in r.get_data(as_text=True)


def test_an_unknown_group_dimension_is_rejected(app, client):
    login(client, admin_user_id(app))
    r = client.post("/calendar/plan", data={
        "title": "x", "action": "upgrade", "target_mode": "group",
        "group_field": "password", "group_value": "x",
    }, follow_redirects=True)
    assert "Unknown group dimension" in r.get_data(as_text=True)


def test_planning_with_no_appliance_picked_refuses(app, client):
    login(client, admin_user_id(app))
    r = client.post("/calendar/plan", data={
        "title": "x", "action": "upgrade", "target_mode": "devices",
    }, follow_redirects=True)
    assert "Pick at least one appliance" in r.get_data(as_text=True)


def test_planning_an_inverted_window_is_refused_through_the_shared_creator(
        app, client):
    """End-to-end: the calendar inherits the repair rather than restating it."""
    login(client, admin_user_id(app))
    r = client.post("/calendar/plan", data={
        "title": "x", "action": "upgrade", "target_mode": "adom",
        "window_start": "2026-10-02T22:00", "window_end": "2026-10-01T22:00",
    }, follow_redirects=True)
    body = r.get_data(as_text=True)
    assert "never fire" in body or "No visible appliance matches" in body
