"""Guards for the per-user Calendar switch and the day panel.

Two features, one page.

THE SWITCH is a preference, not a permission. It hides a VIEW for one operator
and must never be read as "the fleet stopped" — the changes on that grid keep
being approved and the automations keep firing. Half of these tests defend that
sentence, because it is the one an operator can get wrong at 03:00.

THE DAY PANEL is one macro rendered three times (side card, hidden pre-render,
modal). The tests defend that it stays ONE: the defect this codebase has paid
for repeatedly is two renderings of the same thing, neither of which fails —
they simply drift, and the one nobody looks at goes stale.
"""
from __future__ import annotations

import io
import os
import re
from datetime import date, datetime, timedelta

import pytest

from conftest import admin_user_id, login, make_user

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TPL = os.path.join(ROOT, "app", "templates", "calendar", "index.html")
NAV = os.path.join(ROOT, "app", "templates", "partials", "nav_calendar.html")


def _read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def _code(text):
    """Source with its COMMENTS removed.

    Every comment in these files explains the rule the guard below checks, in
    the words the guard greps for. Asserting against raw source is asserting
    that the explanation exists — this repo has shipped that mistake more than
    once, and the guard passes forever while the code says the opposite.
    """
    text = re.sub(r"\{#.*?#\}", " ", text, flags=re.S)     # jinja
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)     # css / js block
    text = re.sub(r"^\s*//.*$", " ", text, flags=re.M)     # js line
    return text


# --------------------------------------------------------------------------- #
# the preference: the DIRECTION of the stored value is the default
# --------------------------------------------------------------------------- #
def test_a_user_who_never_answered_has_the_calendar_on(app):
    from app.services import user_settings_store as store
    with app.app_context():
        assert store.calendar_enabled(admin_user_id(app)) is True


def test_the_row_records_the_deviation_so_a_missing_row_means_on(app):
    """The key means "switched OFF". A key meaning "on" would read absent ->
    false for every user who never opened their profile, and the feature would
    vanish for the whole install the day this shipped."""
    from app.models import UserSetting
    from app.services import user_settings_store as store
    with app.app_context():
        uid = admin_user_id(app)
        assert store.save_calendar_enabled(uid, False) is False
        assert UserSetting.get(uid, store.K_CALENDAR_OFF) == "1"
        assert store.calendar_enabled(uid) is False

        assert store.save_calendar_enabled(uid, True) is True
        assert UserSetting.get(uid, store.K_CALENDAR_OFF) == "0"
        assert store.calendar_enabled(uid) is True


def test_switching_it_off_touches_nobody_else(app):
    from app.services import user_settings_store as store
    with app.app_context():
        mine = admin_user_id(app)
        theirs = make_user(app, username="colleague", role="readonly")
        store.save_calendar_enabled(mine, False)
        assert store.calendar_enabled(mine) is False
        assert store.calendar_enabled(theirs) is True


def test_a_broken_preference_leaves_the_calendar_visible(app, monkeypatch):
    """Degrade to ON. Hiding a page nobody asked to hide is the worse failure:
    it looks like the feature was removed, and the switch that would bring it
    back is the thing that is broken."""
    from app.models import UserSetting
    from app.services import user_settings_store as store
    with app.app_context():
        def boom(*a, **k):
            raise RuntimeError("no such table: user_settings")
        monkeypatch.setattr(UserSetting, "get", boom)
        assert store.calendar_enabled(admin_user_id(app)) is True


# --------------------------------------------------------------------------- #
# the route that writes it
# --------------------------------------------------------------------------- #
def test_an_absent_checkbox_is_off_not_ignored(app, client):
    """An unchecked checkbox SENDS NOTHING. Reading the value and comparing it
    against 'on'/'1' makes the OFF direction unreachable from a real browser —
    which is the half of this switch the user asked for."""
    from app.services import user_settings_store as store
    uid = admin_user_id(app)
    login(client, uid)
    r = client.post("/auth/profile/calendar", data={}, follow_redirects=False)
    assert r.status_code in (302, 303)
    with app.app_context():
        assert store.calendar_enabled(uid) is False


def test_a_checked_checkbox_switches_it_back_on(app, client):
    from app.services import user_settings_store as store
    uid = admin_user_id(app)
    with app.app_context():
        store.save_calendar_enabled(uid, False)
    login(client, uid)
    client.post("/auth/profile/calendar", data={"calendar_on": "1"})
    with app.app_context():
        assert store.calendar_enabled(uid) is True


def test_hiding_the_calendar_stops_nothing_that_was_scheduled(app, client):
    """The sentence the whole feature has to keep true. An operator can read
    "disable the calendar" as "stop the scheduled work"; the switch must not
    make that reading correct."""
    from app.models import ScheduledAction, db
    from app.views.change_requests import create_change_request

    uid = admin_user_id(app)
    with app.app_context():
        act = ScheduledAction(name="nightly-sweep", action="metrics_scrape",
                              enabled=True)
        db.session.add(act)
        db.session.commit()
        aid = act.id
    with app.test_request_context():
        cr, err = create_change_request({
            "title": "planned", "action": "upgrade", "device_ids": [],
            "window_start": datetime(2030, 5, 1, 22, 0),
            "window_end": datetime(2030, 5, 1, 23, 59),
        })
        assert err == "" and cr is not None
        cid, cstatus = cr.id, cr.status

    login(client, uid)
    client.post("/auth/profile/calendar", data={})

    from app.models import ChangeRequest
    with app.app_context():
        assert ScheduledAction.query.get(aid).enabled is True
        kept = ChangeRequest.query.get(cid)
        assert kept is not None and kept.status == cstatus
        assert kept.window_start == datetime(2030, 5, 1, 22, 0)


# --------------------------------------------------------------------------- #
# what the switch does to the chrome and the page
# --------------------------------------------------------------------------- #
def test_the_nav_entry_follows_the_preference(app, client):
    from app.services import user_settings_store as store
    uid = admin_user_id(app)
    login(client, uid)
    assert 'href="/calendar/"' in client.get("/auth/profile").get_data(as_text=True)
    with app.app_context():
        store.save_calendar_enabled(uid, False)
    assert 'href="/calendar/"' not in client.get("/auth/profile").get_data(as_text=True)


def test_the_nav_entry_survives_a_context_without_the_processor():
    """``|default(true)``. A template rendered outside a full request context
    has no ``calendar_on``, and an undefined in a boolean test is falsey — the
    entry would vanish for a reason that has nothing to do with the user."""
    assert "calendar_on|default(true)" in _code(_read(NAV))


def test_a_switched_off_calendar_answers_with_the_switch_not_a_refusal(app, client):
    """They hold the permission; they hid it. A 403 would be a lie, and a
    refusal that does not name the remedy is a dead end for anybody arriving
    from a bookmark."""
    from app.services import user_settings_store as store
    uid = admin_user_id(app)
    with app.app_context():
        store.save_calendar_enabled(uid, False)
    login(client, uid)
    r = client.get("/calendar/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "/auth/profile/calendar" in body        # the switch is ON the page
    assert 'href="/auth/profile#calendar"' in body  # and so is the way to it
    assert "fw-cal-table" not in body               # the grid is not drawn


def test_the_switched_off_page_says_the_fleet_was_not_paused(app, client):
    from app.services import user_settings_store as store
    uid = admin_user_id(app)
    with app.app_context():
        store.save_calendar_enabled(uid, False)
    login(client, uid)
    body = client.get("/calendar/").get_data(as_text=True).lower()
    assert "still run" in body or "keep running" in body


def test_the_switched_off_page_carries_no_dark_theme_literals(app, client):
    """SATOM is a light product (safeguards §9m). A pastel from a dark theme
    lands at ~1.4:1 on white."""
    from app.services import user_settings_store as store
    uid = admin_user_id(app)
    with app.app_context():
        store.save_calendar_enabled(uid, False)
    login(client, uid)
    page = _read(os.path.join(ROOT, "app", "templates", "calendar", "off.html"))
    for bad in ("#080d1a", "rgba(30,41,59", "backdrop-filter", "#6ee7b7",
                "#fcd34d", "#fca5a5"):
        assert bad not in page


def test_planning_while_switched_off_is_refused_and_creates_nothing(app, client):
    from app.models import ChangeRequest
    from app.services import user_settings_store as store
    uid = admin_user_id(app)
    with app.app_context():
        store.save_calendar_enabled(uid, False)
        before = ChangeRequest.query.count()
    login(client, uid)
    r = client.post("/calendar/plan", data={
        "title": "smuggled", "action": "upgrade", "target_mode": "adom",
        "window_start": "2030-05-01T22:00", "window_end": "2030-05-01T23:59",
    })
    assert r.status_code in (302, 303)
    # WHERE it lands is the assertion. A fixture with no appliances refuses
    # this same post for a completely different reason ("no visible appliance
    # matches") and lands back on the calendar, so counting change requests
    # cannot tell the switch from an empty inventory -- and a guard that
    # passes with the switch removed is not a guard.
    assert "/auth/profile" in (r.headers.get("Location") or "")
    with app.app_context():
        assert ChangeRequest.query.count() == before
        assert ChangeRequest.query.filter_by(title="smuggled").first() is None


# --------------------------------------------------------------------------- #
# a day is ALWAYS selected
# --------------------------------------------------------------------------- #
def _selected_day(body):
    m = re.search(r'id="calDayBody" data-day="(\d{4}-\d\d-\d\d)"', body)
    return m.group(1) if m else None


def test_a_day_is_selected_without_being_asked_for(app, client):
    login(client, admin_user_id(app))
    body = client.get("/calendar/").get_data(as_text=True)
    assert _selected_day(body) == date.today().isoformat()


def test_an_explicit_day_still_wins(app, client):
    login(client, admin_user_id(app))
    body = client.get("/calendar/?d=2030-05-17").get_data(as_text=True)
    assert _selected_day(body) == "2030-05-17"


def test_an_explicit_day_wins_inside_the_month_that_holds_today(app, client):
    """The 2030 case above cannot see this: with today outside that range the
    default resolves to the anchor, which IS the requested day, so a mutation
    that ignores ``?d=`` entirely still produces the right answer. The day has
    to be one the default would overrule -- a day in the month on screen,
    while today is in it too."""
    today = date.today()
    other = today.replace(day=2) if today.day != 2 else today.replace(day=3)
    login(client, admin_user_id(app))
    body = client.get("/calendar/?d=" + other.isoformat()).get_data(as_text=True)
    assert _selected_day(body) == other.isoformat()


def test_the_default_day_is_the_anchor_not_the_grids_padding(app, client):
    """A month view is padded to whole weeks, so ``day_from`` can belong to the
    PREVIOUS month. Defaulting there pre-fills the planner with a window
    outside the month on screen."""
    login(client, admin_user_id(app))
    body = client.get("/calendar/?y=2030&m=5").get_data(as_text=True)
    assert _selected_day(body) == "2030-05-01"


def test_every_cell_says_which_day_it_picks(app, client):
    login(client, admin_user_id(app))
    body = client.get("/calendar/").get_data(as_text=True)
    # A padded month is 28..42 cells; fewer than 28 means the attribute is not
    # on the cell macro at all.
    assert len(re.findall(r'<td class="fw-cal-cell[^>]*data-day="', body)) >= 28


def test_the_selected_days_panel_is_always_pre_rendered(app, client):
    """The fallback for an un-pre-rendered day is a page load whose selected
    day IS that day. If the selected day could be budgeted out, that fallback
    would arrive and find it missing again — the panel would never open."""
    login(client, admin_user_id(app))
    body = client.get("/calendar/?d=2030-05-17").get_data(as_text=True)
    assert 'data-cal-panel="2030-05-17"' in body


def test_the_selected_day_is_kept_even_when_the_budget_is_already_blown(app):
    from app.views.calendar import MAX_PANEL_EVENTS, _panel_days
    sel = date(2030, 5, 17)
    buckets = {sel: ["x"] * (MAX_PANEL_EVENTS + 50)}
    assert _panel_days(buckets, sel, date(2030, 5, 1), date(2030, 5, 31)) == [sel]


def test_one_crowded_day_does_not_starve_the_quiet_days_after_it(app):
    """``continue``, not ``break``. A Tuesday with four hundred runs must not
    cost every other day in the month its panel."""
    from app.views.calendar import MAX_PANEL_EVENTS, _panel_days
    crowded, quiet = date(2030, 5, 2), date(2030, 5, 3)
    buckets = {crowded: ["x"] * (MAX_PANEL_EVENTS + 1), quiet: ["y"]}
    out = _panel_days(buckets, date(2030, 5, 1), date(2030, 5, 1), date(2030, 5, 31))
    assert quiet in out and crowded not in out


def test_a_day_outside_the_drawn_range_is_not_pre_rendered(app):
    from app.views.calendar import _panel_days
    inside, outside = date(2030, 5, 10), date(2030, 6, 10)
    buckets = {inside: ["a"], outside: ["b"]}
    out = _panel_days(buckets, date(2030, 5, 1), date(2030, 5, 1), date(2030, 5, 31))
    assert inside in out and outside not in out


# --------------------------------------------------------------------------- #
# ONE macro, three renderings
# --------------------------------------------------------------------------- #
def test_the_side_card_and_the_pre_rendered_days_both_call_the_one_macro():
    src = _code(_read(TPL))
    assert src.count("{% macro daypanel(") == 1
    assert "{{ daypanel(selected_events) }}" in src
    assert "{{ daypanel(buckets.get(d, [])) }}" in src


def test_the_modal_is_filled_from_the_side_card_not_rendered_again():
    """The modal is the day panel without the compact CSS. A second rendering
    would be a second thing to keep true."""
    src = _code(_read(TPL))
    assert "mBody.innerHTML = body.innerHTML;" in src


def test_compact_and_full_differ_by_css_only(app, client):
    """Both halves are in the markup on every render; a class on the container
    picks which one is shown. Branching in the macro would put the modal's
    content on a code path the side card never exercises."""
    src = _code(_read(TPL))
    assert ".fw-cal-clip .fw-cal-more-only { display:none; }" in src
    assert ".fw-cal-full .fw-cal-brief-only { display:none; }" in src
    login(client, admin_user_id(app))
    body = client.get("/calendar/").get_data(as_text=True)
    assert 'class="fw-card-body p-0 fw-cal-clip"' in body
    assert 'class="modal-body p-0 fw-cal-full"' in body


def test_a_window_that_can_never_open_is_in_neither_visibility_set():
    """A warning hidden behind "expand for more" is a warning nobody reads.
    The clipped-span line carries neither class, so both containers show it."""
    src = _code(_read(TPL))
    i = src.index("{% macro daypanel(")
    j = src.index("{%- endmacro %}", i)
    line = [ln for ln in src[i:j].splitlines() if "ev.span_clipped" in ln]
    assert len(line) == 1
    assert "fw-cal-more-only" not in line[0] and "fw-cal-brief-only" not in line[0]


# --------------------------------------------------------------------------- #
# picking a day
# --------------------------------------------------------------------------- #
def _pick_js(src):
    i = src.index("function reanchor(")
    return src[i:src.index("function pick(", i)]


def test_picking_a_day_moves_the_planner_date_and_keeps_the_typed_time():
    """The date half is re-anchored; the time half is whatever the operator
    typed. Overwriting the time discards a deliberate edit; leaving the date
    alone plans a maintenance window on a night nobody is watching."""
    body = _pick_js(_code(_read(TPL)))
    assert "'T'" in body and "parts[1]" in body
    assert "iso + 'T' +" in body
    # A literal default is the FALLBACK for an empty field, never the value
    # written over a filled one.
    assert "defs[i]" in body


def test_the_planner_back_link_follows_the_picked_day():
    """Otherwise a refused plan bounces the operator back to the day they were
    on before they picked."""
    assert 'back.value = href(iso);' in _code(_read(TPL))


def test_a_chip_link_is_not_swallowed_by_the_day_picker():
    """Chips link to the change itself. Only the day number and the "+n more"
    line carry data-cal-pick, and an anchor without it is left alone."""
    src = _code(_read(TPL))
    i = src.index("table.addEventListener('click'")
    window = src[i:i + 700]
    assert "if (!iso) { return; }" in window


def test_an_unrenderable_day_falls_back_to_its_own_link(app):
    """The bound is on how many panels the page CARRIES, never on which days
    can be opened."""
    src = _code(_read(TPL))
    i = src.index("function pick(")
    window = src[i:src.index("if (table)", i)]
    assert "if (!node) { window.location = href(iso); return; }" in window


def test_the_day_number_link_still_works_without_javascript(app, client):
    """The picker is an enhancement. The href stays, so the page degrades to a
    page load rather than to a grid that does nothing."""
    login(client, admin_user_id(app))
    body = client.get("/calendar/").get_data(as_text=True)
    m = re.search(r'<a class="fw-cal-daynum" data-cal-pick="(\d{4}-\d\d-\d\d)" href="([^"]+)"', body)
    assert m is not None
    assert ("d=" + m.group(1)) in m.group(2).replace("&amp;", "&")


def test_the_new_style_and_script_carry_the_csp_nonce(app, client):
    """style-src-elem names a nonce, so an unmarked <style> renders the page
    unstyled and an unmarked <script> never runs."""
    login(client, admin_user_id(app))
    body = client.get("/calendar/").get_data(as_text=True)
    for tag in re.findall(r"<(?:style|script)(?![^>]*\bsrc=)[^>]*>", body):
        assert "nonce=" in tag, tag


def test_a_broken_preference_still_draws_the_menu_entry(app, client, monkeypatch):
    """The context processor degrades to ON as well. It is a separate fallback
    from the store's: a store that answers fine but a processor that raises for
    another reason (no request context, a half-initialised extension) would
    otherwise hide the entry from every page in the product at once."""
    from app.services import user_settings_store as store
    login(client, admin_user_id(app))

    def boom(*a, **k):
        raise RuntimeError("preference unavailable")
    monkeypatch.setattr(store, "calendar_enabled", boom)
    assert 'href="/calendar/"' in client.get("/auth/profile").get_data(as_text=True)


def test_a_broken_preference_still_opens_the_page(app, client, monkeypatch):
    """Same direction on the view side. A preference that cannot be read must
    not become a page that cannot be opened."""
    from app.services import user_settings_store as store
    login(client, admin_user_id(app))

    def boom(*a, **k):
        raise RuntimeError("preference unavailable")
    monkeypatch.setattr(store, "calendar_enabled", boom)
    r = client.get("/calendar/")
    assert r.status_code == 200 and "fw-cal-table" in r.get_data(as_text=True)
