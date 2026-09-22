"""Guards for the Integrations page's reconciliation card.

The card does ONE thing that needs protecting: it turns a number and a cadence
into a real :class:`ScheduledAction` — the same row the Automation page edits
and the calendar draws — and then TELLS the operator it did. Every guard here
is about that sentence being true:

* a DISABLED row is saved but neither run nor drawn, so it must not be
  reported as "on the calendar". A confirmation that overstates is worse than
  none: it is the operator's reason not to go and look;
* saving twice must UPDATE the one task, never grow a second one that fights
  the first over the same device map;
* a schedule the form could not parse must be corrected OUT LOUD — a silently
  dropped time is a task that never fires and never says so;
* the page is USER_MANAGE only, on the route as well as in the menu.

Plus the executor contract: an integration that could not be asked is a FAILED
run, never a green one.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import admin_user_id, login, make_user, profile_id
from app.services import scheduled_actions as sa

URL = "/settings/integrations/netbox/schedule"
PAGE = "/settings/integrations/"
PO = Path(__file__).resolve().parent.parent / "app/translations/es/LC_MESSAGES/messages.po"


def _rows(app):
    from app.models import ScheduledAction
    with app.app_context():
        return ScheduledAction.query.filter_by(action="netbox_reconcile").all()


def _one(app):
    rows = _rows(app)
    assert len(rows) == 1, "expected exactly one task, got %d" % len(rows)
    return rows[0]


# ── the catalog entry ───────────────────────────────────────────────────────

def test_the_action_is_in_the_admin_catalog_and_targets_nothing():
    spec = sa.get_spec("netbox_reconcile")
    assert spec is not None
    assert spec.scope == "admin"
    assert spec.needs_targets is False      # fleet-wide: it reads the map, not a box
    assert spec.danger is False
    assert not spec.requires_change_request


def test_the_executor_passes_the_round_size_through(monkeypatch):
    seen = {}

    def fake(*, per_round, dry_run=False):
        seen.update(per_round=per_round, dry_run=dry_run)
        return {"checked": True, "error": "", "per_round": per_round, "fleet": 9,
                "pending": 9, "scanned": 3, "mapped": ["a", "b", "c"],
                "unresolved": [], "unknown": [], "remaining": 6,
                "dry_run": dry_run, "log": ""}

    from app.services import netbox_client as nb
    monkeypatch.setattr(nb, "reconcile", fake)
    out = sa.run_action(sa.get_spec("netbox_reconcile"), None, {"per_round": 3})
    assert seen["per_round"] == 3           # the operator's number, not a default
    assert out["ok"] is True
    assert "6 still unmapped" in out["summary"]


def test_an_integration_that_could_not_be_asked_is_a_failed_run(monkeypatch):
    from app.services import netbox_client as nb
    monkeypatch.setattr(nb, "reconcile", lambda **kw: {
        "checked": False, "error": "NetBox integration is disabled.",
        "per_round": 25, "fleet": 4, "pending": 4, "scanned": 4, "mapped": [],
        "unresolved": [], "unknown": ["fw1"], "remaining": 0,
        "dry_run": False, "log": ""})
    out = sa.run_action(sa.get_spec("netbox_reconcile"), None, {})
    assert out["ok"] is False               # never a green sweep on a dead link
    assert "disabled" in out["summary"]


def test_what_netbox_does_not_document_is_named_in_the_summary(monkeypatch):
    from app.services import netbox_client as nb
    monkeypatch.setattr(nb, "reconcile", lambda **kw: {
        "checked": True, "error": "", "per_round": 25, "fleet": 2, "pending": 2,
        "scanned": 2, "mapped": [], "unresolved": ["fortiweb17"], "unknown": [],
        "remaining": 0, "dry_run": False, "log": ""})
    out = sa.run_action(sa.get_spec("netbox_reconcile"), None, {})
    assert out["ok"] is True                # somebody else's inventory, not a fault
    assert "fortiweb17" in out["summary"]   # by NAME, never as a count


# ── the card ────────────────────────────────────────────────────────────────

def test_the_card_is_on_the_page_and_says_it_is_not_scheduled_yet(app, client):
    login(client, admin_user_id(app))
    body = client.get(PAGE).get_data(as_text=True)
    assert "Scheduled reconciliation" in body
    assert 'name="per_round"' in body
    assert "not scheduled" in body
    assert 'action="%s"' % URL in body


def test_saving_creates_the_task_and_says_so(app, client):
    login(client, admin_user_id(app))
    body = client.post(URL, data={"name": "NetBox inventory reconcile",
                                  "per_round": "4", "schedule_kind": "daily",
                                  "daily_time": "03:30", "enabled": "on"},
                       follow_redirects=True).get_data(as_text=True)
    row = _one(app)
    assert row.params_dict["per_round"] == 4
    assert row.schedule_dict["time"] == "03:30"
    assert row.schedule_kind == "daily"
    assert row.enabled is True
    assert row.next_run is not None         # a task with no next fire is not scheduled
    assert json.loads(row.targets) == []
    assert "added to Scheduled Actions and is on the calendar" in body


def test_saving_twice_updates_the_one_task(app, client):
    login(client, admin_user_id(app))
    data = {"per_round": "4", "schedule_kind": "daily", "daily_time": "03:30",
            "enabled": "on"}
    # follow_redirects on BOTH: an unconsumed flash from the first save would
    # still be queued in the session and render on the second page, which is
    # what made the 'has been added' assertion below pass for the wrong reason.
    client.post(URL, data=data, follow_redirects=True)
    body = client.post(URL, data={**data, "per_round": "9"},
                       follow_redirects=True).get_data(as_text=True)
    row = _one(app)                          # ONE row, not two
    assert row.params_dict["per_round"] == 9
    assert "was updated in Scheduled Actions" in body
    assert "has been added" not in body


def test_a_disabled_save_is_not_reported_as_on_the_calendar(app, client):
    login(client, admin_user_id(app))
    body = client.post(URL, data={"per_round": "4", "schedule_kind": "daily",
                                  "daily_time": "03:30"},
                       follow_redirects=True).get_data(as_text=True)
    row = _one(app)
    assert row.enabled is False
    assert "is not drawn on the calendar" in body
    assert "is on the calendar" not in body


def test_an_unparsable_time_is_corrected_out_loud(app, client):
    login(client, admin_user_id(app))
    body = client.post(URL, data={"per_round": "4", "schedule_kind": "daily",
                                  "daily_time": "9pm", "enabled": "on"},
                       follow_redirects=True).get_data(as_text=True)
    assert _one(app).schedule_dict["time"] == "03:00"
    assert "is not a HH:MM time" in body     # corrected, and SAID


def test_the_round_size_is_clamped_and_an_interval_survives(app, client):
    login(client, admin_user_id(app))
    client.post(URL, data={"per_round": "10000000", "schedule_kind": "interval",
                           "interval_every": "2", "interval_unit": "hours",
                           "enabled": "on"})
    row = _one(app)
    from app.services import netbox_client as nb
    assert row.params_dict["per_round"] == nb.MAX_PER_ROUND
    assert row.schedule_kind == "interval"
    assert row.schedule_dict == {"every": 2, "unit": "hours"}


def test_a_bogus_unit_falls_back_rather_than_reaching_the_scheduler(app, client):
    login(client, admin_user_id(app))
    client.post(URL, data={"per_round": "4", "schedule_kind": "interval",
                           "interval_every": "3", "interval_unit": "fortnights",
                           "enabled": "on"})
    assert _one(app).schedule_dict["unit"] == "hours"


def test_the_route_is_user_manage_only(app, client):
    bob = make_user(app, username="bob", role="readonly",
                    profile_id=profile_id(app, "readonly"))
    login(client, bob)
    assert client.post(URL, data={"per_round": "4"}).status_code == 403
    assert _rows(app) == []                  # and nothing was written


# ── the sentence itself ─────────────────────────────────────────────────────

def test_the_confirmation_exists_in_spanish(app):
    """The operator asked for this sentence in Spanish. An English fallback
    would technically 'work' and would not be the thing that was asked for."""
    from babel.messages.pofile import read_po
    with PO.open(encoding="utf-8") as fh:
        cat = read_po(fh, locale="es")
    for msgid, must in (
        ("The task “%(name)s” has been added to Scheduled Actions and is on the "
         "calendar.", "se ha agregado a las acciones programadas"),
        ("The task “%(name)s” was saved, but it is DISABLED: it will not run and "
         "it is not drawn on the calendar.", "no se dibuja en el calendario"),
        ("Virtual machines per round", "Máquinas virtuales por ronda"),
    ):
        msg = cat.get(msgid)
        assert msg is not None, "not in the es catalogue: %r" % msgid
        assert must in msg.string
