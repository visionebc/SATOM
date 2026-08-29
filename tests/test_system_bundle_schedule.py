"""The system bundle had a destination and no visible cadence.

Why this file exists
--------------------
"System bundles path" told an operator WHERE this node's own backups land and
nothing about WHEN they are written — and the hour was reachable only from the
Automation list, under an action name, three pages away from the folder it
fills. Nothing failed: the job ran nightly and the page rendered. The pane was
simply silent about the half of the fact that decides whether an empty folder
is a problem.

The knob writes the ``system_backup`` SCHEDULE ROW, not a settings key of its
own, for the same reason the SoT cadence does: an hour with two authors is a
page that prints 01:30 over a node backing up at 03:00, with neither of them
wrong about itself.

Two things here are load-bearing and neither is visible in a render:

1. **``next_run`` is recomputed, in the configured timezone.** ``daily`` is a
   wall-clock kind. Computed in UTC, "01:30" typed on a Europe/Zurich console
   fires at 03:30 local in summer — and the Automation page, which does pass
   the zone, would disagree with this one about the same row. The guard pins a
   DST-free zone with a known offset so the conversion is an exact number, not
   a "something changed".
2. **A bundle already scheduled some other way is refused, not converted.**
   ``save_sot_refresh`` adds a row in that situation because two harvests cost
   device calls; two system backups cost a full bundle each — 578 MB apiece on
   a node with 9 GB free.

Assertions are scoped to the FORM that owns the field, never to the pane and
never to the page: this pane already contains three path inputs, a Test button
and the word "backup" in every other sentence, and a whole-page search is how a
guard ends up answered by something else.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from tests.conftest import admin_user_id, login

ROOT = pathlib.Path(__file__).resolve().parents[1]
STORE_PY = ROOT / "app/services/settings_store.py"
ENDPOINT = "/settings/backup-server/schedule"
PANE_OPEN = 'class="tab-pane'


@pytest.fixture()
def admin(client, app):
    login(client, admin_user_id(app))
    return client


def _pane(html, target):
    marker = '<div class="tab-pane fade" id="%s">' % target
    assert marker in html, "pane %s is not rendered" % target
    body = html.split(marker, 1)[1]
    nxt = body.find(PANE_OPEN)
    return body[:nxt] if nxt > 0 else body


def _schedule_form(client):
    """The form that OWNS the hour field — not the pane, not the page."""
    pane = _pane(client.get("/settings/").get_data(as_text=True), "tab-backupsrv")
    assert ENDPOINT in pane, "the bundle schedule form is not on the Backup Server pane"
    body = pane.split(ENDPOINT, 1)[1]
    end = body.find("</form>")
    assert end > 0, "the schedule form is never closed"
    return body[:end]


def _hour_input(form):
    """The <input> tag itself.

    Sixteenth assertion in this repo that was answered by something else: the
    guard below looked for 'disabled' in the whole form, and the SUBMIT BUTTON
    carries that attribute too — so re-enabling the field survived.  An
    attribute assertion belongs on the tag that is supposed to carry it.
    """
    at = form.find('name="bundle_time"')
    assert at > 0, "no bundle hour field in this form"
    start = form.rfind("<input", 0, at)
    end = form.find(">", at)
    assert start >= 0 and end > start
    return form[start:end + 1]


def _submit_button(form):
    at = form.find('<button type="submit"')
    assert at > 0, "the schedule form has no submit button"
    return form[at:form.find("</button>", at)]


# ── 1. the hour is on the pane that owns the destination ────────────────────

def test_the_pane_offers_an_hour_for_the_bundle(admin):
    form = _schedule_form(admin)
    assert 'name="bundle_time"' in form, "no bundle hour on the Backup Server pane"
    assert 'type="time"' in form, "the hour is not entered as a time"


def test_the_hour_posts_to_its_own_endpoint(admin):
    """Sharing the SFTP form's action would make saving an hour rewrite creds."""
    pane = _pane(admin.get("/settings/").get_data(as_text=True), "tab-backupsrv")
    assert pane.count('name="bundle_time"') == 1
    assert '<form method="post" action="%s">' % ENDPOINT in pane, \
        "the hour must have its own POST, like every other pane's control"


def test_the_hour_says_which_timezone_it_is_in(admin, monkeypatch):
    """"01:30" with no zone beside it is the ambiguity the scheduler already hit."""
    from app.services import settings_store as store
    monkeypatch.setattr(store, "tz_name", lambda: "Asia/Kolkata")
    form = _schedule_form(admin)
    assert "Asia/Kolkata" in form, "the field does not name the zone its hour is in"


def test_the_pane_still_explains_where_bundles_land(admin):
    """The cadence is added BESIDE the destination, it does not replace it."""
    pane = _pane(admin.get("/settings/").get_data(as_text=True), "tab-backupsrv")
    assert 'name="system_path"' in pane, "the system bundles path field is gone"


# ── 2. saving reaches the row that actually writes a bundle ─────────────────

def test_saving_writes_the_bundle_row_and_moves_the_next_run(admin, app):
    from app.extensions import db
    from app.models import ScheduledAction
    from app.services import settings_store as store

    with app.app_context():
        ScheduledAction.query.filter_by(action="system_backup").delete()
        row = ScheduledAction(name="t", scope="admin", product="fortiweb",
                              action="system_backup", targets="[]", params="{}",
                              schedule_kind="daily",
                              schedule=json.dumps({"time": "01:30"}), enabled=True)
        db.session.add(row)
        db.session.commit()
        rid, before = row.id, row.next_run

    admin.post(ENDPOINT, data={"bundle_time": "04:45"})

    with app.app_context():
        row = db.session.get(ScheduledAction, rid)
        assert row.schedule_kind == "daily"
        assert json.loads(row.schedule) == {"time": "04:45"}
        assert row.next_run is not None and row.next_run != before, \
            "an hour that does not move next_run is stored and inert"
        assert store.system_backup_schedule()["time"] == "04:45"


def test_the_next_run_is_computed_in_the_configured_zone(app, monkeypatch):
    """A wall-clock hour saved as UTC is a job that runs at the wrong time.

    Asia/Kolkata is +05:30 all year, so the answer is an exact number rather
    than "it changed": 01:30 there is 20:00 UTC, never 01:30 UTC.
    """
    from app.extensions import db
    from app.models import ScheduledAction
    from app.services import settings_store as store

    with app.app_context():
        ScheduledAction.query.filter_by(action="system_backup").delete()
        db.session.commit()
        monkeypatch.setattr(store, "tz_name", lambda: "Asia/Kolkata")
        res = store.save_system_backup_schedule("01:30")
        row = db.session.get(ScheduledAction, res["action_id"])
        assert row.next_run.strftime("%H:%M") == "20:00", (
            "next_run is %s — the hour was scheduled in UTC, so this node backs "
            "up 5h30 away from the time the page shows"
            % row.next_run.strftime("%H:%M"))


def test_a_node_with_no_bundle_schedule_gets_one(app):
    from app.extensions import db
    from app.models import ScheduledAction
    from app.services import settings_store as store
    with app.app_context():
        ScheduledAction.query.filter_by(action="system_backup").delete()
        db.session.commit()
        assert store.system_backup_schedule()["configured"] is False
        res = store.save_system_backup_schedule("02:15")
        assert res["created"] is True
        cfg = store.system_backup_schedule()
        assert cfg["configured"] is True and cfg["time"] == "02:15"


# ── 3. an unreadable submit must not move the backup ────────────────────────

@pytest.mark.parametrize("bad", ["", "   ", "nope", "99:99", "24:00", "-1:30", "3"])
def test_an_unreadable_hour_keeps_the_one_in_force(app, bad):
    from app.extensions import db
    from app.models import ScheduledAction
    from app.services import settings_store as store
    with app.app_context():
        ScheduledAction.query.filter_by(action="system_backup").delete()
        db.session.add(ScheduledAction(
            name="t", scope="admin", product="fortiweb", action="system_backup",
            targets="[]", params="{}", schedule_kind="daily",
            schedule=json.dumps({"time": "01:30"}), enabled=True))
        db.session.commit()
        assert store.save_system_backup_schedule(bad)["time"] == "01:30", \
            "a submit the parser cannot read moved the nightly backup"


def test_a_readable_hour_is_normalised_not_rejected(app):
    from app.extensions import db
    from app.models import ScheduledAction
    from app.services import settings_store as store
    with app.app_context():
        ScheduledAction.query.filter_by(action="system_backup").delete()
        db.session.commit()
        assert store.save_system_backup_schedule("3:05")["time"] == "03:05"


# ── 4. a bundle scheduled some other way is reported, never duplicated ──────

def test_a_weekly_bundle_is_reported_not_converted(app):
    from app.extensions import db
    from app.models import ScheduledAction
    from app.services import settings_store as store
    with app.app_context():
        ScheduledAction.query.filter_by(action="system_backup").delete()
        row = ScheduledAction(name="weekly", scope="admin", product="fortiweb",
                              action="system_backup", targets="[]", params="{}",
                              schedule_kind="weekly",
                              schedule=json.dumps({"weekday": 0, "time": "02:00"}),
                              enabled=True)
        db.session.add(row)
        db.session.commit()
        rid = row.id

        cfg = store.system_backup_schedule()
        assert cfg["configured"] is False, "a weekly row is not a daily one"
        assert cfg["other_kind"] == "weekly", "and must be reported, not hidden"

        res = store.save_system_backup_schedule("05:00")
        assert res["conflict"] is True, "the weekly bundle was silently taken over"

        kept = db.session.get(ScheduledAction, rid)
        assert kept.schedule_kind == "weekly"
        assert json.loads(kept.schedule) == {"weekday": 0, "time": "02:00"}
        assert ScheduledAction.query.filter_by(action="system_backup").count() == 1, \
            "a second nightly bundle was created behind the operator's back"


def test_the_pane_sends_that_operator_to_automation(admin, app, monkeypatch):
    from app.extensions import db
    from app.models import ScheduledAction
    with app.app_context():
        ScheduledAction.query.filter_by(action="system_backup").delete()
        db.session.add(ScheduledAction(
            name="weekly", scope="admin", product="fortiweb", action="system_backup",
            targets="[]", params="{}", schedule_kind="weekly",
            schedule=json.dumps({"weekday": 0, "time": "02:00"}), enabled=True))
        db.session.commit()
    form = _schedule_form(admin)
    assert "disabled" in _hour_input(form), \
        "the hour field is editable against a weekly bundle"
    assert "disabled" in _submit_button(form), \
        "the save button still offers to take the weekly bundle over"
    assert "weekly" in form, "the pane does not say what schedule is actually in force"


# ── 5. the hour has one author, and it is not this pane ─────────────────────

def test_the_hour_is_not_a_settings_key(app):
    """A key here would be a second author of the same number."""
    src = STORE_PY.read_text()
    assert '"system_backup.' not in src and "'system_backup." not in src, \
        "a settings key for the bundle hour is a second author of one number"

    from app.extensions import db
    from app.models import AppSetting
    from app.services import settings_store as store
    with app.app_context():
        before = AppSetting.query.count()
        store.save_system_backup_schedule("06:00")
        db.session.commit()
        assert AppSetting.query.count() == before, \
            "saving the hour wrote a settings row; the schedule row is the author"


def test_saving_the_hour_leaves_the_backup_credentials_alone(admin, app):
    from app.services import settings_store as store
    with app.app_context():
        store.save_backup_server({"host": "backup-server.example", "port": "22",
                                  "username": "fmbackup", "password": "s3cret",
                                  "config_path": "/configs",
                                  "firmware_path": "/firmware",
                                  "system_path": "/system"})
    admin.post(ENDPOINT, data={"bundle_time": "04:00"})
    with app.app_context():
        cfg = store.backup_server()
        assert cfg["host"] == "backup-server.example", \
            "saving an hour rewrote the SFTP destination"
        assert cfg["system_path"] == "/system"
