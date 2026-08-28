"""Three controls on the Settings panes that were saying the wrong thing.

Why this file exists
--------------------
None of the three defects below could fail a test that only asks "does the page
render?", because all three rendered:

1. **The repository form was always open.**  "Repository" and "Configure
   Repository" sat as two cards of equal weight, and the second one's three
   boxes render EMPTY until an async fetch fills them.  A submit before that
   fetch lands writes blanks over a working origin.  The form is the thing an
   operator needs in exactly one state — a node that was never given a remote —
   so the guards here assert the *default state*, in both directions, which is
   the only thing a render test can see and the only thing that was wrong.

2. **The SoT had no cadence control at all**, and the honest place to put one is
   not a new settings key: ``device_sync`` is what reads a device and mints a
   version, so a key of its own would be a SECOND author of one number.  The
   guards go through ``save_sot_refresh`` to the schedule row, and specifically
   through ``next_run`` — a cadence that is stored but does not move the next
   fire is a setting that looks saved and is inert, which is exactly how the
   retention knob failed for three weeks.

3. **Three backup paths side by side said nothing about what lands in each.**
   The distinction that matters is WHO writes: an empty config folder means the
   appliance is not pushing, not that SATOM failed.  Guards assert three
   distinct explanations, on the fields, not on the page.

Every assertion is scoped to the pane, and the git ones to the CARD inside it:
"Configure Repository" appears in a heading, and 'hidden' appears all over a
settings page.  A whole-page search is how a guard ends up answered by
something else — this repo has retired more than a dozen of those.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from tests.conftest import admin_user_id, login

ROOT = pathlib.Path(__file__).resolve().parents[1]
IDX = ROOT / "app/templates/settings/index.html"
PANE_OPEN = 'class="tab-pane'


def _page(client):
    return client.get("/settings/").get_data(as_text=True)


def _pane(html, target):
    marker = '<div class="tab-pane fade" id="%s">' % target
    assert marker in html, "pane %s is not rendered" % target
    body = html.split(marker, 1)[1]
    nxt = body.find(PANE_OPEN)
    return body[:nxt] if nxt > 0 else body


def _repo_card(pane):
    """The Repository card only — from its title to the next card's title.

    Scoping matters here more than anywhere: the words "Configure Repository"
    must appear INSIDE this card and nowhere else in the pane, and asserting
    that against the pane cannot tell the two apart.
    """
    open_at = pane.find("{}Repository".format(">"))
    marker = "bi-git me-2 text-accent"
    assert marker in pane, "the Repository card is not in this pane"
    body = pane.split(marker, 1)[1]
    nxt = body.find("bi-cloud-download me-2")   # the next card ("Update from Gitea")
    assert nxt > 0, "could not find the card that follows Repository"
    return body[:nxt]


@pytest.fixture()
def admin(client, app):
    login(client, admin_user_id(app))
    return client


# ── 1. the repository form is folded away unless there is nothing to lose ───

def test_the_form_lives_inside_the_repository_card(admin):
    card = _repo_card(_pane(_page(admin), "tab-git"))
    assert 'id="git-config-block"' in card, \
        "the configuration form must live inside the Repository card"
    assert 'id="gc-remote"' in card and 'data-js="git-configure"' in card, \
        "the form's own controls moved out of the card that now owns them"


def test_there_is_no_second_configure_card(admin):
    pane = _pane(_page(admin), "tab-git")
    # A card is a card because of fw-card-title; the form's heading is an <h6>.
    titles = pane.count('class="fw-card-title"')
    assert 'fw-card-title"><i class="bi bi-gear me-2 text-accent"></i>' not in pane, \
        "the standalone 'Configure Repository' card is back"
    assert titles == 4, \
        "expected 4 cards in the git pane (Repository, Pull, Commits, Console), got %d" % titles


def test_the_edit_button_controls_the_block(admin):
    card = _repo_card(_pane(_page(admin), "tab-git"))
    assert 'data-js="git-edit"' in card, "no Edit button on the Repository card"
    assert 'aria-controls="git-config-block"' in card, \
        "the Edit button must name the region it opens"


def test_a_configured_node_renders_the_form_closed(admin, monkeypatch):
    from app.services import git_service
    monkeypatch.setattr(git_service, "remote_configured", lambda: True)
    card = _repo_card(_pane(_page(admin), "tab-git"))
    block = card.split('id="git-config-block"', 1)[1].split(">", 1)[0]
    assert "hidden" in block, \
        "a node WITH a repository must not open the overwrite form by default"
    assert 'id="git-unconfigured"' not in card, \
        "a configured node must not be told it has no repository"


def test_a_fresh_node_renders_the_form_open(admin, monkeypatch):
    from app.services import git_service
    monkeypatch.setattr(git_service, "remote_configured", lambda: False)
    card = _repo_card(_pane(_page(admin), "tab-git"))
    block = card.split('id="git-config-block"', 1)[1].split(">", 1)[0]
    assert "hidden" not in block, \
        "a node with NO repository must show the form without hunting for Edit"
    assert 'id="git-unconfigured"' in card, "and must say why it is open"


def test_the_toggle_script_flips_that_exact_block():
    """The button is inert unless the script names the same id.

    Anchored on the function, never on the page: `git-config-block` also
    appears in the markup and in aria-controls, so a page-wide search stays
    green with the handler deleted.
    """
    src = IDX.read_text()
    assert "function gitToggleConfig()" in src, "the toggle is gone"
    fn = src.split("function gitToggleConfig()", 1)[1].split("\nfunction ", 1)[0]
    # The EXACT call, not the bare id: 'git-config-block' is a prefix of any
    # renamed id, so a substring assert stays green against a toggle pointing
    # at git-config-blockZZ — the fifteenth of these this repo has retired.
    assert "getElementById('git-config-block')" in fn, \
        "the toggle no longer opens the block it is wired to"
    assert "hidden" in fn, "the toggle no longer opens or closes anything"
    assert "onJs('git-edit', 'click'" in src, "the Edit button is not wired"


# ── 2. the SoT cadence, on the row that actually harvests ───────────────────

def test_the_pane_offers_a_cadence_with_a_default(admin):
    pane = _pane(_page(admin), "tab-sot")
    assert 'name="refresh_minutes"' in pane, "no refresh-frequency field on the SoT pane"
    assert "/settings/sot/refresh" in pane, \
        "the cadence must POST to its own endpoint, not the retention one"
    from app.services import settings_store as store
    assert str(store.SOT_REFRESH_DEFAULT_MINUTES) in pane, "the default is not shown"


def test_saving_writes_the_harvest_row_and_moves_the_next_run(admin, app):
    from app.extensions import db
    from app.models import ScheduledAction
    from app.services import settings_store as store

    with app.app_context():
        row = ScheduledAction(name="t", scope="admin", product="fortiweb",
                              action="device_sync", targets="[]", params="{}",
                              schedule_kind="interval",
                              schedule=json.dumps({"every": 60, "unit": "minutes"}),
                              enabled=True)
        db.session.add(row)
        db.session.commit()
        rid, before = row.id, row.next_run

    admin.post("/settings/sot/refresh", data={"refresh_minutes": "15"})

    with app.app_context():
        row = db.session.get(ScheduledAction, rid)
        assert json.loads(row.schedule) == {"every": 15, "unit": "minutes"}
        assert row.next_run is not None and row.next_run != before, \
            "a cadence that does not move next_run is stored and inert"
        assert store.sot_refresh()["minutes"] == 15


def test_a_zero_or_garbage_cadence_means_unset_not_never(admin, app):
    from app.services import settings_store as store
    with app.app_context():
        assert store.save_sot_refresh("0")["minutes"] == store.SOT_REFRESH_DEFAULT_MINUTES
        assert store.save_sot_refresh("")["minutes"] == store.SOT_REFRESH_DEFAULT_MINUTES
        assert store.save_sot_refresh("nope")["minutes"] == store.SOT_REFRESH_DEFAULT_MINUTES


def test_the_cadence_is_clamped_at_both_ends(admin, app):
    from app.services import settings_store as store
    with app.app_context():
        assert store.save_sot_refresh("1")["minutes"] == store.SOT_REFRESH_MIN_MINUTES
        assert store.save_sot_refresh("999999")["minutes"] == store.SOT_REFRESH_MAX_MINUTES


def test_a_node_with_no_harvest_gets_one_rather_than_a_silent_no_op(app):
    from app.extensions import db
    from app.models import ScheduledAction
    from app.services import settings_store as store
    with app.app_context():
        ScheduledAction.query.filter_by(action="device_sync").delete()
        db.session.commit()
        assert store.sot_refresh()["configured"] is False
        res = store.save_sot_refresh("30")
        assert res["created"] is True
        assert store.sot_refresh()["minutes"] == 30
        assert store.sot_refresh()["configured"] is True


def test_a_wall_clock_harvest_is_reported_not_rewritten(app):
    """A daily harvest is a different statement, and converting it discards it."""
    from app.extensions import db
    from app.models import ScheduledAction
    from app.services import settings_store as store
    with app.app_context():
        ScheduledAction.query.filter_by(action="device_sync").delete()
        db.session.commit()
        row = ScheduledAction(name="nightly", scope="admin", product="fortiweb",
                              action="device_sync", targets="[]", params="{}",
                              schedule_kind="daily",
                              schedule=json.dumps({"time": "02:00"}), enabled=True)
        db.session.add(row)
        db.session.commit()
        rid = row.id
        cfg = store.sot_refresh()
        assert cfg["configured"] is False, "a daily row is not an interval"
        assert cfg["others"] == 1, "and must still be reported, not hidden"
        store.save_sot_refresh("20")
        kept = db.session.get(ScheduledAction, rid)
        assert kept.schedule_kind == "daily" and json.loads(kept.schedule) == {"time": "02:00"}, \
            "the wall-clock harvest was overwritten by the interval knob"


# ── 3. the three backup paths each say what lands in them ───────────────────

@pytest.mark.parametrize("field,must_say", [
    ("config_path", "appliances"),
    ("firmware_path", "firmware"),
    ("system_path", "postgres"),
])
def test_each_backup_path_carries_its_own_explanation(admin, field, must_say):
    pane = _pane(_page(admin), "tab-backupsrv")
    # The label owning this input: from the previous column boundary to the input.
    assert 'name="%s"' % field in pane, "%s is not on the form" % field
    label = pane.split('name="%s"' % field, 1)[0].rsplit('<div class="col-4">', 1)[1]
    assert "data-fw-hint" in label, "%s has no '?' hint" % field
    title = label.split('title="', 1)[1].split('"', 1)[0]
    assert must_say in title.lower(), \
        "the %s hint does not say what is written there: %r" % (field, title[:80])


def test_the_three_hints_are_three_different_texts(admin):
    pane = _pane(_page(admin), "tab-backupsrv")
    titles = []
    for field in ("config_path", "firmware_path", "system_path"):
        label = pane.split('name="%s"' % field, 1)[0].rsplit('<div class="col-4">', 1)[1]
        titles.append(label.split('title="', 1)[1].split('"', 1)[0])
    assert len(set(titles)) == 3, "two paths are explained with the same sentence"


def test_the_hint_macro_is_imported_so_the_page_renders_at_all(admin):
    """A macro used without its import is a 500, and this page has 40 panes."""
    assert '{% from "partials/_hint.html" import hint %}' in IDX.read_text()
    assert admin.get("/settings/").status_code == 200
