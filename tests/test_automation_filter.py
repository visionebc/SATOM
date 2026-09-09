"""Guards for the Automation list filter (2026-09-09).

Everything here defends ONE property: a filter may change what a page DRAWS and
must never change what it MEANS or what anyone may DO.

Every failure mode below renders as a page that looks perfectly correct —

  * a filter that quietly empties a list reads as "my automations were
    deleted", while every hidden row keeps firing on its schedule;
  * a saved facet the catalog no longer offers matches nothing on every future
    visit, forever, with nothing on screen to say why;
  * one preference key shared by both surfaces re-filters a page the user was
    not looking at;
  * the cross-scope facet drawing the other surface's rows with THIS page's
    controls arms buttons whose by-id guard answers 404 — which reads as a
    deleted automation, not as a wrong link;
  * "remember" unticked while a stored filter exists resurrects the filter on
    the next visit and contradicts the box the user just cleared;
  * "showing N of M" with N > M when the cross-scope facet is on.

None of those raise. That is why they are asserted.

Helpers are IMPORTED from ``test_automation_split`` rather than copied: a second
author for ``_split_chrome`` is the exact defect that file documents, and this
file asserts against the same two halves of the same document.
"""
from __future__ import annotations

import json

import pytest

from conftest import login
from test_automation_split import _admin, _mk, _operator, _page, _sidebar

USER_ACTION = "policy_set_status"      # scope 'user'   -> /automations/
ADMIN_ACTION = "system_backup"         # scope 'admin'  -> /scheduled-actions/

USR = "/web/automations/"
SYS = "/web/scheduled-actions/"


# --------------------------------------------------------------------------- #
#  Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _pref(app, uid, key):
    from app.models import UserSetting
    with app.app_context():
        return UserSetting.get(uid, key)


def _set_pref(app, uid, key, raw):
    from app.models import UserSetting
    with app.app_context():
        UserSetting.set(uid, key, raw)


def _kind(app, rid, kind):
    """Retarget one row's schedule kind.

    ``_mk`` fixes it at 'daily'; the schedule facet needs a second value and a
    second row-creator would be the duplication this suite exists to avoid.
    """
    from app.extensions import db
    from app.models import ScheduledAction
    with app.app_context():
        row = db.session.get(ScheduledAction, rid)
        row.schedule_kind = kind
        db.session.commit()


def _count(html):
    """``(shown, total)`` as the page states them, read from the filter bar.

    Parsed from the markup rather than recomputed, because the number the user
    acts on is the one printed — a count recomputed in the test would agree with
    a page that prints something else entirely.
    """
    import re
    m = re.search(r"Showing\s*<strong>(\d+)</strong>\s*of\s*<strong>(\d+)</strong>",
                  html, re.S)
    assert m, "the filter bar does not state a shown/total count"
    return int(m.group(1)), int(m.group(2))


def _filter_form(html):
    """Just the filter <form>, so a facet assertion cannot match the row table
    or the sidebar. Same discipline as ``_split_chrome``."""
    page = _page(html)
    start = page.index('<form method="GET"')
    return page[start:page.index("</form>", start)]


def _table(html):
    """Just the results table.

    The ninth assert-by-substring in this repo to match a string its own
    document supplied elsewhere: "System Automations" is the row badge AND the
    label of the cross-scope checkbox ("Also show System Automations"), so
    "the revealed row is labelled with its owner" passed with the badge
    deleted. Slice the table off the form before asserting about rows.
    """
    page = _page(html)
    start = page.index('<div class="fw-table-wrapper">')
    return page[start:page.index("</table>", start)]


# --------------------------------------------------------------------------- #
#  1. The pure resolver — no Flask, no DB, no request                           #
# --------------------------------------------------------------------------- #
CHOICES = {"action": {USER_ACTION, ADMIN_ACTION}, "schedule": {"daily", "weekly"}}


def _resolve(args=None, saved=None, allow_cross=False):
    from app.services import automation_filters as af
    return af.resolve(args or {}, saved, choices=CHOICES, allow_cross=allow_cross)


def test_blank_is_a_fresh_dict_every_call():
    """A shared module-level constant would be mutated by the first request
    that edits its own filter and would leak into every other one."""
    from app.services import automation_filters as af
    a = af.blank()
    a["q"] = "poisoned"
    assert af.blank()["q"] == ""


def test_pref_key_is_per_surface():
    """One shared key means saving 'only disabled' while triaging System
    Automations silently re-filters the operator's own page."""
    from app.services import automation_filters as af
    assert af.pref_key("automations") != af.pref_key("scheduled_actions")


def test_no_args_and_no_store_is_inactive():
    r = _resolve()
    assert r.filters == {k: "" for k in ("q", "action", "status", "schedule", "scope")}
    assert not r.active and not r.saved and not r.from_query


def test_query_string_wins_and_is_marked_from_query():
    r = _resolve({"q": " shop "})
    assert r.filters["q"] == "shop"      # trimmed
    assert r.active and r.from_query and not r.saved


def test_save_flag_marks_it_saved():
    assert _resolve({"q": "shop", "save": "1"}).saved


def test_the_submit_marker_alone_counts_as_a_submission():
    """A GET form sends every named field, so clearing every box yields
    ``?q=&action=&...`` — indistinguishable from a bare visit once trimmed.
    Without the marker, "clear the boxes and press Filter" falls through to
    "restore the saved filter" and the filter comes straight back."""
    from app.services import automation_filters as af
    r = _resolve({af.SUBMIT_MARKER: "1", "q": ""}, saved='{"q": "old"}')
    assert r.from_query and not r.active and r.filters["q"] == ""


def test_a_bare_visit_still_restores_the_store():
    """The mirror of the guard above: making from_query always true would mean
    a saved filter is never restored and the feature does nothing."""
    r = _resolve({}, saved='{"q": "old"}')
    assert not r.from_query and r.filters["q"] == "old"


def test_save_alone_counts_as_a_query_submission():
    """Ticking 'remember' on an otherwise-blank form must reach the store, not
    fall through to 'restore whatever was saved'."""
    r = _resolve({"save": "1"}, saved='{"q": "old"}')
    assert r.from_query and r.saved and r.filters["q"] == ""


def test_clear_forgets_everything_and_is_not_a_query_submission():
    r = _resolve({"clear": "1", "q": "shop"}, saved='{"q": "old"}')
    assert not r.active and not r.saved and not r.from_query


def test_saved_blob_is_restored_when_no_args():
    r = _resolve(saved=json.dumps({"q": "shop", "status": "disabled"}))
    assert r.filters["q"] == "shop" and r.filters["status"] == "disabled"
    assert r.saved and not r.from_query


def test_stale_action_key_is_dropped_and_named():
    """A saved key the catalog retired would match nothing on every future
    visit. Silently applying it turns the page into 'you have none'."""
    r = _resolve(saved=json.dumps({"action": "retired_in_1_29", "q": "shop"}))
    assert r.filters["action"] == ""
    assert r.filters["q"] == "shop"          # the rest survives
    assert ("action type", "retired_in_1_29") in r.stale


def test_stale_schedule_kind_is_dropped_and_named():
    r = _resolve(saved=json.dumps({"schedule": "fortnightly"}))
    assert r.filters["schedule"] == ""
    assert ("schedule", "fortnightly") in r.stale


def test_status_vocabulary_is_this_modules_own_not_the_callers():
    """A view that forgot to pass 'status' must not silently accept any string
    and hand it to the matcher, which would match nothing."""
    from app.services import automation_filters as af
    r = af.resolve({"status": "paused"}, None, choices=CHOICES)
    assert r.filters["status"] == ""
    assert ("status", "paused") in r.stale


def test_caller_cannot_widen_the_status_vocabulary():
    from app.services import automation_filters as af
    r = af.resolve({"status": "paused"}, None,
                   choices=dict(CHOICES, status={"paused"}))
    assert r.filters["status"] == ""


def test_unreadable_blob_is_reported_not_silently_blank():
    r = _resolve(saved="{not json")
    assert not r.active and r.unreadable and not r.saved


def test_non_dict_blob_is_unreadable():
    assert _resolve(saved="[1, 2, 3]").unreadable


def test_a_blob_that_validates_to_nothing_is_not_reported_as_saved():
    """Otherwise a 'saved to profile' badge sits over a completely unfiltered
    list, and Clear appears to do nothing."""
    r = _resolve(saved=json.dumps({"action": "retired"}))
    assert not r.active and not r.saved and r.stale


def test_cross_scope_is_dropped_silently_without_the_permission():
    """Not stale — it is not a retired catalog value, it is a request this
    viewer may not make. Naming the page they cannot see is a disclosure the
    split exists to avoid."""
    r = _resolve({"scope": "all"}, allow_cross=False)
    assert not r.cross_scope
    assert r.stale == []


def test_cross_scope_is_honoured_with_the_permission():
    assert _resolve({"scope": "all"}, allow_cross=True).cross_scope


def test_saved_cross_scope_is_also_gated():
    """A permission lost since the filter was saved must not keep widening the
    page — the store is not an access-control record."""
    r = _resolve(saved=json.dumps({"scope": "all"}), allow_cross=False)
    assert not r.cross_scope


def test_active_is_computed_from_the_values():
    """Tracked as a separate flag, a facet added later forgets to set it and the
    page silently reverts to the never-created empty state."""
    from app.services import automation_filters as af
    r = af.Resolved(filters=dict(af.blank(), schedule="daily"))
    assert r.active


def test_to_json_omits_empty_facets():
    """A stored '' is indistinguishable from a facet that did not exist when the
    blob was written, and the difference decides how a NEW facet defaults."""
    from app.services import automation_filters as af
    data = json.loads(af.to_json(dict(af.blank(), q="shop")))
    assert data == {"q": "shop"}


# --------------------------------------------------------------------------- #
#  2. The matcher                                                               #
# --------------------------------------------------------------------------- #
def _row(**kw):
    base = {"name": "spo-tienda-mx", "scope": "user", "action_key": USER_ACTION,
            "enabled": True, "schedule_kind": "daily"}
    base.update(kw)
    return base


def _blank():
    from app.services import automation_filters as af
    return af.blank()


def test_own_scope_row_survives_a_blank_filter():
    from app.services import automation_filters as af
    assert af.row_matches(_row(), _blank(), surface_scope="user")


def test_other_scope_row_is_absent_without_the_cross_facet():
    """The partition the two blueprints rest on. Without this the user page
    lists rows whose Delete it cannot serve."""
    from app.services import automation_filters as af
    assert not af.row_matches(_row(scope="admin"), _blank(), surface_scope="user")


def test_other_scope_row_appears_with_the_cross_facet():
    from app.services import automation_filters as af
    flt = dict(_blank(), scope="all")
    assert af.row_matches(_row(scope="admin"), flt, surface_scope="user")


def test_name_match_is_case_insensitive_substring():
    from app.services import automation_filters as af
    assert af.row_matches(_row(), dict(_blank(), q="TIENDA"), surface_scope="user")
    assert not af.row_matches(_row(), dict(_blank(), q="api"), surface_scope="user")


def test_status_facet_selects_both_ways():
    from app.services import automation_filters as af
    on, off = _row(enabled=True), _row(enabled=False)
    assert af.row_matches(on, dict(_blank(), status="enabled"), surface_scope="user")
    assert not af.row_matches(on, dict(_blank(), status="disabled"), surface_scope="user")
    assert af.row_matches(off, dict(_blank(), status="disabled"), surface_scope="user")
    assert not af.row_matches(off, dict(_blank(), status="enabled"), surface_scope="user")


def test_action_and_schedule_facets_are_exact():
    from app.services import automation_filters as af
    assert not af.row_matches(_row(), dict(_blank(), action=ADMIN_ACTION),
                              surface_scope="user")
    assert not af.row_matches(_row(), dict(_blank(), schedule="weekly"),
                              surface_scope="user")


def test_row_is_foreign_is_about_the_surface_not_the_filter():
    from app.services import automation_filters as af
    assert af.row_is_foreign(_row(scope="admin"), surface_scope="user")
    assert not af.row_is_foreign(_row(scope="user"), surface_scope="user")


# --------------------------------------------------------------------------- #
#  3. The permission lives in ONE place                                         #
# --------------------------------------------------------------------------- #
def test_surfaces_declare_the_permission_each_gate_uses(app):
    """The page that OFFERS the cross-scope facet and the factory that BINDS the
    gate must read one value; two copies drift silently."""
    from app.models import Permission
    from app.views.scheduled_actions import SURFACES
    assert SURFACES["automations"]["permission"] == Permission.CONFIG_WRITE
    assert SURFACES["scheduled_actions"]["permission"] == Permission.USER_MANAGE


def test_the_gates_still_bite_after_the_lookup_moved(app, client):
    login(client, _operator(app))
    assert client.get(USR).status_code == 200
    assert client.get(SYS).status_code == 403


# --------------------------------------------------------------------------- #
#  4. The page: counts, and what an empty list MEANS                            #
# --------------------------------------------------------------------------- #
def test_count_states_shown_and_total(app, client):
    _mk(app, "spo-tienda-mx", USER_ACTION, scope="user")
    _mk(app, "spo-api-prod", USER_ACTION, scope="user")
    login(client, _operator(app))
    assert _count(client.get(USR).get_data(as_text=True)) == (2, 2)


def test_a_filter_hides_a_row_and_the_count_says_so(app, client):
    _mk(app, "spo-tienda-mx", USER_ACTION, scope="user")
    _mk(app, "spo-api-prod", USER_ACTION, scope="user")
    login(client, _operator(app))
    html = client.get(USR + "?q=tienda").get_data(as_text=True)
    assert _count(html) == (1, 2)
    assert "spo-api-prod" not in _page(html)


def test_filtered_empty_never_borrows_the_never_created_wording(app, client):
    """One pixel apart on screen, an order of magnitude apart in consequence:
    the hidden rows keep firing."""
    _mk(app, "spo-tienda-mx", USER_ACTION, scope="user")
    login(client, _operator(app))
    page = _page(client.get(USR + "?q=nothing-matches-this").get_data(as_text=True))
    assert "No scheduled actions yet" not in page
    assert "No automation matches this filter" in page
    assert "clear=1" in page          # the way out is on the page


def test_never_created_still_says_never_created(app, client):
    login(client, _operator(app))
    page = _page(client.get(USR).get_data(as_text=True))
    assert "No scheduled actions yet" in page
    assert "No automation matches this filter" not in page


# --------------------------------------------------------------------------- #
#  5. Persistence — per user, per surface                                       #
# --------------------------------------------------------------------------- #
def test_saving_writes_the_surfaces_own_key(app, client):
    uid = _operator(app)
    login(client, uid)
    client.get(USR + "?q=tienda&save=1")
    assert json.loads(_pref(app, uid, "automations.filters")) == {"q": "tienda"}


def test_saving_on_one_surface_leaves_the_other_alone(app, client):
    uid = _admin(app)
    login(client, uid)
    client.get(SYS + "?q=backup&save=1")
    assert _pref(app, uid, "automations.filters") is None


def test_the_saved_filter_is_restored_on_the_next_visit(app, client):
    _mk(app, "spo-tienda-mx", USER_ACTION, scope="user")
    _mk(app, "spo-api-prod", USER_ACTION, scope="user")
    uid = _operator(app)
    login(client, uid)
    client.get(USR + "?q=tienda&save=1")
    html = client.get(USR).get_data(as_text=True)
    assert _count(html) == (1, 2)
    assert "saved to profile" in _page(html)


def test_unticking_remember_forgets_the_stored_filter(app, client):
    """Leaving it stored resurrects it next visit and contradicts the box the
    user just cleared."""
    _mk(app, "spo-tienda-mx", USER_ACTION, scope="user")
    _mk(app, "spo-api-prod", USER_ACTION, scope="user")
    uid = _operator(app)
    login(client, uid)
    client.get(USR + "?q=tienda&save=1")
    client.get(USR + "?submitted=1&q=")           # submitted, boxes cleared
    assert json.loads(_pref(app, uid, "automations.filters")) == {}
    assert _count(client.get(USR).get_data(as_text=True)) == (2, 2)


def test_clear_forgets_the_stored_filter(app, client):
    uid = _operator(app)
    login(client, uid)
    client.get(USR + "?q=tienda&save=1")
    client.get(USR + "?clear=1")
    assert json.loads(_pref(app, uid, "automations.filters")) == {}


def test_a_saved_filter_belongs_to_one_user(app, client):
    _mk(app, "spo-tienda-mx", USER_ACTION, scope="user")
    _mk(app, "spo-api-prod", USER_ACTION, scope="user")
    owner = _operator(app)
    login(client, owner)
    client.get(USR + "?q=tienda&save=1")

    from conftest import make_user
    other = make_user(app, username="op2", role="operator")
    login(client, other)
    assert _count(client.get(USR).get_data(as_text=True)) == (2, 2)


def test_a_stale_saved_facet_is_named_on_the_page(app, client):
    _mk(app, "spo-tienda-mx", USER_ACTION, scope="user")
    uid = _operator(app)
    _set_pref(app, uid, "automations.filters",
              json.dumps({"action": "retired_in_1_29"}))
    login(client, uid)
    page = _page(client.get(USR).get_data(as_text=True))
    assert "retired_in_1_29" in page
    assert _count(page) == (1, 1)      # and the list is NOT empty


def test_an_unreadable_saved_filter_says_so_and_shows_everything(app, client):
    _mk(app, "spo-tienda-mx", USER_ACTION, scope="user")
    uid = _operator(app)
    _set_pref(app, uid, "automations.filters", "{not json")
    login(client, uid)
    page = _page(client.get(USR).get_data(as_text=True))
    assert "could not be read" in page
    assert _count(page) == (1, 1)


def test_a_stale_facet_is_not_written_back(app, client):
    """Written back, the bad value survives every future visit and the page can
    never recover on its own."""
    uid = _operator(app)
    _set_pref(app, uid, "automations.filters", json.dumps({"action": "retired"}))
    login(client, uid)
    client.get(USR + "?q=tienda&action=retired&save=1")
    assert json.loads(_pref(app, uid, "automations.filters")) == {"q": "tienda"}


# --------------------------------------------------------------------------- #
#  6. The cross-scope facet — a view widening, never a permission               #
# --------------------------------------------------------------------------- #
def test_operator_is_not_offered_the_cross_scope_facet(app, client):
    login(client, _operator(app))
    assert 'name="scope"' not in _filter_form(client.get(USR).get_data(as_text=True))


def test_admin_is_offered_the_cross_scope_facet(app, client):
    login(client, _admin(app))
    assert 'name="scope"' in _filter_form(client.get(USR).get_data(as_text=True))


def test_operator_asking_for_it_by_url_gets_nothing_extra(app, client):
    _mk(app, "nightly-system-backup", ADMIN_ACTION, scope="admin")
    _mk(app, "spo-tienda-mx", USER_ACTION, scope="user")
    login(client, _operator(app))
    html = client.get(USR + "?scope=all").get_data(as_text=True)
    assert "nightly-system-backup" not in _page(html)
    assert _count(html) == (1, 1)


def test_admin_asking_for_it_sees_the_other_half(app, client):
    _mk(app, "nightly-system-backup", ADMIN_ACTION, scope="admin")
    _mk(app, "spo-tienda-mx", USER_ACTION, scope="user")
    login(client, _admin(app))
    html = client.get(USR + "?scope=all").get_data(as_text=True)
    assert "nightly-system-backup" in _page(html)
    assert _count(html) == (2, 2)


def test_shown_never_exceeds_total_with_the_cross_facet_on(app, client):
    """A total counting only this surface's half would print 'showing 2 of 1'."""
    _mk(app, "nightly-system-backup", ADMIN_ACTION, scope="admin")
    _mk(app, "spo-tienda-mx", USER_ACTION, scope="user")
    login(client, _admin(app))
    shown, total = _count(client.get(USR + "?scope=all").get_data(as_text=True))
    assert shown <= total


def test_a_revealed_row_is_drawn_read_only(app, client):
    """Its Edit / Run / Delete resolve to THIS blueprint, whose by-id guard 404s
    a row it does not own — a button that answers 'gone' reads as deleted."""
    rid = _mk(app, "nightly-system-backup", ADMIN_ACTION, scope="admin")
    login(client, _admin(app))
    table = _table(client.get(USR + "?scope=all").get_data(as_text=True))
    assert f"/web/automations/{rid}/delete" not in table
    assert f"/web/automations/{rid}/edit" not in table
    assert SYS in table                       # and it links to its owner


def test_the_revealed_row_is_labelled_with_its_owning_page(app, client):
    """Asserted against the TABLE: the cross-scope checkbox's own label reads
    "Also show System Automations", so a page-wide assertion here passes with
    the row badge deleted — which is exactly what the harness caught."""
    _mk(app, "nightly-system-backup", ADMIN_ACTION, scope="admin")
    login(client, _admin(app))
    table = _table(client.get(USR + "?scope=all").get_data(as_text=True))
    assert "System Automations" in table


def test_the_pages_own_rows_keep_their_controls(app, client):
    """The read-only branch must not swallow the rows this page DOES own."""
    rid = _mk(app, "spo-tienda-mx", USER_ACTION, scope="user")
    login(client, _admin(app))
    page = _page(client.get(USR + "?scope=all").get_data(as_text=True))
    assert f"/web/automations/{rid}/delete" in page


def test_the_by_id_guard_is_unchanged_by_the_facet(app, client):
    """The filter widened the LIST. It may not widen what the routes serve."""
    rid = _mk(app, "nightly-system-backup", ADMIN_ACTION, scope="admin")
    login(client, _admin(app))
    client.get(USR + "?scope=all&save=1")
    assert client.get(f"/web/automations/{rid}/edit").status_code == 404


# --------------------------------------------------------------------------- #
#  7. The action dropdown offers only what can match here                       #
# --------------------------------------------------------------------------- #
def test_action_dropdown_omits_the_other_halfs_actions(app, client):
    """An option that cannot match anything on this page is the mirror of a
    stale facet: it produces an empty list and blames the user."""
    login(client, _operator(app))
    assert ADMIN_ACTION not in _filter_form(client.get(USR).get_data(as_text=True))


def test_action_dropdown_gains_them_when_the_cross_facet_is_on(app, client):
    login(client, _admin(app))
    form = _filter_form(client.get(USR + "?scope=all").get_data(as_text=True))
    assert ADMIN_ACTION in form


def test_schedule_facet_selects_by_kind(app, client):
    a = _mk(app, "spo-tienda-mx", USER_ACTION, scope="user")
    _mk(app, "spo-api-prod", USER_ACTION, scope="user")
    _kind(app, a, "weekly")
    login(client, _operator(app))
    html = client.get(USR + "?schedule=weekly").get_data(as_text=True)
    assert _count(html) == (1, 2)
    assert "spo-api-prod" not in _page(html)


def test_status_facet_selects_disabled_rows(app, client):
    _mk(app, "spo-tienda-mx", USER_ACTION, scope="user", enabled=False)
    _mk(app, "spo-api-prod", USER_ACTION, scope="user", enabled=True)
    login(client, _operator(app))
    html = client.get(USR + "?status=disabled").get_data(as_text=True)
    assert _count(html) == (1, 2)
    assert "spo-api-prod" not in _page(html)


def test_the_form_carries_the_submit_marker(app, client):
    """Unwired, the resolver's marker branch is unreachable and clearing the
    boxes silently restores the saved filter — which is how this was found."""
    from app.services import automation_filters as af
    login(client, _operator(app))
    form = _filter_form(client.get(USR).get_data(as_text=True))
    assert f'name="{af.SUBMIT_MARKER}"' in form


def test_the_filter_bar_is_on_the_system_surface_too(app, client):
    """Two implementations of one list is how the two surfaces drift apart."""
    login(client, _admin(app))
    assert 'name="q"' in _filter_form(client.get(SYS).get_data(as_text=True))


def test_the_sidebar_is_not_what_carries_these_assertions(app, client):
    """Sanity check on the harness itself: four guards in the sibling suite
    survived their own mutation by matching a string the sidebar supplied."""
    login(client, _operator(app))
    html = client.get(USR).get_data(as_text=True)
    assert "Showing" not in _sidebar(html)
