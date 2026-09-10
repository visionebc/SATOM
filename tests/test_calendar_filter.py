"""Guards for the Change Calendar filter (2026-09-09).

The calendar is where the split between Automations and System Automations
becomes VISIBLE: it is the only page that draws both halves at once, and it is
the page the operator opens to answer "what is going to happen to the fleet
tonight". So the filter here defends one property — it may change what the grid
DRAWS and must never change what it MEANS.

Every failure mode below renders as a page that looks perfectly correct:

  * a facet that empties a band paints a quiet month over a fleet mid-cutover,
    and every hidden automation still fires;
  * the owner vocabulary drifting from ``scheduled_actions.effective_scope``
    draws an empty band and blames the fleet;
  * a chip that carries only its own facet silently widens the other one, so
    turning "what ran" off also un-hides the system automations;
  * a saved filter stored as an explicit "all" hides tomorrow's fourth event
    family forever, with nothing on screen to un-tick;
  * a stored filter naming a retired value matches nothing on every future
    visit;
  * "remember" unticked while a stored filter exists resurrects it next visit;
  * one preference key shared with the Automation pages re-filters a page the
    user was not looking at.

None of those raise. That is why they are asserted.

Helpers are IMPORTED from ``test_automation_split``: a second author for
``_split_chrome`` is the exact defect that file documents, and the sidebar of
every calendar page mentions both surfaces whether or not a single event points
at either.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from conftest import login
from test_automation_split import _admin, _mk, _page

from app.services import calendar_filters as calf

USER_ACTION = "policy_set_status"      # catalog scope 'user'
ADMIN_ACTION = "system_backup"         # catalog scope 'admin'

CAL = "/calendar/"
KEY = "calendar_plan.filters"


class _Args:
    """The smallest thing that behaves like Flask's MultiDict.

    A double, not a real request: the resolver must be provable against a saved
    blob no store would ever write, which is precisely the input that breaks it.
    """

    def __init__(self, **kw):
        self._d = {k: (v if isinstance(v, list) else [v]) for k, v in kw.items()}

    def get(self, name, default=None):
        vals = self._d.get(name)
        return vals[0] if vals else default

    def getlist(self, name):
        return list(self._d.get(name, ()))


def _pref(app, uid, key=KEY):
    from app.models import UserSetting
    with app.app_context():
        return UserSetting.get(uid, key)


def _set_pref(app, uid, raw, key=KEY):
    from app.models import UserSetting
    with app.app_context():
        UserSetting.set(uid, key, raw)


def _run(app, action_id, minutes_ago=30, status="ok"):
    from app.extensions import db
    from app.models import ScheduledActionRun
    with app.app_context():
        row = ScheduledActionRun(
            action_id=action_id, status=status, trigger="schedule",
            started_at=datetime.utcnow() - timedelta(minutes=minutes_ago))
        db.session.add(row)
        db.session.commit()
        return row.id


def _both(app):
    """One automation on each side of the split, plus one run for each."""
    u = _mk(app, "usr-cutover", USER_ACTION, scope="user")
    s = _mk(app, "sys-backup", ADMIN_ACTION, scope="admin")
    _run(app, u)
    _run(app, s)
    return u, s


# --------------------------------------------------------------------------- #
#  1. The vocabulary is not this module's to invent                             #
# --------------------------------------------------------------------------- #
def test_owner_vocabulary_matches_the_splitter(app):
    """The calendar filters on the strings the SPLITTER returns.

    If it filtered on 'system' while ``effective_scope`` answered 'admin', the
    band would be empty and the page would read as a fleet with no maintenance
    scheduled — the calendar's worst possible lie, told silently.
    """
    from app.views.scheduled_actions import ADMIN_SCOPE, USER_SCOPE
    assert set(calf.OWNERS) == {USER_SCOPE, ADMIN_SCOPE}


def test_an_orphan_run_lands_on_the_system_band(app):
    """A run whose action row is gone gets its history link from
    ``_owner_endpoint``, which answers with the system surface. Filing it under
    'user' would draw an event whose own link contradicts the band it is in."""
    assert calf.owner_of(None, scope_of=lambda a: "user") == "admin"


def test_an_unknown_scope_lands_on_the_system_band(app):
    """Total by construction, like ``effective_scope`` itself: a scope string
    from a future version must not fall out of every band and become invisible
    on the one page that draws everything."""
    assert calf.owner_of(object(), scope_of=lambda a: "sideways") == "admin"


# --------------------------------------------------------------------------- #
#  2. resolve(): precedence and the marker                                      #
# --------------------------------------------------------------------------- #
def test_a_bare_visit_draws_everything(app):
    got = calf.resolve(_Args(), None)
    assert got.kinds == calf.all_kinds() and got.owners == calf.all_owners()
    assert not got.active and not got.saved and not got.from_query


def test_a_saved_filter_is_applied_on_a_bare_visit(app):
    got = calf.resolve(_Args(), json.dumps({"owner": ["user"]}))
    assert got.owners == {"user"} and got.saved and got.active


def test_the_marker_beats_a_saved_filter(app):
    """THE TRAP THIS MARKER EXISTS FOR. Clicking the chip that turns the last
    hidden owner back on produces the full set — which, once normalised, is the
    same URL as a bare visit. Without the marker that click falls through to
    "restore the saved filter" and the filter the user just widened comes
    straight back, in response to a click that asked for the opposite.
    """
    args = _Args(kind=list(calf.all_kinds()), owner=list(calf.all_owners()),
                 **{calf.MARKER: "1"})
    got = calf.resolve(args, json.dumps({"owner": ["user"]}))
    assert got.owners == calf.all_owners() and got.from_query
    assert not got.active


def test_the_marker_alone_is_a_submission(app):
    """A control that carries only the marker (every facet at its default) is
    still a submission, not a bare visit."""
    got = calf.resolve(_Args(**{calf.MARKER: "1"}), json.dumps({"kind": ["run"]}))
    assert got.kinds == calf.all_kinds() and got.from_query


def test_clear_forgets_and_draws_everything(app):
    got = calf.resolve(_Args(clear="1"), json.dumps({"owner": ["user"]}))
    assert got.owners == calf.all_owners() and not got.saved and not got.from_query


def test_save_marks_the_filter_as_stored(app):
    got = calf.resolve(_Args(owner="user", save="1"), None)
    assert got.saved and got.from_query and got.owners == {"user"}


def test_a_filter_typed_this_request_is_not_saved(app):
    """``saved`` describes the STORE — it is what the badge and the checkbox
    claim. A query-string filter that happens to equal the stored one has not
    been saved by this request."""
    got = calf.resolve(_Args(owner="user"), json.dumps({"owner": ["user"]}))
    assert got.from_query and not got.saved


# --------------------------------------------------------------------------- #
#  3. resolve(): a filter may never empty the grid                              #
# --------------------------------------------------------------------------- #
def test_a_stale_saved_value_is_named_and_widened(app):
    got = calf.resolve(_Args(), json.dumps({"kind": ["seance"]}))
    assert got.kinds == calf.all_kinds()
    assert ("event type", "seance") in got.stale


def test_a_saved_facet_that_validates_to_nothing_reports_itself(app):
    """Widening back is not enough on its own: the user's saved choice was
    dropped, and a page that draws everything without saying so looks like the
    filter was never saved at all."""
    got = calf.resolve(_Args(), json.dumps({"owner": ["nobody"]}))
    assert got.owners == calf.all_owners()
    assert ("automation owner", "nobody") in got.stale


def test_an_unreadable_blob_is_reported_not_swallowed(app):
    got = calf.resolve(_Args(), "{not json")
    assert got.unreadable and got.kinds == calf.all_kinds() and not got.saved


def test_a_blob_that_is_not_an_object_is_unreadable(app):
    assert calf.resolve(_Args(), "[1,2,3]").unreadable


def test_a_stored_filter_that_hides_nothing_is_not_badged_as_saved(app):
    """A "saved filter" badge over an unfiltered grid claims a state the user
    cannot see and cannot clear."""
    got = calf.resolve(_Args(), json.dumps({"kind": sorted(calf.all_kinds())}))
    assert not got.active and not got.saved


# --------------------------------------------------------------------------- #
#  4. to_json(): only a strict subset is stored                                 #
# --------------------------------------------------------------------------- #
def test_remembering_everything_stores_nothing(app):
    """An explicit "all" freezes the vocabulary against its own future: ship a
    fourth event family and every user who pressed Remember has it hidden
    forever, with no facet on screen to un-tick."""
    assert json.loads(calf.to_json(calf.all_kinds(), calf.all_owners())) == {}


def test_a_strict_subset_is_stored(app):
    blob = json.loads(calf.to_json({"change"}, calf.all_owners()))
    assert blob == {"kind": ["change"]}


def test_the_round_trip_survives(app):
    raw = calf.to_json({"automation", "run"}, {"user"})
    got = calf.resolve(_Args(), raw)
    assert got.kinds == {"automation", "run"} and got.owners == {"user"}
    assert not got.stale


# --------------------------------------------------------------------------- #
#  5. counts_note(): silence only when nothing is hidden                        #
# --------------------------------------------------------------------------- #
def test_the_count_is_silent_when_nothing_is_hidden(app):
    assert calf.counts_note(8, 8, "automations") == ""


def test_the_count_names_what_is_hidden_and_that_it_still_fires(app):
    note = calf.counts_note(3, 11, "automations")
    assert "3 of 11" in note and "8 hidden" in note and "still fire" in note


# --------------------------------------------------------------------------- #
#  6. The page: the facet actually narrows the grid                             #
# --------------------------------------------------------------------------- #
def test_both_halves_are_drawn_by_default(app, client):
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "usr-cutover" in page and "sys-backup" in page


def test_the_owner_facet_hides_the_other_half(app, client):
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL + "?owner=user&f=1").get_data(as_text=True))
    assert "usr-cutover" in page and "sys-backup" not in page


def test_the_owner_facet_follows_the_runs_too(app, client):
    """History is where a half-applied facet is most misleading: a band showing
    "what ran" for automations it is not drawing invites the operator to
    conclude the schedule was deleted after its last run."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL + "?kind=run&owner=admin&f=1").get_data(as_text=True))
    assert "sys-backup" in page and "usr-cutover" not in page


def test_the_grid_says_how_many_it_is_hiding(app, client):
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL + "?owner=user&f=1").get_data(as_text=True))
    assert "1 of 2 automations drawn" in page and "still fire" in page


def test_an_unfiltered_grid_does_not_print_a_count(app, client):
    """A page that says "2 of 2" on every visit teaches the eye to skip the one
    line that matters."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "automations drawn" not in page


# --------------------------------------------------------------------------- #
#  7. The page: the controls carry the WHOLE filter                             #
# --------------------------------------------------------------------------- #
def _chips(html, facet):
    """The hrefs of one chip family, read by the marker the MARKUP carries.

    Not by a regex over every calendar link: now that every control carries the
    whole filter, "an owner chip preserved the families" and "a family chip
    changed them" are the same string to a URL-shaped pattern — and the version
    that could not tell them apart passed against a chip that dropped the other
    facet entirely.
    """
    import re
    return [h.replace("&amp;", "&") for h in re.findall(
        r'data-facet="%s"[^>]*?href="([^"]+)"' % facet, html, re.S)]


def test_every_family_chip_carries_the_owner_facet(app, client):
    """A chip that carries only its own facet silently widens the other one:
    turning "what ran" off would also un-hide the system automations, in
    response to a click that said nothing about them."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL + "?owner=user&f=1").get_data(as_text=True))
    hrefs = _chips(page, "kind")
    assert len(hrefs) == len(calf.all_kinds()), hrefs
    for href in hrefs:
        assert "owner=user" in href and "owner=admin" not in href, href


def test_every_owner_chip_carries_the_family_facet(app, client):
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL + "?kind=automation&f=1").get_data(as_text=True))
    hrefs = _chips(page, "owner")
    assert len(hrefs) == len(calf.all_owners()), hrefs
    for href in hrefs:
        assert "kind=automation" in href, href
        assert "kind=change" not in href and "kind=run" not in href, href


def test_every_filter_link_carries_the_marker(app, client):
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL + "?owner=user&f=1").get_data(as_text=True))
    hrefs = _chips(page, "kind") + _chips(page, "owner")
    assert hrefs
    for href in hrefs:
        assert "f=1" in href, href


def test_paging_the_month_keeps_the_filter(app, client):
    """EVERY calendar link carries the whole filter, not just the chips.

    Prev / next / Today / a day cell all come from the ``qs`` macro. A macro
    that drops the facet means the filter survives exactly as long as the user
    does not navigate — and the widening happens on the click that changes the
    month, so it reads as "there is more scheduled in October", which is the
    one conclusion a maintenance calendar must never invite by accident.

    ``clear`` is excluded on purpose: dropping the filter IS what it does.
    """
    import re
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL + "?owner=user&f=1").get_data(as_text=True))
    links = [h.replace("&amp;", "&")
             for h in re.findall(r'href="(/calendar/\?[^"]*)"', page)]
    nav = [h for h in links if "view=" in h and "clear=1" not in h]
    assert len(nav) > 3, nav
    for href in nav:
        assert "owner=user" in href, href
        assert "f=1" in href, href


def test_the_last_owner_does_not_toggle_itself_off(app, client):
    """Turning the last owner off hides every automation AND its history, which
    on a month grid is indistinguishable from a fleet with nothing scheduled.

    Asserted on the ONE chip that is currently on: its link must still name an
    owner. A link with no ``owner=`` at all would read as "everything" on the
    way back in, which is the opposite of what the click asks for.
    """
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL + "?owner=user&f=1").get_data(as_text=True))
    for href in _chips(page, "owner"):
        assert "owner=" in href, href
    # The chip for the owner already on cannot produce an ownerless URL.
    assert any("owner=user" in h and "owner=admin" in h
               for h in _chips(page, "owner")), "the off chip must widen"


# --------------------------------------------------------------------------- #
#  8. The page: what the profile remembers                                      #
# --------------------------------------------------------------------------- #
def test_saving_writes_the_calendar_key_only(app, client):
    """ONE KEY PER SURFACE. A key shared with the Automation pages would mean
    filtering the calendar silently re-filters a list the user was not looking
    at."""
    _both(app)
    uid = _admin(app)
    login(client, uid)
    client.get(CAL + "?owner=user&f=1&save=1")
    assert json.loads(_pref(app, uid)) == {"owner": ["user"]}
    assert not _pref(app, uid, "automations.filters")
    assert not _pref(app, uid, "scheduled_actions.filters")


def test_the_saved_filter_comes_back_on_the_next_visit(app, client):
    _both(app)
    uid = _admin(app)
    login(client, uid)
    client.get(CAL + "?owner=user&f=1&save=1")
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "usr-cutover" in page and "sys-backup" not in page
    assert "Saved filter" in page


def test_filtering_without_remember_forgets_the_stored_one(app, client):
    """Leaving it stored resurrects it on the next visit and contradicts the
    choice just made."""
    _both(app)
    uid = _admin(app)
    login(client, uid)
    client.get(CAL + "?owner=user&f=1&save=1")
    client.get(CAL + "?owner=admin&f=1")
    assert json.loads(_pref(app, uid) or "{}") == {}
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "usr-cutover" in page and "sys-backup" in page


def test_clear_erases_the_stored_filter(app, client):
    _both(app)
    uid = _admin(app)
    login(client, uid)
    client.get(CAL + "?owner=user&f=1&save=1")
    client.get(CAL + "?clear=1")
    assert json.loads(_pref(app, uid) or "{}") == {}


def test_a_stale_stored_facet_is_named_on_the_page(app, client):
    """Named, not merely dropped: the user is looking at a grid that ignores
    the filter they saved, and nothing else on screen explains why."""
    _both(app)
    uid = _admin(app)
    login(client, uid)
    _set_pref(app, uid, json.dumps({"owner": ["nobody"]}))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "no longer exists" in page and "automation owner" in page
    assert "usr-cutover" in page and "sys-backup" in page


def test_an_unreadable_stored_filter_is_named_on_the_page(app, client):
    _both(app)
    uid = _admin(app)
    login(client, uid)
    _set_pref(app, uid, "{not json")
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "could not be read" in page
    assert "usr-cutover" in page and "sys-backup" in page


# --------------------------------------------------------------------------- #
#  9. The filter is a view preference, never a permission                       #
# --------------------------------------------------------------------------- #
def test_the_owner_facet_does_not_change_the_gate(app, client):
    """The split between the two Automation pages is a PERMISSION boundary; the
    calendar's facet is a preference over what it paints. Filtering to the user
    band must not turn the calendar into a page a weaker role may open."""
    from test_automation_split import _operator
    login(client, _operator(app))
    for url in (CAL, CAL + "?owner=user&f=1"):
        resp = client.get(url)
        assert resp.status_code in (302, 403), url


def test_each_event_still_links_to_the_page_that_owns_it(app, client):
    """Unchanged by the filter, and asserted here because the filter is the
    thing most likely to start deciding it."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "/web/automations/" in page and "/web/scheduled-actions/" in page


def test_the_page_carries_no_dark_theme_literals(app, client):
    """SATOM is light-only (safeguards §9m). The filter bar is new markup on a
    page nobody re-reads."""
    _both(app)
    login(client, _admin(app))
    html = client.get(CAL + "?owner=user&f=1").get_data(as_text=True)
    for literal in ("#080d1a", "rgba(30,41,59", "backdrop-filter"):
        assert literal not in html, literal


# --------------------------------------------------------------------------- #
#  10. Gaps found by the mutation harness                                       #
# --------------------------------------------------------------------------- #
def test_the_vocabulary_helpers_hand_out_a_fresh_set_every_call(app):
    """A shared constant is mutated by the first caller that edits its own
    selection and leaks into every later request of the same gunicorn worker —
    one user's filter would silently narrow another user's grid, and nothing on
    either page would explain it. The dataclass defaults come from these two
    helpers, so the leak reaches every ``Resolved`` ever built."""
    from app.services import calendar_plan as cal

    first = calf.all_kinds()
    first.discard(sorted(first)[0])
    assert calf.all_kinds() == set(cal.KINDS)

    first_owners = calf.all_owners()
    first_owners.discard('user')
    assert calf.all_owners() == set(calf.OWNERS)

    a, b = calf.Resolved(), calf.Resolved()
    assert a.kinds is not b.kinds
    assert a.owners is not b.owners


def test_a_saved_facet_that_all_validated_away_says_it_was_widened(app):
    """Naming the dead value is not enough on its own. The user is looking at a
    grid WIDER than the one they saved, and the widening is the fact that
    explains the rows they did not expect to see."""
    got = calf.resolve(_Args(), json.dumps({"owner": ["nobody"]}))
    assert ("automation owner", "") in got.stale
    got = calf.resolve(_Args(), json.dumps({"kind": ["seance"]}))
    assert ("event type", "") in got.stale


def test_a_facet_absent_from_the_store_is_not_reported_as_stale(app):
    """ABSENT IS NOT STALE. ``to_json`` writes strict subsets only, so a filter
    on one facet stores exactly one key — the ordinary shape of a working saved
    filter. Reporting the other facet as "no longer exists" would print that
    banner on every visit of a filter that is doing its job."""
    got = calf.resolve(_Args(), json.dumps({"owner": ["user"]}))
    assert got.stale == []
    assert got.owners == {"user"} and got.kinds == calf.all_kinds()

    got = calf.resolve(_Args(), json.dumps({"kind": ["change"]}))
    assert got.stale == []

    # And the same on a bare query string, which is the other absent case.
    assert calf.resolve(_Args(f="1"), None).stale == []


def test_an_ordinary_saved_filter_prints_no_stale_banner(app, client):
    """The page half of the rule above: it is the banner, not the tuple, that
    the operator is trained by."""
    _both(app)
    uid = _admin(app)
    login(client, uid)
    client.get(CAL + "?owner=user&f=1&save=1")
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "no longer exists" not in page
    assert "Saved filter" in page


def test_the_run_band_counts_before_the_filter_too(app, client):
    """Both bands or neither. A history band that quietly shrinks reads as runs
    that never happened, which is worse than the automation band shrinking:
    nobody can tell a filtered past from a past that did not occur."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL + "?kind=run&owner=admin&f=1")
                 .get_data(as_text=True))
    assert "1 of 2 runs drawn" in page and "still fire" in page


def test_the_store_never_keeps_a_value_the_resolver_dropped(app, client):
    """Writing the QUERY STRING instead of the RESOLUTION puts a value the
    resolver already rejected into the profile, where it matches nothing on
    every future visit and there is no chip on screen to un-tick."""
    _both(app)
    uid = _admin(app)
    login(client, uid)
    client.get(CAL + "?owner=user&owner=nobody&f=1&save=1")
    assert json.loads(_pref(app, uid)) == {"owner": ["user"]}

    # And the grid drawn from it is the resolved one, not the junk.
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "usr-cutover" in page and "sys-backup" not in page
    assert "no longer exists" not in page
