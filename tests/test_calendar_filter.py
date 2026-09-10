"""Guards for the Change Calendar filter (2026-09-10, rewritten).

The calendar is where the split between Automations and System Automations
becomes VISIBLE: it is the only page that draws both halves at once, and it is
the page the operator opens to answer "what is going to happen to the fleet
tonight".

WHAT CHANGED, AND WHY THESE GUARDS CHANGED WITH IT
--------------------------------------------------
The bar used to carry TWO facets — an event family (``kind``) and an automation
owner (``owner``). Together they printed the word "Automations" four times in
one row with three different meanings, and being independent they multiplied:
``kind=change&owner=user`` is a legal URL in which the owner half decides
nothing. It is now ONE list of the things the grid draws:

    Planned changes · Automations · System Automations · What already ran

Every failure mode below renders as a page that looks perfectly correct:

  * a band that empties the grid paints a quiet month over a fleet mid-cutover,
    and every hidden automation still fires;
  * the owner vocabulary drifting from ``scheduled_actions.effective_scope``
    draws an empty band and blames the fleet;
  * a chip that carries only itself silently widens the rest of the filter;
  * history drawn for a band that is hidden paints the past of something the
    page just said is not there — and history hidden with no band to hang it on
    paints a fleet whose automations have never run;
  * a saved filter stored as an explicit "all" hides tomorrow's fifth band
    forever, with nothing on screen to un-tick;
  * a blob written under the OLD two-facet bar reported as stale blames the
    user for a vocabulary WE renamed;
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
import re
from datetime import datetime, timedelta

from conftest import login
from test_automation_split import _admin, _mk, _page

from app.services import calendar_filters as calf

USER_ACTION = "policy_set_status"      # catalog scope 'user'
ADMIN_ACTION = "system_backup"         # catalog scope 'admin'

CAL = "/calendar/"
KEY = "calendar_plan.filters"

#: The stale-filter banner's own sentence.
#:
#: Asserted verbatim because the bare words "no longer" ALSO appear in a
#: JavaScript comment further down this very page — the tenth guard in this
#: repo to match a string the document supplies itself, and it passed with the
#: banner deleted.
STALE_BANNER = "Part of your saved filter no longer exists"


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
def test_the_band_owners_match_the_splitter(app):
    """``OWNER_OF_BAND`` restates what ``effective_scope`` returns. A calendar
    that filtered on 'admin' while the splitter answered 'system' would draw an
    empty band and blame the fleet."""
    from app.views.scheduled_actions import effective_scope
    from app.models import ScheduledAction
    with app.app_context():
        u = ScheduledAction.query.get(_mk(app, "v-u", USER_ACTION, scope="user"))
        s = ScheduledAction.query.get(_mk(app, "v-s", ADMIN_ACTION, scope="admin"))
        assert effective_scope(u) == calf.OWNER_OF_BAND["automation"]
        assert effective_scope(s) == calf.OWNER_OF_BAND["system"]


def test_the_history_band_is_not_a_primary_one(app):
    """``run`` is a TIME switch, not a thing the grid is made of. Listing it as
    primary would let the bar refuse to turn it off — and turning the past off
    is a perfectly ordinary, non-empty state."""
    assert calf.HISTORY in calf.BANDS
    assert calf.HISTORY not in calf.PRIMARY
    assert set(calf.PRIMARY) < set(calf.BANDS)


def test_the_two_automation_bands_are_the_only_owned_ones(app):
    assert set(calf.OWNER_OF_BAND) == {"automation", "system"}
    assert set(calf.OWNER_OF_BAND) < set(calf.PRIMARY)


def test_an_orphan_run_lands_on_the_system_band(app):
    """Its own history link points at the system surface; drawing it in the
    fleet-work band would paint an event whose link contradicts its band."""
    assert calf.owner_of(None, scope_of=lambda a: "user") == calf.ORPHAN_OWNER
    assert calf.ORPHAN_OWNER == calf.OWNER_OF_BAND["system"]


def test_an_unknown_scope_lands_on_the_system_band(app):
    """A scope from a future release must not vanish from the grid. Falling
    through to the system band draws it; falling through to nothing hides a
    live automation with no chip to bring it back."""
    assert calf.owner_of(object(), scope_of=lambda a: "martian") == \
        calf.ORPHAN_OWNER


def test_the_vocabulary_helper_hands_out_a_fresh_set_every_call(app):
    """A shared constant is mutated by the first caller that edits its own
    selection and leaks into every later request in the same worker — one
    user's filter would narrow another user's grid."""
    first = calf.all_bands()
    first.add("martian")
    assert "martian" not in calf.all_bands()
    assert calf.all_bands() == set(calf.BANDS)


# --------------------------------------------------------------------------- #
#  2. The resolver: precedence                                                  #
# --------------------------------------------------------------------------- #
def test_a_bare_visit_draws_everything(app):
    got = calf.resolve(_Args(), None)
    assert got.bands == calf.all_bands()
    assert not got.active and not got.saved and not got.from_query


def test_a_saved_filter_is_applied_on_a_bare_visit(app):
    got = calf.resolve(_Args(), json.dumps({"show": ["change"]}))
    assert got.bands == {"change"} and got.saved and got.active


def test_the_marker_beats_a_saved_filter(app):
    """Widening back to everything produces the full set, which normalises to
    the same URL as a bare visit. Without the marker that click would restore
    the very filter the user just widened."""
    got = calf.resolve(_Args(show=list(calf.BANDS), f="1"),
                       json.dumps({"show": ["change"]}))
    assert got.bands == calf.all_bands()
    assert got.from_query and not got.saved


def test_the_marker_alone_is_a_submission(app):
    got = calf.resolve(_Args(f="1"), json.dumps({"show": ["change"]}))
    assert got.bands == calf.all_bands() and got.from_query


def test_clear_forgets_and_draws_everything(app):
    got = calf.resolve(_Args(clear="1", show="change"),
                       json.dumps({"show": ["change"]}))
    assert got.bands == calf.all_bands() and not got.saved


def test_save_marks_the_filter_as_stored(app):
    got = calf.resolve(_Args(show="change", save="1"), None)
    assert got.bands == {"change"} and got.saved and got.from_query


def test_a_filter_typed_this_request_is_not_saved(app):
    """``saved`` describes the STORE, and it is what the badge claims. A filter
    equal to the stored one is still not the stored one being applied."""
    got = calf.resolve(_Args(show="change", f="1"),
                       json.dumps({"show": ["change"]}))
    assert got.bands == {"change"} and not got.saved


# --------------------------------------------------------------------------- #
#  3. The resolver: the grid can never be emptied                               #
# --------------------------------------------------------------------------- #
def test_a_request_naming_only_history_is_widened_and_says_so(app):
    """Reachable only by hand-typed URL — the bar refuses the link. Drawing the
    past alone is an empty month, so it widens back and reports it rather than
    painting the fleet idle."""
    got = calf.resolve(_Args(show=calf.HISTORY, f="1"), None)
    assert got.bands == calf.all_bands()
    assert got.stale and got.stale[-1] == (calf.FACET_LABEL, "")


def test_a_stored_blob_naming_only_history_is_widened_too(app):
    got = calf.resolve(_Args(), json.dumps({"show": [calf.HISTORY]}))
    assert got.bands == calf.all_bands()
    assert (calf.FACET_LABEL, "") in got.stale


def test_a_stale_saved_value_is_named_and_widened(app):
    got = calf.resolve(_Args(), json.dumps({"show": ["change", "martian"]}))
    assert got.bands == {"change"}
    assert (calf.FACET_LABEL, "martian") in got.stale


def test_a_saved_facet_that_validates_to_nothing_reports_itself(app):
    """Their saved choice really WAS dropped, the grid really is wider than
    they asked for, and nothing else on screen says so."""
    got = calf.resolve(_Args(), json.dumps({"show": ["martian"]}))
    assert got.bands == calf.all_bands()
    assert (calf.FACET_LABEL, "") in got.stale
    assert (calf.FACET_LABEL, "martian") in got.stale


def test_a_facet_absent_from_the_store_is_not_reported_as_stale(app):
    """``to_json`` writes STRICT SUBSETS, so an empty blob is the ordinary shape
    of "nothing hidden". Crying wolf on every visit of a working filter is how
    a page teaches the eye to skip the banner that matters."""
    got = calf.resolve(_Args(), json.dumps({}))
    assert got.bands == calf.all_bands() and not got.stale


def test_an_unreadable_blob_is_reported_not_swallowed(app):
    got = calf.resolve(_Args(), "{not json")
    assert got.unreadable and got.bands == calf.all_bands()


def test_a_blob_that_is_not_an_object_is_unreadable(app):
    got = calf.resolve(_Args(), json.dumps(["change"]))
    assert got.unreadable


def test_a_stored_filter_that_hides_nothing_is_not_badged_as_saved(app):
    """A "saved" badge over an unfiltered grid claims a state the user cannot
    see and cannot clear."""
    got = calf.resolve(_Args(), json.dumps({"show": sorted(calf.BANDS)}))
    assert got.bands == calf.all_bands() and not got.saved


# --------------------------------------------------------------------------- #
#  4. The resolver: the retired facets TRANSLATE, they do not go stale          #
# --------------------------------------------------------------------------- #
def test_an_old_owner_blob_translates_instead_of_going_stale(app):
    """A blob written yesterday under the two-facet bar. Reporting it stale
    would blame the user for a vocabulary WE renamed."""
    got = calf.resolve(_Args(), json.dumps({"owner": ["user"]}))
    assert got.bands == {"change", "automation", "run"}
    assert not got.stale


def test_an_old_kind_and_owner_blob_translates(app):
    got = calf.resolve(_Args(), json.dumps({"kind": ["automation"],
                                            "owner": ["admin"]}))
    assert got.bands == {"system"} and not got.stale


def test_an_old_query_string_translates(app):
    got = calf.resolve(_Args(kind="automation", owner="user"), None)
    assert got.bands == {"automation"} and got.from_query


def test_an_old_kind_only_query_keeps_both_automation_bands(app):
    """Absent meant "all" on both sides of the old bar, so ``kind=automation``
    alone named both halves. Translating it to one would hide a live band on
    the strength of a click that never mentioned it."""
    got = calf.resolve(_Args(kind="automation"), None)
    assert got.bands == {"automation", "system"}


def test_the_new_facet_beats_the_old_one_rather_than_merging(app):
    """Merging two vocabularies is how a chip stops meaning what it says."""
    got = calf.resolve(_Args(show="change", kind="run", owner="user"), None)
    assert got.bands == {"change"}


# --------------------------------------------------------------------------- #
#  5. What gets stored                                                          #
# --------------------------------------------------------------------------- #
def test_remembering_everything_stores_nothing(app):
    """An explicit "all" freezes today's vocabulary: ship a fifth band and
    every user who ever pressed Remember has it hidden forever."""
    assert json.loads(calf.to_json(calf.all_bands())) == {}
    assert json.loads(calf.to_json(set())) == {}


def test_a_strict_subset_is_stored(app):
    assert json.loads(calf.to_json({"change"})) == {"show": ["change"]}


def test_the_round_trip_survives(app):
    raw = calf.to_json({"automation", "run"})
    got = calf.resolve(_Args(), raw)
    assert got.bands == {"automation", "run"} and got.saved and not got.stale


# --------------------------------------------------------------------------- #
#  6. ``toggled`` — one author for "which chip may be switched off"             #
# --------------------------------------------------------------------------- #
def test_an_off_band_toggles_back_on(app):
    assert calf.toggled({"change"}, "system") == sorted({"change", "system"})


def test_an_on_band_toggles_off_while_another_primary_remains(app):
    assert calf.toggled({"change", "system"}, "system") == ["change"]


def test_the_last_primary_band_refuses_to_toggle(app):
    """Turning it off leaves an empty month that reads as a quiet fleet rather
    than a filter. Returning [] is how the caller draws a chip that is not a
    link, instead of a link to the state the resolver would refuse."""
    for band in calf.PRIMARY:
        assert calf.toggled({band}, band) == []
        assert calf.toggled({band, calf.HISTORY}, band) == []


def test_the_history_band_always_toggles(app):
    assert calf.toggled({calf.HISTORY}, calf.HISTORY) == []  # no primary left
    assert calf.toggled({"change", calf.HISTORY}, calf.HISTORY) == ["change"]


def test_toggled_does_not_mutate_what_it_is_given(app):
    bands = {"change", "system"}
    calf.toggled(bands, "system")
    assert bands == {"change", "system"}


def test_the_bar_and_the_resolver_agree_on_the_invariant(app):
    """Every link the bar can draw resolves to a filter with a primary band.
    Two authors of that rule is how a bar and its page start disagreeing."""
    from itertools import combinations
    for size in range(1, len(calf.BANDS) + 1):
        for combo in combinations(calf.BANDS, size):
            bands = set(combo)
            if not (bands & set(calf.PRIMARY)):
                continue
            for band in calf.BANDS:
                other = calf.toggled(bands, band)
                if not other:
                    continue
                got = calf.resolve(_Args(show=list(other), f="1"), None)
                assert got.bands & set(calf.PRIMARY), (combo, band, other)
                assert got.bands == set(other), (combo, band, other)


# --------------------------------------------------------------------------- #
#  7. History follows its group                                                 #
# --------------------------------------------------------------------------- #
def test_history_is_scoped_by_the_automation_bands(app):
    got = calf.resolve(_Args(show=["automation", calf.HISTORY], f="1"), None)
    assert got.owners == {calf.OWNER_OF_BAND["automation"]}
    assert got.draws_runs and got.draws_automations and not got.draws_changes


def test_history_alone_draws_nothing_and_says_so(app):
    """Reachable: hide both automation groups, leave Planned changes on. The
    grid then has no past at all, which is indistinguishable from a fleet whose
    automations have never run."""
    got = calf.resolve(_Args(show=["change", calf.HISTORY], f="1"), None)
    assert got.bands == {"change", calf.HISTORY}
    assert not got.draws_runs and not got.draws_automations
    assert calf.history_orphan_note(got.bands)


def test_the_orphan_note_is_silent_when_history_has_a_band(app):
    assert not calf.history_orphan_note({"automation", calf.HISTORY})
    assert not calf.history_orphan_note({"change"})
    assert not calf.history_orphan_note(calf.all_bands())


def test_the_orphan_note_names_the_switch_and_the_groups(app):
    note = calf.history_orphan_note({"change", calf.HISTORY})
    assert "already ran" in note and "hidden" in note


# --------------------------------------------------------------------------- #
#  8. The counts                                                                #
# --------------------------------------------------------------------------- #
def test_the_count_is_silent_when_nothing_is_hidden(app):
    assert calf.counts_note(3, 3, "automations") == ""
    assert calf.counts_note(4, 3, "automations") == ""


def test_the_count_names_what_is_hidden_and_that_it_still_fires(app):
    note = calf.counts_note(1, 4, "automations")
    assert "1 of 4 automations drawn" in note and "3 hidden" in note
    assert "still fire" in note


def test_a_hidden_run_is_not_described_as_still_firing(app):
    """A run is OVER. Telling an operator that last week's runs still fire is a
    worse sentence than no sentence."""
    note = calf.counts_note(0, 4, "runs", tail="and they still happened.")
    assert "still fire" not in note
    assert "still happened" in note and "0 of 4 runs drawn" in note


# --------------------------------------------------------------------------- #
#  9. The page: what the grid draws                                             #
# --------------------------------------------------------------------------- #
def test_both_halves_are_drawn_by_default(app, client):
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "usr-cutover" in page and "sys-backup" in page


def test_hiding_a_band_hides_its_automations(app, client):
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(
        CAL + "?show=change&show=automation&show=run&f=1").get_data(as_text=True))
    assert "usr-cutover" in page and "sys-backup" not in page


def test_hiding_a_band_hides_its_runs_too(app, client):
    """A calendar that hides System Automations and still draws their runs is
    drawing the history of something it just said is not there."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(
        CAL + "?show=change&show=system&show=run&f=1").get_data(as_text=True))
    assert "sys-backup" in page and "usr-cutover" not in page


def test_turning_history_off_leaves_the_upcoming_ones(app, client):
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(
        CAL + "?show=change&show=automation&show=system&f=1"
    ).get_data(as_text=True))
    assert "usr-cutover" in page and "sys-backup" in page
    assert "runs drawn" in page


def test_the_grid_says_how_many_automations_it_is_hiding(app, client):
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(
        CAL + "?show=change&show=run&f=1").get_data(as_text=True))
    assert "0 of 2 automations drawn" in page
    assert "still fire" in page


def test_the_grid_prints_the_orphan_history_sentence(app, client):
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(
        CAL + "?show=change&show=run&f=1").get_data(as_text=True))
    assert "already ran" in page and "both are hidden" in page


def test_the_run_band_counts_before_the_filter_too(app, client):
    """A past that shrinks in silence reads as runs that never happened."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(
        CAL + "?show=change&show=automation&show=run&f=1").get_data(as_text=True))
    assert "1 of 2 runs drawn" in page
    # A run is OVER. The default tail is a claim about the future and belongs
    # to the schedule band only; on the history band it tells an operator that
    # last week's runs are still firing.
    assert "1 of 2 runs drawn — 1 hidden by the filter, and they still " \
           "happened." in page
    assert "runs drawn — 1 hidden by the filter, and they still fire." \
        not in page


def test_an_unfiltered_grid_does_not_print_a_count(app, client):
    """"Showing 8 of 8" on every visit trains the eye to skip the line."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "automations drawn" not in page and "runs drawn" not in page


# --------------------------------------------------------------------------- #
# 10. The page: ONE list, and the word is not repeated                          #
# --------------------------------------------------------------------------- #
def _chips(html):
    """``[(band, href)]`` for every chip that is a LINK, read by the marker the
    MARKUP carries.

    Not by a regex over every calendar link: every control carries the whole
    filter, so "a chip preserved the rest" and "a chip dropped it" are the same
    string to a URL-shaped pattern.
    """
    return [(b, h.replace("&amp;", "&")) for b, h in re.findall(
        r'data-band="([a-z]+)"[^>]*?href="([^"]+)"', html, re.S)]


def _frozen(html):
    """The bands drawn as text rather than as a link."""
    return re.findall(r'<span[^>]*data-band="([a-z]+)"', html, re.S)


def test_the_bar_offers_every_band_exactly_once(app, client):
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL).get_data(as_text=True))
    drawn = [b for b, _ in _chips(page)] + _frozen(page)
    assert sorted(drawn) == sorted(calf.BANDS), drawn


def test_the_bar_names_the_two_surfaces_as_their_pages_name_them(app, client):
    """A calendar band labelled differently from the page it links to reads as
    a third kind of thing."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert ">Automations" in page
    assert "System Automations" in page


def test_the_bar_no_longer_prints_automations_as_a_group_heading(app, client):
    """THE DEFECT THIS ROUND EXISTS FOR. The old bar had a family chip
    "Automations (upcoming)", a group label "Automations:" and an owner chip
    "Automations (fleet work)" — one word, three meanings, in one row."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "Automations (upcoming)" not in page
    assert "Automations (fleet work)" not in page
    assert "What ran<" not in page


def test_the_bar_carries_one_facet_only(app, client):
    """Two facets multiplied into states in which half the bar decided
    nothing."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert 'data-facet="kind"' not in page and 'data-facet="owner"' not in page
    for _, href in _chips(page):
        assert "kind=" not in href and "owner=" not in href, href


def test_every_chip_carries_the_whole_filter(app, client):
    """A chip that carries only itself silently widens the rest: turning the
    past off would also un-hide the system automations, in response to a click
    that said nothing about them."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(
        CAL + "?show=change&show=automation&f=1").get_data(as_text=True))
    for band, href in _chips(page):
        rest = {"change", "automation"} - {band}
        for keep in rest:
            assert "show=%s" % keep in href, (band, href)


def test_every_filter_link_carries_the_marker(app, client):
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(
        CAL + "?show=change&show=automation&f=1").get_data(as_text=True))
    hrefs = [h for _, h in _chips(page)]
    assert hrefs
    for href in hrefs:
        assert "f=1" in href, href


def test_the_last_primary_chip_is_not_a_link(app, client):
    """A link to the state the resolver refuses is a control that lies. It is
    drawn as text instead."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL + "?show=change&f=1").get_data(as_text=True))
    assert _frozen(page) == ["change"], _frozen(page)
    assert "change" not in [b for b, _ in _chips(page)]


def test_the_history_chip_stays_a_link_even_when_it_is_the_only_extra(app, client):
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(
        CAL + "?show=change&show=run&f=1").get_data(as_text=True))
    assert calf.HISTORY in [b for b, _ in _chips(page)]


def test_paging_the_month_keeps_the_filter(app, client):
    """EVERY calendar link carries the whole filter, not just the chips.

    Prev / next / Today / a day cell all come from the ``qs`` macro. A macro
    that drops the facet means the filter survives exactly as long as the user
    does not navigate — and the widening happens on the click that changes the
    month, so it reads as "there is more scheduled in October", which is the one
    conclusion a maintenance calendar must never invite by accident.

    ``clear`` is excluded on purpose: dropping the filter IS what it does.
    """
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(
        CAL + "?show=change&show=automation&f=1").get_data(as_text=True))
    links = [h.replace("&amp;", "&")
             for h in re.findall(r'href="(/calendar/\?[^"]*)"', page)]
    # The chips carry ``view=`` too and a chip's whole job is to change one
    # band, so sweeping them in here would assert that a toggle does not
    # toggle. Excluded by the marker the markup carries, not by shape.
    chips = {h for _, h in _chips(page)}
    nav = [h for h in links
           if "view=" in h and "clear=1" not in h and h not in chips
           and "save=1" not in h]
    assert len(nav) > 3, nav
    for href in nav:
        assert "show=change" in href and "show=automation" in href, href
        assert "show=system" not in href and "show=run" not in href, href
        assert "f=1" in href, href


# --------------------------------------------------------------------------- #
# 11. The page: what the profile remembers                                      #
# --------------------------------------------------------------------------- #
def test_saving_writes_the_calendar_key_only(app, client):
    """ONE KEY PER SURFACE. A key shared with the Automation pages would mean
    filtering the calendar silently re-filters a list the user was not looking
    at."""
    _both(app)
    uid = _admin(app)
    login(client, uid)
    client.get(CAL + "?show=change&f=1&save=1")
    assert json.loads(_pref(app, uid)) == {"show": ["change"]}
    assert not _pref(app, uid, "automations.filters")
    assert not _pref(app, uid, "scheduled_actions.filters")


def test_the_saved_filter_comes_back_on_the_next_visit(app, client):
    _both(app)
    uid = _admin(app)
    login(client, uid)
    client.get(CAL + "?show=change&show=system&show=run&f=1&save=1")
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "sys-backup" in page and "usr-cutover" not in page
    assert "Saved filter" in page


def test_filtering_without_remember_forgets_the_stored_one(app, client):
    """Leaving it stored resurrects it next visit and contradicts the choice
    just made."""
    _both(app)
    uid = _admin(app)
    login(client, uid)
    client.get(CAL + "?show=change&f=1&save=1")
    client.get(CAL + "?show=change&show=automation&f=1")
    assert json.loads(_pref(app, uid) or "{}") == {}


def test_clear_erases_the_stored_filter(app, client):
    _both(app)
    uid = _admin(app)
    login(client, uid)
    client.get(CAL + "?show=change&f=1&save=1")
    client.get(CAL + "?clear=1")
    assert json.loads(_pref(app, uid) or "{}") == {}
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "usr-cutover" in page and "sys-backup" in page


def test_the_store_never_keeps_a_value_the_resolver_dropped(app, client):
    """A dropped value written back hides a band on every future visit with
    nothing on screen to un-tick."""
    _both(app)
    uid = _admin(app)
    login(client, uid)
    client.get(CAL + "?show=change&show=martian&f=1&save=1")
    assert json.loads(_pref(app, uid)) == {"show": ["change"]}


def test_an_old_stored_blob_is_applied_without_a_banner(app, client):
    """Yesterday's blob. It must filter, and it must not accuse the user."""
    _both(app)
    uid = _admin(app)
    login(client, uid)
    _set_pref(app, uid, json.dumps({"kind": ["automation"],
                                    "owner": ["admin"]}))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "sys-backup" in page and "usr-cutover" not in page
    assert STALE_BANNER not in page


def test_a_stale_stored_value_is_named_on_the_page(app, client):
    _both(app)
    uid = _admin(app)
    login(client, uid)
    _set_pref(app, uid, json.dumps({"show": ["change", "martian"]}))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert STALE_BANNER in page
    assert "martian" in page


def test_an_unreadable_stored_filter_is_named_on_the_page(app, client):
    """A blob nobody can read is still a filter the user believes is on."""
    _both(app)
    uid = _admin(app)
    login(client, uid)
    _set_pref(app, uid, "{not json")
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "could not be read" in page or "unreadable" in page.lower()


def test_an_ordinary_saved_filter_prints_no_stale_banner(app, client):
    _both(app)
    uid = _admin(app)
    login(client, uid)
    _set_pref(app, uid, json.dumps({"show": ["change"]}))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert STALE_BANNER not in page


# --------------------------------------------------------------------------- #
# 12. The filter is a VIEW preference and nothing else                          #
# --------------------------------------------------------------------------- #
def test_the_filter_does_not_change_the_gate(app, client):
    """It changes what the grid DRAWS and nothing about what anyone may do."""
    _both(app)
    login(client, _admin(app))
    for qs in ("", "?show=change&f=1", "?show=system&show=run&f=1"):
        assert client.get(CAL + qs).status_code == 200, qs


def test_each_event_still_links_to_the_page_that_owns_it(app, client):
    """The two surfaces refuse each other's ids (404). One hardcoded endpoint
    would make every fleet-work automation look deleted to the very operator
    who scheduled it."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL).get_data(as_text=True))
    assert "/automations/" in page and "/scheduled-actions/" in page


def test_the_page_carries_no_dark_theme_literals(app, client):
    """SATOM is a LIGHT product (safeguards §9m): a dark-theme pastel lands at
    ~1.4:1 on white, which is a badge that cannot be read."""
    _both(app)
    login(client, _admin(app))
    page = _page(client.get(CAL).get_data(as_text=True))
    for literal in ("#080d1a", "rgba(30,41,59", "backdrop-filter",
                    "#6ee7b7", "#fcd34d", "#fca5a5"):
        assert literal not in page, literal
