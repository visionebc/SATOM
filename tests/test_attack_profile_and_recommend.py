"""Attack ID: show which profile the block lands on, and pre-select the scope.

Two requests from the same session, both about the same gap — the page knew
things the operator had to find out the hard way.

**The profile column.** Whether the policy's Web Protection Profile is shared
decides whether authoring an exception here is one click or a profile clone and
a re-bind of a live Server Policy. The page had that fact (it reads the bindings
to run the scope gate) and showed it only *after* the operator had committed to
a carve-out — and, on 2026-08-08, showed it by failing.

**The pre-selection.** The field picker opened with nothing ticked, which asks
the operator the one question they came here unable to answer: which of the
twenty-two fields on this entry scope THIS kind of exception. Everything needed
to answer it — which fields exist, which are required, which order is most
precise — was already declared in ``SCOPERS``.

What is guarded is not that the features exist but the properties that make them
safe to trust: an unreadable device never renders as a blank cell, a
recommendation is never wider than what the operator would have picked, and the
default selection is proved by RUNNING the real assembly rather than asserted.
"""
from __future__ import annotations

import os

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: An entry carrying a value for every field a scoper can use.
ROW = {'msg_id': '000000032768', 'main_type': 'Signature Detection',
       'sub_type': 'SQL Injection', 'policy': 'pol-shop-cms',
       'http_url': '/shop/checkout?x=1', 'http_host': 'shop.example',
       'http_method': 'post', 'src': '203.0.113.44', 'signature_id': '090200001',
       'signature_subclass': '9'}


def _read(rel: str) -> str:
    with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
        return fh.read()


class _Ap:
    id = 10
    name = 'fortiweb08'


# ═══════════════════════════════════════════════════════════════════════════ #
#  1. The Web Protection Profile column                                        #
# ═══════════════════════════════════════════════════════════════════════════ #
def _cells(monkeypatch, binding_map, err, rows):
    from app.views import attack_search
    from app.services import wpp_scope
    calls = []

    def _b(ap):
        calls.append(ap)
        return binding_map, err

    monkeypatch.setattr(wpp_scope, 'bindings', _b)
    return attack_search._wpp_cells(_Ap(), rows), calls


def test_a_shared_profile_is_flagged_and_names_the_other_policies(app, monkeypatch):
    """"It is shared" without "with what?" cannot be acted on. The real case:
    wpp-full-lab bound by three policies on fortiweb08."""
    bm = {'pol-shop-cms': 'wpp-full-lab', 'pol-full-api': 'wpp-full-lab',
          'pol-full-cr': 'wpp-full-lab'}
    with app.app_context():
        cells, _ = _cells(monkeypatch, bm, '', [ROW])
    assert cells[0]['state'] == 'shared'
    assert cells[0]['wpp'] == 'wpp-full-lab'
    assert cells[0]['shared_with'] == ['pol-full-api', 'pol-full-cr']
    assert 'pol-full-api' in cells[0]['detail']


def test_an_exclusive_profile_is_not_dressed_up_as_a_problem(app, monkeypatch):
    """The other half of the request: a policy that already has its own profile
    needs no clone, and saying otherwise manufactures a second profile and
    dirties the next audit."""
    with app.app_context():
        cells, _ = _cells(monkeypatch, {'pol-shop-cms': 'wpp-pol-shop-cms'},
                          '', [ROW])
    assert cells[0]['state'] == 'exclusive'
    assert cells[0]['shared_with'] == []


def test_an_unreadable_device_renders_unknown_and_never_a_blank(app, monkeypatch):
    """The distinction ``wpp_scope.bindings`` exists to preserve. "SATOM could
    not ask" and "this policy binds nothing" are opposite facts and produce the
    same empty dict; a blank cell is how the harmless one looks."""
    with app.app_context():
        cells, _ = _cells(monkeypatch, {}, 'connection refused', [ROW])
    assert cells[0]['state'] == 'unknown'
    assert cells[0]['state'] != 'none'
    assert 'connection refused' in cells[0]['detail']


def test_a_policy_the_device_does_not_have_is_not_reported_as_unbound(app, monkeypatch):
    """A renamed or deleted policy is a distinct fact from one that binds no
    profile, and only one of them means "nothing to protect here"."""
    with app.app_context():
        cells, _ = _cells(monkeypatch, {'pol-other': 'w'}, '', [ROW])
    assert cells[0]['state'] == 'missing'


def test_a_policy_that_binds_nothing_says_so(app, monkeypatch):
    with app.app_context():
        cells, _ = _cells(monkeypatch, {'pol-shop-cms': ''}, '', [ROW])
    assert cells[0]['state'] == 'none'


def test_an_entry_with_no_policy_is_not_an_error(app, monkeypatch):
    with app.app_context():
        cells, _ = _cells(monkeypatch, {}, '', [dict(ROW, policy='')])
    assert cells[0]['state'] == 'none'


def test_the_whole_table_costs_one_device_read(app, monkeypatch):
    """Per-row lookups would open one session per match against a production
    WAF for a page that renders a table."""
    bm = {'pol-shop-cms': 'wpp-pol-shop-cms'}
    with app.app_context():
        cells, calls = _cells(monkeypatch, bm, '', [ROW] * 12)
    assert len(cells) == 12
    assert len(calls) == 1


def test_no_rows_means_no_device_read_at_all(app, monkeypatch):
    with app.app_context():
        cells, calls = _cells(monkeypatch, {}, '', [])
    assert cells == [] and calls == []


def test_the_derived_profile_is_never_written_into_the_entry(app, monkeypatch):
    """A row is the evidence the appliance reported. A derived field mixed into
    it reaches the AI prompt, the detail panel and the audit trail dressed up as
    something the device said."""
    row = dict(ROW)
    before = set(row)
    with app.app_context():
        _cells(monkeypatch, {'pol-shop-cms': 'wpp-x'}, '', [row])
    assert set(row) == before


def test_the_column_is_rendered_by_one_macro_for_both_tables():
    """The "recent entries" table stands in for the matches table when the
    search misses. Two renderings would let the stand-in describe the appliance
    differently from the table it replaces."""
    html = _read('app/templates/attack_search/index.html')
    assert html.count('{% macro wpp_cell(') == 1
    assert html.count('wpp_cell(row_wpps[ridx])') == 1
    assert html.count('wpp_cell(recent_wpps[ridx])') == 1


def test_the_derived_column_lives_in_the_shared_column_list():
    """Both tables are driven by ``TABLE_COLUMNS``; a header hard-coded into
    one of them is how they drift apart. Derived or not, the column belongs in
    the list — only its VALUE comes from somewhere other than ``row[key]``."""
    from app.services import attack_log
    keys = [k for k, _ in attack_log.TABLE_COLUMNS]
    assert attack_log.WPP_FIELD in keys
    assert keys.index(attack_log.WPP_FIELD) == keys.index('policy') + 1, (
        'the profile belongs beside the policy it is bound to')
    html = _read('app/templates/attack_search/index.html')
    assert '<th>Web Protection Profile</th>' not in html


def test_the_template_is_told_which_column_is_derived():
    """``wpp_field`` comes from ``attack_log``, for the same reason
    ``time_field`` does: the cell cannot be rendered from ``row[key]``, and a
    literal in the template is a second copy of a name owned by the service."""
    from app.services import attack_log
    html = _read('app/templates/attack_search/index.html')
    assert attack_log.WPP_FIELD == 'wpp'
    assert html.count('key == wpp_field') == 2
    assert "key == 'wpp'" not in html


def test_the_derived_key_is_one_no_entry_carries(app):
    """The profile is read from the appliance, never from anything a caller
    sent. Sharing a name with a real log field would make that ambiguous."""
    from app.services import attack_log
    with app.app_context():
        assert attack_log.WPP_FIELD not in ROW
        assert attack_log.WPP_FIELD not in {k for k, _ in attack_log.PRIMARY_FIELDS}


# ═══════════════════════════════════════════════════════════════════════════ #
#  2. The recommended scope                                                    #
# ═══════════════════════════════════════════════════════════════════════════ #
def test_a_required_field_present_in_the_entry_is_always_picked(app):
    from app.services import attack_carveout as ac
    with app.app_context():
        rec = ac.recommend(ROW, 'allow_method_exception_item')
    assert 'http_url' in rec['picked']
    assert 'Required' in rec['reasons']['http_url']


def test_a_signature_exception_picks_exactly_one_element(app):
    """FortiWeb matches ONE element per signature row. Ticking several does not
    narrow it further — the assembly picks by precedence and reports the rest —
    so a default that ticked several would recommend a selection the device
    cannot honour."""
    from app.services import attack_carveout as ac
    with app.app_context():
        rec = ac.recommend(ROW, 'signature_filter_item')
    assert len(rec['picked']) == 1
    assert rec['picked'] == ['http_url'], 'the most precise element must win'
    assert rec['single_element'] is True


def test_the_one_element_falls_back_when_the_precise_one_is_absent(app):
    from app.services import attack_carveout as ac
    with app.app_context():
        rec = ac.recommend(dict(ROW, http_url=''), 'signature_filter_item')
    assert rec['picked'] == ['http_host']


def test_the_elements_not_chosen_say_why_and_how_to_swap(app):
    from app.services import attack_carveout as ac
    with app.app_context():
        rec = ac.recommend(ROW, 'signature_filter_item')
    skipped = {s['row_key'] for s in rec['skipped']}
    assert {'http_host', 'src', 'http_method'} <= skipped


def test_the_caller_address_is_held_back_while_the_request_can_be_described(app):
    """A carve-out says which traffic is legitimate. The source address in one
    entry is one observation of one caller; scoping to it produces an exception
    that stops applying when that integration is re-addressed, which the
    operator reads as "the exception did nothing"."""
    from app.services import attack_carveout as ac
    with app.app_context():
        rec = ac.recommend(ROW, 'http_constraint_exception_item')
    assert 'http_url' in rec['picked'] and 'http_host' in rec['picked']
    assert 'src' not in rec['picked']
    held = {s['row_key']: s['why'] for s in rec['skipped']}
    assert 'src' in held and 'caller' in held['src']


def test_the_caller_address_is_picked_when_it_is_the_only_thing_there_is(app):
    """A geo-IP carve-out exists to exempt an address. The rule is "prefer a
    request-shaped element", not "never use the source"."""
    from app.services import attack_carveout as ac
    with app.app_context():
        rec = ac.recommend(ROW, 'geo_ip_exception_member_item')
    assert rec['picked'] == ['src']


def test_a_field_the_entry_does_not_carry_is_never_picked(app):
    from app.services import attack_carveout as ac
    with app.app_context():
        rec = ac.recommend(dict(ROW, http_host=''),
                           'http_constraint_exception_item')
    assert 'http_host' not in rec['picked']
    held = {s['row_key'] for s in rec['skipped']}
    assert 'http_host' in held


def test_every_picked_field_carries_its_reason(app):
    """A pre-selection the operator cannot interrogate is one they either accept
    blindly or clear wholesale."""
    from app.services import attack_carveout as ac
    with app.app_context():
        for exc_type in ('http_constraint_exception_item',
                         'allow_method_exception_item',
                         'signature_filter_item',
                         'geo_ip_exception_member_item'):
            rec = ac.recommend(ROW, exc_type)
            for key in rec['picked']:
                assert rec['reasons'].get(key), (exc_type, key)


def test_every_offered_field_is_either_picked_or_explained(app):
    """Silence about a field the entry carries reads as SATOM having missed it."""
    from app.services import attack_carveout as ac
    with app.app_context():
        for exc_type in ('http_constraint_exception_item',
                         'signature_filter_item'):
            rec = ac.recommend(ROW, exc_type)
            accounted = set(rec['picked']) | {s['row_key'] for s in rec['skipped']}
            offered = {s['row_key'] for s in ac.scopers_for(exc_type)}
            assert offered <= accounted, exc_type


def test_the_recommendation_actually_assembles(app):
    """Proved by running the REAL assembly, never asserted. A default selection
    that does not validate has to be discovered here, not at Preview."""
    from app.services import attack_carveout as ac
    with app.app_context():
        for exc_type in ('http_constraint_exception_item',
                         'allow_method_exception_item',
                         'signature_filter_item',
                         'geo_ip_exception_member_item'):
            rec = ac.recommend(ROW, exc_type)
            built = ac.build(ROW, exc_type, rec['picked'])
            assert not built['errors'], (exc_type, built['errors'])
            assert built['payload'], exc_type


def test_the_recommendation_is_never_wider_than_no_recommendation(app):
    """Every scoper NARROWS, so pre-ticking can only reduce what the exception
    matches. The property that makes doing it unasked defensible at all."""
    from app.services import attack_carveout as ac
    with app.app_context():
        for exc_type in ('http_constraint_exception_item',
                         'signature_filter_item'):
            rec = ac.recommend(ROW, exc_type)
            wide = ac.build(ROW, exc_type, [])
            narrow = ac.build(ROW, exc_type, rec['picked'])
            assert len(narrow['payload']) >= len(wide['payload']), exc_type


def test_a_type_with_no_element_scope_recommends_nothing_and_says_so(app):
    from app.services import attack_carveout as ac
    with app.app_context():
        rec = ac.recommend(ROW, 'signature_disable_item')
    assert rec['picked'] == []
    assert 'no element scope' in rec['summary']


def test_an_entry_missing_the_subject_is_reported_not_silently_saved(app):
    """An Allow Method row with no method saves happily, applies, and unblocks
    nothing — with nothing anywhere saying why."""
    from app.services import attack_carveout as ac
    with app.app_context():
        rec = ac.recommend(dict(ROW, http_method=''),
                           'allow_method_exception_item')
    assert any(s['label'] == 'subject' for s in rec['skipped'])


def test_the_summary_names_what_was_ticked(app):
    from app.services import attack_carveout as ac
    with app.app_context():
        rec = ac.recommend(ROW, 'http_constraint_exception_item')
    assert 'URL' in rec['summary'] and 'Host' in rec['summary']


def test_the_panel_reads_the_recommendation_instead_of_re_deriving_it(app):
    """The browser used to decide the ticks itself. Two implementations of "what
    to select" agree the day they are written."""
    js = _read('app/static/js/attack_drawer.js')
    i = js.index('function autoTick()')
    fn = js[i:js.index('function refresh()', i)]
    assert 'recommended' in fn and 'picked' in fn


def test_the_panel_still_enforces_the_required_field_itself(app):
    """Floor, not duplication: a required scoper is what makes the exception
    valid at all, so a regressed server recommendation must leave the panel
    slightly wide, never invalid."""
    js = _read('app/static/js/attack_drawer.js')
    i = js.index('function autoTick()')
    fn = js[i:js.index('function refresh()', i)]
    assert 's.required' in fn


def test_the_options_endpoint_ships_the_recommendation_with_its_preview():
    view = _read('app/views/attack_search.py')
    assert "attack_carveout.recommend(" in view
    assert "rec['preview']" in view
