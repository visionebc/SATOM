"""Attack ID → the required scoper is ticked, not demanded.

The page knew three things the operator did not: which field FortiWeb keys this
kind of exception on, that the entry carried a value for it, and that leaving
it unticked produces no exception at all. It spent all three on an instruction
— *tick URL (/) in the Entry table above* — pointing at an unlabelled 14-pixel
checkbox in a twenty-two row table, in a different card, above the fold. An
operator who did not find it got the same refusal every time, phrased in device
schema keys they never typed.

So the panel ticks it. What is worth guarding is not that it happens but the
three properties that make it defensible:

* **Only fields that NARROW are ever pre-ticked.** Every scoper reduces what
  the exception matches, so ticking one unasked cannot widen a carve-out. A
  default that widened would need the operator's hand, and no argument here
  would justify it.
* **The tick is made where it can be seen.** In ``sel`` *and* in the checkbox.
  A page that posts a field it draws as unticked is worse than one that
  refuses, because the refusal is at least visible.
* **The hint reports what IS ticked, not what was meant to be.** It reads
  ``sel`` at render time. Those two agree until something goes wrong, and the
  case worth showing on screen is the one where they do not.
"""
from __future__ import annotations

import os
import re

import pytest

from test_attack_search import JS, VIEW, _code_only_py, _flat, _read, _no_comments_js

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: One entry with a value for every field a scoper can use.
ROW = {'msg_id': '1', 'main_type': 'Allow Method', 'sub_type': 'N/A',
       'policy': 'pol-shop-cms', 'http_url': '/a/b?x=1', 'http_host': 'h:80',
       'http_method': 'get', 'src': '192.0.2.7', 'signature_id': '12345',
       'signature_subclass': '9'}


def _between(src: str, start: str, end: str) -> str:
    """The slice from *start* up to *end*, both located literally.

    Bounded by the next construct rather than by a character count: a window of
    "the following N characters" starts swallowing the next function the day
    this one grows, and the guard quietly stops meaning what it says.
    """
    i = src.index(start)
    j = src.index(end, i + len(start))
    return src[i:j]


def _js() -> str:
    """The panel with comments stripped and string literals KEPT.

    ``_code_only`` would also remove the strings, and half of what is asserted
    below — a CSS selector, a sentence shown to the operator — exists only
    inside a string literal. A guard written against a string-stripped source
    passes without asserting anything, which has already happened twice in this
    suite.
    """
    return _no_comments_js(_read(JS))


def _auto_tick() -> str:
    return _between(_js(), 'function autoTick()', 'function refresh()')


def _hint() -> str:
    return _between(_js(), 'function scoperHintHtml(', 'function builderHtml(')


# --------------------------------------------------------------------------- #
#  1. the promise the pre-tick depends on                                      #
# --------------------------------------------------------------------------- #
def test_ticking_exactly_the_required_scopers_is_enough(app):
    """Every type that HAS required scopers validates when only those are
    picked.

    This is the whole premise: the panel ticks the required ones and stops. If
    some type needed a second, non-required field to validate, the operator
    would be handed a pre-ticked selection that still refuses — the old dead
    end, now with the appearance of having been dealt with.
    """
    from app.services import attack_carveout as ac

    checked = 0
    for exc_type, scopers in ac.SCOPERS.items():
        required = [s.row_key for s in scopers if s.required]
        if not required:
            continue
        checked += 1
        built = ac.build(ROW, exc_type, required)
        assert built['errors'] == [], (exc_type, built)
        assert built['payload'], exc_type
    assert checked >= 2, 'no type declares a required scoper — guard is vacuous'


def test_the_refusal_survives_for_the_operator_who_unticks(app):
    """Pre-ticking must not be the only thing standing between an empty
    selection and a save. Unticking is allowed, so the explanation that names
    the remedy has to still be there when someone does."""
    from app.services import attack_carveout as ac

    built = ac.build(ROW, 'allow_method_exception_item', [])
    assert built['errors'], 'an empty selection now validates'
    assert 'tick URL' in built['errors'][0]
    assert 'request-file' in built['errors'][0]


def test_a_required_scoper_the_entry_cannot_fill_is_not_a_tick_away(app):
    """When the entry carries no URL there is no row to tick, so no remedy
    naming a checkbox may be offered — that is the dead end, not the fix."""
    from app.services import attack_carveout as ac

    built = ac.build(dict(ROW, http_url=''), 'allow_method_exception_item', [])
    assert built['errors']
    assert not any('tick URL' in e for e in built['errors']), built['errors']


def test_the_browser_is_told_which_scoper_is_required_and_what_it_holds():
    """Both halves come off the server. ``required`` decides whether the panel
    ticks at all; ``value`` decides whether there is a row to tick. A panel
    inferring either from the field name would be a second copy of the schema."""
    from app.services import attack_carveout as ac

    scopers = ac.scopers_for('allow_method_exception_item')
    assert [s['row_key'] for s in scopers if s['required']] == ['http_url']
    src = _code_only_py(_read(VIEW))
    fn = _between(src, 'def carveout_options(', 'def build_carveout(')
    assert _flat("value=str(row.get(s['row_key']) or '')") in _flat(fn)


# --------------------------------------------------------------------------- #
#  2. what the panel ticks                                                     #
# --------------------------------------------------------------------------- #
def test_the_panel_ticks_the_required_scoper():
    js = _js()
    assert 'function autoTick()' in js
    fn = _auto_tick()
    assert 's.required' in fn
    assert 'sel[s.row_key] = true' in fn


def test_only_a_required_scoper_with_a_value_is_ticked():
    """Two conditions, and dropping either one breaks something different:
    without ``required`` the panel would choose the operator's scope for them,
    and without ``value`` it would tick a field the table above never drew."""
    fn = _auto_tick()
    guard = _between(fn, 'forEach(function (s) {', 'sel[s.row_key] = true')
    assert '!s.required' in guard
    assert '!s.value' in guard


def test_a_field_the_operator_already_chose_is_left_alone():
    fn = _auto_tick()
    guard = _between(fn, 'forEach(function (s) {', 'sel[s.row_key] = true')
    assert 'sel[s.row_key]' in guard, 'the tick is not idempotent'


def test_the_pre_tick_never_unticks_anything():
    """A pre-tick that could clear a box would be able to WIDEN a carve-out
    without being asked, which is the one thing this default cannot do and
    remain defensible."""
    fn = _auto_tick()
    assert '= false' not in fn.replace(' ', '').replace('=false', '= false')
    assert 'checked = false' not in fn


def test_the_tick_is_made_in_the_table_as_well_as_in_the_state():
    """`sel` is what gets posted; the checkbox is what the operator reads. A
    page that posts a field it draws as unticked has told them something
    untrue about a rule they are about to authorise."""
    fn = _auto_tick()
    assert ".atk-pick[data-atk-field=" in fn
    assert 'box.checked = true' in fn


def test_the_tick_is_re_evaluated_when_the_type_changes():
    """Each carve-out type keys on its own field, so a tick decided once at
    load is the wrong tick for every type but the first."""
    js = _js()
    wire = _between(js, 'function wireBuilder(', 'function wireBody(')
    handler = _between(wire, ".atk-type'), function (r)", 'preview.addEventListener')
    assert 'autoTick()' in handler
    assert 'refresh()' in handler
    # ...and once at load BEFORE the first render: the hint reports what is
    # ticked, so a render that ran first would say "not ticked" and would never
    # be corrected — no change event fires for a tick the panel made itself.
    boot = _between(wire, 'onPick = refresh;', 'Array.prototype.forEach.call')
    assert boot.index('autoTick()') < boot.index('refresh()')


# --------------------------------------------------------------------------- #
#  3. one writer of `sel`, and the hint reads it after the write               #
# --------------------------------------------------------------------------- #
def test_only_the_body_handler_and_the_pre_tick_write_the_selection():
    """Every other reader of `sel` is downstream of these two. A third writer
    is how the posted selection and the drawn checkboxes come apart."""
    js = _js()
    writes = re.findall(r'sel\[[^\]]+\] = ', js)
    assert len(writes) == 2, writes


def test_the_hint_is_redrawn_through_the_handler_that_owns_the_write():
    """Ordering, not taste. A `change` listener the builder attached itself
    would sit on a descendant of the body and therefore run BEFORE the handler
    that updates `sel` — rendering the selection as it stood one click ago —
    and would stack one more listener per open() on a node open() never
    replaces, which is the fault already recorded in ensureChrome()."""
    js = _js()
    assert js.count("addEventListener('change'") == 2, \
        'a listener was added or removed on the body'
    body_handler = _between(js, "body.addEventListener('change'", '});')
    assert body_handler.index('sel[pick.dataset.atkField] = pick.checked') < \
        body_handler.index('onPick()')


def test_the_redraw_hook_is_per_open_state():
    """Left set, a hook closed over the previous entry's hint node redraws a
    card that is no longer on screen."""
    js = _js()
    assert re.search(r'\n  var onPick = null;', js), 'not module state'
    open_fn = _between(js, 'function open(index)', 'function close(')
    assert 'onPick = null;' in open_fn
    assert 'onPick = refresh;' in _between(js, 'function wireBuilder(',
                                           'function wireBody(')


def test_the_hint_reports_the_selection_it_can_see():
    """Read from `sel`, not from "the builder ticked it". Those two agree
    until something goes wrong, which is exactly when the operator is
    reading it."""
    hint = _hint()
    # The CHIP specifically, not merely somewhere in the function: the missing
    # -required calculation also reads `sel`, so a whole-function search would
    # keep passing with the chip hard-wired to a constant.
    chip = _between(hint, "var state = ''", "h += '<li>")
    assert 'sel[s.row_key]' in chip
    assert '>ticked<' in chip


def test_the_page_claims_to_have_ticked_only_when_nothing_is_missing():
    """The claim is a statement about the current state, not about intent. An
    operator who unticks the box must not be told it is ticked."""
    hint = _hint()
    claim = 'SATOM has ticked'
    assert claim in hint
    branch = _between(hint, 'if (miss.length) {', claim)
    assert '} else if (' in branch, 'the claim is not gated on the state'
    assert 'tick ' in branch, 'the "still missing" wording was lost'


def test_a_required_field_absent_from_the_entry_is_not_reported_as_untickable():
    """No value means no row in the table above. Saying "tick it" sends the
    operator hunting for a checkbox that was never drawn — the same dead end
    this whole change exists to close, reached from the other side."""
    hint = _hint()
    assert 'not in this entry' in hint
    miss = _between(hint, 'var miss = ', ';')
    assert 's.value' in miss and '!sel[s.row_key]' in miss
    assert 'author this one from the Exceptions page' in hint


# --------------------------------------------------------------------------- #
#  4. tripwire — these guards read a source that still has its strings         #
# --------------------------------------------------------------------------- #
def test_the_guards_above_are_not_vacuous():
    """``_no_comments_js`` must keep string literals. If it ever stops, most
    of the assertions here would pass against an empty haystack rather than
    fail, and nothing else in the file would notice."""
    js = _js()
    assert "'.atk-pick[data-atk-field=\"'" in js or '.atk-pick[data-atk-field=' in js
    assert 'SATOM has ticked' in js, 'string literals were stripped'
    assert '// A required scoper is not' not in js, 'comments were kept'


@pytest.mark.parametrize('needle', [
    'function autoTick()', 'onPick', 'not in this entry', 'SATOM has ticked'])
def test_every_needle_exists_once_or_more(needle):
    assert _js().count(needle) >= 1, needle


# --------------------------------------------------------------------------- #
#  5. one boot, one binding                                                    #
# --------------------------------------------------------------------------- #
def test_the_result_table_is_bound_once_per_render():
    """boot() runs twice on a first load — this file registers on
    ``DOMContentLoaded``, ``turbo-boot.js`` remaps that to ``turbo:load``, and
    the file registers ``turbo:load`` as well for the body swap. Two click
    handlers on one table opened every entry twice: two reads of the entry off
    the appliance per click, two builder renders, and a redraw hook left
    pointing at whichever render lost the race."""
    js = _js()
    boot = _between(js, 'function boot()', 'if (document.readyState')
    assert js.count("table.addEventListener('click'") == 1
    guard = _between(boot, "getElementById('atk-results')",
                     "table.addEventListener('click'")
    assert 'dataset.atkBound' in guard
    assert 'return;' in guard, 'the flag is set but never checked'


def test_the_bind_flag_lives_on_the_table_not_on_the_window():
    """Turbo replaces the body on every visit, so the table is new each time
    and binds again. A flag on ``window`` would bind once per browser session
    and leave every visit after the first with a dead result table."""
    js = _js()
    guard = _between(js, "getElementById('atk-results')",
                     "table.addEventListener('click'")
    assert 'window.' not in guard, guard
    assert 'table.dataset.atkBound' in guard
