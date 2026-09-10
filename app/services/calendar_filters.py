"""Change Calendar filters — what the grid DRAWS, and what it remembers.

Pure: no Flask, no DB, no request. :func:`resolve` takes the query string, the
saved preference blob and nothing else, and returns the two facets the grid
draws by plus everything the page needs to be honest about what it is hiding.

WHY THIS IS NOT ``automation_filters``
--------------------------------------
The two Automation surfaces have a ``scope`` facet that can only ever WIDEN a
page (draw the other surface's rows read-only), because there the split is a
PERMISSION boundary and a preference may not move one. The calendar owns no
half: it already draws every automation the ADOM can see. Its ``owner`` facet
therefore NARROWS — 'show me only the fleet work I scheduled', 'show me only
what SATOM does to itself'. Same word, opposite direction, so it is a separate
resolver rather than a fifth branch of that one. The key convention IS shared
(``automation_filters.pref_key``): one author for "where a surface saves its
filter" is what stops two pages writing the same row.

THE OWNER VOCABULARY IS NOT THIS MODULE'S
-----------------------------------------
:data:`OWNERS` are the exact strings ``views.scheduled_actions.effective_scope``
returns. They are restated here only so this module stays importable without a
view; ``tests/test_calendar_filter.py`` asserts the two agree. A calendar that
filtered on 'admin' while the splitter answered 'system' would draw an empty
band and blame the fleet.

A FILTER MUST NEVER SILENTLY EMPTY THE GRID
-------------------------------------------
An automation keeps FIRING whether or not a calendar draws it, so a day cell
that is blank because of a filter and a day cell that is blank because nothing
is scheduled are one pixel apart and an order of magnitude apart in
consequence. Two rules follow:

* A facet that validates down to NOTHING falls back to everything and says so
  (:attr:`Resolved.stale`) — never to an empty set, which would render a quiet
  month over a fleet mid-cutover.
* The caller must render the counts (:func:`counts_note`), so "3 of 11 drawn"
  is on screen whenever anything is hidden.

ONLY A STRICT SUBSET IS STORED
------------------------------
Pressing *Remember* while everything is shown writes ``{}``, not the three kinds
spelled out. A stored explicit list freezes the vocabulary: ship a fourth event
kind and every user who ever pressed Remember would have it hidden forever, with
no clue on screen and no facet to un-tick. Absent means "all", today and after
the vocabulary grows.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import calendar_plan as cal

#: Automation owners, as ``scheduled_actions.effective_scope`` names them.
OWNERS: tuple[str, ...] = ('user', 'admin')

#: Owner assumed for a run whose action row is gone. Mirrors
#: ``views.calendar._owner_endpoint``: the history link for an orphan run points
#: at the system surface, so filtering it into the user band would draw an event
#: whose own link leads somewhere the band says it is not.
ORPHAN_OWNER = 'admin'

#: Hidden marker every filter control on the page carries.
#:
#: The calendar's controls are LINKS, not a form, so "the user chose to see only
#: changes" arrives as ``?kind=change`` and a bare visit arrives as nothing —
#: but a link that turns the last owner back on arrives as the full set, which
#: is byte-identical to a bare visit once normalised. Without this marker that
#: click would fall through to "restore the saved filter" and the filter the
#: user just widened would come straight back.
MARKER = 'f'

FACET_LABELS: dict[str, str] = {
    'kind': 'event type',
    'owner': 'automation owner',
}


def all_kinds() -> set:
    """A NEW set every call — a shared constant would be mutated by the first
    caller that edits its own selection and leak into every later request."""
    return set(cal.KINDS)


def all_owners() -> set:
    return set(OWNERS)


@dataclass
class Resolved:
    """The outcome of resolving the calendar filter for one request."""

    kinds: set = field(default_factory=all_kinds)
    owners: set = field(default_factory=all_owners)
    #: True when the ACTIVE filter is the one stored on the user's profile.
    saved: bool = False
    #: ``(facet_label, value)`` for every value dropped because the vocabulary
    #: no longer offers it, plus ``(facet_label, '')`` when a facet validated
    #: down to nothing and was widened back to all.
    stale: list = field(default_factory=list)
    #: The saved blob existed and could not be read at all.
    unreadable: bool = False
    #: This filter came from the query string, not the store. The caller needs
    #: it to FORGET a stored filter when the user filters without Remember:
    #: leaving it stored resurrects it on the next visit and contradicts the
    #: choice just made.
    from_query: bool = False

    @property
    def active(self) -> bool:
        """Is anything being hidden? Computed from the values, never carried as
        a flag a future facet could forget to set."""
        return self.kinds != all_kinds() or self.owners != all_owners()

    @property
    def draws_automations(self) -> bool:
        return 'automation' in self.kinds or 'run' in self.kinds


def _picked(raw, vocabulary: set, label: str, stale: list) -> set:
    """Validate one multi-valued facet. Unknown values are NAMED, not ignored:
    a saved facet naming a retired kind would match nothing on every future
    visit, and the page would read as a fleet with nothing scheduled."""
    out: set = set()
    for value in (raw or ()):
        value = value.strip() if isinstance(value, str) else ''
        if not value:
            continue
        if value in vocabulary:
            out.add(value)
        else:
            stale.append((FACET_LABELS[label], value))
    return out


def _was_named(raw, empty_is_all: bool) -> bool:
    """Did this facet get NAMED and then validate down to nothing?

    Three inputs look alike at the point of widening and mean different things:

    * a query string that never mentioned the facet — a bare visit, or a link
      carrying only the other facet. Means "all". Never a note.
    * a STORED blob that never mentioned it. Also means "all": that is the
      strict-subset convention :func:`to_json` writes by, so an owner-only blob
      is the ORDINARY shape of a working saved filter. Never a note — saying
      "part of your saved filter no longer exists" on every visit of a filter
      that is doing its job is how a page teaches its own banner to be ignored,
      and the banner is the only thing that will ever explain the real case.
    * a stored blob that named values which are ALL gone from the vocabulary.
      That user's saved choice really was dropped, the grid really is wider
      than they asked for, and nothing else on screen says so.

    ``raw is None`` is the discriminator, so it must survive the call: passing
    ``data.get('kind')`` straight through is deliberate, and a caller that
    normalises an absent facet to ``[]`` first would resurrect the false banner.
    """
    return not empty_is_all and raw is not None


def _resolve_facets(kind_raw, owner_raw, *, empty_is_all: bool) -> tuple:
    stale: list = []
    kinds = _picked(kind_raw, set(cal.KINDS), 'kind', stale)
    owners = _picked(owner_raw, set(OWNERS), 'owner', stale)
    if not kinds:
        if _was_named(kind_raw, empty_is_all):
            stale.append((FACET_LABELS['kind'], ''))
        kinds = all_kinds()
    if not owners:
        if _was_named(owner_raw, empty_is_all):
            stale.append((FACET_LABELS['owner'], ''))
        owners = all_owners()
    return kinds, owners, stale


def resolve(args, saved_raw) -> Resolved:
    """Resolve the calendar filter for one request.

    Precedence, matching ``automation_filters.resolve`` so the product has ONE
    protocol for "a filter you can save":

    * ``clear``            -> forget the saved filter, draw everything;
    * :data:`MARKER`, ``save`` or any facet in the query string -> the query
      string IS the filter, and ``save`` writes it to the profile;
    * otherwise            -> the saved filter, if any.

    ``args`` is anything with ``get`` and ``getlist`` (Flask's MultiDict, or a
    plain double). ``saved_raw`` is the raw ``UserSetting`` value or None.
    """
    def _one(name):
        value = args.get(name)
        return value.strip() if isinstance(value, str) else ''

    if _one('clear'):
        return Resolved(saved=False)

    kind_raw = list(args.getlist('kind'))
    owner_raw = list(args.getlist('owner'))
    if kind_raw or owner_raw or _one(MARKER) or _one('save'):
        kinds, owners, stale = _resolve_facets(kind_raw, owner_raw,
                                               empty_is_all=True)
        # A filter typed THIS request is not "saved" merely because it equals
        # the stored one: ``saved`` describes the store, and it is what the
        # badge and the checkbox claim.
        return Resolved(kinds=kinds, owners=owners, saved=bool(_one('save')),
                        stale=stale, from_query=True)

    if not saved_raw:
        return Resolved(saved=False)
    try:
        data = json.loads(saved_raw)
    except (ValueError, TypeError):
        return Resolved(saved=False, unreadable=True)
    if not isinstance(data, dict):
        return Resolved(saved=False, unreadable=True)

    kinds, owners, stale = _resolve_facets(data.get('kind'), data.get('owner'),
                                           empty_is_all=False)
    got = Resolved(kinds=kinds, owners=owners, stale=stale)
    # ``saved`` is False for a blob that survived validation with nothing left:
    # the profile holds a filter that no longer hides anything, and a "saved"
    # badge over an unfiltered grid claims a state the user cannot see.
    got.saved = got.active
    return got


def to_json(kinds, owners) -> str:
    """Serialise for the store, keeping only STRICT SUBSETS. See the module
    docstring: an explicit "all" freezes the vocabulary against its own future."""
    blob: dict = {}
    kinds = set(kinds or ())
    owners = set(owners or ())
    if kinds and kinds != all_kinds():
        blob['kind'] = sorted(kinds)
    if owners and owners != all_owners():
        blob['owner'] = sorted(owners)
    return json.dumps(blob, sort_keys=True)


def owner_of(action, *, scope_of) -> str:
    """The owner band ``action`` belongs to; :data:`ORPHAN_OWNER` when the row
    is gone. ``scope_of`` is injected so this module never imports a view."""
    if action is None:
        return ORPHAN_OWNER
    got = scope_of(action)
    return got if got in OWNERS else ORPHAN_OWNER


def counts_note(drawn: int, total: int, noun: str) -> str:
    """The sentence that keeps a filtered band from reading as an empty one.

    Returns '' when nothing is hidden — a page that says "showing 8 of 8" on
    every visit trains the eye to skip the line that matters.
    """
    if total <= drawn:
        return ''
    return (f'{drawn} of {total} {noun} drawn — {total - drawn} hidden by the '
            f'filter, and they still fire.')
