"""Automation list filters — what a surface SHOWS, and what it remembers.

One author for both Automation surfaces (``/automations`` and
``/scheduled-actions``). Pure: no Flask, no DB, no request. The view hands in
the query string, the saved preference blob and the catalog's live choices, and
gets back a resolved filter plus everything the page needs to be honest about
what it is hiding.

WHY THIS IS NOT THE SPLIT, AND MAY NEVER BECOME IT
--------------------------------------------------
A filter is a VIEW preference; the split between the two surfaces is a
PERMISSION boundary. They look alike on screen and are not the same object: a
row hidden by a filter is one the viewer may still edit by typing its URL, and a
preference row in ``user_settings`` is not an access-control decision. So the
scope facet below can only ever WIDEN what a page draws, never widen what it
lets anyone do, and it is offered only to a viewer who already holds the other
surface's permission (``allow_cross``). Rows it reveals are drawn read-only and
link to the page that owns them — see ``row_is_foreign``.

A FILTER MUST NEVER SILENTLY EMPTY A LIST
-----------------------------------------
This module exists inside a subsystem whose entire premise (see
``app/views/scheduled_actions.py``) is that a scheduled row keeps FIRING whether
or not any page draws it. An empty page that means "nothing matches your filter"
and an empty page that means "you have no automations" are one pixel apart and
an order of magnitude apart in consequence. Hence ``Resolved.active`` and the
caller's obligation to render the filtered-empty state differently from the
never-created one, and hence:

STALE FACETS ARE NAMED, NOT APPLIED
-----------------------------------
A saved filter naming an action key the catalog no longer has (an ActionSpec
retired between visits) would match nothing on every future visit, forever, with
no clue on screen — the user would conclude their automations were deleted. Such
a facet is DROPPED and reported in ``Resolved.stale`` so the page can say which
one and why. Same for a corrupted blob: silently reading it as blank is fine for
the rows, but the user must be told their saved filter is gone.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

#: Facet -> the query-string argument and preference key it is stored under.
#: ``q`` is a substring of the name; the rest are exact matches against a
#: closed set the caller supplies from the live catalog.
FACETS: tuple[str, ...] = ('q', 'action', 'status', 'schedule', 'scope')

#: The only values ``status`` accepts. '' means "any", which is NOT the same as
#: matching nothing — an unknown value is a stale facet, not an empty list.
STATUS_CHOICES: tuple[str, ...] = ('enabled', 'disabled')

#: The only values ``scope`` accepts. '' = this surface only (the default, and
#: what a viewer without the other permission always gets); 'all' = draw the
#: other surface's rows too, read-only.
SCOPE_ALL = 'all'

#: Hidden marker the filter form submits so an all-empty submission is
#: distinguishable from no submission at all.
#:
#: A GET form sends every named field, so clearing every box produces
#: ``?q=&action=&status=&schedule=`` — which, once trimmed, is indistinguishable
#: from a bare visit. Without this marker "clear the boxes and press Filter"
#: falls through to "restore the saved filter", and the filter the user just
#: emptied comes straight back. Found by the guard, not by reading the code.
SUBMIT_MARKER = 'submitted'

#: Human labels for the stale report. A refusal that does not name the facet
#: leaves the user re-picking every field to find which one went bad.
FACET_LABELS: dict[str, str] = {
    'q': 'name',
    'action': 'action type',
    'status': 'status',
    'schedule': 'schedule',
    'scope': 'scope',
}


def blank() -> dict:
    """A fresh, everything-shown filter. Returned as a NEW dict every call:
    a shared module-level constant would be mutated by the first caller that
    edits its own filter and would then leak into every other request."""
    return {k: '' for k in FACETS}


def pref_key(blueprint: str) -> str:
    """The ``UserSetting`` key this surface saves under.

    Keyed by BLUEPRINT, not by the module: one shared key would mean saving
    "only disabled ones" while triaging System Automations also silently
    re-filters the operator's own Automations page, which is a change to a page
    the user was not looking at.
    """
    return f'{blueprint}.filters'


@dataclass
class Resolved:
    """The outcome of resolving a filter for one request."""

    #: facet -> value, every key in FACETS present, '' meaning "any".
    filters: dict = field(default_factory=blank)
    #: True when the ACTIVE filter is the one stored on the user's profile.
    saved: bool = False
    #: Facets dropped because their saved value is no longer offered, as
    #: ``(facet_label, value)``. Empty on the happy path.
    stale: list = field(default_factory=list)
    #: True when the saved blob existed but could not be read at all.
    unreadable: bool = False
    #: True when this filter came from the query string rather than the store.
    #: The caller needs it to FORGET a stored filter when the user submits with
    #: "remember" unticked: leaving it stored resurrects it on the next visit
    #: and silently contradicts the box they just cleared.
    from_query: bool = False

    @property
    def active(self) -> bool:
        """Is anything being hidden? Drives the "showing N of M" banner and the
        filtered-empty state. Computed from the values, never tracked as a
        separate flag that a future facet could forget to set."""
        return any(self.filters.get(k) for k in FACETS)

    @property
    def cross_scope(self) -> bool:
        """Is this filter asking for the other surface's rows as well?"""
        return self.filters.get('scope') == SCOPE_ALL


def _clean(value) -> str:
    return (value or '').strip() if isinstance(value, str) else ''


def _choices(choices: dict) -> dict:
    """Normalise the caller's closed sets, defaulting the ones it did not pass.

    ``status`` and ``scope`` are this module's own vocabulary and are NOT taken
    from the caller: a view that forgot to pass them would otherwise silently
    accept any string and hand it to the matcher, which would match nothing.
    """
    out = {
        'action': set(choices.get('action') or ()),
        'schedule': set(choices.get('schedule') or ()),
        'status': set(STATUS_CHOICES),
        'scope': {SCOPE_ALL},
    }
    return out


def _validate(raw: dict, choices: dict, *, allow_cross: bool) -> tuple[dict, list]:
    """Keep the facets whose values are still offered; name the ones that are not.

    ``q`` is free text and can never be stale. A ``scope`` of 'all' from a
    viewer without the other permission is dropped SILENTLY, not reported: it is
    not a stale catalog entry, it is a request this viewer may not make, and
    telling them which page they cannot see is a disclosure the split exists to
    avoid.
    """
    flt = blank()
    stale: list = []
    for facet in FACETS:
        value = _clean(raw.get(facet))
        if not value:
            continue
        if facet == 'q':
            flt[facet] = value
            continue
        if facet == 'scope' and not allow_cross:
            continue
        if value in choices[facet]:
            flt[facet] = value
        else:
            stale.append((FACET_LABELS[facet], value))
    return flt, stale


def resolve(args, saved_raw, *, choices: dict, allow_cross: bool = False) -> Resolved:
    """Resolve the filter for one request.

    Precedence, matching the ``provisioning.baselines`` precedent so there is
    one protocol in the product for "a filter you can save":

    * ``clear``  -> forget the saved filter and show everything;
    * any facet in the query string (or ``save``) -> that is the active filter,
      and ``save`` writes it to the profile;
    * otherwise  -> the saved filter, if any.

    ``saved_raw`` is the raw ``UserSetting`` value (or None). The caller does
    the writing: this module stays pure so it can be tested against a saved blob
    that no store would ever produce, which is exactly the case that breaks it.
    """
    sets = _choices(choices)
    if _clean(args.get('clear')):
        return Resolved(filters=blank(), saved=False)

    from_query = (any(_clean(args.get(f)) for f in FACETS)
                  or bool(_clean(args.get('save')))
                  or bool(_clean(args.get(SUBMIT_MARKER))))
    if from_query:
        flt, stale = _validate({f: args.get(f) for f in FACETS}, sets,
                               allow_cross=allow_cross)
        # A filter typed THIS request is not "saved to profile" merely because
        # it happens to equal the stored one; ``saved`` means the badge and the
        # checkbox, and both describe the store, not the query string.
        return Resolved(filters=flt, saved=bool(_clean(args.get('save'))),
                        stale=stale, from_query=True)

    if not saved_raw:
        return Resolved(filters=blank(), saved=False)
    try:
        data = json.loads(saved_raw)
    except (ValueError, TypeError):
        return Resolved(filters=blank(), saved=False, unreadable=True)
    if not isinstance(data, dict):
        return Resolved(filters=blank(), saved=False, unreadable=True)

    flt, stale = _validate(data, sets, allow_cross=allow_cross)
    # ``saved`` is False for a stored blob that survived validation with nothing
    # left: the profile holds a filter that no longer selects anything, and
    # claiming it is active would put a "saved" badge over an unfiltered list.
    return Resolved(filters=flt, saved=any(flt.values()), stale=stale)


def to_json(flt: dict) -> str:
    """Serialise a resolved filter for the store, dropping empty facets.

    Empty facets are omitted rather than stored as '': a stored '' is
    indistinguishable from a facet that did not exist when the blob was written,
    and the difference decides whether a NEW facet defaults to "any" or to
    whatever the old blob implies.
    """
    return json.dumps({k: v for k, v in flt.items() if v}, sort_keys=True)


def row_matches(row: dict, flt: dict, *, surface_scope: str) -> bool:
    """Does ``row`` survive ``flt`` on a surface owning ``surface_scope``?

    ``row`` needs: ``scope``, ``action_key``, ``enabled``, ``schedule_kind``,
    ``name``. The scope test comes FIRST and is the only one that is not a
    user preference: without the cross-scope facet a surface draws its own half
    and nothing else, which is the partition the two blueprints rest on.
    """
    if row.get('scope') != surface_scope and flt.get('scope') != SCOPE_ALL:
        return False
    q = flt.get('q')
    if q and q.casefold() not in (row.get('name') or '').casefold():
        return False
    action = flt.get('action')
    if action and row.get('action_key') != action:
        return False
    status = flt.get('status')
    if status and (status == 'enabled') != bool(row.get('enabled')):
        return False
    schedule = flt.get('schedule')
    if schedule and row.get('schedule_kind') != schedule:
        return False
    return True


def row_is_foreign(row: dict, *, surface_scope: str) -> bool:
    """Is this a row the cross-scope facet revealed, that this page does NOT own?

    Such a row must be drawn read-only and linked to its owning page. Its Edit /
    Run / Delete controls on THIS page resolve to this blueprint, whose by-id
    guard 404s them — buttons that look armed and answer "gone" are worse than
    no buttons, because the operator concludes the automation was deleted.
    """
    return row.get('scope') != surface_scope
