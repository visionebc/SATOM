"""Change Calendar filter — ONE list of the things the grid draws.

Pure: no Flask, no DB, no request. :func:`resolve` takes the query string, the
saved preference blob and nothing else.

WHY THERE IS ONLY ONE FACET
---------------------------
There used to be two — an event-family facet (``kind``) and an automation-owner
facet (``owner``) — and together they printed the word "Automations" four times
in one bar with three different meanings: a family chip *Automations
(upcoming)*, a group label *Automations:*, and an owner chip *Automations
(fleet work)* sitting next to *System Automations*. Two independent facets also
multiply: ``kind=change&owner=user`` is a legal URL in which the owner half
decides nothing, so the bar offered states that do not exist.

A filter bar is a list of the things a page can draw. This one now IS that
list, in the order the product names them:

    Planned changes · Automations · System Automations · What already ran

:data:`OWNER_OF_BAND` is the whole of what used to be the owner facet: the two
automation bands ARE the two Automation surfaces, so the split the product
rests on is drawn once, by name, instead of being a second axis the reader has
to multiply out.

HISTORY FOLLOWS ITS GROUP
-------------------------
``run`` is a TIME switch, not a fourth kind of thing: it decides whether the
past is painted at all, and the past it paints is the past of the bands that
are on. A calendar that hides *System Automations* and still draws their runs
is drawing the history of something it just said is not there.

The consequence is deliberate and has to be SAID rather than rendered: with
both automation bands off, ``run`` alone draws nothing, so
:func:`history_orphan_note` puts that sentence on the page. An empty band that
explains itself is a filter; one that does not is a fleet that looks idle.

A FILTER MUST NEVER SILENTLY EMPTY THE GRID
-------------------------------------------
An automation keeps FIRING whether or not a calendar draws it, so a day cell
blank because of a filter and a day cell blank because nothing is scheduled are
one pixel apart and an order of magnitude apart in consequence. Three rules:

* At least one :data:`PRIMARY` band is always on — the caller locks the
  checkbox of the last one, and :func:`resolve` falls back to the default view
  if a request arrives with none. A wholly empty grid is therefore
  not reachable through this filter at all.
* A facet that validates down to NOTHING falls back to the default and says so
  (:attr:`Resolved.stale`) — never to an empty set.
* The caller prints what each unticked band holds back (:func:`hidden_label`)
  next to its checkbox, so a hidden band is never a silent one.

SYSTEM AUTOMATIONS ARE OFF BY DEFAULT (2026-10-23)
--------------------------------------------------
The product's own housekeeping (backups, sweeps, scrapes) fires every few
minutes and buried the fleet work an operator opens the calendar to plan. The
default view is therefore :data:`DEFAULT_OFF` hidden, and the band is switched
on with its checkbox. Hidden is not absent: the bar prints how many automations
and runs each unticked band is holding back (``band_hidden`` in the view), so a
quiet grid still says what it is not drawing.

EVERY CHANGE IS SAVED — AND WHAT IS STORED IS WHAT IS HIDDEN
------------------------------------------------------------
The bar is a row of checkboxes and every tick is written to the profile; there
is no separate *Remember* step. The store holds ``{"hide": [...]}`` relative to
the full vocabulary, or ``{}`` for the default. Storing the HIDDEN list, never
the shown one, is what keeps the vocabulary open: ship a fifth band and every
user sees it, because nobody ever hid it. A stored explicit "show" list (the
pre-2026-10-23 shape) is still read.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

#: Everything the grid can draw, in the order the bar lists it.
BANDS: tuple[str, ...] = ('change', 'automation', 'system', 'run')

#: The bands that carry the grid. One of these is always on; see the module
#: docstring. ``run`` is excluded because it is a time switch: turning it off
#: is a meaningful state, turning the last of THESE off is an empty month.
PRIMARY: tuple[str, ...] = ('change', 'automation', 'system')

#: The band that paints the past, scoped by whichever automation bands are on.
HISTORY = 'run'

#: band -> the ``scheduled_actions.effective_scope`` string it draws.
#:
#: These are the exact strings the splitter returns; ``tests/
#: test_calendar_filter.py`` asserts the two agree. A calendar that filtered on
#: 'admin' while the splitter answered 'system' would draw an empty band and
#: blame the fleet.
OWNER_OF_BAND: dict[str, str] = {'automation': 'user', 'system': 'admin'}

#: Owner assumed for a run whose action row is gone. Mirrors
#: ``views.calendar._owner_endpoint``: the history link for an orphan run points
#: at the system surface, so drawing it in the fleet-work band would paint an
#: event whose own link leads somewhere the band says it is not.
ORPHAN_OWNER = 'admin'

#: Hidden marker every filter control on the page carries.
#:
#: The calendar's controls are LINKS, not a form, so "show me only changes"
#: arrives as ``?show=change`` and a bare visit arrives as nothing — but a link
#: that turns the last band back on arrives as the full set, which is
#: byte-identical to a bare visit once normalised. Without this marker that
#: click would fall through to "restore the saved filter" and the filter the
#: user just widened would come straight back.
MARKER = 'f'

FACET_LABEL = 'calendar band'

#: Retired facets, and how a value of each maps into :data:`BANDS`. Kept so a
#: blob or a bookmark written under the two-facet bar TRANSLATES instead of
#: being reported stale: telling a user "part of your saved filter no longer
#: exists" because *we* renamed the vocabulary is a banner that blames them for
#: our change, and it is the only banner that will ever explain the real case.
_LEGACY_KIND = {'change': 'change', 'run': 'run'}
_LEGACY_OWNER = {'user': 'automation', 'admin': 'system'}


#: Bands a user who never touched the bar does not see. See the module
#: docstring; the bar still counts what these hold back.
DEFAULT_OFF: tuple[str, ...] = ('system',)


def all_bands() -> set:
    """A NEW set every call — a shared constant would be mutated by the first
    caller that edits its own selection and leak into every later request."""
    return set(BANDS)


def default_bands() -> set:
    """What a bare visit with nothing stored draws. A new set every call, for
    the same reason as :func:`all_bands`."""
    return set(BANDS) - set(DEFAULT_OFF)


def owners_for(bands) -> set:
    """The automation owners the given bands draw. Empty means no automation
    band is on, which is also what makes :data:`HISTORY` draw nothing."""
    return {OWNER_OF_BAND[b] for b in bands if b in OWNER_OF_BAND}


@dataclass
class Resolved:
    """The outcome of resolving the calendar filter for one request."""

    bands: set = field(default_factory=default_bands)
    #: True when the ACTIVE filter is stored on the user's profile — read from
    #: it, or submitted this request (every submission is saved).
    saved: bool = False
    #: ``(facet_label, value)`` for every value dropped because the vocabulary
    #: no longer offers it, plus ``(facet_label, '')`` when the facet validated
    #: down to nothing and fell back to the default.
    stale: list = field(default_factory=list)
    #: The saved blob existed and could not be read at all.
    unreadable: bool = False
    #: This filter came from the query string, not the store — the caller
    #: writes it to the profile.
    from_query: bool = False

    @property
    def active(self) -> bool:
        """Does this differ from the default view? Computed from the values,
        never carried as a flag a future band could forget to set."""
        return self.bands != default_bands()

    @property
    def owners(self) -> set:
        return owners_for(self.bands)

    @property
    def draws_changes(self) -> bool:
        return 'change' in self.bands

    @property
    def draws_automations(self) -> bool:
        return bool(self.owners)

    @property
    def draws_runs(self) -> bool:
        """History is drawn only where there is a band to hang it on."""
        return HISTORY in self.bands and bool(self.owners)


def _picked(raw, stale: list) -> set:
    """Validate the facet. Unknown values are NAMED, not ignored: a saved band
    naming something retired would match nothing on every future visit, and the
    page would read as a fleet with nothing scheduled."""
    out: set = set()
    for value in (raw or ()):
        value = value.strip() if isinstance(value, str) else ''
        if not value:
            continue
        if value in BANDS:
            out.add(value)
        else:
            stale.append((FACET_LABEL, value))
    return out


def _from_legacy(kind_raw, owner_raw, stale: list) -> set:
    """Translate the retired ``kind`` + ``owner`` pair into bands.

    Absent means "all" on BOTH sides, exactly as the old resolver read them, so
    ``?kind=automation`` alone still means both automation groups.
    """
    kinds = list(kind_raw or ())
    owners = list(owner_raw or ())
    out: set = set()
    for value in kinds:
        value = value.strip() if isinstance(value, str) else ''
        if not value:
            continue
        if value in _LEGACY_KIND:
            out.add(_LEGACY_KIND[value])
        elif value == 'automation':
            pass          # expanded below, once, by owner
        else:
            stale.append((FACET_LABEL, value))
    wants_auto = (not kinds) or any(
        (v.strip() if isinstance(v, str) else '') == 'automation' for v in kinds)
    if not kinds:
        out |= {'change', 'run'}
    if wants_auto:
        if owners:
            for value in owners:
                value = value.strip() if isinstance(value, str) else ''
                if not value:
                    continue
                if value in _LEGACY_OWNER:
                    out.add(_LEGACY_OWNER[value])
                else:
                    stale.append((FACET_LABEL, value))
        else:
            out |= {'automation', 'system'}
    return out


def _resolve_bands(raw, legacy, *, empty_is_all: bool) -> tuple:
    """Validate, then guarantee the invariant the whole page rests on.

    ``legacy`` is ``(kind_raw, owner_raw)`` or None. It is consulted only when
    the current facet was not named at all, so a request that carries both
    speaks the new vocabulary and the old one is ignored rather than merged —
    merging two vocabularies is how a chip stops meaning what it says.
    """
    stale: list = []
    named = raw is not None
    bands = _picked(raw, stale)
    if not named and legacy is not None and (legacy[0] or legacy[1]):
        named = True
        bands = _from_legacy(legacy[0], legacy[1], stale)
    return _guard(bands, stale, named=named, empty_is_default=empty_is_all)


def _guard(bands: set, stale: list, *, named: bool,
           empty_is_default: bool) -> tuple:
    """The invariant every path ends in: at least one PRIMARY band is on."""
    if not bands:
        # Named and validated down to nothing: the user's choice really was
        # dropped, the grid is not what they asked for, and nothing else on
        # screen says so. A facet that was never named just means the default.
        if named and not empty_is_default:
            stale.append((FACET_LABEL, ''))
        return default_bands(), stale
    if not (bands & set(PRIMARY)):
        # Only the history switch survived. Drawing that alone is an empty
        # month; fall back to the default and say so rather than paint the
        # fleet idle. Unreachable from the bar (the last primary checkbox is
        # locked), so this is for hand-typed URLs and blobs from elsewhere.
        stale.append((FACET_LABEL, ''))
        return default_bands(), stale
    return bands, stale


def resolve(args, saved_raw) -> Resolved:
    """Resolve the calendar filter for one request.

    Precedence:

    * ``clear``            -> forget the saved filter, draw the default;
    * :data:`MARKER`, ``save`` or the facet in the query string -> the query
      string IS the filter, and the caller writes it to the profile (every
      submission is saved — the bar has no separate *Remember* step);
    * otherwise            -> the saved filter, or the default.

    ``args`` is anything with ``get`` and ``getlist`` (Flask's MultiDict, or a
    plain double). ``saved_raw`` is the raw ``UserSetting`` value or None.
    """
    def _one(name):
        value = args.get(name)
        return value.strip() if isinstance(value, str) else ''

    if _one('clear'):
        return Resolved(saved=False)

    raw = list(args.getlist('show'))
    legacy = (list(args.getlist('kind')), list(args.getlist('owner')))
    if raw or legacy[0] or legacy[1] or _one(MARKER) or _one('save'):
        bands, stale = _resolve_bands(raw or None, legacy, empty_is_all=True)
        return Resolved(bands=bands, saved=True, stale=stale, from_query=True)

    if not saved_raw:
        return Resolved(saved=False)
    try:
        data = json.loads(saved_raw)
    except (ValueError, TypeError):
        return Resolved(saved=False, unreadable=True)
    if not isinstance(data, dict):
        return Resolved(saved=False, unreadable=True)

    if 'hide' in data:
        # The current shape. A hidden value the vocabulary no longer offers
        # hides nothing, so it is dropped in silence — there is no band on
        # screen it could be wrongly hiding.
        hide = data.get('hide')
        if not isinstance(hide, list):
            return Resolved(saved=False, unreadable=True)
        bands, stale = _guard(all_bands() - {str(h) for h in hide}, [],
                              named=True, empty_is_default=False)
        got = Resolved(bands=bands, stale=stale)
        got.saved = got.active
        return got

    # ``data.get('show')`` is passed through UNNORMALISED on purpose: ``None``
    # (this blob predates the facet, or stores nothing) and ``[]`` (this blob
    # named values that are all gone) are the discriminator between a working
    # saved filter and one that really was dropped. A caller that turned an
    # absent facet into an empty list would print the stale banner on every
    # visit of a filter that is doing its job, and a page that cries wolf on
    # every visit teaches the eye to skip the line that matters.
    bands, stale = _resolve_bands(data.get('show'),
                                  (data.get('kind'), data.get('owner')),
                                  empty_is_all=False)
    got = Resolved(bands=bands, stale=stale)
    # ``saved`` is False for a blob that survived validation with nothing left:
    # the profile holds a filter that no longer hides anything, and a "saved"
    # badge over an unfiltered grid claims a state the user cannot see.
    got.saved = got.active
    return got


def to_json(bands) -> str:
    """Serialise for the store: ``{}`` for the default view, otherwise the
    HIDDEN bands. See the module docstring: storing what is shown would freeze
    the vocabulary and hide every band shipped after the user's last click.
    ``{"hide": []}`` is a real value — "show everything, System Automations
    included" — and must not collapse into ``{}``, which means the default.
    """
    bands = set(bands or ()) & all_bands()
    if not bands or bands == default_bands():
        return json.dumps({}, sort_keys=True)
    return json.dumps({'hide': sorted(all_bands() - bands)}, sort_keys=True)


def toggled(bands, band: str) -> list:
    """The band set a chip's link should carry, or [] when the chip must not
    toggle.

    Returning [] is how the caller renders a chip that cannot be switched off:
    the last :data:`PRIMARY` band standing. Deciding that HERE rather than in
    the template is what keeps the rule and the invariant in
    :func:`_resolve_bands` from drifting into two authors.
    """
    bands = set(bands or ())
    if band not in bands:
        return sorted(bands | {band})
    left = bands - {band}
    if band in PRIMARY and not (left & set(PRIMARY)):
        return []
    return sorted(left)


def owner_of(action, *, scope_of) -> str:
    """The owner band ``action`` belongs to; :data:`ORPHAN_OWNER` when the row
    is gone. ``scope_of`` is injected so this module never imports a view."""
    if action is None:
        return ORPHAN_OWNER
    got = scope_of(action)
    return got if got in set(OWNER_OF_BAND.values()) else ORPHAN_OWNER


def hidden_label(automations: int, runs: int) -> str:
    """What an unticked band is holding back, printed next to its checkbox.

    Replaces the old "N of M drawn" banners: with System Automations hidden by
    default a banner would print on every visit, and a line that is always
    there teaches the eye to skip it. Next to the checkbox it is where the eye
    already is. '' when the band holds nothing back.
    """
    parts = []
    if automations:
        parts.append(f'{automations} hidden')
    if runs:
        parts.append(f'{runs} run{"s" if runs != 1 else ""}')
    return ' · '.join(parts)


def history_orphan_note(bands) -> str:
    """Said when the history switch is on but has no band to hang history on.

    This is the one state the collapse into a single list makes reachable, and
    it renders as a month with no past at all. Without this sentence it is
    indistinguishable from a fleet whose automations have never run.
    """
    bands = set(bands or ())
    if HISTORY not in bands or owners_for(bands):
        return ''
    return ('“What already ran” follows the two automation groups above, and '
            'both are hidden — so no history is drawn.')
