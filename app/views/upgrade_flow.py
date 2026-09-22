"""Upgrade Flow — a maintenance window as ONE staged workflow, in bulk.

Every piece of a windowed firmware upgrade already existed in SATOM, and every
piece was per-device or unlinked: the pre-flight lived on one appliance's page,
the change request could cite one run, the customer-impact export came off that
one change, and execution was a separate scheduled action somebody had to
remember to bind. An operator upgrading sixty FortiWeb walked that path sixty
times and still finished holding a change document whose evidence covered one
box.

This blueprint is the staged front for the whole thing:

  1. Pre-upgrade (BULK) — N runs of :func:`app.services.prep_store.run_for`,
     one persisted ``UpgradePrep`` per device;
  2. Change request — ONE change citing ALL of those runs (``models.CrPrep``);
  3. Customer impact — the consolidated XLSX/CSV off that change's frozen,
     merged inventory;
  4. Execution — the approved change's one-shot action, or manual.

It OWNS no workflow of its own. Stage 1 calls ``services.prep_store``, stage 2
calls :func:`app.views.change_requests.create_change_request` — the same one
implementation the single-change form uses, and the same one the batched wave
route uses — stages 3 and 4 link into that change. A second implementation of any of them is precisely the defect this
feature was built to remove: ``scheduled_actions._do_upgrade_prep`` spent
months as a rival "upgrade prep" that stored no evidence at all.

Import side-effect-free: importing this module touches no DB and contacts no
device.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from flask import (Blueprint, abort, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import (Appliance, ChangeRequest, Permission, ScheduledAction,
                      ScheduledActionRun, ScheduledActionTarget, db,
                      visible_appliances)
from ..services import scheduled_actions as sa
from ..services.audit import log_action

bp = Blueprint('upgrade_flow', __name__, url_prefix='/upgrade-flow')

# How many devices one sweep may cover. The sweep is SEQUENTIAL and each device
# takes a configuration backup, so this is a request-timeout guard, not a
# capacity opinion — and it is enforced with a message naming the number, never
# by silently truncating the selection. A sweep that quietly pre-flights the
# first 40 of 60 boxes and reports success is how nineteen devices enter a
# window with no baseline.
MAX_SWEEP = 40

# How many waves one selection may be split into (stage 2, batched). Same rule
# as MAX_SWEEP: it REFUSES naming the number rather than quietly making fewer
# waves than were asked for, because a wave that silently disappeared takes its
# appliances out of every window without anybody being told.
MAX_WAVES = 12

#: The change type this flow raises. Fixed — the page is the *upgrade*
#: workflow and stage 4 binds the upgrade executor — but every WORD it puts on
#: the change comes from Administration -> Change Types, never from this
#: template. A page that hard-codes its own title and reason is a second author
#: of the same prose: an administrator corrects the wording there, the single
#: change picks it up, and the bulk one keeps printing the sentence that was
#: compiled in. Nothing fails; the two documents simply stop agreeing.
CR_ACTION = 'upgrade'


def crsvc_risks() -> tuple:
    """The risk vocabulary, read from the service that owns it.

    Imported at call time like every other service reference in this module,
    so importing the blueprint still touches nothing.
    """
    from ..services import change_requests as crsvc
    return tuple(crsvc.RISKS)


def cr_draft_context() -> dict:
    """The stage-2 wording, authored by Administration -> Change Types.

    Read through ``services.cr_types`` (not ``cr_document``) for the same
    reason the single-change form does: an administrator's text wins PER
    FIELD, and every field they left alone falls back to the sentence shipped
    with the product. Reading the compiled module here would print the shipped
    paragraph next to the corrected one, on the same console.

    ``entry`` is ``None`` when the built-in has been disabled on that page. It
    is surfaced rather than ignored because ``create_change_request`` refuses
    an action that is not on offer — without it the operator fills the whole
    form and is told at submit time, after the pre-flight sweep.

    **No pre-flight run is cited.** ``draft_fields(prep=...)`` names one run's
    id, timestamp and backup, and this stage rests on N of them. Picking one to
    quote is exactly the defect this flow was built to remove: a document whose
    evidence sentence describes a single box while the change covers forty.
    The consolidated coverage is on the change itself.
    """
    from ..services import cr_document, cr_types
    from .change_requests import cr_type_entries

    codes = [code for code, _label in cr_document.document_langs()]
    entry = {e['key']: e for e in cr_type_entries()}.get(CR_ACTION)
    return {
        'entry': entry,
        'langs': cr_document.document_langs(),
        'drafts': {code: cr_types.draft_fields(CR_ACTION, code)
                   for code in codes},
        'labels': {code: cr_types.label(CR_ACTION, code) for code in codes},
        'devices_token': cr_document.DEVICES_TOKEN,
        'devices_none': {code: cr_document.devices_placeholder(code)
                         for code in codes},
    }


def prep_kinds() -> tuple[str, ...]:
    """Appliance kinds the pre-upgrade actually runs against.

    DERIVED from the ``upgrade_prep`` action's own product list, never
    re-listed here. A hand-kept copy is how this page would come to offer
    FortiAnalyzer the day somebody adds it to the picker and nowhere else — the
    sweep would run, every device would raise, and the operator would read
    forty errors instead of one honest absence.
    """
    spec = sa.ALL_ACTIONS.get('upgrade_prep')
    return tuple(getattr(spec, 'products', ()) or ())


#: What one destination does to ONE appliance. Four outcomes, not a
#: boolean: "already there" and "already past it" send the operator to two
#: different places, and "cannot tell" must not be collapsed into either.
MOVE_UP = 'up'
MOVE_SAME = 'same'
MOVE_BEHIND = 'behind'
MOVE_UNKNOWN = 'unknown'

#: The two outcomes a sweep refuses to run. Kept as a set beside the codes so
#: a fifth outcome cannot be added without deciding which side it falls on.
HELD_MOVES = (MOVE_SAME, MOVE_BEHIND)


def classify_move(version, dev) -> tuple:
    """``(code, current)`` — what ``version`` would do to one appliance.

    The single authority for the comparison, because it has three callers
    that must not be allowed to disagree: the select's filter, the sweep's
    per-appliance skip, and the hint the page paints beside a row. The first
    two disagreeing is exactly the gap this function was added to close — the
    select narrows against the whole PAGE, the sweep runs against the TICKED
    rows, and those sets need not be the same.

    Compares NOTHING across products; the caller decides which appliances are
    even comparable. See :func:`firmware_versions.compare`.
    """
    from ..services import firmware_versions as fv
    current = fv.normalize(getattr(dev, 'fw_version', '')
                           or getattr(dev, 'firmware', '') or '')
    verdict = fv.compare(version, current)
    if verdict is None:
        return MOVE_UNKNOWN, current
    if verdict > 0:
        return MOVE_UP, current
    return (MOVE_SAME if verdict == 0 else MOVE_BEHIND), current


def hold_reason(code, name, current, version) -> str:
    """The ONE sentence explaining why an appliance is not swept.

    Written here and nowhere else because it is read in two places that have
    to agree word for word: the hint the page paints beside the row BEFORE
    the operator presses the button, and the flash the POST sends back AFTER.
    A hint written in the template and a refusal written in the view are two
    authors of the same promise, and the template's copy is the one nothing
    tests.

    ``same`` and ``behind`` do NOT share a sentence. "It is already on 8.0.5"
    is fixed by picking a later version or unticking the row; "it is on 8.0.6,
    you picked 8.0.5" means the version chosen for the whole window is older
    than something in it, which is a downgrade — a different operation that
    this pre-flight reviews nothing about. Telling an operator the second
    story with the first one's words sends them to reread a selection that is
    not the mistake.
    """
    if code == MOVE_BEHIND:
        return ('%s cannot be upgraded to %s: it is already running %s, which '
                'is newer — that move is a DOWNGRADE, and the pre-upgrade '
                'reviews upgrades.' % (name, version, current or '?'))
    return ('%s cannot be upgraded to %s: it is already running it, so there '
            'is no upgrade to pre-flight.' % (name, version))


def forward_only(version, products, devices) -> dict:
    """What one destination would DO to the appliances on this page.

    The rule this implements — *only offer versions newer than the one the
    system is running* — has no single referent on a page that lists boxes
    on different firmware, and the fleet is exactly that case: fortiweb15
    and fortiweb16 run 7.6.8 while fortiweb17 runs 8.0.5. Hiding everything
    that is not newer than the HIGHEST would have hidden 8.0.5 — the one
    move two of the three boxes are actually waiting for — and left the
    operator a select that offers nothing while the window it describes is
    perfectly legal. So a version stays on the list while it moves AT LEAST
    ONE appliance forward, and the option SAYS how many of how many, plus
    which boxes are already there. The page narrows the choice; it does not
    make it.

    Compared PER PRODUCT. A FortiAuthenticator running 8.0.3 says nothing
    about whether FortiWeb 8.0.5 is an upgrade — folding the two would hide
    a real destination on the strength of another vendor's digits.

    A version is hidden ONLY when this page can show it is not an upgrade.
    No comparable appliance, or a comparison ``firmware_versions.compare``
    refuses to decide (a line-only destination against a box already on
    that line, or a box whose firmware was never read), leaves it on the
    list: absence of evidence is not evidence of a downgrade, and a
    destination silently missing from a select is unreportable — the
    operator has no way to ask why the version they came for is not there.
    """
    ups, held, undecided = [], [], []
    same, behind, holds = [], [], {}
    for dev in (devices or []):
        if (getattr(dev, 'kind', '') or '') not in (products or []):
            continue
        name = getattr(dev, 'name', '') or ''
        code, current = classify_move(version, dev)
        if code == MOVE_UNKNOWN:
            undecided.append(name)
        elif code == MOVE_UP:
            ups.append(name)
        else:
            held.append(name)
            (same if code == MOVE_SAME else behind).append(name)
            holds[name] = hold_reason(code, name, current, version)
    comparable = len(ups) + len(held) + len(undecided)
    return {
        'upgrades': sorted(ups),
        'at_or_above': sorted(held),
        # ``at_or_above`` is the union and stays, because the option label
        # reads better as one list. The split is carried BESIDE it rather
        # than replacing it: a downgrade and a no-op are one line apart on
        # this page and a long way apart in a maintenance window.
        'same': sorted(same),
        'behind': sorted(behind),
        'holds': holds,
        'undecided': sorted(undecided),
        'comparable': comparable,
        'offerable': comparable == 0 or bool(ups) or bool(undecided),
    }


def sweep_split(version, products, devices) -> dict:
    """The TICKED appliances, split into the ones a sweep may run against.

    A different question from the one :func:`forward_only` answers, and the
    gap between them is a real hole this closes. ``forward_only`` narrows the
    select against everything the PAGE lists — a version stays offered while
    it moves at least one box forward. The sweep runs against the boxes the
    operator TICKED, and nothing makes those two sets the same: tick only the
    appliance that is already on 8.0.5, sweep it towards 8.0.5, and every
    window-level rule passes while what gets written is evidence whose
    declared move is 8.0.5 -> 8.0.5.

    SKIPPED, never refused wholesale, whenever anything else still moves. One
    box too many in a selection of forty must not throw away the thirty-nine
    that were right — the operator would simply retick them and press the same
    button. The window is only refused when NOTHING in it moves, because then
    there is no sweep left to run.

    Nothing is stored for a held appliance. A row written to say "this did not
    run" is still a row the citation picker offers and the Move column paints,
    and evidence for a move that never happened is the thing the destination
    column exists to prevent.

    Held only when this page can PROVE it: an appliance of another product, or
    one whose firmware could not be read, or a comparison
    ``firmware_versions.compare`` refuses to decide, is swept. Absence of
    evidence is not evidence of a no-op, and silently not running a box the
    operator ticked is unreportable.
    """
    run, held = [], []
    for dev in (devices or []):
        name = getattr(dev, 'name', '') or ''
        if (getattr(dev, 'kind', '') or '') not in (products or []):
            run.append(dev)
            continue
        code, current = classify_move(version, dev)
        if code in HELD_MOVES:
            held.append({'id': getattr(dev, 'id', None), 'name': name,
                         'code': code, 'current': current,
                         'reason': hold_reason(code, name, current, version)})
        else:
            run.append(dev)
    return {'run': run, 'held': held}


def target_options(kinds=None, devices=None) -> list[dict]:
    """Every version this window may be upgraded TO, newest first.

    ``devices`` are the appliances the page is rendering. Passed in rather
    than re-queried so the select can only ever be narrowed by the SAME
    rows the checkboxes below it come from: a version filtered out by a box
    the operator cannot see would be a destination missing for a reason
    nothing on screen explains. Omitted, every row is offerable and the
    return is what it always was.

    DERIVED from ``services.firmware_versions.catalog`` — the one authority for
    "what versions does this console know of" — for each product the sweep
    actually runs against. Re-listing them here would be a second catalogue
    that silently stops agreeing with API Versions the first time somebody
    declares a release on that page.

    ``has_image`` answers a DIFFERENT question from "is this version known",
    and the two are kept apart on purpose: an operator may legitimately
    pre-flight a window towards a release whose ``.out`` has not been uploaded
    yet, and refusing that would make the pre-flight impossible to run until
    the last moment. The page SAYS which is which; it does not decide.

    Only ``upgrade`` images count. An install image (``.zip``/``.qcow2``/
    ``.ova``) builds a machine from nothing, and reporting one as "the image
    for 8.0.5 is here" is how somebody walks into a window holding a file that
    was never meant to touch a running appliance.
    """
    from ..models_firmware import FirmwareImage
    from ..services import firmware_versions as fv

    kinds = tuple(kinds if kinds is not None else prep_kinds())
    images: dict[str, list[str]] = {}
    if kinds:
        for row in (FirmwareImage.query
                    .filter(FirmwareImage.product.in_(kinds)).all()):
            if (row.image_kind or 'upgrade') != 'upgrade':
                continue
            version = fv.normalize(row.version)
            if version:
                images.setdefault(version, []).append(row.filename or '')

    merged: dict[str, dict] = {}
    for kind in kinds:
        for version, entry in fv.catalog(kind).items():
            row = merged.setdefault(version, {
                'version': version, 'line': entry.get('line') or '',
                'line_only': bool(entry.get('line_only')),
                'products': [], 'appliances': [], 'note': ''})
            row['products'].append(kind)
            row['appliances'].extend(entry.get('appliances') or [])
            if entry.get('note') and not row['note']:
                row['note'] = entry['note']

    out = []
    for version in sorted(merged, key=fv.sort_key, reverse=True):
        row = merged[version]
        files = sorted({f for f in (images.get(version) or []) if f})
        row['images'] = files
        row['has_image'] = bool(files)
        row['appliances'] = sorted(set(row['appliances']))
        row['in_fleet'] = bool(row['appliances'])
        row.update(forward_only(version, row['products'], devices))
        out.append(row)
    return out


def resolve_target(raw, options) -> tuple[str, str]:
    """``(version, error)`` for the destination a sweep was asked for.

    Resolved against the SAME list the select renders, never against a regex
    alone, for the reason ``preselect_device`` resolves ids against the rows on
    screen: a version this console has never heard of is not a typo to be
    normalised through, it is a destination nothing on this page can say
    anything about — no image, no release notes, no Scout verdict.

    An ABSENT answer is refused rather than defaulted. "Upgrade to the newest
    one we know about" is a decision, and a page that makes it silently writes
    a destination onto forty pieces of evidence that nobody chose.
    """
    from ..services import firmware_versions as fv
    raw = (raw or '').strip()
    if not raw:
        return '', ('Choose the version this window upgrades TO before running '
                    'the sweep. The pre-flight is evidence FOR a specific move: '
                    'the same green run says nothing comparable about 7.6.8 → '
                    '8.0.5 and 7.6.8 → 8.0.6. Nothing was started.')
    version = fv.normalize(raw)
    if not version:
        return '', (f'"{raw}" is not a firmware version. Nothing was started.')
    row = next((o for o in (options or []) if o.get('version') == version),
               None)
    if row is None:
        return '', (f'{version} is not a version this console knows of, so '
                    f'nothing here can review the move to it. Declare it under '
                    f'Firmware → API versions, or upload its image, and it '
                    f'appears in this list. Nothing was started.')
    # A FOURTH sentence, and not a variant of the third. "This console has
    # never heard of 9.9.9" and "7.6.8 exists and every one of these boxes
    # is already on it or past it" send the operator to two different
    # places -- one to declare a version, the other to re-read their own
    # selection -- and answering the second with the first would send them
    # to declare a version that is already declared.
    if not row.get('offerable', True):
        held = row.get('at_or_above') or []
        shown = ', '.join(held[:4]) + ('…' if len(held) > 4 else '')
        return '', (f'{version} would not move any of these appliances '
                    f'forward — {shown} '
                    f'{"is" if len(held) == 1 else "are"} already running it '
                    f'or something newer. Pick a later version, or sweep the '
                    f'appliances that are still behind. Nothing was started.')
    return version, ''


def scout_reviews(devices, preps) -> dict:
    """``{appliance_id: summary}`` — Scout's reading of each recorded move.

    Computed at RENDER time, not stored on the run: Scout reads harvested
    vendor prose, so a corpus that gains the 8.0.5 page tonight must change
    this badge tomorrow without anybody re-running a sweep against forty live
    appliances. The pre-flight measures the BOX; Scout reads the NOTES, and
    freezing the second into the first would make a stale corpus look like
    measured evidence.

    Only appliances whose newest run DECLARED a destination get an entry.
    Absent is absent: a row with no badge has no target recorded, which is a
    different statement from ``unknown`` (Scout looked and the corpus had
    nothing) and from ``clear``.

    Memoised per ``(kind, current, target)`` because that triple is the whole
    of what :func:`upgrade_scout.review` reads — ``current`` is passed
    explicitly here, so the only attribute taken off the appliance is its
    kind. Forty boxes on four versions cost four corpus reads, not forty.
    """
    from ..services import upgrade_scout
    out: dict = {}
    cache: dict = {}
    for dev in devices or []:
        prep = (preps or {}).get(getattr(dev, 'id', None))
        target = ((getattr(prep, 'target_version', '') or '').strip()
                  if prep is not None else '')
        if not target:
            continue
        # The version the RUN observed, falling back to the inventory row.
        # The run's own reading is preferred because it is what was true when
        # the evidence was taken; the appliance row may have been re-probed
        # since, and grading old evidence against today's firmware is how a
        # box that has already been upgraded shows a review of a move it is
        # no longer making.
        current = upgrade_scout.normalise(
            (getattr(prep, 'firmware', '') or '')
            or (getattr(dev, 'firmware', '') or ''))
        key = ((getattr(dev, 'kind', '') or ''), current, target)
        if key not in cache:
            cache[key] = upgrade_scout.summary(
                upgrade_scout.review(dev, target, current=current))
        out[dev.id] = cache[key]
    return out


def _eligible():
    kinds = prep_kinds()
    query = visible_appliances()
    if kinds:
        query = query.filter(Appliance.kind.in_(kinds))
    return query.order_by(Appliance.name.asc()).all()


def preselect_device(raw, devices):
    """``(id, unresolved)`` for a ``?device=`` hand-off from a prep page.

    The single-appliance pre-upgrade page asks the operator whether this box is
    part of a full upgrade window, and carries its id here ONLY on "yes". The
    answer is what carries the id; nothing is sent when they stay.

    It NEVER silently selects nothing. A hand-off that lands on a list with no
    row ticked reads exactly like a page opened by hand: the operator ticks a
    box themselves and never learns the link pointed at an appliance this
    console cannot pre-flight. The unresolved value is returned so the page can
    say so, and it is returned VERBATIM rather than coerced — ``?device=abc``
    and ``?device=999`` are both "not on this list" to the operator, and a
    silent 0 would name the wrong thing.
    """
    raw = (raw or '').strip()
    if not raw:
        return None, None
    try:
        did = int(raw)
    except (TypeError, ValueError):
        return None, raw
    if any(d.id == did for d in devices):
        return did, None
    return None, raw


def preselect_prep(raw, device_id, runs):
    """``(prep_id, unresolved)`` for a ``?prep=`` hand-off from a prep page.

    Resolved against the runs THIS page renders for THAT appliance, never
    against the store. A run belonging to another box must not arrive
    pre-chosen: the change would then be signed against a pre-flight of a
    device it does not touch, and nothing on the page would say so.

    Unresolved is returned VERBATIM for the same reason ``preselect_device``
    does it -- "prep=abc" and "prep=999" are both "not one of this appliance's
    runs", and a silent None reads exactly like arriving with no run at all.
    """
    raw = (raw or '').strip()
    if not raw:
        return None, None
    try:
        pid = int(raw)
    except (TypeError, ValueError):
        return None, raw
    for row in (runs.get(device_id) or []) if device_id else []:
        if row.id == pid:
            return pid, None
    return None, raw


def submitted_fields(form) -> dict:
    """What the operator had in stage 2, as the page must be able to re-read it.

    Verbatim, and the windows as TEXT: they go back into the
    ``datetime-local`` inputs exactly as they were typed, in the console's
    timezone, never re-formatted out of the UTC value the parser produced. A
    refused change that comes back with the hour shifted is worse than an
    empty form, because it looks like the operator typed it.
    """
    def ints(name):
        out = set()
        for raw in form.getlist(name):
            try:
                out.add(int(raw))
            except (TypeError, ValueError):
                continue
        return out

    return {
        'doc_lang': (form.get('doc_lang') or '').strip(),
        'risk': (form.get('risk') or '').strip(),
        'target_version': (form.get('target_version') or '').strip(),
        'title': form.get('title') or '',
        'reason': form.get('reason') or '',
        'rollback': form.get('rollback') or '',
        'owner': form.get('owner') or '',
        'notify_to': form.get('notify_to') or '',
        'approval_mode': (form.get('approval_mode') or '').strip(),
        'window_start': (form.get('window_start') or '').strip(),
        'window_end': (form.get('window_end') or '').strip(),
        'device_ids': ints('device_ids'),
        'prep_ids': ints('prep_ids'),
    }


def prep_choice(devices, runs, preselect, prep_pick, posted) -> dict:
    """``{appliance_id: prep_id or ''}`` — WHICH run each row cites.

    ONE author for a question the page answers in three situations: a plain
    visit (the newest run is proposed), a hand-off from an appliance's own
    pre-upgrade page (``?prep=`` wins, and only for that appliance), and a
    refused change coming back (whatever the operator had chosen). Spelt out
    in the template the first two were already a compound condition and the
    third had nowhere to go: a re-render would have re-proposed the newest run
    over a citation the operator had deliberately cleared, and the page would
    have looked exactly as if they had chosen it.
    """
    out: dict = {}
    for dev in devices:
        rows = runs.get(dev.id) or []
        if not rows:
            continue
        if posted is not None and dev.id in posted['device_ids']:
            # '' is a REAL answer here — "this appliance is in the change and
            # cites no run" — not a missing one.
            out[dev.id] = next((r.id for r in rows
                                if r.id in posted['prep_ids']), '')
            continue
        if prep_pick and preselect == dev.id:
            out[dev.id] = prep_pick
            continue
        out[dev.id] = rows[0].id
    return out


def cited_targets(devices, runs, choice) -> dict:
    """What destination the runs THIS page has ticked actually declare.

    ``{'versions': [...], 'one': str, 'split': bool, 'uncited': int}``.

    Computed from the same ``prep_choice`` the selects render, so stage 2 shows
    the number ``create_change_request`` is about to derive — and would refuse
    over. Re-deriving it there from the change's own rows would be a check
    comparing a value with itself.

    ``split`` is the interesting one: two ticked runs swept towards different
    versions is one window carrying two moves, and it is REPORTED here rather
    than only at submit time, after the operator has filled the whole form.
    """
    picked = {d.id for d in (devices or [])}
    versions, uncited = [], 0
    for dev_id, prep_id in (choice or {}).items():
        if dev_id not in picked:
            continue
        if not prep_id:
            uncited += 1
            continue
        row = next((r for r in (runs.get(dev_id) or []) if r.id == prep_id),
                   None)
        target = (getattr(row, 'target_version', '') or '').strip() if row else ''
        if target:
            versions.append(target)
        else:
            # A cited run with no destination is NOT the same as an uncited
            # appliance: there IS evidence, it simply predates the question.
            uncited += 1
    uniq = sorted(set(versions))
    return {'versions': uniq, 'one': uniq[0] if len(uniq) == 1 else '',
            'split': len(uniq) > 1, 'uncited': uncited}


def auto_fields(posted, crdoc, devices, render_lang) -> dict:
    """Which of title/reason/rollback still hold the product's own proposal.

    On a plain visit, all three. On a re-render it is COMPUTED: the proposal
    the page would have shown is rebuilt here — the change type's sentence
    with the device token replaced by the names the operator had ticked, in
    the order the table lists them, which is exactly what the page's own
    substitution does — and compared with what came back. Marking all three
    "edited" would be simpler and wrong in the common case: an operator who
    corrected only the window would find the wording frozen for the rest of
    the session, with a chip claiming text is theirs that they never touched.
    """
    keys = ('title', 'reason', 'rollback')
    if posted is None:
        return {k: True for k in keys}
    drafts = crdoc.get('drafts') or {}
    code = posted['doc_lang'] if posted['doc_lang'] in drafts else render_lang
    draft = drafts.get(code) or {}
    names = [d.name for d in devices if d.id in posted['device_ids']]
    shown = (', '.join(names) if names
             else (crdoc.get('devices_none', {}).get(code) or ''))
    token = crdoc.get('devices_token') or ''
    return {k: posted[k] == str(draft.get(k) or '').replace(token, shown)
            for k in keys}


def created_change(raw):
    """The change stage 2 has just raised, cited back on the flow. Or None.

    Never a 404: this is decoration on a page that renders perfectly without
    it, and an id naming a change outside the operator's ADOM must read as no
    citation at all rather than as the existence of something they cannot see.
    """
    raw = (raw or '').strip()
    if not raw:
        return None
    try:
        cid = int(raw)
    except (TypeError, ValueError):
        return None
    cr = db.session.get(ChangeRequest, cid)
    if cr is None or not _visible_to_me(cr):
        return None
    return cr


def rollout_context(cr) -> dict:
    """Stage 4 — the rollout plan, as plain data.

    ``cr`` is the change stage 3 is showing, or ``None`` on a visit that names
    none. Never raises: this is decoration on a page that renders without it,
    and a card that 500s the whole flow because a scheduled row is odd is
    worse than a card that says it cannot read the plan.

    The question "may this be scheduled" is asked of
    :func:`services.change_requests.schedulable` and NOT re-spelt here — the
    control this card offers and the call behind it have to agree about it.
    """
    from ..services import change_requests as crsvc
    from ..services import settings_store
    empty = {
        'total': 0, 'ok': False, 'reason': '', 'per_round': 1,
        'gap': crsvc.DEFAULT_ROUND_GAP_MINUTES, 'max_rounds': crsvc.MAX_ROUNDS,
        'task': None, 'rounds': [], 'calendar_on': False,
        'savable': False, 'save_reason': '', 'plan': {},
    }
    if cr is None:
        return empty
    ids = list(cr.device_ids_list or [])
    ok, reason = crsvc.schedulable(cr)
    # TWO questions, asked of two authors on purpose. ``ok`` is "may rows be
    # put on the calendar now", which needs the signature; ``savable`` is "may
    # the plan be written down", which does not. Asking only the first is what
    # made the operator approve a change before they could record how many
    # appliances it may take down at a time.
    savable, save_reason = crsvc.plannable(cr)
    plan = crsvc.rollout_plan(cr)

    task = None
    if cr.scheduled_action_id:
        task = db.session.get(ScheduledAction, cr.scheduled_action_id)
    saved = task.params_dict if task is not None else {}

    def _int(value, fallback):
        try:
            out = int(value)
        except (TypeError, ValueError):
            return fallback
        return out if out > 0 else fallback

    # What the operator last SAVED, read back off the rows the executor will
    # actually fire — never off a default that merely looks like it. A card
    # that re-opens proposing 25 over a plan saved at 5 is a card that invites
    # somebody to press Save and silently triple the blast radius.
    # Rows first, then the plan saved on the change, then a default. The
    # middle step is what stops a number typed before approval from vanishing
    # on the way back from the Approve button - which is exactly how somebody
    # re-opens this card, sees 25 over a plan they had set to 5, and presses
    # Save.
    per_round = _int(saved.get('round_size'),
                     _int(plan.get('size'), len(ids) or 1))
    gap = _int(saved.get('round_gap_minutes'),
               _int(plan.get('gap'), crsvc.DEFAULT_ROUND_GAP_MINUTES))

    rows = ([task] if task is not None else []) + crsvc.round_siblings(cr.id)
    names = {}
    if ids:
        names = {a.id: a.name for a in
                 Appliance.query.filter(Appliance.id.in_(ids)).all()}
    rounds = []
    for row in rows:
        params = row.params_dict
        targets = [t for t in row.targets_list]
        rounds.append({
            'id': row.id,
            # A round with no index IS round 1 of 1: the un-batched action this
            # product has always created carries no round bookkeeping, and
            # rendering it as "round None" would make the plain case look broken.
            'index': _int(params.get('round_index'), 1),
            'total': _int(params.get('round_total'), 1),
            'at': settings_store.to_local(row.schedule_dict.get('at')),
            'count': len(targets),
            'names': ', '.join(str(names.get(t, f'#{t}')) for t in targets) or '—',
            'enabled': bool(row.enabled),
            'last_status': row.last_status or '',
        })
    rounds.sort(key=lambda r: r['index'])

    calendar_on = False
    try:
        from .calendar import _calendar_on
        calendar_on = bool(_calendar_on())
    except Exception:  # noqa: BLE001 - a card must not 500 over a preference
        calendar_on = False

    return dict(empty, total=len(ids), ok=ok, reason=reason,
                savable=savable, save_reason=save_reason, plan=plan,
                per_round=min(per_round, len(ids)) if ids else per_round,
                gap=gap, task=task, rounds=rounds, calendar_on=calendar_on)


def page_context(posted=None) -> dict:
    """Everything the flow page renders, as plain data.

    ``posted`` is the stage-2 form coming BACK after the change was refused;
    it is None on an ordinary visit. Built as a function so the refusal path
    re-renders the very page the operator was on instead of redirecting them
    to a different form — the two would otherwise be two authors of the same
    screen, and it is the error path, the one nobody looks at twice, that
    would have drifted.
    """
    from ..services import prep_store
    devices = _eligible()
    # Scoped against the SAME list the checkboxes are rendered from, never
    # against the database: an id the operator cannot see must not be able to
    # tick a row here just because it exists.
    preselect, preselect_unresolved = preselect_device(
        request.args.get('device'), devices)
    # EVERY recorded run per appliance, not just the newest: stage 1 offers
    # the operator which one this change is signed against, and the hand-off
    # from a single appliance's page arrives naming one.
    runs = prep_store.recent_for_many([d.id for d in devices], 10)
    # ONE author for "the newest run": derived from the same list the chooser
    # renders, so the column and the dropdown cannot disagree about which run
    # is on top.
    latest = {aid: rows[0] for aid, rows in runs.items() if rows}
    # The destinations this window may be swept towards, and what each
    # appliance's newest run was actually swept towards. The select is
    # re-proposed from the LAST sweep rather than reset to blank: an operator
    # who ran 20 boxes towards 8.0.5 and comes back for the other 20 is
    # answering the same question again, and a blank control invites a second,
    # different answer that would split one window across two moves.
    targets = target_options(devices=devices)
    # What each offered destination would REFUSE to do, keyed by version and
    # then by appliance name. Computed on the SERVER and handed over as data
    # so the hint beside a row is the same sentence the POST flashes back;
    # re-deriving "is this box already there" in JavaScript would be a second
    # author of the refusal, and the browser's copy is the one nothing tests.
    holds = {t['version']: t['holds'] for t in targets if t.get('holds')}
    target_pick = (request.args.get('target') or '').strip()
    if not target_pick:
        declared = [(p.target_version or '').strip() for p in latest.values()]
        declared = [d for d in declared if d]
        # Re-proposed only when the fleet AGREES. Picking the most common one
        # out of a split would silently answer "which of these two windows am
        # I continuing" on the operator's behalf.
        if declared and len(set(declared)) == 1:
            target_pick = declared[0]
    # NOT also filtered by ``offerable`` here, and that was tried. The only
    # consumer of ``target_pick`` is the option loop, which already iterates
    # the offered rows -- a version filtered out there can never be marked
    # selected, so the extra term changes no rendered byte and would be a
    # second author of "which versions are offered". The behaviour it was
    # meant to protect is guarded at the template instead.
    if target_pick not in {o['version'] for o in targets}:
        target_pick = ''
    prep_pick, prep_unresolved = preselect_prep(
        request.args.get('prep'), preselect, runs)
    # Computed ONCE, and AFTER prep_pick exists. The stage-2 header and the
    # per-row selects must describe the same choice; two calls that happen to
    # agree today are the pair that stops agreeing the moment somebody makes
    # this function depend on anything that is not its arguments.
    #
    # Placed here for a reason that cost a render: the first attempt put this
    # block higher, next to the target select it feeds, and `prep_pick` is
    # assigned BELOW. Python raised NameError on every visit -- the page 500'd
    # outright, which is at least loud. The quiet version of this mistake is
    # what the comment is for.
    chosen = prep_choice(devices, runs, preselect, prep_pick, posted)
    ticked_ids = (posted['device_ids'] if posted is not None
                  else ({preselect} if preselect else set()))
    # Batched rollouts, newest group first. Grouped HERE rather than left as
    # ten look-alike rows: five changes whose only distinguishing mark is
    # "wave 3/5" buried in the title is precisely the register this page
    # exists to replace.
    wave_groups: list[dict] = []
    seen_groups: dict[str, dict] = {}
    for cr in (ChangeRequest.query
               .filter(ChangeRequest.wave_group.isnot(None),
                       ChangeRequest.wave_group != '')
               .order_by(ChangeRequest.id.desc()).limit(60).all()):
        group = seen_groups.get(cr.wave_group)
        if group is None:
            if len(seen_groups) >= 5:
                continue
            # NOT 'items': in Jinja a dict's `.items` resolves to the dict
            # METHOD, so `group.items|length` blows up with "object of type
            # builtin_function_or_method has no len()" — a 500 on a page that
            # renders fine until the first batched rollout exists.
            group = {'ref': cr.wave_group, 'total': cr.wave_total or 0,
                     'waves': []}
            seen_groups[cr.wave_group] = group
            wave_groups.append(group)
        group['waves'].append(cr)
    for group in wave_groups:
        group['waves'].sort(key=lambda c: c.wave_index or 0)
    # Question "which language is this document written in" is answered from
    # the operator's PROFILE and from nowhere else, exactly as the single
    # change form answers it. A pre-checked first radio is not an answer: the
    # document that comes out of stage 2 is signed in whatever it says.
    from ..services import langs as lang_registry
    from ..services import user_settings_store as user_store
    crdoc = cr_draft_context()
    codes = [code for code, _label in crdoc["langs"]]
    pref_lang = user_store.language(getattr(current_user, 'id', 0) or 0)
    lang_preset = pref_lang if pref_lang in set(codes) else ''
    # Rendered in a language the document can actually be produced in. Falling
    # back to a hard-coded 'en' would put a proposal on screen that no entry in
    # `drafts` corresponds to, and the fields would come out blank.
    fallback = (lang_registry.DEFAULT if lang_registry.DEFAULT in codes
                else (codes[0] if codes else lang_registry.DEFAULT))
    # The same proposals the single change form makes, from the same two
    # sources. Typing either default here would be a second author of a value
    # the operator is about to sign their name to.
    from ..services import email_service
    from .appliances import _adom_arg
    from .change_requests import (_tz_name, cr_view_context,
                                  new_form_context)
    defaults = {
        'owner': (getattr(current_user, 'username', '') or ''),
        'notify_to': (email_service.config().get('default_to') or '').strip(),
    }
    render_lang = (lang_preset or fallback)
    # Resolved ONCE: the citation and the embedded view have to be the same
    # change, and two independent lookups of the same query argument is how
    # a page comes to name one record and render another.
    asked_cr = request.args.get('cr')
    created = created_change(asked_cr)
    # Every change this flow has raised that this operator may see, newest
    # first. Stage 2 renders the CHANGE ITSELF.
    #
    # Scoped through _visible_to_me -- the SAME gate the citation uses -- so
    # the picker cannot offer a change this very page would then decline to
    # render.
    flow_changes = [c for c in (ChangeRequest.query
                                .filter(ChangeRequest.action == CR_ACTION)
                                .order_by(ChangeRequest.id.desc())
                                .limit(60).all())
                    if _visible_to_me(c)][:12]
    # A plain visit opens the NEWEST change this flow raised. Requiring a
    # click meant the stage looked like a bare form to anyone who had not just
    # pressed its button -- which is every visit after the first.
    #
    # There is NO closed state any more. `?cr=0` used to be one, written by
    # the picker's "Close it" button; the picker was removed on request and
    # the state outlived its only control, so anyone still holding that URL
    # sat on a bare form with the change gone and nothing able to reopen it.
    # A dead end reachable only by a stale link is worse than no state at all,
    # and this one hid the whole stage. Any `cr` that does not resolve to a
    # change this operator may see -- 0, a deleted id, another ADOM's -- now
    # falls back to the newest, exactly like a plain visit.
    #
    # What the auto-open costs: the blocks carry Approve, Schedule, Mark
    # notified and Cancel, so the change the page opened for you is one you did
    # not name. That is why every one of those buttons sits under a header that
    # states the ref, the title and the status of the change it acts on.
    # Stage 3 opens ONLY for a change this visit NAMES. The fallback to the
    # newest meant the stage was already open before anyone pressed Create
    # draft -- and its blocks carry Approve, Schedule, Mark notified and
    # Cancel, so a plain visit offered lifecycle buttons over a change the
    # operator had not raised in this sitting. `?cr=` is written by the
    # redirect Create draft takes, so the stage appears exactly when the
    # change was just created, and the same link reopens it later.
    # Returned as ONE dict and splatted by the caller. Enumerating the keys at
    # the render call is how a value this function computes can fail to reach
    # the template with every assertion about it still green.
    # Stage 2 IS the new-change-request form, so it is fed by the SAME
    # builder that page uses. Merged UNDER this function's own keys: where the
    # two overlap (defaults, tz_name, risks, lang_preset...) the flow's value
    # wins, so nothing stage 1 or the waves post renders changes meaning.
    return dict(new_form_context(preset_action=CR_ACTION), **dict(
        devices=devices, latest=latest, runs=runs,
        preselect_prep=prep_pick,
        preselect_prep_unresolved=prep_unresolved,
        defaults=defaults, tz_name=_tz_name(),
        preselect=preselect,
        preselect_unresolved=preselect_unresolved,
        wave_groups=wave_groups,
        risks=crsvc_risks(),
        kinds=prep_kinds(), max_sweep=MAX_SWEEP,
        targets=targets, target_pick=target_pick, holds=holds,
        cited_target=cited_targets(
            [d for d in devices if d.id in ticked_ids], runs, chosen),
        # Scout's verdict per appliance, for the move its newest run declared.
        scout=scout_reviews(devices, latest),
        max_waves=MAX_WAVES, crdoc=crdoc,
        cr_action=CR_ACTION,
        # Stage 2's change-type select is fixed to this flow's one action and
        # locked. Opt-in key: the shared partial keeps ASKING on the page that
        # does not set it.
        locked_action=CR_ACTION,
        # Same opt-in shape: stage 2 shows the step-1 ticks read-only instead
        # of asking the question a second time. The standalone page does not
        # set it and keeps its inventory picker.
        locked_devices=True,
        # Third opt-in key: Create draft comes back HERE, to stage 3, instead
        # of leaving the flow for the change's own page.
        cr_back='upgrade_flow',
        lang_preset=lang_preset,
        # The text has to be rendered in SOME language for the page to work
        # without scripting; that is not the same as the question being
        # answered, and the radios still ask it.
        render_lang=render_lang,
        lang_pref_label=(lang_registry.label(pref_lang)
                         if pref_lang else ''),
        lang_pref_unrenderable=(bool(pref_lang) and not lang_preset),
        # --- the three answers that differ between a visit and a refusal ---
        posted=posted,
        ticked=ticked_ids,
        prep_choice=chosen,
        auto=auto_fields(posted, crdoc, devices, render_lang),
        created=created,
        flow_changes=flow_changes,
        # Stage 4 - the rollout this change will actually be carried out as.
        rollout=rollout_context(created),
        # The change this flow raised, rendered WHOLE right here - the same
        # action bar, overview, document, frozen inventory, external record,
        # timeline and notice its own page shows, from the ONE builder both
        # pages call. Citing it with a link and nothing else still made
        # approving, scheduling, notifying or exporting it a trip to another
        # screen, which is the trip this stage exists to remove.
        created_view=(cr_view_context(
            created, drift=request.args.get('drift') == '1',
            back='upgrade_flow', self_endpoint='upgrade_flow.index',
            self_args=dict({'cr': created.id}, **_adom_arg()))
            if created is not None else None),
    ))


@bp.route('/')
@login_required
@require_permission(Permission.BACKUP)
def index():
    return render_template('upgrade_flow/index.html', **page_context())


@bp.route('/change', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def change():
    """Stage 2 — raise the ONE change, without leaving the flow.

    Stage 2 used to post straight at ``change_requests.new``, which cannot do
    either of the two things a stage inside a staged page has to do. On
    success it sent the operator to that change's own page — out of the flow,
    two stages from the end, with no way back to the selection they had built.
    On refusal it redirected to an EMPTY ``/change-requests/new``: the form
    they had deliberately not used, with everything they had typed gone, and
    the pre-flight evidence they had picked per appliance gone with it.

    This is NOT a second implementation of "raise a change". What a legal
    change is stays in ``change_requests.create_change_request``, exactly as
    the batched wave route uses it. Only the two answers are this page's own.
    """
    from .change_requests import _parse_dt, create_change_request
    posted = submitted_fields(request.form)
    cr, error = create_change_request({
        'title': posted['title'],
        # Read from the module, never from the post. The flow raises the
        # upgrade change — the pre-flight above it, the wording beside it and
        # the executor after it are all that one action — and a type arriving
        # in a form field is a type somebody could substitute for one whose
        # wording this page cannot propose.
        'action': CR_ACTION,
        'risk': posted['risk'],
        'reason': posted['reason'],
        'rollback': posted['rollback'],
        'owner': posted['owner'],
        'notify_to': posted['notify_to'],
        'approval_mode': posted['approval_mode'],
        'doc_lang': posted['doc_lang'],
        'device_ids': sorted(posted['device_ids']),
        'prep_ids': sorted(posted['prep_ids']),
        # Declared, and cross-checked against the runs above by
        # create_change_request. Posted rather than re-derived here so the
        # check has two independent sides to compare: a destination read back
        # off the same evidence it is being compared with can never disagree
        # with it, which is a check that cannot fail.
        'target_version': posted['target_version'],
        'window_start': _parse_dt(posted['window_start']),
        'window_end': _parse_dt(posted['window_end']),
        'requested_by': getattr(current_user, 'username', '') or '',
    })
    if cr is None:
        flash(error, 'danger')
        # Re-rendered, not redirected: a redirect cannot carry the form back.
        # 200 and not 4xx because a reverse proxy in front of this product may
        # be configured to replace an error body with its own page, which
        # would answer a refused change with a blank error screen.
        return render_template('upgrade_flow/index.html',
                               **page_context(posted=posted))
    log_action('upgrade_flow.change', target=cr.ref or f'#{cr.id}',
               detail=f'{len(cr.device_ids_list)} appliance(s)')
    flash(f'Change request {cr.ref} "{cr.title}" was raised. Approve and '
          f'schedule it from the change itself; this flow now cites it.',
          'success')
    # BACK to the flow, citing the change. The operator is mid-window-planning
    # and the next thing they do is stage 2b or the change's own page — both
    # of which are reachable from here, and neither of which was reachable
    # from where this used to land them.
    from .appliances import _adom_arg
    return redirect(url_for('upgrade_flow.index', cr=cr.id, **_adom_arg()))


@bp.route('/schedule', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def schedule():
    """Stage 4 — save the rollout as real scheduled task(s) on the calendar.

    NOT a second implementation of "schedule a change". What a schedulable
    change is, what the bound action carries and how the rounds are laid out
    all stay in :func:`services.change_requests.schedule_change_request` —
    the same call the change's own Schedule button makes. This route is the
    two answers a stage inside a staged page has to give: come back HERE
    citing the change, and say in words what was created.
    """
    from flask_babel import gettext

    from ..services import change_requests as crsvc
    from ..services import settings_store
    from .appliances import _adom_arg

    # Through the SAME gate the citation uses. An id naming a change outside
    # this operator's ADOM must not be schedulable from here just because the
    # form posted it.
    cr = created_change(request.form.get('cr_id'))
    back = lambda: redirect(url_for(  # noqa: E731 - one destination, one author
        'upgrade_flow.index', **dict({'cr': cr.id} if cr is not None else {},
                                     **_adom_arg())))
    if cr is None:
        flash('That change request is not one this flow can schedule — it does '
              'not exist, or it is not visible to you. Nothing was scheduled.',
              'danger')
        return redirect(url_for('upgrade_flow.index', **_adom_arg()))

    try:
        per_round = int(request.form.get('per_round') or 0)
    except (TypeError, ValueError):
        per_round = 0
    if per_round < 1:
        # Refused, not defaulted: "how many go down at a time" is the one
        # question this card exists to ask, and answering it on the operator's
        # behalf is how sixty appliances reboot together.
        flash('Set how many appliances go in each round. Nothing was scheduled.',
              'warning')
        return back()
    try:
        gap = int(request.form.get('round_gap') or crsvc.DEFAULT_ROUND_GAP_MINUTES)
    except (TypeError, ValueError):
        gap = crsvc.DEFAULT_ROUND_GAP_MINUTES

    # The field is READONLY, not authoritative: a number input still answers
    # its spinner in some browsers, and readonly is a courtesy to the operator
    # rather than a guarantee to the server. Clamped to the same ceiling the
    # card renders, so a plan can never be STORED claiming a round wider than
    # the change it belongs to.
    device_ids = list(cr.device_ids_list or [])
    if device_ids:
        per_round = min(per_round, len(device_ids))

    # Two different things wear the word "Save" on this card, and collapsing
    # them is the bug this branch exists to prevent. An APPROVED change gets
    # real rows on the calendar. A change still waiting for a signature gets
    # its plan written onto the change and NOTHING scheduled - because the
    # executor re-checks approval at fire time and would find none, and
    # because printing "it is on the calendar" over an unapproved plan is a
    # sentence this product could not keep.
    gate_ok, _gate_why = crsvc.schedulable(cr)
    if not gate_ok:
        try:
            plan = crsvc.save_rollout_plan(
                cr.id, getattr(current_user, 'username', '') or '',
                per_round=per_round, round_gap_minutes=gap)
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), 'danger')
            return back()
        log_action('upgrade_flow.plan', target=cr.ref or f'#{cr.id}',
                   detail=f"rounds={plan.get('total')} "
                          f"per_round={plan.get('size')} "
                          f"gap={plan.get('gap')}m (not scheduled: "
                          f"{cr.status})")
        flash(gettext('Rollout plan saved on this change: %(total)d round(s) '
                      'of at most %(size)d appliance(s), %(gap)d minute(s) '
                      'apart. Nothing is in Scheduled Actions or on the '
                      'calendar yet — the rounds are created the moment this '
                      'change is approved.',
                      total=plan.get('total') or 1, size=plan.get('size') or 1,
                      gap=plan.get('gap') or crsvc.DEFAULT_ROUND_GAP_MINUTES),
              'success')
        return back()

    existed = bool(cr.scheduled_action_id)
    try:
        action_id = crsvc.schedule_change_request(
            cr.id, getattr(current_user, 'username', '') or '',
            per_round=per_round, round_gap_minutes=gap)
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), 'danger')
        return back()

    action = db.session.get(ScheduledAction, action_id)
    name = action.name if action is not None else f'CR #{cr.id}'
    total = len(crsvc.round_slices(cr.device_ids_list, per_round))
    log_action('upgrade_flow.schedule', target=cr.ref or f'#{cr.id}',
               detail=f'action={action_id} rounds={total} '
                      f'per_round={per_round} gap={gap}m')

    # The SAME sentence the other scheduling card in this product prints, from
    # the same message. Two spellings of "it is saved and on the calendar" is
    # how one of them comes to claim it over a row that is switched off.
    if existed:
        flash(gettext('The task “%(name)s” was updated in Scheduled Actions and '
                      'is on the calendar.', name=name), 'success')
    else:
        flash(gettext('The task “%(name)s” has been added to Scheduled Actions '
                      'and is on the calendar.', name=name), 'success')
    if total > 1:
        flash(gettext('It runs in %(total)d rounds of at most %(size)d '
                      'appliance(s), %(gap)d minute(s) apart — the first at '
                      '%(at)s.', total=total, size=per_round, gap=gap,
                      at=settings_store.to_local(cr.window_start)), 'info')
    return back()


def split_waves(devices, size: int) -> list[list]:
    """Split an ordered device list into waves of at most ``size``.

    Deterministic: the caller has already ordered the devices, and this only
    chunks. Kept as a plain function so the wave boundaries can be asserted
    without a request, a database or a clock — the arithmetic that decides
    which box goes down at 22:00 and which at 23:30 is exactly the part that
    must be testable in isolation.
    """
    size = max(1, int(size or 1))
    return [list(devices[i:i + size]) for i in range(0, len(devices), size)]


def wave_windows(start, count: int, minutes: int, gap: int) -> list[tuple]:
    """``[(start, end), ...]`` for ``count`` consecutive waves.

    Windows never overlap: wave *k+1* starts at wave *k*'s END plus the gap.
    Deriving each start from the FIRST one (``start + k*(minutes+gap)``) gives
    the same answer only while nothing is edited, and the moment an operator
    lengthens one window by hand the arithmetic silently puts two waves on the
    same appliances' upstream at once.

    ``start`` may be None — a batched rollout with no window yet is legitimate
    (the operator schedules each wave later), and inventing one here would put
    a window on a change nobody chose a time for.
    """
    if start is None:
        return [(None, None) for _ in range(max(0, count))]
    minutes = max(1, int(minutes or 1))
    gap = max(0, int(gap or 0))
    out, cursor = [], start
    for _ in range(max(0, count)):
        end = cursor + timedelta(minutes=minutes)
        out.append((cursor, end))
        cursor = end + timedelta(minutes=gap)
    return out


@bp.route('/waves', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def waves():
    """Stage 2, batched — split the selection into N waves, one change each.

    This is the shape a ninety-appliance rollout actually takes: the
    non-production boxes go down first, somebody looks at them, and only then
    does the next group get a window. It is built ENTIRELY on top of the
    single-change path — one wave is one ordinary change request, raised
    through :func:`app.views.change_requests.create_change_request`, carrying
    its own devices, its own evidence and its own approval. Nothing about
    approval, execution, documents or exports needed a wave-shaped variant,
    and giving them one would have been the two-implementations defect again.

    A wave that fails validation stops the batch and says which one. Creating
    waves 1-3 and abandoning 4-6 would leave a rollout that LOOKS scheduled
    while a third of the fleet has no window at all.
    """
    from ..views.change_requests import create_change_request
    from ..services import settings_store

    raw = request.form.getlist('device_ids')
    ids: list[int] = []
    for value in raw:
        try:
            ids.append(int(value))
        except (TypeError, ValueError):
            continue
    ids = list(dict.fromkeys(ids))
    if not ids:
        flash('Select at least one appliance to build waves from.', 'warning')
        return redirect(url_for('upgrade_flow.index'))

    devices = (visible_appliances()
               .filter(Appliance.id.in_(ids))
               .order_by(Appliance.name.asc()).all())
    if len(devices) != len(ids):
        flash('One or more selected appliances do not exist or are not visible '
              'to you. Nothing was created.', 'danger')
        return redirect(url_for('upgrade_flow.index'))

    try:
        size = int(request.form.get('wave_size') or 0)
    except (TypeError, ValueError):
        size = 0
    if size < 1:
        flash('Set how many appliances go in each wave.', 'warning')
        return redirect(url_for('upgrade_flow.index'))

    groups = split_waves(devices, size)
    if len(groups) > MAX_WAVES:
        flash(f'{len(devices)} appliance(s) at {size} per wave is '
              f'{len(groups)} waves; at most {MAX_WAVES} are created at once. '
              f'Raise the wave size or split the selection — nothing was '
              f'created.', 'danger')
        return redirect(url_for('upgrade_flow.index'))

    start = None
    if (request.form.get('window_start') or '').strip():
        # Through the ONE timezone conversion path, exactly as the change form
        # does. A wave plan parsed as if the operator had typed UTC opens every
        # window in the batch at the wrong hour, consistently, which is how a
        # mistake like that survives review.
        start = settings_store.parse_local(request.form.get('window_start'))
    windows = wave_windows(start, len(groups),
                           request.form.get('wave_minutes') or 120,
                           request.form.get('wave_gap') or 30)

    # Preps arrive for the WHOLE selection; each wave keeps only its own. The
    # per-run appliance check inside create_change_request would drop the rest
    # anyway — filtering here as well means a wave never even offers evidence
    # about a box it does not touch.
    prep_by_dev: dict[int, str] = {}
    for pair in request.form.getlist('prep_pairs'):
        dev, _, prep = str(pair).partition(':')
        try:
            prep_by_dev[int(dev)] = prep
        except (TypeError, ValueError):
            continue

    group_ref = f'W{datetime.utcnow().strftime("%Y%m%d%H%M%S")}-{ids[0]}'
    title = (request.form.get('title') or '').strip()
    if not title:
        # Refused rather than allowed through: the suffix alone is non-empty,
        # so an empty title would sail past create_change_request's own check
        # and produce a register of changes called "— wave 1/6".
        flash('The waves need a title. It is proposed from the change type — '
              'restore it or write your own. Nothing was created.', 'danger')
        return redirect(url_for('upgrade_flow.index'))
    created = []
    for index, (members, (w_start, w_end)) in enumerate(zip(groups, windows), 1):
        # The suffix is reserved out of the 200-character budget instead of
        # being appended and truncated away: "… — wave 3/6" is the only thing
        # on the change list that tells two waves apart, and it is the part a
        # blind truncation would cut.
        suffix = f' — wave {index}/{len(groups)}'
        cr, error = create_change_request({
            'title': f'{title[:200 - len(suffix)]}{suffix}',
            'action': CR_ACTION,
            'risk': request.form.get('risk'),
            'reason': request.form.get('reason'),
            'rollback': request.form.get('rollback'),
            'doc_lang': request.form.get('doc_lang'),
            # Carried, not dropped: a wave that loses the owner, the notify
            # address and the approval mode is silently the un-owned,
            # un-notified, locally-approved variant of the same change.
            'owner': request.form.get('owner'),
            'notify_to': request.form.get('notify_to'),
            'approval_mode': request.form.get('approval_mode'),
            'device_ids': [d.id for d in members],
            'prep_ids': [prep_by_dev[d.id] for d in members
                         if prep_by_dev.get(d.id)],
            # Every wave of one batch is the SAME move; carrying it per wave
            # rather than per batch is how each wave's own document states its
            # destination without a reader having to find the others.
            'target_version': request.form.get('target_version'),
            'window_start': w_start,
            'window_end': w_end,
            'requested_by': getattr(current_user, 'username', '') or '',
        })
        if cr is None:
            db.session.rollback()
            flash(f'Wave {index} was refused: {error} '
                  f'{len(created)} wave(s) had already been created — open '
                  f'Change Requests and remove them before retrying.', 'danger')
            return redirect(url_for('upgrade_flow.index'))
        cr.wave_group = group_ref
        cr.wave_index = index
        cr.wave_total = len(groups)
        db.session.commit()
        created.append(cr)

    log_action('upgrade_flow.waves', target=group_ref,
               detail=f'{len(created)} waves over {len(devices)} appliances')
    flash(f'{len(created)} wave(s) raised over {len(devices)} appliance(s). '
          f'Each is an ordinary change request: approve, schedule and execute '
          f'them one at a time.', 'success')
    return redirect(url_for('upgrade_flow.index'))


def _visible_to_me(cr) -> bool:
    """Does this change name any appliance this operator can see?

    A change with NO devices is visible: it names nothing to be scoped by, and
    hiding it would make an empty change unreachable from the page that raised
    it. One author, because the 404 gate and the "just created" citation must
    agree about what "visible" means — disagreeing would either 404 a change
    the flow had just cited or cite one its own page refuses to open.
    """
    ids = cr.device_ids_list
    if not ids:
        return True
    visible = {row[0] for row in
               visible_appliances().with_entities(Appliance.id).all()}
    return any(i in visible for i in ids)


def _cr_or_404(cr_id: int) -> ChangeRequest:
    """Load an upgrade change, honouring the SAME ADOM scope as its own page.

    Scoped by the devices it names, exactly as ``change_requests`` does. 404,
    never 403: this route must not confirm that a change outside the operator's
    ADOM exists.
    """
    cr = ChangeRequest.query.get_or_404(cr_id)
    if not _visible_to_me(cr):
        abort(404)
    return cr


def execution_state(cr) -> dict:
    """Everything stage 4 knows about a change's execution, as plain data.

    ONE author for the page and its polling endpoint. Two of them would drift
    the instant somebody fixed a status rule in the template and not in the
    JSON, and the pair that drifts here is "what the operator is watching"
    against "what the page refreshes it to".

    Devices are listed from the CHANGE, not from the run: a change over twenty
    appliances whose run has reached the third one must show seventeen pending
    rows. Listing only what the run has touched renders a window that is 15%
    done as one that is complete.
    """
    devices = (Appliance.query.filter(Appliance.id.in_(cr.device_ids_list)).all()
               if cr.device_ids_list else [])
    action = (db.session.get(ScheduledAction, cr.scheduled_action_id)
              if cr.scheduled_action_id else None)
    run = None
    if action is not None:
        run = (ScheduledActionRun.query
               .filter_by(action_id=action.id)
               .order_by(ScheduledActionRun.id.desc()).first())
    rows = ({r.appliance_id: r for r in
             ScheduledActionTarget.query.filter_by(run_id=run.id).all()}
            if run is not None else {})
    run_over = run is not None and run.status != 'running'

    targets = []
    for dev in sorted(devices, key=lambda d: (d.name or '').lower()):
        row = rows.get(dev.id)
        if row is None:
            # 'pending' and 'never reported' are different facts. A device the
            # run has not reached yet is pending; a device the run finished
            # without ever opening a row for is not, and collapsing the two
            # would hide a target-resolution bug as ordinary progress.
            state = 'not_run' if run_over else 'pending'
            targets.append({'appliance_id': dev.id, 'appliance': dev.name,
                            'kind': dev.kind or '', 'status': state,
                            'summary': '', 'elapsed_ms': None,
                            'started_at': None})
            continue
        status = row.status
        if status == 'running' and run_over:
            # The run ended and this device never stamped an outcome — the
            # worker died mid-window. It is NOT graded 'failed': nobody
            # observed the device, and asserting an outcome nobody measured is
            # how a box that upgraded fine gets rolled back.
            status = 'interrupted'
        targets.append({
            'appliance_id': dev.id, 'appliance': dev.name,
            'kind': dev.kind or '', 'status': status,
            'summary': row.summary or '', 'elapsed_ms': row.elapsed_ms,
            'started_at': (row.started_at.isoformat()
                           if row.started_at else None),
        })

    done = sum(1 for t in targets if t['status'] in ('ok', 'failed'))
    return {
        'cr_id': cr.id, 'ref': cr.ref or f'#{cr.id}', 'status': cr.status,
        'action_id': getattr(action, 'id', None),
        'run_id': getattr(run, 'id', None),
        'run_status': getattr(run, 'status', None),
        'run_summary': getattr(run, 'summary', '') or '',
        'targets': targets,
        'total': len(targets),
        'done': done,
        'ok': sum(1 for t in targets if t['status'] == 'ok'),
        'failed': sum(1 for t in targets if t['status'] == 'failed'),
        # Percentage of DEVICES, not of elapsed time. A window that is half
        # over says nothing about how many boxes are upgraded.
        'percent': int(round(100.0 * done / len(targets))) if targets else 0,
    }


@bp.route('/change/<int:cr_id>')
@login_required
@require_permission(Permission.BACKUP)
def progress(cr_id):
    """Stage 4 — per-device execution progress for one change."""
    from ..services import change_requests as crsvc, prep_store
    cr = _cr_or_404(cr_id)
    runnable_ok, runnable_reason = crsvc.cr_runnable(cr)
    return render_template('upgrade_flow/progress.html',
                           cr=cr, state=execution_state(cr),
                           evidence=prep_store.coverage(cr),
                           runnable_ok=runnable_ok,
                           runnable_reason=runnable_reason,
                           executable=sa.get_spec(cr.action) is not None)


@bp.route('/change/<int:cr_id>/progress.json')
@login_required
@require_permission(Permission.BACKUP)
def progress_json(cr_id):
    """The same state the page renders, for polling. See :func:`execution_state`."""
    return jsonify(execution_state(_cr_or_404(cr_id)))


@bp.route('/change/<int:cr_id>/start', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def start_now(cr_id):
    """Fire the change's bound action NOW, out of process.

    It brings ``next_run`` forward and lets the scheduler sidecar pick it up on
    its next tick; it does NOT run the upgrade in this request. Scheduled
    Actions' own Run-now executes synchronously in the web worker, which is
    fine for a one-box sweep and wrong here: sixty appliances upgraded
    sequentially outstay any HTTP timeout, and a worker recycled mid-window
    kills the change halfway through with the browser showing a gateway error.

    The window is NOT bypassed. ``cr_runnable`` is re-checked at fire time by
    the executor regardless of what this route did, so bringing the clock
    forward on a change that is not yet approved buys a 'skipped' run and
    nothing else — but it is refused here too, while somebody is still looking
    at the screen.
    """
    cr = _cr_or_404(cr_id)
    from ..services import change_requests as crsvc
    ok, reason = crsvc.cr_runnable(cr)
    if not ok:
        flash(f'Not started — {reason}. The maintenance window is the '
              f'authorization; this button does not replace it.', 'danger')
        return redirect(url_for('upgrade_flow.progress', cr_id=cr.id))
    action = (db.session.get(ScheduledAction, cr.scheduled_action_id)
              if cr.scheduled_action_id else None)
    if action is None:
        flash('This change has no bound action yet — schedule it first.',
              'warning')
        return redirect(url_for('change_requests.detail', id=cr.id))
    if action.running_at is not None:
        flash('The bound action is already running.', 'warning')
        return redirect(url_for('upgrade_flow.progress', cr_id=cr.id))
    action.next_run = datetime.utcnow()
    action.enabled = True
    db.session.commit()
    log_action('upgrade_flow.start_now', target=cr.ref or f'#{cr.id}',
               detail=f'action={action.id}')
    flash('Execution requested. The scheduler picks it up within a minute and '
          'this page shows each appliance as it is reached.', 'success')
    return redirect(url_for('upgrade_flow.progress', cr_id=cr.id))


@bp.route('/prep', methods=['POST'])
@login_required
@require_permission(Permission.BACKUP)
def prep():
    """Stage 1 — pre-flight every selected device and PERSIST each run."""
    from ..services import prep_store
    raw = request.form.getlist('device_ids')
    ids: list[int] = []
    for value in raw:
        try:
            ids.append(int(value))
        except (TypeError, ValueError):
            continue
    ids = list(dict.fromkeys(ids))
    if not ids:
        flash('Select at least one appliance to pre-flight.', 'warning')
        return redirect(url_for('upgrade_flow.index'))
    if len(ids) > MAX_SWEEP:
        flash(f'{len(ids)} appliances selected; one sweep covers at most '
              f'{MAX_SWEEP}. Run it in batches — nothing was started.', 'danger')
        return redirect(url_for('upgrade_flow.index'))

    # WHERE this window is going, answered before anything runs. Refused, not
    # defaulted: a pre-flight is evidence for a specific move, and a sweep that
    # stored no destination produces rows citable as proof of any upgrade at
    # all — including the one nobody read the release notes for.
    #
    # Checked AFTER the cap, deliberately, and this order was got wrong once.
    # Putting it first read better ("answer the one question you must answer")
    # and it took the cap's message away: 41 selected appliances with no
    # destination were told to pick a version, and the operator retried 41
    # appliances. The cap's sentence NAMES THE NUMBER, which is the thing they
    # have to act on either way -- `test_an_oversized_sweep_starts_nothing_and
    # _says_how_many` is the guard that settled it, and it bit.
    # Against the page's own list -- _eligible() is what the select was
    # built from -- so a refusal here names the same options the operator
    # was looking at when they chose.
    options = target_options(devices=_eligible())
    target, target_error = resolve_target(request.form.get('target_version'),
                                          options)
    if target_error:
        flash(target_error, 'danger')
        return redirect(url_for('upgrade_flow.index'))

    # Re-resolve through visible_appliances(): the posted ids are user input,
    # and a device this user cannot see must not be backed up because its id
    # was typed into a form.
    devices = (visible_appliances()
               .filter(Appliance.id.in_(ids))
               .order_by(Appliance.name.asc()).all())
    kinds = prep_kinds()
    wrong = [d for d in devices if kinds and (d.kind or '') not in kinds]
    if wrong:
        flash('The pre-upgrade does not run against '
              + ', '.join(sorted({(d.kind or "?") for d in wrong}))
              + ' (' + ', '.join(d.name for d in wrong) + '). It supports: '
              + ', '.join(kinds) + '. Nothing was started.', 'danger')
        return redirect(url_for('upgrade_flow.index'))
    if len(devices) != len(ids):
        flash('One or more selected appliances do not exist or are not '
              'visible to you. Nothing was started.', 'danger')
        return redirect(url_for('upgrade_flow.index'))

    # PER APPLIANCE, and last, because every check above is about the
    # window (how many, towards what, may you see them, does the action even
    # support their product) while this one is about the pair (this box, this
    # destination). Running it earlier would take the cap's number or the
    # visibility refusal away from a selection that has both problems.
    chosen = next((o for o in options if o.get('version') == target), None)
    split = sweep_split(target, (chosen or {}).get('products') or [], devices)
    if not split['run']:
        for hold in split['held']:
            flash(hold['reason'], 'danger')
        flash(f'Nothing was started: not one of the {len(split["held"])} '
              f'selected appliance(s) would move forward to {target}. Pick a '
              f'later version, or select an appliance that is still behind '
              f'it.', 'danger')
        return redirect(url_for('upgrade_flow.index', target=target))
    for hold in split['held']:
        flash(f'{hold["reason"]} It was skipped; the rest of the sweep ran.',
              'warning')
    devices = split['run']

    rows = prep_store.run_bulk(
        devices,
        do_backup=request.form.get('backup', '1') == '1',
        do_health=request.form.get('health', '1') == '1',
        do_services=request.form.get('services', '1') == '1',
        target_version=target,
        created_by=getattr(current_user, 'username', '') or '')

    clean = [r for r in rows if r['ok'] and r['stored']]
    dirty = [r for r in rows if r['stored'] and not r['ok']]
    broken = [r for r in rows if not r['stored']]
    log_action('upgrade_flow.prep_sweep',
               target=f'{len(rows)} appliances',
               detail=f'to={target} clean={len(clean)} not-clean={len(dirty)} '
                      f'failed={len(broken)} skipped={len(split["held"])}')
    # Three counts, never one. "38 of 40 succeeded" hides which two, and the
    # two that failed are the only ones anybody has to act on before the
    # window opens.
    # The destination is NAMED in the sentence that reports the sweep. Three
    # counts and no target reads as "the fleet is ready", which is the claim
    # this column exists to qualify: ready FOR WHAT.
    # A FOURTH count, not folded into "could not be pre-flighted". A box
    # that was skipped because it is already there had nothing go wrong with
    # it, and reporting the two together would send somebody to debug a
    # healthy appliance.
    skipped = ('' if not split['held'] else
               f' {len(split["held"])} skipped: already on {target} or past it.')
    flash(f'Pre-upgrade swept {len(rows)} appliance(s) towards {target}: '
          f'{len(clean)} clean, {len(dirty)} ran but not clean, '
          f'{len(broken)} could not be pre-flighted.' + skipped,
          'success' if not broken and not dirty and not split['held']
          else 'warning')
    for row in broken:
        flash(f'{row["name"]}: {row["error"] or "no evidence stored"}', 'danger')
    for row in dirty:
        flash(f'{row["name"]}: {row["summary"]}', 'warning')
    return redirect(url_for('upgrade_flow.index', target=target))
