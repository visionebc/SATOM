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
    prep_pick, prep_unresolved = preselect_prep(
        request.args.get('prep'), preselect, runs)
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
    from .change_requests import _tz_name, cr_view_context
    defaults = {
        'owner': (getattr(current_user, 'username', '') or ''),
        'notify_to': (email_service.config().get('default_to') or '').strip(),
    }
    render_lang = (lang_preset or fallback)
    # Resolved ONCE: the citation and the embedded view have to be the same
    # change, and two independent lookups of the same query argument is how
    # a page comes to name one record and render another.
    created = created_change(request.args.get('cr'))
    # Every change this flow has raised that this operator may see, newest
    # first. Stage 2 renders the CHANGE ITSELF, and until now the only way to
    # reach that rendering was to hand-type ?cr= -- so the stage looked like a
    # bare form to everyone who had not just pressed its button.
    #
    # Nothing here is auto-opened. The blocks it opens carry Approve, Schedule,
    # Mark notified and Cancel, which act on a real change; a page that picks
    # one for you is a page that can get one approved by somebody who thought
    # they were reading a form.
    #
    # Scoped through _visible_to_me -- the SAME gate the citation uses -- so
    # the picker cannot offer a change this very page would then decline to
    # render.
    flow_changes = [c for c in (ChangeRequest.query
                                .filter(ChangeRequest.action == CR_ACTION)
                                .order_by(ChangeRequest.id.desc())
                                .limit(60).all())
                    if _visible_to_me(c)][:12]
    # Returned as ONE dict and splatted by the caller. Enumerating the keys at
    # the render call is how a value this function computes can fail to reach
    # the template with every assertion about it still green.
    return dict(
        devices=devices, latest=latest, runs=runs,
        preselect_prep=prep_pick,
        preselect_prep_unresolved=prep_unresolved,
        defaults=defaults, tz_name=_tz_name(),
        preselect=preselect,
        preselect_unresolved=preselect_unresolved,
        wave_groups=wave_groups,
        risks=crsvc_risks(),
        kinds=prep_kinds(), max_sweep=MAX_SWEEP,
        max_waves=MAX_WAVES, crdoc=crdoc,
        cr_action=CR_ACTION,
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
        ticked=(posted['device_ids'] if posted is not None
                else ({preselect} if preselect else set())),
        prep_choice=prep_choice(devices, runs, preselect, prep_pick, posted),
        auto=auto_fields(posted, crdoc, devices, render_lang),
        created=created,
        flow_changes=flow_changes,
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
    )


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

    rows = prep_store.run_bulk(
        devices,
        do_backup=request.form.get('backup', '1') == '1',
        do_health=request.form.get('health', '1') == '1',
        do_services=request.form.get('services', '1') == '1',
        created_by=getattr(current_user, 'username', '') or '')

    clean = [r for r in rows if r['ok'] and r['stored']]
    dirty = [r for r in rows if r['stored'] and not r['ok']]
    broken = [r for r in rows if not r['stored']]
    log_action('upgrade_flow.prep_sweep',
               target=f'{len(rows)} appliances',
               detail=f'clean={len(clean)} not-clean={len(dirty)} '
                      f'failed={len(broken)}')
    # Three counts, never one. "38 of 40 succeeded" hides which two, and the
    # two that failed are the only ones anybody has to act on before the
    # window opens.
    flash(f'Pre-upgrade swept {len(rows)} appliance(s): {len(clean)} clean, '
          f'{len(dirty)} ran but not clean, {len(broken)} could not be '
          f'pre-flighted.',
          'success' if not broken and not dirty else 'warning')
    for row in broken:
        flash(f'{row["name"]}: {row["error"] or "no evidence stored"}', 'danger')
    for row in dirty:
        flash(f'{row["name"]}: {row["summary"]}', 'warning')
    return redirect(url_for('upgrade_flow.index'))
