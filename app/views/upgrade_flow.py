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
posts to :func:`app.views.change_requests.new`, stages 3 and 4 link into that
change. A second implementation of any of them is precisely the defect this
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


@bp.route('/')
@login_required
@require_permission(Permission.BACKUP)
def index():
    from ..services import prep_store
    devices = _eligible()
    latest = prep_store.latest_for_many([d.id for d in devices])
    # Changes that already cite a run, newest first — stage 2's "carry on with
    # the one you started" list. Bounded: this is a landing page, not a
    # register, and the full list is one click away on Change Requests.
    recent_crs = (ChangeRequest.query
                  .filter(ChangeRequest.action == 'upgrade')
                  .order_by(ChangeRequest.id.desc())
                  .limit(10).all())
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
    return render_template('upgrade_flow/index.html',
                           devices=devices, latest=latest,
                           recent_crs=recent_crs, wave_groups=wave_groups,
                           kinds=prep_kinds(), max_sweep=MAX_SWEEP,
                           max_waves=MAX_WAVES)


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
    created = []
    for index, (members, (w_start, w_end)) in enumerate(zip(groups, windows), 1):
        cr, error = create_change_request({
            'title': f'{title} — wave {index}/{len(groups)}',
            'action': 'upgrade',
            'risk': request.form.get('risk'),
            'reason': request.form.get('reason'),
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


def _cr_or_404(cr_id: int) -> ChangeRequest:
    """Load an upgrade change, honouring the SAME ADOM scope as its own page.

    Scoped by the devices it names, exactly as ``change_requests`` does. 404,
    never 403: this route must not confirm that a change outside the operator's
    ADOM exists.
    """
    cr = ChangeRequest.query.get_or_404(cr_id)
    ids = cr.device_ids_list
    if ids:
        visible = {row[0] for row in
                   visible_appliances().with_entities(Appliance.id).all()}
        if not any(i in visible for i in ids):
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
