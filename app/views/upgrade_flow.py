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

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Appliance, ChangeRequest, Permission, visible_appliances
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
    return render_template('upgrade_flow/index.html',
                           devices=devices, latest=latest,
                           recent_crs=recent_crs,
                           kinds=prep_kinds(), max_sweep=MAX_SWEEP)


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
