"""Operations > Automation > Mass Deploy — approved templates pushed to one or
many devices of the active ADOM (services.mass_deploy, 2026-10-24).

Gated like a fleet rollout from the Template Library: ``operations.apply``
(Run operations) AND ``operations.template_apply``. The preview never contacts
a device for real; the deploy is the canary-gated background job.

Secrets typed at apply time travel in this request and in the job's memory
only. They are not stored, logged or sent back (services.secret_mask).
"""
from __future__ import annotations

from flask import (Blueprint, abort, current_app, jsonify, render_template,
                   request)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..extensions import db
from ..services import mass_deploy as md
from ..services import secret_mask
from ..services import template_apply as ta
from ..services import template_compat as tc
from ..services.audit import log_action
from ..services.bulk import iter_push_items

bp = Blueprint('mass_deploy', __name__, url_prefix='/mass-deploy')


def _gate():
    if not current_user.can('operations.template_apply'):
        abort(403)


def _secrets_from_form() -> dict:
    """``{field_key: value}`` from ``secret:<field_key>`` inputs."""
    return {k[len('secret:'):]: v for k, v in request.form.items()
            if k.startswith('secret:') and v}


@bp.route('/')
@login_required
@require_permission('operations.apply')
def index():
    _gate()
    product = tc.session_product()
    supported = product in md.PRODUCTS
    entries = md.catalog(product) if supported else []
    selected = None
    devices = []
    tid = request.args.get('template', type=int)
    if supported and tid:
        selected = md.get_deployable(tid, product)
        if selected is not None:
            devices = md.device_rows(selected, product)
    return render_template(
        'mass_deploy/index.html', product=product, supported=supported,
        entries=entries, selected=selected,
        selected_scope=md.scope_info(selected) if selected is not None else None,
        secret_fields=(secret_mask.secret_fields(iter_push_items(selected.body_dict))
                       if selected is not None else []),
        devices=devices, history=md.history(product) if supported else [],
        can_override=bool(current_user.can('operations.template_approve')),
        stale_template=bool(tid) and selected is None)


def _plan(template_id: int):
    product = tc.session_product()
    if product not in md.PRODUCTS:
        return None, (jsonify({'ok': False, 'error': 'Mass Deploy works in a FortiWeb ADOM.'}), 400)
    row = md.get_deployable(template_id, product)
    if row is None:
        return None, (jsonify({'ok': False, 'error': 'This template is not the newest '
                               'approved version in this ADOM any more — reload the page.'}), 409)
    ids = ta.parse_ids(request.form.getlist('device_ids'))
    if not ids:
        return None, (jsonify({'ok': False, 'error': 'Select at least one device.'}), 400)
    # fleet=True even for one device: Mass Deploy is a rollout, so the approval
    # must be validated for each target's build (an approver may override).
    plan = ta.Plan(row, ids, secrets=_secrets_from_form(), respect_pins=True, fleet=True)
    # visible_appliances() is the ADOM's devices: another ADOM's id is unknown.
    if plan.unknown:
        return None, (jsonify({'ok': False, 'error': 'Unknown appliance.'}), 404)
    return plan, None


@bp.route('/<int:template_id>/preview', methods=['POST'])
@login_required
@require_permission('operations.apply')
def preview(template_id: int):
    _gate()
    plan, err = _plan(template_id)
    if err:
        return err
    row = plan.row
    out = plan.preview()
    info = md.scope_info(row)
    limit = request.form.get('limit') == '1'
    will_bind = []
    if info['wpp'] and (info['scoped'] or limit):
        will_bind = [a.name for a in plan.targets if a.id not in set(info['bound'])]
    log_action('mass_deploy.preview', target=f'{row.kind}/{row.name}',
               detail=f'v{row.version} devices={plan.device_ids} '
                      f'blocked={out["compat"]["blocked"]} '
                      f'secrets_typed={len(plan.secrets["sent"])}')
    return jsonify({'ok': True, 'mode': 'preview',
                    'template': {'id': row.id, 'name': row.name, 'kind': row.kind,
                                 'version': row.version},
                    'scope': {'text': info['text'], 'will_bind': will_bind,
                              'limit': limit and not info['scoped']},
                    **out,
                    'can_override': bool(current_user.can('operations.template_approve'))
                                    and not plan.blocks})


@bp.route('/<int:template_id>/deploy', methods=['POST'])
@login_required
@require_permission('operations.apply')
def deploy(template_id: int):
    _gate()
    plan, err = _plan(template_id)
    if err:
        return err
    row = plan.row
    allowed, compat = plan.enforce(current_user, request.form.get('override_reason', ''),
                                   'mass_deploy.deploy')
    if not allowed:
        log_action('mass_deploy.refused', target=f'{row.kind}/{row.name}',
                   detail=' | '.join(compat['blocks'])[:1500])
        return jsonify({'ok': False, 'compat': compat,
                        'error': 'Refused: ' + '; '.join(compat['blocks'][:4])
                                 + (' (+%d more)' % (len(compat['blocks']) - 4)
                                    if len(compat['blocks']) > 4 else '')
                                 + ('' if plan.blocks else
                                    ' — ' + (compat.get('override_hint') or ''))}), 409
    by = getattr(current_user, 'username', '') or ''
    try:
        bound = md.bind_targets(row, plan.device_ids,
                                limit=request.form.get('limit') == '1', by=by)
        hist = md.record(row, plan, by=by, bound=bound)
        db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        return jsonify({'ok': False, 'error': str(exc)}), 400
    app = current_app._get_current_object()
    job = plan.start(app, by=by, compat=compat,
                     title=f'Mass Deploy "{row.name}" v{row.version} to '
                           f'{len(plan.device_ids)} device(s)',
                     meta={'trigger': 'mass_deploy', 'mass_deploy_id': hist.id},
                     on_done=md.finisher(app, hist.id))
    hist.job_id = job['id']
    db.session.commit()
    log_action('mass_deploy.start', target=f'{row.kind}/{row.name}',
               detail=f'v{row.version} devices={plan.device_ids} job={job["id"]} '
                      f'history={hist.id}'
                      + (f' bound={bound}' if bound else '')
                      + (f' secrets_typed={",".join(plan.secrets["sent"])}'
                         if plan.secrets['sent'] else '')
                      + (' override' if compat.get('overridden') else ''))
    return jsonify({'ok': True, 'mode': 'deploy', 'job_id': job['id'],
                    'history_id': hist.id, 'bound': bound}), 202
