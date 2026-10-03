"""Capacity Limits admin — the editable catalog behind the capacity guardrails.

One row per (product, firmware major, model, object type): ``hard_max`` is
Fortinet's ceiling (datasheet / Appendix B — admin-entered, the unlicensed VMs
can't self-report a SKU) and the operational cap is the admin's OWN safety
buffer, entered either as an absolute NUMBER or as a PERCENT of the hard max.
Automations honour the effective cap (min of both) via
``services.capacity.check_headroom``.
"""
from __future__ import annotations

from collections import OrderedDict

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from ..auth.decorators import require_permission
from ..models import Appliance, CapacityLimit, Permission, db
from ..services import capacity as capsvc
from ..services.audit import log_action

bp = Blueprint('capacity', __name__, url_prefix='/capacity')


def _grouped_rows():
    """OrderedDict[(product, fw_major, model)] -> [CapacityLimit …] in the
    catalog's object-type order, scoped to the active ADOM's product (a
    FortiADC session sees only 'fortiadc' groups, FortiWeb the rest, Global
    everything)."""
    from ..services.product_scope import scope_query
    order = {k: i for i, (k, _) in enumerate(capsvc.object_types_ordered())}
    rows = scope_query(CapacityLimit.query, CapacityLimit.product).order_by(
        CapacityLimit.model, CapacityLimit.firmware_major).all()
    groups: OrderedDict = OrderedDict()
    for r in rows:
        groups.setdefault((r.product, r.firmware_major, r.model), []).append(r)
    for key in groups:
        groups[key].sort(key=lambda r: order.get(r.object_type, 99))
    return groups


def _fleet_usage():
    """(model, fw_major) -> {object_type: max used across matching appliances},
    over the ADOM-visible fleet only."""
    from ..models import visible_appliances
    usage: dict = {}
    for a in visible_appliances().all():
        fw = capsvc.firmware_major(a.firmware)
        if not a.model or not fw:
            continue
        bucket = usage.setdefault((a.model, fw), {})
        for h in capsvc.fleet_headroom(a):
            bucket[h.object_type] = max(bucket.get(h.object_type, 0), h.used)
    return usage


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    from ..models import visible_appliances
    groups = _grouped_rows()
    usage = _fleet_usage()
    fleet = []
    known = {(p, m, f) for (p, f, m) in groups}
    for a in visible_appliances().order_by(Appliance.name).all():
        fw = capsvc.firmware_major(a.firmware)
        product = a.kind or capsvc.PRODUCT_DEFAULT
        if a.model and fw and (product, a.model, fw) not in known:
            if (product, a.model, fw) not in [(x['product'], x['model'], x['fw']) for x in fleet]:
                fleet.append({'product': product, 'model': a.model, 'fw': fw})
    labels = dict(capsvc.object_types_ordered())
    from ..services import product_scope
    from ..services import device_health as devhealth
    # The "in use" highlight follows the configured capacity warning level
    # of each product (Thresholds page), not a hard-coded 80 %.
    warn_pct = {p: devhealth.thresholds(p)[0] for (p, _f, _m) in groups}
    return render_template('capacity/index.html', groups=groups, usage=usage,
                           missing_models=fleet, labels=labels,
                           product_options=product_scope.creatable_kinds(),
                           warn_pct=warn_pct)


@bp.route('/add-model', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def add_model():
    from ..services import product_scope
    model = (request.form.get('model') or '').strip()
    fw = (request.form.get('firmware_major') or '').strip()
    if not model or not fw:
        flash('Model and firmware major are both required.', 'danger')
        return redirect(url_for('capacity.index'))
    # The catalog is per product: rows created without one were always
    # FortiWeb rows, invisible from the product the model belongs to.
    offered = [k for k, _ in product_scope.creatable_kinds()]
    product = (request.form.get('product') or '').strip().lower() or (
        offered[0] if len(offered) == 1 else capsvc.PRODUCT_DEFAULT)
    if product not in offered:
        flash(f'This ADOM cannot add capacity rows for {product}.', 'danger')
        return redirect(url_for('capacity.index'))
    n = capsvc.ensure_rows_for(model, fw, product=product)
    log_action('capacity.model_add', f'{product}/{model}/{fw}', detail=f'{n} object-type rows')
    flash(f'Added {model} ({fw}, {product}) — {n} object types ready to configure.', 'success')
    return redirect(url_for('capacity.index'))


@bp.route('/save', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save():
    changed = 0
    errors = []
    ids = request.form.getlist('row_id', type=int)
    for rid in ids:
        row = db.session.get(CapacityLimit, rid)
        if row is None:
            continue
        raw_hard = (request.form.get(f'hard_{rid}') or '').strip()
        mode = (request.form.get(f'mode_{rid}') or 'none').strip()
        raw_val = (request.form.get(f'val_{rid}') or '').strip()

        try:
            hard = int(raw_hard) if raw_hard else None
            if hard is not None and hard < 0:
                raise ValueError
        except ValueError:
            errors.append(f'{row.model}/{row.object_type}: hard max must be a non-negative integer')
            continue

        opcap, pct = None, None
        if mode == 'number' and raw_val:
            try:
                opcap = int(raw_val)
                if opcap < 0:
                    raise ValueError
            except ValueError:
                errors.append(f'{row.model}/{row.object_type}: cap must be a non-negative integer')
                continue
            if hard is not None and opcap > hard:
                errors.append(f'{row.model}/{row.object_type}: cap {opcap} exceeds hard max {hard}')
                continue
        elif mode == 'percent' and raw_val:
            try:
                pct = float(raw_val)
                if not (0 < pct <= 100):
                    raise ValueError
            except ValueError:
                errors.append(f'{row.model}/{row.object_type}: percent must be greater than 0 and at most 100')
                continue

        if (row.hard_max, row.operational_cap, row.cap_percent) != (hard, opcap, pct):
            row.hard_max, row.operational_cap, row.cap_percent = hard, opcap, pct
            row.source = 'admin'
            row.updated_by = getattr(current_user, 'username', '') or ''
            changed += 1
    if changed:
        db.session.commit()
        log_action('capacity.limits_update', 'capacity_limits', detail=f'{changed} rows updated')
    for e in errors[:6]:
        flash(e, 'danger')
    if changed:
        flash(f'Saved {changed} limit row{"s" if changed != 1 else ""}.', 'success')
    elif not errors:
        flash('No changes.', 'info')
    return redirect(url_for('capacity.index'))


@bp.route('/delete-model', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete_model():
    from ..services.product_scope import scope_query
    model = (request.form.get('model') or '').strip()
    fw = (request.form.get('firmware_major') or '').strip()
    product = (request.form.get('product') or '').strip().lower() or capsvc.PRODUCT_DEFAULT
    # One product's catalog only, and only one this ADOM can see: the same
    # model name may exist for two products.
    q = scope_query(CapacityLimit.query, CapacityLimit.product).filter(
        CapacityLimit.model == model, CapacityLimit.firmware_major == fw,
        CapacityLimit.product == product)
    n = q.delete(synchronize_session=False)
    db.session.commit()
    log_action('capacity.model_delete', f'{product}/{model}/{fw}', detail=f'{n} rows removed')
    flash(f'Removed {model} ({fw}) — {n} rows.', 'success')
    return redirect(url_for('capacity.index'))
