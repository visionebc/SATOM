"""Capacity Limits admin — the editable catalog behind the capacity guardrails.

One row per (product, firmware major, platform, object type). The page shows
Fortinet's FACTORY limit per device (from the knowledge / API packs; a
FortiWeb-VM's depends on its memory) and the admin's OWN limit, entered as an
absolute NUMBER or as a PERCENT of the factory limit; ``hard_max`` is only an
override of the factory number. Automations honour the effective cap (the
lowest) via ``services.capacity.check_headroom``.
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
    """OrderedDict[(product, fw_major, platform)] -> [CapacityLimit …] in the
    catalog's object-type order, scoped to the active ADOM's product (a
    FortiADC session sees only 'fortiadc' groups, FortiWeb the rest, Global
    everything)."""
    from ..services.product_scope import scope_query
    order = {k: i for i, (k, _) in enumerate(capsvc.object_types_ordered())}
    rows = scope_query(CapacityLimit.query, CapacityLimit.product).order_by(
        CapacityLimit.model, CapacityLimit.firmware_major).all()
    groups: OrderedDict = OrderedDict()
    for r in rows:
        if r.object_type not in capsvc.OBJECT_TYPES:
            continue        # a type retired from the catalog: not editable here
        groups.setdefault((r.product, r.firmware_major, r.model), []).append(r)
    for key in groups:
        groups[key].sort(key=lambda r: order.get(r.object_type, 99))
    return groups


def _fleet_by_group():
    """(product, fw_major, platform) -> [appliance …] over the ADOM-visible
    fleet, and the catalog rows each group needs (insert-only, so the page
    shows every fleet platform with its factory limits without a click)."""
    from ..models import visible_appliances
    out: dict = {}
    added = 0
    for a in visible_appliances().order_by(Appliance.name).all():
        product = a.kind or capsvc.PRODUCT_DEFAULT
        if product != capsvc.PRODUCT_DEFAULT:
            continue        # the object-type catalog counts FortiWeb objects only
        fw = capsvc.firmware_major(a.firmware)
        model = capsvc.catalog_model(a.model, product)
        if not model or not fw:
            continue
        out.setdefault((product, fw, model), []).append(a)
    for (product, fw, model) in out:
        added += capsvc.ensure_rows_for(model, fw, product=product, commit=False)
    if added:
        db.session.commit()
    return out


def _cell(rows_h: list, row) -> dict:
    """What one object-type row shows, from the headroom of every device of
    the group (they share the platform and the firmware major; a VM's factory
    number still differs by memory, and the build may differ by patch)."""
    if not rows_h:
        return {"used": None, "factory": [], "effective": [], "info": {},
                "contradicted": []}
    fac = [(a.name, h.factory) for a, h in rows_h]
    eff = [(a.name, h.effective_cap) for a, h in rows_h]
    info = next((h.factory_info for _a, h in rows_h if h.factory is not None),
                rows_h[0][1].factory_info)
    return {"used": max(h.used for _a, h in rows_h),
            "used_by": [(a.name, h.used) for a, h in rows_h],
            "factory": fac, "factory_same": len({v for _n, v in fac}) == 1,
            "effective": eff, "effective_same": len({v for _n, v in eff}) == 1,
            "info": info,
            "contradicted": [(a.name, h.used, h.factory) for a, h in rows_h
                             if h.contradicted],
            "scope": rows_h[0][1].scope}


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    fleet = _fleet_by_group()
    groups = _grouped_rows()
    view: dict = {}
    for key, rows in groups.items():
        devices = fleet.get(key, [])
        per = {}
        for r in rows:
            if devices:
                per[r.id] = _cell([(a, capsvc.headroom(a, r.object_type)) for a in devices], r)
                continue
            # A platform planned on this page with no device yet: the factory
            # number of the newest build of that major (a VM has no memory to
            # evaluate its rule against, so it shows the rule).
            from types import SimpleNamespace
            ghost = SimpleNamespace(id=None, name="", model=key[2], kind=key[0],
                                    firmware="%s.9999" % key[1])
            f = capsvc.factory_for(ghost, r.object_type)
            eff, _b, _c = capsvc.effective_limit(f.value, r)
            per[r.id] = {"used": None, "factory": [("", f.value)], "factory_same": True,
                         "effective": [("", eff)], "effective_same": True,
                         "info": f.to_dict(), "contradicted": [],
                         "scope": capsvc.OBJECT_TYPES[r.object_type]["scope"]}
        view[key] = {"devices": devices, "cells": per}
    labels = dict(capsvc.object_types_ordered())
    from ..services import product_scope
    from ..services import device_health as devhealth
    # The "in use" highlight follows the configured capacity warning level
    # of each product (Thresholds page), not a hard-coded 80 %.
    warn_pct = {p: devhealth.thresholds(p)[0] for (p, _f, _m) in groups}
    return render_template('capacity/index.html', groups=groups, view=view,
                           labels=labels, known_models=capsvc.KNOWN_MODELS,
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
    model = capsvc.catalog_model(model, product) or model
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
            errors.append(f'{row.model}/{row.object_type}: the override must be a non-negative integer')
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
                errors.append(f'{row.model}/{row.object_type}: your limit {opcap} exceeds the override {hard}')
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
    model = capsvc.catalog_model(model, product) or model
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
