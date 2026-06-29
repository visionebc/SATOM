"""**Naming** scheme — standalone admin page.

The name-pattern editor (ported ``services.naming``) with a live preview from one
sample web address. Split by **product** (FortiWeb / FortiADC) via a selector —
each product has its own object catalog and its own stored overrides.

Admin-only (USER_MANAGE), mirroring the desktop Settings console.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import naming as naming_svc
from ..services import settings_store as store
from ..services.audit import log_action

bp = Blueprint('naming', __name__, url_prefix='/naming')


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    product = naming_svc.valid_product(request.args.get('product'))
    scheme = naming_svc.effective_scheme(store.naming_overrides(product), product)
    return render_template(
        'naming/index.html',
        naming_sections=naming_svc.elements_by_section(product),
        naming_scheme=scheme,
        products=naming_svc.PRODUCTS,
        current_product=product,
        product_label=dict(naming_svc.PRODUCTS)[product],
    )


@bp.route('/save', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save():
    product = naming_svc.valid_product(request.form.get('product'))
    label = dict(naming_svc.PRODUCTS)[product]
    if request.form.get('action') == 'reset':
        store.reset_naming(product)
        log_action('naming.save', detail=f'Reset {label} naming to defaults')
        flash(f'{label} naming patterns restored to defaults.', 'success')
        return redirect(url_for('naming.index', product=product))
    scheme = {
        e.key: request.form.get('nm_' + e.key, '')
        for e in naming_svc.elements_for_product(product)
    }
    store.save_naming(scheme, product)
    log_action('naming.save',
               detail=f'{label}: {len([v for v in scheme.values() if v.strip()])} patterns')
    flash(f'{label} naming patterns saved.', 'success')
    return redirect(url_for('naming.index', product=product))
