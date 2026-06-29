"""Device **Classification** — standalone admin page.

The zones / lines / departments catalogs that drive the appliance
Zone/Line/Department dropdowns. Ported out of the Settings console into its own
page (Administrator section) so it reads like every other feature page.

Admin-only (USER_MANAGE), mirroring the desktop Settings console.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import settings_store as store
from ..services.audit import log_action

bp = Blueprint('classification', __name__, url_prefix='/classification')


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    return render_template(
        'classification/index.html',
        classification=store.all_classification(),
    )


@bp.route('/save', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save():
    counts = {}
    for kind in store.CLASSIFICATION_KINDS:
        raw = request.form.get(kind, '')
        values = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        store.save_classification(kind, values)
        counts[kind] = len(store.classification(kind))
    log_action('classification.save',
               detail=f"{counts.get('zones', 0)} zones, {counts.get('lines', 0)} lines, "
                      f"{counts.get('departments', 0)} departments")
    flash('Classification catalogs saved.', 'success')
    return redirect(url_for('classification.index'))
