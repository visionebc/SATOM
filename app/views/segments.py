"""**Network Segments** — standalone admin page.

Named back-end networks (CIDR + interface + gateway) from which a new policy
builds its server pool, each scoped to a classification value. Ported out of the
Settings console into its own page (Administrator section).

Admin-only (USER_MANAGE), mirroring the desktop Settings console.
"""
from __future__ import annotations

import ipaddress

from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import settings_store as store
from ..services.audit import log_action

bp = Blueprint('segments', __name__, url_prefix='/segments')


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    return render_template(
        'segments/index.html',
        segments=store.segments(),
        classification=store.all_classification(),
    )


@bp.route('/save', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save():
    names = request.form.getlist('seg_name[]')
    rows, bad_cidr = [], []
    for i, name in enumerate(names):
        def col(field):
            vals = request.form.getlist(f'seg_{field}[]')
            return vals[i] if i < len(vals) else ''
        cidr = (col('cidr') or '').strip()
        if not (name or '').strip() and not cidr:
            continue
        if cidr:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                bad_cidr.append(cidr)
                continue
        rows.append({
            'name': name, 'zone': col('zone'), 'line': col('line'),
            'department': col('department'), 'cidr': cidr,
            'interface': col('interface') or 'port1', 'gateway': col('gateway'),
            'note': col('note'),
        })
    store.save_segments(rows)
    log_action('segments.save', detail=f'{len(rows)} segment(s)')
    if bad_cidr:
        flash(f"Skipped invalid CIDR(s): {', '.join(bad_cidr)}", 'warning')
    flash(f'{len(rows)} network segment(s) saved.', 'success')
    return redirect(url_for('segments.index'))
