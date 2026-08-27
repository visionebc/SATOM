"""**Network Segments** — standalone admin page.

Named back-end networks (CIDR + interface + gateway) from which a new policy
builds its server pool, each scoped to a classification value. Ported out of the
Settings console into its own page (Administrator section).

Admin-only (USER_MANAGE), mirroring the desktop Settings console.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import settings_store as store
from ..services.audit import log_action
from . import _segments_form as segment_form

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
    rows, bad_cidr = segment_form.parse_rows(request.form)
    try:
        store.save_segments(rows)
    except store.SegmentError as exc:
        # NOTHING was written. Re-showing the page would silently drop the
        # operator's edits, so the refusal is stated and the previous list is
        # what remains -- a rejected save is not a partial save.
        flash(str(exc), 'danger')
        return redirect(url_for('segments.index'))
    log_action('segments.save', detail=f'{len(rows)} segment(s)')
    if bad_cidr:
        flash(f"Skipped invalid CIDR(s): {', '.join(bad_cidr)}", 'warning')
    flash(f'{len(rows)} network segment(s) saved.', 'success')
    return redirect(url_for('segments.index'))
