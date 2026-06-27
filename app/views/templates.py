"""Templates — desired-state library admin page (web port of the desktop
Settings → WPP Templates console).

Admin-only: templates are authored by admins and pushed on demand. Applying a
template to a live appliance is a separate, audited action and is intentionally
not wired here yet (the library is useful standalone as versioned desired state).
"""
from __future__ import annotations

import json

from flask import (Blueprint, render_template, request, jsonify, flash,
                   redirect, url_for, abort)
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Permission, Template
from ..services import templates as lib
from ..services.audit import log_action

bp = Blueprint('templates', __name__, url_prefix='/templates')


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    kind = request.args.get('kind') or None
    if kind and kind not in Template.KINDS:
        kind = None
    return render_template(
        'templates/index.html',
        templates=lib.list_templates(kind),
        kinds=Template.KINDS,
        kind_labels=lib.KIND_LABELS,
        active_kind=kind,
    )


@bp.route('/', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def create():
    kind = request.form.get('kind', '')
    name = request.form.get('name', '')
    body = request.form.get('body', '{}')
    note = request.form.get('note', '')
    try:
        row = lib.save_template(kind, name, body, note=note)
        log_action('template.create', target=f'{row.kind}/{row.name}',
                   detail=f'version {row.version}')
        flash(f'Template "{row.name}" saved (v{row.version}).', 'success')
    except ValueError as exc:
        flash(f'Could not save template: {exc}', 'danger')
    return redirect(url_for('templates.index', kind=kind if kind in Template.KINDS else None))


@bp.route('/<int:template_id>')
@login_required
@require_permission(Permission.USER_MANAGE)
def detail(template_id: int):
    """Return a single template (incl. pretty-printed body) as JSON for the
    view/inspect modal."""
    row = lib.get_template(template_id)
    if row is None:
        abort(404)
    return jsonify({
        'id': row.id, 'kind': row.kind, 'name': row.name, 'version': row.version,
        'note': row.note or '', 'author': row.author or '',
        'locked': bool(row.locked),
        'created_at': row.created_at.isoformat() if row.created_at else '',
        'body': json.dumps(row.body_dict, indent=2, sort_keys=True),
    })


@bp.route('/<int:template_id>/delete', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete(template_id: int):
    row = lib.get_template(template_id)
    label = f'{row.kind}/{row.name}' if row else str(template_id)
    if lib.delete_template(template_id):
        log_action('template.delete', target=label)
        flash('Template deleted.', 'success')
    else:
        flash('Template not found or locked.', 'warning')
    return redirect(url_for('templates.index'))
