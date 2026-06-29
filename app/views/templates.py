"""Templates — desired-state library admin page (web port of the desktop
Settings → WPP Templates console).

Admin-only: templates are authored by admins and pushed on demand. Applying a
template to a live appliance is a separate, audited action and is intentionally
not wired here yet (the library is useful standalone as versioned desired state).
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

from flask import (Blueprint, render_template, request, jsonify, flash,
                   redirect, url_for, abort)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Appliance, Template
from ..services import templates as lib
from ..services.audit import log_action
from ..services.bulk import BulkRunner, iter_push_items

bp = Blueprint('templates', __name__, url_prefix='/templates')


def _safe_next(fallback: str) -> str:
    """Return a same-origin ``next`` target if present, else the fallback.

    Lets the per-section configuration page reuse the templates routes and bounce
    back to itself, without opening an open-redirect (only local paths allowed).
    """
    nxt = request.values.get('next') or ''
    if nxt.startswith('/') and not nxt.startswith('//'):
        ref = urlparse(nxt)
        if not ref.scheme and not ref.netloc:
            return nxt
    return fallback


def _pretty_json(raw: str) -> str:
    """Best-effort pretty-print of a stored JSON blob (empty -> '')."""
    if not (raw or '').strip():
        return ''
    try:
        return json.dumps(json.loads(raw), indent=2, sort_keys=True)
    except (ValueError, TypeError):
        return raw


@bp.route('/')
@login_required
@require_permission('operations.view')
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
        appliances=Appliance.query.order_by(Appliance.name).all(),
        edit_template_id=None,
    )


@bp.route('/', methods=['POST'])
@login_required
@require_permission('operations.template_save')
def create():
    kind = request.form.get('kind', '')
    name = request.form.get('name', '')
    body = request.form.get('body', '{}')
    note = request.form.get('note', '')
    exceptions = request.form.get('exceptions', '')
    try:
        row = lib.save_template(kind, name, body, note=note, exceptions=exceptions,
                                author=current_user.username)
        log_action('template.create', target=f'{row.kind}/{row.name}',
                   detail=f'version {row.version}')
        flash(f'Template "{row.name}" saved (v{row.version}).', 'success')
    except ValueError as exc:
        flash(f'Could not save template: {exc}', 'danger')
    return redirect(_safe_next(
        url_for('templates.index', kind=kind if kind in Template.KINDS else None)))


@bp.route('/<int:template_id>')
@login_required
@require_permission('operations.view')
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
        'exceptions': _pretty_json(row.exceptions or ''),
    })


@bp.route('/<int:template_id>/delete', methods=['POST'])
@login_required
@require_permission('operations.template_save')
def delete(template_id: int):
    row = lib.get_template(template_id)
    label = f'{row.kind}/{row.name}' if row else str(template_id)
    if lib.delete_template(template_id):
        log_action('template.delete', target=label)
        flash('Template deleted.', 'success')
    else:
        flash('Template not found or locked.', 'warning')
    return redirect(_safe_next(url_for('templates.index')))


@bp.route('/<int:template_id>/clone', methods=['POST'])
@login_required
@require_permission('operations.template_save')
def clone(template_id: int):
    """Clone a template (body + exceptions) under a new name (default '<name>
    (copy)'). The clone is unlocked and versioned for its name."""
    new_name = (request.form.get('new_name') or '').strip() or None
    try:
        row = lib.clone_template(template_id, new_name)
        log_action('template.clone', target=f'{row.kind}/{row.name}',
                   detail=f'from={template_id} version {row.version}')
        flash(f'Cloned to "{row.name}" (v{row.version}).', 'success')
    except ValueError as exc:
        flash(f'Could not clone template: {exc}', 'danger')
    return redirect(_safe_next(url_for('templates.index')))


@bp.route('/<int:template_id>/edit', methods=['GET', 'POST'])
@login_required
@require_permission('operations.template_save')
def edit(template_id: int):
    """Load an existing template's body + exceptions into the editor and save a
    NEW version of the same kind/name (the original version is preserved)."""
    row = lib.get_template(template_id)
    if row is None:
        abort(404)
    if request.method == 'POST':
        name = request.form.get('name', row.name)
        body = request.form.get('body', '{}')
        note = request.form.get('note', '')
        exceptions = request.form.get('exceptions', '')
        try:
            new = lib.save_template(row.kind, name, body, note=note,
                                    exceptions=exceptions, new_version=True,
                                    author=current_user.username)
            log_action('template.edit', target=f'{new.kind}/{new.name}',
                       detail=f'version {new.version} (from {template_id})')
            flash(f'Template "{new.name}" saved as v{new.version}.', 'success')
        except ValueError as exc:
            flash(f'Could not save template: {exc}', 'danger')
        return redirect(_safe_next(url_for('templates.index')))
    # GET — render the library with the edit modal pre-opened for this template.
    return render_template(
        'templates/index.html',
        templates=lib.list_templates(),
        kinds=Template.KINDS,
        kind_labels=lib.KIND_LABELS,
        active_kind=None,
        appliances=Appliance.query.order_by(Appliance.name).all(),
        edit_template_id=row.id,
    )


@bp.route('/<int:template_id>/apply', methods=['POST'])
@login_required
@require_permission('operations.template_apply')
def apply(template_id: int):
    """Apply a template to selected appliances.

    Two-step and gated: a POST WITHOUT ``confirm`` returns a JSON dry-run preview
    (no device is contacted for real); a POST WITH ``confirm=1`` performs the
    live write (canary device first, the rest only if the canary succeeds).
    """
    row = lib.get_template(template_id)
    if row is None:
        abort(404)

    device_ids: list[int] = []
    for value in request.form.getlist('device_ids'):
        try:
            device_ids.append(int(value))
        except (TypeError, ValueError):
            continue
    confirm = request.form.get('confirm') == '1'
    wants_json = (request.form.get('format') == 'json'
                  or 'application/json' in (request.headers.get('Accept') or ''))
    # Single-device apply works on any status (operations.template_apply, already
    # enforced above). Multi-device = fleet rollout: needs operations.apply AND an
    # APPROVED template. This is the "approved != deployed; fleet rollout is a
    # separate, gated action" rule.
    if len(device_ids) > 1:
        if not current_user.can('operations.apply'):
            if wants_json:
                return jsonify({'ok': False,
                                'error': 'Fleet rollout requires the Run operations '
                                         'permission.'}), 403
            abort(403)
        if row.status != Template.STATUS_APPROVED:
            if wants_json:
                return jsonify({'ok': False,
                                'error': 'Template must be APPROVED before a '
                                         'multi-device (fleet) rollout.'}), 403
            abort(403)
    items = iter_push_items(row.body_dict)

    if not device_ids:
        if wants_json:
            return jsonify({'ok': False, 'error': 'Select at least one device.'}), 400
        flash('Select at least one device to apply to.', 'warning')
        return redirect(_safe_next(url_for('templates.index')))

    if not confirm:
        # Dry-run preview only — pure, never contacts a device for real.
        preview = BulkRunner(items).preview(device_ids)
        log_action('template.apply.preview', target=f'{row.kind}/{row.name}',
                   detail=f'devices={device_ids} items={len(items)}')
        return jsonify({
            'ok': True, 'mode': 'preview',
            'template': {'id': row.id, 'name': row.name,
                         'kind': row.kind, 'version': row.version},
            'item_count': len(items),
            'preview': preview,
        })

    # Confirmed live apply. CONFIG_WRITE is already enforced by the decorator.
    result = BulkRunner(items).apply(device_ids, canary=1)
    runs = (result.get('canary') or []) + (result.get('rest') or [])
    ok_count = sum(1 for r in runs if r.get('ok'))
    total = len(runs)
    log_action('template.apply', target=f'{row.kind}/{row.name}',
               detail=f'devices={device_ids} items={len(items)} '
                      f'aborted={result.get("aborted")} ok={ok_count}/{total}')
    if result.get('aborted'):
        flash(f'Apply aborted — the canary device failed for "{row.name}". '
              'Remaining devices were skipped.', 'danger')
    elif ok_count == total:
        flash(f'Applied "{row.name}" v{row.version} to {ok_count}/{total} device(s).',
              'success')
    else:
        flash(f'Applied "{row.name}" v{row.version} to {ok_count}/{total} device(s) '
              '— some writes failed.', 'warning')
    return redirect(_safe_next(url_for('templates.index')))


@bp.route('/<int:template_id>/approve', methods=['POST'])
@login_required
@require_permission('operations.template_approve')
def approve(template_id: int):
    """Approve a pending template, making it eligible for fleet rollout."""
    try:
        row = lib.approve_template(template_id, reviewer=current_user.username)
        log_action('template.approve', target=f'{row.kind}/{row.name}',
                   detail=f'version {row.version}')
        flash(f'Approved "{row.name}" v{row.version} — now fleet-deployable.',
              'success')
    except ValueError as exc:
        flash(f'Could not approve template: {exc}', 'danger')
    return redirect(_safe_next(url_for('templates.index')))


@bp.route('/<int:template_id>/reject', methods=['POST'])
@login_required
@require_permission('operations.template_approve')
def reject(template_id: int):
    """Reject a template with an author-visible reason."""
    reason = (request.form.get('reason') or '').strip()
    try:
        row = lib.reject_template(template_id, reviewer=current_user.username,
                                  reason=reason)
        log_action('template.reject', target=f'{row.kind}/{row.name}',
                   detail=f'version {row.version}: {reason[:120]}')
        flash(f'Rejected "{row.name}" v{row.version}.', 'warning')
    except ValueError as exc:
        flash(f'Could not reject template: {exc}', 'danger')
    return redirect(_safe_next(url_for('templates.index')))
