"""Factory catalog pages: the predefined WPPs SATOM holds per firmware build +
API version, one entry's full tree, a comparison between two entries, and
"Save as template" from an entry.

Reading is gated on ``registry.view`` (the catalog is vendor content filed
by build, the same kind of knowledge as the API library). Saving a template
needs ``operations.template_save``, exactly like "Save as template" on a live
profile, and lands PENDING in the Template Library like every other template.
"""
from __future__ import annotations

import json

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_babel import gettext as _
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..services import factory_catalog as fc
from ..services.audit import log_action

bp = Blueprint('factory_catalog', __name__, url_prefix='/factory-catalog')

_DIFF_LIMIT = 400


def _row(r) -> dict:
    return {'id': r.id, 'kind': r.kind, 'kind_label': fc.KIND_LABEL.get(r.kind, r.kind),
            'name': r.name, 'firmware': r.firmware, 'build_no': r.build_no,
            'api_version': r.api_version, 'status': r.status,
            'status_reason': r.status_reason, 'node_count': r.node_count,
            'read_count': r.read_count, 'captured_from': r.captured_from,
            'captured_at': r.captured_at, 'last_verified_at': r.last_verified_at,
            'last_verified_from': r.last_verified_from, 'verify_count': r.verify_count,
            'reuse_count': r.reuse_count, 'last_reused_at': r.last_reused_at,
            'content_sha': r.content_sha, 'stale': fc.stale(r),
            'surface': fc.surface_label({'product': r.product, 'firmware': r.firmware,
                                         'build_no': r.build_no,
                                         'api_version': r.api_version})}


def _entry_or_404(entry_id: int):
    row = fc.get(entry_id)
    if row is None:
        abort(404)
    return row


@bp.route('/')
@login_required
@require_permission('registry.view')
def index():
    product = 'fortiweb'
    surfaces = fc.surfaces(product)
    pick = request.args.get('surface', '')
    current = next((s for s in surfaces
                    if '%s|%s|%s' % (s['firmware'], s['build_no'], s['api_version']) == pick),
                   surfaces[0] if surfaces else None)
    rows = []
    if current is not None:
        rows = [_row(r) for r in fc.entries(product, current['firmware'],
                                            current['build_no'], current['api_version'])]
        # the same name on the other surfaces, for the "compare" shortcut
        others: dict = {}
        for r in fc.entries(product):
            if (r.firmware, r.build_no, r.api_version) != (
                    current['firmware'], current['build_no'], current['api_version']):
                others.setdefault((r.kind, r.name), []).append(
                    {'id': r.id, 'surface': fc.surface_label(
                        {'product': r.product, 'firmware': r.firmware,
                         'build_no': r.build_no, 'api_version': r.api_version})})
        for row in rows:
            row['others'] = others.get((row['kind'], row['name']), [])
    return render_template('factory_catalog/index.html', surfaces=surfaces,
                           current=current, rows=rows,
                           reverify_days=fc.reverify_days(), enabled=fc.enabled())


@bp.route('/<int:entry_id>')
@login_required
@require_permission('registry.view')
def entry(entry_id: int):
    row = _entry_or_404(entry_id)
    tree = fc.tree_of(row)
    return render_template('factory_catalog/entry.html', e=_row(row),
                           tree_json=json.dumps(tree, indent=2, sort_keys=True,
                                                default=str),
                           variants=[_row(r) for r in fc.entries(
                               row.product, row.firmware, row.build_no,
                               row.api_version, row.name) if r.kind == row.kind],
                           elsewhere=[_row(r) for r in fc.entries(row.product, name=row.name)
                                      if r.kind == row.kind and r.id != row.id])


@bp.route('/compare')
@login_required
@require_permission('registry.view')
def compare():
    try:
        a_id, b_id = int(request.args.get('a', '')), int(request.args.get('b', ''))
    except ValueError:
        abort(400)
    a, b = _entry_or_404(a_id), _entry_or_404(b_id)
    d = fc.diff(fc.tree_of(a), fc.tree_of(b))
    shown = {k: d[k][:_DIFF_LIMIT] for k in ('added', 'removed', 'changed')}
    return render_template('factory_catalog/compare.html', a=_row(a), b=_row(b),
                           d=shown, total=d['total'], limit=_DIFF_LIMIT,
                           truncated=any(len(d[k]) > _DIFF_LIMIT
                                         for k in ('added', 'removed', 'changed')))


@bp.route('/<int:entry_id>/save-as-template', methods=['POST'])
@login_required
@require_permission('operations.template_save')
def save_as_template(entry_id: int):
    row = _entry_or_404(entry_id)
    name = (request.form.get('name') or '').strip() or row.name
    try:
        t = fc.save_as_template(row, name=name,
                                author=getattr(current_user, 'username', '') or '')
    except fc.CatalogMiss:
        flash(_('This entry does not hold every read the template needs. Save the '
                'profile as a template from an appliance running %(fw)s instead.',
                fw=row.firmware), 'warning')
        return redirect(url_for('factory_catalog.entry', entry_id=row.id))
    except ValueError as exc:
        flash(str(exc), 'danger')
        return redirect(url_for('factory_catalog.entry', entry_id=row.id))
    log_action('factory_catalog.save_template', target=row.name,
               detail='entry=%s firmware=%s build=%s api=%s template=%s v%s'
               % (row.id, row.firmware, row.build_no or '-', row.api_version or '-',
                  t.name, t.version))
    flash(_('Saved "%(name)s" v%(v)s for FortiWeb %(fw)s (pending approval).',
            name=t.name, v=t.version, fw=row.firmware), 'success')
    return redirect(url_for('templates.detail', template_id=t.id))
