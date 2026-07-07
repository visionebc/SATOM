"""FortiWeb endpoint registry — catalog editor + reads.

Reads come from :mod:`app.registry.loader` (DB-first, ``endpoints.yaml`` as
seed/fallback). Writes are gated on ``Permission.REGISTRY_EDIT``, audited, and
soft-delete only (``enabled=False``) so the boot seeder never resurrects a
name the operator removed.

The standalone Registry *page* was FUSED into the API-Registry Explorer
(2026-07-05): the catalog is now browsed + edited on the Explorer's API-Menu
tree. ``index`` / ``section_detail`` therefore redirect there; the write path
(``save`` / ``toggle``) and ``_edit_context`` live on here and are reused by the
Explorer view. Old ``/registry`` bookmarks keep working via the redirect.
"""
import re

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..extensions import db
from ..models import Permission, RegistryEndpoint
from ..registry import loader
from ..services.audit import log_action

bp = Blueprint('registry', __name__, url_prefix='/registry')

_NAME_RE = re.compile(r'^[A-Za-z0-9_.\-]+$')


def _edit_context() -> dict:
    """Editor context: DB row metadata keyed by endpoint name (ids for the edit
    buttons) plus the disabled rows, only when the user may edit — read-only
    users get none of it. Reused by the API-Registry Explorer so its API-Menu
    tree is editable in place."""
    if not (current_user.is_authenticated and current_user.can(Permission.REGISTRY_EDIT)):
        return {'can_edit': False, 'db_rows': {}, 'disabled_rows': []}
    rows = RegistryEndpoint.query.filter_by(product='fortiweb').order_by(RegistryEndpoint.name).all()
    return {
        'can_edit': True,
        'db_rows': {r.name: r for r in rows if r.enabled},
        'disabled_rows': [r for r in rows if not r.enabled],
    }


@bp.route('/')
@login_required
def index():
    # Fused into the API-Registry Explorer — send bookmarks there.
    return redirect(url_for('api_explorer.index'))


@bp.route('/<path:section>')
@login_required
def section_detail(section):
    # The by-section table view is gone (the Explorer's tree replaces it);
    # keep the route so old links resolve, redirect to the fused page.
    return redirect(url_for('api_explorer.index'))


@bp.route('/search')
@login_required
def search():
    term = request.args.get('q', '').strip().lower()
    results = []
    if term:
        for e in loader.get_all_endpoints():
            if term in e['name'].lower() or term in (e['urn'] or '').lower():
                results.append({'section': e['section'], 'endpoint': e})
    return render_template(
        'registry/search.html',
        term=term,
        results=results,
        sections=loader.get_all_sections(),
    )


# ---------------------------------------------------------------------------
# editor (REGISTRY_EDIT) — reused by the API-Registry Explorer
# ---------------------------------------------------------------------------

def _redirect_back():
    nxt = request.form.get('next') or ''
    # only ever bounce back inside the API hub (the fused Explorer or the
    # legacy registry path, which itself redirects to the Explorer)
    if nxt.startswith('/api-explorer') or nxt.startswith('/registry'):
        return redirect(nxt)
    return redirect(url_for('api_explorer.index'))


@bp.route('/save', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def save():
    """Create (no id) or update (id) one endpoint row."""
    rid = request.form.get('id', type=int)
    name = (request.form.get('name') or '').strip()
    urn = (request.form.get('urn') or '').strip()
    api_version = (request.form.get('api_version') or 'v2.0').strip() or 'v2.0'

    if not name or not urn:
        flash('Name and URN are both required.', 'danger')
        return _redirect_back()
    if not _NAME_RE.match(name):
        flash('Endpoint name may only contain letters, digits, "_", "-" and ".".', 'danger')
        return _redirect_back()
    if not urn.startswith('/'):
        flash('URN must be an absolute API path (e.g. /api/v2.0/cmdb/...).', 'danger')
        return _redirect_back()

    row = None
    if rid:
        row = db.session.get(RegistryEndpoint, rid)
        if row is None:
            abort(404)

    dup = RegistryEndpoint.query.filter_by(
        product='fortiweb', api_version=api_version, name=name).first()
    if dup is not None and (row is None or dup.id != row.id):
        flash(f'An endpoint named "{name}" already exists ({dup.urn}).', 'danger')
        return _redirect_back()

    if row is None:
        row = RegistryEndpoint(product='fortiweb', api_version=api_version)
        db.session.add(row)
        action = 'registry.endpoint_create'
        before = None
    else:
        action = 'registry.endpoint_update'
        before = {'name': row.name, 'urn': row.urn, 'api_version': row.api_version}

    row.name, row.urn, row.api_version = name, urn, api_version
    row.updated_by = current_user.username
    db.session.commit()
    loader.invalidate_cache()
    log_action(action, target=name, extra={'urn': urn, 'api_version': api_version,
                                           'before': before})
    flash(f'Endpoint "{name}" saved.', 'success')
    return _redirect_back()


@bp.route('/toggle/<int:rid>', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def toggle(rid):
    """Soft-delete / restore one endpoint row (the row stays so the YAML boot
    seeder cannot resurrect a name the operator removed)."""
    row = db.session.get(RegistryEndpoint, rid)
    if row is None:
        abort(404)
    row.enabled = not row.enabled
    row.updated_by = current_user.username
    db.session.commit()
    loader.invalidate_cache()
    state = 'enabled' if row.enabled else 'disabled'
    log_action('registry.endpoint_toggle', target=row.name,
               extra={'urn': row.urn, 'state': state})
    flash(f'Endpoint "{row.name}" {state}.', 'success')
    return _redirect_back()
