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
from ..services import registry_write
from ..services.audit import log_action
from . import _apiversions, _reconcile

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

    before = None
    if rid:
        existing = db.session.get(RegistryEndpoint, rid)
        if existing is None or existing.product != 'fortiweb':
            # An edit may only touch a row of THIS product. Before the shared
            # writer, this page would happily rewrite a FortiADC row by id.
            abort(404)
        before = {'name': existing.name, 'urn': existing.urn,
                  'api_version': existing.api_version}

    ok, msg, _row = registry_write.save_endpoint(
        product='fortiweb', name=name, urn=urn, api_version=api_version,
        row_id=rid, actor=current_user.username)
    if not ok:
        flash(msg, 'danger')
        return _redirect_back()

    log_action('registry.endpoint_update' if rid else 'registry.endpoint_create',
               target=name, extra={'urn': urn, 'api_version': api_version,
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


# ---------------------------------------------------------------------------
# reconcile — the sweep's verdicts read back against the catalog
# ---------------------------------------------------------------------------
# The rediscovery sweep is the only thing in SATOM that asks a live appliance
# about every endpoint in the catalog. Its verdicts used to die in a JSON file;
# these two routes are the return path. The body is shared with the FortiADC
# hub (``views/_reconcile.py``) because the catalog is keyed (product,
# api_version) and each product's API hub is its own ADOM-scoped page.
#
# Both routes require REGISTRY_EDIT: the page exists to drive registry.toggle,
# and its apply POST performs exactly that write.

@bp.route('/reconcile')
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def reconcile():
    return _reconcile.render_page('fortiweb', 'registry.reconcile_apply',
                                  'api_explorer.index')


@bp.route('/reconcile/apply', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def reconcile_apply():
    return _reconcile.apply_page('fortiweb', 'registry.reconcile')


# ---------------------------------------------------------------------------
# API versions (firmware-line matrix) — shared body in views/_apiversions.py
# ---------------------------------------------------------------------------
# The registry's api_version axis says FortiWeb 7.6 and 8.0 are the same
# surface (both v2.0). Measured on this fleet's own artifacts they are not:
# 8.0 carries more FIELDS. This page is that difference, and the rebuild POST
# writes only the derived matrix file.

@bp.route('/versions')
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def api_versions():
    return _apiversions.render_page('fortiweb', 'api_explorer.index',
                                    'registry.api_versions_rebuild',
                                    'registry.api_versions',
                                    'registry.api_versions_declare',
                                    'registry.api_versions_forget',
                                    'registry.api_versions_export',
                                    'registry.api_versions_export_pdf',
                                    'registry.api_versions_review')


# GET, and read-only: it renders the same comparison the page does, so it is
# gated exactly like the page and not one notch looser.
@bp.route('/versions/export.csv')
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def api_versions_export():
    return _apiversions.export_page('fortiweb', 'registry.api_versions')


# Same gate, same resolved comparison, different container. The two exports
# share their row builder and their column legend; only the file format differs.
@bp.route('/versions/export.pdf')
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def api_versions_export_pdf():
    return _apiversions.export_pdf_page('fortiweb', 'registry.api_versions')


@bp.route('/versions/rebuild', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def api_versions_rebuild():
    return _apiversions.rebuild_page('fortiweb', 'registry.api_versions')


@bp.route('/versions/declare', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def api_versions_declare():
    """Register a firmware version by hand.

    The other half of registration — "a version exists because its image was
    uploaded" — is DERIVED from the FirmwareImage table on every read, never
    written here. Two code paths create those rows; hooking both would be one
    refactor away from a version that silently never appears on the page.
    """
    return _apiversions.declare_page('fortiweb', 'registry.api_versions')


@bp.route('/versions/review', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def api_versions_review():
    """Accept or refuse one recorded disappearance.

    Gated on the same permission as declare/forget and for the same reason: it
    writes one row of operator judgement about the catalogue. It writes NO
    catalogue entry -- see ``absence_record.BLOCKED_REASON``.
    """
    return _apiversions.review_page('fortiweb', 'registry.api_versions')


@bp.route('/versions/forget', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def api_versions_forget():
    """Drop a hand-authored declaration. A version that is also derived (an
    image is in the vault, or a box runs it) stays on the page afterwards —
    forgetting a note cannot unmake a fact."""
    return _apiversions.forget_page('fortiweb', 'registry.api_versions')
