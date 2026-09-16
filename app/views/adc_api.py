"""FortiADC API section — the ADC mirror of the FortiWeb API hub.

FortiWeb's API area fuses the endpoint Registry + a live API Explorer console
(``app/views/api_explorer.py`` + ``registry.py``). This is the same thing scoped
to the **fortiadc** product:

* left — the registry catalog browsed as the FortiADC GUI menu
  (:mod:`app.services.adc_menu` groups → items → object-type endpoints), with
  New / Edit / Disable affordances when the user has ``REGISTRY_EDIT``; the
  soft-deleted rows are listed so a disabled endpoint can be restored (the boot
  seeder is INSERT-ONLY so it never resurrects a name the operator removed).
* right — a live console: pick a FortiADC, a method, a logical endpoint (or a
  raw ``/api/...`` path) and a JSON body, execute through
  :class:`app.clients.fortiadc.FortiADCClient` (``registry.execute_write`` gates
  the non-GET verbs).

All writes are audited. The registry is 2D from day one
(``product='fortiadc'``), so this never touches the FortiWeb catalog.
"""
from __future__ import annotations

import json
import re

from flask import (Blueprint, abort, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..clients.fortiadc import FortiADCClient
from ..extensions import db
from ..models import Appliance, Permission, RegistryEndpoint
from ..models import visible_appliances, visible_appliance_or_404
from ..registry import loader
from ..services import adc_menu, registry_write
from ..services.audit import log_action
from . import _clicoverage, _discovery
from . import _apiversions, _reconcile

bp = Blueprint('adc_api', __name__, url_prefix='/adc/api')

_NAME_RE = re.compile(r'^[A-Za-z0-9_.\-]+$')
_WRITE_METHODS = {'POST', 'PUT', 'DELETE', 'PATCH'}


def _edit_context() -> dict:
    """Editor metadata (DB rows keyed by endpoint name + the disabled rows),
    only when the user may edit — read-only users get none of it. Scoped to
    ``product='fortiadc'`` so it never crosses into the FortiWeb catalog."""
    if not (current_user.is_authenticated and current_user.can(Permission.REGISTRY_EDIT)):
        return {'can_edit': False, 'db_rows': {}, 'disabled_rows': []}
    rows = (RegistryEndpoint.query
            .filter_by(product='fortiadc')
            .order_by(RegistryEndpoint.name).all())
    return {
        'can_edit': True,
        'db_rows': {r.name: r for r in rows if r.enabled},
        'disabled_rows': [r for r in rows if not r.enabled],
    }


@bp.route('/')
@login_required
def index():
    fleet = (visible_appliances().filter_by(kind='fortiadc')
             .order_by(Appliance.name).all())
    reg = loader.load_adc_registry()
    # Browse tree = the FortiADC GUI menu (already groups every logical); add a
    # synthetic "Other" group for registry endpoints the menu doesn't surface
    # (child tables, integrations) so the whole catalog is reachable.
    groups = adc_menu.menu()
    in_menu = {t.logical for g in groups for i in g.items for t in i.tabs}
    extras = sorted(name for name in reg if name not in in_menu)
    total = len(reg)
    return render_template(
        'adc_api/index.html',
        fleet=fleet,
        groups=groups,
        extras=[{'name': n, 'urn': reg[n]} for n in extras],
        total=total,
        can_write=current_user.can('registry.execute_write'),
        **_edit_context(),
        **_clicoverage.context(
            'fortiadc',
            block_endpoint='adc_api.cli_coverage_block',
            capture_endpoint='adc_api.cli_coverage_capture',
            live_endpoint='adc_api.cli_coverage_live',
            page_endpoint='adc_api.index',
            probe_endpoint='adc_api.cli_coverage_probe',
            registry_save_endpoint='adc_api.registry_save'),
        **_discovery.context(
            'fortiadc',
            load_endpoint='adc_api.discovery_load'),
    )


# ---------------------------------------------------------------------------
# Discovery run (shared body in views/_discovery.py)
# ---------------------------------------------------------------------------

@bp.route('/discovery/plan', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def discovery_plan():
    return _discovery.plan_payload('fortiadc')


@bp.route('/discovery/run', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def discovery_run():
    return _discovery.run_payload('fortiadc')


@bp.route('/discovery/register', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def discovery_register():
    return _discovery.register_payload('fortiadc')


@bp.route('/discovery/load', methods=['POST'])
@login_required
@require_permission('appliances.apply')
def discovery_load():
    # Back to the page that mounts the card (see api_explorer.discovery_load).
    return _discovery.load('fortiadc', 'adc_api.api_versions')


@bp.route('/execute', methods=['POST'])
@login_required
def execute():
    appliance_id = request.form.get('appliance_id', type=int)
    endpoint = (request.form.get('endpoint') or '').strip()
    method = (request.form.get('method') or 'GET').upper()
    body_raw = (request.form.get('body') or '').strip()

    if not appliance_id or not endpoint:
        return jsonify(ok=False, error='Appliance and endpoint are required.')
    if method in _WRITE_METHODS and not current_user.can('registry.execute_write'):
        return jsonify(ok=False, error='The "Execute write API calls" permission '
                                       'is required for non-GET methods.')

    appliance = visible_appliance_or_404(appliance_id)
    if appliance.kind != 'fortiadc':
        return jsonify(ok=False, error='Selected device is not a FortiADC.')

    # Accept either a logical registry name or a raw /api/... path.
    path = endpoint
    if not endpoint.startswith('/'):
        try:
            path = loader.resolve_adc(endpoint)
        except KeyError:
            return jsonify(ok=False, error=f'Unknown FortiADC endpoint: {endpoint}')

    mkey = (request.form.get('mkey') or '').strip()
    if mkey:
        from urllib.parse import quote
        path += ('&' if '?' in path else '?') + 'mkey=' + quote(mkey)

    body = None
    if body_raw:
        try:
            body = json.loads(body_raw)
        except ValueError as exc:
            return jsonify(ok=False, error=f'Invalid JSON body: {exc}')

    try:
        resp = FortiADCClient(appliance).api_call(method, path, body)
        log_action('adc_api.execute', target=appliance.name,
                   extra={'method': method, 'endpoint': path})
        try:
            result = resp.json()
        except Exception:  # noqa: BLE001
            result = resp.text
        return jsonify(ok=True, status=resp.status_code, path=path, result=result)
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc))


# --------------------------------------------------------------------------- #
#  Registry catalog editor (REGISTRY_EDIT) — product='fortiadc'                 #
# --------------------------------------------------------------------------- #

def _back():
    return redirect(url_for('adc_api.index'))


@bp.route('/registry/save', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def registry_save():
    rid = request.form.get('id', type=int)
    name = (request.form.get('name') or '').strip()
    urn = (request.form.get('urn') or '').strip()
    api_version = (request.form.get('api_version') or 'v1').strip() or 'v1'

    before, action = None, 'registry.adc_endpoint_create'
    if rid:
        existing = db.session.get(RegistryEndpoint, rid)
        if existing is None or existing.product != 'fortiadc':
            abort(404)
        action = 'registry.adc_endpoint_update'
        before = {'name': existing.name, 'urn': existing.urn,
                  'api_version': existing.api_version}

    ok, msg, _row = registry_write.save_endpoint(
        product='fortiadc', name=name, urn=urn, api_version=api_version,
        row_id=rid, actor=current_user.username)
    if not ok:
        flash(msg, 'danger')
        return _back()

    log_action(action, target=name, extra={'urn': urn, 'api_version': api_version,
                                           'before': before})
    flash(f'FortiADC endpoint "{name}" saved.', 'success')
    return _back()


@bp.route('/registry/toggle/<int:rid>', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def registry_toggle(rid):
    row = db.session.get(RegistryEndpoint, rid)
    if row is None or row.product != 'fortiadc':
        abort(404)
    row.enabled = not row.enabled
    row.updated_by = current_user.username
    db.session.commit()
    loader.invalidate_adc_cache()
    adc_menu.invalidate()
    state = 'enabled' if row.enabled else 'disabled'
    log_action('registry.adc_endpoint_toggle', target=row.name,
               extra={'urn': row.urn, 'state': state})
    flash(f'FortiADC endpoint "{row.name}" {state}.', 'success')
    return _back()


# ---------------------------------------------------------------------------
# reconcile — the FortiADC half of the sweep-to-catalog return path
# ---------------------------------------------------------------------------
# Same page, same service, ``product='fortiadc'``. The ADC's "absent" signal is
# an HTTP 404 rather than an errcode envelope (see adc_ops.make_probe), which
# the sweep normalises into the same three verdicts before they get here.

@bp.route('/reconcile')
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def reconcile():
    return _reconcile.render_page('fortiadc', 'adc_api.reconcile_apply',
                                  'adc_api.index')


@bp.route('/reconcile/apply', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def reconcile_apply():
    return _reconcile.apply_page('fortiadc', 'adc_api.reconcile')


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
    return _apiversions.render_page('fortiadc', 'adc_api.index',
                                    'adc_api.api_versions_rebuild',
                                    'adc_api.api_versions',
                                    'adc_api.api_versions_declare',
                                    'adc_api.api_versions_forget',
                                    'adc_api.api_versions_export',
                                    'adc_api.api_versions_export_pdf')


@bp.route('/versions/export.csv')
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def api_versions_export():
    return _apiversions.export_page('fortiadc', 'adc_api.api_versions')


@bp.route('/versions/export.pdf')
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def api_versions_export_pdf():
    return _apiversions.export_pdf_page('fortiadc', 'adc_api.api_versions')


@bp.route('/versions/rebuild', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def api_versions_rebuild():
    return _apiversions.rebuild_page('fortiadc', 'adc_api.api_versions')


# ---------------------------------------------------------------------------
# CLI ↔ API coverage (shared body — see views/_clicoverage.py)
# ---------------------------------------------------------------------------
# The counts and the CLI paths render with the page; these three carry
# Permission.BACKUP because every one of them hands over device CONFIGURATION,
# and the config vault they read from is gated on exactly that permission.

@bp.route('/cli-coverage/block')
@login_required
@require_permission(Permission.BACKUP)
def cli_coverage_block():
    return _clicoverage.block_payload('fortiadc')


@bp.route('/cli-coverage/live', methods=['POST'])
@login_required
@require_permission(Permission.BACKUP)
def cli_coverage_live():
    return _clicoverage.live_payload('fortiadc')


@bp.route('/cli-coverage/capture', methods=['POST'])
@login_required
@require_permission(Permission.BACKUP)
def cli_coverage_capture():
    return _clicoverage.capture('fortiadc', 'adc_api.index')


@bp.route('/cli-coverage/probe', methods=['POST'])
@login_required
def cli_coverage_probe():
    """Ask the device which candidate REST path exists for a CLI-only block.

    Deliberately NOT gated on Permission.BACKUP — see probe_payload: it returns
    a verdict and a row count, and the console on this same page already lets
    this user GET any path directly.
    """
    return _clicoverage.probe_payload('fortiadc')


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
    return _apiversions.declare_page('fortiadc', 'adc_api.api_versions')


@bp.route('/versions/forget', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def api_versions_forget():
    """Drop a hand-authored declaration. A version that is also derived (an
    image is in the vault, or a box runs it) stays on the page afterwards —
    forgetting a note cannot unmake a fact."""
    return _apiversions.forget_page('fortiadc', 'adc_api.api_versions')
