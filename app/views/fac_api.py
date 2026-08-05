"""FortiAuthenticator API section — the FAC edition of the API hub.

Same two-panel shape as the FortiWeb/FortiADC/FortiAnalyzer consoles:

* left  — the registry catalog browsed as the FAC menu
  (:mod:`app.services.fac_menu` groups → items → bound endpoints), plus a
  synthetic "Other" group so a registry row the menu does not surface is still
  reachable. THIS is the page to fix when a firmware upgrade moves a resource.
* right — a live console: pick a FortiAuthenticator, an HTTP method, a logical
  endpoint (or a raw ``/api/v1/…`` path) and a JSON body.

The transport twist here is the opposite of FortiAnalyzer's: FAC is a plain
Django/Tastypie REST API, so the console picks a real **HTTP method** rather
than a JSON-RPC verb, and the URN is a path.

**Writes are DRY-RUN BY DEFAULT.** A mutating method returns the exact request
it would send and changes nothing until ``apply=true`` is passed; that also
requires the ``registry.execute_write`` permission and is audited. The reason
is specific to this product rather than ceremony: FAC's write surface is the
identity store — a stray ``DELETE /api/v1/localusers/`` removes accounts, and
its bulk ``POST /api/v1/localusers/`` answers 207 with a *partial* success list,
so "the call returned 2xx" is not the same as "what you asked for happened".
The console shows the device's body verbatim so the operator reads the real
per-item outcome, including the vendor's misspelled ``statue`` key.

All writes are audited. The registry is product-scoped
(``product='fortiauthenticator'``), so this never touches the other catalogs.
"""
from __future__ import annotations

import json
import re

from flask import (Blueprint, abort, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..clients.fortiauthenticator import FortiAuthenticatorClient
from ..extensions import db
from ..models import (Appliance, Permission, RegistryEndpoint,
                      visible_appliances, visible_appliance_or_404)
from ..registry import loader
from ..services import fac_menu
from ..services.audit import log_action

bp = Blueprint('fac_api', __name__, url_prefix='/fac/api')

_NAME_RE = re.compile(r'^[A-Za-z0-9_.\-]+$')
# Only paths under the API root are reachable from the console. Without this a
# raw-path field is a request forger pointed at the device's GUI/admin views,
# which live on the same origin and answer to the same session.
_PATH_RE = re.compile(r'^/api/v1/[A-Za-z0-9_./\-]*$')

_METHODS = ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')
_WRITE_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}


def _edit_context() -> dict:
    """Editor metadata (DB rows keyed by endpoint name + the disabled rows),
    only when the user may edit. Scoped to ``product='fortiauthenticator'`` so
    it never crosses the other catalogs."""
    if not (current_user.is_authenticated and current_user.can(Permission.REGISTRY_EDIT)):
        return {'can_edit': False, 'db_rows': {}, 'disabled_rows': []}
    rows = (RegistryEndpoint.query
            .filter_by(product='fortiauthenticator')
            .order_by(RegistryEndpoint.name).all())
    return {
        'can_edit': True,
        'db_rows': {r.name: r for r in rows if r.enabled},
        'disabled_rows': [r for r in rows if not r.enabled],
    }


@bp.route('/')
@login_required
def index():
    fleet = (visible_appliances().filter_by(kind='fortiauthenticator')
             .order_by(Appliance.name).all())
    reg = loader.load_fac_registry()
    groups = fac_menu.visible_menu()
    in_menu = set(fac_menu.bound_logicals())
    extras = sorted(name for name in reg if name not in in_menu)
    return render_template(
        'fac_api/index.html',
        fleet=fleet,
        groups=groups,
        reg=reg,
        extras=[{'name': n, 'urn': reg[n]} for n in extras],
        total=len(reg),
        methods=_METHODS,
        can_write=current_user.can('registry.execute_write'),
        **_edit_context(),
    )


def _resolve_target(endpoint: str):
    """(path, error) for a logical registry name OR a raw ``/api/v1/…`` path."""
    if endpoint.startswith('/'):
        if not _PATH_RE.match(endpoint):
            return None, ('Raw paths must live under /api/v1/ — the console '
                          'will not post to the appliance GUI.')
        return endpoint, None
    if not _NAME_RE.match(endpoint):
        return None, 'Invalid endpoint name.'
    try:
        return loader.resolve_fac(endpoint), None
    except KeyError as exc:
        return None, str(exc)


@bp.route('/execute', methods=['POST'])
@login_required
def execute():
    appliance_id = request.form.get('appliance_id', type=int)
    endpoint = (request.form.get('endpoint') or '').strip()
    method = (request.form.get('method') or 'GET').upper()
    body_raw = (request.form.get('body') or '').strip()
    apply_ = (request.form.get('apply') or '').lower() in ('1', 'true', 'on', 'yes')

    if not appliance_id or not endpoint:
        return jsonify(ok=False, error='Appliance and endpoint are required.')
    if method not in _METHODS:
        return jsonify(ok=False, error=f'Unknown HTTP method: {method}')
    if method in _WRITE_METHODS and not current_user.can('registry.execute_write'):
        return jsonify(ok=False, error='The "Execute write API calls" permission '
                                       'is required for non-GET methods.')

    appliance = visible_appliance_or_404(appliance_id)
    if appliance.kind != 'fortiauthenticator':
        return jsonify(ok=False, error='Selected device is not a FortiAuthenticator.')

    path, err = _resolve_target(endpoint)
    if err:
        return jsonify(ok=False, error=err)

    data = None
    if body_raw:
        try:
            data = json.loads(body_raw)
        except ValueError as exc:
            return jsonify(ok=False, error=f'Body is not valid JSON: {exc}')

    preview = {'method': method, 'url': f'https://{appliance.host}:{appliance.port}{path}',
               'body': data}

    # DRY RUN — the default for every mutating method. Nothing is sent.
    if method in _WRITE_METHODS and not apply_:
        return jsonify(ok=True, dry_run=True, request=preview,
                       note=('Dry run — nothing was sent. Re-submit with Apply '
                             'to perform this write on the device.'))

    client = FortiAuthenticatorClient(appliance, timeout=30.0)
    if method == 'GET':
        # Reads go through the paginating helper so the console can never show
        # a silently truncated first page as the whole collection.
        rows, call_err = client.list_path_with_error(path)
        payload = rows
    else:
        payload, call_err = client.api_call(method, path, data=data)

    if method in _WRITE_METHODS:
        log_action('fac_api.execute', f'{appliance.name}:{path}',
                   {'method': method, 'body': data, 'error': call_err})

    if call_err:
        return jsonify(ok=False, error=call_err, request=preview)
    return jsonify(ok=True, dry_run=False, request=preview, result=payload)


@bp.route('/endpoint/save', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def save_endpoint():
    """Create or re-point one registry row. The knob to turn when a firmware
    upgrade moves a resource — no code change, no deploy."""
    name = (request.form.get('name') or '').strip()
    urn = (request.form.get('urn') or '').strip()
    if not _NAME_RE.match(name):
        flash('Invalid endpoint name.', 'danger')
        return redirect(url_for('fac_api.index'))
    if not _PATH_RE.match(urn):
        flash('URN must be a path under /api/v1/.', 'danger')
        return redirect(url_for('fac_api.index'))

    row = RegistryEndpoint.query.filter_by(
        product='fortiauthenticator', name=name).first()
    before = row.urn if row else None
    if row is None:
        row = RegistryEndpoint(product='fortiauthenticator', api_version='v1',
                               name=name, urn=urn)
        db.session.add(row)
    else:
        row.urn = urn
        row.enabled = True
    row.updated_by = current_user.username
    db.session.commit()
    loader.invalidate_fac_cache()
    log_action('fac_api.registry_save', name, {'from': before, 'to': urn})
    flash(f'Endpoint {name} saved.', 'success')
    return redirect(url_for('fac_api.index'))


@bp.route('/endpoint/toggle/<int:id>', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def toggle_endpoint(id):
    row = RegistryEndpoint.query.get_or_404(id)
    if row.product != 'fortiauthenticator':
        abort(404)
    row.enabled = not row.enabled
    row.updated_by = current_user.username
    db.session.commit()
    loader.invalidate_fac_cache()
    log_action('fac_api.registry_toggle', row.name, {'enabled': row.enabled})
    flash(f'Endpoint {row.name} {"enabled" if row.enabled else "disabled"}.', 'success')
    return redirect(url_for('fac_api.index'))
