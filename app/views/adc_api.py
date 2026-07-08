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
from ..services import adc_menu
from ..services.audit import log_action

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
    )


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

    if not name or not urn:
        flash('Name and URN are both required.', 'danger')
        return _back()
    if not _NAME_RE.match(name):
        flash('Endpoint name may only contain letters, digits, "_", "-" and ".".', 'danger')
        return _back()
    if not urn.startswith('/'):
        flash('URN must be an absolute API path (e.g. /api/load_balance_pool).', 'danger')
        return _back()

    row = None
    if rid:
        row = db.session.get(RegistryEndpoint, rid)
        if row is None or row.product != 'fortiadc':
            abort(404)

    dup = RegistryEndpoint.query.filter_by(
        product='fortiadc', api_version=api_version, name=name).first()
    if dup is not None and (row is None or dup.id != row.id):
        flash(f'An endpoint named "{name}" already exists ({dup.urn}).', 'danger')
        return _back()

    if row is None:
        row = RegistryEndpoint(product='fortiadc', api_version=api_version)
        db.session.add(row)
        action, before = 'registry.adc_endpoint_create', None
    else:
        action = 'registry.adc_endpoint_update'
        before = {'name': row.name, 'urn': row.urn, 'api_version': row.api_version}

    row.name, row.urn, row.api_version = name, urn, api_version
    row.updated_by = current_user.username
    db.session.commit()
    loader.invalidate_adc_cache()
    adc_menu.invalidate()
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
