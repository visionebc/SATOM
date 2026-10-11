"""FortiGate API section — the FortiGate edition of the API hub.

Same two-panel shape as the FortiWeb/FortiADC/FortiAnalyzer/FortiAuthenticator
consoles:

* left  — the registry catalog browsed as the FortiGate menu
  (:mod:`app.services.fgt_menu` groups → items → one registry name per tab),
  plus "Other" for every table the baseline holds and no menu page shows. The
  catalog is the baseline promoted from what fgt02 (FortiOS 8.0.1) answered to
  ``?action=schema``; names are the cmdb path flattened by
  ``registry.loader.fgt_logical`` (``firewall/policy`` → ``firewall_policy``).
* right — a live console: pick a FortiGate, an HTTP method, a registry name (or
  a raw ``/api/v2/…`` path), an optional object key and a JSON body.

**Writes are DRY-RUN BY DEFAULT**, exactly as on the FortiAuthenticator
console: a mutating method returns the request it would send and changes
nothing until ``apply=true`` is passed, which also needs the
``registry.execute_write`` permission and is audited. What is FortiOS-specific:

* writes go to ``/api/v2/cmdb/`` only (``FortiGateClient.write`` refuses
  anything else). The monitor tree holds device ACTIONS — reboot, restore,
  firmware upgrade — and a console that could POST there is a reboot button;
* ``DELETE`` needs an object key. A table-wide ``DELETE`` is refused here, not
  sent: one click must not empty ``firewall/address``;
* there is no ``PATCH``: FortiOS answers ``PUT`` for an update, and a ``PUT``
  REPLACES a member list (``srcaddr``, ``member``) instead of merging into it.

Every answer is scrubbed by the same rule as the FortiGate section pages
(``views.fgt.scrub``): FortiOS serves secrets as ``ENC …`` — or in clear to a
super_admin token — and a credential in a page is a credential in every browser
cache and screenshot. The audit line scrubs the request body the same way.

The registry is product-scoped (``product='fortigate'``), so this never touches
the other catalogs.
"""
from __future__ import annotations

import json
import re
from urllib.parse import quote

from flask import (Blueprint, abort, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..clients.fortigate import FortiGateClient
from ..extensions import db
from ..models import (Appliance, Permission, RegistryEndpoint,
                      visible_appliances, visible_appliance_or_404)
from ..registry import loader
from ..services import fgt_menu, registry_write
from ..services.audit import log_action
from . import _clicoverage
from .fgt import scrub

bp = Blueprint('fgt_api', __name__, url_prefix='/fgt/api')

_NAME_RE = re.compile(r'^[A-Za-z0-9_.\-]+$')
# Reads may look at the three REST trees; nothing else on the origin (the GUI,
# /logincheck, /api/v2/… siblings) is reachable from the console.
_PATH_RE = re.compile(r'^/api/v2/(?:cmdb|monitor|log)/[A-Za-z0-9_./\-]*$')
_CMDB_PREFIX = '/api/v2/cmdb/'

_METHODS = ('GET', 'POST', 'PUT', 'DELETE')
_WRITE_METHODS = {'POST', 'PUT', 'DELETE'}


def _edit_context() -> dict:
    """Editor metadata, only when the user may edit; ``product='fortigate'``."""
    if not (current_user.is_authenticated and current_user.can(Permission.REGISTRY_EDIT)):
        return {'can_edit': False, 'db_rows': {}, 'disabled_rows': []}
    rows = (RegistryEndpoint.query
            .filter_by(product='fortigate')
            .order_by(RegistryEndpoint.name).all())
    return {
        'can_edit': True,
        'db_rows': {r.name: r for r in rows if r.enabled},
        'disabled_rows': [r for r in rows if not r.enabled],
    }


def _menu_groups():
    """``[(group, [(item, ((name, tab label), ...)), ...]), ...]``."""
    return [(g, [(it, fgt_menu.item_logicals(it)) for it in g.items])
            for g in fgt_menu.visible_menu()]


@bp.route('/')
@login_required
@require_permission('registry.view')
def index():
    fleet = (visible_appliances().filter_by(kind='fortigate')
             .order_by(Appliance.name).all())
    reg = loader.load_fgt_registry()
    in_menu = set(fgt_menu.bound_logicals())
    extras = sorted(name for name in reg if name not in in_menu)
    return render_template(
        'fgt_api/index.html',
        fleet=fleet,
        groups=_menu_groups(),
        reg=reg,
        extras=[{'name': n, 'urn': reg[n]} for n in extras],
        total=len(reg),
        methods=_METHODS,
        can_write=current_user.can('registry.execute_write'),
        **_edit_context(),
        **_clicoverage.context('fortigate', page_endpoint='fgt_api.index'),
    )


def _resolve_target(endpoint: str, version: str = ''):
    """(path, error) for a registry name OR a raw ``/api/v2/…`` path.

    A name resolves for the box's build (``loader.resolve_for``); a name the
    build does not serve comes back as the ``EndpointNotServed`` message.
    """
    if endpoint.startswith('/'):
        if '..' in endpoint or not _PATH_RE.match(endpoint):
            return None, ('Raw paths must live under /api/v2/cmdb/, /api/v2/monitor/ '
                          'or /api/v2/log/ — the console will not reach the '
                          'FortiGate GUI.')
        return endpoint, None
    if not _NAME_RE.match(endpoint):
        return None, 'Invalid endpoint name.'
    try:
        return loader.resolve_for('fortigate', endpoint, version), None
    except KeyError as exc:
        return None, str(exc)


def _with_key(path: str, mkey: str) -> str:
    """``path`` + the URL-encoded object key. ``/`` in a key is encoded too:
    an address named ``192.0.2.0/24`` is ONE path segment to FortiOS."""
    if not mkey:
        return path
    return path.rstrip('/') + '/' + quote(mkey, safe='')


def _names_an_object(path: str) -> bool:
    """True when a cmdb path goes past ``<a.b>/<c>`` to one object."""
    rest = path[len(_CMDB_PREFIX):].strip('/')
    return rest.count('/') >= 2


@bp.route('/execute', methods=['POST'])
@login_required
@require_permission('registry.view')
def execute():
    appliance_id = request.form.get('appliance_id', type=int)
    endpoint = (request.form.get('endpoint') or '').strip()
    mkey = (request.form.get('mkey') or '').strip()
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
    if appliance.kind != 'fortigate':
        return jsonify(ok=False, error='Selected device is not a FortiGate.')

    path, err = _resolve_target(endpoint, appliance.fw_version)
    if err:
        return jsonify(ok=False, error=err)
    path = _with_key(path, mkey)

    if method in _WRITE_METHODS:
        if not path.startswith(_CMDB_PREFIX):
            return jsonify(ok=False, error=(
                'Writes go to /api/v2/cmdb/ only. The monitor tree holds device '
                'actions (reboot, restore, firmware upgrade), not configuration.'))
        if method == 'DELETE' and not _names_an_object(path):
            return jsonify(ok=False, error=(
                'DELETE needs an object key: a DELETE on the whole table is '
                'refused, not sent.'))

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

    client = FortiGateClient(appliance, timeout=30.0)
    if method == 'GET':
        payload, call_err = client.api_call('GET', path)
    else:
        payload, call_err = client.write(method, path, data=data)

    if method in _WRITE_METHODS:
        log_action('fgt_api.execute', f'{appliance.name}:{path}',
                   {'method': method, 'body': scrub(data), 'error': call_err})

    if call_err:
        return jsonify(ok=False, error=call_err, request=preview)
    return jsonify(ok=True, dry_run=False, request=preview, result=scrub(payload))


@bp.route('/endpoint/save', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def save_endpoint():
    """Create or re-point one registry row — the knob to turn when a firmware
    upgrade moves a table. No code change, no deploy."""
    name = (request.form.get('name') or '').strip()
    urn = (request.form.get('urn') or '').strip()

    row = RegistryEndpoint.query.filter_by(
        product='fortigate', name=name).first() if name else None
    before = row.urn if row else None
    # The ONE catalog writer. It never touches ``enabled``: re-pointing a
    # disabled endpoint leaves it disabled until someone restores it on purpose.
    ok, msg, row = registry_write.save_endpoint(
        product='fortigate', name=name, urn=urn,
        api_version=row.api_version if row else '',
        row_id=row.id if row else None, actor=current_user.username)
    if not ok:
        flash(msg, 'danger')
        return redirect(url_for('fgt_api.index'))
    log_action('fgt_api.registry_save', name,
               {'from': before, 'to': urn, 'enabled': row.enabled})
    if row.enabled:
        flash(f'Endpoint {name} saved.', 'success')
    else:
        flash(f'Endpoint {name} saved; it is still disabled — restore it to use it.',
              'warning')
    return redirect(url_for('fgt_api.index'))


@bp.route('/endpoint/toggle/<int:id>', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def toggle_endpoint(id):
    row = RegistryEndpoint.query.get_or_404(id)
    if row.product != 'fortigate':
        abort(404)
    row.enabled = not row.enabled
    row.updated_by = current_user.username
    db.session.commit()
    loader.invalidate_fgt_cache()
    log_action('fgt_api.registry_toggle', row.name, {'enabled': row.enabled})
    flash(f'Endpoint {row.name} {"enabled" if row.enabled else "disabled"}.', 'success')
    return redirect(url_for('fgt_api.index'))
