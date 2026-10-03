"""FortiAnalyzer API section — the FAZ mirror of the FortiWeb/FortiADC API hub.

FortiWeb's API area fuses the endpoint Registry + a live API Explorer console;
``adc_api`` is the same thing scoped to FortiADC. This is the **fortianalyzer**
edition, with one transport twist: FortiAnalyzer speaks JSON-RPC over a single
``POST /jsonrpc`` endpoint, so the console picks a JSON-RPC *verb*
(``get``/``exec``/``add``/``set``/``update``/``delete``) instead of an HTTP
method, and the URN is the JSON-RPC ``url`` (the client auto-selects the
legacy vs apiver-3 envelope from the URL family — see
:class:`app.clients.fortianalyzer.FortiAnalyzerClient`).

* left — the registry catalog browsed as the FAZ menu
  (:mod:`app.services.faz_menu` groups → items → bound endpoints), with
  New / Edit / Disable affordances when the user has ``REGISTRY_EDIT``; the
  soft-deleted rows are listed so a disabled endpoint can be restored (the
  boot seeder is INSERT-ONLY so it never resurrects a name the operator
  removed). THIS is the page to fix when a FAZ upgrade moves an URI.
* right — a live console: pick a FortiAnalyzer, a verb, a logical endpoint
  (or a raw ``/…`` JSON-RPC url) and a JSON ``data`` body.

**Console writes are DRY-RUN BY DEFAULT**, exactly like the FortiAuthenticator
console: a mutating verb returns the request it would send and changes nothing
until ``apply=true`` is passed. Every applied write is audited, including the
ones the device refused; reads are not audited. The registry is 2D
(``product='fortianalyzer'``), so this never touches the FortiWeb/FortiADC
catalogs.
"""
from __future__ import annotations

import json

from flask import (Blueprint, abort, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..clients.fortianalyzer import FortiAnalyzerClient
from ..extensions import db
from ..models import Appliance, Permission, RegistryEndpoint
from ..models import visible_appliances, visible_appliance_or_404
from ..registry import loader
from ..services import faz_menu, registry_write
from ..services.audit import log_action
from . import _clicoverage

bp = Blueprint('faz_api', __name__, url_prefix='/faz/api')

# JSON-RPC verbs (lowercase on the wire); everything but 'get' mutates.
_VERBS = ('get', 'exec', 'add', 'set', 'update', 'delete')
_WRITE_VERBS = {'exec', 'add', 'set', 'update', 'delete'}


def _edit_context() -> dict:
    """Editor metadata (DB rows keyed by endpoint name + the disabled rows),
    only when the user may edit — read-only users get none of it. Scoped to
    ``product='fortianalyzer'`` so it never crosses the other catalogs."""
    if not (current_user.is_authenticated and current_user.can(Permission.REGISTRY_EDIT)):
        return {'can_edit': False, 'db_rows': {}, 'disabled_rows': []}
    rows = (RegistryEndpoint.query
            .filter_by(product='fortianalyzer')
            .order_by(RegistryEndpoint.name).all())
    return {
        'can_edit': True,
        'db_rows': {r.name: r for r in rows if r.enabled},
        'disabled_rows': [r for r in rows if not r.enabled],
    }


@bp.route('/')
@login_required
@require_permission('registry.view')
def index():
    fleet = (visible_appliances().filter_by(kind='fortianalyzer')
             .order_by(Appliance.name).all())
    reg = loader.load_faz_registry()
    # Browse tree = the FAZ menu (already groups the bound logicals); add a
    # synthetic "Other" group for registry endpoints the menu doesn't surface
    # so the whole catalog is reachable.
    groups = faz_menu.menu()
    in_menu = {lg for g in groups for i in g.items for lg, _lb in i.logicals}
    extras = sorted(name for name in reg if name not in in_menu)
    total = len(reg)
    return render_template(
        'faz_api/index.html',
        fleet=fleet,
        groups=groups,
        reg=reg,
        extras=[{'name': n, 'urn': reg[n]} for n in extras],
        total=total,
        verbs=_VERBS,
        can_write=current_user.can('registry.execute_write'),
        **_edit_context(),
        **_clicoverage.context('fortianalyzer', page_endpoint='faz_api.index'),
    )


@bp.route('/execute', methods=['POST'])
@login_required
@require_permission('registry.view')
def execute():
    appliance_id = request.form.get('appliance_id', type=int)
    endpoint = (request.form.get('endpoint') or '').strip()
    verb = (request.form.get('method') or 'get').lower()
    body_raw = (request.form.get('body') or '').strip()
    apply_ = (request.form.get('apply') or '').lower() in ('1', 'true', 'on', 'yes')

    if not appliance_id or not endpoint:
        return jsonify(ok=False, error='Appliance and endpoint are required.')
    if verb not in _VERBS:
        return jsonify(ok=False, error=f'Unknown JSON-RPC verb: {verb}')
    if verb in _WRITE_VERBS and not current_user.can('registry.execute_write'):
        return jsonify(ok=False, error='The "Execute write API calls" permission '
                                       'is required for non-get verbs.')

    appliance = visible_appliance_or_404(appliance_id)
    if appliance.kind != 'fortianalyzer':
        return jsonify(ok=False, error='Selected device is not a FortiAnalyzer.')

    # Accept either a logical registry name or a raw JSON-RPC url.
    path = endpoint
    if not endpoint.startswith('/'):
        try:
            path = loader.resolve_for('fortianalyzer', endpoint, appliance.fw_version)
        except loader.EndpointNotServed as exc:
            return jsonify(ok=False, error=str(exc))
        except KeyError:
            return jsonify(ok=False, error=f'Unknown FortiAnalyzer endpoint: {endpoint}')

    body = None
    if body_raw:
        try:
            body = json.loads(body_raw)
        except ValueError as exc:
            return jsonify(ok=False, error=f'Invalid JSON body: {exc}')

    preview = {'method': verb, 'path': path, 'body': body}
    write = verb in _WRITE_VERBS

    # DRY RUN — the default for every mutating verb. Nothing is sent.
    if write and not apply_:
        return jsonify(ok=True, dry_run=True, path=path, request=preview,
                       note=('Dry run — nothing was sent. Re-submit with Apply '
                             'to perform this write on the device.'))

    try:
        client = FortiAnalyzerClient(appliance)
        raw = client.api_call(verb, path, body)
        try:
            client.logout()
        except Exception:  # noqa: BLE001 — best-effort session hygiene
            pass
    except Exception as exc:  # noqa: BLE001
        if write:
            log_action('faz_api.execute', target=appliance.name,
                       extra={'method': verb, 'endpoint': path, 'error': str(exc)})
        return jsonify(ok=False, error=str(exc), request=preview)

    # JSON-RPC rides HTTP 200 whatever happened; the outcome is the envelope's
    # status code (0 = success), so that is what the console reports.
    code, device_err = _rpc_outcome(raw)
    if write:
        log_action('faz_api.execute', target=appliance.name,
                   extra={'method': verb, 'endpoint': path, 'error': device_err})
    return jsonify(ok=True, dry_run=False, status=code, device_error=device_err,
                   path=path, request=preview, result=raw)


def _rpc_outcome(raw):
    """``(code, error)`` of a JSON-RPC envelope: the device status code
    (``result[0].status.code`` legacy, ``result.status.code`` apiver-3, the
    ``error.code`` of a JSON-RPC 2.0 error) and the error text, or None."""
    _data, err = FortiAnalyzerClient._unwrap(raw)
    code = None
    if isinstance(raw, dict):
        if isinstance(raw.get('error'), dict):
            code = raw['error'].get('code')
        else:
            res = raw.get('result')
            if isinstance(res, list):
                res = res[0] if res else {}
            if isinstance(res, dict):
                code = (res.get('status') or {}).get('code')
    return code, err


# --------------------------------------------------------------------------- #
#  Registry catalog editor (REGISTRY_EDIT) — product='fortianalyzer'           #
# --------------------------------------------------------------------------- #

def _back():
    return redirect(url_for('faz_api.index'))


@bp.route('/registry/save', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def registry_save():
    rid = request.form.get('id', type=int)
    name = (request.form.get('name') or '').strip()
    urn = (request.form.get('urn') or '').strip()
    api_version = (request.form.get('api_version') or 'jsonrpc').strip() or 'jsonrpc'

    before, action = None, 'registry.faz_endpoint_create'
    if rid:
        existing = db.session.get(RegistryEndpoint, rid)
        if existing is None or existing.product != 'fortianalyzer':
            abort(404)
        action = 'registry.faz_endpoint_update'
        before = {'name': existing.name, 'urn': existing.urn,
                  'api_version': existing.api_version}

    # The ONE catalog writer (validation, duplicate check, cache drop).
    ok, msg, _row = registry_write.save_endpoint(
        product='fortianalyzer', name=name, urn=urn, api_version=api_version,
        row_id=rid, actor=current_user.username)
    if not ok:
        flash(msg, 'danger')
        return _back()

    log_action(action, target=name, extra={'urn': urn, 'api_version': api_version,
                                           'before': before})
    flash(f'FortiAnalyzer endpoint "{name}" saved.', 'success')
    return _back()


@bp.route('/registry/toggle/<int:rid>', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def registry_toggle(rid):
    row = db.session.get(RegistryEndpoint, rid)
    if row is None or row.product != 'fortianalyzer':
        abort(404)
    row.enabled = not row.enabled
    row.updated_by = current_user.username
    db.session.commit()
    loader.invalidate_faz_cache()
    state = 'enabled' if row.enabled else 'disabled'
    log_action('registry.faz_endpoint_toggle', target=row.name,
               extra={'urn': row.urn, 'state': state})
    flash(f'FortiAnalyzer endpoint "{row.name}" {state}.', 'success')
    return _back()
