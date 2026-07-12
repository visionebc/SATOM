"""FortiAnalyzer manager area — the FAZ ADOM shell.

FortiAnalyzer is a log aggregator / SIEM: it speaks JSON-RPC and its 'objects'
are logs, reports, event handlers and incidents. The sidebar mirrors the REAL
FAZ 7.6.7 GUI panes (:mod:`app.services.faz_menu` — crawled from the official
administration guide); every leaf's tabs bind to registry endpoints
(product='fortianalyzer', DB-first — see ``registry.loader.load_faz_registry``)
and render LIVE device data through
:class:`app.clients.fortianalyzer.FortiAnalyzerClient`.

Config-tree tabs are EDITABLE like the real unit's toolbar (Create New /
Edit / Delete): writes go through the same dry-run-default contract as the
FortiWeb/FortiADC editors — the endpoint returns the exact JSON-RPC request
it would send, a real device write needs ``apply=true``, requires the
``config_write`` permission and is audited. Which endpoints accept writes is
decided by :mod:`app.services.faz_objform` (config families only — the
operational panes stay read-only, exactly like the real GUI).

The Fleet (Architecture / Analysis / Metrics) and Administration (Appliances
/ Audit / Firmware / Network segment) areas reuse the SAME shared,
product-scoped blueprints every ADOM uses; the DB row carries
cap_firmware/cap_tokens so Firmware and API tokens scope to this ADOM
automatically.
"""
from __future__ import annotations

from flask import (Blueprint, abort, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..clients.fortianalyzer import FortiAnalyzerClient
from ..models import (Appliance, Permission, visible_appliances,
                      visible_appliance_or_404)
from ..registry import loader
from ..services import device_context, faz_menu, faz_objform
from ..services.audit import log_action

bp = Blueprint('faz', __name__, url_prefix='/faz')

# Section pages are browse views — keep row counts honest but bounded.
_MAX_ROWS = 500


def _current_faz() -> Appliance | None:
    appl = device_context.current_appliance()
    if appl is not None and appl.kind == 'fortianalyzer':
        return appl
    return None


def _faz_fleet():
    return (visible_appliances().filter_by(kind='fortianalyzer')
            .order_by(Appliance.name).all())


@bp.route('/')
@login_required
def index():
    """FortiAnalyzer dashboard + device picker."""
    groups = faz_menu.menu()
    n_items = sum(len(g.items) for g in groups)
    return render_template('faz/index.html', fleet=_faz_fleet(), groups=groups,
                           n_items=n_items, current=_current_faz())


@bp.route('/use/<int:id>')
@login_required
def use_device(id):
    appl = visible_appliance_or_404(id)
    if appl.kind != 'fortianalyzer':
        abort(404)
    device_context.set_current(appl.id)
    nxt = request.args.get('next')
    return redirect(nxt if nxt and nxt.startswith('/faz') else url_for('faz.index'))


def _columns_for(rows: list) -> list:
    """Display columns: union of the first rows' keys, 'name' first, capped so
    wide CLI objects stay readable (the full object is in the row expander)."""
    cols: list = []
    for r in rows[:25]:
        for k in r:
            if k not in cols and not k.startswith('_') and k != 'obj flags':
                cols.append(k)
    for lead in ('name', 'mkey', 'id'):
        if lead in cols:
            cols.remove(lead)
            cols.insert(0, lead)
    return cols[:8]


def _load_tab(appliance, logical: str, label: str) -> dict:
    """Fetch ONE tab live (the ADC pattern: a page reload per tab keeps every
    request one device round-trip). A device refusal / moved URI degrades to
    an inline error — the page shell stays up."""
    reg = loader.load_faz_registry()
    urn = reg.get(logical) or ''
    writable = faz_objform.is_writable(logical, urn)
    tab = {'logical': logical, 'label': label, 'urn': urn,
           'rows': [], 'kv': None, 'columns': [], 'error': None,
           'truncated': False, 'writable': writable,
           'can_create': writable and faz_objform.can_create(logical),
           'can_delete': writable and faz_objform.can_delete(logical),
           'mkey': ''}
    client = FortiAnalyzerClient(appliance, timeout=20.0)
    rows, err = client.list_with_error(logical, **faz_objform.extra_params(logical))
    try:
        client.logout()
    except Exception:  # noqa: BLE001 — best-effort session hygiene
        pass
    if err:
        tab['error'] = err
        return tab
    rows = [r for r in rows if isinstance(r, dict)]
    if len(rows) == 1 and not logical.startswith('dvmdb_'):
        # single config object → key/value card (CLI 'get' style)
        tab['kv'] = rows[0]
        tab['kv_fields'] = faz_objform.clean_fields(rows[0])
    else:
        tab['truncated'] = len(rows) > _MAX_ROWS
        tab['rows'] = rows[:_MAX_ROWS]
        tab['columns'] = _columns_for(tab['rows'])
        tab['mkey'] = faz_objform.mkey_field(logical, tab['rows'])
    return tab


@bp.route('/m/<item_key>')
@login_required
def menu_page(item_key):
    """One menu leaf: live registry-bound tabs off the selected FortiAnalyzer."""
    found = faz_menu.find_item(item_key)
    if not found:
        abort(404)
    group, item = found
    appliance = _current_faz()
    tab = None
    if appliance and item.logicals:
        wanted = (request.args.get('tab') or '').strip()
        logical, label = item.logicals[0]
        for lg, lb in item.logicals:
            if lg == wanted:
                logical, label = lg, lb
                break
        tab = _load_tab(appliance, logical, label)
    can_write = current_user.can(Permission.CONFIG_WRITE)
    return render_template('faz/section.html', group=group, item=item,
                           fleet=_faz_fleet(), appliance=appliance, tab=tab,
                           can_write=can_write)


# --------------------------------------------------------------------------- #
#  Section-page writes — DRY-RUN DEFAULT (the objedit/ADC contract): the       #
#  endpoint returns the exact JSON-RPC request it would send; a real device    #
#  write needs apply=true. Config families only (faz_objform allow-list) so    #
#  this can never be pointed at an arbitrary JSON-RPC url.                     #
# --------------------------------------------------------------------------- #
def _write_request(op: str, urn: str, mkey_fld: str, mkey: str, fields: dict):
    """(verb, url, data) for one write — the single place the JSON-RPC write
    dialect lives. Legacy CLI/dvmdb tables address rows path-style; report
    config (apiver 3) addresses them by name in the body."""
    v3 = urn.startswith('/report/')
    if op == 'create':
        return 'add', urn, {mkey_fld: mkey, **fields}
    if op == 'update':
        if not mkey:                       # singleton (kv card) edit
            return 'update', urn, fields
        if v3:
            return 'update', urn, {mkey_fld: mkey, **fields}
        return 'update', f'{urn}/{mkey}', {mkey_fld: mkey, **fields}
    if op == 'delete':
        if v3:
            return 'delete', urn, {mkey_fld: mkey}
        return 'delete', f'{urn}/{mkey}', None
    raise ValueError(f'unknown op {op!r}')


# --------------------------------------------------------------------------- #
#  Device Manager toolbar — device-authorization commands (NOT table CRUD).    #
#  Same dry-run-default contract as writes: the endpoint returns the exact      #
#  JSON-RPC ``exec`` it would send; a real device command needs apply=true,     #
#  requires CONFIG_WRITE and is audited. Only the fixed verbs below are         #
#  reachable. Verified live on faz01 7.6.7: ``add/dev-list`` is accepted        #
#  (returns a taskid) — ``del`` shapes are best-effort and the device's own     #
#  error is surfaced verbatim, never faked as success.                          #
# --------------------------------------------------------------------------- #
_DEVICE_ACTIONS = ('authorize', 'delete')


def _device_action_request(action: str, names: list, adom: str):
    """(verb, url, data) for one Device Manager command."""
    if action == 'authorize':
        return ('exec', '/dvm/cmd/add/dev-list',
                {'adom': adom, 'flags': ['create_task', 'nonblocking'],
                 'add-dev-list': [{'name': n} for n in names]})
    if action == 'delete':
        return ('exec', '/dvm/cmd/del/dev-list',
                {'adom': adom,
                 'del-dev-member-list': [{'name': n} for n in names]})
    raise ValueError(f'unknown device action {action!r}')


@bp.route('/device-action', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def device_action():
    """Device Manager toolbar (Authorize / Delete): dry-run-default exec."""
    appliance = _current_faz()
    if appliance is None:
        return jsonify(ok=False, error='no FortiAnalyzer selected'), 400
    body = request.get_json(silent=True) or {}
    action = (body.get('action') or '').strip()
    names = [str(n).strip() for n in (body.get('names') or []) if str(n).strip()]
    adom = (str(body.get('adom') or '').strip() or 'root')
    do_apply = bool(body.get('apply'))

    if action not in _DEVICE_ACTIONS:
        return jsonify(ok=False, error=f'unknown action: {action}'), 400
    if not names:
        return jsonify(ok=False, error='no devices selected'), 400

    try:
        verb, url, data = _device_action_request(action, names, adom)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400

    if not do_apply:
        return jsonify(ok=True, dry_run=True,
                       request={'method': verb, 'path': url, 'body': data})

    client = FortiAnalyzerClient(appliance, timeout=30.0)
    try:
        out, err = client.call(verb, url, data)
    finally:
        try:
            client.logout()
        except Exception:  # noqa: BLE001
            pass
    if err:
        return jsonify(ok=False, error=err), 502
    log_action(f'faz.device.{action}', target=','.join(names),
               detail={'adom': adom}, appliance_id=appliance.id)
    return jsonify(ok=True, dry_run=False, result=out)


@bp.route('/write/<logical>', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def write(logical):
    appliance = _current_faz()
    if appliance is None:
        return jsonify(ok=False, error='no FortiAnalyzer selected'), 400
    reg = loader.load_faz_registry()
    urn = reg.get(logical)
    if not urn or not faz_objform.is_writable(logical, urn):
        return jsonify(ok=False, error='endpoint not writable'), 400

    body = request.get_json(silent=True) or {}
    op = (body.get('op') or '').strip()
    mkey = str(body.get('mkey') or '').strip()
    fields = faz_objform.clean_fields(body.get('fields') or {})
    do_apply = bool(body.get('apply'))

    if op not in ('create', 'update', 'delete'):
        return jsonify(ok=False, error=f'unknown op: {op}'), 400
    if op == 'create' and not faz_objform.can_create(logical):
        return jsonify(ok=False, error='create not supported here'), 400
    if op == 'delete' and not faz_objform.can_delete(logical):
        return jsonify(ok=False, error='delete not supported here'), 400
    if op == 'create' and not mkey:
        return jsonify(ok=False, error='name (mkey) required'), 400
    if op == 'delete' and not mkey:
        return jsonify(ok=False, error='mkey required'), 400
    if op in ('create', 'update') and not fields and not (op == 'create' and mkey):
        return jsonify(ok=False, error='no changes to save'), 400

    mkey_fld = faz_objform.mkey_field(logical)
    try:
        verb, url, data = _write_request(op, urn, mkey_fld, mkey, fields)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400

    if not do_apply:
        return jsonify(ok=True, dry_run=True,
                       request={'method': verb, 'path': url, 'body': data})

    client = FortiAnalyzerClient(appliance, timeout=20.0)
    try:
        _out, err = client.call(verb, url, data)
    finally:
        try:
            client.logout()
        except Exception:  # noqa: BLE001
            pass
    if err:
        return jsonify(ok=False, error=err), 502
    log_action(f'faz.{op}', target=f'{logical}/{mkey or "(singleton)"}',
               detail={'fields': sorted(fields)}, appliance_id=appliance.id)
    return jsonify(ok=True, dry_run=False)
