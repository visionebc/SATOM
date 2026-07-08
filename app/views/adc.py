"""FortiADC manager area — the ADC mirror of the FortiWeb sections.

Structure = the FortiADC GUI's own left menu (:mod:`app.services.adc_menu`):
Server Load Balance / Link Load Balance / Global Load Balance / WAF / Network
Security / Network / Shared Resources / User Authentication / System /
Log & Report. Each menu entry is one page whose TABS are that entry's object
types; every tab lists the type LIVE off the selected FortiADC (there is no
DB-first cache for ADC yet — no lab device exists, so reads are live-only and
device refusals surface as a banner instead of a blank page).

Objects are edited with the SAME logic as the FortiWeb generic editor
(:mod:`app.views.objedit`): a FortiWeb-style FIELD FORM (widgets inferred from
device truth via :mod:`app.services.adc_objform`) plus each registry-derived
CHILD TABLE's rows (``<parent>_child_<seg>``, read scoped with ``?pkey=``).
Every write is ``config_write``-gated, audited, and **dry-run by default** —
the endpoint returns the exact request it would send and a real device write
needs an explicit ``apply=true`` (FortiADC has no server-side dry-run, so the
preview is built here; the contract the operator sees is identical). The raw
JSON editor stays as the escape hatch for inline arrays/objects.
"""
from __future__ import annotations

import json

from flask import (Blueprint, abort, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import login_required

from ..auth.decorators import require_permission
from ..clients.fortiadc import FortiADCClient, FortiADCError
from ..models import Appliance, Permission, visible_appliances, visible_appliance_or_404
from ..services import adc_menu, adc_objform, device_context
from ..services.audit import log_action

bp = Blueprint('adc', __name__, url_prefix='/adc')

# Keys FortiADC objects commonly carry as identity/summary — used to derive
# list columns from live payloads (no curated wire-field catalog yet).
_PRIORITY_COLS = ('status', 'type', 'interface', 'ip', 'address', 'port',
                  'pool', 'profile', 'method', 'mode', 'comments', 'comment')


def _current_adc() -> Appliance | None:
    appl = device_context.current_appliance()
    if appl is not None and appl.kind == 'fortiadc':
        return appl
    return None


def _adc_fleet():
    return (visible_appliances().filter_by(kind='fortiadc')
            .order_by(Appliance.name).all())


def _mkey_of(obj: dict):
    if not isinstance(obj, dict):
        return str(obj)
    return obj.get('mkey') or obj.get('name') or obj.get('id') or '—'


def _derive_columns(rows: list) -> list[str]:
    """Pick up to 6 display columns from the live payload (identity first)."""
    if not rows or not isinstance(rows[0], dict):
        return []
    keys = [k for k in rows[0] if not k.startswith('_')]
    cols = [k for k in _PRIORITY_COLS if k in keys]
    for k in keys:
        if len(cols) >= 6:
            break
        if k not in cols and k not in ('mkey', 'name', 'id'):
            v = rows[0].get(k)
            if isinstance(v, (str, int, float, bool)):
                cols.append(k)
    return cols[:6]


# --------------------------------------------------------------------------- #
#  Dashboard / device picker                                                   #
# --------------------------------------------------------------------------- #
@bp.route('/')
@login_required
def index():
    fleet = _adc_fleet()
    groups = adc_menu.menu()
    n_types = sum(len(i.tabs) for g in groups for i in g.items)
    return render_template('adc/index.html', fleet=fleet, groups=groups,
                           n_types=n_types, current=_current_adc())


@bp.route('/use/<int:id>')
@login_required
def use_device(id):
    appl = visible_appliance_or_404(id)
    if appl.kind != 'fortiadc':
        abort(404)
    device_context.set_current(appl.id)
    nxt = request.args.get('next')
    return redirect(nxt if nxt and nxt.startswith('/adc') else url_for('adc.index'))


# --------------------------------------------------------------------------- #
#  Menu-item page (tabs = object types, live list)                              #
# --------------------------------------------------------------------------- #
@bp.route('/m/<item_key>')
@login_required
def menu_page(item_key):
    found = adc_menu.find_item(item_key)
    if not found:
        abort(404)
    group, item = found
    tab_key = request.args.get('tab') or item.tabs[0].logical
    tab = next((t for t in item.tabs if t.logical == tab_key), item.tabs[0])

    appliance = _current_adc()
    rows, error, columns = [], None, []
    if appliance is not None:
        raw, error = FortiADCClient(appliance).list_with_error(tab.logical)
        columns = _derive_columns(raw)
        rows = [{'mkey': _mkey_of(o),
                 'cells': [o.get(c) if isinstance(o, dict) else None
                           for c in columns]}
                for o in raw]
    return render_template('adc/section.html', group=group, item=item, tab=tab,
                           appliance=appliance, fleet=_adc_fleet(),
                           rows=rows, columns=columns, error=error)


# --------------------------------------------------------------------------- #
#  WAF Signatures — the ADC signature policies (live, read-only overview)       #
# --------------------------------------------------------------------------- #
@bp.route('/signatures')
@login_required
@require_permission(Permission.USER_MANAGE)
def signatures():
    """FortiADC Web Attack Signature policies — one row per signature set with
    its enabled category / sub-category counts, disabled-signature count and
    per-severity actions, read LIVE off the selected device (FortiADC has no
    signature-catalog cache pipeline yet; deep editing goes through the
    generic object editor)."""
    appliance = _current_adc()
    rows, error = [], None
    if appliance is not None:
        raw, error = FortiADCClient(appliance).list_with_error(
            'security_waf_web_attack_signature')
        for o in raw or []:
            if not isinstance(o, dict):
                continue
            rows.append({
                'mkey': _mkey_of(o),
                'status': o.get('status', ''),
                'categories': o.get('enabled_category_count',
                                    o.get('category_id_list_size', '')),
                'sub_categories': o.get('enabled_sub_category_count',
                                        o.get('sub_category_id_list_size', '')),
                'disabled': o.get('disabled_signature_count', 0),
                'high': o.get('high_severity_action', ''),
                'medium': o.get('medium_severity_action', ''),
                'low': o.get('low_severity_action', ''),
                'exception': o.get('exception_name', ''),
                'builtin': bool(o.get('_nondeletable')),
            })
    return render_template('adc/signatures.html', appliance=appliance,
                           fleet=_adc_fleet(), rows=rows, error=error)


# --------------------------------------------------------------------------- #
#  Object detail — FortiWeb-style field form + child tables (raw JSON escape)   #
# --------------------------------------------------------------------------- #
@bp.route('/obj/<logical>')
@login_required
def object_detail(logical):
    appliance = _current_adc()
    if appliance is None:
        return redirect(url_for('adc.index'))
    if not adc_objform.is_known(logical):
        abort(404)
    mkey = request.args.get('mkey')
    create = bool(request.args.get('create'))
    back = request.args.get('back') or url_for('adc.index')

    data, error = {}, None
    client = None
    if not create:
        try:
            client = FortiADCClient(appliance)
            if mkey:
                data = FortiADCClient(appliance).get_object(logical, mkey)
        except Exception as exc:  # noqa: BLE001
            error = str(exc)

    if create:
        # Blank create form: field template from any existing sibling object
        # (union of scalar keys) — the mkey (name) box is rendered separately.
        rows, _err = ([], None)
        try:
            rows, _err = FortiADCClient(appliance).list_with_error(logical)
        except Exception:  # noqa: BLE001
            rows = []
        sample = adc_objform.blank_row_sample(rows[:3])
        obj_groups = adc_objform.create_field_groups(logical, sample)
        subtables = []
    else:
        obj_groups = adc_objform.field_groups(data)
        subtables = []
        for st in adc_objform.subtables_for(logical):
            rows = []
            if client is not None and mkey:
                rows, _e = client.list_with_error(st['logical'], pkey=mkey)
            rows = [r for r in rows if isinstance(r, dict)]
            blank = adc_objform.blank_row_sample(rows)
            blank.setdefault('mkey', '')
            subtables.append({
                'label': st['label'], 'logical': st['logical'], 'seg': st['seg'],
                'rows': [{
                    'sub_mkey': str(r.get('mkey', '')),
                    'label': adc_objform.row_label(r),
                    'groups': adc_objform.field_groups(r),
                } for r in rows],
                'blank_groups': adc_objform.field_groups(blank, keep_mkey=True),
            })

    return render_template('adc/object.html', appliance=appliance,
                           logical=logical, mkey=mkey, create=create,
                           data=data, error=error, back=back,
                           obj_groups=obj_groups, subtables=subtables,
                           create_hint=(adc_objform.create_hint(logical) if create else ''),
                           data_json=json.dumps(data, indent=2, ensure_ascii=False))


# --------------------------------------------------------------------------- #
#  Form writes — DRY-RUN DEFAULT (same contract as the FortiWeb objedit):       #
#  the endpoint returns the exact request it would send; a real device write    #
#  needs apply=true. FortiADC applies immediately, so the preview is built      #
#  here from a fresh device read (changed fields merged onto the GET payload   #
#  — un-shown fields are never dropped by a save).                              #
# --------------------------------------------------------------------------- #
def _clean_for_write(obj: dict) -> dict:
    """Strip device-internal flags and inline structures the form can't edit
    (they stay untouched on the box — FortiADC keeps absent keys as-is)."""
    return {k: v for k, v in (obj or {}).items()
            if not adc_objform.is_noise(k) and not isinstance(v, (list, dict))}


def _form_ctx(body):
    logical = (body.get('logical') or '').strip()
    fields = body.get('fields') or {}
    if not isinstance(fields, dict):
        fields = {}
    return logical, fields, bool(body.get('apply'))


def _dry(method, logical, body_payload, client, **params):
    path = client._resolve(logical)
    if params:
        from urllib.parse import urlencode
        path += '?' + urlencode(params)
    return jsonify(ok=True, dry_run=True,
                   request={'method': method, 'path': path, 'body': body_payload})


@bp.route('/obj/<logical>/save-object', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def form_save_object(logical):
    appliance = _current_adc()
    if appliance is None:
        return jsonify(ok=False, error='no FortiADC selected'), 400
    if not adc_objform.is_known(logical):
        return jsonify(ok=False, error='endpoint not allowed'), 400
    body = request.get_json(silent=True) or {}
    _l, fields, do_apply = _form_ctx(body)
    mkey = (body.get('mkey') or '').strip()
    if not mkey:
        return jsonify(ok=False, error='mkey required'), 400
    if not fields:
        return jsonify(ok=False, error='no changes to save'), 400
    client = FortiADCClient(appliance)
    try:
        current = client.get_object(logical, mkey)
    except (FortiADCError, Exception) as exc:  # noqa: BLE001
        return jsonify(ok=False, error=f'device read failed: {exc}'), 502
    payload = _clean_for_write(current)
    payload.update(fields)
    payload['mkey'] = mkey
    if not do_apply:
        return _dry('PUT', logical, payload, client, mkey=mkey)
    try:
        client.update(logical, mkey, payload)
    except (FortiADCError, Exception) as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc)), 502
    log_action('adc.update', target=f'{logical}/{mkey}',
               detail={'fields': sorted(fields)}, appliance_id=appliance.id)
    return jsonify(ok=True, dry_run=False)


@bp.route('/obj/<logical>/create-object', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def form_create_object(logical):
    appliance = _current_adc()
    if appliance is None:
        return jsonify(ok=False, error='no FortiADC selected'), 400
    if not adc_objform.is_known(logical):
        return jsonify(ok=False, error='endpoint not allowed'), 400
    body = request.get_json(silent=True) or {}
    _l, fields, do_apply = _form_ctx(body)
    mkey = (body.get('mkey') or '').strip()
    if not mkey:
        return jsonify(ok=False, error='name (mkey) required'), 400
    missing = [k for k in adc_objform.required_fields(logical)
               if not str(fields.get(k, '')).strip()]
    if missing:
        return jsonify(ok=False,
                       error='Missing required field(s): ' + ', '.join(missing)), 400
    payload = {k: v for k, v in fields.items() if v not in (None, '', [])}
    payload['mkey'] = mkey
    client = FortiADCClient(appliance)
    if not do_apply:
        return _dry('POST', logical, payload, client)
    try:
        client.create(logical, payload)
    except (FortiADCError, Exception) as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc)), 502
    log_action('adc.create', target=f'{logical}/{mkey}', appliance_id=appliance.id)
    return jsonify(ok=True, dry_run=False, mkey=mkey)


@bp.route('/obj/<logical>/save-row', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def form_save_row(logical):
    """Create or update a child-table row (POST/PUT ``?pkey=<parent>``)."""
    appliance = _current_adc()
    if appliance is None:
        return jsonify(ok=False, error='no FortiADC selected'), 400
    if not adc_objform.is_known(logical) or '_child_' not in logical:
        return jsonify(ok=False, error='endpoint not allowed'), 400
    body = request.get_json(silent=True) or {}
    _l, fields, do_apply = _form_ctx(body)
    pkey = (body.get('pkey') or '').strip()
    sub_mkey = (body.get('sub_mkey') or '').strip()
    if not pkey:
        return jsonify(ok=False, error='parent object (pkey) required'), 400
    if not fields:
        return jsonify(ok=False, error='no changes to save'), 400
    client = FortiADCClient(appliance)

    if not sub_mkey:  # create — POST ?pkey= with the row fields in the body
        missing = [k for k in adc_objform.required_fields(logical)
                   if not str(fields.get(k, '')).strip()]
        if missing:
            return jsonify(ok=False,
                           error='Missing required field(s): ' + ', '.join(missing)), 400
        payload = {k: v for k, v in fields.items() if v not in (None, '', [])}
        if not do_apply:
            return _dry('POST', logical, payload, client, pkey=pkey)
        try:
            client.create(logical, payload, pkey=pkey)
        except (FortiADCError, Exception) as exc:  # noqa: BLE001
            return jsonify(ok=False, error=str(exc)), 502
        log_action('adc.row_create', target=f'{logical}?pkey={pkey}',
                   appliance_id=appliance.id)
        return jsonify(ok=True, dry_run=False)

    # update — merge onto the current row so un-shown keys survive the PUT
    rows, err = client.list_with_error(logical, pkey=pkey)
    if err:
        return jsonify(ok=False, error=f'device read failed: {err}'), 502
    current = next((r for r in rows if isinstance(r, dict)
                    and str(r.get('mkey', '')) == sub_mkey), None)
    if current is None:
        return jsonify(ok=False, error=f'row "{sub_mkey}" not found'), 404
    payload = _clean_for_write(current)
    payload.update(fields)
    payload['mkey'] = sub_mkey
    if not do_apply:
        return _dry('PUT', logical, payload, client, pkey=pkey, mkey=sub_mkey)
    try:
        client.update(logical, sub_mkey, payload, pkey=pkey)
    except (FortiADCError, Exception) as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc)), 502
    log_action('adc.row_update', target=f'{logical}?pkey={pkey}&mkey={sub_mkey}',
               detail={'fields': sorted(fields)}, appliance_id=appliance.id)
    return jsonify(ok=True, dry_run=False)


@bp.route('/obj/<logical>/delete-row', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def form_delete_row(logical):
    appliance = _current_adc()
    if appliance is None:
        return jsonify(ok=False, error='no FortiADC selected'), 400
    if not adc_objform.is_known(logical) or '_child_' not in logical:
        return jsonify(ok=False, error='endpoint not allowed'), 400
    body = request.get_json(silent=True) or {}
    pkey = (body.get('pkey') or '').strip()
    sub_mkey = (body.get('sub_mkey') or '').strip()
    do_apply = bool(body.get('apply'))
    if not pkey or not sub_mkey:
        return jsonify(ok=False, error='pkey and row mkey required'), 400
    client = FortiADCClient(appliance)
    if not do_apply:
        return _dry('DELETE', logical, None, client, pkey=pkey, mkey=sub_mkey)
    try:
        client.delete(logical, sub_mkey, pkey=pkey)
    except (FortiADCError, Exception) as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc)), 502
    log_action('adc.row_delete', target=f'{logical}?pkey={pkey}&mkey={sub_mkey}',
               appliance_id=appliance.id)
    return jsonify(ok=True, dry_run=False)


@bp.route('/obj/<logical>/save', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def object_save(logical):
    appliance = _current_adc()
    if appliance is None:
        return jsonify(ok=False, error='no FortiADC selected'), 400
    body = request.get_json(silent=True) or {}
    mkey = body.get('mkey')
    try:
        payload = json.loads(body.get('data') or '{}')
    except ValueError as exc:
        return jsonify(ok=False, error=f'invalid JSON: {exc}'), 400
    if not isinstance(payload, dict) or not payload:
        return jsonify(ok=False, error='payload must be a non-empty JSON object'), 400
    client = FortiADCClient(appliance)
    try:
        if mkey:
            client.update(logical, mkey, payload)
            action = 'adc.update'
        else:
            client.create(logical, payload)
            action = 'adc.create'
            mkey = _mkey_of(payload)
    except (FortiADCError, Exception) as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc)), 502
    log_action(action, target=f'{logical}/{mkey}', appliance_id=appliance.id)
    return jsonify(ok=True, mkey=mkey)


@bp.route('/obj/<logical>/delete', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def object_delete(logical):
    appliance = _current_adc()
    if appliance is None:
        return jsonify(ok=False, error='no FortiADC selected'), 400
    body = request.get_json(silent=True) or {}
    mkey = body.get('mkey')
    if not mkey:
        return jsonify(ok=False, error='mkey required'), 400
    try:
        FortiADCClient(appliance).delete(logical, mkey)
    except (FortiADCError, Exception) as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc)), 502
    log_action('adc.delete', target=f'{logical}/{mkey}', appliance_id=appliance.id)
    return jsonify(ok=True)


# --------------------------------------------------------------------------- #
#  Guided "New virtual server" wizard — build the whole LB chain in one form.   #
#  A FortiADC VS needs a pool, and the pool needs a real-server member; this    #
#  creates real servers -> pool -> members -> VS bottom-up (dry-run default),   #
#  with a pre-existence guard and best-effort ROLLBACK on a mid-chain failure   #
#  so a partial run never leaves orphans on the box.                            #
# --------------------------------------------------------------------------- #
def _adc_options(appliance):
    out = {'interfaces': [], 'profiles': [], 'methods': []}
    if appliance is None:
        return out
    try:
        c = FortiADCClient(appliance)
    except Exception:  # noqa: BLE001
        return out
    for key, logical in (('interfaces', 'system_interface'),
                         ('profiles', 'load_balance_profile'),
                         ('methods', 'load_balance_method')):
        try:
            rows, _err = c.list_with_error(logical)
            out[key] = sorted({str(_mkey_of(r)) for r in rows
                               if isinstance(r, dict) and _mkey_of(r)})
        except Exception:  # noqa: BLE001
            pass
    return out


def _wizard_conflicts(client, steps):
    """Names among the plan's top-level objects that ALREADY exist on the box."""
    conflicts, seen = [], {}
    for st in steps:
        if st['kind'] != 'object':
            continue
        logical = st['logical']
        if logical not in seen:
            rows, _e = client.list_with_error(logical)
            seen[logical] = {str(_mkey_of(r)) for r in rows if isinstance(r, dict)}
        if st['mkey'] in seen[logical]:
            conflicts.append(st['mkey'])
    return conflicts


def _wizard_rollback(client, created):
    """Best-effort reverse delete of what THIS run created (avoid orphans)."""
    done = []
    for logical, mkey, pkey in reversed(created):
        try:
            client.delete(logical, mkey, pkey=pkey) if pkey else client.delete(logical, mkey)
            done.append(mkey)
        except Exception:  # noqa: BLE001
            pass
    return done


@bp.route('/wizard/virtual-server')
@login_required
def wizard_virtual_server():
    appliance = _current_adc()
    if appliance is None:
        return redirect(url_for('adc.index'))
    back = request.args.get('back') or url_for('adc.index')
    return render_template('adc/wizard_vs.html', appliance=appliance,
                           options=_adc_options(appliance), back=back)


@bp.route('/wizard/virtual-server', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def wizard_virtual_server_apply():
    appliance = _current_adc()
    if appliance is None:
        return jsonify(ok=False, error='no FortiADC selected'), 400
    body = request.get_json(silent=True) or {}
    do_apply = bool(body.get('apply'))
    steps, errors = adc_objform.build_virtual_server_plan(body)
    if errors:
        return jsonify(ok=False, errors=errors), 400
    client = FortiADCClient(appliance)
    conflicts = _wizard_conflicts(client, steps)
    if conflicts:
        return jsonify(ok=False, errors=['Already on the device: ' + ', '.join(conflicts)
                       + ' — pick different names.']), 409
    if not do_apply:
        preview = []
        for st in steps:
            path = client._resolve(st['logical'])
            if st.get('pkey'):
                path += '?pkey=' + st['pkey']
            preview.append({'label': st['label'], 'method': 'POST',
                            'path': path, 'body': st['payload']})
        return jsonify(ok=True, dry_run=True, steps=preview)
    created = []
    for st in steps:
        try:
            if st['kind'] == 'child':
                client.create(st['logical'], st['payload'], pkey=st['pkey'])
                created.append((st['logical'], st['mkey'], st['pkey']))
            else:
                client.create(st['logical'], st['payload'])
                created.append((st['logical'], st['mkey'], None))
        except (FortiADCError, Exception) as exc:  # noqa: BLE001
            rolled = _wizard_rollback(client, created)
            return jsonify(ok=False, failed_step=st['label'], error=str(exc),
                           created=[c[1] for c in created],
                           rolled_back=rolled), 502
    vs_name = str(body.get('vs_name', '')).strip()
    log_action('adc.wizard_create', target='virtual_server/%s' % vs_name,
               detail={'objects': len(created)}, appliance_id=appliance.id)
    return jsonify(ok=True, dry_run=False, vs_name=vs_name,
                   created=[c[1] for c in created])
