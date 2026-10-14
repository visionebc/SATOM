"""Diagnose Log Collection — run the active ADOM's read-only battery over SSH.

Web counterpart of the desktop Logs page (``app/ui/pages/logs_page.py``). Tick
devices of the ACTIVE ADOM, give the run a label, collect that ADOM's
diagnostic battery (Administrator → Diagnostic Battery,
:mod:`app.services.diag_battery`) — or your own get/show/diagnose commands —
into labelled ``.txt`` files under ``data/diagnostics/``, then browse/view the
history. Read-only by construction (every command passes the battery rule
before it is accepted and again before it is sent) and CONFIG_WRITE gated.

Since 2026-10-14 (operator request) the page lives under Operations ›
Troubleshooting in all five device ADOMs, not FortiWeb only. Each device's
plan (which battery commands its build has) is computed here, in the request
context, and travels with the credential snapshot; the worker sends only the
commands the plan runs and writes the others into the report as SKIPPED.

This REPLACES the earlier migration's REST "attack/event log" table viewer,
which never matched what the standalone Logs page actually does (it collects a
diagnostic battery over SSH, it does not page the on-box log database).
"""
from __future__ import annotations

from os.path import basename
from types import SimpleNamespace

from flask import (Blueprint, render_template, request, jsonify, abort, Response,
                   current_app)
from flask_login import login_required, current_user
from sqlalchemy import or_

from ..auth.decorators import require_permission
from ..models import Appliance, Permission
from ..models import visible_appliances, visible_appliance_or_404
from ..services import diag_battery, logcollect
from ..services.product_scope import session_product
from ..services.audit import log_action

bp = Blueprint('logs', __name__, url_prefix='/logs')


#: The ADOM the page falls back to when the request's ADOM is not a device
#: ADOM (the product gate pins Global to FortiWeb for this blueprint).
_FALLBACK_ADOM = "fortiweb"


def _adom_key() -> str:
    """The active device ADOM: its devices are offered and its battery runs."""
    key = session_product()
    return key if key in diag_battery.PRODUCTS else _FALLBACK_ADOM


def _adom_appliances(key: str, ids: list[int] | None = None):
    """Visible appliances of the ADOM's kind. FortiWeb rows may carry no kind
    (they predate the column), exactly as the ADOM scope reads them."""
    q = visible_appliances()
    if key == "fortiweb":
        q = q.filter(or_(Appliance.kind.is_(None), Appliance.kind == "",
                         Appliance.kind == "fortiweb"))
    else:
        q = q.filter(Appliance.kind == key)
    if ids is not None:
        q = q.filter(Appliance.id.in_(ids))
    return q.order_by(Appliance.name).all()


def _adom_name(key: str) -> str:
    try:
        from ..branding import PRODUCTS
        return (PRODUCTS.get(key) or {}).get("name") or key
    except Exception:  # noqa: BLE001 — a label must never break the page
        return key


def _when(value) -> str:
    if value is None:
        return '—'
    if hasattr(value, 'strftime'):
        return value.strftime('%Y-%m-%d %H:%M')
    return str(value)


def _custom_commands(text: str) -> list[str]:
    """The custom box, one command per line, held to the battery rule
    (:func:`app.services.diag_battery.command_reason`). Raises
    :class:`diag_battery.BatteryError` naming the first refused line."""
    return diag_battery.clean_commands(text.splitlines())


@bp.route('/')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def index():
    key = _adom_key()
    commands, meta = diag_battery.get_battery(key)
    return render_template(
        'logs/index.html',
        appliances=_adom_appliances(key),
        history=_visible_history(),
        progress=logcollect.status(),
        battery=commands,
        battery_meta=meta,
        battery_when=_when(meta.get('updated_at')),
        adom_key=key,
        adom_name=_adom_name(key),
        battery_admin_link=('diag_battery.index' in current_app.view_functions
                            and current_user.can('user_manage')),
    )


@bp.route('/collect', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def collect():
    raw_ids = request.form.getlist('appliance_ids') or request.form.getlist('appliance_ids[]')
    ids: list[int] = []
    for x in raw_ids:
        try:
            ids.append(int(x))
        except (TypeError, ValueError):
            continue

    label = (request.form.get('label') or 'manual').strip() or 'manual'
    custom_text = (request.form.get('commands') or '').strip()
    key = _adom_key()

    custom = bool(custom_text)
    if custom:
        try:
            commands = _custom_commands(custom_text)
        except diag_battery.BatteryError as e:
            return jsonify({'ok': False, 'error': f'Refused: {e}'}), 400
        if not commands:
            return jsonify({'ok': False,
                            'error': 'Enter at least one get, show or diagnose command.'}), 400
    else:
        commands, _meta = diag_battery.get_battery(key)
        if not commands:
            return jsonify({'ok': False,
                            'error': 'This ADOM has no diagnostic battery.'}), 400

    appliances = _adom_appliances(key, ids) if ids else []
    if not appliances:
        return jsonify({'ok': False, 'error': 'Select at least one device.'}), 400

    # Snapshot credentials + each device's plan in the request context — the
    # worker thread never touches the ORM. SSH logs in with the SSH login:
    # FortiAuthenticator has a separate SSH password, FortiGate may have a
    # separate SSH user (``ssh_login``/``ssh_secret`` fall back to the API
    # credential when none is set).
    targets = []
    for a in appliances:
        kind = a.kind or 'fortiweb'
        try:
            secret = a.ssh_secret
        except Exception as e:  # noqa: BLE001 — e.g. the vault holds it and is unreachable
            return jsonify({'ok': False,
                            'error': f'{a.name}: the SSH password cannot be read ({e})'}), 400
        targets.append(SimpleNamespace(
            id=a.id, name=a.name, host=a.host, kind=kind,
            firmware=a.firmware or '',
            username=a.ssh_login, ssh_login=a.ssh_login, password=secret,
            ssh_port=a.ssh_port or 22,
            plan=diag_battery.plan(kind, a.firmware, commands)))

    res = logcollect.start(targets, label=label, commands=commands,
                           by=getattr(current_user, 'username', ''), custom=custom)
    if not res.get('started'):
        return jsonify({'ok': False, 'error': res.get('reason', 'could not start'),
                        'progress': res.get('progress')}), 409

    log_action('logs.collect', target=f'{len(targets)} device(s)',
               extra={'label': label, 'adom': key,
                      'devices': [t.name for t in targets],
                      'commands': len(commands),
                      'skipped': {t.name: sum(1 for p in t.plan if p['action'] != 'run')
                                  for t in targets},
                      'custom': custom})
    return jsonify({'ok': True, 'progress': res.get('progress')})


@bp.route('/status')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def status():
    return jsonify(logcollect.status() or {'state': 'idle'})


@bp.route('/history')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def history():
    return jsonify({'ok': True, 'files': _visible_history()})


def _visible_history() -> list[dict]:
    visible = _visible_ids()
    return [f for f in logcollect.history() if str(f.get('device_id')) in visible]


def _visible_ids() -> set[str]:
    """Ids (as the filename prefix spells them) of the devices this user can
    see. A saved log is device output; maintenance devices and other ADOMs
    stay out of the history and out of the file view, as everywhere else."""
    return {str(a.id) for a in visible_appliances().all()}


@bp.route('/file/<path:name>')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def view_file(name):
    if str(logcollect._parse_meta(basename(name or ''))['device_id']) not in _visible_ids():
        abort(404)
    text = logcollect.read_log(name)
    if text is None:
        abort(404)
    resp = Response(text, mimetype='text/plain; charset=utf-8')
    if request.args.get('download') == '1':
        resp.headers['Content-Disposition'] = f'attachment; filename="{basename(name)}"'
    return resp
