"""Log Collection — run the read-only get/diagnose battery over SSH per device.

Web counterpart of the desktop Logs page (``app/ui/pages/logs_page.py``). Tick
FortiWeb appliances, give the run a label, collect the read-only diagnostic
battery (or your own get/diagnose commands) into labelled ``.txt`` files under
``data/diagnostics/``, then browse/view the history. Read-only by construction
(every command asserted read-only) and CONFIG_WRITE gated.

This REPLACES the earlier migration's REST "attack/event log" table viewer,
which never matched what the standalone Logs page actually does (it collects a
diagnostic battery over SSH, it does not page the on-box log database).
"""
from __future__ import annotations

from os.path import basename
from types import SimpleNamespace

from flask import (Blueprint, render_template, request, jsonify, abort, Response)
from flask_login import login_required, current_user

from ..auth.decorators import require_permission
from ..models import Appliance, Permission
from ..models import visible_appliances, visible_appliance_or_404
from ..services import logcollect
from ..services.ssh_ops import TROUBLESHOOT, ReadOnlyViolation
from ..services.audit import log_action

bp = Blueprint('logs', __name__, url_prefix='/logs')


def _fortiweb_appliances():
    """FortiWeb appliances only — SSH log collection is FortiWeb-specific."""
    return (visible_appliances()
            .filter(Appliance.kind == 'fortiweb')
            .order_by(Appliance.name).all())


@bp.route('/')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def index():
    return render_template(
        'logs/index.html',
        appliances=_fortiweb_appliances(),
        history=logcollect.history(),
        progress=logcollect.status(),
        battery=logcollect.DIAGNOSTIC_COMMANDS,
        presets=TROUBLESHOOT,
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

    commands = None
    if custom_text:
        try:
            commands = logcollect.parse_commands(custom_text)
        except ReadOnlyViolation as e:
            return jsonify({'ok': False, 'error': str(e)}), 400
        if not commands:
            return jsonify({'ok': False,
                            'error': 'Enter at least one get/diagnose command.'}), 400

    appliances = (visible_appliances()
                  .filter(Appliance.kind == 'fortiweb', Appliance.id.in_(ids)).all()
                  if ids else [])
    if not appliances:
        return jsonify({'ok': False, 'error': 'Select at least one FortiWeb.'}), 400

    # Snapshot credentials in the request context — the worker thread never
    # touches the ORM (and ``password`` is decrypted here while we have context).
    targets = [SimpleNamespace(id=a.id, name=a.name, host=a.host,
                               username=a.username, password=a.password,
                               ssh_port=a.ssh_port or 22)
               for a in appliances]

    res = logcollect.start(targets, label=label, commands=commands,
                           by=getattr(current_user, 'username', ''))
    if not res.get('started'):
        return jsonify({'ok': False, 'error': res.get('reason', 'could not start'),
                        'progress': res.get('progress')}), 409

    log_action('logs.collect', target=f'{len(targets)} device(s)',
               extra={'label': label,
                      'devices': [t.name for t in targets],
                      'commands': len(commands) if commands else len(logcollect.DIAGNOSTIC_COMMANDS),
                      'custom': bool(commands)})
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
    return jsonify({'ok': True, 'files': logcollect.history()})


@bp.route('/file/<path:name>')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def view_file(name):
    text = logcollect.read_log(name)
    if text is None:
        abort(404)
    resp = Response(text, mimetype='text/plain; charset=utf-8')
    if request.args.get('download') == '1':
        resp.headers['Content-Disposition'] = f'attachment; filename="{basename(name)}"'
    return resp
