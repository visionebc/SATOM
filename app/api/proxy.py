from flask import request, jsonify
from flask_login import login_required, current_user
from . import bp
from ..models import Appliance, db, Permission
from ..auth.decorators import require_permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

WRITE_METHODS = {'POST', 'PUT', 'DELETE', 'PATCH'}


def _check_write_permission():
    if request.method.upper() in WRITE_METHODS:
        if not current_user.can(Permission.CONFIG_WRITE):
            return jsonify({'error': 'CONFIG_WRITE permission required'}), 403
    return None


@bp.route('/fw/<int:id>/proxy/<path:endpoint_path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def fortiweb_proxy(id, endpoint_path):
    perm_error = _check_write_permission()
    if perm_error:
        return perm_error

    appliance = Appliance.query.get_or_404(id)
    method = request.method.upper()
    body = request.get_json(silent=True) if method in WRITE_METHODS else None

    try:
        client = FortiWebClient(appliance)
        result = client.api_call(method, '/' + endpoint_path, body)
        if method in WRITE_METHODS:
            log_action(
                'api.proxy.fw',
                appliance_id=appliance.id,
                detail=f'{method} /{endpoint_path}',
            )
        try:
            return jsonify(result.json()), result.status_code
        except Exception:
            return result.content, result.status_code, {'Content-Type': result.headers.get('content-type', 'application/octet-stream')}
    except Exception as exc:
        return jsonify({'error': str(exc)}), 502


@bp.route('/adc/<int:id>/proxy/<path:endpoint_path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def fortiadc_proxy(id, endpoint_path):
    perm_error = _check_write_permission()
    if perm_error:
        return perm_error

    appliance = Appliance.query.get_or_404(id)
    method = request.method.upper()
    body = request.get_json(silent=True) if method in WRITE_METHODS else None

    try:
        client = FortiADCClient(appliance)
        result = client.api_call(method, '/' + endpoint_path, body)
        if method in WRITE_METHODS:
            log_action(
                'api.proxy.adc',
                appliance_id=appliance.id,
                detail=f'{method} /{endpoint_path}',
            )
        try:
            return jsonify(result.json()), result.status_code
        except Exception:
            return result.content, result.status_code, {'Content-Type': result.headers.get('content-type', 'application/octet-stream')}
    except Exception as exc:
        return jsonify({'error': str(exc)}), 502
