from flask import request, jsonify
from flask_login import login_required, current_user
from . import bp
from ..models import Appliance, db, Permission
from ..models import visible_appliances, visible_appliance_or_404
from ..auth.decorators import require_permission
from ..clients import client_for
from ..services.audit import log_action
import ipaddress as _ipaddress


def _host_is_blocked(host: str) -> bool:
    """Refuse proxying to link-local / cloud-metadata addresses (169.254/16,
    fe80::/10). Hostnames and normal (incl. RFC1918 fleet) IPs are allowed; we
    don't do DNS on the request path. Defence-in-depth against SSRF."""
    try:
        addr = _ipaddress.ip_address(host.strip())
    except ValueError:
        return False
    return addr.is_link_local

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

    appliance = visible_appliance_or_404(id)
    if _host_is_blocked(appliance.host):
        return jsonify({'error': 'appliance host is not permitted'}), 400
    method = request.method.upper()
    body = request.get_json(silent=True) if method in WRITE_METHODS else None

    if appliance.kind != 'fortiweb':
        return jsonify({'error': 'not a FortiWeb appliance'}), 400
    try:
        client = client_for(appliance)
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

    appliance = visible_appliance_or_404(id)
    if _host_is_blocked(appliance.host):
        return jsonify({'error': 'appliance host is not permitted'}), 400
    method = request.method.upper()
    body = request.get_json(silent=True) if method in WRITE_METHODS else None

    if appliance.kind != 'fortiadc':
        return jsonify({'error': 'not a FortiADC appliance'}), 400
    try:
        client = client_for(appliance)
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
