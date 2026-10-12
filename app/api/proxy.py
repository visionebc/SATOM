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
    fe80::/10) and loopback (127.0.0.0/8, ::1). Hostnames and normal (incl.
    RFC1918 fleet) IPs are allowed; we don't do DNS on the request path.
    Defence-in-depth against SSRF."""
    try:
        addr = _ipaddress.ip_address(host.strip())
    except ValueError:
        return False
    return addr.is_link_local or addr.is_loopback

WRITE_METHODS = {'POST', 'PUT', 'DELETE', 'PATCH'}


def _verified(response, verify):
    """Carry the device re-read of a write as two response HEADERS: the body
    and status are the device's own reply, passed through byte for byte, and
    a client of this proxy parses that reply — a field folded into it would
    change what it reads. ``X-SATOM-Verify``: ``verified`` / ``mismatch`` /
    ``unverified``; ``X-SATOM-Verify-Detail``: the operator line (ASCII: a
    header is Latin-1 on the wire)."""
    if not isinstance(verify, dict):
        return response
    from flask import make_response
    resp = make_response(response)
    resp.headers['X-SATOM-Verify'] = verify.get('verdict') or 'unverified'
    detail = str(verify.get('label') or '').replace('\u2014', '-').replace('\u2192', '->')
    resp.headers['X-SATOM-Verify-Detail'] = detail.encode('ascii', 'replace').decode()[:400]
    return resp


def _accepted_write(kind, method, result):
    """Was this raw write ACCEPTED (so worth re-reading)? FortiWeb: HTTP < 400
    and no body ``errcode`` (``FortiWebOps._response_ok``); FortiADC: no
    negative ``payload`` (``device_verify.adc_refusal``)."""
    if method not in WRITE_METHODS:
        return False
    from ..services import device_verify
    if kind == 'fortiadc':
        return not device_verify.adc_refusal(result)
    from ..services.fortiweb_ops import FortiWebOps
    return FortiWebOps._response_ok(result)[0]


def _verdict(appliance, client, method, path, body, result):
    from ..services import device_verify
    if not _accepted_write(appliance.kind, method, result):
        return None
    return device_verify.after_request(appliance, client, method, path, body)


def _check_write_permission():
    """A raw write through the proxy is the same act as a raw write from the
    API Explorer, so it needs the same key: ``registry.execute_write`` (the
    coarse ``config_write`` alone would let an operator do arbitrary appliance
    REST writes the Explorer refuses them)."""
    if request.method.upper() in WRITE_METHODS:
        if not current_user.can('registry.execute_write'):
            return jsonify({'error': 'registry.execute_write permission required'}), 403
    return None


@bp.route('/fw/<int:id>/proxy/<path:endpoint_path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
@require_permission('registry.view')
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
        verify = _verdict(appliance, client, method, '/' + endpoint_path, body, result)
        if method in WRITE_METHODS:
            log_action(
                'api.proxy.fw',
                appliance_id=appliance.id,
                detail=f'{method} /{endpoint_path}'
                       + (f' verify={verify["verdict"]}' if verify else ''),
            )
        try:
            return _verified((jsonify(result.json()), result.status_code), verify)
        except Exception:
            return _verified((result.content, result.status_code, {'Content-Type': result.headers.get('content-type', 'application/octet-stream')}), verify)
    except Exception as exc:
        return jsonify({'error': str(exc)}), 502


@bp.route('/adc/<int:id>/proxy/<path:endpoint_path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
@require_permission('registry.view')
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
        verify = _verdict(appliance, client, method, '/' + endpoint_path, body, result)
        if method in WRITE_METHODS:
            log_action(
                'api.proxy.adc',
                appliance_id=appliance.id,
                detail=f'{method} /{endpoint_path}'
                       + (f' verify={verify["verdict"]}' if verify else ''),
            )
        try:
            return _verified((jsonify(result.json()), result.status_code), verify)
        except Exception:
            return _verified((result.content, result.status_code, {'Content-Type': result.headers.get('content-type', 'application/octet-stream')}), verify)
    except Exception as exc:
        return jsonify({'error': str(exc)}), 502
