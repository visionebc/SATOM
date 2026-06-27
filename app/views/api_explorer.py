from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('api_explorer', __name__, url_prefix='/api-explorer')

WRITE_METHODS = {'POST', 'PUT', 'DELETE', 'PATCH'}


@bp.route('/')
@login_required
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    return render_template('api_explorer/index.html', appliances=appliances)


@bp.route('/execute', methods=['POST'])
@login_required
def execute():
    appliance_id = request.form.get('appliance_id', type=int)
    endpoint = request.form.get('endpoint', '').strip()
    method = request.form.get('method', 'GET').upper()
    body_raw = request.form.get('body', '').strip()

    if not appliance_id or not endpoint:
        return jsonify({'ok': False, 'error': 'Appliance and endpoint are required.'})

    if method in WRITE_METHODS and not current_user.can(Permission.CONFIG_WRITE):
        return jsonify({'ok': False, 'error': 'CONFIG_WRITE permission required for write operations.'})

    appliance = Appliance.query.get_or_404(appliance_id)

    body = None
    if body_raw:
        import json
        try:
            body = json.loads(body_raw)
        except ValueError as exc:
            return jsonify({'ok': False, 'error': f'Invalid JSON body: {exc}'})

    try:
        client = FortiWebClient(appliance)
        resp = client.api_call(method, endpoint, body)
        log_action('api_explorer.execute', target=appliance.name,
                   extra={'method': method, 'endpoint': endpoint})
        try:
            result = resp.json()
        except Exception:
            result = resp.text
        return jsonify({'ok': True, 'status': resp.status_code, 'result': result})
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)})
