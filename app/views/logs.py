from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('logs', __name__, url_prefix='/logs')


@bp.route('/')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    return render_template('logs/index.html', appliances=appliances)


@bp.route('/<int:id>')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def view_logs(id):
    appliance = Appliance.query.get_or_404(id)
    return render_template('logs/view.html', appliance=appliance)


@bp.route('/<int:id>/data')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def logs_data(id):
    appliance = Appliance.query.get_or_404(id)
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    log_type = request.args.get('type', 'attack')
    try:
        client = FortiWebClient(appliance)
        start = (page - 1) * per_page
        path = f'/Log/LogReport/AttackEventLog?start={start}&count={per_page}&type={log_type}'
        resp = client.api_call('GET', path)
        data = resp.json().get('data', [])
        return jsonify({
            'ok': True,
            'data': data,
            'page': page,
            'per_page': per_page,
        })
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)})
