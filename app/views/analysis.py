from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('analysis', __name__, url_prefix='/analysis')


@bp.route('/')
@login_required
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    return render_template('analysis/index.html', appliances=appliances)


@bp.route('/<int:id>')
@login_required
def dashboard(id):
    appliance = Appliance.query.get_or_404(id)
    sessions = []
    top_sources = []
    top_attacks = []
    error = None
    try:
        client = FortiWebClient(appliance)
        sessions = client.api_call('GET', '/FortiView/FortiView/SessionHistory').json().get('data', [])
        top_sources = client.api_call('GET', '/FortiView/FortiView/TopSources').json().get('data', [])
        top_attacks = client.api_call('GET', '/FortiView/FortiView/TopAttacks').json().get('data', [])
    except Exception as exc:
        error = str(exc)
    return render_template(
        'analysis/dashboard.html',
        appliance=appliance,
        sessions=sessions,
        top_sources=top_sources,
        top_attacks=top_attacks,
        error=error,
    )


@bp.route('/<int:id>/sessions')
@login_required
def sessions_data(id):
    appliance = Appliance.query.get_or_404(id)
    try:
        client = FortiWebClient(appliance)
        data = client.api_call('GET', '/FortiView/FortiView/SessionHistory').json().get('data', [])
        return jsonify({'ok': True, 'data': data})
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)})
