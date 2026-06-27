from flask import Blueprint, render_template, jsonify
from flask_login import login_required
from ..models import Appliance
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient

bp = Blueprint('workspace', __name__, url_prefix='/workspace')


@bp.route('/')
@login_required
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    return render_template('workspace/index.html', appliances=appliances)


@bp.route('/<int:appliance_id>')
@login_required
def appliance(appliance_id):
    appl = Appliance.query.get_or_404(appliance_id)
    policies = []
    error = None
    try:
        if appl.kind == 'fortiweb':
            client = FortiWebClient(appl)
            raw = client.list_server_policies()
            policies = raw.get('data', raw.get('results', []))
        elif appl.kind == 'fortiadc':
            client = FortiADCClient(appl)
            raw = client.list_virtual_servers()
            policies = raw.get('payload', [])
    except Exception as exc:
        error = str(exc)
    return render_template('workspace/policies.html', appliance=appl, policies=policies, error=error)


@bp.route('/<int:appliance_id>/policy/<path:name>')
@login_required
def policy_detail(appliance_id, name):
    appl = Appliance.query.get_or_404(appliance_id)
    policy_data = None
    error = None
    try:
        client = FortiWebClient(appl)
        raw = client.get_server_policy(name)
        policy_data = raw.get('data', raw)
    except Exception as exc:
        error = str(exc)
    return render_template('workspace/policy_detail.html', appliance=appl, policy_name=name,
                           policy_data=policy_data, error=error)


@bp.route('/<int:appliance_id>/browse/<path:endpoint_path>')
@login_required
def browse(appliance_id, endpoint_path):
    appl = Appliance.query.get_or_404(appliance_id)
    data = None
    error = None
    try:
        client = FortiWebClient(appl) if appl.kind == 'fortiweb' else FortiADCClient(appl)
        resp = client.api_call('GET', '/' + endpoint_path)
        data = resp.json()
    except Exception as exc:
        error = str(exc)
    return render_template('workspace/browse.html', appliance=appl, endpoint_path=endpoint_path,
                           data=data, error=error)
