from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('architecture', __name__, url_prefix='/architecture')


@bp.route('/')
@login_required
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    return render_template('architecture/index.html', appliances=appliances)


@bp.route('/data')
@login_required
def topology_data():
    appliances = Appliance.query.order_by(Appliance.name).all()
    nodes = []
    edges = []
    for appliance in appliances:
        try:
            client = FortiWebClient(appliance)
            policies = client.list_server_policies() or []
            appliance_node = {
                'id': f'appliance_{appliance.id}',
                'label': appliance.name,
                'type': 'appliance',
                'kind': appliance.kind,
                'host': appliance.host,
            }
            nodes.append(appliance_node)
            for policy in policies:
                policy_name = policy.get('name') or policy.get('id', 'unknown')
                policy_node_id = f'policy_{appliance.id}_{policy_name}'
                nodes.append({
                    'id': policy_node_id,
                    'label': policy_name,
                    'type': 'policy',
                    'appliance_id': appliance.id,
                })
                edges.append({
                    'source': f'appliance_{appliance.id}',
                    'target': policy_node_id,
                })
        except Exception:
            nodes.append({
                'id': f'appliance_{appliance.id}',
                'label': appliance.name,
                'type': 'appliance',
                'kind': appliance.kind,
                'host': appliance.host,
                'offline': True,
            })
    return jsonify({'nodes': nodes, 'edges': edges})
