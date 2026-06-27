from collections import OrderedDict

from flask import Blueprint, render_template, jsonify
from flask_login import login_required

from ..models import Appliance
from ..clients.fortiweb import FortiWebClient

bp = Blueprint('architecture', __name__, url_prefix='/architecture')


@bp.route('/')
@login_required
def index():
    appliances = Appliance.query.all()
    sorted_appliances = sorted(
        appliances,
        key=lambda a: (a.zone or 'zzz', a.line or 'zzz', a.department or 'zzz', a.name or ''),
    )
    groups = OrderedDict()
    for a in sorted_appliances:
        z = a.zone or '(no zone)'
        l = a.line or '(no line)'
        d = a.department or '(no department)'
        if z not in groups:
            groups[z] = OrderedDict()
        if l not in groups[z]:
            groups[z][l] = OrderedDict()
        if d not in groups[z][l]:
            groups[z][l][d] = []
        groups[z][l][d].append(a)
    return render_template('architecture/index.html',
                           fleet_map=groups,
                           appliances=appliances,
                           total=len(appliances))


@bp.route('/data')
@login_required
def topology_data():
    appliances = Appliance.query.order_by(Appliance.name).all()
    nodes = []
    edges = []
    for a in appliances:
        try:
            client = FortiWebClient(a)
            policies = client.list_server_policies() or []
            nodes.append({
                'id': f'appliance_{a.id}',
                'label': a.name,
                'type': 'appliance',
                'kind': a.kind,
                'host': a.host,
                'zone': a.zone,
                'line': a.line,
                'department': a.department,
                'policy_count': len(policies),
            })
            for p in policies:
                pid = p.get('name') or p.get('id', 'unknown')
                nodes.append({'id': f'policy_{a.id}_{pid}', 'label': pid, 'type': 'policy'})
                edges.append({'source': f'appliance_{a.id}', 'target': f'policy_{a.id}_{pid}'})
        except Exception:
            nodes.append({
                'id': f'appliance_{a.id}',
                'label': a.name,
                'type': 'appliance',
                'kind': a.kind,
                'host': a.host,
                'zone': a.zone,
                'line': a.line,
                'department': a.department,
                'offline': True,
                'policy_count': None,
            })
    return jsonify({'nodes': nodes, 'edges': edges})
