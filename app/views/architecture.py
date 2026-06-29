from collections import OrderedDict

from flask import (Blueprint, render_template, jsonify, url_for, request,
                   redirect, session)
from flask_login import login_required, current_user

from ..models import Appliance
from ..clients.fortiweb import FortiWebClient
from ..services import device_context
from ..services import user_settings_store as _ustore

bp = Blueprint('architecture', __name__, url_prefix='/architecture')


def _grouped(appliances):
    sorted_appliances = sorted(
        appliances,
        key=lambda a: (a.zone or 'zzz', a.line or 'zzz', a.department or 'zzz', a.name or ''),
    )
    groups = OrderedDict()
    for a in sorted_appliances:
        z = a.zone or '(no zone)'
        l = a.line or '(no line)'
        d = a.department or '(no department)'
        groups.setdefault(z, OrderedDict()).setdefault(l, OrderedDict()).setdefault(d, []).append(a)
    return groups


def _facets(appliances):
    zones, lines, depts = set(), set(), set()
    for a in appliances:
        if a.zone:
            zones.add(a.zone)
        if a.line:
            lines.add(a.line)
        if a.department:
            depts.add(a.department)
    return sorted(zones), sorted(lines), sorted(depts)


@bp.route('/')
@login_required
def index():
    appliances = Appliance.query.all()
    zones, lines, depts = _facets(appliances)
    try:
        saved = _ustore.architecture_filters(current_user.id)
    except Exception:
        saved = {}
    return render_template('architecture/index.html',
                           fleet_map=_grouped(appliances),
                           appliances=appliances,
                           total=len(appliances),
                           current=device_context.current_appliance(),
                           facet_zones=zones,
                           facet_lines=lines,
                           facet_depts=depts,
                           saved_filters=saved)


@bp.route('/picker')
@login_required
def picker():
    """Lightweight device-picker fragment for the banner switch modal."""
    appliances = Appliance.query.all()
    zones, lines, depts = _facets(appliances)
    try:
        saved = _ustore.architecture_filters(current_user.id)
    except Exception:
        saved = {}
    return render_template('architecture/_picker.html',
                           fleet_map=_grouped(appliances),
                           current=device_context.current_appliance(),
                           facet_zones=zones,
                           facet_lines=lines,
                           facet_depts=depts,
                           saved_filters=saved)


@bp.route('/select/<int:id>', methods=['POST'])
@login_required
def select(id):
    """Pick a device → make it the session context, then go to its Server Policy."""
    appl = Appliance.query.get_or_404(id)
    device_context.set_current(appl.id)
    nxt = request.form.get('next') or request.args.get('next')
    if nxt and nxt.startswith('/'):
        return redirect(nxt)
    return redirect(url_for('workspace.index'))


@bp.route('/filters', methods=['POST'])
@login_required
def save_filters():
    """Persist this user's Fleet-map filters (JSON body or form)."""
    data = request.get_json(silent=True) or request.form.to_dict()
    try:
        _ustore.save_architecture_filters(current_user.id, data)
        return jsonify(ok=True)
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc)), 400


@bp.route('/device/<int:id>')
@login_required
def device_detail(id):
    """Read-only physical-inventory payload for the Fleet Map modal."""
    a = Appliance.query.get_or_404(id)
    data = a.inventory_view()
    data['detail_url'] = url_for('appliances.detail', id=a.id)
    data['datasheet_url'] = (
        url_for('appliances.datasheet', id=a.id) if a.datasheet_filename else None
    )
    return jsonify(data)


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
                'id': f'appliance_{a.id}', 'label': a.name, 'type': 'appliance',
                'kind': a.kind, 'host': a.host, 'zone': a.zone, 'line': a.line,
                'department': a.department, 'policy_count': len(policies),
            })
            for p in policies:
                pid = p.get('name') or p.get('id', 'unknown')
                nodes.append({'id': f'policy_{a.id}_{pid}', 'label': pid, 'type': 'policy'})
                edges.append({'source': f'appliance_{a.id}', 'target': f'policy_{a.id}_{pid}'})
        except Exception:
            nodes.append({
                'id': f'appliance_{a.id}', 'label': a.name, 'type': 'appliance',
                'kind': a.kind, 'host': a.host, 'zone': a.zone, 'line': a.line,
                'department': a.department, 'offline': True, 'policy_count': None,
            })
    return jsonify({'nodes': nodes, 'edges': edges})
