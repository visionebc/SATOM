from flask import request, jsonify
from flask_login import login_required, current_user
from . import bp
from ..models import Appliance, db, Permission
from ..auth.decorators import require_permission
from ..services.audit import log_action


@bp.route('/appliances', methods=['GET'])
@login_required
def list_appliances():
    appliances = Appliance.query.order_by(Appliance.name).all()
    return jsonify([
        {
            'id': a.id,
            'name': a.name,
            'kind': a.kind,
            'host': a.host,
            'port': a.port,
            'status': getattr(a, 'last_status', None),
        }
        for a in appliances
    ])


@bp.route('/appliances', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def create_appliance():
    data = request.get_json(force=True) or {}
    name = data.get('name', '').strip()
    kind = data.get('kind', 'fortiweb').strip()
    host = data.get('host', '').strip()
    port = int(data.get('port', 443))
    username = data.get('username', '').strip()
    password = data.get('password', '')
    verify_ssl = bool(data.get('verify_ssl', False))
    vdom = data.get('vdom', '').strip()
    tags = data.get('tags', '').strip()
    department = data.get('department', '').strip()
    zone = data.get('zone', '').strip()

    if not name or not host:
        return jsonify({'error': 'name and host are required'}), 400

    if Appliance.query.filter_by(name=name).first():
        return jsonify({'error': f'Appliance with name {name!r} already exists'}), 409

    appliance = Appliance(
        name=name,
        kind=kind,
        host=host,
        port=port,
        username=username,
        verify_ssl=verify_ssl,
        vdom=vdom,
        tags=tags,
        department=department,
        zone=zone,
    )
    appliance.set_password(password)
    db.session.add(appliance)
    db.session.commit()
    log_action('api.appliance.create', appliance_id=appliance.id, detail=f'Created appliance {name}')
    return jsonify({
        'id': appliance.id,
        'name': appliance.name,
        'kind': appliance.kind,
        'host': appliance.host,
        'port': appliance.port,
    }), 201


@bp.route('/appliances/<int:id>', methods=['PUT'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def update_appliance(id):
    appliance = Appliance.query.get_or_404(id)
    data = request.get_json(force=True) or {}

    if 'name' in data:
        appliance.name = data['name'].strip()
    if 'kind' in data:
        appliance.kind = data['kind'].strip()
    if 'host' in data:
        appliance.host = data['host'].strip()
    if 'port' in data:
        appliance.port = int(data['port'])
    if 'username' in data:
        appliance.username = data['username'].strip()
    if 'password' in data and data['password']:
        appliance.set_password(data['password'])
    if 'verify_ssl' in data:
        appliance.verify_ssl = bool(data['verify_ssl'])
    if 'vdom' in data:
        appliance.vdom = data['vdom'].strip()
    if 'tags' in data:
        appliance.tags = data['tags'].strip()
    if 'department' in data:
        appliance.department = data['department'].strip()
    if 'zone' in data:
        appliance.zone = data['zone'].strip()

    db.session.commit()
    log_action('api.appliance.update', appliance_id=appliance.id, detail=f'Updated appliance {appliance.name}')
    return jsonify({
        'id': appliance.id,
        'name': appliance.name,
        'kind': appliance.kind,
        'host': appliance.host,
        'port': appliance.port,
    })


@bp.route('/appliances/<int:id>', methods=['DELETE'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def delete_appliance(id):
    appliance = Appliance.query.get_or_404(id)
    name = appliance.name
    db.session.delete(appliance)
    db.session.commit()
    log_action('api.appliance.delete', detail=f'Deleted appliance {name}')
    return jsonify({'deleted': True, 'id': id})
