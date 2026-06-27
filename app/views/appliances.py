from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required
from ..auth.decorators import require_permission
from sqlalchemy.exc import IntegrityError
from ..models import Appliance, AuditLog, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action
from ..services import settings_store as store

bp = Blueprint('appliances', __name__, url_prefix='/appliances')


@bp.route('/')
@login_required
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    return render_template('appliances/index.html', appliances=appliances,
                           classification=store.all_classification())


@bp.route('/<int:id>')
@login_required
def detail(id):
    appliance = Appliance.query.get_or_404(id)
    recent_audit = AuditLog.query.filter(
        AuditLog.target.like(f'%{appliance.name}%')
    ).order_by(AuditLog.timestamp.desc()).limit(20).all()
    return render_template('appliances/detail.html', appliance=appliance, audit_entries=recent_audit)


@bp.route('/', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def create():
    name = request.form.get('name', '').strip()
    kind = request.form.get('kind', 'fortiweb').strip()
    host = request.form.get('host', '').strip()
    port = int(request.form.get('port', 443) or 443)
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    verify_ssl = request.form.get('verify_ssl') == 'on'
    vdom = request.form.get('vdom', '').strip() or None
    tags = request.form.get('tags', '').strip() or None
    department = request.form.get('department', '').strip() or None
    zone = request.form.get('zone', '').strip() or None
    line = request.form.get('line', '').strip() or None

    if not name or not host:
        flash('Name and host are required.', 'danger')
        return redirect(url_for('appliances.index'))

    appliance = Appliance(
        name=name, kind=kind, host=host, port=port,
        username=username, verify_ssl=verify_ssl,
        vdom=vdom, tags=tags, department=department, zone=zone, line=line,
        password_enc='placeholder',
    )
    appliance.set_password(password)
    db.session.add(appliance)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash(f'Appliance name {name!r} already exists.', 'danger')
        return redirect(url_for('appliances.index'))
    log_action('appliance.create', target=name)
    flash(f'Appliance {name} created.', 'success')
    return redirect(url_for('appliances.detail', id=appliance.id))


@bp.route('/<int:id>/edit')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def edit(id):
    appliance = Appliance.query.get_or_404(id)
    return render_template('appliances/edit.html', appliance=appliance,
                           classification=store.all_classification())


@bp.route('/<int:id>/edit', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def edit_save(id):
    appliance = Appliance.query.get_or_404(id)
    appliance.name = request.form.get('name', appliance.name).strip()
    appliance.kind = request.form.get('kind', appliance.kind).strip()
    appliance.host = request.form.get('host', appliance.host).strip()
    appliance.port = int(request.form.get('port', appliance.port) or 443)
    appliance.username = request.form.get('username', appliance.username).strip()
    appliance.verify_ssl = request.form.get('verify_ssl') == 'on'
    appliance.vdom = request.form.get('vdom', appliance.vdom or '').strip() or None
    appliance.tags = request.form.get('tags', appliance.tags or '').strip() or None
    appliance.department = request.form.get('department', appliance.department or '').strip() or None
    appliance.zone = request.form.get('zone', appliance.zone or '').strip() or None
    appliance.line = request.form.get('line', appliance.line or '').strip() or None
    password = request.form.get('password', '')
    if password:
        appliance.set_password(password)
    db.session.commit()
    log_action('appliance.update', target=appliance.name)
    flash(f'Appliance {appliance.name} updated.', 'success')
    return redirect(url_for('appliances.detail', id=appliance.id))


@bp.route('/<int:id>/delete', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def delete(id):
    appliance = Appliance.query.get_or_404(id)
    name = appliance.name
    db.session.delete(appliance)
    db.session.commit()
    log_action('appliance.delete', target=name)
    flash(f'Appliance {name} deleted.', 'success')
    return redirect(url_for('appliances.index'))


@bp.route('/<int:id>/test', methods=['POST'])
@login_required
def test_connection(id):
    appliance = Appliance.query.get_or_404(id)
    try:
        if appliance.kind == 'fortiweb':
            client = FortiWebClient(appliance)
        else:
            client = FortiADCClient(appliance)
        status = client.status_check()
        log_action('appliance.test', target=appliance.name)
        return jsonify({'ok': True, 'status': status})
    except Exception as exc:
        return jsonify({'ok': False, 'status': str(exc)})
