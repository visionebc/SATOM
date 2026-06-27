from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('server_objects', __name__, url_prefix='/server-objects')


@bp.route('/')
@login_required
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    return render_template('server_objects/index.html', appliances=appliances)


@bp.route('/<int:id>')
@login_required
def overview(id):
    appliance = Appliance.query.get_or_404(id)
    virtual_servers = []
    pools = []
    content_routing = []
    error = None
    try:
        client = FortiWebClient(appliance)
        virtual_servers = client.api_call('GET', '/ServerObjects/Server/VirtualServer').json().get('data', [])
        pools = client.api_call('GET', '/ServerObjects/Server/ServerPool').json().get('data', [])
        content_routing = client.api_call('GET', '/ServerObjects/Server/ContentRouting').json().get('data', [])
    except Exception as exc:
        error = str(exc)
    return render_template(
        'server_objects/overview.html',
        appliance=appliance,
        virtual_servers=virtual_servers,
        pools=pools,
        content_routing=content_routing,
        error=error,
    )


@bp.route('/<int:id>/virtual-servers')
@login_required
def virtual_servers(id):
    appliance = Appliance.query.get_or_404(id)
    items = []
    error = None
    try:
        client = FortiWebClient(appliance)
        items = client.api_call('GET', '/ServerObjects/Server/VirtualServer').json().get('data', [])
    except Exception as exc:
        error = str(exc)
    return render_template(
        'server_objects/virtual_servers.html',
        appliance=appliance,
        items=items,
        error=error,
    )


@bp.route('/<int:id>/pools')
@login_required
def pools(id):
    appliance = Appliance.query.get_or_404(id)
    items = []
    error = None
    try:
        client = FortiWebClient(appliance)
        items = client.api_call('GET', '/ServerObjects/Server/ServerPool').json().get('data', [])
    except Exception as exc:
        error = str(exc)
    return render_template(
        'server_objects/pools.html',
        appliance=appliance,
        items=items,
        error=error,
    )


@bp.route('/<int:id>/content-routing')
@login_required
def content_routing(id):
    appliance = Appliance.query.get_or_404(id)
    items = []
    error = None
    try:
        client = FortiWebClient(appliance)
        items = client.api_call('GET', '/ServerObjects/Server/ContentRouting').json().get('data', [])
    except Exception as exc:
        error = str(exc)
    return render_template(
        'server_objects/content_routing.html',
        appliance=appliance,
        items=items,
        error=error,
    )
