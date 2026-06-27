from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('search', __name__, url_prefix='/search')

SEARCH_ENDPOINTS = [
    '/ServerObjects/Server/ServerPolicy',
    '/ServerObjects/Server/VirtualServer',
    '/ServerObjects/Server/ServerPool',
    '/WebProtection/Profile/InlineProtection',
    '/WebProtection/Exception/ExceptionURL',
]


@bp.route('/')
@login_required
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    return render_template('search/index.html', appliances=appliances)


@bp.route('/results')
@login_required
def results():
    term = request.args.get('q', '').strip()
    appliance_ids = request.args.getlist('appliances', type=int)

    if not term:
        flash('Please enter a search term.', 'warning')
        return redirect(url_for('search.index'))

    if appliance_ids:
        appliances = Appliance.query.filter(Appliance.id.in_(appliance_ids)).all()
    else:
        appliances = Appliance.query.order_by(Appliance.name).all()

    search_results = []
    for appliance in appliances:
        appliance_hits = []
        try:
            client = FortiWebClient(appliance)
            for endpoint in SEARCH_ENDPOINTS:
                try:
                    resp = client.api_call('GET', endpoint)
                    items = resp.json().get('data', [])
                    for item in items:
                        item_str = str(item).lower()
                        if term.lower() in item_str:
                            appliance_hits.append({
                                'endpoint': endpoint,
                                'item': item,
                            })
                except Exception:
                    pass
        except Exception as exc:
            appliance_hits = [{'error': str(exc)}]
        if appliance_hits:
            search_results.append({
                'appliance': appliance,
                'hits': appliance_hits,
            })

    return render_template(
        'search/results.html',
        term=term,
        search_results=search_results,
        appliances=appliances,
    )
