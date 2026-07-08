from flask import current_app, Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..models import visible_appliances, visible_appliance_or_404
from ..clients import client_for
from ..clients.fortiweb import FortiWebClient
from ..services.audit import log_action

bp = Blueprint('search', __name__, url_prefix='/search')

SEARCH_ENDPOINTS = [
    '/ServerObjects/Server/ServerPolicy',
    '/ServerObjects/Server/VirtualServer',
    '/ServerObjects/Server/ServerPool',
    '/WebProtection/Profile/InlineProtection',
    '/WebProtection/Exception/ExceptionURL',
]

# FortiADC — registry LOGICAL collections swept by the free-text search
# (the ADC client resolves each against the fortiadc registry).
ADC_SEARCH_LOGICALS = [
    'load_balance_virtual_server',
    'load_balance_pool',
    'load_balance_real_server',
    'security_waf_profile',
    'system_certificate_local',
]


def _adc_hits(appliance, term: str) -> list[dict]:
    """Free-text hits across the ADC search collections (live, read-only)."""
    hits: list[dict] = []
    client = client_for(appliance)
    low = term.lower()
    for logical in ADC_SEARCH_LOGICALS:
        try:
            rows, err = client.list_with_error(logical)
            if err:
                current_app.logger.info(
                    'search: %s %s device error: %s', appliance.name, logical, err)
                continue
            for item in rows or []:
                if low in str(item).lower():
                    hits.append({'endpoint': logical, 'item': item})
        except Exception as _exc:  # noqa: BLE001 — one dead collection never sinks the sweep
            current_app.logger.info(
                'search: %s %s failed: %s', appliance.name, logical, _exc)
    return hits


@bp.route('/')
@login_required
def index():
    appliances = visible_appliances().order_by(Appliance.name).all()
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
        appliances = visible_appliances().filter(Appliance.id.in_(appliance_ids)).all()
    else:
        appliances = visible_appliances().order_by(Appliance.name).all()

    search_results = []
    for appliance in appliances:
        appliance_hits = []
        if getattr(appliance, 'kind', '') == 'fortiadc':
            try:
                appliance_hits = _adc_hits(appliance, term)
            except Exception as exc:  # noqa: BLE001 — surface, don't 500
                appliance_hits = [{'error': str(exc)}]
            if appliance_hits:
                search_results.append({'appliance': appliance,
                                       'hits': appliance_hits})
            continue
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
                except Exception as _exc:
                    current_app.logger.info(
                        'search: %s %s failed: %s', appliance.name, endpoint, _exc)
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
