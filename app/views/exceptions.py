from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('exceptions', __name__, url_prefix='/exceptions')


def _results(resp):
    """Extract the object list from a FortiWeb cmdb response.

    FortiWeb 7.6 wraps cmdb GET payloads as ``{"results": [...]}`` (some paths
    use ``"data"``). Returns [] for error envelopes so the view never iterates a
    raw Response object.
    """
    j = resp.json()
    if isinstance(j, dict):
        out = j.get('results', j.get('data', []))
        return out if isinstance(out, list) else ([out] if out else [])
    return j if isinstance(j, list) else []


@bp.route('/')
@login_required
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    return render_template('exceptions/index.html', appliances=appliances)


@bp.route('/<int:id>')
@login_required
def list_exceptions(id):
    appliance = Appliance.query.get_or_404(id)
    exceptions = []
    error = None
    try:
        client = FortiWebClient(appliance)
        exceptions = _results(client.api_call('GET', '/api/v2.0/cmdb/waf/url-access.url-access-rule'))
    except Exception as exc:
        error = str(exc)
    return render_template(
        'exceptions/list.html',
        appliance=appliance,
        exceptions=exceptions,
        error=error,
    )
