from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('web_protection', __name__, url_prefix='/web-protection')

# Real FortiWeb 7.6 cmdb endpoints (verified against the live appliance).
EP_INLINE = '/api/v2.0/cmdb/waf/web-protection-profile.inline-protection'
EP_SIGNATURE = '/api/v2.0/cmdb/waf/signature'


def _results(resp):
    """Extract the object list from a FortiWeb cmdb response (``{"results": …}``)."""
    j = resp.json()
    if isinstance(j, dict):
        out = j.get('results', j.get('data', []))
        return out if isinstance(out, list) else ([out] if out else [])
    return j if isinstance(j, list) else []


@bp.route('/')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    return render_template('web_protection/index.html', appliances=appliances)


@bp.route('/<int:id>')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def overview(id):
    appliance = Appliance.query.get_or_404(id)
    wpp_profiles = []
    signatures = []
    error = None
    try:
        client = FortiWebClient(appliance)
        wpp_profiles = _results(client.api_call('GET', EP_INLINE))
        signatures = _results(client.api_call('GET', EP_SIGNATURE))
    except Exception as exc:
        error = str(exc)
    return render_template(
        'web_protection/overview.html',
        appliance=appliance,
        wpp_profiles=wpp_profiles,
        signatures=signatures,
        error=error,
    )


@bp.route('/<int:id>/wpp/<name>')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def wpp_detail(id, name):
    appliance = Appliance.query.get_or_404(id)
    wpp = None
    sub_policies = {}
    error = None
    try:
        client = FortiWebClient(appliance)
        result = _results(client.api_call('GET', f'{EP_INLINE}?mkey={name}'))
        wpp = result[0] if result else None
        if isinstance(wpp, dict):
            for key, endpoint in [('signature', EP_SIGNATURE)]:
                try:
                    sub_policies[key] = _results(client.api_call('GET', endpoint))
                except Exception:
                    sub_policies[key] = []
    except Exception as exc:
        error = str(exc)
    return render_template(
        'web_protection/wpp_detail.html',
        appliance=appliance,
        wpp_name=name,
        wpp=wpp,
        sub_policies=sub_policies,
        error=error,
    )
