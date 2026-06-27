from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('web_protection', __name__, url_prefix='/web-protection')


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
        wpp_profiles = client.api_call('GET', '/WebProtection/Profile/InlineProtection') or []
        signatures = client.api_call('GET', '/WebProtection/Signature/MainSignatures') or []
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
        wpp = client.api_call('GET', f'/WebProtection/Profile/InlineProtection/{name}')
        if wpp:
            sub_policy_keys = [
                ('signature', '/WebProtection/Signature/MainSignatures'),
                ('bot_detection', '/WebProtection/BotMitigation/BotDetectionPolicy'),
                ('ip_reputation', '/WebProtection/IPReputation/IPReputationPolicy'),
                ('data_loss', '/WebProtection/DataLossPrevention/DataLossPreventionPolicy'),
            ]
            for key, endpoint in sub_policy_keys:
                try:
                    sub_policies[key] = client.api_call('GET', endpoint) or []
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
