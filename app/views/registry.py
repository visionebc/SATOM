from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('registry', __name__, url_prefix='/registry')

FORTIWEB_SECTIONS = [
    'System',
    'ServerObjects',
    'WebProtection',
    'Signature',
    'BotMitigation',
    'IPReputation',
    'DataLossPrevention',
    'NetworkConfiguration',
    'AuthUsers',
    'Log',
    'FortiView',
    'Policy',
    'Certificate',
    'Antivirus',
    'ContentRouting',
]

SECTION_ENDPOINTS = {
    'System': [
        {'name': 'Status', 'path': '/System/Status/Status', 'methods': ['GET']},
        {'name': 'Admin', 'path': '/System/Admin/Admin', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
        {'name': 'Interface', 'path': '/System/Network/Interface', 'methods': ['GET', 'PUT']},
        {'name': 'DNS', 'path': '/System/Network/DNS', 'methods': ['GET', 'PUT']},
        {'name': 'NTP', 'path': '/System/Time/NTPServerList', 'methods': ['GET', 'PUT']},
        {'name': 'Backup', 'path': '/System/Maintenance/Backup', 'methods': ['GET', 'POST']},
        {'name': 'Restore', 'path': '/System/Maintenance/Restore', 'methods': ['POST']},
    ],
    'ServerObjects': [
        {'name': 'Server Policy', 'path': '/ServerObjects/Server/ServerPolicy', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
        {'name': 'Virtual Server', 'path': '/ServerObjects/Server/VirtualServer', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
        {'name': 'Server Pool', 'path': '/ServerObjects/Server/ServerPool', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
        {'name': 'Content Routing', 'path': '/ServerObjects/Server/ContentRouting', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
        {'name': 'Health Check', 'path': '/ServerObjects/Server/HealthCheck', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
    ],
    'WebProtection': [
        {'name': 'Inline Protection Profile', 'path': '/WebProtection/Profile/InlineProtection', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
        {'name': 'Exception URL', 'path': '/WebProtection/Exception/ExceptionURL', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
        {'name': 'Allowed Method Exception', 'path': '/WebProtection/Exception/AllowedMethodException', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
    ],
    'Signature': [
        {'name': 'Main Signatures', 'path': '/WebProtection/Signature/MainSignatures', 'methods': ['GET', 'PUT']},
        {'name': 'Custom Signatures', 'path': '/WebProtection/Signature/CustomSignatures', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
    ],
    'BotMitigation': [
        {'name': 'Bot Detection Policy', 'path': '/WebProtection/BotMitigation/BotDetectionPolicy', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
    ],
    'IPReputation': [
        {'name': 'IP Reputation Policy', 'path': '/WebProtection/IPReputation/IPReputationPolicy', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
    ],
    'DataLossPrevention': [
        {'name': 'DLP Policy', 'path': '/WebProtection/DataLossPrevention/DataLossPreventionPolicy', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
    ],
    'NetworkConfiguration': [
        {'name': 'Interface', 'path': '/System/Network/Interface', 'methods': ['GET', 'PUT']},
        {'name': 'Route', 'path': '/System/Network/Route', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
    ],
    'AuthUsers': [
        {'name': 'Local Users', 'path': '/System/Admin/Admin', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
        {'name': 'LDAP Server', 'path': '/System/Admin/LDAPServer', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
    ],
    'Log': [
        {'name': 'Attack Event Log', 'path': '/Log/LogReport/AttackEventLog', 'methods': ['GET']},
        {'name': 'Traffic Log', 'path': '/Log/LogReport/TrafficLog', 'methods': ['GET']},
        {'name': 'Event Log', 'path': '/Log/LogReport/EventLog', 'methods': ['GET']},
    ],
    'FortiView': [
        {'name': 'Session History', 'path': '/FortiView/FortiView/SessionHistory', 'methods': ['GET']},
        {'name': 'Top Sources', 'path': '/FortiView/FortiView/TopSources', 'methods': ['GET']},
        {'name': 'Top Attacks', 'path': '/FortiView/FortiView/TopAttacks', 'methods': ['GET']},
    ],
    'Policy': [
        {'name': 'Server Policy', 'path': '/ServerObjects/Server/ServerPolicy', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
    ],
    'Certificate': [
        {'name': 'Local Certificate', 'path': '/System/Certificate/LocalCertificate', 'methods': ['GET', 'POST', 'DELETE']},
        {'name': 'CA Certificate', 'path': '/System/Certificate/CACertificate', 'methods': ['GET', 'POST', 'DELETE']},
    ],
    'Antivirus': [
        {'name': 'Antivirus Policy', 'path': '/WebProtection/AntiVirus/AntiVirusPolicy', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
    ],
    'ContentRouting': [
        {'name': 'Content Routing', 'path': '/ServerObjects/Server/ContentRouting', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
        {'name': 'Content Routing Policy', 'path': '/ServerObjects/Server/ContentRoutingPolicy', 'methods': ['GET', 'POST', 'PUT', 'DELETE']},
    ],
}


@bp.route('/')
@login_required
def index():
    return render_template(
        'registry/index.html',
        sections=FORTIWEB_SECTIONS,
        section_endpoints=SECTION_ENDPOINTS,
    )


@bp.route('/<section>')
@login_required
def section_detail(section):
    if section not in FORTIWEB_SECTIONS:
        abort(404)
    endpoints = SECTION_ENDPOINTS.get(section, [])
    return render_template(
        'registry/section.html',
        section=section,
        endpoints=endpoints,
        sections=FORTIWEB_SECTIONS,
    )


@bp.route('/search')
@login_required
def search():
    term = request.args.get('q', '').strip().lower()
    results = []
    if term:
        for section, endpoints in SECTION_ENDPOINTS.items():
            for ep in endpoints:
                if term in ep['name'].lower() or term in ep['path'].lower():
                    results.append({'section': section, 'endpoint': ep})
    return render_template(
        'registry/search.html',
        term=term,
        results=results,
        sections=FORTIWEB_SECTIONS,
    )
