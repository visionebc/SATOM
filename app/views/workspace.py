from flask import Blueprint, render_template, jsonify
from flask_login import login_required
from ..models import Appliance
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient

bp = Blueprint('workspace', __name__, url_prefix='/workspace')


# Server-policy fields grouped like FortiWeb's own GUI (ported from the desktop
# app's policy_view._SECTIONS). (label, REST key, kind) — 'onoff' renders an
# enable/disable badge, 'text' a plain value. Only non-empty rows are shown.
POLICY_SECTIONS = [
    ("Network Configuration", [
        ("Status", "status", "onoff"),
        ("Deployment Mode", "deployment-mode", "text"),
        ("Protocol", "protocol", "text"),
        ("Virtual Server", "vserver", "text"),
        ("Server Pool", "server-pool", "text"),
        ("HTTP Service", "service", "text"),
        ("HTTPS Service", "https-service", "text"),
        ("HTTP/3 Service", "http3-service", "text"),
        ("Protected Hostnames", "allow-hosts", "text"),
        ("Client Real IP", "client-real-ip", "onoff"),
        ("IP/IP Range", "real-ip-addr", "text"),
        ("HTTP/2", "http2", "onoff"),
        ("Redirect HTTP to HTTPS", "http-to-https", "onoff"),
        ("Redirect Naked Domain", "redirect-naked-domain", "onoff"),
        ("Comments", "comment", "text"),
    ]),
    ("HTTPS / SSL", [
        ("SSL", "ssl", "onoff"),
        ("Multi-Certificate", "multi-certificate", "onoff"),
        ("Certificate Type", "certificate-type", "text"),
        ("Certificate", "certificate", "text"),
        ("Letsencrypt Certificate", "lets-certificate", "text"),
        ("SSL Client Verify", "ssl-client-verify", "text"),
        ("Enable SNI", "sni", "onoff"),
        ("SNI Policy", "sni-certificate", "text"),
        ("TLS 1.0", "tls-v10", "onoff"),
        ("TLS 1.1", "tls-v11", "onoff"),
        ("TLS 1.2", "tls-v12", "onoff"),
        ("TLS 1.3", "tls-v13", "onoff"),
        ("SSL Ciphers Group", "ssl-ciphers-group", "text"),
        ("SSL/TLS Encryption Level", "ssl-cipher", "text"),
    ]),
    ("Application Delivery", [
        ("Proxy Protocol", "proxy-protocol", "onoff"),
        ("Retry On", "retry-on", "onoff"),
        ("Web Cache", "web-cache", "onoff"),
    ]),
    ("Scripting", [
        ("Scripting", "scripting", "onoff"),
        ("Scripting List", "scripting-list", "text"),
    ]),
    ("Security Configuration", [
        ("Monitor Mode", "monitor-mode", "onoff"),
        ("Syn Cookie", "syncookie", "onoff"),
        ("Web Protection Profile", "web-protection-profile", "text"),
        ("Allow List", "allow-list", "text"),
        ("Replacement Message", "replacemsg", "text"),
        ("URL Case Sensitivity", "case-sensitive", "onoff"),
    ]),
    ("Log Config", [
        ("Enable Traffic Log", "tlog", "onoff"),
    ]),
]

# WPP sub-policy reference fields → GUI label (shown when the WPP names one).
WPP_SUBPOLICIES = [
    ("signature-rule", "Signatures"),
    ("http-protocol-parameter-restriction", "HTTP Protocol Constraints"),
    ("x-forwarded-for-rule", "X-Forwarded-For"),
    ("allow-method-policy", "Allowed Methods"),
    ("ip-list-policy", "IP List"),
    ("geo-block-list-policy", "Geo IP Block"),
    ("url-access-policy", "URL Access"),
    ("custom-access-policy", "Custom Access"),
    ("application-layer-dos-prevention", "DoS Prevention"),
    ("bot-mitigate-policy", "Bot Mitigation"),
    ("advanced-bot-protection", "Advanced Bot Protection"),
    ("syntax-based-attack-detection", "Syntax-based Detection"),
    ("http-header-security", "HTTP Header Security"),
    ("cors-protection-policy", "CORS Protection"),
    ("cookie-security-policy", "Cookie Security"),
    ("csrf-protection", "CSRF Protection"),
    ("hidden-fields-protection", "Hidden Fields"),
    ("parameter-validation-rule", "Parameter Validation"),
    ("file-upload-policy", "File Upload Restriction"),
    ("json-validation-policy", "JSON Validation"),
    ("xml-validation-policy", "XML Validation"),
    ("openapi-validation-policy", "OpenAPI Validation"),
    ("api-management-policy", "API Management"),
    ("url-rewrite-policy", "URL Rewriting"),
    ("user-tracking-policy", "User Tracking"),
    ("threat-score-profile", "Threat Score"),
]

_ON_VALUES = {"enable", "enabled", "on", "1", "true", "yes"}
_NOISE_SUFFIX = ("_val",)
_NOISE_PREFIX = ("q_", "sub_table", "sz_", "can_")
_NOISE_KEYS = {"id", "policy-id", "tags", "flag", "trigger", "host-for-deny",
               "url-for-deny", "hostname", "domainname"}


def _is_on(v):
    return str(v).strip().lower() in _ON_VALUES


def _render_sections(policy):
    """Build the non-empty, GUI-grouped rows for a policy (sections with no
    populated field are dropped, so the page shows real config, not a wall of —)."""
    out = []
    for title, fields in POLICY_SECTIONS:
        rows = []
        for label, key, kind in fields:
            v = policy.get(key)
            if v in (None, "", []):
                continue
            rows.append({"label": label, "kind": kind, "value": v,
                         "on": _is_on(v) if kind == "onoff" else None})
        if rows:
            out.append({"title": title, "rows": rows})
    return out


def _clean_policy(policy):
    """Drop FortiWeb's companion *_val enums, q_*/sz_* metadata and empties for the
    raw-config view, so it shows the real configuration not ~200 noise keys."""
    out = {}
    for k, v in (policy or {}).items():
        if (k in _NOISE_KEYS or k.endswith(_NOISE_SUFFIX) or k.startswith(_NOISE_PREFIX)):
            continue
        if v in (None, "", []):
            continue
        out[k] = v
    return out


@bp.route('/')
@login_required
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    return render_template('workspace/index.html', appliances=appliances)


@bp.route('/<int:appliance_id>')
@login_required
def appliance(appliance_id):
    appl = Appliance.query.get_or_404(appliance_id)
    policies = []
    error = None
    try:
        if appl.kind == 'fortiweb':
            client = FortiWebClient(appl)
            raw = client.list_server_policies()
            policies = raw.get('results', raw.get('data', []))
        elif appl.kind == 'fortiadc':
            client = FortiADCClient(appl)
            raw = client.list_virtual_servers()
            policies = raw.get('payload', [])
    except Exception as exc:
        error = str(exc)
    return render_template('workspace/policies.html', appliance=appl, policies=policies, error=error)


@bp.route('/<int:appliance_id>/policy/<path:name>')
@login_required
def policy_detail(appliance_id, name):
    appl = Appliance.query.get_or_404(appliance_id)
    data = {}
    error = None
    try:
        client = FortiWebClient(appl)
        data = client.policy_full(name)
    except Exception as exc:
        error = str(exc)
    policy = data.get('policy') or {}
    wpp = data.get('wpp') or {}
    wpp_bindings = [(lbl, wpp.get(k)) for k, lbl in WPP_SUBPOLICIES
                    if wpp.get(k) not in (None, "", [])]
    return render_template(
        'workspace/policy_detail.html',
        appliance=appl, policy_name=name, policy=policy,
        sections=_render_sections(policy),
        vserver=data.get('vserver') or {}, vips=data.get('vips') or [],
        pool=data.get('pool') or {}, backends=data.get('backends') or [],
        health=data.get('health') or {}, wpp=wpp, wpp_bindings=wpp_bindings,
        policy_clean=_clean_policy(policy), policy_on=_is_on(policy.get('status')),
        error=error,
    )


@bp.route('/<int:appliance_id>/browse/<path:endpoint_path>')
@login_required
def browse(appliance_id, endpoint_path):
    appl = Appliance.query.get_or_404(appliance_id)
    data = None
    error = None
    try:
        client = FortiWebClient(appl) if appl.kind == 'fortiweb' else FortiADCClient(appl)
        resp = client.api_call('GET', '/' + endpoint_path)
        data = resp.json()
    except Exception as exc:
        error = str(exc)
    return render_template('workspace/browse.html', appliance=appl, endpoint_path=endpoint_path,
                           data=data, error=error)
