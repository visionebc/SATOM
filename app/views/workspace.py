from urllib.parse import quote

from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required
from ..models import Appliance
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.fortiweb_field_schema import (
    build_groups, descriptor, is_noise, is_on, REF_ENDPOINTS, ALL_REF_ENDPOINTS,
    CREATE_FIELDS,
)
from ..services import policy_form
from ..services.fortiweb_ops import FortiWebOps

bp = Blueprint('workspace', __name__, url_prefix='/workspace')

# Full cmdb endpoints the editable workspace reads/writes (allow-listed for
# save). FortiWeb writes go to the REST cmdb tree and the body must be wrapped
# in {"data": {...}}; child sub-tables are addressed with &sub_mkey=<id>.
EP_POLICY = '/api/v2.0/cmdb/server-policy/policy'
EP_POOL = '/api/v2.0/cmdb/server-policy/server-pool'
EP_WPP = '/api/v2.0/cmdb/waf/web-protection-profile.inline-protection'
EP_VIPLIST = '/api/v2.0/cmdb/server-policy/vserver/vip-list'
EP_PSERVER = '/api/v2.0/cmdb/server-policy/server-pool/pserver-list'
_SAVE_EPS = {EP_POLICY, EP_POOL, EP_WPP, EP_VIPLIST, EP_PSERVER}
_CHILD_EPS = {EP_VIPLIST, EP_PSERVER}

# Referenced objects are editable in place — the ✎ on a dropdown opens the
# selected object. Allow-list their full cmdb paths through the same audited save.
_REF_COLLECTIONS = {c for ep in REF_ENDPOINTS.values() for c in ep.split('|')}
_REF_FULL_EPS = {'/api/v2.0/cmdb/' + c for c in _REF_COLLECTIONS}
_SAVE_EPS = _SAVE_EPS | _REF_FULL_EPS

# Keys pulled out of the policy field groups into their own card: the operator
# picks the profile, its contents are NOT edited from the policy form.
_HOIST_KEYS = {'web-protection-profile'}

_NOISE_SUFFIX = ("_val",)
_NOISE_PREFIX = ("q_", "sub_table", "sz_", "can_")
_NOISE_KEYS = {"id", "policy-id", "tags", "flag", "trigger", "host-for-deny",
               "url-for-deny", "hostname", "domainname"}


def _clean_policy(policy):
    """Trim FortiWeb's *_val companions / q_* metadata for the raw-JSON view."""
    out = {}
    for k, v in (policy or {}).items():
        if (k in _NOISE_KEYS or k.endswith(_NOISE_SUFFIX) or k.startswith(_NOISE_PREFIX)):
            continue
        if v in (None, "", []):
            continue
        out[k] = v
    return out


def _filter_groups(groups, drop_keys):
    """Drop hoisted keys (rendered in their own card) from grouped fields."""
    out = []
    for g in groups:
        fields = [f for f in g['fields'] if f['key'] not in drop_keys]
        if fields:
            out.append({'title': g['title'], 'fields': fields})
    return out


@bp.route('/')
@login_required
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    from flask import redirect as _redir, url_for as _ufor
    from ..services import device_context as _dc
    _cur = _dc.current_appliance()
    if _cur is None:
        return _redir(_ufor('architecture.index'))
    return _redir(_ufor('workspace.appliance', appliance_id=_cur.id))


@bp.route('/<int:appliance_id>')
@login_required
def appliance(appliance_id):
    appl = Appliance.query.get_or_404(appliance_id)
    policies = []
    error = None
    meta = {}
    try:
        if appl.kind == 'fortiweb':
            # DB-first: serve the local source of truth; the box is touched only
            # on an explicit Refresh (see workspace.refresh). Empty cache => the
            # badge prompts a refresh rather than auto-hitting the device.
            from ..services import read_layer
            policies, meta = read_layer.read_policies(appl)
        elif appl.kind == 'fortiadc':
            client = FortiADCClient(appl)
            raw = client.list_virtual_servers()
            policies = raw.get('payload', [])
    except Exception as exc:
        error = str(exc)
    from ..services import read_layer as _rl
    return render_template('workspace/policies.html', appliance=appl,
                           policies=policies, error=error, cache_meta=meta,
                           cache_freshness=_rl.freshness_label(meta) if appl.kind == 'fortiweb' else '')


@bp.route('/<int:appliance_id>/refresh', methods=['POST'])
@login_required
def refresh(appliance_id):
    """Pull live config from the device into the local source of truth (cache +
    JSON backup), then return to the Server Policy list. DB-first reads serve
    everything else; this is the explicit ⟳ the user controls."""
    from flask import redirect, url_for, flash
    from flask_login import current_user
    appl = Appliance.query.get_or_404(appliance_id)
    try:
        if appl.kind == 'fortiweb':
            from ..services import device_sync
            run = device_sync.sync_device(
                appl, publish=False,
                user_label=getattr(current_user, 'username', None),
                trigger='manual')
            flash(f"Refreshed from {appl.name}: {run.detail}",
                  "success" if run.status == 'ok' else "danger")
        else:
            flash("Refresh is FortiWeb-only for now.", "warning")
    except Exception as exc:  # noqa: BLE001
        flash(f"Refresh failed: {exc}", "danger")
    return redirect(url_for('workspace.appliance', appliance_id=appliance_id))


EP_CRLIST = '/api/v2.0/cmdb/server-policy/policy/http-content-routing-list'
EP_CRPOLICY = '/api/v2.0/cmdb/server-policy/http-content-routing-policy'
_SAVE_EPS = _SAVE_EPS | {EP_CRLIST, EP_CRPOLICY}
_CHILD_EPS = _CHILD_EPS | {EP_CRLIST}


@bp.route('/<int:appliance_id>/policy/<path:name>')
@login_required
def policy_detail(appliance_id, name):
    appl = Appliance.query.get_or_404(appliance_id)
    data = {}
    cr_entries = []
    error = None
    try:
        client = FortiWebClient(appl)
        data = client.policy_full(name)
        # Content-routing bindings (a by-parent sub-table of the policy, scoped
        # ?mkey=<policy>) — fetched regardless of mode so the card is ready if the
        # operator switches Deployment Mode to HTTP Content Routing in the form.
        cr_entries = client._safe_list(
            '%s?mkey=%s' % (EP_CRLIST, quote(name, safe='')))
    except Exception as exc:
        error = str(exc)
    policy = data.get('policy') or {}
    pool = data.get('pool') or {}
    wpp_sel = policy.get('web-protection-profile') or ''
    return render_template(
        'workspace/policy_detail.html',
        appliance=appl, policy_name=name, policy=policy,
        policy_on=is_on(policy.get('status')),
        deploy_mode=policy.get('deployment-mode') or '',
        vserver_name=policy.get('vserver') or '', vips=data.get('vips') or [],
        pool_name=policy.get('server-pool') or '', pool=pool, backends=data.get('backends') or [],
        wpp_name=wpp_sel,
        # GUI-faithful, ordered, conditional-visibility sections (the desktop form).
        policy_sections=policy_form.build_policy_sections(policy),
        pool_groups=build_groups('pool', pool),
        cr_entries=cr_entries,
        policy_clean=_clean_policy(policy),
        create_fields=CREATE_FIELDS,
        eps={'policy': EP_POLICY, 'pool': EP_POOL, 'wpp': EP_WPP,
             'viplist': EP_VIPLIST, 'pserver': EP_PSERVER,
             'crlist': EP_CRLIST, 'crpolicy': EP_CRPOLICY},
        error=error,
    )


@bp.route('/<int:appliance_id>/cmdb-options')
@login_required
def cmdb_options(appliance_id):
    """Lazy options for a reference <select> — names of configured objects in
    the given cmdb collection. Allow-listed to the endpoints our schema declares
    (so this can't be used to read arbitrary cmdb paths)."""
    appl = Appliance.query.get_or_404(appliance_id)
    endpoint = request.args.get('endpoint', '')
    if endpoint not in ALL_REF_ENDPOINTS:
        return jsonify(error='endpoint not allowed', names=[]), 400
    try:
        return jsonify(names=FortiWebClient(appl).cmdb_names(endpoint))
    except Exception as exc:
        return jsonify(error=str(exc), names=[])


@bp.route('/<int:appliance_id>/ref-object')
@login_required
def ref_object(appliance_id):
    """Load the currently-selected referenced object so the ✎ button can edit it
    in place (mirrors FortiWeb's inline edit pencil). Returns a rendered field
    form scoped to the object's own cmdb collection."""
    appl = Appliance.query.get_or_404(appliance_id)
    coll = request.args.get('endpoint', '')
    name = request.args.get('name', '')
    if coll not in _REF_COLLECTIONS:
        return jsonify(ok=False, error='endpoint not allowed', html=''), 400
    if not name:
        return jsonify(ok=False, error='Select an object first', html='')
    try:
        obj = FortiWebClient(appl)._safe_one(
            '/api/v2.0/cmdb/%s?mkey=%s' % (coll, quote(name, safe='')))
    except Exception as exc:
        return jsonify(ok=False, error=str(exc), html='')
    if not obj:
        return jsonify(ok=False, error='Object not found on the device', html='')
    html = render_template('workspace/_ref_object.html',
                           groups=build_groups('ref', obj),
                           endpoint='/api/v2.0/cmdb/' + coll, mkey=name)
    return jsonify(ok=True, name=name, html=html)


@bp.route('/<int:appliance_id>/save', methods=['POST'])
@login_required
def save(appliance_id):
    """Apply a minimal-diff change to one object. dry_run (default) previews the
    exact PUT body without touching the device; apply=true writes it through
    FortiWebOps (before/after snapshot + ChangeHistory + audit)."""
    appl = Appliance.query.get_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    endpoint = body.get('endpoint', '')
    mkey = body.get('mkey', '')
    fields = body.get('fields') or {}
    child_id = body.get('child_id')
    do_apply = bool(body.get('apply'))
    if endpoint not in _SAVE_EPS:
        return jsonify(ok=False, error='endpoint not allowed'), 400
    if not isinstance(fields, dict) or not fields:
        return jsonify(ok=False, error='no changes to save'), 400

    # child sub-table rows (VIP, back-end server) are keyed by &sub_mkey=<id>;
    # the id stays out of the body. Top-level objects key on ?mkey=<name>.
    ep = endpoint
    if endpoint in _CHILD_EPS and child_id not in (None, ''):
        ep = '%s%ssub_mkey=%s' % (endpoint, '&' if '?' in endpoint else '?', child_id)
    payload = {'data': dict(fields)}   # FortiWeb cmdb writes are {"data": {...}}

    res = FortiWebOps(appl).update(ep, mkey, payload, dry_run=not do_apply)
    return jsonify(
        ok=res.ok, dry_run=res.get('dry_run'),
        request=res.get('request'), error=res.get('error', ''),
    )


@bp.route('/<int:appliance_id>/create-ref', methods=['POST'])
@login_required
def create_ref(appliance_id):
    """Create-new for a reference field (mirrors the FortiWeb dropdown '+').
    Optionally clones an existing object's fields under a new name — used for
    spinning up a Web Protection Profile from one of the inline templates."""
    appl = Appliance.query.get_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    endpoint = body.get('endpoint', '')
    name = (body.get('name') or '').strip()
    clone_from = (body.get('clone_from') or '').strip()
    extra = body.get('fields') or {}
    do_apply = bool(body.get('apply'))
    if endpoint not in ALL_REF_ENDPOINTS:
        return jsonify(ok=False, error='endpoint not allowed'), 400
    if not name:
        return jsonify(ok=False, error='name required'), 400
    ep = endpoint.split('|')[0]                 # create in the primary collection
    client = FortiWebClient(appl)
    payload = {'name': name}
    if clone_from:
        src = client._safe_one('/api/v2.0/cmdb/%s?mkey=%s' % (ep, quote(clone_from, safe='')))
        for k, v in (src or {}).items():
            if k == 'name' or is_noise(k):
                continue
            payload[k] = v
    # Up-front fields the create modal collected (VIP IP/interface, Service port…),
    # restricted to the keys CREATE_FIELDS declares for this collection so the
    # form can't post arbitrary keys.
    allowed = {f['key'] for f in CREATE_FIELDS.get(ep, [])}
    if isinstance(extra, dict):
        for k, v in extra.items():
            if k in allowed and v not in (None, '', []):
                payload[k] = v
    res = FortiWebOps(appl).create('/api/v2.0/cmdb/' + ep, {'data': payload}, dry_run=not do_apply)
    return jsonify(ok=res.ok, dry_run=res.get('dry_run'),
                   request=res.get('request'), error=res.get('error', ''))


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


# ─────────────────────────── CREATE Server Policy ────────────────────────────
# Schema-driven create: the form renders the COMPLETE live-validated field set
# (policy 121 / pool 17 / vserver+VIP / pserver), grouped like the GUI. Build
# order on apply mirrors FortiWeb's dependency graph: vserver → vip-list →
# server-pool → pserver-list → policy (binds vserver + pool). Preview (dry_run)
# shows the exact POST bodies; apply=true writes each through audited create.
from ..services.fortiweb_field_schema import build_create_groups, create_skeleton_keys

_CREATE_EPS = {
    'policy':  EP_POLICY,
    'vserver': '/api/v2.0/cmdb/server-policy/vserver',
    'vip':     EP_VIPLIST,
    'pool':    EP_POOL,
    'pserver': EP_PSERVER,
}


@bp.route('/<int:appliance_id>/new-policy')
@login_required
def new_policy(appliance_id):
    appl = Appliance.query.get_or_404(appliance_id)
    return render_template(
        'workspace/policy_new.html',
        appliance=appl,
        policy_groups=_filter_groups(build_create_groups('policy'), _HOIST_KEYS),
        pool_groups=build_create_groups('pool'),
        vip_fields=[f for g in build_create_groups('vip') for f in g['fields']],
        pserver_keys=[k for k in create_skeleton_keys('pserver') if k != 'name'],
        wpp_field=descriptor('policy', 'web-protection-profile', '', {}),
        eps=_CREATE_EPS,
    )


def _clean_create_fields(fields):
    """Drop blanks and noise from a submitted create object."""
    out = {}
    for k, v in (fields or {}).items():
        if k == '' or is_noise(k):
            continue
        if v in (None, '', []):
            continue
        out[k] = v
    return out


@bp.route('/<int:appliance_id>/create-policy', methods=['POST'])
@login_required
def create_policy(appliance_id):
    """Create a Server Policy and its objects in dependency order. dry_run
    (default) returns the exact POST bodies without touching the device."""
    appl = Appliance.query.get_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    do_apply = bool(body.get('apply'))
    ops = FortiWebOps(appl)

    policy = dict(body.get('policy') or {})
    pname = (policy.get('name') or '').strip()
    if not pname:
        return jsonify(ok=False, error='Policy name is required'), 400
    vserver_name = (body.get('vserver_name') or '').strip()
    pool_name = (body.get('pool_name') or '').strip()
    vips = body.get('vips') or []
    pool = dict(body.get('pool') or {})
    pservers = body.get('pservers') or []

    steps = []   # ordered (label, endpoint, payload, child_of)

    if vserver_name:
        steps.append(('Virtual Server', _CREATE_EPS['vserver'], {'name': vserver_name}, None))
        for i, v in enumerate(vips):
            vf = _clean_create_fields(v)
            if vf:
                steps.append(('VIP %d' % (i + 1), _CREATE_EPS['vip'], vf, vserver_name))
        policy['vserver'] = vserver_name
    if pool_name:
        pf = _clean_create_fields(pool)
        pf['name'] = pool_name
        steps.append(('Server Pool', _CREATE_EPS['pool'], pf, None))
        for i, ps in enumerate(pservers):
            pf2 = _clean_create_fields(ps)
            if pf2:
                steps.append(('Pool member %d' % (i + 1), _CREATE_EPS['pserver'], pf2, pool_name))
        policy['server-pool'] = pool_name
    steps.append(('Server Policy', _CREATE_EPS['policy'], _clean_create_fields(policy) | {'name': pname}, None))

    results = []
    for label, ep, payload, child_of in steps:
        full_ep = ep
        if ep in _CHILD_EPS and child_of:
            full_ep = '%s%smkey=%s' % (ep, '&' if '?' in ep else '?', quote(child_of, safe=''))
        if not do_apply:
            results.append({'label': label, 'endpoint': full_ep,
                            'body': {'data': payload}, 'dry_run': True})
            continue
        res = ops.create(full_ep, {'data': payload}, dry_run=False)
        results.append({'label': label, 'endpoint': full_ep, 'ok': res.ok,
                        'error': res.get('error', ''), 'request': res.get('request')})
        if not res.ok:
            return jsonify(ok=False, applied=results,
                           error='%s failed: %s' % (label, res.get('error', ''))), 200
    return jsonify(ok=True, dry_run=not do_apply, steps=results)
