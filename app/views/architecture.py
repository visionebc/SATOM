import re
from collections import OrderedDict

from flask import (Blueprint, render_template, jsonify, url_for, request,
                   redirect, session)
from flask_login import login_required, current_user

from ..models import Appliance, visible_appliances, visible_appliance_or_404
from ..services import device_context
from ..services import user_settings_store as _ustore

bp = Blueprint('architecture', __name__, url_prefix='/architecture')


def _grouped(appliances):
    sorted_appliances = sorted(
        appliances,
        key=lambda a: (a.zone or 'zzz', a.line or 'zzz', a.department or 'zzz', a.name or ''),
    )
    groups = OrderedDict()
    for a in sorted_appliances:
        z = a.zone or '(no zone)'
        l = a.line or '(no line)'
        d = a.department or '(no department)'
        groups.setdefault(z, OrderedDict()).setdefault(l, OrderedDict()).setdefault(d, []).append(a)
    return groups


def _facets(appliances):
    zones, lines, depts = set(), set(), set()
    for a in appliances:
        if a.zone:
            zones.add(a.zone)
        if a.line:
            lines.add(a.line)
        if a.department:
            depts.add(a.department)
    return sorted(zones), sorted(lines), sorted(depts)


@bp.route('/')
@login_required
def index():
    appliances = visible_appliances().all()
    zones, lines, depts = _facets(appliances)
    try:
        saved = _ustore.architecture_filters(current_user.id)
    except Exception:
        saved = {}
    return render_template('architecture/index.html',
                           appliances=appliances,
                           total=len(appliances),
                           current=device_context.current_appliance(),
                           facet_zones=zones,
                           facet_lines=lines,
                           facet_depts=depts,
                           saved_filters=saved)


@bp.route('/picker')
@login_required
def picker():
    """Lightweight device-picker fragment for the banner switch modal."""
    appliances = visible_appliances().all()
    zones, lines, depts = _facets(appliances)
    try:
        saved = _ustore.architecture_filters(current_user.id)
    except Exception:
        saved = {}
    return render_template('architecture/_picker.html',
                           fleet_map=_grouped(appliances),
                           current=device_context.current_appliance(),
                           facet_zones=zones,
                           facet_lines=lines,
                           facet_depts=depts,
                           saved_filters=saved)


@bp.route('/select/<int:id>', methods=['POST'])
@login_required
def select(id):
    """Pick a device → make it the session context, then go to its Server Policy."""
    appl = visible_appliance_or_404(id)
    device_context.set_current(appl.id)
    nxt = request.form.get('next') or request.args.get('next')
    if (appl.kind or 'fortiweb') == 'fortiadc':
        # An ADC device belongs to the ADC ADOM — never land it on a
        # FortiWeb page (the product gate would bounce it anyway).
        if nxt and nxt.startswith('/adc'):
            return redirect(nxt)
        return redirect(url_for('adc.index'))
    if nxt and nxt.startswith('/'):
        return redirect(nxt)
    return redirect(url_for('workspace.index'))


@bp.route('/filters', methods=['POST'])
@login_required
def save_filters():
    """Persist this user's Fleet-map filters (JSON body or form)."""
    data = request.get_json(silent=True) or request.form.to_dict()
    try:
        _ustore.save_architecture_filters(current_user.id, data)
        return jsonify(ok=True)
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc)), 400


@bp.route('/device/<int:id>')
@login_required
def device_detail(id):
    """Read-only physical-inventory payload for the Fleet Map modal."""
    a = visible_appliance_or_404(id)
    data = a.inventory_view()
    data['detail_url'] = url_for('appliances.detail', id=a.id)
    data['datasheet_url'] = (
        url_for('appliances.datasheet', id=a.id) if a.datasheet_filename else None
    )
    return jsonify(data)


# --- DB-first topology feeds -------------------------------------------------
# The map NEVER touches an appliance: everything below reads the device cache
# (deep/config layers). Live REST here would hang the page against a
# license-locked or powered-off box (fw fleet trial licenses flap).

def _policy_names(appliance_id, layer):
    from ..extensions import db
    from ..models_cache import DeviceObject
    rows = (db.session.query(DeviceObject.mkey)
            .filter_by(appliance_id=appliance_id, logical_name='server_policy',
                       layer=layer, depth=0)
            .order_by(DeviceObject.mkey).all())
    return [r[0] for r in rows]


def _custom_service_ports(appliance_id):
    from ..extensions import db
    from ..models_cache import DeviceObject
    ports = {}
    rows = (db.session.query(DeviceObject)
            .filter_by(appliance_id=appliance_id, logical_name='services_custom',
                       depth=0).all())
    for r in rows:
        p = r.payload or {}
        try:
            ports[p.get('name')] = int(str(p.get('port', '')).strip().split('-')[0])
        except (TypeError, ValueError):
            continue
    return ports


def _service_port(name, svc_ports):
    if not name:
        return None
    if name in svc_ports:
        return svc_ports[name]
    upper = name.upper()
    if upper == 'HTTP':
        return 80
    if upper == 'HTTPS':
        return 443
    m = re.search(r'(\d+)\s*$', name)
    return int(m.group(1)) if m else None


@bp.route('/map-data')
@login_required
def map_data():
    """Whole-fleet service topology from the device cache (no box calls)."""
    from ..services import read_layer
    from ..services.hardware import hardware_map

    hw_map = hardware_map()
    devices = []
    for a in visible_appliances().order_by(Appliance.name).all():
        layer = 'deep'
        names = _policy_names(a.id, 'deep')
        if not names:
            layer = 'config'
            names = _policy_names(a.id, 'config')
        svc_ports = _custom_service_ports(a.id)

        policies = []
        for name in names:
            try:
                data, _cr, _meta = read_layer.policy_full_cached(a.id, name)
            except Exception:
                data = None
            if not data:
                continue
            pol = data.get('policy') or {}
            vips = []
            for v in data.get('vips', []) or []:
                vips.append({
                    'ip': v.get('effective_ip') or '',
                    'source': v.get('ip_source') or '',
                })
            pool = data.get('pool') or {}
            backends = [{
                'ip': b.get('ip') or '',
                'port': b.get('port'),
                'status': b.get('status') or '',
            } for b in (data.get('backends') or [])]
            policies.append({
                'name': name,
                'status': pol.get('status') or '',
                'mode': pol.get('deployment-mode') or '',
                'monitor': pol.get('monitor-mode') == 'enable',
                'ssl': pol.get('ssl') == 'enable',
                'http_service': pol.get('service') or '',
                'https_service': pol.get('https-service') or '',
                'port': _service_port(pol.get('service'), svc_ports),
                'https_port': _service_port(pol.get('https-service'), svc_ports),
                'vserver': pol.get('vserver') or '',
                'vips': vips,
                'pool': {
                    'name': pool.get('name') or pol.get('server-pool') or '',
                    'health': pool.get('health') or '',
                    'balance': pool.get('server-balance') or '',
                },
                'backends': backends,
                'wpp': (pol.get('web-protection-profile')
                        or (data.get('wpp') or {}).get('name') or ''),
            })

        meta = read_layer._layer_meta(a.id, layer=layer)
        devices.append({
            'id': a.id,
            'name': a.name,
            'host': a.host,
            'port': a.port,
            'kind': a.kind,
            'zone': a.zone or '',
            'line': a.line or '',
            'department': a.department or '',
            'firmware': getattr(a, 'firmware', None) or '',
            'model': getattr(a, 'model', None) or '',
            'hw': hw_map.get(a.id),
            'cached': bool(policies),
            'layer': layer if policies else '',
            'freshness': read_layer.freshness_label(meta) if policies else 'no local data',
            'policies': policies,
        })
    return jsonify({'devices': devices})


@bp.route('/data')
@login_required
def topology_data():
    """Legacy nodes/edges feed — kept for compatibility, now DB-first."""
    from ..services import read_layer

    nodes = []
    edges = []
    for a in visible_appliances().order_by(Appliance.name).all():
        names = _policy_names(a.id, 'deep') or _policy_names(a.id, 'config')
        cached = bool(names) or read_layer.has_any_cache(a.id)
        node = {
            'id': f'appliance_{a.id}', 'label': a.name, 'type': 'appliance',
            'kind': a.kind, 'host': a.host, 'zone': a.zone, 'line': a.line,
            'department': a.department,
            'policy_count': len(names) if names else None,
        }
        if not cached:
            node['offline'] = True
        nodes.append(node)
        for pid in names:
            nodes.append({'id': f'policy_{a.id}_{pid}', 'label': pid, 'type': 'policy'})
            edges.append({'source': f'appliance_{a.id}', 'target': f'policy_{a.id}_{pid}'})
    return jsonify({'nodes': nodes, 'edges': edges})


@bp.route('/policy/<int:appliance_id>/<path:name>')
@login_required
def policy_data(appliance_id, name):
    """Full cached detail of ONE server policy for the Fleet Map modal.

    DB-first like the rest of the map (never a live box call). Besides the raw
    payloads it returns a ``links`` map: a deep-link to the exact page where
    each element of the service chain is configured (policy form, vserver /
    pool / health / VIP / WPP / custom-service object editors).
    """
    from ..services import read_layer

    a = visible_appliance_or_404(appliance_id)
    data, cr_entries, meta = read_layer.policy_full_cached(a.id, name)
    if not data:
        return jsonify(ok=False, error='This policy is not in the device cache yet '
                                       '— run a sync or deep capture first.'), 404

    pol = data.get('policy') or {}
    pool = data.get('pool') or {}
    wpp_name = (pol.get('web-protection-profile')
                or (data.get('wpp') or {}).get('name') or '')

    def edit_link(collection, mkey, title):
        if not mkey:
            return None
        return url_for('objedit.edit', appliance_id=a.id, collection=collection,
                       mkey=mkey, title='%s · %s' % (title, mkey))

    svc_ports = _custom_service_ports(a.id)

    def service_link(svc):
        # only CUSTOM services are editable objects; predefined HTTP/HTTPS are not
        if svc and svc in svc_ports:
            return edit_link('server-policy/service.custom', svc, 'Custom Service')
        return None

    vip_links = {}
    for v in (data.get('vips') or []):
        nm = (v or {}).get('vip') or (v or {}).get('name')
        if nm and nm not in vip_links:
            vip_links[nm] = edit_link('system/vip', nm, 'VIP')

    cr_links = {}
    for e in (cr_entries or []):
        nm = (e or {}).get('content-routing-policy-name')
        if nm and nm not in cr_links:
            cr_links[nm] = edit_link('server-policy/http-content-routing-policy',
                                     nm, 'Content Routing')

    links = {
        'policy': url_for('workspace.policy_detail', appliance_id=a.id, name=name),
        'vserver': edit_link('server-policy/vserver', pol.get('vserver'),
                             'Virtual Server'),
        'pool': edit_link('server-policy/server-pool',
                          pool.get('name') or pol.get('server-pool'),
                          'Server Pool'),
        'health': edit_link('server-policy/health', pool.get('health'),
                            'Health Check'),
        'wpp': edit_link('waf/web-protection-profile.inline-protection',
                         wpp_name, 'Web Protection Profile'),
        'http_service': service_link(pol.get('service')),
        'https_service': service_link(pol.get('https-service')),
        'appliance': url_for('appliances.detail', id=a.id),
        'vips': vip_links,
        'content_routing': cr_links,
    }
    return jsonify(ok=True,
                   appliance={'id': a.id, 'name': a.name, 'host': a.host},
                   name=name,
                   freshness=read_layer.freshness_label(meta),
                   layer=(meta or {}).get('layer') or '',
                   data=data,
                   content_routing=cr_entries or [],
                   links=links)
