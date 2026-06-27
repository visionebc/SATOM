import ipaddress

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services import settings_store as store
from ..services.audit import log_action

bp = Blueprint('architecture', __name__, url_prefix='/architecture')


@bp.route('/')
@login_required
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    return render_template('architecture/index.html', appliances=appliances)


@bp.route('/data')
@login_required
def topology_data():
    appliances = Appliance.query.order_by(Appliance.name).all()
    nodes = []
    edges = []
    for appliance in appliances:
        try:
            client = FortiWebClient(appliance)
            policies = client.list_server_policies() or []
            appliance_node = {
                'id': f'appliance_{appliance.id}',
                'label': appliance.name,
                'type': 'appliance',
                'kind': appliance.kind,
                'host': appliance.host,
            }
            nodes.append(appliance_node)
            for policy in policies:
                policy_name = policy.get('name') or policy.get('id', 'unknown')
                policy_node_id = f'policy_{appliance.id}_{policy_name}'
                nodes.append({
                    'id': policy_node_id,
                    'label': policy_name,
                    'type': 'policy',
                    'appliance_id': appliance.id,
                })
                edges.append({
                    'source': f'appliance_{appliance.id}',
                    'target': policy_node_id,
                })
        except Exception:
            nodes.append({
                'id': f'appliance_{appliance.id}',
                'label': appliance.name,
                'type': 'appliance',
                'kind': appliance.kind,
                'host': appliance.host,
                'offline': True,
            })
    return jsonify({'nodes': nodes, 'edges': edges})


# ---------------------------------------------------------------------------
# Device Classification — zones / lines / departments catalogs.
# Ported from the desktop Settings → Architecture group (settings_page.py);
# the catalogs drive the appliance Zone/Line/Department dropdowns. Admin-only,
# exactly like the desktop config console. Persistence reuses settings_store.
# ---------------------------------------------------------------------------
@bp.route('/classification')
@login_required
@require_permission(Permission.USER_MANAGE)
def classification():
    return render_template(
        'architecture/classification.html',
        classification=store.all_classification(),
    )


@bp.route('/classification/save', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def classification_save():
    counts = {}
    for kind in store.CLASSIFICATION_KINDS:
        raw = request.form.get(kind, '')
        values = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        store.save_classification(kind, values)
        counts[kind] = len(store.classification(kind))
    log_action('architecture.classification',
               detail=f"{counts.get('zones', 0)} zones, {counts.get('lines', 0)} lines, "
                      f"{counts.get('departments', 0)} departments")
    flash('Classification catalogs saved.', 'success')
    return redirect(url_for('architecture.classification'))


# ---------------------------------------------------------------------------
# Network Segments — named back-end networks (CIDR/interface/gateway) scoped to
# a classification value. Ported from the same desktop Architecture group.
# ---------------------------------------------------------------------------
@bp.route('/segments')
@login_required
@require_permission(Permission.USER_MANAGE)
def segments():
    return render_template(
        'architecture/segments.html',
        classification=store.all_classification(),
        segments=store.segments(),
    )


@bp.route('/segments/save', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def segments_save():
    names = request.form.getlist('seg_name[]')
    rows, bad_cidr = [], []
    for i, name in enumerate(names):
        def col(field):
            vals = request.form.getlist(f'seg_{field}[]')
            return vals[i] if i < len(vals) else ''
        cidr = (col('cidr') or '').strip()
        if not (name or '').strip() and not cidr:
            continue
        if cidr:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                bad_cidr.append(cidr)
                continue
        rows.append({
            'name': name, 'zone': col('zone'), 'line': col('line'),
            'department': col('department'), 'cidr': cidr,
            'interface': col('interface') or 'port1', 'gateway': col('gateway'),
            'note': col('note'),
        })
    store.save_segments(rows)
    log_action('architecture.segments', detail=f'{len(rows)} segment(s)')
    if bad_cidr:
        flash(f"Skipped invalid CIDR(s): {', '.join(bad_cidr)}", 'warning')
    flash(f'{len(rows)} network segment(s) saved.', 'success')
    return redirect(url_for('architecture.segments'))
