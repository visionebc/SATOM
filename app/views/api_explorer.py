from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..models import visible_appliances, visible_appliance_or_404
from ..clients.fortiweb import FortiWebClient
from ..services.audit import log_action
from ..registry import loader, tree
# The catalog editor (New / Edit / Disable) lives on the Registry blueprint and
# writes through registry.save / registry.toggle. The API-Registry Explorer
# reuses that SAME context so its API-Menu tree is editable in place — one page,
# no duplicated write path (see registry._edit_context).
from .registry import _edit_context

bp = Blueprint('api_explorer', __name__, url_prefix='/api-explorer')

WRITE_METHODS = {'POST', 'PUT', 'DELETE', 'PATCH'}


@bp.route('/')
@login_required
def index():
    appliances = visible_appliances().order_by(Appliance.name).all()
    # Registry-backed section > endpoint tree for the left-hand "API Menu"
    # sidebar. Built from the same loader the Endpoint Registry uses; when the
    # user has registry_edit, _edit_context() adds the per-endpoint DB rows so
    # each leaf grows Edit/Disable affordances (the Registry catalog, fused in).
    api_tree = tree.build_category_tree(loader.get_all_endpoints())
    return render_template(
        'api_explorer/index.html',
        appliances=appliances,
        api_tree=api_tree,
        can_write=current_user.can('registry.execute_write'),
        **_edit_context(),
    )


@bp.route('/execute', methods=['POST'])
@login_required
def execute():
    appliance_id = request.form.get('appliance_id', type=int)
    endpoint = request.form.get('endpoint', '').strip()
    method = request.form.get('method', 'GET').upper()
    body_raw = request.form.get('body', '').strip()

    if not appliance_id or not endpoint:
        return jsonify({'ok': False, 'error': 'Appliance and endpoint are required.'})

    if method in WRITE_METHODS and not current_user.can('registry.execute_write'):
        return jsonify({'ok': False, 'error': 'The "Execute write API calls" permission is required for non-GET methods.'})

    appliance = visible_appliance_or_404(appliance_id)

    body = None
    if body_raw:
        import json
        try:
            body = json.loads(body_raw)
        except ValueError as exc:
            return jsonify({'ok': False, 'error': f'Invalid JSON body: {exc}'})

    try:
        client = FortiWebClient(appliance)
        resp = client.api_call(method, endpoint, body)
        log_action('api_explorer.execute', target=appliance.name,
                   extra={'method': method, 'endpoint': endpoint})
        try:
            result = resp.json()
        except Exception:
            result = resp.text
        return jsonify({'ok': True, 'status': resp.status_code, 'result': result})
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)})
