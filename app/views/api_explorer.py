from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..models import visible_appliances, visible_appliance_or_404
from ..clients.fortiweb import FortiWebClient
from ..services.audit import log_action
from . import _clicoverage, _discovery
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
        **_clicoverage.context(
            'fortiweb',
            block_endpoint='api_explorer.cli_coverage_block',
            capture_endpoint='api_explorer.cli_coverage_capture',
            live_endpoint='api_explorer.cli_coverage_live',
            page_endpoint='api_explorer.index',
            probe_endpoint='api_explorer.cli_coverage_probe',
            registry_save_endpoint='registry.save'),
        **_discovery.context(
            'fortiweb',
            run_endpoint='api_explorer.discovery_run',
            plan_endpoint='api_explorer.discovery_plan',
            register_endpoint='api_explorer.discovery_register',
            load_endpoint='api_explorer.discovery_load'),
    )


# ---------------------------------------------------------------------------
# Discovery run — the catalog's growth path (shared body in views/_discovery.py)
# ---------------------------------------------------------------------------

@bp.route('/discovery/plan', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def discovery_plan():
    return _discovery.plan_payload('fortiweb')


@bp.route('/discovery/run', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def discovery_run():
    return _discovery.run_payload('fortiweb')


@bp.route('/discovery/register', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def discovery_register():
    return _discovery.register_payload('fortiweb')


@bp.route('/discovery/load', methods=['POST'])
@login_required
@require_permission('appliances.apply')
def discovery_load():
    # The page to come back to is the one that MOUNTS the card, which since
    # 2026-09-16 is the API-versions page — not this hub, which now carries
    # only a pointer to it. Returning here left the operator watching a page
    # with no card while their sweep ran to completion elsewhere.
    return _discovery.load('fortiweb', 'registry.api_versions')


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


# ---------------------------------------------------------------------------
# CLI ↔ API coverage (shared body — see views/_clicoverage.py)
# ---------------------------------------------------------------------------
# The counts and the CLI paths render with the page; these three carry
# Permission.BACKUP because every one of them hands over device CONFIGURATION,
# and the config vault they read from is gated on exactly that permission.

@bp.route('/cli-coverage/block')
@login_required
@require_permission(Permission.BACKUP)
def cli_coverage_block():
    return _clicoverage.block_payload('fortiweb')


@bp.route('/cli-coverage/live', methods=['POST'])
@login_required
@require_permission(Permission.BACKUP)
def cli_coverage_live():
    return _clicoverage.live_payload('fortiweb')


@bp.route('/cli-coverage/capture', methods=['POST'])
@login_required
@require_permission(Permission.BACKUP)
def cli_coverage_capture():
    return _clicoverage.capture('fortiweb', 'api_explorer.index')


@bp.route('/cli-coverage/probe', methods=['POST'])
@login_required
def cli_coverage_probe():
    """Ask the device which candidate REST path exists for a CLI-only block.

    Deliberately NOT gated on Permission.BACKUP — see probe_payload: it returns
    a verdict and a row count, and the console on this same page already lets
    this user GET any path directly.
    """
    return _clicoverage.probe_payload('fortiweb')
