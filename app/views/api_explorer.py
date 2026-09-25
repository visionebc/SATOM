import json
import logging

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from sqlalchemy import select
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..models import visible_appliances, visible_appliance_or_404
from ..clients import client_for
from ..services.audit import log_action
from ..services import api_library as apilib
from . import _clicoverage, _discovery
from ..registry import loader, tree
# The catalog editor (New / Edit / Disable) lives on the Registry blueprint and
# writes through registry.save / registry.toggle. The API-Registry Explorer
# reuses that SAME context so its API-Menu tree is editable in place — one page,
# no duplicated write path (see registry._edit_context).
from .registry import _edit_context

bp = Blueprint('api_explorer', __name__, url_prefix='/api-explorer')

log = logging.getLogger(__name__)

WRITE_METHODS = {'POST', 'PUT', 'DELETE', 'PATCH'}


# ---------------------------------------------------------------------------
# Firmware awareness — what the API library knows about the selected build
# ---------------------------------------------------------------------------
# The tree used to be keyed only by the API generation (v2.0), so 7.6.8 and
# 8.0.5 looked identical and execute() sent anything anywhere. Every answer
# below comes from services.api_library for the appliance's EXACT build; the
# library's own rule applies here too: no evidence is "unknown", never
# "served", and "absent" needs a real verdict for that build.

SERVED, ABSENT, UNKNOWN = 'served', 'absent', 'unknown'

#: Build statuses from resolve_appliance() for which no real box was measured.
#: Only these offer "Harvest this appliance now".
_UNMEASURED_STATUSES = ('unmeasured', 'vendor_only', 'unknown_firmware')

# Same order as the library's verdict merge: ok > absent > error.
_VERDICT_RANK = {apilib.VERDICT_OK: 3, apilib.VERDICT_ABSENT: 2, apilib.VERDICT_ERROR: 1}


def _iso(dt) -> str:
    return dt.isoformat(timespec='seconds') if dt else ''


def _norm_path(path) -> str:
    """A path as typed or picked -> the form library URNs are compared in.

    Query string (``?mkey=``) and slashes at either end are not part of the
    endpoint's identity; case never is on these appliances.
    """
    p = str(path or '').split('#', 1)[0].split('?', 1)[0]
    return p.strip().strip('/').lower()


def _state_of(verdict) -> str:
    # 'error' only means the build was asked and did not answer: not a "no".
    return {apilib.VERDICT_OK: SERVED, apilib.VERDICT_ABSENT: ABSENT}.get(verdict, UNKNOWN)


def _library_view(appliance) -> dict:
    """Resolve ``appliance`` to a build and index what that build serves.

    One resolve + one endpoints_at() per call (a handful of SQL statements), so
    the per-request cost does not grow with the tree.
    """
    res = apilib.resolve_appliance(appliance)
    eps = {}
    if res.get('version') and res.get('product'):
        eps = apilib.endpoints_at(res['product'], res['version'])
    by_urn: dict = {}
    for name, e in eps.items():
        u = _norm_path(e.get('urn'))
        if u:
            by_urn.setdefault(u, []).append(name)
    return {'resolved': res, 'endpoints': eps, 'by_urn': by_urn}


def _endpoint_state(view: dict, path='', name='') -> dict:
    """served / absent / unknown for one endpoint on the view's build.

    The URN decides when one is given — it is what execute() will actually
    send, so a stale or forged ``name`` cannot talk the guard out of a refusal.
    Several library names can share a URN; the best verdict among them wins
    (``ok`` beats ``absent``), so the guard never refuses on a tie.
    """
    eps = view['endpoints']
    names = view['by_urn'].get(_norm_path(path), []) if path else []
    if not names and name and name in eps and not path:
        names = [name]
    if not names:
        return {'state': UNKNOWN, 'endpoint': name or '', 'vendor_claim': False,
                'reason': 'not in the library for this build'}
    verdict = max((eps[n]['verdict'] for n in names), key=lambda v: _VERDICT_RANK.get(v, 0))
    lead = next((n for n in names if eps[n]['verdict'] == verdict), names[0])
    e = eps[lead]
    return {'state': _state_of(verdict), 'endpoint': lead, 'urn': e.get('urn', ''),
            'vendor_claim': bool(e.get('vendor_only')), 'sources': e.get('sources', []),
            'witnesses': e.get('witnesses', []), 'reason': ''}


def _provenance(res: dict) -> list:
    """Which evidence speaks for the resolved build, newest first.

    Point evidence is the build's own rows. Vendor evidence has no build row —
    it speaks for every version inside its [min, max] range (the library's
    rule 4), so it is matched on the summary's sort keys.
    """
    from ..models_apilib import ApiLibBuild, ApiLibEvidence
    product, version = res.get('product') or '', res.get('version') or ''
    if not product or not version:
        return []
    b = res.get('build') or {}
    key = b.get('sort_key') or apilib.version_key(version)
    line = res.get('line') or ''
    line_row = (ApiLibBuild.query.filter_by(product=product, version=line).first()
                if line and line != version else None)
    wanted = [i for i in (b.get('id'), line_row.id if line_row else None) if i]
    q = select(ApiLibEvidence.build_id, ApiLibEvidence.source, ApiLibEvidence.device_name,
               ApiLibEvidence.origin_ref, ApiLibEvidence.captured_at,
               ApiLibEvidence.healthy, ApiLibEvidence.summary).where(
        ApiLibEvidence.product == product)
    q = q.where((ApiLibEvidence.build_id.in_(wanted or [-1]))
                | (ApiLibEvidence.source == apilib.SOURCE_VENDOR))
    out = []
    for bid, source, device, ref, captured, healthy, summ in db.session.execute(q):
        summ = summ or {}
        if source == apilib.SOURCE_VENDOR:
            if not (summ.get('min_key') and summ.get('max_key')
                    and summ['min_key'] <= key <= summ['max_key']):
                continue
            scope = 'vendor range %s-%s' % (summ.get('min_version', '?'),
                                            summ.get('max_version', '?'))
        elif line_row is not None and bid == line_row.id:
            scope = 'line %s' % line
        else:
            scope = 'build %s' % version
        out.append({'source': source, 'device': device or '', 'origin_ref': ref or '',
                    'captured_at': _iso(captured), 'healthy': bool(healthy),
                    'scope': scope})
    out.sort(key=lambda r: r['captured_at'], reverse=True)
    return out


def _status_label(res: dict, prov: list) -> str:
    status = res.get('status')
    if status == 'measured':
        srcs = sorted({p['source'] for p in prov if p['healthy']
                       and p['scope'].startswith('build ')})
        return 'measured by %s' % ' + '.join(srcs) if srcs else 'measured'
    return {'vendor_only': 'vendor data only (a claim, not a measurement)',
            'unmeasured': 'unmeasured (no evidence for this build)',
            'unknown_firmware': 'firmware unknown (never read from the appliance)',
            }.get(status, status or 'unknown')


def _field_since(product: str, endpoint: str, version: str) -> dict:
    """``{field: {"since": version, "source": s}}`` where a field is provably newer.

    "Since X" is only claimed when an OLDER build measured the same endpoint's
    fields from the SAME kind of evidence and that field was not there — the
    library's rule that fields compare only like-for-like (a sweep carries wire
    noise a schema strips). A field first seen on the oldest measured build is
    simply "known", not "new since", so it gets no hint.
    """
    from ..models_apilib import (ApiLibBuild, ApiLibEndpoint, ApiLibField,
                                 ApiLibFieldFact, ApiLibSpan)
    ep = ApiLibEndpoint.query.filter_by(product=product, name=endpoint).first()
    if ep is None:
        return {}
    cur = apilib.version_key(version)
    ep_first: dict = {}
    f_first: dict = {}
    q = (select(ApiLibField.name, ApiLibFieldFact.source, ApiLibBuild.sort_key, ApiLibBuild.version)
         .join(ApiLibFieldFact, ApiLibFieldFact.field_id == ApiLibField.id)
         .join(ApiLibBuild, ApiLibBuild.id == ApiLibFieldFact.build_id)
         .where(ApiLibField.endpoint_id == ep.id, ApiLibBuild.sort_key <= cur))
    for fname, source, key, ver in db.session.execute(q):
        if source not in ep_first or key < ep_first[source][0]:
            ep_first[source] = (key, ver)
        k = (fname, source)
        if k not in f_first or key < f_first[k][0]:
            f_first[k] = (key, ver)
    # Vendor spans carry their own "from" per field; the endpoint's own span
    # start is the baseline a field must be newer than.
    ep_span = db.session.execute(
        select(ApiLibSpan.from_key).where(ApiLibSpan.endpoint_id == ep.id,
                                         ApiLibSpan.field_id.is_(None))).scalars().all()
    if ep_span:
        base = min(ep_span)
        q = (select(ApiLibField.name, ApiLibSpan.from_key, ApiLibSpan.from_version)
             .join(ApiLibSpan, ApiLibSpan.field_id == ApiLibField.id)
             .where(ApiLibField.endpoint_id == ep.id, ApiLibSpan.from_key <= cur))
        ep_first[apilib.SOURCE_VENDOR] = (base, '')
        for fname, key, ver in db.session.execute(q):
            k = (fname, apilib.SOURCE_VENDOR)
            if k not in f_first or key < f_first[k][0]:
                f_first[k] = (key, ver)
    out: dict = {}
    for (fname, source), (key, ver) in f_first.items():
        if key > ep_first[source][0]:
            prev = out.get(fname)
            if prev is None or key < prev['_key']:
                out[fname] = {'since': ver, 'source': source, '_key': key}
    return {f: {'since': r['since'], 'source': r['source']} for f, r in out.items()}


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


def _tree_marks(view: dict) -> dict:
    """``{registry name: state}`` for every leaf of the API Menu tree."""
    marks = {}
    for ep in loader.get_all_endpoints():
        name = ep.get('name')
        if name:
            marks[name] = _endpoint_state(view, path=ep.get('urn') or ep.get('path') or '',
                                          name=name)['state']
    return marks


@bp.route('/build')
@login_required
def build_info():
    """The selected appliance's build: banner facts + per-leaf marks.

    Read-only and cheap; the page calls it whenever the appliance picker
    changes, so the tree never shows one build's verdicts under another's name.
    """
    appliance_id = request.args.get('appliance_id', type=int)
    if not appliance_id:
        return jsonify({'ok': False, 'msg': 'appliance_id is required.'}), 400
    appliance = visible_appliance_or_404(appliance_id)
    view = _library_view(appliance)
    res = view['resolved']
    prov = _provenance(res)
    marks = _tree_marks(view)
    counts = {SERVED: 0, ABSENT: 0, UNKNOWN: 0}
    for state in marks.values():
        counts[state] += 1
    lib_counts = {SERVED: 0, ABSENT: 0, UNKNOWN: 0}
    for e in view['endpoints'].values():
        lib_counts[_state_of(e.get('verdict'))] += 1
    return jsonify({
        'ok': True,
        'appliance': {'id': appliance.id, 'name': appliance.name},
        'build': {'product': res.get('product') or '', 'version': res.get('version') or '',
                  'firmware_raw': res.get('firmware_raw') or '', 'line': res.get('line') or '',
                  'status': res.get('status') or '', 'status_label': _status_label(res, prov),
                  'row': res.get('build')},
        'provenance': prov[:12],
        'harvestable': res.get('status') in _UNMEASURED_STATUSES,
        'marks': marks,
        'counts': counts,
        'library_counts': lib_counts,
    })


@bp.route('/fields')
@login_required
def endpoint_fields():
    """Fields one endpoint serves on the selected appliance's build."""
    appliance_id = request.args.get('appliance_id', type=int)
    name = (request.args.get('endpoint') or '').strip()
    path = (request.args.get('path') or '').strip()
    if not appliance_id or not (name or path):
        return jsonify({'ok': False, 'msg': 'appliance_id and endpoint are required.'}), 400
    appliance = visible_appliance_or_404(appliance_id)
    view = _library_view(appliance)
    res = view['resolved']
    st = _endpoint_state(view, path=path, name=name)
    lib_name = st.get('endpoint') or name
    out = {'ok': True, 'endpoint': lib_name, 'state': st['state'],
           'version': res.get('version') or '', 'status': 'unmeasured', 'fields': {},
           'provenance': [], 'line_fallback': None}
    if not (res.get('product') and res.get('version') and lib_name):
        return jsonify(out)
    fa = apilib.fields_at(res['product'], lib_name, res['version'])
    since = _field_since(res['product'], lib_name, res['version']) \
        if fa['status'] == 'measured' else {}
    for fname, spec in fa['fields'].items():
        if fname in since:
            spec['since'] = since[fname]['since']
            spec['since_source'] = since[fname]['source']
    out.update(status=fa['status'], fields=fa['fields'], provenance=fa['provenance'])
    # FortiWeb sweeps are often blind (an empty table reveals no columns) while
    # a schema was harvested per LINE. Offered separately and labelled as the
    # line's, never merged into this build's answer — that would be the
    # neighbour-filling the library forbids.
    line = res.get('line') or ''
    if fa['status'] != 'measured' and line and line != res['version']:
        lf = apilib.fields_at(res['product'], lib_name, line)
        if lf['status'] == 'measured':
            out['line_fallback'] = {'line': line, 'fields': lf['fields'],
                                    'provenance': lf['provenance']}
    return jsonify(out)


@bp.route('/harvest/<int:appliance_id>', methods=['POST'])
@login_required
@require_permission('appliances.apply')
def harvest(appliance_id):
    """Queue a library harvest of one appliance (the "unmeasured" way out).

    Same gate as discovery_load, the other route here that makes SATOM reach
    out to an appliance on the operator's say-so. The harvest module is
    optional at import time: a build without it must answer with a message,
    not a 500 that takes the whole page's JS down with it.
    """
    appliance = visible_appliance_or_404(appliance_id)
    try:
        from ..services import apilib_harvest
        enqueue = apilib_harvest.enqueue
    except (ImportError, AttributeError):
        return jsonify({'ok': False, 'msg': 'The harvest service is not available in this '
                        'installation; run a harvest from the API versions page instead.'}), 503
    try:
        result = enqueue(appliance.id, reason='explorer')
    except Exception as exc:  # noqa: BLE001 — surfaced to the operator verbatim
        log.warning('explorer harvest of %s failed: %s', appliance.name, exc)
        return jsonify({'ok': False, 'msg': 'Harvest could not be queued: %s' % exc}), 500
    try:
        json.dumps(result)
    except (TypeError, ValueError):
        result = str(result)
    # enqueue() answers {"queued", "msg", "reason"}; a refusal (unsupported
    # product, maintenance, disabled) is an answer, not a crash, and its reason
    # is what the operator needs to read. "duplicate" means one is already
    # pending — from the operator's side, the harvest IS queued.
    queued = True
    msg = 'Harvest queued for %s.' % appliance.name
    if isinstance(result, dict) and 'queued' in result:
        queued = bool(result.get('queued')) or result.get('reason') == 'duplicate'
        msg = result.get('msg') or ('Harvest not queued: %s' % (result.get('reason') or 'unknown'))
    log_action('api_explorer.harvest', target=appliance.name,
               extra={'appliance_id': appliance.id, 'queued': queued})
    return jsonify({'ok': queued, 'msg': msg, 'result': result})


def _truthy(value) -> bool:
    return str(value or '').strip().lower() in ('1', 'true', 'yes', 'on')


@bp.route('/execute', methods=['POST'])
@login_required
def execute():
    appliance_id = request.form.get('appliance_id', type=int)
    endpoint = request.form.get('endpoint', '').strip()
    method = request.form.get('method', 'GET').upper()
    body_raw = request.form.get('body', '').strip()
    confirm_unserved = _truthy(request.form.get('confirm_unserved'))

    if not appliance_id or not endpoint:
        return jsonify({'ok': False, 'error': 'Appliance and endpoint are required.',
                        'msg': 'Appliance and endpoint are required.'})

    if method in WRITE_METHODS and not current_user.can('registry.execute_write'):
        m = 'The "Execute write API calls" permission is required for non-GET methods.'
        return jsonify({'ok': False, 'error': m, 'msg': m})

    appliance = visible_appliance_or_404(appliance_id)
    # The proxy this page used to call refused these; execute() inherits the
    # same SSRF floor now that it is the page's only way out.
    from ..api.proxy import _host_is_blocked
    if _host_is_blocked(appliance.host or ''):
        m = 'Appliance host is not permitted.'
        return jsonify({'ok': False, 'error': m, 'msg': m}), 400

    body = None
    if body_raw:
        try:
            body = json.loads(body_raw)
        except ValueError as exc:
            m = f'Invalid JSON body: {exc}'
            return jsonify({'ok': False, 'error': m, 'msg': m})

    # Firmware guard — SERVER-side on purpose: the page's warning is advice, this
    # is the rule. Known-not-served needs an explicit confirm_unserved; unknown
    # (unmeasured build, or an endpoint nobody probed on it) passes with a
    # warning, because refusing on ignorance would lock operators out of every
    # build the library has not met yet.
    view = _library_view(appliance)
    res = view['resolved']
    st = _endpoint_state(view, path=endpoint)
    build_label = '%s %s' % (res.get('product') or appliance.kind, res.get('version') or '?')
    guard = {'state': st['state'], 'endpoint': st.get('endpoint') or '',
             'build': res.get('version') or '', 'build_status': res.get('status') or '',
             'confirmed': False, 'warning': ''}
    if st['state'] == ABSENT:
        basis = 'the vendor\'s data says' if st.get('vendor_claim') else 'the library measured that'
        if not confirm_unserved:
            m = ('Refused: %s %s does not serve %s on %s. Send again with '
                 'confirm_unserved to override.' % (basis, appliance.name,
                                                    '/' + _norm_path(endpoint), build_label))
            return jsonify({'ok': False, 'refused': True, 'needs_confirm': True,
                            'error': m, 'msg': m, 'library': guard}), 409
        guard['confirmed'] = True
        guard['warning'] = ('Sent despite the library: %s %s does not serve this endpoint on %s.'
                            % (basis, appliance.name, build_label))
    elif st['state'] == UNKNOWN:
        why = ('the library has no evidence for build %s' % build_label
               if res.get('status') in _UNMEASURED_STATUSES
               else 'this endpoint was never measured on %s' % build_label)
        guard['warning'] = 'Unverified: %s — the appliance decides.' % why

    try:
        client = client_for(appliance)
        resp = client.api_call(method, endpoint, body)
        log_action('api_explorer.execute', target=appliance.name,
                   extra={'method': method, 'endpoint': endpoint,
                          'library_state': guard['state'],
                          'confirm_unserved': guard['confirmed']})
        try:
            result = resp.json()
        except Exception:
            result = resp.text
        return jsonify({'ok': True, 'status': resp.status_code, 'result': result,
                        'warning': guard['warning'], 'library': guard})
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc), 'msg': str(exc),
                        'library': guard})


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
