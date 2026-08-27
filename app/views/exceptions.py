"""Exceptions — author desired-state WAF / signature carve-outs bound to a
Server Policy.

A Web Protection Profile is usually SHARED, so an exception on it applies to
every policy that binds it and FortiWeb can't record which policy a carve-out
was authored for. This page records that intent in the manager DB (NEVER on the
box from here — pushing to a device is a separate, later step). It REPLACES the
old stub that listed url-access rules and mislabelled them "exceptions".
"""
import json

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

from ..auth.decorators import require_permission
from ..models import Appliance
from ..models import visible_appliances, visible_appliance_or_404
from ..clients.fortiweb import FortiWebClient
from ..services import wpp_exceptions as store
from ..services.fortiweb_ops import FortiWebOps
from ..services import exception_inject, exception_detect
from ..services import wpp_clone_flow
from ..services import exception_versions as versions
from ..services import exception_advice, exception_deploy, exception_lifecycle
from ..services.audit import log_action

bp = Blueprint('exceptions', __name__, url_prefix='/exceptions')

_WPP_COLL = 'waf/web-protection-profile.inline-protection'
EP_POLICY = '/api/v2.0/cmdb/server-policy/policy'


def _clone_suggestion(appliance, source, policies):
    """The guided-clone offer (rule 3). Delegates to ``wpp_clone_flow`` so this
    page and the Attack-ID investigation page derive the SAME name and read the
    SAME headroom — see that module's docstring for why it is not inlined."""
    return wpp_clone_flow.suggestion(appliance, source, policies)


def _device_lists(appliance):
    """Best-effort server-policy + WPP names off the device (for the pickers)."""
    policies, wpps = [], []
    try:
        client = FortiWebClient(appliance)
        raw = client.list_server_policies()
        rows = raw.get('results', raw.get('data', [])) if isinstance(raw, dict) else []
        policies = sorted(r.get('name', '') for r in rows if isinstance(r, dict) and r.get('name'))
        wpps = sorted(client.cmdb_names(_WPP_COLL))
    except Exception:  # noqa: BLE001 — dead device → empty pickers, page still works
        pass
    return policies, wpps


@bp.route('/')
@login_required
def index():
    appliances = visible_appliances().order_by(Appliance.name).all()
    from flask import redirect as _redir, url_for as _ufor
    from ..services import device_context as _dc
    _cur = _dc.current_appliance()
    if _cur is None:
        return _redir(_ufor('architecture.index'))
    return _redir(_ufor('exceptions.list_exceptions', id=_cur.id))


@bp.route('/<int:id>')
@login_required
def list_exceptions(id):
    """The (device, ADOM) inventory — option B of the two the operator asked for.

    The filters are resolved HERE, server-side. A client-side overlay that hides
    rows leaves the page shipping a superset it claims not to be showing, and
    the tally line above the table would then be counting rows nobody can see.
    The fleet-wide counterpart is ``waf.exceptions``.
    """
    appliance = visible_appliance_or_404(id)
    policies, wpps = _device_lists(appliance)
    all_items = store.list_exceptions(appliance.id)

    sel_type = (request.args.get('type') or '').strip()
    sel_cat = (request.args.get('category') or '').strip()
    sel_policy = (request.args.get('policy') or '').strip()
    sel_state = (request.args.get('state') or '').strip()
    sel_q = (request.args.get('q') or '').strip().lower()

    items = all_items
    if sel_type:
        items = [i for i in items if store.canonical_type(i.exc_type) == sel_type]
    if sel_cat:
        items = [i for i in items if i.category == sel_cat]
    if sel_policy:
        items = [i for i in items if sel_policy in i.policy_names]
    if sel_state == 'stale':
        items = [i for i in items if i.stale]
    elif sel_state == 'disabled':
        items = [i for i in items if not i.enabled]
    elif sel_state == 'unversioned':
        items = [i for i in items if not i.lineage]
    elif sel_state == 'active':
        items = [i for i in items if i.enabled and not i.stale]
    if sel_q:
        items = [i for i in items
                 if sel_q in (i.name or '').lower()
                 or sel_q in (i.wpp_mkey or '').lower()
                 or sel_q in (i.reason or '').lower()
                 or sel_q in ' '.join(i.policy_names).lower()
                 or sel_q in json.dumps(i.payload_dict).lower()]

    # Type choices come from what is PRESENT, not from the catalog: offering a
    # filter that can only ever return nothing makes an empty table look like
    # data loss.
    present_types: dict[str, str] = {}
    for i in all_items:
        key = store.canonical_type(i.exc_type)
        t = store.type_for(key)
        present_types.setdefault(key, t['label'] if t else key)

    # Which Server Policy holds how many — the "¿qué SPO la tiene?" half of the
    # ask, answered on the scope the operator is standing on.
    by_policy: dict[str, int] = {}
    for i in all_items:
        for p in i.policy_names:
            by_policy[p] = by_policy.get(p, 0) + 1
        if not i.policy_names:
            by_policy.setdefault('(unbound)', 0)
            by_policy['(unbound)'] += 1

    from ..services.templates import managed_wpp_names
    return render_template(
        'exceptions/list.html',
        appliance=appliance,
        items=items,
        total=len(all_items),
        exception_types=store.EXCEPTION_TYPES,
        signature_types=store.SIGNATURE_TYPES,
        policies=policies,
        wpps=wpps,
        managed_wpps=managed_wpp_names(),
        stale_count=sum(1 for it in all_items if getattr(it, 'stale', False)),
        unversioned_count=sum(1 for it in all_items if not it.lineage),
        restorable_count=len(versions.restorable_for(appliance.id)),
        present_types=sorted(present_types.items(), key=lambda kv: kv[1]),
        by_policy=sorted(by_policy.items(), key=lambda kv: (-kv[1], kv[0])),
        selected={'type': sel_type, 'category': sel_cat, 'policy': sel_policy,
                  'state': sel_state, 'q': request.args.get('q') or ''},
        cat_exception=store.CAT_EXCEPTION,
        cat_signature=store.CAT_SIGNATURE,
    )


@bp.route('/type-fields')
@login_required
def type_fields(id=None):
    """Field spec for a carve-out type, so the New/Edit form renders inputs."""
    key = request.args.get('type', '')
    t = store.type_for(key)
    if not t:
        return jsonify(ok=False, error='unknown type', fields=[]), 400
    return jsonify(ok=True, type=t, fields=store.fields_for(key),
                   help=store.help_for(key))


@bp.route('/<int:id>/save', methods=['POST'])
@require_permission('config_write')
def save(id):
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    exc_id = body.get('exc_id')
    exc_type = (body.get('exc_type') or '').strip()
    wpp_mkey = (body.get('wpp_mkey') or '').strip()
    name = (body.get('name') or '').strip()
    reason = (body.get('reason') or '').strip()
    policies = body.get('policies') or []
    fields = body.get('fields') or {}
    if not isinstance(fields, dict):
        fields = {}
    payload = {k: v for k, v in fields.items() if v not in (None, '', [])}

    # Rule 2 — templates stay clean: a carve-out can never target a
    # template-managed WPP. The 403 carries the guided-clone offer (rule 3):
    # clone the profile as wpp-{policy}, rebind the policy, author on the clone.
    lock = store.template_lock_error(wpp_mkey)
    if lock:
        return jsonify(ok=False, error=lock, template_locked=True,
                       clone_suggestion=_clone_suggestion(appliance, wpp_mkey, policies)), 403

    if exc_id:
        existing = store.get(int(exc_id))
        if existing is None:
            return jsonify(ok=False, error='not found'), 404
        errors = store.validate_payload(existing.exc_type, payload)
        if errors:
            return jsonify(ok=False, error='; '.join(errors), errors=errors), 400
        exc = store.update(int(exc_id), wpp_mkey=wpp_mkey, payload=payload,
                           name=name, reason=reason, policies=policies,
                           author=getattr(current_user, 'username', '') or '')
        return jsonify(ok=True, id=exc.id)

    if not store.type_for(exc_type):
        return jsonify(ok=False, error='unknown carve-out type'), 400
    errors = store.validate_payload(exc_type, payload)
    if errors:
        return jsonify(ok=False, error='; '.join(errors), errors=errors), 400
    author = getattr(current_user, 'username', '') or ''
    exc = store.add(appliance.id, wpp_mkey=wpp_mkey, exc_type=exc_type, payload=payload,
                    name=name, reason=reason, author=author, policies=policies)
    return jsonify(ok=True, id=exc.id)


@bp.route('/<int:id>/delete', methods=['POST'])
@require_permission('config_write')
def delete(id):
    visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    ok = store.delete(int(body.get('exc_id') or 0),
                      author=getattr(current_user, 'username', '') or '',
                      note=(body.get('note') or ''))
    return jsonify(ok=ok)


@bp.route('/<int:id>/purge', methods=['POST'])
@require_permission('config_write')
def purge(id):
    """The Server-Policy cascade — PREVIEWED unless ``apply=true``.

    This used to delete on the first click. It was the one destructive path in
    the page with no question in front of it, and a carve-out is authored
    against a PROFILE, which is usually shared: a row that also serves another
    policy would go with it. Now the default answer is the preview
    (:func:`exception_lifecycle.on_server_policy_deleted`), which names every
    affected carve-out and says which are deleted and which merely unbound.
    """
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    pol = (body.get('server_policy') or '').strip()
    if not pol:
        return jsonify(ok=False, error='server policy required'), 400
    res = exception_lifecycle.on_server_policy_deleted(
        appliance.id, pol,
        author=getattr(current_user, 'username', '') or '',
        apply=bool(body.get('apply')))
    if res['applied']:
        log_action('wpp_exception.purge', target='server_policy:%s' % pol)
    return jsonify(**res)


# --------------------------------------------------------------------------- #
#  Lifecycle — impact, guarded delete, split, clone                             #
# --------------------------------------------------------------------------- #
def _live_bindings_or_none(appliance):
    """``{policy: wpp}`` off the box, or ``None`` when it could not be read.

    ``None`` and ``{}`` MUST stay distinguishable: an empty map from a healthy
    box means "no policy binds anything", and from a dead one it means "we do
    not know". Only one of those makes a delete safe.
    """
    b = _policy_wpp_bindings(appliance)
    return b or None


@bp.route('/<int:id>/impact')
@login_required
def impact(id):
    """What deleting one carve-out would take away, and from whom."""
    appliance = visible_appliance_or_404(id)
    exc = store.get(int(request.args.get('exc_id') or 0))
    if exc is None or exc.appliance_id != appliance.id:
        return jsonify(ok=False, error='carve-out not found'), 404
    rep = exception_lifecycle.impact(
        exc, bindings=_live_bindings_or_none(appliance))
    return jsonify(ok=True, impact=rep)


@bp.route('/<int:id>/guarded-delete', methods=['POST'])
@require_permission('config_write')
def guarded_delete(id):
    """Delete only when it costs nobody else; otherwise return the reason."""
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    exc = store.get(int(body.get('exc_id') or 0))
    if exc is None or exc.appliance_id != appliance.id:
        return jsonify(ok=False, error='carve-out not found'), 404
    res = exception_lifecycle.guarded_delete(
        exc, author=getattr(current_user, 'username', '') or '',
        acknowledge=bool(body.get('acknowledge')),
        bindings=_live_bindings_or_none(appliance))
    code = res.pop('code', 200 if res.get('ok') else 400)
    if res.get('ok'):
        log_action('wpp_exception.delete', target='wpp_exception:%s'
                   % body.get('exc_id'))
    return jsonify(**res), code


@bp.route('/<int:id>/split', methods=['POST'])
@require_permission('config_write')
def split(id):
    """One carve-out per Server Policy — the remedy behind a SPLIT verdict."""
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    exc = store.get(int(body.get('exc_id') or 0))
    if exc is None or exc.appliance_id != appliance.id:
        return jsonify(ok=False, error='carve-out not found'), 404
    res = exception_lifecycle.split_by_policy(
        exc, author=getattr(current_user, 'username', '') or '')
    return jsonify(**res), (200 if res.get('ok') else 400)


@bp.route('/<int:id>/clone-exception', methods=['POST'])
@require_permission('config_write')
def clone_exception(id):
    """A private copy for one Server Policy, leaving the original alone."""
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    exc = store.get(int(body.get('exc_id') or 0))
    if exc is None or exc.appliance_id != appliance.id:
        return jsonify(ok=False, error='carve-out not found'), 404
    res = exception_lifecycle.clone_for_policy(
        exc, (body.get('server_policy') or ''),
        author=getattr(current_user, 'username', '') or '')
    return jsonify(**res), (200 if res.get('ok') else 400)


# --------------------------------------------------------------------------- #
#  Deploy to one or MANY FortiWebs                                              #
# --------------------------------------------------------------------------- #
@bp.route('/<int:id>/deploy-targets')
@login_required
def deploy_targets(id):
    """Every visible FortiWeb scope with a verdict for this carve-out.

    Refused scopes are RETURNED, not filtered out: a list of only the eligible
    destinations cannot be audited, because "not offered" and "not applicable"
    look the same.
    """
    appliance = visible_appliance_or_404(id)
    exc = store.get(int(request.args.get('exc_id') or 0))
    if exc is None or exc.appliance_id != appliance.id:
        return jsonify(ok=False, error='carve-out not found', targets=[]), 404
    rows = exception_deploy.targets(exc, current_user,
                                    known_profiles=_known_profiles())
    return jsonify(ok=True, targets=rows,
                   verdict_labels=exception_deploy.VERDICT_LABEL)


def _known_profiles():
    """``appliance_id -> {wpp names}`` from the source-of-truth snapshots.

    A scope with no snapshot is ABSENT from this map, not present-and-empty:
    the deploy planner treats absence as "unknown" and lets the destination
    through, and an empty set would refuse it on a fact nobody established.
    """
    try:
        from ..services import waf_fleet
        universe = waf_fleet.collect()
    except Exception:  # noqa: BLE001 — no snapshots is not an error here
        return None
    out: dict[int, set] = {}
    for prof in universe.get('profiles', []):
        aid = prof.get('appliance_id')
        if aid is None:
            continue
        out.setdefault(aid, set()).add(prof.get('name') or '')
    return out or None


@bp.route('/<int:id>/deploy', methods=['POST'])
@require_permission('config_write')
def deploy(id):
    """Place one carve-out on several scopes as desired state (dry-run first).

    Placing is not pushing. Nothing here contacts an appliance; each new
    placement is pushed from its own scope, which is where the headroom and
    template checks live. Said in the response rather than assumed.
    """
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    exc = store.get(int(body.get('exc_id') or 0))
    if exc is None or exc.appliance_id != appliance.id:
        return jsonify(ok=False, error='carve-out not found'), 404
    ids = [int(x) for x in (body.get('appliance_ids') or []) if str(x).strip()]
    if not ids:
        return jsonify(ok=False, error='choose at least one destination'), 400
    known = _known_profiles()
    if not body.get('apply'):
        return jsonify(ok=True, dry_run=True,
                       **exception_deploy.plan(exc, ids, current_user,
                                               known_profiles=known))
    res = exception_deploy.place(
        exc, ids, author=getattr(current_user, 'username', '') or '',
        user=current_user, known_profiles=known)
    if res.get('ok'):
        log_action('wpp_exception.deploy', target='wpp_exception:%d' % exc.id)
    return jsonify(dry_run=False, **res), (200 if res.get('ok') else 400)


# --------------------------------------------------------------------------- #
#  AI advisory gate — offered BEFORE anything is implemented                     #
# --------------------------------------------------------------------------- #
@bp.route('/<int:id>/advice', methods=['POST'])
@login_required
def advice(id):
    """Analyse a DRAFT carve-out before it is saved or pushed.

    Opt-in and non-blocking by contract: it returns a recommendation, never a
    veto. A model that can stop a change becomes an outage during an incident,
    which is exactly when a false positive needs waiving fastest.

    Works on a draft (type + fields straight off the form) so the question can
    be asked BEFORE the record exists — which is what "before implementing
    anything" means.
    """
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    exc_type = (body.get('exc_type') or '').strip()
    if not store.type_for(exc_type):
        return jsonify(ok=False, error='unknown carve-out type'), 400
    fields = body.get('fields') or {}
    payload = {k: v for k, v in (fields if isinstance(fields, dict) else {}).items()
               if v not in (None, '', [])}
    wpp = (body.get('wpp_mkey') or '').strip()
    policy = (body.get('server_policy') or '').strip()

    scope_verdict = None
    if wpp:
        try:
            from ..services import wpp_scope
            scope_verdict = wpp_scope.check(appliance, wpp, policy).to_dict()
        except Exception:  # noqa: BLE001 — an advisory must never 500 on this
            scope_verdict = None

    res = exception_advice.analyse(
        exc_type, payload, wpp=wpp, policy=policy,
        problem=(body.get('problem') or ''), scope_verdict=scope_verdict,
        provider_key=(body.get('provider') or ''),
        use_model=bool(body.get('use_model')))
    return jsonify(ok=True, advice=res, scope=scope_verdict,
                   suggestions=exception_advice.type_suggestions(
                       body.get('problem') or ''))


@bp.route('/<int:id>/clone-for-policy', methods=['POST'])
@require_permission('config_write')
def clone_for_policy(id):
    """Rule 3 — the guided flow: deep-clone a (template-managed or shared) WPP
    under the Naming-derived per-policy name, re-bind the Server Policy to the
    clone, and re-point any authored carve-outs. Headroom-checked per object
    TYPE (rule 4). Dry-run unless ``apply=true``.

    The clone copies the WHOLE subtree, so the response carries ``renames`` (the
    sub-objects it will duplicate) and ``questions`` (the ones it cannot, with
    the reason). Applying a plan that leaves anything shared needs
    ``acknowledge=true``; ``clone_anyway`` overrides the predefined/template
    refusals object by object."""
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    res = wpp_clone_flow.clone_and_rebind(
        appliance,
        source=(body.get('source') or ''),
        policy=(body.get('server_policy') or ''),
        new_name=(body.get('new_name') or ''),
        apply=bool(body.get('apply')),
        clone_anyway=body.get('clone_anyway') or (),
        acknowledge=bool(body.get('acknowledge')),
        actor=getattr(current_user, 'username', None) or '')
    code = res.pop('code', 200)
    return jsonify(**res), code


# --------------------------------------------------------------------------- #
#  Inject to device (dry-run preview -> real push) + Detect from device         #
# --------------------------------------------------------------------------- #
def _policy_wpp_bindings(appliance):
    """Live ``{server_policy: wpp}`` map off the device (empty on a dead box)."""
    try:
        client = FortiWebClient(appliance)
        rows = client._results_list(client.list_server_policies())
        return {r['name']: (r.get('web-protection-profile') or '')
                for r in rows if isinstance(r, dict) and r.get('name')}
    except Exception:  # noqa: BLE001 - dead device -> no bindings
        return {}


@bp.route('/<int:id>/inject-targets')
@login_required
def inject_targets(id):
    """Candidate parent objects on the device a carve-out type can target."""
    appliance = visible_appliance_or_404(id)
    _type = request.args.get('type', '')
    rest = exception_inject.rest_for(_type)
    if rest is None:
        return jsonify(ok=False, error='type cannot be injected', targets=[]), 400
    if rest.top_level:
        # A named object of its own — nothing to target. Said explicitly so the
        # empty picker does not read as an unreachable device.
        return jsonify(ok=True, targets=[], inline=False, counts={},
                       needs_target=False, can_create=False,
                       limit=store.SIG_FILTER_MAX)
    try:
        targets = exception_inject.candidate_targets(FortiWebClient(appliance),
                                                     request.args.get('type', ''))
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc), targets=[])
    # Rule 4 — a signature set caps at 128 filter_list (per-signature exception)
    # entries. Show each candidate set's usage so the operator sees headroom
    # BEFORE picking a target. Best-effort: a read failure just omits counts.
    counts = {}
    if request.args.get('type', '') == 'signature_filter_item':
        try:
            from .objedit import _read_rows
            client = FortiWebClient(appliance)
            for t in targets[:20]:
                counts[t] = len(_read_rows(client, 'waf/signature/filter_list', t))
        except Exception:  # noqa: BLE001
            counts = {}
    return jsonify(ok=True, targets=targets, inline=rest.inline,
                   counts=counts, limit=store.SIG_FILTER_MAX, needs_target=True,
                   can_create=(not rest.inline
                               and rest.parent_logical not in ('signature', 'signature_group_rule')))


@bp.route('/<int:id>/inject', methods=['POST'])
@require_permission('config_write')
def inject(id):
    """Push one authored carve-out onto the device (dry-run unless apply=true)."""
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    exc = store.get(int(body.get('exc_id') or 0))
    if exc is None or exc.appliance_id != appliance.id:
        return jsonify(ok=False, error='carve-out not found'), 404
    # Rule 2 also holds at PUSH time: never inject into a template-managed WPP.
    lock = store.template_lock_error(exc.wpp_mkey)
    if lock:
        return jsonify(ok=False, error=lock, template_locked=True), 403
    # Rule 4 — hard FortiWeb cap: 128 filter_list entries per signature set.
    target = (body.get('target') or '').strip()
    if exc.exc_type == 'signature_filter_item' and target:
        try:
            from .objedit import _read_rows
            used = len(_read_rows(FortiWebClient(appliance),
                                  'waf/signature/filter_list', target))
        except Exception:  # noqa: BLE001 — unreadable set → let the box decide
            used = None
        if used is not None and used >= store.SIG_FILTER_MAX:
            return jsonify(ok=False, error=(
                'Signature set "%s" already holds %d/%d exception entries — '
                'FortiWeb rejects more. Remove an entry first.' % (
                    target, used, store.SIG_FILTER_MAX))), 409
    res = exception_inject.apply_injection(
        FortiWebOps(appliance), exc_type=exc.exc_type, payload=exc.payload_dict,
        target=target, dry_run=not bool(body.get('apply')),
        create_container=bool(body.get('create_container')))
    return jsonify(ok=res['ok'], dry_run=res['dry_run'], steps=res['steps'],
                   plan={k: res['plan'].get(k) for k in ('status', 'method', 'endpoint', 'error')})


# --------------------------------------------------------------------------- #
#  Versioner — history, structural diff, rollback, restore                      #
# --------------------------------------------------------------------------- #
@bp.route('/<int:id>/versions')
@login_required
def version_history(id):
    """Every recorded state of one carve-out, newest first.

    ``versioned=False`` is NOT the same as "never changed": a carve-out
    authored before the versioner shipped has no history at all, and the page
    must say that rather than render an empty timeline as a clean one.
    """
    visible_appliance_or_404(id)
    exc = store.get(int(request.args.get('exc_id') or 0))
    if exc is None or exc.appliance_id != id:
        return jsonify(ok=False, error='carve-out not found', versions=[]), 404
    rows = versions.history(exc.lineage)
    return jsonify(ok=True, versioned=bool(exc.lineage and rows),
                   lineage=exc.lineage or '',
                   current_sha=versions.sha_of(versions.body_of(exc)),
                   versions=[r.to_dict() for r in rows])


@bp.route('/<int:id>/version-diff')
@login_required
def version_diff(id):
    """Structural A->B comparison of two recorded bodies.

    ``b`` omitted means "against the carve-out as it stands now", which is the
    comparison an operator about to roll back actually wants.
    """
    visible_appliance_or_404(id)
    from ..models_exceptions import ExceptionVersion
    from ..models import db as _db
    a = _db.session.get(ExceptionVersion, int(request.args.get('a') or 0))
    if a is None:
        return jsonify(ok=False, error='version not found'), 404
    exc = store.get(int(request.args.get('exc_id') or 0))
    if exc is None or exc.appliance_id != id or exc.lineage != a.lineage:
        return jsonify(ok=False, error='version belongs to another carve-out'), 404
    b_id = request.args.get('b')
    if b_id:
        b = _db.session.get(ExceptionVersion, int(b_id))
        if b is None or b.lineage != a.lineage:
            return jsonify(ok=False, error='version belongs to another carve-out'), 404
        right, label = b.body_dict, 'version #%d' % b.id
    else:
        right, label = versions.body_of(exc), 'current'
    return jsonify(ok=True, left='version #%d' % a.id, right=label,
                   diff=versions.diff(a.body_dict, right))


@bp.route('/<int:id>/rollback', methods=['POST'])
@require_permission('config_write')
def rollback(id):
    """Restore an earlier body. Appends a version; deletes nothing."""
    visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    exc = store.get(int(body.get('exc_id') or 0))
    if exc is None or exc.appliance_id != id:
        return jsonify(ok=False, error='carve-out not found'), 404
    res = versions.rollback(exc, int(body.get('version_id') or 0),
                            author=getattr(current_user, 'username', '') or '',
                            note=(body.get('note') or ''))
    if not res.get('ok'):
        return jsonify(**res), 400
    log_action('wpp_exception.rollback', target='wpp_exception:%d' % exc.id)
    return jsonify(**res)


@bp.route('/<int:id>/restorable')
@login_required
def restorable(id):
    """Carve-outs deleted on this scope whose history can bring them back."""
    visible_appliance_or_404(id)
    return jsonify(ok=True, items=versions.restorable_for(id))


@bp.route('/<int:id>/restore', methods=['POST'])
@require_permission('config_write')
def restore(id):
    """Re-create a deleted carve-out from the last body its lineage recorded."""
    visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    res = versions.restore((body.get('lineage') or '').strip(), appliance_id=id,
                           author=getattr(current_user, 'username', '') or '')
    if not res.get('ok'):
        return jsonify(**res), 400
    log_action('wpp_exception.restore', target='wpp_exception:%s' % res.get('exc_id'))
    return jsonify(**res)


@bp.route('/<int:id>/detect', methods=['POST'])
@require_permission('config_write')
def detect(id):
    """Read live per-signature exceptions off the device, bound to their policy."""
    appliance = visible_appliance_or_404(id)
    bindings = _policy_wpp_bindings(appliance)
    if not bindings:
        return jsonify(ok=False, error='no server policies / device unreachable', found=[])
    try:
        found = exception_detect.detect_signature_exceptions(
            exception_detect.ClientReader(FortiWebClient(appliance)), bindings)
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc), found=[])
    return jsonify(ok=True, found=found, policies=len(bindings))


@bp.route('/<int:id>/detect-import', methods=['POST'])
@require_permission('config_write')
def detect_import(id):
    """Import chosen detected carve-outs into desired-state (idempotent)."""
    appliance = visible_appliance_or_404(id)
    body = request.get_json(silent=True) or {}
    incoming = body.get('found') or []
    existing = store.list_exceptions(appliance.id, store.CAT_SIGNATURE)

    def _dup(d):
        sid = (d.get('payload') or {}).get('signature_id') or d.get('signature_id')
        pol = d.get('policy')
        return any(e.wpp_mkey == d.get('wpp') and e.payload_dict.get('signature_id') == sid
                   and pol in (e.policy_names or []) for e in existing)

    author = getattr(current_user, 'username', '') or ''
    fresh = [d for d in incoming if not _dup(d)]

    def _add(**kw):
        store.add(appliance.id, author=author, **kw)

    n = exception_detect.import_detected_signature_exceptions(fresh, add=_add)
    return jsonify(ok=True, imported=n, skipped=len(incoming) - n)
