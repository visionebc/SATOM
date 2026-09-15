"""FortiWeb object **Structure** — dependency tree + registry coverage cross-reference.

Port of the desktop "Settings -> Structure" page. The read view (admin section)
shows three things over the built-in exporter capture
(:mod:`app.registry.dependencies`):

* (a) the ``├──/└──`` **box tree** of FortiWeb objects and sub-elements,
* (b) a **cross-reference table** [object | URN | in registry?] resolved against
  the endpoint registry (:func:`app.registry.loader.get_all_endpoints`),
* (c) **coverage stats** (matched / fetchable / missing).

An admin-only **overlay** (persisted as ``settings_store('structure.overlay')``)
is merged on top of the seed so the shape can be tweaked without code changes —
add / edit / remove / reorder nodes via a JSON overlay. The catalog is built
lazily inside the request, so importing this blueprint has no side effects.
"""
from __future__ import annotations

import json

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..registry import loader
from ..services import cli_coverage
from ..services import settings_store as store
from ..services import structure
from ..services.audit import log_action

bp = Blueprint('structure', __name__, url_prefix='/structure')

# Overlay persistence key. NOTE: kept local (the task forbids adding key
# constants to settings_store.py); store.get_json/set_json take the raw key.
_OVERLAY_KEY = 'structure.overlay'


def _truthy(val: str | None) -> bool:
    return (val or '').strip().lower() in ('1', 'true', 'on', 'yes')


@bp.route('/')
@login_required
def index():
    """Render the box tree, the registry cross-reference and coverage stats."""
    overlay = store.get_json(_OVERLAY_KEY, {})
    show_urn = _truthy(request.args.get('urns'))

    # The tree itself is deliberately NOT versioned. ``dependencies.ROOTS`` is
    # a hand-authored dependency map, not a measurement: nobody has ever swept
    # "the structure of 8.0.5". Minting a per-build tree would be inventing
    # evidence and would look exactly like having measured it. What IS
    # per-build is what a build SERVES and what its CLI dump holds, and those
    # are the two columns the scope below drives.
    cat = structure.load_catalog(overlay)
    tree = cat.tree()
    matched, fetchable, missing = structure.coverage(tree)

    # Which transport serves each node. Resolved by REGISTRY NAME when the
    # URN is in the catalog and by URN when it is not — and the second case
    # is the interesting one: a node the registry does not cover but the CLI
    # dump does is a gap this table exists to expose, and a name-only lookup
    # would print '—' over it.
    # ONE report for the whole page. ``cli_coverage.provenance()`` would parse
    # the dump a second time to answer a question this diff already contains,
    # and two parses of one 690 KB file can disagree the moment a capture lands
    # between them.
    # --- which firmware this page is about ---------------------------------
    # Until 2026-09-16 the answer was "whichever dump sorted first", and the
    # page never said so. Everything below — the transport badges, the CLI-only
    # subtree, the clone gap — comes out of ONE report, so an unnamed dump made
    # the whole page an unattributed claim about an unknown build.
    #
    # The scope is a FILTER and never a fallback: a build with no dump reports
    # no CLI evidence rather than borrowing another build's, because 8.0.4 and
    # 8.0.7 are both "8.0" and their CLI is not the same.
    from ..services import api_matrix, firmware_versions
    matrix = firmware_versions.overlay(
        'fortiweb', api_matrix.load('fortiweb') or {'lines': {}, 'versions': {}})
    scope_versions = sorted((matrix.get('versions') or {}),
                            key=firmware_versions.sort_key)
    scope_lines = sorted(matrix.get('lines') or {})
    scope = (request.args.get('scope') or '').strip()
    if scope not in set(scope_versions) | set(scope_lines):
        scope = ''
    scope_doc, scope_kind = api_matrix.resolve_scope(matrix, scope)

    rep = cli_coverage.report(
        'fortiweb',
        version=scope if scope_kind == 'version' else '',
        line=scope if scope_kind == 'line' else '')
    diff = rep['diff']
    prov = cli_coverage.provenance_from(diff, rep.get('chosen'))
    rows = structure.cross_reference(tree)

    # The REST half of the same question, per build. ``api`` is a THIRD state
    # beside matched/missing: the registry can name an endpoint that this build
    # does not serve, and those two facts have been indistinguishable on this
    # page since it was written.
    served = (scope_doc or {}).get('endpoints') or {}
    cli_counts, api_counts = {}, {}
    for r in rows:
        if not r['urn']:
            r['cli'] = None          # a grouping node addresses nothing
            r['api'] = None
            continue
        r['cli'] = (prov.for_name(r['endpoint']) if r['endpoint']
                    else prov.for_urn(r['urn']))
        cli_counts[r['cli']['bucket']] = cli_counts.get(r['cli']['bucket'], 0) + 1
        # Three outcomes that never merge: served / absent / unmeasured on this
        # build. With no scope chosen the answer is None — "nobody asked about
        # a firmware" — which is not the same as "unmeasured", and rendering it
        # as a verdict would put a claim where a question mark belongs.
        if not scope:
            r['api'] = None
        else:
            hit = served.get(r['endpoint']) if r['endpoint'] else None
            if hit is None:
                r['api'] = {'verdict': 'unmeasured',
                            'attested_on': [], 'silent_on': []}
            else:
                r['api'] = {'verdict': hit.get('verdict') or 'unmeasured',
                            'attested_on': hit.get('attested_on') or [],
                            'silent_on': hit.get('silent_on') or []}
            api_counts[r['api']['verdict']] = api_counts.get(r['api']['verdict'], 0) + 1

    # The elements the dependency tree CANNOT contain: the seed was captured by
    # walking REST, so anything REST never names is missing from it by
    # construction. They render as their own root — never grafted into the
    # Server Policy / WPP subtree, because a CLI block has no ``via`` edge and
    # inventing one produces a tree that looks complete and a clone the
    # appliance rejects (dependencies.py records that failure, measured).
    cli_tree = structure.cli_only_nodes(diff)
    cli_rows = structure.cli_cross_reference(cli_tree)
    clone_gap = structure.clone_gap(diff)
    from ..models import Appliance, visible_appliances
    probe_appliances = (visible_appliances()
                        .filter(Appliance.kind == 'fortiweb')
                        .order_by(Appliance.name).all())

    return render_template(
        'structure/index.html',
        box=structure.render_box(tree, show_urn=show_urn),
        cli_box=(structure.render_box(cli_tree, show_urn=False) if cli_tree else ''),
        cli_rows=cli_rows,
        cli_evidence=rep.get('chosen'),
        cli_supported=bool(diff.get('supported')),
        cli_reason=diff.get('reason') or '',
        clone_gap=clone_gap,
        probe_appliances=probe_appliances,
        rows=rows,
        prov=prov,
        cli_counts=cli_counts,
        api_counts=api_counts,
        scope=scope,
        scope_kind=scope_kind,
        scope_versions=scope_versions,
        scope_lines=scope_lines,
        scope_heterogeneous=bool((scope_doc or {}).get('heterogeneous')),
        scope_members=(scope_doc or {}).get('measured_versions') or [],
        functions=cat.functions(),
        matched=matched,
        fetchable=fetchable,
        missing=missing,
        total_nodes=structure.node_count(tree),
        total_endpoints=len(loader.get_all_endpoints()),
        pct=(round(matched * 100 / fetchable) if fetchable else 0),
        show_urn=show_urn,
        has_overlay=bool(overlay),
        overlay_json=(json.dumps(overlay, indent=2) if overlay else ''),
    )


@bp.route('/save', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save():
    """Persist (or reset/clear) the admin overlay JSON. Admin only."""
    action = request.form.get('action', 'save')

    if action == 'reset':
        store.set_json(_OVERLAY_KEY, {})
        log_action('structure.save', target='overlay',
                   detail='Reset structure overlay to built-in defaults')
        flash('Structure overlay reset to the built-in defaults.', 'success')
        return redirect(url_for('structure.index'))

    raw_text = (request.form.get('overlay') or '').strip()
    if not raw_text:
        store.set_json(_OVERLAY_KEY, {})
        log_action('structure.save', target='overlay', detail='Cleared structure overlay')
        flash('Structure overlay cleared.', 'success')
        return redirect(url_for('structure.index'))

    try:
        data = json.loads(raw_text)
        cleaned = structure.validate_overlay(data)
    except (ValueError, TypeError) as exc:
        flash(f'Invalid overlay: {exc}', 'danger')
        return redirect(url_for('structure.index'))

    store.set_json(_OVERLAY_KEY, cleaned)
    log_action('structure.save', target='overlay',
               detail=f'Saved structure overlay ({len(cleaned.get("added", []))} added, '
                      f'{len(cleaned.get("edited", {}))} edited, '
                      f'{len(cleaned.get("removed", []))} removed)')
    flash('Structure overlay saved.', 'success')
    return redirect(url_for('structure.index'))
