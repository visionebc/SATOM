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

    cat = structure.load_catalog(overlay)
    tree = cat.tree()
    matched, fetchable, missing = structure.coverage(tree)

    return render_template(
        'structure/index.html',
        box=structure.render_box(tree, show_urn=show_urn),
        rows=structure.cross_reference(tree),
        functions=cat.functions(),
        matched=matched,
        fetchable=fetchable,
        missing=missing,
        total_nodes=structure.node_count(tree),
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
