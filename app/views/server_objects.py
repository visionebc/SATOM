"""Server Objects — the FortiWeb GUI **Server Objects** menu, web port.

Device → the GUI-faithful Server Objects menu (Server / Protected Hostnames /
Service / Certificates / SSL Ciphers / Global / X-Forwarded-For / IP Group) →
the live object list of a chosen type → the SAME generic recursive editor
(:mod:`app.views.objedit`) every other config area uses, so each object's
by-parent sub-tables (pool members, VIP list, SNI members, health rules, content
-routing match conditions…) are edited in place, several levels deep.

The menu SET + grouping comes from :mod:`app.services.server_objects` (explicit,
registry-resolved); the live OBJECTS are fetched here through
:class:`FortiWebClient` (parent-scoped reads via the editor). Reads are open to
any signed-in user; New/Edit/Delete are ``config_write`` + audited + dry-run
default, exactly like ``objedit``.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request, abort
from flask_login import login_required

from ..models import Appliance
from ..models import visible_appliances, visible_appliance_or_404
from ..clients.fortiweb import FortiWebClient
from ..services import objform
from ..services import server_objects as so

bp = Blueprint('server_objects', __name__, url_prefix='/server-objects')


def _row_view(obj: dict) -> dict:
    """A compact list-row projection (name + a couple of GUI-meaningful fields)."""
    if not isinstance(obj, dict):
        return {'name': str(obj), 'status': '', 'detail': ''}
    name = obj.get('name') or obj.get('mkey') or obj.get('id') or '—'
    status = obj.get('status') or ''
    # Pick the first non-empty "describing" field for a generic 2nd column.
    detail = ''
    for k in ('comment', 'comments', 'type', 'ip', 'ipv4-address', 'vip',
              'deployment-mode', 'server-balance', 'lb-algo', 'domain', 'port',
              'load-balance', 'persistence'):
        v = obj.get(k)
        if v not in (None, '', []):
            detail = '%s: %s' % (k, v)
            break
    return {'name': name, 'status': status, 'detail': detail}


@bp.route('/')
@login_required
def index():
    """Appliance picker — choose a device to browse its Server Objects."""
    appliances = visible_appliances().order_by(Appliance.name).all()
    from flask import redirect as _redir, url_for as _ufor
    from ..services import device_context as _dc
    _cur = _dc.current_appliance()
    if _cur is None:
        return _redir(_ufor('architecture.index'))
    return _redir(_ufor('server_objects.overview', id=_cur.id))


@bp.route('/<int:id>')
@login_required
def overview(id):
    """The Server Objects menu for one device, plus the selected type's objects.

    ``?type=<logical>`` selects a menu leaf; its live objects are fetched and
    listed. With no ``type`` the page shows the menu with a hint to pick one.
    """
    appliance = visible_appliance_or_404(id)
    menu = so.server_objects_menu()

    selected = None
    rows: list[dict] = []
    error = None
    freshness = None
    logical = (request.args.get('type') or '').strip()
    if logical:
        selected = so.type_for(logical)
        if selected is None:
            abort(404)
        # DB-first: serve the object list from the local source of truth; the
        # device is touched only on an explicit refresh (server_objects.refresh).
        from ..services import read_layer
        payloads, meta = read_layer.read_objects(appliance.id, logical)
        rows = [_row_view(o) for o in payloads]
        freshness = read_layer.freshness_label(meta)

    return render_template(
        'server_objects/overview.html',
        appliance=appliance,
        menu=menu,
        selected=selected,
        rows=rows,
        error=error,
        freshness=freshness if logical else None,
    )


@bp.route('/<int:id>/refresh', methods=['POST'])
@login_required
def refresh(id):
    """Pull live config into the local source of truth, then return to the
    selected Server Objects type (DB-first)."""
    from flask import redirect, url_for, flash
    from flask_login import current_user
    appliance = visible_appliance_or_404(id)
    logical = (request.form.get('type') or '').strip()
    try:
        from ..services import device_sync
        run = device_sync.sync_device(appliance, publish=False,
                                      user_label=getattr(current_user, 'username', None),
                                      trigger='manual')
        flash(f"Refreshed from {appliance.name}: {run.detail}",
              "success" if run.status == 'ok' else "danger")
    except Exception as exc:  # noqa: BLE001
        flash(f"Refresh failed: {exc}", "danger")
    return redirect(url_for('server_objects.overview', id=id, type=logical) if logical
                    else url_for('server_objects.overview', id=id))
