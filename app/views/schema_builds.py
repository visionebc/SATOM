"""Schema builds: the adapters, the builds nobody harvested, and the diff after a harvest.

One page for the five products (``services.schema_adapters``):

* every adapter with its capabilities and whether it was verified on a device
  (and which device and build) -- an unverified adapter says so, with why;
* the appliances whose running build has no harvested schema
  (``services.schema_watch``), each with a one-click harvest when the adapter
  can run live;
* after a harvest (or on request) the comparison of a build with the closest
  harvested build of the same product, item by item, with the channel of each
  new/changed item on the new build and "to verify" when its REST side was
  not measured there.

Reading is ``registry.view`` (the API pages' gate); harvesting reaches out to
a device, so it is ``appliances.apply``, like the API Explorer's harvest.
"""
from __future__ import annotations

import logging

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_babel import gettext as _
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import visible_appliance_or_404
from ..services.audit import log_action

log = logging.getLogger(__name__)

bp = Blueprint('schema_builds', __name__, url_prefix='/schema-builds')


def _harvested() -> dict:
    """``{product: [versions with the adapter's schema source]}``."""
    from ..services import schema_adapters as sa
    from ..services import schema_watch as sw
    out = {}
    for a in sa.all_adapters():
        try:
            out[a.product] = sw._harvested_versions(a.product, a.cli_source)
        except Exception:  # noqa: BLE001 — a listing, never a reason to 500
            out[a.product] = []
    return out


@bp.route('/')
@login_required
@require_permission('registry.view')
def index():
    from ..services import schema_adapters as sa
    from ..services import schema_watch as sw
    adapters = [a.to_dict() for a in sa.all_adapters()]
    pending = sw.scan(notify=False)
    focus = request.args.get('appliance', type=int)
    product = (request.args.get('product') or '').strip()
    version = (request.args.get('version') or '').strip()
    diff = None
    if product and version and sa.get(product) is not None:
        try:
            diff = sw.diff_after_harvest(product, version)
        except Exception as exc:  # noqa: BLE001 — shown, not raised
            log.warning('schema diff %s %s failed: %s', product, version, exc)
            diff = {'product': product, 'version': version, 'items': [],
                    'reason': 'the comparison could not be computed: %s' % exc}
    return render_template('registry/schema_builds.html', adapters=adapters,
                           pending=pending, focus=focus, harvested=_harvested(), diff=diff)


@bp.route('/harvest/<int:appliance_id>', methods=['POST'])
@login_required
@require_permission('appliances.apply')
def harvest(appliance_id):
    """One-click harvest of one appliance's build through its adapter, then
    the diff against the closest harvested build."""
    from ..services import schema_adapters as sa
    appliance = visible_appliance_or_404(appliance_id)
    kw = {}
    if appliance.kind == 'fortiauthenticator':
        # The CLI walk needs a CLI login SATOM does not store for FAC (its
        # appliance secret is the REST API key). Used for this request only.
        secret = request.form.get('ssh_secret') or ''
        if secret:
            kw['ssh_secret'] = secret
    res = sa.harvest(appliance, **kw)
    log_action('schema_builds.harvest', target=appliance.name,
               extra={'appliance_id': appliance.id, 'ok': bool(res.get('ok')),
                      'version': res.get('version') or '', 'product': appliance.kind})
    flash(res.get('msg') or (_('Harvest done.') if res.get('ok') else _('Harvest failed.')),
          'success' if res.get('ok') else 'danger')
    if res.get('version'):
        return redirect(url_for('schema_builds.index', product=appliance.kind,
                                version=res['version']))
    return redirect(url_for('schema_builds.index', appliance=appliance.id))
