"""Global ADOM — the fleet-wide landing at ``/``.

One dashboard spanning EVERY product ADOM: device counts, running jobs,
certificate posture and quick links into every fleet-wide section. The route
itself lives in the app factory (endpoint ``index``, path ``/``) so legacy
``url_for('index')`` callers keep working — this module only gathers the data
and renders.

**The ADOM roster is DERIVED here, never listed.** Until 2026-08-06 this module
built exactly two lists (``fw`` / ``adc``) and the template rendered exactly
two stat-cards. FortiAuthenticator and FortiAnalyzer had both been real
products for a day by then; neither had a card, and ``fac01`` was missing from
the fleet table as well. Nothing raised — the console that exists to see the
WHOLE fleet simply did not know half of it existed, which is the worst possible
place for a hardcoded product list to rot.

The roster now comes from :func:`app.services.product_scope.device_products`,
the same registry-backed enumeration the appliance forms use, so a product
declared in Settings → ADOMs appears here the day it is declared.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from flask import current_app, render_template

from ..branding import get_product
from ..models import Appliance, visible_appliances
from ..services.product_scope import device_products

# The one fact about an ADOM that is NOT in the registry: which blueprint owns
# its device view. Same resolution ``partials/nav_device_context.html`` does for
# its Device link (fortiadc → adc, fortianalyzer → faz, fortiauthenticator →
# fac); FortiWeb has no device blueprint of its own and uses the shared
# appliance page. A key missing from this map is NOT broken — _open_endpoint()
# probes the URL map and falls back to ``appliances.detail``, which every kind
# has. That is why a fifth ADOM still gets a working row on day one.
_ADOM_BLUEPRINT = {
    'fortiadc': 'adc',
    'fortianalyzer': 'faz',
    'fortiauthenticator': 'fac',
}

# Appliances predating the ``kind`` column carry NULL/'' and are FortiWeb-era by
# construction — the same rule services/product_scope.py applies to its filters.
_LEGACY_KIND = 'fortiweb'


def _open_endpoint(kind: str) -> str:
    """Endpoint that opens a ``kind`` device in its OWN ADOM, or the shared
    appliance detail page when that product has no device view."""
    bp = _ADOM_BLUEPRINT.get(kind, kind)
    endpoint = '%s.use_device' % bp
    if endpoint in current_app.view_functions:
        return endpoint
    return 'appliances.detail'


def adom_cards(fleet: list) -> list[dict]:
    """One entry per ACTIVE product ADOM, in registry order.

    ``fleet`` is passed in rather than re-queried so the counts, the rows and
    the fleet table are all the same scoped result set.
    """
    cards = []
    for key, name in device_products():
        prod = get_product(key)
        rows = [a for a in fleet if (a.kind or _LEGACY_KIND) == key]
        cards.append({
            'key': key,
            'name': name,
            'mark': prod.get('mark') or 'img/global-mark.svg',
            'n_appliances': len(rows),
            'appliances': rows,
            'open_endpoint': _open_endpoint(key),
        })
    return cards


def dashboard():
    fleet = visible_appliances().order_by(Appliance.kind, Appliance.name).all()
    adoms = adom_cards(fleet)

    # Registry order for the table (fortiweb, fortiadc, … ), then anything the
    # registry does not claim. A device whose kind matches no ACTIVE ADOM is
    # visible in the Global ADOM and NOWHERE else (see
    # product_scope.scope_appliance_query), so dropping it here would hide it
    # from the only console that can still show it.
    claimed = {a.id for c in adoms for a in c['appliances']}
    rows = [a for c in adoms for a in c['appliances']]
    rows += [a for a in fleet if a.id not in claimed]

    # kind -> badge/link metadata, so the template branches on nothing.
    kind_meta = {c['key']: {'name': c['name'], 'mark': c['mark'],
                            'open_endpoint': c['open_endpoint']}
                 for c in adoms}

    jobs_running = 0
    try:
        from ..services import jobs as jobsvc
        jobs_running = len(jobsvc.list_jobs(active_only=True, limit=200))
    except Exception:  # noqa: BLE001 — dashboard stays up without the jobs dir
        pass

    certs = {'total': 0, 'expiring': 0}
    try:
        from ..models import DeviceCertificate
        soon = datetime.utcnow() + timedelta(days=30)
        certs['total'] = DeviceCertificate.query.count()
        certs['expiring'] = (DeviceCertificate.query
                             .filter(DeviceCertificate.not_after.isnot(None))
                             .filter(DeviceCertificate.not_after <= soon)
                             .count())
    except Exception:  # noqa: BLE001
        pass

    return render_template('global_home/index.html', adoms=adoms, fleet=rows,
                           kind_meta=kind_meta, jobs_running=jobs_running,
                           certs=certs)
