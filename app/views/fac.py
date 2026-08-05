"""FortiAuthenticator manager area — the FAC ADOM shell.

FortiAuthenticator is an identity provider: its "objects" are users, groups,
tokens, certificates and the RADIUS/TACACS+ clients that authenticate against
it. The sidebar mirrors the REAL FAC 8.0.3 GUI panes (:mod:`app.services
.fac_menu`, captured from the unit's own ``nav_menu_definition``); every leaf's
tabs bind to registry endpoints (product='fortiauthenticator', DB-first — see
``registry.loader.load_fac_registry``) and render LIVE device data through
:class:`app.clients.fortiauthenticator.FortiAuthenticatorClient`.

**Section pages are READ-ONLY, deliberately.** FortiWeb/FortiADC/FortiAnalyzer
grew editable config tabs on top of a dry-run contract that took several
iterations to get right. Rather than ship a fourth copy of that machinery
unproven against this device, writes live in the API console
(:mod:`app.views.fac_api`) where every request is explicit, permission-gated,
dry-run by default and audited. The read path is what makes the fleet
observable; the write path can grow later against the same registry without
moving anything here.

A device refusal is NEVER rendered as an empty table: the client surfaces it as
an error and the tab shows it inline, because "this appliance has no users" and
"the API key was rejected" look identical once you flatten them to a row count.

The Fleet (Architecture / Analysis / Metrics) and Administration (Appliances /
Audit / Network segment) areas are NOT here — they reuse the SAME shared,
product-scoped blueprints every ADOM uses.
"""
from __future__ import annotations

from flask import (Blueprint, abort, redirect, render_template, request,
                   url_for)
from flask_login import login_required

from ..clients.fortiauthenticator import FortiAuthenticatorClient
from ..models import Appliance, visible_appliances, visible_appliance_or_404
from ..registry import loader
from ..services import device_context, fac_menu

bp = Blueprint('fac', __name__, url_prefix='/fac')

# Section pages are browse views — keep row counts honest but bounded. The tab
# reports the truncation explicitly rather than quietly showing a prefix.
_MAX_ROWS = 500

# Columns worth leading with, per FortiAuthenticator's own field naming.
_LEAD_COLUMNS = ('name', 'username', 'label', 'id')

# Never render these into a table cell even if a future firmware starts
# returning them. Verified 2026-08-05 that the device omits them today; this is
# the belt to that braces, because the cost of being wrong is a credential in a
# browser cache and in every screenshot of this page.
_NEVER_RENDER = ('password', 'secret', 'passwd', 'private_key', 'api_key')


def _current_fac() -> Appliance | None:
    appl = device_context.current_appliance()
    if appl is not None and appl.kind == 'fortiauthenticator':
        return appl
    return None


def _fac_fleet():
    return (visible_appliances().filter_by(kind='fortiauthenticator')
            .order_by(Appliance.name).all())


@bp.route('/')
@login_required
def index():
    """FortiAuthenticator dashboard + device picker."""
    groups = fac_menu.visible_menu()
    items = fac_menu.all_items()
    fleet = _fac_fleet()
    current = _current_fac()
    # With a single FAC appliance the header should always describe it, even
    # before an explicit pick — otherwise the device banner looks 'missing'.
    header_dev = current or (fleet[0] if len(fleet) == 1 else None)

    status, status_err = {}, None
    if header_dev is not None:
        client = FortiAuthenticatorClient(header_dev, timeout=15.0)
        try:
            status = client.sys_status()
        except Exception as exc:  # noqa: BLE001 — dashboard must still render
            status_err = str(exc)

    return render_template('fac/index.html', fleet=fleet, groups=groups,
                           n_items=len(items),
                           n_bound=sum(1 for i in items if i.logicals),
                           current=current, header_dev=header_dev,
                           status=status, status_err=status_err)


@bp.route('/use/<int:id>')
@login_required
def use_device(id):
    appl = visible_appliance_or_404(id)
    if appl.kind != 'fortiauthenticator':
        abort(404)
    device_context.set_current(appl.id)
    nxt = request.args.get('next')
    return redirect(nxt if nxt and nxt.startswith('/fac') else url_for('fac.index'))


def _columns_for(rows: list) -> list:
    """Display columns: union of the first rows' keys, identity fields first,
    capped so wide objects stay readable (the full object is in the expander)."""
    cols: list = []
    for r in rows[:25]:
        for k in r:
            if k in cols or k.startswith('_'):
                continue
            if k in _NEVER_RENDER or k == 'resource_uri':
                continue
            cols.append(k)
    for lead in reversed(_LEAD_COLUMNS):
        if lead in cols:
            cols.remove(lead)
            cols.insert(0, lead)
    return cols[:8]


def _scrub(row: dict) -> dict:
    """Drop never-render fields from one row before it reaches a template."""
    return {k: v for k, v in row.items() if k not in _NEVER_RENDER}


def _load_tab(appliance, logical: str, label: str) -> dict:
    """Fetch ONE tab live (the ADC/FAZ pattern: a page reload per tab keeps
    every request to a single device round-trip). A device refusal or a moved
    URI degrades to an inline error — the page shell stays up."""
    reg = loader.load_fac_registry()
    urn = reg.get(logical) or ''
    tab = {'logical': logical, 'label': label, 'urn': urn,
           'rows': [], 'kv': None, 'columns': [], 'error': None,
           'truncated': False, 'total': 0}

    client = FortiAuthenticatorClient(appliance, timeout=20.0)
    rows, err = client.list_with_error(logical)
    if err:
        # A partial read still carries rows; show BOTH so a truncated harvest
        # can never read as a complete one.
        tab['error'] = err
    rows = [_scrub(r) for r in rows if isinstance(r, dict)]
    tab['total'] = len(rows)

    if len(rows) == 1 and _is_singleton(rows[0]):
        tab['kv'] = rows[0]                      # singleton → key/value card
    else:
        tab['truncated'] = len(rows) > _MAX_ROWS
        tab['rows'] = rows[:_MAX_ROWS]
        tab['columns'] = _columns_for(tab['rows'])
    return tab


def _is_singleton(row: dict) -> bool:
    """A Tastypie *collection* row always carries ``resource_uri``; the
    singleton resources (system_info, log settings, lockout policy, …) do not.

    Keyed on the payload, not on a hand-written list of singleton names — the
    registry YAML is already the one place resources are enumerated, and a
    parallel list would rot the first time the vendor changes a shape.
    """
    return 'resource_uri' not in row


@bp.route('/m/<item_key>')
@login_required
def menu_page(item_key):
    """One menu leaf: live registry-bound tabs off the selected FortiAuthenticator."""
    group, item = fac_menu.find_item(item_key)
    if item is None:
        abort(404)
    appliance = _current_fac()
    tab = None
    if appliance is not None and item.logicals:
        wanted = (request.args.get('tab') or '').strip()
        logical, label = item.logicals[0]
        for lg, lb in item.logicals:
            if lg == wanted:
                logical, label = lg, lb
                break
        tab = _load_tab(appliance, logical, label)
    return render_template('fac/section.html', group=group, item=item,
                           fleet=_fac_fleet(), appliance=appliance, tab=tab)
