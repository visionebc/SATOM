"""FortiAnalyzer manager area — the FAZ ADOM shell.

FortiAnalyzer is a log aggregator / SIEM: it speaks JSON-RPC and its 'objects'
are logs, reports, event handlers and incidents. The Configuration / Device
Manager / Operation / Automation sections are curated menu leaves
(:mod:`app.services.faz_menu`) whose tabs bind to registry endpoints
(product='fortianalyzer', DB-first — see ``registry.loader.load_faz_registry``)
and render LIVE device data through
:class:`app.clients.fortianalyzer.FortiAnalyzerClient`. The Fleet
(Architecture / Analysis / Metrics) and Administration (Appliances / Audit /
Firmware / Network segment) areas reuse the SAME shared, product-scoped
blueprints every ADOM uses; the DB row carries cap_firmware/cap_tokens so
Firmware and API tokens scope to this ADOM automatically.
"""
from __future__ import annotations

from flask import (Blueprint, abort, redirect, render_template, request,
                   url_for)
from flask_login import login_required

from ..clients.fortianalyzer import FortiAnalyzerClient
from ..models import Appliance, visible_appliances, visible_appliance_or_404
from ..registry import loader
from ..services import device_context, faz_menu

bp = Blueprint('faz', __name__, url_prefix='/faz')

# Section pages are browse views — keep row counts honest but bounded.
_MAX_ROWS = 500


def _current_faz() -> Appliance | None:
    appl = device_context.current_appliance()
    if appl is not None and appl.kind == 'fortianalyzer':
        return appl
    return None


def _faz_fleet():
    return (visible_appliances().filter_by(kind='fortianalyzer')
            .order_by(Appliance.name).all())


@bp.route('/')
@login_required
def index():
    """FortiAnalyzer dashboard + device picker."""
    groups = faz_menu.menu()
    n_items = sum(len(g.items) for g in groups)
    return render_template('faz/index.html', fleet=_faz_fleet(), groups=groups,
                           n_items=n_items, current=_current_faz())


@bp.route('/use/<int:id>')
@login_required
def use_device(id):
    appl = visible_appliance_or_404(id)
    if appl.kind != 'fortianalyzer':
        abort(404)
    device_context.set_current(appl.id)
    nxt = request.args.get('next')
    return redirect(nxt if nxt and nxt.startswith('/faz') else url_for('faz.index'))


def _columns_for(rows: list) -> list:
    """Display columns: union of the first rows' keys, 'name' first, capped so
    wide CLI objects stay readable (the full object is in the row expander)."""
    cols: list = []
    for r in rows[:25]:
        for k in r:
            if k not in cols and not k.startswith('_') and k != 'obj flags':
                cols.append(k)
    for lead in ('name', 'mkey', 'id'):
        if lead in cols:
            cols.remove(lead)
            cols.insert(0, lead)
    return cols[:8]


def _load_tab(appliance, logical: str, label: str) -> dict:
    """Fetch ONE tab live (the ADC pattern: a page reload per tab keeps every
    request one device round-trip). A device refusal / moved URI degrades to
    an inline error — the page shell stays up."""
    reg = loader.load_faz_registry()
    tab = {'logical': logical, 'label': label, 'urn': reg.get(logical),
           'rows': [], 'kv': None, 'columns': [], 'error': None,
           'truncated': False}
    client = FortiAnalyzerClient(appliance, timeout=20.0)
    rows, err = client.list_with_error(logical)
    try:
        client.logout()
    except Exception:  # noqa: BLE001 — best-effort session hygiene
        pass
    if err:
        tab['error'] = err
        return tab
    rows = [r for r in rows if isinstance(r, dict)]
    if len(rows) == 1 and not logical.startswith('dvmdb_'):
        # single config object → key/value card (CLI 'get' style)
        tab['kv'] = rows[0]
    else:
        tab['truncated'] = len(rows) > _MAX_ROWS
        tab['rows'] = rows[:_MAX_ROWS]
        tab['columns'] = _columns_for(tab['rows'])
    return tab


@bp.route('/m/<item_key>')
@login_required
def menu_page(item_key):
    """One menu leaf: live registry-bound tabs off the selected FortiAnalyzer."""
    found = faz_menu.find_item(item_key)
    if not found:
        abort(404)
    group, item = found
    appliance = _current_faz()
    tab = None
    if appliance and item.logicals:
        wanted = (request.args.get('tab') or '').strip()
        logical, label = item.logicals[0]
        for lg, lb in item.logicals:
            if lg == wanted:
                logical, label = lg, lb
                break
        tab = _load_tab(appliance, logical, label)
    return render_template('faz/section.html', group=group, item=item,
                           fleet=_faz_fleet(), appliance=appliance, tab=tab)
