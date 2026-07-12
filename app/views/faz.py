"""FortiAnalyzer manager area — the FAZ ADOM shell.

FortiAnalyzer is a log aggregator / SIEM. Unlike FortiWeb/FortiADC (REST/CMDB
object browsers) it speaks JSON-RPC and its 'objects' are logs, reports, event
handlers and incidents — so the Configuration / Operation / Automation sections
are honest scaffolds (:mod:`app.services.faz_menu`) until a FortiAnalyzer
JSON-RPC client is wired. Everything else is real from day one: the Fleet
(Architecture / Analysis / Metrics) and Administration (Appliances / Audit /
Firmware / Network segment) areas reuse the SAME shared, product-scoped
blueprints every ADOM uses; the DB row carries cap_firmware/cap_tokens so
Firmware and API tokens scope to this ADOM automatically.
"""
from __future__ import annotations

from flask import (Blueprint, abort, redirect, render_template, request,
                   url_for)
from flask_login import login_required

from ..models import Appliance, visible_appliances, visible_appliance_or_404
from ..services import device_context, faz_menu

bp = Blueprint('faz', __name__, url_prefix='/faz')


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


@bp.route('/m/<item_key>')
@login_required
def menu_page(item_key):
    """One Configuration/Operation/Automation leaf — an honest scaffold until
    the FortiAnalyzer JSON-RPC backend exists."""
    found = faz_menu.find_item(item_key)
    if not found:
        abort(404)
    group, item = found
    return render_template('faz/section.html', group=group, item=item,
                           fleet=_faz_fleet(), appliance=_current_faz())
