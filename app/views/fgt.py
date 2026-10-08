"""FortiGate manager area — the FGT ADOM shell (BASE, 2026-10-07).

A dashboard with the device picker and the live unit status, plus one
read-only section page per sidebar leaf (:mod:`app.services.fgt_menu`). Each
tab is ONE cmdb read through :class:`app.clients.fortigate.FortiGateClient`.

Read-only on purpose: no editor, no API console, no registry binding yet. Those
arrive as later rounds on top of this shell without moving it.

A device refusal is never rendered as an empty table (same contract as the
FortiAuthenticator ADOM): "no policies configured" and "the token was
refused" must not look alike.

The Fleet and Administration areas reuse the shared, product-scoped
blueprints every ADOM uses.
"""
from __future__ import annotations

from flask import (Blueprint, abort, redirect, render_template, request,
                   url_for)
from flask_login import login_required

from ..auth.decorators import require_permission
from ..clients.fortigate import FortiGateClient, cmdb_url
from ..models import Appliance, visible_appliances, visible_appliance_or_404
from ..services import device_context, fgt_menu

bp = Blueprint('fgt', __name__, url_prefix='/fgt')

# Browse views — bounded, and the truncation is reported, never silent.
_MAX_ROWS = 500

# Identity columns to lead with, in FortiOS field naming.
_LEAD_COLUMNS = ('name', 'policyid', 'seq-num', 'id', 'q_origin_key')

# FortiOS returns secrets as "ENC <base64>" — or, on some tables, in clear to a
# super_admin. Both are dropped before a row reaches a template: a credential
# in a page is a credential in every browser cache and screenshot.
_SECRET_KEYS = frozenset({
    'password', 'passwd', 'secret', 'psksecret', 'psksecret-remote',
    'private-key', 'passphrase', 'api-key', 'key', 'ppk-secret',
    'auth-password', 'priv-pwd', 'auth-pwd', 'radius-secret',
    'secondary-secret', 'tertiary-secret', 'server-key',
})


def _is_secret(key: str, value) -> bool:
    return key in _SECRET_KEYS or (isinstance(value, str)
                                   and value.startswith('ENC '))


def scrub(obj):
    """Recursively drop secret fields (by name, or by an ``ENC`` value)."""
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items() if not _is_secret(k, v)}
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    return obj


def _current_fgt() -> Appliance | None:
    appl = device_context.current_appliance()
    if appl is not None and appl.kind == 'fortigate':
        return appl
    return None


def _fgt_fleet():
    return (visible_appliances().filter_by(kind='fortigate')
            .order_by(Appliance.name).all())


@bp.route('/')
@login_required
@require_permission('view')
def index():
    """FortiGate dashboard + device picker."""
    groups = fgt_menu.visible_menu()
    current = _current_fgt()
    status, status_err = {}, None
    if current is not None:
        try:
            status = FortiGateClient(current, timeout=15.0).sys_status()
        except Exception as exc:  # noqa: BLE001 — dashboard must still render
            status_err = str(exc)
    return render_template('fgt/index.html', fleet=_fgt_fleet(), groups=groups,
                           n_items=sum(len(g.items) for g in groups),
                           n_paths=len(fgt_menu.all_paths()),
                           current=current, header_dev=current,
                           status=status, status_err=status_err)


@bp.route('/use/<int:id>')
@login_required
@require_permission('view')
def use_device(id):
    appl = visible_appliance_or_404(id)
    if appl.kind != 'fortigate':
        abort(404)
    device_context.set_current(appl.id)
    nxt = request.args.get('next')
    return redirect(nxt if nxt and nxt.startswith('/fgt') else url_for('fgt.index'))


def _columns_for(rows: list) -> list:
    """Display columns: identity fields first, then the scalar fields of the
    first rows in served order, capped (the full row is in the expander)."""
    cols: list = []
    for r in rows[:25]:
        for k, v in r.items():
            if k in cols or isinstance(v, (list, dict)):
                continue
            cols.append(k)
    for lead in reversed(_LEAD_COLUMNS):
        if lead in cols:
            cols.remove(lead)
            cols.insert(0, lead)
    if 'q_origin_key' in cols and len(cols) > 1:
        cols.remove('q_origin_key')     # duplicate of the mkey column
    return cols[:8]


def _not_in_gui(appliance, path, results):
    """"Not in GUI, but in CLI" for this table on the device's build (the
    fields FortiOS serves only by CLI). Secrets never reach the section."""
    from ..services import not_in_gui
    return not_in_gui.for_view(appliance, path, results,
                               noise=lambda k: k.startswith('q_') or _is_secret(k, None))


def _load_tab(appliance, path: str, label: str) -> dict:
    tab = {'path': path, 'label': label, 'url': cmdb_url(path),
           'rows': [], 'kv': None, 'columns': [], 'error': None,
           'truncated': False, 'total': 0}
    results, err = FortiGateClient(appliance, timeout=20.0).cmdb(path)
    if err:
        tab['error'] = err
        return tab
    tab['not_in_gui'] = _not_in_gui(appliance, path, results)
    if isinstance(results, dict):            # single-instance setting
        tab['kv'] = scrub(results)
        return tab
    rows = [scrub(r) for r in (results or []) if isinstance(r, dict)]
    tab['total'] = len(rows)
    tab['truncated'] = len(rows) > _MAX_ROWS
    tab['rows'] = rows[:_MAX_ROWS]
    tab['columns'] = _columns_for(tab['rows'])
    return tab


@bp.route('/m/<item_key>')
@login_required
@require_permission('view')
def menu_page(item_key):
    """One menu leaf: live cmdb tabs off the selected FortiGate."""
    group, item = fgt_menu.find_item(item_key)
    if item is None:
        abort(404)
    appliance = _current_fgt()
    tab = None
    if appliance is not None and item.tabs:
        wanted = (request.args.get('tab') or '').strip()
        path, label = item.tabs[0]
        for p, lb in item.tabs:
            if p == wanted:
                path, label = p, lb
                break
        tab = _load_tab(appliance, path, label)
    return render_template('fgt/section.html', group=group, item=item,
                           fleet=_fgt_fleet(), appliance=appliance, tab=tab)
