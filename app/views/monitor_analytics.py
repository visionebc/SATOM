"""Analytics — boards that compose many monitor series onto one chart.

Every other chart in Monitoring is bound to a single probe. This page answers
the comparative question ("how do the FortiWebs differ", "did throughput move
this month") that the per-probe drill-down structurally cannot.

Same contract as the rest of Monitoring: **a page load never touches an
appliance.** Everything renders from ``monitor_sample`` / ``monitor_rollup``
rows the sweep already recorded, so a board opens instantly and keeps opening
when every appliance is off.

Reads need VIEW. Creating, editing, deleting a board or a panel needs
CONFIG_WRITE. Built-in boards are reconciled from code and refuse edits at the
route, not merely in the template — a board whose Save button is hidden but
whose endpoint still writes is hidden, not read-only.
"""
from __future__ import annotations

import json

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Permission, db
from ..models_analytics import (SELECT_MODES, STAT_FUNCS, VIZ_KINDS,
                                MonitorDashboard, MonitorPanel)
from ..services import monitor_analytics as ma
from ..services.audit import log_action

bp = Blueprint('monitor_analytics', __name__, url_prefix='/monitoring/analytics')


def _product() -> str:
    from ..services.product_scope import GLOBAL, session_product
    p = session_product() or GLOBAL
    return "" if p == GLOBAL else p


def _boards():
    """Boards visible in this ADOM: Global-authored ones plus this product's.

    A board scoped to a product is invisible in Global on purpose — Global
    already sees every device, so a FortiWeb-only board there would duplicate a
    Global board with a narrower rule and no way to tell them apart.
    """
    prod = _product()
    q = MonitorDashboard.query
    if prod:
        q = q.filter(MonitorDashboard.product.in_(("", prod)))
    else:
        q = q.filter(MonitorDashboard.product == "")
    return q.order_by(MonitorDashboard.position, MonitorDashboard.title).all()


def _get_board(slug: str):
    for b in _boards():
        if b.slug == slug:
            return b
    return None


def _window():
    """Resolve the requested window from the query string."""
    from ..views.monitor_probes import _parse_dt
    return ma.range_bounds(request.args.get('range', ma.DEFAULT_RANGE),
                           frm=_parse_dt(request.args.get('from')),
                           to=_parse_dt(request.args.get('to')))


# --------------------------------------------------------------------------- #
#  Pages                                                                       #
# --------------------------------------------------------------------------- #
@bp.route('/')
@login_required
def index():
    boards = _boards()
    slug = request.args.get('board') or (boards[0].slug if boards else '')
    return render_template(
        'monitoring/analytics.html',
        boards=[b.to_dict() for b in boards],
        active_slug=slug,
        catalog=ma.metric_catalog(),
        ranges=list(ma.RANGES),
        default_range=ma.DEFAULT_RANGE,
        can_edit=current_user.can(Permission.CONFIG_WRITE),
        product_key=_product(),
    )


@bp.route('/data')
@login_required
def data():
    """Every panel of one board, over one consistent window."""
    board = _get_board(request.args.get('board', ''))
    if board is None:
        boards = _boards()
        if not boards:
            return jsonify({"ok": False, "error": "no boards"}), 404
        board = boards[0]
    start, end, key = _window()
    payload = ma.dashboard_payload(board, start, end)
    payload["range"] = key
    payload["ok"] = True
    return jsonify(payload)


@bp.route('/panel/<int:pid>/data')
@login_required
def panel_data(pid: int):
    """One panel, refreshed on its own (per-panel range, auto-refresh)."""
    panel = MonitorPanel.query.get(pid)
    if panel is None or _get_board_of(panel) is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    start, end, key = _window()
    out = ma.panel_payload(panel, start, end)
    out["range"] = key
    out["ok"] = True
    return jsonify(out)


def _get_board_of(panel):
    """The panel's board IF this ADOM may see it, else None.

    Scoping is checked through the board list rather than by reading
    ``panel.dashboard`` directly, so a panel on a board belonging to another
    product is a 404 here — it does not exist from this page's point of view.
    """
    for b in _boards():
        if b.id == panel.dashboard_id:
            return b
    return None


@bp.route('/catalog')
@login_required
def catalog():
    return jsonify({"ok": True, **ma.metric_catalog()})


@bp.route('/cadence')
@login_required
def cadence():
    """Declared vs effective collection cadence for every visible probe."""
    return jsonify({"ok": True, **ma.cadence_report()})


# --------------------------------------------------------------------------- #
#  Writes                                                                      #
# --------------------------------------------------------------------------- #
def _slugify(text: str, taken: set[str]) -> str:
    base = "".join(c if c.isalnum() else "-" for c in (text or "").lower())
    base = "-".join(x for x in base.split("-") if x)[:48] or "board"
    slug, n = base, 2
    while slug in taken:
        slug = "%s-%d" % (base, n)
        n += 1
    return slug


@bp.route('/board', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def create_board():
    title = (request.form.get('title') or '').strip() or 'New board'
    taken = {b.slug for b in MonitorDashboard.query.all()}
    board = MonitorDashboard(
        slug=_slugify(title, taken), title=title[:120],
        description=(request.form.get('description') or '')[:400],
        product=_product(),
        default_range=_one_of(request.form.get('default_range'),
                              ma.RANGES, ma.DEFAULT_RANGE),
        refresh_s=_int(request.form.get('refresh_s'), 0, 0, 3600),
        created_by=getattr(current_user, 'username', '') or '',
        position=_next_position(),
    )
    db.session.add(board)
    db.session.commit()
    log_action('analytics.board.create', board.slug, {"title": board.title})
    return jsonify({"ok": True, "board": board.to_dict()})


def _next_position() -> int:
    rows = MonitorDashboard.query.order_by(MonitorDashboard.position.desc()).first()
    return (rows.position + 1) if rows else 100


@bp.route('/board/<int:bid>', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def update_board(bid: int):
    board = _owned_board(bid)
    if board is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    if board.builtin:
        return jsonify({"ok": False,
                        "error": "Built-in boards are reconciled from code and "
                                 "cannot be edited. Duplicate it first."}), 403
    if 'title' in request.form:
        board.title = (request.form.get('title') or board.title)[:120]
    if 'description' in request.form:
        board.description = (request.form.get('description') or '')[:400]
    if 'default_range' in request.form:
        board.default_range = _one_of(request.form.get('default_range'),
                                      ma.RANGES, board.default_range)
    if 'refresh_s' in request.form:
        board.refresh_s = _int(request.form.get('refresh_s'), 0, 0, 3600)
    db.session.commit()
    log_action('analytics.board.update', board.slug, {"title": board.title})
    return jsonify({"ok": True, "board": board.to_dict()})


@bp.route('/board/<int:bid>/delete', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def delete_board(bid: int):
    board = _owned_board(bid)
    if board is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    if board.builtin:
        return jsonify({"ok": False,
                        "error": "Built-in boards cannot be deleted."}), 403
    slug = board.slug
    db.session.delete(board)
    db.session.commit()
    log_action('analytics.board.delete', slug, {})
    return jsonify({"ok": True})


@bp.route('/board/<int:bid>/duplicate', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def duplicate_board(bid: int):
    """Copy a board (including built-ins) into an editable one.

    This is what makes built-ins read-only rather than merely frustrating: the
    shipped board stays authoritative and the operator gets their own.
    """
    src = _owned_board(bid)
    if src is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    taken = {b.slug for b in MonitorDashboard.query.all()}
    title = "%s (copy)" % src.title
    board = MonitorDashboard(
        slug=_slugify(title, taken), title=title[:120],
        description=src.description, product=_product(), builtin=False,
        default_range=src.default_range, refresh_s=src.refresh_s,
        created_by=getattr(current_user, 'username', '') or '',
        position=_next_position())
    db.session.add(board)
    db.session.flush()
    for p in src.panels:
        clone = MonitorPanel(dashboard_id=board.id)
        for col in ('title', 'subtitle', 'viz', 'select_mode', 'probe_ids',
                    'vm_expr', 'vm_legend', 'vm_unit',
                    'rule_kind', 'rule_devices', 'rule_match', 'range_key',
                    'stat_func', 'show_band', 'show_v2', 'show_thresholds',
                    'compare_prev', 'width', 'height', 'position', 'options'):
            setattr(clone, col, getattr(p, col))
        db.session.add(clone)
    db.session.commit()
    log_action('analytics.board.duplicate', board.slug, {"from": src.slug})
    return jsonify({"ok": True, "board": board.to_dict()})


def _owned_board(bid: int):
    for b in _boards():
        if b.id == bid:
            return b
    return None


@bp.route('/board/<int:bid>/panel', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def create_panel(bid: int):
    board = _owned_board(bid)
    if board is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    if board.builtin:
        return jsonify({"ok": False,
                        "error": "Built-in boards cannot be edited."}), 403
    panel = MonitorPanel(dashboard_id=board.id, position=_next_panel_pos(board))
    err = _apply_panel(panel, request.form)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    db.session.add(panel)
    db.session.commit()
    log_action('analytics.panel.create', str(panel.id), {"title": panel.title})
    return jsonify({"ok": True, "panel": panel.to_dict()})


def _next_panel_pos(board) -> int:
    last = board.panels.order_by(MonitorPanel.position.desc()).first()
    return (last.position + 1) if last else 100


@bp.route('/panel/<int:pid>', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def update_panel(pid: int):
    panel = MonitorPanel.query.get(pid)
    board = _get_board_of(panel) if panel else None
    if panel is None or board is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    if board.builtin:
        return jsonify({"ok": False,
                        "error": "Built-in boards cannot be edited."}), 403
    err = _apply_panel(panel, request.form)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    db.session.commit()
    log_action('analytics.panel.update', str(panel.id), {"title": panel.title})
    return jsonify({"ok": True, "panel": panel.to_dict()})


@bp.route('/panel/<int:pid>/delete', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def delete_panel(pid: int):
    panel = MonitorPanel.query.get(pid)
    board = _get_board_of(panel) if panel else None
    if panel is None or board is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    if board.builtin:
        return jsonify({"ok": False,
                        "error": "Built-in boards cannot be edited."}), 403
    db.session.delete(panel)
    db.session.commit()
    log_action('analytics.panel.delete', str(pid), {})
    return jsonify({"ok": True})


@bp.route('/board/<int:bid>/reorder', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def reorder(bid: int):
    """Persist panel order after a drag. Ignores ids not on this board."""
    board = _owned_board(bid)
    if board is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    if board.builtin:
        return jsonify({"ok": False,
                        "error": "Built-in boards cannot be edited."}), 403
    try:
        order = json.loads(request.form.get('order') or '[]')
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "bad order"}), 400
    mine = {p.id: p for p in board.panels}
    for i, raw in enumerate(order if isinstance(order, list) else []):
        try:
            pid = int(raw)
        except (ValueError, TypeError):
            continue
        if pid in mine:
            mine[pid].position = i
    db.session.commit()
    return jsonify({"ok": True})


# --------------------------------------------------------------------------- #
#  Form handling                                                               #
# --------------------------------------------------------------------------- #
def _int(raw, default: int, lo: int, hi: int) -> int:
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, val))


def _one_of(raw, allowed, default: str) -> str:
    raw = (raw or '').strip()
    return raw if raw in allowed else default


def _bool(form, key: str) -> bool:
    return (form.get(key) or '').lower() in ('1', 'true', 'on', 'yes')


def _csv_ids(raw: str, limit: int = 40) -> str:
    """Normalise a submitted id list: ints only, deduped, length-capped.

    The cap is not cosmetic. ``probe_ids`` is a 500-character column, and a
    truncated list would silently drop the tail — a panel that quietly watches
    fewer series than its author selected while its title still claims all of
    them.
    """
    out: list[str] = []
    seen: set[int] = set()
    for chunk in (raw or '').split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            val = int(chunk)
        except ValueError:
            continue
        if val in seen:
            continue
        seen.add(val)
        out.append(str(val))
        if len(out) >= limit:
            break
    joined = ",".join(out)
    while len(joined) > 500 and out:
        out.pop()
        joined = ",".join(out)
    return joined


def _apply_panel(panel, form) -> str:
    """Write a submitted panel. Returns an error string, or '' on success."""
    viz = _one_of(form.get('viz'), VIZ_KINDS, panel.viz or 'line')
    mode = _one_of(form.get('select_mode'), SELECT_MODES,
                   panel.select_mode or 'rule')

    panel.title = (form.get('title') or panel.title or 'Panel')[:120]
    panel.subtitle = (form.get('subtitle') or '')[:200]
    panel.viz = viz
    panel.select_mode = mode

    if mode == 'metricsql':
        expr = (form.get('vm_expr') or '').strip()
        if not expr:
            return "A store panel needs a MetricsQL expression."
        # Validated by EXECUTING it against the store, not by pattern-matching:
        # the store is the only authority on its own query language, and a
        # regex here would reject valid queries as the language grows.
        from ..services import vm_store
        probe = vm_store.query(expr)
        if probe.get('status') != 'success':
            return "The store rejected that expression: %s" % (
                probe.get('error') or 'query failed')[:160]
        panel.vm_expr = expr[:500]
        panel.vm_legend = (form.get('vm_legend') or '')[:120]
        panel.vm_unit = (form.get('vm_unit') or '')[:24]
    elif mode == 'probes':
        panel.probe_ids = _csv_ids(form.get('probe_ids') or '')
        if not panel.probe_ids:
            return "Select at least one probe."
        # Leave the rule fields as-is rather than clearing them: switching a
        # panel to explicit ids and back should not lose the rule the operator
        # spent time building.
    else:
        kind = (form.get('rule_kind') or '').strip()
        if kind and kind not in _known_kinds():
            return "Unknown metric %r." % kind
        panel.rule_kind = kind[:24]
        panel.rule_devices = _csv_ids(form.get('rule_devices') or '')
        panel.rule_match = (form.get('rule_match') or '')[:120]
        if not panel.rule_kind and not panel.rule_devices:
            return "A rule needs a metric or at least one device."

    panel.range_key = _one_of(form.get('range_key'), ma.RANGES, '') \
        if (form.get('range_key') or '') else ''
    panel.stat_func = _one_of(form.get('stat_func'), STAT_FUNCS,
                              panel.stat_func or 'last')
    # Checkboxes are only written when the form actually carries them. A
    # partial form (the compact inline editor) must not silently clear a flag
    # its markup never rendered — the same trap that once blanked a probe's
    # policy name on every save.
    for key, col in (('show_band', 'show_band'), ('show_v2', 'show_v2'),
                     ('show_thresholds', 'show_thresholds'),
                     ('compare_prev', 'compare_prev')):
        if key in form or ('%s__present' % key) in form:
            setattr(panel, col, _bool(form, key))
    panel.width = _int(form.get('width'), panel.width or 6, 3, 12)
    panel.height = _int(form.get('height'), panel.height or 260, 160, 900)
    if 'position' in form:
        panel.position = _int(form.get('position'), panel.position or 100, 0, 9999)
    return ''


def _known_kinds() -> set[str]:
    from ..services import deep_monitor as dm
    return set(dm.KINDS)
