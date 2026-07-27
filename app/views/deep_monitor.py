"""Deep monitors — Monitoring's third view.

Fleet health is *is the box alive*; Metrics is *how much does it hold*. This is
*is the service actually serving* — synthetic HTTPS against the published
front-end of a server policy, interface IP/link drift, and the ``proxyd``
daemon's worker count / CPU / restarts.

Contract, identical to the other two Monitoring views: **a page load never
touches an appliance.** The page renders from ``monitor_probe`` /
``monitor_sample`` rows; probing is a background job (``/run``) or the
``deep_monitor`` scheduled action. Reads need VIEW; creating, editing, deleting
or triggering a probe needs CONFIG_WRITE.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from flask import (Blueprint, current_app, jsonify, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import (Appliance, MonitorProbe, MonitorSample, Permission, db,
                      visible_appliances)
from ..services import deep_monitor as dm
from ..services import jobs as jobsvc
from ..services import notifications as notify
from ..services.audit import log_action

bp = Blueprint('deep_monitor', __name__, url_prefix='/monitoring/deep')

# How many samples the sparkline / history strip carries per probe.
SERIES_POINTS = 60


def _visible_ids() -> set[int]:
    return {a.id for a in visible_appliances().all()}


def _probes_query():
    """Probes for devices this session can see, plus device-less URL probes."""
    ids = _visible_ids()
    return (MonitorProbe.query
            .filter(db.or_(MonitorProbe.appliance_id.is_(None),
                           MonitorProbe.appliance_id.in_(ids or [-1])))
            .order_by(MonitorProbe.kind, MonitorProbe.name))


def _series(probe_id: int, limit: int = SERIES_POINTS) -> list[dict]:
    rows = (MonitorSample.query
            .filter(MonitorSample.probe_id == probe_id)
            .order_by(MonitorSample.ts.desc()).limit(limit).all())
    return [r.to_dict() for r in reversed(rows)]


def _payload() -> dict:
    probes = _probes_query().all()
    out, by_kind = [], {}
    for p in probes:
        row = p.to_dict()
        row["series"] = _series(p.id)
        latest = row["series"][-1] if row["series"] else None
        row["latest"] = latest
        # A probe that has never run is 'unknown', not 'ok' — never imply health
        # we have not measured.
        row["status"] = (latest or {}).get("status") or "unknown"
        out.append(row)
        by_kind.setdefault(p.kind, []).append(row["status"])
    summary = {k: {"count": len(v), "worst": dm.worst(v)} for k, v in by_kind.items()}
    return {
        "probes": out,
        "summary": summary,
        "worst": dm.worst([r["status"] for r in out]),
        "kinds": [{"key": k, "label": dm.KIND_LABEL[k]} for k in dm.KINDS],
        "devices": [{"id": a.id, "name": a.name, "kind": a.kind or "fortiweb",
                     "host": a.host}
                    for a in visible_appliances().order_by(Appliance.name).all()],
    }


@bp.route('/')
@login_required
def index():
    try:
        can_edit = current_user.can(Permission.CONFIG_WRITE)
    except Exception:  # noqa: BLE001
        can_edit = False
    return render_template('monitoring/deep.html', can_edit=can_edit)


@bp.route('/data')
@login_required
def data():
    return jsonify(_payload())


@bp.route('/probe/<int:pid>/history')
@login_required
def history(pid: int):
    probe = MonitorProbe.query.get_or_404(pid)
    if probe.appliance_id and probe.appliance_id not in _visible_ids():
        return jsonify({"error": "not visible in this ADOM"}), 403
    rows = (MonitorSample.query.filter(MonitorSample.probe_id == pid)
            .order_by(MonitorSample.ts.desc()).limit(200).all())
    out = []
    for r in rows:
        item = r.to_dict()
        try:
            item["payload"] = json.loads(r.payload or "{}")
        except (ValueError, TypeError):
            item["payload"] = {}
        out.append(item)
    return jsonify({"probe": probe.to_dict(), "samples": out})


# Fixed windows the chart offers. `custom` takes explicit from/to.
SERIES_RANGES = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


def _parse_dt(raw: str | None):
    """Accept an ISO instant (what the picker sends) or a bare ``YYYY-MM-DD``."""
    raw = (raw or "").strip()
    if not raw:
        return None
    txt = raw.replace("Z", "").replace(" ", "T")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(txt, fmt)
        except ValueError:
            continue
    return None


def _thresholds(probe) -> dict:
    """Threshold lines to draw, per kind — empty when the kind has none."""
    if probe.kind in ("cpu", "memory"):
        return {"warn": probe.warn_pct or 0, "crit": probe.crit_pct or 0}
    if probe.kind == "https":
        return {"warn": probe.warn_ms or 0, "crit": 0}
    return {}


@bp.route('/probe/<int:pid>/series')
@login_required
def probe_series(pid: int):
    """Chart data for the drill-down: 1 h / 24 h / 7 d / 30 d or explicit dates.

    Resolution is chosen server-side (raw samples, hourly buckets or daily
    buckets) and reported back in ``source`` — the UI states which one it drew,
    because an average over a day and a reading every five minutes are not the
    same claim about the device.
    """
    probe = MonitorProbe.query.get_or_404(pid)
    if probe.appliance_id and probe.appliance_id not in _visible_ids():
        return jsonify({"error": "not visible in this ADOM"}), 403

    rng = (request.args.get('range') or '24h').strip()
    now = datetime.utcnow()
    if rng == 'custom':
        start = _parse_dt(request.args.get('from'))
        end = _parse_dt(request.args.get('to'))
        if start is None or end is None:
            return jsonify({"error": "from/to must be ISO timestamps"}), 400
        if end <= start:
            return jsonify({"error": "'to' must be after 'from'"}), 400
        if end - start > timedelta(days=dm.MAX_RANGE_DAYS):
            return jsonify({"error": f"range capped at {dm.MAX_RANGE_DAYS} days"}), 400
    else:
        delta = SERIES_RANGES.get(rng)
        if delta is None:
            return jsonify({"error": f"unknown range {rng!r}"}), 400
        end, start = now, now - delta

    out = dm.series(pid, start, end)
    out["range"] = rng
    out["probe"] = probe.to_dict()
    out["meta"] = dm.METRIC_META.get(probe.kind, {})
    out["thresholds"] = _thresholds(probe)
    out["retention"]["raw_samples"] = int(probe.retention or 0)
    return jsonify(out)


@bp.route('/device/<int:aid>/ports')
@login_required
def ports(aid: int):
    """Interface names for the probe form's port picker.

    Read from the harvest CACHE, never the box: the operator picks from what the
    device actually has instead of typing a name blind, the modal opens
    instantly, and it still works with the appliance powered off.
    """
    from ..services import interface_inventory

    if aid not in _visible_ids():
        return jsonify({"error": "not visible in this ADOM"}), 403
    appliance = Appliance.query.get_or_404(aid)
    try:
        rows = interface_inventory.merged(appliance).get("interfaces") or []
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ports": [], "error": str(exc)})
    out = [{"name": str(r.get("name") or "").strip(),
            "ip": str(r.get("ip_address") or "").strip(),
            "status": str(r.get("status") or "").strip()}
           for r in rows if str(r.get("name") or "").strip()]
    out.sort(key=lambda r: r["name"])
    return jsonify({"ports": out})


# ---------------------------------------------------------------------------
# Mutations (CONFIG_WRITE)
# ---------------------------------------------------------------------------

_INT_FIELDS = ("expect_status", "warn_ms", "tls_warn_days", "stale_after_h",
               "warn_cpu", "warn_mem", "warn_pct", "crit_pct",
               "timeout_s", "interval_min", "retention")


def _interface_target(form) -> str:
    """Join the ticked ports into ``target`` without ever slicing a name in half.

    ``target`` is 120 chars. Truncating mid-name would produce a port that
    matches nothing and a probe that silently watches less than it claims, so a
    list that does not fit drops whole names at the end instead.
    """
    joined = ""
    for raw in form.getlist('target'):
        name = (raw or '').strip()
        if not name:
            continue
        cand = (joined + "," + name) if joined else name
        if len(cand) > 120:
            break
        joined = cand
    return joined


def _apply_form(probe: MonitorProbe, form) -> str:
    """Copy submitted fields onto ``probe``. Returns an error string or ''."""
    kind = (form.get('kind') or probe.kind or 'https').strip()
    if kind not in dm.KINDS:
        return f"unknown probe kind {kind!r}"
    probe.kind = kind
    probe.name = (form.get('name') or '').strip()[:120]
    probe.note = (form.get('note') or '').strip()[:250]
    aid = form.get('appliance_id', type=int)
    probe.appliance_id = aid or None
    if probe.appliance_id and probe.appliance_id not in _visible_ids():
        return "that device is not visible in this ADOM"
    if kind == 'interface':
        # Multi-select: no tick at all means "every port", which is the
        # whole-device watch the discovery job creates.
        probe.target = _interface_target(form)
    elif 'target' in form:
        # Never blank an HTTPS probe's policy name just because the edit form
        # for another kind does not render the field.
        probe.target = (form.get('target') or '').strip()[:120]
    probe.url = (form.get('url') or '').strip()[:500]
    probe.process_name = (form.get('process_name') or 'proxyd').strip()[:48]
    for f in _INT_FIELDS:
        val = form.get(f, type=int)
        if val is not None:
            setattr(probe, f, max(0, val))
    probe.interval_min = max(1, int(probe.interval_min or 5))
    probe.timeout_s = max(1, int(probe.timeout_s or 10))
    probe.retention = max(10, int(probe.retention or dm.DEFAULT_RETENTION))

    if kind == 'https' and not probe.url:
        return "an HTTPS probe needs a URL"
    if kind != 'https' and not probe.appliance_id:
        return f"a {kind} probe needs a device"
    if kind in dm.BOX_METRICS and probe.warn_pct and probe.crit_pct \
            and probe.crit_pct < probe.warn_pct:
        return "the critical threshold must be at or above the warning one"
    if not probe.name:
        probe.name = (probe.url or probe.kind)[:120]
    return ''


@bp.route('/probe', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def create():
    probe = MonitorProbe()
    err = _apply_form(probe, request.form)
    if err:
        return jsonify({"error": err}), 400
    db.session.add(probe)
    db.session.commit()
    log_action("deep_monitor.create", target=probe.name,
               extra={"kind": probe.kind, "url": probe.url,
                      "appliance_id": probe.appliance_id})
    return jsonify({"ok": True, "probe": probe.to_dict()})


@bp.route('/probe/<int:pid>', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def update(pid: int):
    probe = MonitorProbe.query.get_or_404(pid)
    if probe.appliance_id and probe.appliance_id not in _visible_ids():
        return jsonify({"error": "not visible in this ADOM"}), 403
    err = _apply_form(probe, request.form)
    if err:
        db.session.rollback()
        return jsonify({"error": err}), 400
    db.session.commit()
    log_action("deep_monitor.update", target=probe.name, extra={"id": pid})
    return jsonify({"ok": True, "probe": probe.to_dict()})


@bp.route('/probe/<int:pid>/toggle', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def toggle(pid: int):
    probe = MonitorProbe.query.get_or_404(pid)
    if probe.appliance_id and probe.appliance_id not in _visible_ids():
        return jsonify({"error": "not visible in this ADOM"}), 403
    probe.enabled = not probe.enabled
    db.session.commit()
    log_action("deep_monitor.toggle", target=probe.name,
               extra={"enabled": probe.enabled})
    return jsonify({"ok": True, "enabled": probe.enabled})


@bp.route('/probe/<int:pid>/delete', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def delete(pid: int):
    probe = MonitorProbe.query.get_or_404(pid)
    if probe.appliance_id and probe.appliance_id not in _visible_ids():
        return jsonify({"error": "not visible in this ADOM"}), 403
    name = probe.name
    db.session.delete(probe)
    db.session.commit()
    log_action("deep_monitor.delete", target=name, extra={"id": pid})
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Background execution
# ---------------------------------------------------------------------------

def _run_sweep(app, job_id, ids, uid, link):
    with app.app_context():
        try:
            jobsvc.update_job(job_id, percent=5, message="Probing…")
            res = dm.sweep(ids=ids, force=True)
            counts = ", ".join(f"{v} {k}" for k, v in sorted(res["counts"].items()))
            msg = f"{res['ran']} probe(s) run" + (f" — {counts}" if counts else "")
            jobsvc.finish_success(job_id, message=msg,
                                  result={"reload": True, "reload_path": link,
                                          **res})
            kind = (notify.Notification.KIND_SUCCESS if res["worst"] == "ok"
                    else notify.Notification.KIND_WARNING)
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            jobsvc.finish_error(job_id, f"deep monitor sweep failed: {exc}")
            msg, kind = str(exc)[:200], notify.Notification.KIND_ERROR
        if uid:
            try:
                notify.push(uid, f"Deep monitors: {msg}", kind=kind, link=link)
            except Exception:  # noqa: BLE001
                pass


@bp.route('/run', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def run():
    """Probe now — one id, a list, or every enabled probe. Always a job: an
    HTTPS round trip plus an SSH session per device is far too slow to block a
    request, and a dead appliance would hold the worker for the full timeout."""
    ids = request.form.getlist('id', type=int) or None
    if ids:
        vis = _visible_ids()
        allowed = {p.id for p in MonitorProbe.query.filter(MonitorProbe.id.in_(ids)).all()
                   if not p.appliance_id or p.appliance_id in vis}
        ids = sorted(allowed)
        if not ids:
            return jsonify({"error": "nothing to run"}), 400
    job = jobsvc.create_job("deep_monitor", "Deep monitors — probe",
                            by=getattr(current_user, 'username', '') or '',
                            meta={"ids": ids or "all"})
    link = url_for('deep_monitor.index')
    jobsvc.run_async(current_app._get_current_object(), job["id"],
                     lambda app, jid: _run_sweep(app, jid, ids,
                                                 getattr(current_user, 'id', None),
                                                 link))
    return jsonify({"job_id": job["id"]})


def _run_discover(app, job_id, aid, what, uid, link):
    with app.app_context():
        try:
            appliance = Appliance.query.get(aid)
            jobsvc.update_job(job_id, percent=10,
                              message=f"Reading the cache for {appliance.name}…")
            parts, total = [], 0
            if 'policies' in what:
                res = dm.discover_https_probes(appliance)
                if res.get("error"):
                    # FortiADC / FortiAnalyzer have no server policies. That is
                    # not a failure of the whole run — say so and keep going.
                    parts.append(res["error"])
                else:
                    total += res["created"]
                    parts.append(f"{res['created']} service probe(s) "
                                 f"({res['skipped']} already present)")
            if 'interfaces' in what:
                res = dm.discover_interface_probes(appliance)
                if res.get("error"):
                    parts.append(res["error"])
                else:
                    total += res["created"]
                    parts.append(f"{res['created']} per-port probe(s) "
                                 f"({res['skipped']} already present)")
            if 'baseline' in what:
                base = dm.ensure_baseline(appliance)
                total += len(base["created"])
                parts.append("baseline: "
                             + (", ".join(base["created"]) or "nothing missing"))
            msg = "; ".join(parts) or "nothing selected"
            jobsvc.finish_success(job_id, message=msg,
                                  result={"reload": True, "reload_path": link,
                                          "created": total})
            if uid:
                notify.push(uid, f"Deep monitors: {msg}",
                            kind=notify.Notification.KIND_SUCCESS, link=link)
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            jobsvc.finish_error(job_id, f"discovery failed: {exc}")


@bp.route('/discover', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def discover():
    """Auto-create probes for a device. Idempotent, and the operator picks what:

    ``policies``    one HTTPS probe per server policy front-end (FortiWeb)
    ``baseline``    interfaces (all ports), CPU, memory, proxyd on FortiWeb
    ``interfaces``  one probe PER PORT — a separate series per interface
    """
    aid = request.form.get('appliance_id', type=int)
    if not aid or aid not in _visible_ids():
        return jsonify({"error": "pick a visible device"}), 400
    allowed = {'policies', 'baseline', 'interfaces'}
    what = [w for w in request.form.getlist('what') if w in allowed]
    if not what:
        what = ['policies', 'baseline']
    job = jobsvc.create_job("deep_monitor_discover", "Deep monitors — discover",
                            by=getattr(current_user, 'username', '') or '',
                            meta={"appliance_id": aid, "what": what})
    link = url_for('deep_monitor.index')
    jobsvc.run_async(current_app._get_current_object(), job["id"],
                     lambda app, jid: _run_discover(app, jid, aid, what,
                                                    getattr(current_user, 'id', None),
                                                    link))
    return jsonify({"job_id": job["id"]})
