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


# ---------------------------------------------------------------------------
# Mutations (CONFIG_WRITE)
# ---------------------------------------------------------------------------

_INT_FIELDS = ("expect_status", "warn_ms", "tls_warn_days", "stale_after_h",
               "warn_cpu", "warn_mem", "timeout_s", "interval_min", "retention")


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
    if kind in ('interface', 'proxyd') and not probe.appliance_id:
        return f"a {kind} probe needs a device"
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


def _run_discover(app, job_id, aid, uid, link):
    with app.app_context():
        try:
            appliance = Appliance.query.get(aid)
            jobsvc.update_job(job_id, percent=10,
                              message=f"Resolving policies on {appliance.name}…")
            res = dm.discover_https_probes(appliance)
            base = dm.ensure_baseline(appliance)
            if res.get("error"):
                jobsvc.finish_error(job_id, res["error"])
                return
            msg = (f"{res['created']} service probe(s) created, "
                   f"{res['skipped']} already present"
                   + (f"; baseline: {', '.join(base['created'])}"
                      if base.get("created") else ""))
            jobsvc.finish_success(job_id, message=msg,
                                  result={"reload": True, "reload_path": link, **res})
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
    """Auto-create one HTTPS probe per server policy on a device, plus the two
    device-level probes (interface watch + proxyd). Idempotent."""
    aid = request.form.get('appliance_id', type=int)
    if not aid or aid not in _visible_ids():
        return jsonify({"error": "pick a visible device"}), 400
    job = jobsvc.create_job("deep_monitor_discover", "Deep monitors — discover",
                            by=getattr(current_user, 'username', '') or '',
                            meta={"appliance_id": aid})
    link = url_for('deep_monitor.index')
    jobsvc.run_async(current_app._get_current_object(), job["id"],
                     lambda app, jid: _run_discover(app, jid, aid,
                                                    getattr(current_user, 'id', None),
                                                    link))
    return jsonify({"job_id": job["id"]})
