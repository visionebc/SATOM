"""Monitoring dashboard — fleet health, capacity alerts, manager self-health.

Read view for every role; the hardware SSH scan is a background job gated to
CONFIG_WRITE. All data is served DB-first (device cache + capacity limits +
local /proc probes) — a page load never touches an appliance.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request, jsonify, current_app, url_for
from flask_login import login_required, current_user

from ..auth.decorators import require_permission
from ..models import (Appliance, AppSetting, Permission, db,
                      visible_appliances)
from ..services import jobs as jobsvc
from ..services import notifications as notify

bp = Blueprint('monitoring', __name__, url_prefix='/monitoring')


def _thresholds() -> tuple[float, float]:
    try:
        warn = float(AppSetting.get('capacity.warn_pct', '80') or 80)
    except (TypeError, ValueError):
        warn = 80.0
    try:
        crit = float(AppSetting.get('capacity.crit_pct', '95') or 95)
    except (TypeError, ValueError):
        crit = 95.0
    return warn, crit


def _device_payload(warn: float, crit: float) -> tuple[list[dict], list[dict], list[dict]]:
    """Device cards, capacity alerts and health alerts.

    The card badge is the roll-up from :mod:`services.device_health` -- harvest
    status, cache age, deep monitors AND capacity -- not capacity alone. Before
    2026-07-28 it was capacity-only, and since no appliance in this fleet has an
    admin cap it could never leave 'healthy' even for a box that was powered off.
    """
    from ..services import device_health as devhealth
    from ..services import read_layer
    from ..services.hardware import hardware_map

    hw = hardware_map()
    stale_h = devhealth.stale_hours()
    devices, alerts, health_alerts = [], [], []
    for a in visible_appliances().order_by(Appliance.name).all():
        # Gathering lives in device_health so the alert engine grades identically.
        caps = devhealth.capacity_rows(a, warn, crit)
        for row in caps:
            if row['status'] in ('warn', 'crit'):
                alerts.append({'appliance_id': a.id, 'appliance': a.name,
                               'object': row.get('label'), 'used': row.get('used'),
                               'cap': row.get('effective_cap'), 'pct': row.get('pct'),
                               'status': row['status']})
        meta = devhealth.cache_meta(a)
        try:
            fresh = read_layer.freshness_label(meta) if meta else 'no local data'
        except Exception:
            fresh = 'unknown'
        health = devhealth.collect(a, caps, meta, hours=stale_h)
        worst = health['status']
        for r in health['reasons']:
            if r['status'] in ('warn', 'crit'):
                health_alerts.append({'appliance_id': a.id, 'appliance': a.name,
                                      'signal': r['signal'], 'label': r['label'],
                                      'status': r['status'], 'text': r['text']})
        devices.append({
            'id': a.id, 'name': a.name, 'host': a.host,
            'model': a.model or '', 'firmware': a.firmware or '',
            'kind': (a.kind or 'fortiweb'),
            'ha_mode': a.ha_mode or '', 'ha_role': a.ha_role_hint or '',
            # Appliance.maintenance is the column; 'maintenance_mode' never existed,
            # so this flag was permanently False before 2026-07-28.
            'maintenance': bool(getattr(a, 'maintenance', False)),
            'freshness': fresh,
            'hw': hw.get(a.id),
            'capacity': caps,
            'worst': worst,
            'health': health,
        })
    return devices, alerts, health_alerts


def _payload() -> dict:
    from ..services import system_health as shealth

    warn, crit = _thresholds()
    devices, alerts, health_alerts = _device_payload(warn, crit)
    return {
        'thresholds': {'warn': warn, 'crit': crit},
        'devices': devices,
        'alerts': sorted(alerts, key=lambda x: (x['status'] != 'crit', -(x['pct'] or 0))),
        'health_alerts': sorted(health_alerts, key=lambda x: x['status'] != 'crit'),
        'system': shealth.host_stats(),
        'services': shealth.service_status(),
        'db': shealth.db_stats(),
        'redundancy': shealth.redundancy(),
    }


@bp.route('/')
@login_required
def index():
    try:
        can_scan = current_user.can(Permission.CONFIG_WRITE)
    except Exception:
        can_scan = False
    return render_template('monitoring/index.html', can_scan=can_scan)


@bp.route('/data')
@login_required
def data():
    return jsonify(_payload())


def _run_hw_scan(app, job_id, ids, user_id, uname, link):
    with app.app_context():
        q = Appliance.query
        if ids:
            q = q.filter(Appliance.id.in_(ids))
        targets = q.order_by(Appliance.name).all()
        total = len(targets) or 1
        done, errors = [], {}
        from ..services import hardware as hwsvc
        for i, a in enumerate(targets):
            try:
                jobsvc.checkpoint(job_id)
            except jobsvc.JobCancelled:
                jobsvc.finish_cancelled(job_id)
                return
            jobsvc.update_job(job_id, percent=int(100 * i / total),
                              message=f"Scanning {a.name} over SSH…")
            try:
                hwsvc.scan_appliance(a)
                done.append(a.name)
            except Exception as exc:  # box down / no SSH — keep going
                db.session.rollback()
                errors[a.name] = str(exc)[:180]
        msg = f"{len(done)} scanned" + (f", {len(errors)} failed" if errors else "")
        if done:
            jobsvc.finish_success(job_id, message=msg,
                                  result={"ok": done, "errors": errors,
                                          "reload": True,
                                          "reload_path": link})
            kind = notify.Notification.KIND_SUCCESS
        else:
            jobsvc.finish_error(job_id, f"hardware scan failed on every device: "
                                        f"{'; '.join(f'{k}: {v}' for k, v in errors.items())[:300]}")
            kind = notify.Notification.KIND_ERROR
        if user_id:
            try:
                notify.push(user_id, f"Hardware scan: {msg}", kind=kind,
                            body=("; ".join(f"{k}: {v}" for k, v in errors.items())[:400]
                                  or "All devices scanned."),
                            link=link)
            except Exception:
                pass


@bp.route('/hw-scan', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def hw_scan():
    """Fleet hardware inventory scan (read-only SSH battery) as a background job."""
    ids = request.form.getlist('id', type=int) or None
    uname = getattr(current_user, 'username', '') or ''
    uid = getattr(current_user, 'id', None)
    job = jobsvc.create_job("hardware_scan", "Hardware scan — fleet",
                            by=uname, meta={"ids": ids or "all"})
    link = url_for('monitoring.index')
    app_obj = current_app._get_current_object()
    jobsvc.run_async(app_obj, job["id"],
                     lambda app, jid: _run_hw_scan(app, jid, ids, uid, uname, link))
    return jsonify({"job_id": job["id"]})


@bp.route('/infra')
@login_required
def infra():
    """Cross-node + off-box infrastructure health (HA peers, Gitea, backup-server).
    Network probes with short timeouts — fetched by the card AFTER page render,
    never during a page load."""
    from ..services import infra_health
    return jsonify(infra_health.snapshot())


@bp.route('/encryption')
@login_required
def encryption():
    """Per-channel encryption posture (DB replication TLS, inter-node HTTPS,
    datasync SSH, Git SoT, node cert). Live probes with short timeouts — fetched
    by the card AFTER page render, never during a page load (same contract as
    /monitoring/infra)."""
    from ..services import encryption_health
    return jsonify(encryption_health.snapshot())
