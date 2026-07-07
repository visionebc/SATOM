"""Global ADOM — the fleet-wide landing at ``/``.

One dashboard spanning BOTH products (FortiWeb + FortiADC): device counts,
running jobs, certificate posture and quick links into every fleet-wide
section. The route itself lives in the app factory (endpoint ``index``,
path ``/``) so legacy ``url_for('index')`` callers keep working — this
module only gathers the data and renders.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from flask import render_template

from ..models import Appliance, visible_appliances


def dashboard():
    fleet = visible_appliances().order_by(Appliance.kind, Appliance.name).all()
    fw = [a for a in fleet if (a.kind or 'fortiweb') == 'fortiweb']
    adc = [a for a in fleet if a.kind == 'fortiadc']

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

    return render_template('global_home/index.html', fw_fleet=fw,
                           adc_fleet=adc, jobs_running=jobs_running,
                           certs=certs)
