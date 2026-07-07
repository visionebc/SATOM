"""Signatures — sync the FortiWeb signature database from a base device.

Mirrors the desktop ``SignatureSyncPage``: pick a base FortiWeb (the same
FortiGuard signature package is on every box), read the whole signature catalog
(main class -> sub-class -> individual signature + description) READ-ONLY, and
cache it to ``data/signatures.json`` so the rest of the app can later show
signatures by name instead of a blind id. Re-run to pick up new firmware / new
signatures.

The read is now a BACKGROUND JOB (``services.jobs``, same framework as the
firmware finalize): the request returns immediately, the bottom-right job dock
tracks progress, and a bell notification fires when it finishes.

Admin-only (USER_MANAGE). The blueprint import is side-effect-free; every device
call is wrapped so an unreachable FortiWeb notifies + marks the job error instead
of 500-ing.
"""
from __future__ import annotations

import os
import re

from flask import (
    Blueprint, current_app, flash, redirect, render_template, request, url_for,
)
from flask_login import login_required, current_user

from ..auth.decorators import require_permission
from ..models import Appliance, Permission
from ..models import visible_appliances, visible_appliance_or_404
from ..clients.fortiweb import FortiWebClient
from ..services.audit import log_action
from ..services import signature_catalog as sigcat
from ..services import jobs as jobsvc
from ..services import notifications as notify

bp = Blueprint('signatures', __name__, url_prefix='/signatures')

_VER_RE = re.compile(r"(\d+\.\d+\.\d+)")


def _data_path() -> str:
    """Absolute path to data/signatures.json (created on demand)."""
    d = os.path.join(os.path.dirname(current_app.root_path), 'data')
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, 'signatures.json')


def _read_firmware(client: FortiWebClient) -> str:
    """Best-effort firmware (e.g. '7.6.8') from system status; '' on any failure."""
    try:
        status = client.status_check()
    except Exception:  # noqa: BLE001 — firmware is informational, never block the sync
        return ""
    results = status.get('results', status) if isinstance(status, dict) else {}
    if isinstance(results, list):
        results = results[0] if results else {}
    if isinstance(results, dict):
        for key in ('firmwareVersion', 'version', 'firmware_version',
                    'os_version', 'fos_version'):
            val = results.get(key)
            if isinstance(val, str):
                m = _VER_RE.search(val)
                if m:
                    return m.group(1)
    m = _VER_RE.search(str(status))
    return m.group(1) if m else ""


def _sync_worker(app, job_id, appliance_id, user_id, link):
    """Background worker (daemon thread, fresh app context): read the whole
    signature catalog READ-ONLY from the base device, cache it, and raise a bell
    notification on success/failure. NO request / current_user here."""
    with app.app_context():
        appliance = (Appliance.query
                     .filter_by(id=appliance_id, kind='fortiweb').first())
        if appliance is None:
            jobsvc.finish_error(job_id, "Base device not found.")
            return None
        name = appliance.name
        try:
            jobsvc.set_progress(job_id, 5, "Connecting to %s..." % name)
            client = FortiWebClient(appliance)
            firmware = _read_firmware(client)
            jobsvc.set_progress(job_id, 15, "Selecting signature set...")
            signature_set = sigcat.pick_signature_set(client)
            if not signature_set:
                jobsvc.finish_error(
                    job_id, "No signature set found on %s." % name)
                notify.push(
                    user_id, "Signature sync from %s failed" % name,
                    kind=notify.Notification.KIND_WARNING,
                    body="No signature set found on the device.", link=link)
                return None
            jobsvc.set_progress(
                job_id, 30,
                "Reading signature database (set %s)..." % signature_set)
            sigdb = sigcat.sync_signature_database(
                client, signature_set, firmware=firmware)
            jobsvc.set_progress(job_id, 90, "Saving catalog...")
            sigcat.save_signature_db(sigdb, _data_path())
        except Exception as exc:  # noqa: BLE001 — notify, then let run_async mark error
            notify.push(
                user_id, "Signature sync from %s failed" % name,
                kind=notify.Notification.KIND_ERROR,
                body=str(exc)[:400], link=link)
            raise

        count = len(sigdb.signatures)
        log_action(
            'signatures.sync', target=name,
            extra={'count': count, 'set': signature_set, 'firmware': firmware})
        jobsvc.finish_success(
            job_id,
            message="%d signatures across %d sub-classes" % (
                count, sigdb.subclass_count),
            result={"count": count, "set": signature_set,
                    "firmware": firmware, "reload": True})
        if count:
            notify.push(
                user_id, "Signature database synced — %d signatures" % count,
                kind=notify.Notification.KIND_SUCCESS,
                body=("From %s · set \"%s\" · firmware %s · "
                      "%d sub-classes." % (name, signature_set,
                                           firmware or '?', sigdb.subclass_count)),
                link=link)
        else:
            notify.push(
                user_id, "Signature sync read 0 signatures from %s" % name,
                kind=notify.Notification.KIND_WARNING,
                body=("Connected but read 0 (set \"%s\"). Check the base "
                      "device." % signature_set),
                link=link)
        return None


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    """Base-device selector + cached-status line + Sync button.

    Renders even with NO devices and no cached catalog file (db is None)."""
    appliances = visible_appliances().filter_by(kind='fortiweb').order_by(Appliance.name).all()
    db = sigcat.load_signature_db(_data_path())
    return render_template('signatures/index.html', appliances=appliances, db=db)


@bp.route('/sync', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def sync():
    """Start a BACKGROUND job that reads the signature database (READ-ONLY) from
    the selected base device. The job dock tracks progress; a bell notification
    fires on completion. Redirects back immediately."""
    appliance_id = request.form.get('appliance_id', type=int)
    appliance = (
        Appliance.query.filter_by(id=appliance_id, kind='fortiweb').first()
        if appliance_id else None
    )
    if appliance is None:
        flash('Select a base FortiWeb device to sync from.', 'warning')
        return redirect(url_for('signatures.index'))

    uid = getattr(current_user, 'id', 0) or 0
    link = url_for('signatures.index')
    aid = appliance.id
    name = appliance.name
    log_action('signatures.sync.start', target=name)
    job = jobsvc.create_job(
        'signatures_sync', 'Syncing signatures from %s' % name,
        by=getattr(current_user, 'username', '') or '',
        meta={'appliance_id': aid, 'device': name})
    jobsvc.run_async(
        current_app._get_current_object(), job['id'],
        lambda app, jid: _sync_worker(app, jid, aid, uid, link))
    flash(
        "Signature sync from %s started — follow it in the job dock "
        "(bottom-right). You'll get a notification when it finishes." % name,
        'info')
    return redirect(url_for('signatures.index'))
