"""Signatures — the signature source, the local signature index and its history.

The operator chooses ONE FortiWeb as the **signature source** (setting
``signatures.source.fortiweb``). SATOM reads that device's signature database
READ-ONLY over REST and indexes it locally (``services.signature_index``):
every signature id with its class and description, a snapshot per database
version, and what each new version added, changed or removed. The daily
``signature_check`` action collects on its own when the source's version
moves; **Collect now** runs the same read as a background job
(``services.jobs``) — the job dock tracks it and a bell notification fires.

The index also rewrites ``data/signatures.json``, the catalog the signature
editor and the WPP views read.

Admin-only (USER_MANAGE). The blueprint import is side-effect-free; every device
call is wrapped so an unreachable FortiWeb notifies + marks the job error instead
of 500-ing.
"""
from __future__ import annotations

from flask import (
    Blueprint, abort, current_app, flash, redirect, render_template, request, url_for,
)
from flask_login import login_required, current_user

from ..auth.decorators import require_permission
from ..models import Appliance, Permission
from ..models import visible_appliances
from ..services.audit import log_action
from ..services import signature_catalog as sigcat
from ..services import signature_index as sidx
from ..services import jobs as jobsvc
from ..services import notifications as notify

bp = Blueprint('signatures', __name__, url_prefix='/signatures')

PRODUCT = 'fortiweb'


def _collect_worker(app, job_id, appliance_id, user_id, by):
    """Background worker (daemon thread, fresh app context): read the source's
    signature database READ-ONLY and index it. NO request / current_user here."""
    with app.app_context():
        appliance = (Appliance.query
                     .filter_by(id=appliance_id, kind=PRODUCT).first())
        if appliance is None:
            jobsvc.finish_error(job_id, "Signature source not found.")
            return None
        name = appliance.name
        link = '/web/signatures/'

        def progress(label, count):
            jobsvc.set_progress(job_id, 30, "%s — %d signatures" % (label[:80], count))

        try:
            jobsvc.set_progress(job_id, 10, "Reading %s..." % name)
            res = sidx.collect(appliance, taken_by=by, progress=progress)
        except Exception as exc:  # noqa: BLE001 — notify, then let run_async mark error
            notify.push(
                user_id, "Signature collection from %s failed" % name,
                kind=notify.Notification.KIND_ERROR,
                body=str(exc)[:400], link=link)
            raise
        line = sidx.headline(res)
        log_action('signatures.collect', target=name,
                   extra={k: res.get(k) for k in (
                       'status', 'snapshot_id', 'db_version', 'sig_count',
                       'added', 'changed', 'removed', 'baseline')})
        jobsvc.finish_success(job_id, message=line,
                              result={"count": res.get("sig_count"), "reload": True})
        if res.get("status") == "new":
            sidx.announce(res)
        else:
            notify.push(user_id, "Signatures from %s: %s" % (name, line),
                        kind=notify.Notification.KIND_SUCCESS, link=link)
        return None


def _start_collect(appliance) -> None:
    uid = getattr(current_user, 'id', 0) or 0
    by = 'manual:%s' % (getattr(current_user, 'username', '') or '?')
    aid, name = appliance.id, appliance.name
    log_action('signatures.collect.start', target=name)
    job = jobsvc.create_job(
        'signatures_sync', 'Collecting signatures from %s' % name,
        by=getattr(current_user, 'username', '') or '',
        meta={'appliance_id': aid, 'device': name})
    jobsvc.run_async(
        current_app._get_current_object(), job['id'],
        lambda app, jid: _collect_worker(app, jid, aid, uid, by))
    flash("Collecting signatures from %s — follow it in the job dock "
          "(bottom-right). You'll get a notification when it finishes." % name,
          'info')


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    """Source selector, index status, snapshot history, freshness per device
    and a search over the index. Renders with no device and no index."""
    from ..services import signature_freshness as sf
    appliances = visible_appliances().filter_by(kind=PRODUCT).order_by(Appliance.name).all()
    q = (request.args.get('q') or '').strip()
    hits = sidx.search(PRODUCT, q, limit=200,
                       include_removed=bool(request.args.get('removed'))) if q else []
    meta = sf.meta_for(PRODUCT, [h.sig_id for h in hits]) if hits else {}
    return render_template(
        'signatures/index.html', appliances=appliances,
        source=sidx.source_appliance(PRODUCT), source_id=sidx.source_id(PRODUCT),
        latest=sidx.latest(PRODUCT), snapshots=sidx.snapshots(PRODUCT, 20),
        entry_count=sidx.entry_count(PRODUCT),
        db=sigcat.load_signature_db(sidx.catalog_path()),
        freshness=sf.rows(), max_days=sf.max_days(),
        meta_count=sf.meta_count(PRODUCT), q=q, hits=hits, meta=meta)


@bp.route('/source', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def set_source():
    """Save (or clear) the signature source; ``collect=1`` also starts a read."""
    appliance_id = request.form.get('appliance_id', type=int)
    if not appliance_id:
        sidx.set_source(PRODUCT, None)
        log_action('signatures.source.clear')
        flash('Signature source cleared — SATOM stops collecting signatures.', 'warning')
        return redirect(url_for('signatures.index'))
    appliance = visible_appliances().filter_by(id=appliance_id, kind=PRODUCT).first()
    if appliance is None:
        flash('Select a FortiWeb as the signature source.', 'warning')
        return redirect(url_for('signatures.index'))
    if sidx.source_id(PRODUCT) != appliance.id:
        sidx.set_source(PRODUCT, appliance.id)
        log_action('signatures.source.set', target=appliance.name)
        flash('Signature source set to %s.' % appliance.name, 'success')
    if request.form.get('collect'):
        _start_collect(appliance)
    return redirect(url_for('signatures.index'))


@bp.route('/sync', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def sync():
    """Collect now from the configured signature source (background job)."""
    appliance = sidx.source_appliance(PRODUCT)
    if appliance is None:
        flash('Choose a signature source first.', 'warning')
        return redirect(url_for('signatures.index'))
    _start_collect(appliance)
    return redirect(url_for('signatures.index'))


@bp.route('/snapshots/<int:sid>')
@login_required
@require_permission(Permission.USER_MANAGE)
def snapshot(sid):
    """What one snapshot added, changed and removed."""
    from ..models_signatures import SignatureSnapshot
    snap = SignatureSnapshot.query.get(sid)
    if snap is None:
        abort(404)
    rows = sidx.changes(snap.id)
    prev = SignatureSnapshot.query.get(snap.prev_snapshot_id) if snap.prev_snapshot_id else None
    return render_template('signatures/snapshot.html', snap=snap, prev=prev,
                           added=[r for r in rows if r.kind == 'added'],
                           changed=[r for r in rows if r.kind == 'changed'],
                           removed=[r for r in rows if r.kind == 'removed'])
