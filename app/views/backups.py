"""Backups page — the config-backup VAULT for one appliance.

This page reads and writes the SAME vault the restore flow and the upgrade/
downgrade runbook use: the ``ConfigBackup`` table + on-disk store managed by
``services.backup`` (store_bytes / fetch_device_backup / read_vault_bytes /
delete_vault). It does NOT call phantom device URLs anymore.

Creating a backup is a BACKGROUND JOB (services.jobs): pulling a config off a
box can take a while and device-side create can fail (e.g. -901 when a backup
password is set), so it runs off the request thread, shows in the global Jobs
dock, and raises a bell NOTIFICATION on completion (success or failure) — never
a fake "success" flash.
"""
from flask import (Blueprint, render_template, request, jsonify, flash,
                   redirect, url_for, Response, current_app)
from flask_login import login_required, current_user

from ..auth.decorators import require_permission
from ..models import Appliance, Permission
from ..models import visible_appliances, visible_appliance_or_404
from ..models_backup import ConfigBackup
from ..services import backup as backup_svc
from ..services import jobs as jobsvc
from ..services import notifications as notify
from ..services.audit import log_action

bp = Blueprint('backups', __name__, url_prefix='/backups')


@bp.route('/')
@login_required
@require_permission(Permission.BACKUP)
def index():
    from ..services import device_context as _dc
    _cur = _dc.current_appliance()
    if _cur is None:
        return redirect(url_for('architecture.index'))
    return redirect(url_for('backups.list_backups', id=_cur.id))


@bp.route('/<int:id>')
@login_required
@require_permission(Permission.BACKUP)
def list_backups(id):
    appliance = visible_appliance_or_404(id)
    backups = (ConfigBackup.query
               .filter_by(appliance_id=id)
               .order_by(ConfigBackup.created_at.desc())
               .all())
    return render_template('backups/list.html', appliance=appliance,
                           backups=backups, error=None)


def _run_backup_job(app, job_id, appliance_id, user_id, created_by, link,
                    method="auto"):
    """Worker: pull a backup off the device into the vault, then notify."""
    with app.app_context():
        appliance = Appliance.query.get(appliance_id)
        if appliance is None:
            jobsvc.finish_error(job_id, "appliance no longer exists")
            return
        try:
            _how = {"rest": "device REST backup",
                    "ssh": "SSH CLI dump (show full-configuration)"}.get(
                        method, "REST first, SSH CLI fallback")
            jobsvc.set_progress(job_id, 10,
                                f"Requesting a config backup from {appliance.name}…")
            jobsvc.set_progress(job_id, 40,
                                f"Downloading the configuration into the vault ({_how})…")
            cb = backup_svc.fetch_device_backup_auto(
                appliance, created_by=created_by or "", method=method)
            log_action('backup.create', appliance_id=appliance.id,
                       detail=f'Stored backup {cb.filename} ({cb.size_kb()} KB) '
                              f'from {appliance.name}')
            msg = (f'{appliance.name}: stored “{cb.filename}” '
                   f'({cb.size_kb()} KB) in the vault.')
            jobsvc.finish_success(job_id, message=msg,
                                  result={"backup_id": cb.id, "filename": cb.filename,
                                          "size_bytes": cb.size_bytes,
                                          "appliance_id": appliance.id,
                                          "reload": True, "reload_path": link})
            if user_id:
                notify.push(user_id, f"Backup ready: {appliance.name}",
                            kind=notify.Notification.KIND_SUCCESS, body=msg[:400],
                            link=link)
        except Exception as exc:  # noqa: BLE001
            emsg = (f"Backup failed for {appliance.name}: "
                    f"{type(exc).__name__}: {exc}. You can upload a .conf "
                    f"manually instead.")
            jobsvc.finish_error(job_id, emsg[:380])
            if user_id:
                notify.push(user_id, f"Backup failed: {appliance.name}",
                            kind=notify.Notification.KIND_ERROR, body=emsg[:400],
                            link=link)


@bp.route('/<int:id>/create', methods=['POST'])
@login_required
@require_permission(Permission.BACKUP)
def create_backup(id):
    appliance = visible_appliance_or_404(id)
    method = (request.form.get('method') or 'auto').lower()
    if method not in ('auto', 'rest', 'ssh'):
        method = 'auto'
    uid = getattr(current_user, 'id', None)
    uname = getattr(current_user, 'username', '') or ''
    job = jobsvc.create_job("device_backup", f"Backup — {appliance.name}",
                            by=uname,
                            meta={"appliance_id": appliance.id, "appliance": appliance.name},
                            cancelable=False)
    app_obj = current_app._get_current_object()
    aid = appliance.id
    # url_for needs the request context — resolve the notification link HERE,
    # never inside the worker thread (no SERVER_NAME configured).
    link = url_for('backups.list_backups', id=aid)
    jobsvc.run_async(app_obj, job["id"],
                     lambda app, jid: _run_backup_job(app, jid, aid, uid, uname, link, method))
    wants_json = (request.headers.get('X-Requested-With') == 'XMLHttpRequest'
                  or request.accept_mimetypes.best == 'application/json')
    if wants_json:
        return jsonify({"job_id": job["id"]})
    flash(f'Backup started for {appliance.name} — you’ll be notified when it '
          f'completes (track it in the Jobs dock).', 'info')
    return redirect(url_for('backups.list_backups', id=id))


@bp.route('/<int:id>/upload', methods=['POST'])
@login_required
@require_permission(Permission.BACKUP)
def upload_backup(id):
    """Reliable path: upload a .conf into the vault (device-side create can -901)."""
    appliance = visible_appliance_or_404(id)
    up = request.files.get('config_file')
    if up is None or not up.filename:
        flash('Choose a .conf configuration file to upload into the vault.', 'warning')
        return redirect(url_for('backups.list_backups', id=id))
    data = up.read()
    if not data:
        flash('The uploaded file is empty.', 'warning')
        return redirect(url_for('backups.list_backups', id=id))
    try:
        cb = backup_svc.store_bytes(
            appliance_id=appliance.id, appliance_name=appliance.name, data=data,
            filename=up.filename, source='upload',
            created_by=getattr(current_user, 'username', '') or '',
            note=(request.form.get('note') or '').strip() or None)
    except Exception as exc:  # noqa: BLE001
        flash(f'Could not store the upload: {type(exc).__name__}: {exc}', 'danger')
        return redirect(url_for('backups.list_backups', id=id))
    log_action('backup.upload', appliance_id=appliance.id,
               detail=f'Uploaded {cb.filename} ({cb.size_kb()} KB) into the vault')
    flash(f'Stored “{cb.filename}” in the vault ({cb.size_kb()} KB'
          f'{", encrypted" if cb.encrypted else ""}).', 'success')
    return redirect(url_for('backups.list_backups', id=id))


@bp.route('/<int:id>/download/<int:backup_id>')
@login_required
@require_permission(Permission.BACKUP)
def download_backup(id, backup_id):
    cb = ConfigBackup.query.filter_by(id=backup_id, appliance_id=id).first_or_404()
    try:
        data = backup_svc.read_vault_bytes(cb)
    except Exception as exc:  # noqa: BLE001
        flash(f'Stored backup unreadable: {type(exc).__name__}: {exc}', 'danger')
        return redirect(url_for('backups.list_backups', id=id))
    log_action('backup.download', appliance_id=id, detail=f'Downloaded {cb.filename}')
    return Response(data, mimetype='application/octet-stream',
                    headers={'Content-Disposition': f'attachment; filename="{cb.filename}"'})


@bp.route('/<int:id>/delete/<int:backup_id>', methods=['POST'])
@login_required
@require_permission(Permission.BACKUP)
def delete_backup(id, backup_id):
    cb = ConfigBackup.query.filter_by(id=backup_id, appliance_id=id).first_or_404()
    meta = cb.filename
    backup_svc.delete_vault(cb)
    log_action('backup.delete', appliance_id=id, detail=f'Deleted {meta} from the vault')
    flash(f'Deleted backup “{meta}” from the vault.', 'success')
    return redirect(url_for('backups.list_backups', id=id))
