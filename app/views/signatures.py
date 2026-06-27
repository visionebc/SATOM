"""Signatures — sync the FortiWeb signature database from a base device.

Mirrors the desktop ``SignatureSyncPage``: pick a base FortiWeb (the same
FortiGuard signature package is on every box), read the whole signature catalog
(main class -> sub-class -> individual signature + description) READ-ONLY, and
cache it to ``data/signatures.json`` so the rest of the app can later show
signatures by name instead of a blind id. Re-run to pick up new firmware / new
signatures.

Admin-only (USER_MANAGE). The blueprint import is side-effect-free; every device
call is wrapped so an unreachable FortiWeb flashes an error instead of 500-ing.
"""
from __future__ import annotations

import os
import re

from flask import (
    Blueprint, current_app, flash, redirect, render_template, request, url_for,
)
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Appliance, Permission
from ..clients.fortiweb import FortiWebClient
from ..services.audit import log_action
from ..services import signature_catalog as sigcat

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


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    """Base-device selector + cached-status line + Sync button.

    Renders even with NO devices and no cached catalog file (db is None)."""
    appliances = Appliance.query.filter_by(kind='fortiweb').order_by(Appliance.name).all()
    db = sigcat.load_signature_db(_data_path())
    return render_template('signatures/index.html', appliances=appliances, db=db)


@bp.route('/sync', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def sync():
    """Read the signature database from the selected base device (READ-ONLY),
    cache it to data/signatures.json, flash a summary, redirect back."""
    appliance_id = request.form.get('appliance_id', type=int)
    appliance = (
        Appliance.query.filter_by(id=appliance_id, kind='fortiweb').first()
        if appliance_id else None
    )
    if appliance is None:
        flash('Select a base FortiWeb device to sync from.', 'warning')
        return redirect(url_for('signatures.index'))

    # Every device call wrapped: an unreachable box flashes an error, never 500s.
    try:
        client = FortiWebClient(appliance)
        firmware = _read_firmware(client)
        signature_set = sigcat.pick_signature_set(client)
        if not signature_set:
            flash(
                f'No signature set found on {appliance.name}; cannot read the '
                'signature database.', 'warning')
            return redirect(url_for('signatures.index'))
        db = sigcat.sync_signature_database(client, signature_set, firmware=firmware)
        sigcat.save_signature_db(db, _data_path())
    except Exception as exc:  # noqa: BLE001 — surface, don't crash the page
        flash(f'Signature sync from {appliance.name} failed: {exc}', 'danger')
        return redirect(url_for('signatures.index'))

    count = len(db.signatures)
    log_action(
        'signatures.sync', target=appliance.name,
        extra={'count': count, 'set': signature_set, 'firmware': firmware})
    if count:
        flash(
            f'Synced {count} signatures across {db.subclass_count} sub-classes '
            f'from {appliance.name} (set "{signature_set}", firmware '
            f'{firmware or "?"}).', 'success')
    else:
        flash(
            f'Connected to {appliance.name} but read 0 signatures '
            f'(set "{signature_set}"). Check the base device.', 'warning')
    return redirect(url_for('signatures.index'))
