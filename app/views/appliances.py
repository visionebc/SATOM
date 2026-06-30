import json
import os

from flask import (
    Blueprint, render_template, request, jsonify, flash, redirect, url_for,
    send_file, abort,
)
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from sqlalchemy.exc import IntegrityError
from ..models import Appliance, ApplianceInterface, AuditLog, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..errors import log_exception
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action
from ..services import settings_store as store
from ..services import datasheets

HW_TYPES = ("hardware", "vm", "unknown")
HA_MODES = ("per_node", "vip")


def _parse_ha(form):
    """Return (is_cluster, ha_mode, ha_vip) from a posted appliance form."""
    is_cluster = form.get("is_cluster") == "on"
    if not is_cluster:
        return False, None, None
    mode = (form.get("ha_mode", "") or "").strip().lower()
    if mode not in HA_MODES:
        mode = "per_node"
    vip = (form.get("ha_vip", "") or "").strip() or None
    return True, mode, (vip if mode == "vip" else None)


def _clean_hw_type(raw: str) -> str:
    raw = (raw or "").strip().lower()
    return raw if raw in HW_TYPES else "unknown"


def _rebuild_interfaces(appliance) -> None:
    """Replace-all the appliance's documented interfaces from the posted form
    arrays (if_name[]/if_type[]/if_connected[]/if_ip[]/if_notes[]). Rows whose
    name is blank are skipped."""
    names = request.form.getlist("if_name")
    types = request.form.getlist("if_type")
    conns = request.form.getlist("if_connected")
    ips = request.form.getlist("if_ip")
    notes = request.form.getlist("if_notes")

    ApplianceInterface.query.filter_by(appliance_id=appliance.id).delete()
    order = 0
    for i, raw_name in enumerate(names):
        name = (raw_name or "").strip()
        if not name:
            continue
        db.session.add(ApplianceInterface(
            appliance_id=appliance.id,
            name=name[:64],
            if_type=(types[i].strip()[:64] if i < len(types) and types[i].strip() else None),
            connected_to=(conns[i].strip()[:256] if i < len(conns) and conns[i].strip() else None),
            ip_address=(ips[i].strip()[:64] if i < len(ips) and ips[i].strip() else None),
            notes=(notes[i].strip() if i < len(notes) and notes[i].strip() else None),
            sort_order=order,
        ))
        order += 1

bp = Blueprint('appliances', __name__, url_prefix='/appliances')


@bp.route('/')
@login_required
def index():
    appliances = Appliance.query.order_by(Appliance.name).all()
    return render_template('appliances/index.html', appliances=appliances,
                           classification=store.all_classification())


@bp.route('/<int:id>')
@login_required
def detail(id):
    appliance = Appliance.query.get_or_404(id)
    recent_audit = AuditLog.query.filter(
        AuditLog.target.like(f'%{appliance.name}%')
    ).order_by(AuditLog.timestamp.desc()).limit(20).all()
    return render_template('appliances/detail.html', appliance=appliance, audit_entries=recent_audit)


@bp.route('/', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def create():
    name = request.form.get('name', '').strip()
    kind = request.form.get('kind', 'fortiweb').strip()
    host = request.form.get('host', '').strip()
    port = int(request.form.get('port', 443) or 443)
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    verify_ssl = request.form.get('verify_ssl') == 'on'
    vdom = request.form.get('vdom', '').strip() or None
    tags = request.form.get('tags', '').strip() or None
    department = request.form.get('department', '').strip() or None
    zone = request.form.get('zone', '').strip() or None
    line = request.form.get('line', '').strip() or None
    hw_type = _clean_hw_type(request.form.get('hw_type', 'unknown'))
    model = request.form.get('model', '').strip() or None
    is_cluster, ha_mode, ha_vip = _parse_ha(request.form)

    # VIP cluster: the shared VIP is the connection target.
    if is_cluster and ha_mode == 'vip':
        if not ha_vip:
            flash('A VIP-mode cluster needs the shared VIP address.', 'danger')
            return redirect(url_for('appliances.index'))
        host = host or ha_vip
    # A per-node cluster node 0 has no connection of its own (members do).
    host_required = not (is_cluster and ha_mode == 'per_node')
    if not name or (host_required and not host):
        flash('Name and host are required.', 'danger')
        return redirect(url_for('appliances.index'))

    appliance = Appliance(
        name=name, kind=kind, host=host, port=port,
        username=username, verify_ssl=verify_ssl,
        vdom=vdom, tags=tags, department=department, zone=zone, line=line,
        hw_type=hw_type, model=model,
        is_cluster=is_cluster, ha_mode=ha_mode, ha_vip=ha_vip,
        password_enc='placeholder',
    )
    appliance.set_password(password)
    db.session.add(appliance)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash(f'Appliance name {name!r} already exists.', 'danger')
        return redirect(url_for('appliances.index'))
    log_action('appliance.create', target=name)
    flash(f'Appliance {name} created.', 'success')
    return redirect(url_for('appliances.detail', id=appliance.id))


@bp.route('/<int:id>/edit')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def edit(id):
    appliance = Appliance.query.get_or_404(id)
    return render_template('appliances/edit.html', appliance=appliance,
                           classification=store.all_classification())


@bp.route('/<int:id>/edit', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def edit_save(id):
    appliance = Appliance.query.get_or_404(id)
    appliance.name = request.form.get('name', appliance.name).strip()
    appliance.kind = request.form.get('kind', appliance.kind).strip()
    appliance.host = request.form.get('host', appliance.host).strip()
    appliance.port = int(request.form.get('port', appliance.port) or 443)
    appliance.username = request.form.get('username', appliance.username).strip()
    appliance.verify_ssl = request.form.get('verify_ssl') == 'on'
    appliance.vdom = request.form.get('vdom', appliance.vdom or '').strip() or None
    appliance.tags = request.form.get('tags', appliance.tags or '').strip() or None
    appliance.department = request.form.get('department', appliance.department or '').strip() or None
    appliance.zone = request.form.get('zone', appliance.zone or '').strip() or None
    appliance.line = request.form.get('line', appliance.line or '').strip() or None
    appliance.hw_type = _clean_hw_type(request.form.get('hw_type', appliance.hw_type or 'unknown'))
    appliance.model = request.form.get('model', appliance.model or '').strip() or None
    # HA: a member node's identity is managed from its cluster, not here; only
    # a top-level row (standalone or node 0) toggles cluster/mode/vip.
    if not appliance.is_cluster_member:
        is_cluster, ha_mode, ha_vip = _parse_ha(request.form)
        appliance.is_cluster = is_cluster
        appliance.ha_mode = ha_mode
        appliance.ha_vip = ha_vip
        if is_cluster and ha_mode == 'vip' and ha_vip:
            appliance.host = ha_vip
    password = request.form.get('password', '')
    if password:
        appliance.set_password(password)

    # -- datasheet PDF: remove, replace, or keep --------------------------
    if request.form.get('datasheet_remove') == 'on':
        datasheets.delete(appliance.id)
        appliance.datasheet_filename = None
    upload = request.files.get('datasheet')
    if upload and (upload.filename or '').strip():
        try:
            appliance.datasheet_filename = datasheets.save(appliance.id, upload)
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), 'danger')
            return redirect(url_for('appliances.edit', id=appliance.id))

    # -- physical interfaces: replace-all from posted rows ----------------
    _rebuild_interfaces(appliance)

    db.session.commit()
    log_action('appliance.update', target=appliance.name)
    flash(f'Appliance {appliance.name} updated.', 'success')
    return redirect(url_for('appliances.detail', id=appliance.id))


@bp.route('/<int:id>/delete', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def delete(id):
    appliance = Appliance.query.get_or_404(id)
    name = appliance.name
    datasheets.delete(appliance.id)  # drop the PDF file (interfaces cascade via FK)
    db.session.delete(appliance)
    db.session.commit()
    log_action('appliance.delete', target=name)
    flash(f'Appliance {name} deleted.', 'success')
    return redirect(url_for('appliances.index'))


@bp.route('/<int:id>/datasheet')
@login_required
def datasheet(id):
    """Serve the appliance's datasheet PDF inline (read-only, any logged-in user)."""
    appliance = Appliance.query.get_or_404(id)
    if not appliance.datasheet_filename:
        abort(404)
    path = datasheets.path_for(appliance.id)
    if not os.path.exists(path):
        abort(404)
    return send_file(
        path,
        mimetype='application/pdf',
        as_attachment=False,
        download_name=appliance.datasheet_filename,
    )


@bp.route('/<int:id>/test', methods=['POST'])
@login_required
def test_connection(id):
    appliance = Appliance.query.get_or_404(id)
    try:
        if appliance.kind == 'fortiweb':
            client = FortiWebClient(appliance)
        else:
            client = FortiADCClient(appliance)
        status = client.status_check()
        log_action('appliance.test', target=appliance.name)
        return jsonify({'ok': True, 'status': status})
    except Exception as exc:
        eid = log_exception(exc, context='appliances.test_connection')
        return jsonify({'ok': False, 'status': str(exc), 'error_id': eid})


# ===========================================================================
# HA cluster membership
# ===========================================================================

def _clean_role_hint(raw):
    raw = (raw or '').strip().lower()
    return raw if raw in ('primary', 'secondary') else None


@bp.route('/<int:id>/members', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def add_member(id):
    """Attach an existing standalone appliance, or create a new member node,
    under a cluster node 0."""
    node0 = Appliance.query.get_or_404(id)
    if not node0.is_cluster:
        flash('This appliance is not an HA cluster.', 'warning')
        return redirect(url_for('appliances.detail', id=id))
    role_hint = _clean_role_hint(request.form.get('ha_role_hint'))
    attach_id = (request.form.get('attach_id') or '').strip()

    if attach_id:
        m = Appliance.query.get(int(attach_id)) if attach_id.isdigit() else None
        if m is None or not m.is_standalone or m.id == node0.id:
            flash('Pick an existing standalone appliance to attach.', 'danger')
            return redirect(url_for('appliances.detail', id=id))
        m.parent_id = node0.id
        m.is_cluster_member = True
        m.ha_role_hint = role_hint
    else:
        mname = (request.form.get('member_name') or '').strip()
        mhost = (request.form.get('member_host') or '').strip()
        if not mname or not mhost:
            flash('Member name and host are required.', 'danger')
            return redirect(url_for('appliances.detail', id=id))
        m = Appliance(
            name=mname, kind=node0.kind, host=mhost,
            port=int(request.form.get('member_port', 443) or 443),
            username=(request.form.get('member_username') or '').strip(),
            verify_ssl=node0.verify_ssl, vdom=node0.vdom,
            zone=node0.zone, line=node0.line, department=node0.department,
            is_cluster_member=True, parent_id=node0.id, ha_role_hint=role_hint,
            password_enc='placeholder',
        )
        m.set_password(request.form.get('member_password', ''))
        db.session.add(m)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash('A member with that name already exists.', 'danger')
        return redirect(url_for('appliances.detail', id=id))
    log_action('appliance.member_add', target=node0.name)
    flash('Cluster member added.', 'success')
    return redirect(url_for('appliances.detail', id=id))


@bp.route('/<int:id>/members/<int:mid>/detach', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def detach_member(id, mid):
    """Detach a member (back to standalone) or delete it outright (delete=1)."""
    node0 = Appliance.query.get_or_404(id)
    m = Appliance.query.get_or_404(mid)
    if m.parent_id != node0.id:
        flash('That appliance is not a member of this cluster.', 'warning')
        return redirect(url_for('appliances.detail', id=id))
    if request.form.get('delete') == '1':
        db.session.delete(m)
        msg = 'Cluster member deleted.'
    else:
        m.parent_id = None
        m.is_cluster_member = False
        m.ha_role_hint = None
        msg = 'Cluster member detached (now standalone).'
    db.session.commit()
    log_action('appliance.member_detach', target=node0.name)
    flash(msg, 'success')
    return redirect(url_for('appliances.detail', id=id))


# ===========================================================================
# Appliance actions (ported from the desktop app): Policy Inspector,
# Rediscovery, Console, Upgrade Preparation, Upgrade. FortiWeb only.
# ===========================================================================

def _fortiweb_or_404(id):
    appliance = Appliance.query.get_or_404(id)
    if appliance.kind != 'fortiweb':
        flash('This action is only available for FortiWeb appliances.', 'warning')
        return None, appliance
    return appliance, appliance


# -- 1. Policy Inspector -----------------------------------------------------
@bp.route('/<int:id>/inspector')
@login_required
@require_permission('appliances.view')
def inspector(id):
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        return redirect(url_for('appliances.detail', id=id))
    from ..services import inspector as insp
    policy = request.args.get('policy', '').strip()
    result, error = None, None
    try:
        client = appliance.build_client()
        if policy:
            result = {'policies': [insp.inspect_policy(client, policy)], 'errors': [], 'count': 1}
        else:
            result = insp.inspect_all(client)
        log_action('appliance.inspect', target=appliance.name,
                   extra={'policies': result.get('count'), 'one': policy or None})
    except Exception as exc:
        error = f'{type(exc).__name__}: {exc}'
    return render_template('appliances/inspector.html', appliance=appliance,
                           result=result, error=error, one_policy=policy)


# -- 2. Rediscovery ----------------------------------------------------------
@bp.route('/<int:id>/rediscover')
@login_required
@require_permission('appliances.view')
def rediscover(id):
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        return redirect(url_for('appliances.detail', id=id))
    from ..services import rediscovery
    return render_template('appliances/rediscover.html', appliance=appliance,
                           progress=rediscovery.status(appliance.id),
                           snapshot=rediscovery.latest_snapshot_meta(appliance.id),
                           plan_size=len(rediscovery.sweep_plan()))


@bp.route('/<int:id>/rediscover/start', methods=['POST'])
@login_required
@require_permission('appliances.apply')
def rediscover_start(id):
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        return jsonify({'started': False, 'reason': 'not a FortiWeb'}), 400
    from ..services import rediscovery
    from flask_login import current_user
    res = rediscovery.start(appliance, by=getattr(current_user, 'username', ''))
    if res.get('started'):
        log_action('appliance.rediscover', target=appliance.name)
    return jsonify(res)


@bp.route('/<int:id>/rediscover/status')
@login_required
@require_permission('appliances.view')
def rediscover_status(id):
    appliance = Appliance.query.get_or_404(id)
    from ..services import rediscovery
    st = rediscovery.status(id) or {'state': 'idle'}
    if st.get('state') == 'done':
        # Auto-fill physical inventory from the snapshot, once per snapshot.
        try:
            inv = rediscovery.maybe_apply_inventory(appliance)
            if inv:
                st['inventory'] = inv
        except Exception as exc:  # noqa: BLE001 — sync must never break the poll
            st['inventory'] = {'applied': False, 'reason': str(exc)[:120]}
    return jsonify(st)


# -- 3. Console (read-only SSH) ---------------------------------------------
@bp.route('/<int:id>/console')
@login_required
@require_permission('appliances.view')
def console(id):
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        return redirect(url_for('appliances.detail', id=id))
    from ..services import ssh_ops
    return render_template('appliances/console.html', appliance=appliance,
                           presets=ssh_ops.TROUBLESHOOT)


@bp.route('/<int:id>/console/run', methods=['POST'])
@login_required
@require_permission('appliances.apply')
def console_run(id):
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        return jsonify({'ok': False, 'error': 'not a FortiWeb'}), 400
    from ..services import ssh_ops
    command = (request.json or {}).get('command', '') if request.is_json \
        else request.form.get('command', '')
    try:
        cmd = ssh_ops.assert_readonly(command)  # fail fast, before connecting
    except ssh_ops.ReadOnlyViolation as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400
    try:
        output = ssh_ops.run_command(appliance, cmd)
        log_action('appliance.console', target=appliance.name, extra={'cmd': cmd})
        return jsonify({'ok': True, 'command': cmd, 'output': output})
    except Exception as exc:
        eid = log_exception(exc, context='appliances.console_run')
        return jsonify({'ok': False, 'error': f'{type(exc).__name__}: {exc}', 'error_id': eid})


# -- 4. Upgrade Preparation (read-only) -------------------------------------
@bp.route('/<int:id>/upgrade/prep')
@login_required
@require_permission(Permission.BACKUP)
def upgrade_prep(id):
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        return redirect(url_for('appliances.detail', id=id))
    return render_template('appliances/upgrade_prep.html', appliance=appliance)


@bp.route('/<int:id>/upgrade/prep/run', methods=['POST'])
@login_required
@require_permission(Permission.BACKUP)
def upgrade_prep_run(id):
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        return jsonify({'ok': False, 'error': 'not a FortiWeb'}), 400
    from ..services import upgrade
    opts = request.json or {}
    try:
        result = upgrade.prepare(
            appliance,
            do_backup=opts.get('backup', True),
            do_health=opts.get('health', True),
            do_services=opts.get('services', True),
        )
        log_action('appliance.upgrade_prep', target=appliance.name)
        return jsonify({'ok': True, 'result': result})
    except Exception as exc:
        eid = log_exception(exc, context='appliances.upgrade_prep_run')
        return jsonify({'ok': False, 'error': f'{type(exc).__name__}: {exc}', 'error_id': eid})


# -- 5. Upgrade (firmware push from the repository — WRITE, dry-run default) --
def _selected_compatible_image(appliance, image_id):
    """Resolve a posted image_id to a FirmwareImage that is actually compatible
    with this appliance (defence against a tampered / stale form). Returns the
    row, or None when the id is missing, unknown, or not compatible."""
    from ..models_firmware import FirmwareImage
    from ..services import upgrade as upg
    try:
        iid = int(image_id)
    except (TypeError, ValueError):
        return None
    if iid not in {fw.id for fw in upg.compatible_images(appliance)}:
        return None
    return FirmwareImage.query.get(iid)


@bp.route('/<int:id>/upgrade')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def upgrade(id):
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        return redirect(url_for('appliances.detail', id=id))
    from ..services import upgrade as upg
    fw = ''
    try:
        fw = upg.firmware_version(appliance.build_client(timeout=8))
    except Exception:
        fw = ''
    images = upg.compatible_images(appliance)
    return render_template('appliances/upgrade.html', appliance=appliance,
                           firmware=fw, images=images)


@bp.route('/<int:id>/upgrade', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def upgrade_push(id):
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        flash('Not a FortiWeb appliance.', 'danger')
        return redirect(url_for('appliances.detail', id=id))
    from ..services import upgrade as upg

    image = _selected_compatible_image(appliance, request.form.get('image_id'))
    if image is None:
        flash('Select a compatible firmware image from the repository first.', 'danger')
        return redirect(url_for('appliances.upgrade', id=id))
    dry_run = request.form.get('dry_run', 'on') == 'on'
    confirm_maturity = request.form.get('confirm_maturity') == 'on'

    # A live push requires typing the exact appliance name (defence against a
    # mis-click rebooting the wrong box).
    if not dry_run and request.form.get('confirm_name', '').strip() != appliance.name:
        flash('Live upgrade requires typing the exact appliance name to confirm.', 'danger')
        return redirect(url_for('appliances.upgrade', id=id))

    try:
        image_bytes = upg.read_image_bytes(image)
    except Exception as exc:
        flash(f'Firmware file problem: {type(exc).__name__}: {exc}', 'danger')
        return redirect(url_for('appliances.upgrade', id=id))

    try:
        result = upg.push_firmware(
            appliance, image_bytes, image.filename,
            dry_run=dry_run, confirm_maturity=confirm_maturity,
        )
    except Exception as exc:
        flash(f'Upgrade failed: {type(exc).__name__}: {exc}', 'danger')
        return redirect(url_for('appliances.upgrade', id=id))

    images = upg.compatible_images(appliance)
    return render_template('appliances/upgrade.html', appliance=appliance,
                           firmware=result.get('firmware_before', ''),
                           result=result, images=images, selected_id=image.id)


@bp.route('/<int:id>/upgrade/schedule', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def upgrade_schedule(id):
    """Record a one-shot scheduled firmware upgrade carrying the chosen stored
    image. The dedicated scheduler sidecar fires it at the set time. NOTE: the
    headless upgrade executor is a guarded stub today (it will NOT auto-flash),
    so this records the intent + the validated image — see the page note."""
    from datetime import datetime  # noqa: F401 (kept for parity / future use)
    from ..models import ScheduledAction
    from ..services.scheduler import compute_next_run

    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        flash('Not a FortiWeb appliance.', 'danger')
        return redirect(url_for('appliances.detail', id=id))

    image = _selected_compatible_image(appliance, request.form.get('image_id'))
    if image is None:
        flash('Select a compatible firmware image from the repository first.', 'danger')
        return redirect(url_for('appliances.upgrade', id=id))

    when = (request.form.get('when') or '').strip()
    if not when:
        flash('Pick a date and time for the scheduled upgrade.', 'danger')
        return redirect(url_for('appliances.upgrade', id=id))
    schedule = {"at": when}
    next_run = compute_next_run('once', schedule)
    if next_run is None:
        flash('The scheduled time must be in the future (interpreted as UTC).', 'danger')
        return redirect(url_for('appliances.upgrade', id=id))

    confirm_maturity = request.form.get('confirm_maturity') == 'on'
    action = ScheduledAction(
        name=f"Upgrade {appliance.name} -> {image.version}",
        scope='admin', action='upgrade',
        targets=json.dumps([appliance.id]),
        params=json.dumps({
            "image_id": image.id,
            "image_filename": image.filename,
            "image_version": image.version,
            "confirm_maturity": confirm_maturity,
        }),
        schedule_kind='once', schedule=json.dumps(schedule),
        enabled=True, next_run=next_run,
        created_by=getattr(current_user, 'username', '') or '',
    )
    db.session.add(action)
    db.session.commit()
    log_action('appliance.upgrade_schedule', target=appliance.name,
               extra={"image_id": image.id, "version": image.version, "at": when})
    flash(f'Scheduled upgrade of {appliance.name} to {image.version} at {when} (UTC). '
          'Unattended flashing is gated — review it under Scheduled Actions.', 'success')
    return redirect(url_for('appliances.upgrade', id=id))
