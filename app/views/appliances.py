import json
import os

from flask import (
    Blueprint, render_template, request, jsonify, flash, redirect, url_for,
    send_file, abort, current_app,
)
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from sqlalchemy.exc import IntegrityError
from ..models import Appliance, ApplianceInterface, AuditLog, db, Permission
from ..models_backup import ConfigBackup
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
    # Top-level rows only: standalones + cluster node 0. Member nodes are
    # rendered nested under their cluster, never as standalone entries.
    appliances = (Appliance.query
                  .filter(Appliance.parent_id.is_(None))
                  .order_by(Appliance.name).all())
    from ..services import rediscovery
    return render_template('appliances/index.html', appliances=appliances,
                           classification=store.all_classification(),
                           has_snapshot=rediscovery.has_snapshot)


@bp.route('/<int:id>/members/roles')
@login_required
def member_roles(id):
    """Live HA role per member (read-only JSON for the cluster sub-cards)."""
    node0 = Appliance.query.get_or_404(id)
    from ..services import ha
    return jsonify({str(m.id): ha.member_role(m, timeout=5.0) for m in node0.members})


@bp.route('/<int:id>')
@login_required
def detail(id):
    appliance = Appliance.query.get_or_404(id)
    recent_audit = AuditLog.query.filter(
        AuditLog.target.like(f'%{appliance.name}%')
    ).order_by(AuditLog.timestamp.desc()).limit(20).all()
    from ..services import rediscovery
    return render_template('appliances/detail.html', appliance=appliance, audit_entries=recent_audit,
                           has_snapshot=rediscovery.has_snapshot)


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
    from ..services import rediscovery, analysis
    deep_fresh = analysis.deep_freshness([appliance.id]).get(str(appliance.id))
    return render_template('appliances/rediscover.html', appliance=appliance,
                           progress=rediscovery.status(appliance.id),
                           snapshot=rediscovery.latest_snapshot_meta(appliance.id),
                           deep_fresh=deep_fresh,
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
    deep = (request.form.get('deep') or request.args.get('deep') or '').lower() \
        in ('1', 'true', 'on', 'yes')
    res = rediscovery.start(appliance, by=getattr(current_user, 'username', ''),
                            deep=deep)
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
    _persist_firmware(appliance, fw)
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
    dry_run = request.form.get('dry_run') == 'on'
    confirm_maturity = request.form.get('confirm_maturity') == 'on'

    if _wants_json():
        return _spawn_flash_job(appliance, image, 'upgrade', dry_run, confirm_maturity)

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


# -- Async firmware flash (upgrade/downgrade) via the background-jobs framework -
def _wants_json() -> bool:
    """AJAX path \u2014 the browser's fetch sets this header (or an ajax=1 field)."""
    return (request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or (request.form.get("ajax") or "") in ("1", "true"))


def _persist_firmware(appliance, fw):
    """Best-effort: record the appliance's last-known OS version so the UI
    reflects reality after a flash. Never blocks anything."""
    try:
        from ..extensions import db
        fw = (fw or '').strip()
        if fw and getattr(appliance, 'firmware', None) != fw:
            appliance.firmware = fw
            db.session.commit()
    except Exception:  # noqa: BLE001
        try:
            from ..extensions import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass


@bp.route('/flash-report/<job_id>', methods=['GET'])
@login_required
def flash_report_view(job_id):
    """Serve the self-contained before/after firmware-flash report for a job.
    Served from DISK so it survives the ephemeral job record; any signed-in
    operator may open any firmware report (they are fleet-wide ops artifacts)."""
    from ..services import flash_report as _fr
    page = _fr.read_report(job_id)
    if page is None:
        abort(404)
    return page


@bp.route('/flash-reports', methods=['GET'])
@login_required
def flash_reports():
    """History of every firmware-flash before/after report (upgrade + downgrade),
    newest first. Optional ?appliance_id= focuses one box."""
    from ..services import flash_report as _fr
    try:
        aid = int(request.args.get('appliance_id') or 0) or None
    except (TypeError, ValueError):
        aid = None
    reports = _fr.list_reports(appliance_id=aid)
    focus = Appliance.query.get(aid) if aid else None
    return render_template('appliances/flash_reports.html',
                           reports=reports, focus=focus)


def _flash_worker(app, job_id, appliance_id, image_id, filename,
                  dry_run, confirm_maturity, kind, user_id, link):
    """Background firmware flash: read image \u2192 push \u2192 monitor reboot/recovery
    \u2192 basic health checks \u2192 bell notification. kind \u2208 'upgrade' | 'downgrade'."""
    from ..models_firmware import FirmwareImage
    from ..services import upgrade as upg, jobs as jobsvc
    from ..services import notifications as notify
    K = notify.Notification
    verb = 'Downgrade' if kind == 'downgrade' else 'Upgrade'
    with app.app_context():
        appliance = Appliance.query.get(appliance_id)
        image = FirmwareImage.query.get(image_id)
        if appliance is None or image is None:
            jobsvc.finish_error(job_id, "appliance or image no longer exists")
            return
        try:
            jobsvc.set_progress(job_id, 3, "Reading firmware image\u2026")
            image_bytes = upg.read_image_bytes(image)

            # Downgrade (esp. cross-branch, e.g. 8.0->7.6) must target the ALTERNATE
            # partition and answer the box's maturity + downgrade confirmations,
            # mirroring the GUI "Upload and Reboot". A same-branch upgrade keeps part=0.
            fw_part, fw_active, confirm_dg = 0, 0, False
            if kind == 'downgrade':
                try:
                    _pt = upg.read_partitions(appliance)
                    _alt = _pt.get('alternate') or {}
                    fw_part = int(_alt.get('partition') or 0)
                    fw_active = int(bool(_alt.get('active')))
                    confirm_dg = True
                    confirm_maturity = True
                except Exception:  # noqa: BLE001
                    pass

            if dry_run:
                jobsvc.set_progress(job_id, 40, "Validating image + maintenance permission\u2026")
                result = upg.push_firmware(appliance, image_bytes, filename,
                                           dry_run=True, confirm_maturity=confirm_maturity,
                                           confirm_downgrade=confirm_dg,
                                           part=fw_part, active=fw_active)
                jobsvc.finish_success(job_id, message=result.get("message", "Validated."),
                                      result={"phase": "dry_run"})
                return

            # Runbook pre-flight for BOTH upgrade and downgrade: safety backup +
            # SSH health battery + published-service baseline before the flash,
            # each step announced. Read-only + best-effort (never blocks a flash).
            before_snap = None
            try:
                before_snap = upg.prepare(
                    appliance, do_backup=True, do_health=True, do_services=True,
                    progress=lambda p, m: jobsvc.set_progress(job_id, p, m))
            except Exception:  # noqa: BLE001 - best-effort; never blocks an authorized flash
                before_snap = {"error": "pre-flight incomplete"}

            jobsvc.set_progress(job_id, 16,
                                f"Uploading {image.size_mb()} MB and triggering the flash\u2026")
            result = upg.push_firmware(appliance, image_bytes, filename,
                                       dry_run=False, confirm_maturity=confirm_maturity,
                                       confirm_downgrade=confirm_dg,
                                       part=fw_part, active=fw_active)
            image_bytes = None  # free ~300 MB
            fw_before = result.get("firmware_before", "")

            if not result.get("ok"):
                msg = result.get("message", "the appliance did not accept the flash")
                jobsvc.finish_error(job_id, msg)
                if user_id:
                    notify.push(user_id, f"{verb} not started: {appliance.name}",
                                kind=K.KIND_ERROR, body=msg[:400], link=link)
                return

            jobsvc.set_progress(job_id, 45, "Image accepted \u2014 the appliance is rebooting\u2026")
            rec = upg.monitor_recovery(
                appliance,
                progress=lambda p, m: jobsvc.set_progress(job_id, p, m))

            if not rec.get("recovered"):
                msg = (f"{appliance.name} did not come back online within the wait window "
                       f"(~{int(rec.get('elapsed_s', 0))}s). The flash may still be in progress "
                       f"\u2014 check the console.")
                jobsvc.finish_error(job_id, msg)
                if user_id:
                    notify.push(user_id, f"{verb}: {appliance.name} not back yet",
                                kind=K.KIND_WARNING, body=msg[:400], link=link)
                return

            # A flash that neither dropped the box NOR changed the firmware did not take
            # (the box rejected/ignored the image). Do not report a false win.
            fw_now = rec.get("firmware_after") or ""
            if not rec.get("went_down") and fw_before and fw_now and fw_now == fw_before:
                msg = (f"{appliance.name} never rebooted and is still on {fw_now}. The image was "
                       f"uploaded but NOT installed - the box did not accept this flash / "
                       f"upgrade path, so the firmware is unchanged.")
                jobsvc.finish_error(job_id, msg)
                if user_id:
                    notify.push(user_id, f"{verb} not applied: {appliance.name}",
                                kind=K.KIND_ERROR, body=msg[:400], link=link)
                return

            # Same runbook AFTER the flash (both kinds): re-test services + SSH
            # health and diff them against the pre-flight baseline, each announced.
            after_snap = None
            try:
                after_snap = upg.postflight(
                    appliance, before_snap,
                    progress=lambda p, m: jobsvc.set_progress(job_id, p, m))
            except Exception:  # noqa: BLE001
                after_snap = {"error": "post-flight incomplete"}

            jobsvc.set_progress(job_id, 96, "Back online \u2014 running basic system checks\u2026")
            health = upg.post_flash_checks(appliance)
            fw_after = rec.get("firmware_after") or health.get("firmware", "")
            svc = health.get("services") or {}
            svc_txt = (f" \u00b7 services {svc['up']}/{svc['total']} reachable"
                       if isinstance(svc, dict) and "up" in svc else "")
            done = (f"{appliance.name} is back online on {fw_after or 'the new firmware'} "
                    f"(was {fw_before or '?'}){svc_txt}. Recovered in "
                    f"{int(rec.get('elapsed_s', 0))}s.")
            if isinstance(before_snap, dict):
                _bk = before_snap.get("backup") or {}
                if _bk.get("ok"):
                    done += f" Pre-{kind} backup: {_bk.get('name')}."
            if fw_after:
                jobsvc.set_progress(job_id, 98,
                                    f"Recording new firmware version {fw_after} on the appliance\u2026")
                _persist_firmware(appliance, fw_after)
            # Render the before/after service + SSH-battery report (both kinds).
            report_url = ""
            try:
                from ..services import flash_report
                _bk_name = (((before_snap or {}).get("backup") or {}).get("name")
                            if isinstance(before_snap, dict) else None)
                report_url = flash_report.write_report(
                    job_id,
                    {"appliance": appliance.name, "appliance_id": appliance.id,
                     "kind": kind, "job_id": job_id,
                     "firmware_before": fw_before, "firmware_after": fw_after,
                     "reachable_after": bool(health.get("api_ok")), "image": filename,
                     "by": (jobsvc.get_job(job_id) or {}).get("by") or "",
                     "downtime_s": rec.get("elapsed_s"), "backup": _bk_name},
                    before_snap, after_snap)
            except Exception:  # noqa: BLE001 - a report failure never sinks a completed flash
                report_url = ""
            if report_url:
                done += " Full before/after report available."
            # Final step (both kinds): a full rediscovery sweep so the manager's
            # cached view of the box reflects the just-flashed firmware. Writes a
            # fresh _config.json snapshot + refreshes the device inventory, and its
            # progress shows on the appliance Rediscovery page. Best-effort: a
            # rediscovery failure never sinks an already-completed flash.
            redisc = None
            try:
                from ..services import rediscovery
                jobsvc.set_progress(job_id, 99,
                                    "Rediscovering the appliance (full config sweep)\u2026")
                _rsnap = rediscovery._client_snapshot(appliance)
                rediscovery._run(_rsnap, by=f"post-{kind}", deep=False)
                _st = rediscovery.status(appliance.id) or {}
                redisc = {"objects": _st.get("objects"),
                          "sections": _st.get("section_count"),
                          "errors": len(_st.get("errors") or []),
                          "summary": _st.get("summary")}
                try:
                    rediscovery.maybe_apply_inventory(appliance)
                except Exception:  # noqa: BLE001
                    pass
                if _st.get("summary"):
                    done += f" Rediscovery: {_st['summary']}."
            except Exception as exc:  # noqa: BLE001 - never sinks a completed flash
                redisc = {"error": f"{type(exc).__name__}: {exc}"[:200]}
            jobsvc.finish_success(job_id, message=done,
                                  result={"phase": "done", "firmware_before": fw_before,
                                          "firmware_after": fw_after, "recovery": rec,
                                          "health": health, "reload": True,
                                          "report_url": report_url,
                                          "rediscovery": redisc,
                                          "runbook": {"before": before_snap, "after": after_snap}})
            try:
                _extra = {"from": fw_before, "to": fw_after, "image_id": image_id}
                if kind == 'downgrade' and isinstance(before_snap, dict):
                    _extra["backup"] = (before_snap.get("backup") or {}).get("name")
                if isinstance(redisc, dict) and not redisc.get("error"):
                    _extra["rediscovered"] = redisc.get("objects")
                log_action(f'appliance.{kind}.complete', target=appliance.name,
                           extra=_extra)
            except Exception:  # noqa: BLE001
                pass
            if user_id:
                notify.push(user_id,
                            f"{verb} complete: {appliance.name} \u2192 {fw_after or image.version}",
                            kind=K.KIND_SUCCESS if health.get("api_ok") else K.KIND_WARNING,
                            body=done[:400], link=(report_url or link))
        except Exception as exc:  # noqa: BLE001
            jobsvc.finish_error(job_id, f"{type(exc).__name__}: {exc}"[:300])
            if user_id:
                notify.push(user_id, f"{verb} failed: {getattr(appliance, 'name', '?')}",
                            kind=K.KIND_ERROR, body=str(exc)[:400], link=link)
    return None


def _spawn_flash_job(appliance, image, kind, dry_run, confirm_maturity):
    """Create the background flash job and return {job_id} JSON (the toast then
    polls /jobs/<id>). Name-confirm is enforced here for the AJAX path."""
    from ..services import jobs as jobsvc
    verb = 'Downgrade' if kind == 'downgrade' else 'Upgrade'
    if not dry_run and (request.form.get('confirm_name', '') or '').strip() != appliance.name:
        return jsonify({"error":
                        f"Type the exact appliance name to authorise the live {kind}."}), 400
    title = (f"Validate {image.version} for {appliance.name}" if dry_run
             else f"{verb} {appliance.name} \u2192 {image.version}")
    user_id = getattr(current_user, 'id', 0) or 0
    link = url_for(f'appliances.{kind}', id=appliance.id)
    job = jobsvc.create_job(f'firmware_{kind}', title,
                            by=getattr(current_user, 'username', '') or '',
                            meta={"appliance_id": appliance.id, "image_id": image.id,
                                  "dry_run": dry_run})
    jobsvc.run_async(
        current_app._get_current_object(), job["id"],
        lambda app, jid: _flash_worker(app, jid, appliance.id, image.id, image.filename,
                                       dry_run, confirm_maturity, kind, user_id, link))
    return jsonify({"job_id": job["id"]})


# -- 6. Downgrade / rollback (real in-app firmware push of an OLDER image) ----
def _downgrade_context(appliance):
    """Picker context for the downgrade page: current firmware, the per-image
    relation vs. current (older/same/newer/unknown), the natural rollback default
    (newest image strictly OLDER than current) and whether any older image exists.
    The push mechanism is version-agnostic (same firmwareupgradedowngrade endpoint
    as Upgrade) — this only frames/selects for rollback."""
    from ..services import upgrade as upg
    fw = ''
    try:
        fw = upg.firmware_version(appliance.build_client(timeout=8))
    except Exception:
        fw = ''
    _persist_firmware(appliance, fw)
    images = upg.compatible_images(appliance)   # all product/model matches, newest-first
    cur = upg._version_key(fw) if fw else None
    relations, default_id, older_exists = {}, None, False
    for img in images:
        if cur is None:
            relations[img.id] = 'unknown'
            continue
        k = upg._version_key(img.version)
        if k < cur:
            relations[img.id] = 'older'
            older_exists = True
            if default_id is None:      # images newest-first → first older = best rollback
                default_id = img.id
        elif k > cur:
            relations[img.id] = 'newer'
        else:
            relations[img.id] = 'same'
    if default_id is None and images:   # nothing older (or fw unknown) → newest
        default_id = images[0].id
    return fw, images, relations, default_id, older_exists


@bp.route('/<int:id>/downgrade')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def downgrade(id):
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        return redirect(url_for('appliances.detail', id=id))
    fw, images, relations, default_id, older_exists = _downgrade_context(appliance)
    return render_template('appliances/downgrade.html', appliance=appliance,
                           firmware=fw, images=images, relations=relations,
                           selected_id=default_id, older_exists=older_exists)


@bp.route('/<int:id>/downgrade', methods=['POST'])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def downgrade_push(id):
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        flash('Not a FortiWeb appliance.', 'danger')
        return redirect(url_for('appliances.detail', id=id))
    from ..services import upgrade as upg

    image = _selected_compatible_image(appliance, request.form.get('image_id'))
    if image is None:
        flash('Select a firmware image from the repository first.', 'danger')
        return redirect(url_for('appliances.downgrade', id=id))
    dry_run = request.form.get('dry_run') == 'on'
    confirm_maturity = request.form.get('confirm_maturity') == 'on'

    if _wants_json():
        return _spawn_flash_job(appliance, image, 'downgrade', dry_run, confirm_maturity)

    # A live push requires typing the exact appliance name (mis-click guard).
    if not dry_run and request.form.get('confirm_name', '').strip() != appliance.name:
        flash('Live downgrade requires typing the exact appliance name to confirm.', 'danger')
        return redirect(url_for('appliances.downgrade', id=id))

    try:
        image_bytes = upg.read_image_bytes(image)
    except Exception as exc:
        flash(f'Firmware file problem: {type(exc).__name__}: {exc}', 'danger')
        return redirect(url_for('appliances.downgrade', id=id))

    fw_part = fw_active = 0
    confirm_dg = False
    if not dry_run:
        try:
            _pt = upg.read_partitions(appliance)
            _alt = _pt.get('alternate') or {}
            fw_part = int(_alt.get('partition') or 0)
            fw_active = int(bool(_alt.get('active')))
            confirm_dg = True
            confirm_maturity = True
        except Exception:
            pass
    try:
        result = upg.push_firmware(
            appliance, image_bytes, image.filename,
            dry_run=dry_run, confirm_maturity=confirm_maturity,
            confirm_downgrade=confirm_dg, part=fw_part, active=fw_active,
        )
    except Exception as exc:
        flash(f'Downgrade failed: {type(exc).__name__}: {exc}', 'danger')
        return redirect(url_for('appliances.downgrade', id=id))

    if not dry_run:
        log_action('appliance.downgrade', target=appliance.name,
                   extra={'image_id': image.id, 'version': image.version,
                          'from': result.get('firmware_before', '')})
    fw, images, relations, default_id, older_exists = _downgrade_context(appliance)
    return render_template('appliances/downgrade.html', appliance=appliance,
                           firmware=result.get('firmware_before', '') or fw,
                           result=result, images=images, relations=relations,
                           selected_id=image.id, older_exists=older_exists)


# ===========================================================================
#  Restore — admin-only config restore from the backup vault or an uploaded
#  .conf. Destructive (the box applies the config + reboots): dry_run default,
#  hostname hard-confirm, automatic pre-restore backup, audit. USER_MANAGE only.
# ===========================================================================
def _restore_context(appliance):
    """Current firmware (best-effort, no failure) + this appliance's vault entries."""
    from ..services import upgrade as upg
    fw = ''
    try:
        fw = upg.firmware_version(appliance.build_client(timeout=8))
    except Exception:
        fw = ''
    backups = (ConfigBackup.query
               .filter_by(appliance_id=appliance.id)
               .order_by(ConfigBackup.created_at.desc()).all())
    return fw, backups


@bp.route('/<int:id>/restore')
@login_required
@require_permission(Permission.USER_MANAGE)
def restore(id):
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        return redirect(url_for('appliances.detail', id=id))
    fw, backups = _restore_context(appliance)
    return render_template('appliances/restore.html', appliance=appliance,
                           firmware=fw, backups=backups)


@bp.route('/<int:id>/restore/upload', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def restore_upload(id):
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        return redirect(url_for('appliances.detail', id=id))
    from ..services import backup as backup_svc
    up = request.files.get('config_file')
    if up is None or not up.filename:
        flash('Choose a .conf configuration file to upload into the vault.', 'warning')
        return redirect(url_for('appliances.restore', id=id))
    data = up.read()
    if not data:
        flash('The uploaded file is empty.', 'warning')
        return redirect(url_for('appliances.restore', id=id))
    try:
        cb = backup_svc.store_bytes(
            appliance_id=appliance.id, appliance_name=appliance.name, data=data,
            filename=up.filename, source='upload',
            created_by=getattr(current_user, 'username', '') or '',
            note=(request.form.get('note') or '').strip() or None)
    except Exception as exc:
        flash(f'Could not store the upload: {type(exc).__name__}: {exc}', 'danger')
        return redirect(url_for('appliances.restore', id=id))
    log_action('appliance.backup_upload', target=appliance.name,
               extra={'filename': cb.filename, 'size': cb.size_bytes, 'encrypted': cb.encrypted})
    flash(f'Stored "{cb.filename}" in the vault ({cb.size_kb()} KB'
          f'{", encrypted" if cb.encrypted else ""}).', 'success')
    return redirect(url_for('appliances.restore', id=id))


@bp.route('/<int:id>/restore/fetch', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def restore_fetch(id):
    """Pull a fresh backup off the device into the vault (best-effort)."""
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        return redirect(url_for('appliances.detail', id=id))
    from ..services import backup as backup_svc
    try:
        client = appliance.build_client(timeout=120)
        cb = backup_svc.fetch_device_backup(
            client, appliance_id=appliance.id, appliance_name=appliance.name,
            created_by=getattr(current_user, 'username', '') or '')
    except Exception as exc:
        flash(f'Could not fetch a backup from {appliance.name}: {type(exc).__name__}: {exc}. '
              f'You can upload a .conf manually instead.', 'warning')
        return redirect(url_for('appliances.restore', id=id))
    log_action('appliance.backup_fetch', target=appliance.name, extra={'filename': cb.filename})
    flash(f'Pulled "{cb.filename}" from {appliance.name} into the vault.', 'success')
    return redirect(url_for('appliances.restore', id=id))


@bp.route('/<int:id>/restore/<int:backup_id>/download')
@login_required
@require_permission(Permission.USER_MANAGE)
def restore_download(id, backup_id):
    cb = ConfigBackup.query.filter_by(id=backup_id, appliance_id=id).first()
    if cb is None or not cb.stored_path or not os.path.exists(cb.stored_path):
        abort(404)
    return send_file(cb.stored_path, as_attachment=True, download_name=cb.filename)


@bp.route('/<int:id>/restore/<int:backup_id>/delete', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def restore_delete(id, backup_id):
    from ..services import backup as backup_svc
    cb = ConfigBackup.query.filter_by(id=backup_id, appliance_id=id).first()
    if cb is None:
        abort(404)
    meta = cb.filename
    backup_svc.delete_vault(cb)
    log_action('appliance.backup_delete', target=str(id), extra={'filename': meta})
    flash(f'Deleted backup "{meta}" from the vault.', 'success')
    return redirect(url_for('appliances.restore', id=id))


@bp.route('/<int:id>/restore/run', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def restore_run(id):
    appliance, _ = _fortiweb_or_404(id)
    if appliance is None:
        return redirect(url_for('appliances.detail', id=id))
    from ..services import backup as backup_svc

    dry_run = request.form.get('dry_run') == 'on'
    password = (request.form.get('password') or '').strip() or None

    # Source: an existing vault entry OR a freshly uploaded .conf.
    backup_id = request.form.get('backup_id')
    up = request.files.get('config_file')
    data, filename = None, 'config.conf'
    if up and up.filename:
        data = up.read()
        filename = os.path.basename(up.filename)
        if data:
            try:  # retain the source in the vault
                backup_svc.store_bytes(
                    appliance_id=appliance.id, appliance_name=appliance.name, data=data,
                    filename=filename, source='upload',
                    created_by=getattr(current_user, 'username', '') or '')
            except Exception:
                pass
    elif backup_id:
        cb = ConfigBackup.query.filter_by(id=int(backup_id), appliance_id=appliance.id).first()
        if cb is None:
            flash('Selected backup not found in the vault.', 'danger')
            return redirect(url_for('appliances.restore', id=id))
        try:
            data = backup_svc.read_vault_bytes(cb)
        except Exception as exc:
            flash(f'Stored backup unreadable: {type(exc).__name__}: {exc}', 'danger')
            return redirect(url_for('appliances.restore', id=id))
        filename = cb.filename
    if not data:
        flash('Choose a stored backup or upload a .conf file to restore.', 'warning')
        return redirect(url_for('appliances.restore', id=id))

    # A live restore requires typing the exact appliance name (mis-click guard).
    if not dry_run and request.form.get('confirm_name', '').strip() != appliance.name:
        flash('Live restore requires typing the exact appliance name to confirm.', 'danger')
        return redirect(url_for('appliances.restore', id=id))

    try:
        client = appliance.build_client(timeout=600)
    except Exception as exc:
        flash(f'Cannot connect to {appliance.name}: {type(exc).__name__}: {exc}', 'danger')
        return redirect(url_for('appliances.restore', id=id))

    # Automatic pre-restore backup — the rollback net (real runs only, best-effort).
    pre_backup = None
    if not dry_run:
        try:
            pre = backup_svc.fetch_device_backup(
                client, appliance_id=appliance.id, appliance_name=appliance.name,
                created_by=getattr(current_user, 'username', '') or '')
            pre_backup = pre.filename
        except Exception as exc:
            pre_backup = f'(skipped: {type(exc).__name__})'

    try:
        result = backup_svc.restore(client, data, filename, password=password, dry_run=dry_run)
    except Exception as exc:
        flash(f'Restore failed: {type(exc).__name__}: {exc}', 'danger')
        return redirect(url_for('appliances.restore', id=id))

    if not dry_run:
        log_action('appliance.restore', target=appliance.name,
                   extra={'filename': filename, 'pre_backup': pre_backup,
                          'ok': result.get('ok')})
    fw, backups = _restore_context(appliance)
    return render_template('appliances/restore.html', appliance=appliance, firmware=fw,
                           backups=backups, result=result, pre_backup=pre_backup)
