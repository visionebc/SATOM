"""Phase 9 — System backup & restore page (admin-only).

Whole-instance backup (Postgres pg_dump + reports/ JSON) → downloadable bundle;
restore with a safety dump first; and a one-click "publish per-device JSON to
git" (the off-box, versioned source-of-truth backup).
"""
from __future__ import annotations

import io

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, send_file, abort, jsonify)
from flask_login import login_required

from ..auth.decorators import require_permission
from ..services import system_backup

bp = Blueprint("system_backup", __name__, url_prefix="/system-backup")


def _peer_host() -> str:
    """First registered HA node that is not this one (ha_nodes.json) — the
    backup server the page compares against."""
    try:
        from ..services import self_update as su
        this = su.this_node_name()
        for n in su.load_nodes():
            host = (n.get("host") or "").strip()
            if n.get("name") != this and host and host != "127.0.0.1":
                return host
    except Exception:
        pass
    return ""


def _sot_devices() -> list[dict]:
    """Per-device source-of-truth coverage: which appliances have a
    ``reports/<slug>/_config.json`` snapshot and how fresh it is. Drives the
    'Backup coverage' matrix so a device missing from git (e.g. FortiADC before
    the harvest was wired) is visible at a glance. Never raises."""
    from datetime import datetime
    from ..models import Appliance
    from ..services import device_sync as ds
    rows: list[dict] = []
    try:
        for a in Appliance.query.order_by(Appliance.kind, Appliance.name).all():
            p = ds.device_json_path(a)
            has = p.exists()
            mtime = ""
            if has:
                try:
                    mtime = datetime.utcfromtimestamp(
                        p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                except OSError:
                    mtime = ""
            rows.append({"name": a.name, "kind": a.kind,
                         "has_json": has, "mtime": mtime})
    except Exception:  # noqa: BLE001 — coverage view must never sink the page
        return rows
    return rows


def _page_context(**extra) -> dict:
    from ..services import git_service, settings_store
    from ..services import backup_server as bksrv
    from ..services import git_backup
    from ..models_firmware import FirmwareImage
    local = system_backup.local_inventory()
    peer_host = _peer_host()
    peer = system_backup.peer_inventory(peer_host) if peer_host else {
        "reachable": False, "host": "", "bundles": [], "vault": None}
    local_fw = {f.filename: f for f in FirmwareImage.query.all()}
    ctx = dict(
        backups=local["bundles"],
        vault=local["vault"],
        peer=peer,
        inv_rows=system_backup.compare_inventories(local, peer),
        git=git_service.git_info(),
        git_history=git_service.reports_history(),
        git_dirty=git_service.reports_dirty(),
        code_history=git_service.code_history(),
        bk=bksrv.inventory(),
        bk_system=bksrv.system_inventory(),
        gitb=git_backup.list_bundles(),
        gitb_state=git_backup.unpushed_state(),
        gitb_refs=git_backup.safety_refs(),
        gitb_cfg={"keep": git_backup.keep_count(),
                  "push_server": git_backup.push_enabled(),
                  "remote_dir": git_backup.remote_dir()},
        sot=_sot_devices(),
        local_fw=local_fw,
        fw_repo=settings_store.firmware_repo(),
        diff=None,
    )
    ctx.update(extra)
    return ctx


@bp.route("/")
@login_required
@require_permission("user_manage")
def index():
    return render_template("system_backup/index.html", **_page_context())


@bp.route("/compare")
@login_required
@require_permission("user_manage")
def compare():
    """Compare two git versions of the reports/ source of truth (rollback /
    version inspection)."""
    from ..services import git_service
    ref_a = (request.args.get("ref_a") or "").strip()
    ref_b = (request.args.get("ref_b") or "").strip() or "HEAD"
    device = (request.args.get("device") or "").strip()
    diff = git_service.reports_diff(ref_a, ref_b, device) if ref_a else \
        {"ok": False, "error": "pick the base version (ref A)"}
    return render_template("system_backup/index.html",
                           **_page_context(diff=diff))


@bp.route("/create", methods=["POST"])
@login_required
@require_permission("user_manage")
def create():
    include_reports = request.form.get("include_reports") == "on"
    publish_git = request.form.get("publish_git") == "on"
    res = system_backup.create_backup(include_reports=include_reports,
                                      publish_git=publish_git, label="manual")
    if res["ok"]:
        flash(f"Backup created: {res['name']} ({res['size']//1024} KB) — {res['detail']}",
              "success")
    else:
        flash(f"Backup failed: {res['detail']}", "danger")
    return redirect(url_for("system_backup.index"))


@bp.route("/download/<name>")
@login_required
@require_permission("user_manage")
def download(name):
    if not name.startswith("fmw-backup-") or "/" in name or ".." in name:
        abort(404)
    path = system_backup.backups_dir() / name
    if not path.exists():
        abort(404)
    return send_file(str(path), as_attachment=True, download_name=name)


@bp.route("/delete", methods=["POST"])
@login_required
@require_permission("user_manage")
def delete():
    """Delete an old bundle. Primary-only: the standby mirrors data/ FROM the
    primary (rsync --delete), so deletions here replicate within 5 min while
    a standby-side delete would be resurrected by the next sync."""
    from ..services import self_update as su
    if su.node_role() == "standby":
        flash("This node is the standby — delete bundles on the primary; "
              "the datasync mirrors the deletion here within 5 minutes.", "warning")
        return redirect(url_for("system_backup.index"))
    res = system_backup.delete_backup(request.form.get("name", ""))
    flash(res["detail"], "success" if res["ok"] else "danger")
    return redirect(url_for("system_backup.index"))


@bp.route("/restore", methods=["POST"])
@login_required
@require_permission("user_manage")
def restore():
    name = request.form.get("name", "")
    if request.form.get("confirm") != "RESTORE":
        flash("Restore not confirmed — type RESTORE to proceed.", "warning")
        return redirect(url_for("system_backup.index"))
    res = system_backup.restore_backup(name, restore_reports=True)
    if res["ok"]:
        flash(f"Restored {name}. Safety dump: {res.get('safety')}. {res['detail']}",
              "success")
    else:
        flash(f"Restore failed: {res['detail']}", "danger")
    return redirect(url_for("system_backup.index"))


@bp.route("/code-rollback", methods=["POST"])
@login_required
@require_permission("user_manage")
def code_rollback():
    """Roll the application CODE back (or forward) to a chosen commit — a
    thin wrapper over the self-update queue: the privileged runner
    (satom-updater) does checkout + pip + migrate + restart, with
    all the usual step logging on the Software Update page."""
    from flask_login import current_user
    from ..services import self_update as su
    target = (request.form.get("target") or "").strip()
    if not target or len(target) > 64 or any(ch in target for ch in " ;|&"):
        flash("Pick a commit to roll back to.", "warning")
        return redirect(url_for("system_backup.index"))
    if request.form.get("confirm") != "ROLLBACK":
        flash("Rollback not confirmed — type ROLLBACK to proceed.", "warning")
        return redirect(url_for("system_backup.index"))
    info = su.current_revision()
    if target == info.get("sha", "")[:len(target)]:
        flash("Already running that revision.", "info")
        return redirect(url_for("system_backup.index"))
    uid = su.request_update(target, current_user.username, origin="code-rollback")
    flash(f"Code rollback to {target} queued ({uid}) — follow it on the "
          "Software Update page. The service restarts when it applies.", "success")
    return redirect(url_for("system_backup.index"))


@bp.route("/firmware-pull", methods=["POST"])
@login_required
@require_permission("user_manage")
def firmware_pull():
    """Pull one firmware image from the external backup server into the local
    firmware store, ready for the console-driven Upgrade/Downgrade actions."""
    from flask_login import current_user
    from ..services import backup_server as bksrv
    name = request.form.get("name", "")
    res = bksrv.pull_firmware(name, by=current_user.username)
    flash(("Firmware: " + res["detail"]) if res["ok"] else
          ("Firmware pull failed: " + res["detail"]),
          "success" if res["ok"] else "danger")
    return redirect(url_for("system_backup.index"))


# ── external backup server browser (modal, JSON endpoints) ──────────────────

@bp.route("/external/files")
@login_required
@require_permission("user_manage")
def external_files():
    """All pushed backups for one device on the external backup server."""
    from ..services import backup_server as bksrv
    return jsonify(bksrv.device_files(request.args.get("device", "")))


@bp.route("/external/outline")
@login_required
@require_permission("user_manage")
def external_outline():
    """Sections inside one pushed backup (text vs skipped/encrypted)."""
    from ..services import backup_server as bksrv
    return jsonify(bksrv.backup_outline(request.args.get("device", ""),
                                        request.args.get("name", "")))


@bp.route("/external/diff")
@login_required
@require_permission("user_manage")
def external_diff():
    """Config diff between two pushed backups of the same device."""
    from ..services import backup_server as bksrv
    return jsonify(bksrv.diff_device_backups(request.args.get("device", ""),
                                             request.args.get("a", ""),
                                             request.args.get("b", "")))


@bp.route("/external/search")
@login_required
@require_permission("user_manage")
def external_search():
    """Search inside one pushed backup's plain-text config sections."""
    from ..services import backup_server as bksrv
    return jsonify(bksrv.search_device_backup(request.args.get("device", ""),
                                              request.args.get("name", ""),
                                              request.args.get("q", "")))


@bp.route("/external/content")
@login_required
@require_permission("user_manage")
def external_content():
    """Full plain-text config of one pushed backup (view live)."""
    from ..services import backup_server as bksrv
    return jsonify(bksrv.backup_content(request.args.get("device", ""),
                                        request.args.get("name", ""),
                                        request.args.get("section", "")))


@bp.route("/external/download")
@login_required
@require_permission("user_manage")
def external_download():
    """Grab one pushed backup file (raw, as the appliance pushed it)."""
    from ..services import backup_server as bksrv
    device = request.args.get("device", "")
    name = request.args.get("name", "")
    try:
        data = bksrv.download_backup_stream(device, name)
    except Exception:  # noqa: BLE001 — bad name / unreachable → 404
        abort(404)
    import posixpath
    return send_file(io.BytesIO(data), as_attachment=True,
                     download_name=posixpath.basename(name))


# ── git repository backup (bundles) ─────────────────────────────────────────
#
# Gitea is a distribution point, not custody: while it is unreachable the local
# commits (reports/ source of truth) exist on this node only. A `git bundle` is
# the whole repo — every ref, full history — in one verifiable, clonable file,
# kept here, mirrored to the standby via data/ rsync, pushed to backup-server, and
# downloadable from this page.

@bp.route("/git-bundle/create", methods=["POST"])
@login_required
@require_permission("user_manage")
def git_bundle_create():
    from flask_login import current_user
    from ..services import git_backup
    push = request.form.get("push_server") == "on"
    res = git_backup.create_bundle(label="manual", push_server=push,
                                   by=current_user.username)
    flash(("Git bundle: " + res["detail"]) if res["ok"] else
          ("Git bundle failed: " + res["detail"]),
          "success" if res["ok"] else "danger")
    return redirect(url_for("system_backup.index"))


@bp.route("/git-bundle/config", methods=["POST"])
@login_required
@require_permission("user_manage")
def git_bundle_config():
    from ..services import git_backup
    cfg = git_backup.save_config(request.form)
    flash(f"Git bundle settings saved (keep {cfg['keep']}, "
          f"push to backup server {'on' if cfg['push_server'] else 'off'}).",
          "success")
    return redirect(url_for("system_backup.index"))


@bp.route("/git-bundle/download/<name>")
@login_required
@require_permission("user_manage")
def git_bundle_download(name):
    from ..services import git_backup
    path = git_backup.bundle_path(name)
    if not path:
        abort(404)
    return send_file(str(path), as_attachment=True, download_name=name)


@bp.route("/git-bundle/delete", methods=["POST"])
@login_required
@require_permission("user_manage")
def git_bundle_delete():
    """Primary-only, same reason as the DB bundles: the standby mirrors data/
    FROM the primary with rsync --delete, so a standby-side delete is undone by
    the next sync."""
    from ..services import git_backup
    from ..services import self_update as su
    if su.node_role() == "standby":
        flash("This node is the standby — delete bundles on the primary; "
              "the datasync mirrors the deletion here within 5 minutes.", "warning")
        return redirect(url_for("system_backup.index"))
    res = git_backup.delete_bundle(request.form.get("name", ""))
    flash(res["detail"], "success" if res["ok"] else "danger")
    return redirect(url_for("system_backup.index"))


@bp.route("/git-bundle/external/list")
@login_required
@require_permission("user_manage")
def git_bundle_external_list():
    """On demand, not in the page context: this opens an SFTP session, and the
    page already opens two — an unreachable backup server must not be able to
    slow the whole page down."""
    from ..services import git_backup
    return jsonify(git_backup.external_inventory())


@bp.route("/git-bundle/external/download")
@login_required
@require_permission("user_manage")
def git_bundle_external_download():
    """Pull a bundle back DOWN from backup-server — the recovery direction, for
    when this node is the one that was lost."""
    from ..services import git_backup
    name = request.args.get("name", "")
    try:
        data = git_backup.external_download(name)
    except Exception:  # noqa: BLE001 — bad name / unreachable → 404
        abort(404)
    return send_file(io.BytesIO(data), as_attachment=True, download_name=name)


@bp.route("/publish-json", methods=["POST"])
@login_required
@require_permission("user_manage")
def publish_json():
    """Commit the per-device JSON tree (reports/) to git — the off-box
    versioned source-of-truth backup (also runs hourly via
    satom-git-publish.timer; this button is the on-demand path)."""
    try:
        from ..services import git_service
        git_service.git_publish("source-of-truth: publish device JSON", ["reports"])
        flash("Per-device JSON published to git.", "success")
    except Exception as exc:  # noqa: BLE001
        flash(f"Git publish failed: {exc}", "danger")
    return redirect(url_for("system_backup.index"))
