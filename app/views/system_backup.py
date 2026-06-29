"""Phase 9 — System backup & restore page (admin-only).

Whole-instance backup (Postgres pg_dump + reports/ JSON) → downloadable bundle;
restore with a safety dump first; and a one-click "publish per-device JSON to
git" (the off-box, versioned source-of-truth backup).
"""
from __future__ import annotations

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, send_file, abort)
from flask_login import login_required

from ..auth.decorators import require_permission
from ..services import system_backup

bp = Blueprint("system_backup", __name__, url_prefix="/system-backup")


@bp.route("/")
@login_required
@require_permission("user_manage")
def index():
    return render_template("system_backup/index.html",
                           backups=system_backup.list_backups())


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


@bp.route("/publish-json", methods=["POST"])
@login_required
@require_permission("user_manage")
def publish_json():
    """Commit the per-device JSON tree (reports/) to git — the opt-in off-box
    source-of-truth backup."""
    try:
        from ..services import git_service
        git_service.git_publish("source-of-truth: publish device JSON", ["reports"])
        flash("Per-device JSON published to git.", "success")
    except Exception as exc:  # noqa: BLE001
        flash(f"Git publish failed: {exc}", "danger")
    return redirect(url_for("system_backup.index"))
