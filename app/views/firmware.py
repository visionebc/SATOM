"""Firmware repository (Infrastructure -> Firmware).

Admin-only store of FortiWeb/FortiADC ``.out`` firmware images. The binary lives
on disk under ``<data>/firmware/<id>/<filename>`` (never in SQLite); the DB row
keeps metadata plus a sha256 for integrity. A stored image can later feed the
appliance Upgrade action (deferred wiring) instead of re-uploading every time.

Mirrors the upload pattern in ``app/views/import_backup.py`` (ext allowlist,
flash + redirect, ``log_action`` audit) and gates every route on
``Permission.USER_MANAGE`` (admin) — both legacy roles and the new profiles
resolve that coarse key, so it is stable across the in-flight RBAC refactor.
"""
from __future__ import annotations

import hashlib
import os
import shutil

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..extensions import db
from ..models import Permission
from ..models_firmware import FirmwareImage
from ..services.audit import log_action

bp = Blueprint("firmware", __name__, url_prefix="/firmware")

_ALLOWED_EXT = {".out"}
_PRODUCTS = {"fortiweb", "fortiadc"}


def _firmware_root() -> str:
    """Directory holding firmware folders.

    Derived from the SQLite DB location so it sits next to ``fortinet.db`` in
    ``data/`` in production AND is automatically isolated per test (the test DB
    lives in a tmp dir), so the suite never writes into the live data dir.
    """
    uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "") or ""
    if uri.startswith("sqlite:///"):
        base = os.path.dirname(uri[len("sqlite:///"):])
    else:
        base = os.path.join(os.path.dirname(current_app.root_path), "data")
    d = os.path.join(base, "firmware")
    os.makedirs(d, exist_ok=True)
    return d


def _sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@bp.route("/", methods=["GET"])
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    images = FirmwareImage.query.order_by(FirmwareImage.created_at.desc()).all()
    return render_template("firmware/index.html", images=images)


@bp.route("/upload", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def upload():
    file = request.files.get("image")
    version = (request.form.get("version") or "").strip()
    product = (request.form.get("product") or "fortiweb").strip().lower()
    model = (request.form.get("model") or "").strip()
    build = (request.form.get("build") or "").strip()
    notes = (request.form.get("notes") or "").strip()

    if file is None or not file.filename:
        flash("Please choose a firmware .out file to upload.", "warning")
        return redirect(url_for("firmware.index"))
    if product not in _PRODUCTS:
        product = "fortiweb"
    if not version:
        flash("A firmware version is required (e.g. 7.6.4).", "warning")
        return redirect(url_for("firmware.index"))
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in _ALLOWED_EXT:
        flash(f'Unsupported file type "{ext}". Firmware images must be .out files.',
              "warning")
        return redirect(url_for("firmware.index"))

    # Insert the row first to mint an id, then stream the upload into its folder.
    safe_name = os.path.basename(file.filename)
    fw = FirmwareImage(
        product=product, model=model or None, version=version,
        build=build or None, filename=safe_name, stored_path="",
        notes=notes or None,
        uploaded_by=getattr(current_user, "username", "") or "",
    )
    db.session.add(fw)
    db.session.flush()  # assigns fw.id without committing

    dest_dir = os.path.join(_firmware_root(), str(fw.id))
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, safe_name)
    try:
        file.save(dest_path)  # Werkzeug streams to disk — no full read into RAM
        fw.stored_path = dest_path
        fw.size_bytes = os.path.getsize(dest_path)
        fw.sha256 = _sha256_of(dest_path)
        db.session.commit()
    except Exception as exc:  # noqa: BLE001 — never 500 on a bad upload
        db.session.rollback()
        shutil.rmtree(dest_dir, ignore_errors=True)
        flash(f"Upload failed: {exc}", "danger")
        return redirect(url_for("firmware.index"))

    log_action(
        "firmware.upload",
        target=f"{product} {version} ({safe_name})",
        extra={"id": fw.id, "size_bytes": fw.size_bytes, "sha256": fw.sha256,
               "model": model, "build": build},
    )
    flash(f'Firmware "{safe_name}" ({product} {version}) uploaded — '
          f"{fw.size_mb()} MB.", "success")
    return redirect(url_for("firmware.index"))


@bp.route("/<int:image_id>/download", methods=["GET"])
@login_required
@require_permission(Permission.USER_MANAGE)
def download(image_id):
    fw = FirmwareImage.query.get(image_id)
    if fw is None or not fw.stored_path or not os.path.exists(fw.stored_path):
        abort(404)
    return send_file(fw.stored_path, as_attachment=True, download_name=fw.filename)


@bp.route("/<int:image_id>/delete", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete(image_id):
    fw = FirmwareImage.query.get(image_id)
    if fw is None:
        abort(404)
    folder = os.path.dirname(fw.stored_path) if fw.stored_path else None
    meta = f"{fw.product} {fw.version} ({fw.filename})"
    fw_id = fw.id
    db.session.delete(fw)
    db.session.commit()
    if folder and os.path.isdir(folder):
        shutil.rmtree(folder, ignore_errors=True)
    log_action("firmware.delete", target=meta, extra={"id": fw_id})
    flash(f"Deleted firmware {meta}.", "success")
    return redirect(url_for("firmware.index"))
