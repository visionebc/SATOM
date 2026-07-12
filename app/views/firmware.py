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
import json as _json
import os

from werkzeug.utils import secure_filename
import shutil
import uuid

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from flask_wtf.csrf import validate_csrf

from ..auth.decorators import require_permission
from ..extensions import csrf, db
from ..models import Permission
from ..models_firmware import FirmwareImage
from ..services import jobs as jobsvc
from ..services.audit import log_action

bp = Blueprint("firmware", __name__, url_prefix="/firmware")

_ALLOWED_EXT = {".out"}
# Products that manage firmware images. Derived LIVE from the ADOM registry
# (``cap_firmware``); ``product not in _PRODUCTS`` works on the live sequence.
from ..branding import live_products as _live_products  # noqa: E402

_PRODUCTS = _live_products("firmware")


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


def _wants_json() -> bool:
    """The AJAX (jobs framework) path — the browser's XHR sets this header; a
    plain form POST (JS disabled) falls through to the synchronous path."""
    return (request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or (request.form.get("ajax") or "") in ("1", "true"))


def _finalize_upload(app, job_id: str, image_id: int, dest_path: str,
                     user_id: int = 0, link: str | None = None):
    """Background worker: sha256 the just-uploaded image (reporting progress so
    the toast has a real bar) and stamp the row. Runs in a daemon thread with a
    fresh app context — NO request/current_user here, so the audit row is written
    in the request, not here. Raises a bell notification for the uploading user
    on success/failure (``link`` is resolved in the request and passed in, since
    ``url_for`` can't build a URL from this thread)."""
    from ..services import notifications as notify
    with app.app_context():
        try:
            fw = FirmwareImage.query.get(image_id)
            if fw is None:
                raise ValueError(f"firmware row {image_id} not found")
            total = os.path.getsize(dest_path)
            h = hashlib.sha256()
            read = 0
            with open(dest_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
                    h.update(chunk)
                    read += len(chunk)
                    if total:
                        jobsvc.set_progress(job_id, int(read * 100 / total),
                                            "Verifying integrity…")
            fw.sha256 = h.hexdigest()
            fw.size_bytes = total
            db.session.commit()
            filename, size_mb = fw.filename, fw.size_mb()
        except Exception as exc:  # noqa: BLE001 — notify, then let run_async mark error
            if user_id:
                notify.push(user_id, "Firmware upload failed",
                            kind=notify.Notification.KIND_ERROR,
                            body=str(exc)[:400], link=link)
            raise
        jobsvc.finish_success(
            job_id, message=f"{filename} ready — {size_mb} MB",
            result={"image_id": image_id, "filename": filename,
                    "size_mb": size_mb, "reload": True})
        if user_id:
            notify.push(user_id, f"Firmware image ready: {filename}",
                        kind=notify.Notification.KIND_SUCCESS,
                        body=f"SHA-256 verified — {size_mb} MB. Ready for upgrades.",
                        link=link)
    return None


@bp.route("/", methods=["GET"])
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    images = FirmwareImage.query.order_by(FirmwareImage.created_at.desc()).all()
    # Product dropdown is driven LIVE from the ADOM registry (cap_firmware) so a
    # new firmware-capable product (e.g. FortiAnalyzer) shows up without edits.
    from ..branding import products_with, get_product
    fw_products = [{"key": k, "name": get_product(k).get("name", k.title())}
                   for k in products_with("firmware")]
    # Per-box downgrade deep-links moved to Appliances > (device) >
    # Appliance Actions > Downgrade; this page keeps the rollback guidance.
    return render_template("firmware/index.html", images=images,
                           fw_products=fw_products)


@bp.route("/upload", methods=["POST"])
@csrf.exempt
@login_required
@require_permission(Permission.USER_MANAGE)
def upload():
    # Exempt from the AUTOMATIC CSRF check — which, with WTF_CSRF_SSL_STRICT,
    # also validates the Referer — because a Background Fetch upload is issued by
    # the browser/Service Worker and may not carry a Referer. We STILL require a
    # valid CSRF token, validated manually from the header (AJAX / Background
    # Fetch) or the hidden field (classic form), so the endpoint is no less safe.
    _tok = (request.headers.get("X-CSRFToken")
            or request.headers.get("X-CSRF-Token")
            or request.form.get("csrf_token"))
    # Honour WTF_CSRF_ENABLED=False (tests) exactly like CSRFProtect does —
    # a manual validate_csrf() call ignores that flag on its own.
    if current_app.config.get("WTF_CSRF_ENABLED", True):
        try:
            validate_csrf(_tok)
        except Exception:
            if _wants_json():
                return jsonify({"error": "Invalid or missing CSRF token — "
                                         "reload the page and try again."}), 400
            flash("Your session expired — please reload and try again.", "warning")
            return redirect(url_for("firmware.index"))

    file = request.files.get("image")
    version = (request.form.get("version") or "").strip()
    product = (request.form.get("product") or "fortiweb").strip().lower()
    platform = (request.form.get("platform") or "").strip().lower()
    if platform not in ("hw", "vm"):
        platform = ""          # anything else = universal / any
    build = (request.form.get("build") or "").strip()
    notes = (request.form.get("notes") or "").strip()

    if product not in _PRODUCTS:
        product = "fortiweb"
    ext = os.path.splitext(file.filename)[1].lower() if file and file.filename else ""

    # Validate — return JSON to the AJAX path, flash+redirect to the classic one.
    err = None
    if file is None or not file.filename:
        err = "Please choose a firmware .out file to upload."
    elif not version:
        err = "A firmware version is required (e.g. 7.6.4)."
    elif ext not in _ALLOWED_EXT:
        err = f'Unsupported file type "{ext}". Firmware images must be .out files.'
    if err:
        if _wants_json():
            return jsonify({"error": err}), 400
        flash(err, "warning")
        return redirect(url_for("firmware.index"))

    # Insert the row first to mint an id, then stream the upload into its folder.
    safe_name = secure_filename(file.filename) or "firmware.out"
    fw = FirmwareImage(
        product=product, platform=platform, version=version,
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
    except Exception as exc:  # noqa: BLE001 — never 500 on a bad upload
        db.session.rollback()
        shutil.rmtree(dest_dir, ignore_errors=True)
        if _wants_json():
            return jsonify({"error": f"Upload failed: {exc}"}), 500
        flash(f"Upload failed: {exc}", "danger")
        return redirect(url_for("firmware.index"))

    if _wants_json():
        # Transfer is done (the browser already showed its upload bar); defer the
        # expensive sha256 to a background job and return immediately so the
        # bottom-right toast can track "Verifying…" without holding the request.
        fw.sha256 = ""
        db.session.commit()
        log_action(
            "firmware.upload",
            target=f"{product} {version} ({safe_name})",
            extra={"id": fw.id, "size_bytes": fw.size_bytes, "sha256": "pending",
                   "platform": platform, "build": build},
        )
        image_id = fw.id
        uid = getattr(current_user, "id", 0) or 0
        link = url_for("firmware.index")
        job = jobsvc.create_job(
            "firmware_finalize", f"Verifying {safe_name}", cancelable=False,
            by=getattr(current_user, "username", "") or "",
            meta={"image_id": image_id, "filename": safe_name},
        )
        jobsvc.run_async(
            current_app._get_current_object(), job["id"],
            lambda app, jid: _finalize_upload(app, jid, image_id, dest_path,
                                              uid, link),
        )
        return jsonify({"job_id": job["id"], "image_id": image_id,
                        "filename": safe_name}), 202

    # ── Classic synchronous path (JS disabled): unchanged behaviour ──
    try:
        fw.sha256 = _sha256_of(dest_path)
        db.session.commit()
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        shutil.rmtree(dest_dir, ignore_errors=True)
        flash(f"Upload failed: {exc}", "danger")
        return redirect(url_for("firmware.index"))

    log_action(
        "firmware.upload",
        target=f"{product} {version} ({safe_name})",
        extra={"id": fw.id, "size_bytes": fw.size_bytes, "sha256": fw.sha256,
               "platform": platform, "build": build},
    )
    flash(f'Firmware "{safe_name}" ({product} {version}) uploaded — '
          f"{fw.size_mb()} MB.", "success")
    return redirect(url_for("firmware.index"))


# ─────────────────────────────────────────────────────────────────────────────
# Resumable chunked upload  (survives full-page navigation)
#
# The classic ``/upload`` above streams the whole file in ONE request, which the
# browser aborts the instant you navigate away (the page owns the request). No
# worker / Service-Worker trick reliably keeps a single multi-minute request
# alive across a full-page load — proven from the access log (the SharedWorker
# reported ``active=0`` on every navigation and no POST ever completed).
#
# So the resilient path slices the file into small chunks. The client stages the
# file in the browser's private storage (OPFS) and PUMPS chunks; the server
# appends each to a ``.part`` file. The whole state is the byte offset — read
# straight off the ``.part`` file on disk — so it is self-healing: a resume after
# navigation just continues from ``os.path.getsize(part)``. On ``/finish`` the
# assembled file becomes a real FirmwareImage and hands off to the SAME sha256
# finalize job as the classic path. Each chunk is a short request, so navigation
# only ever interrupts (at most) the current chunk, which the next page re-sends.
#
# The helpers are request-free so they are headless-testable (the app's
# headless-core rule) — begin/append/status/assemble are verified end-to-end,
# including a simulated resume, without a browser or an auth session.
# ─────────────────────────────────────────────────────────────────────────────

_MAX_CHUNK = 32 * 1024 * 1024  # accept up to 32 MB per chunk (client sends 8 MB)


def _uploads_root() -> str:
    d = os.path.join(_firmware_root(), "_uploads")
    os.makedirs(d, exist_ok=True)
    return d


def _upload_dir(upload_id: str) -> str:
    """Resolve + sanitise the per-upload staging dir. Hex tokens only — never let
    a client-supplied id escape the uploads root (path traversal)."""
    uid = "".join(c for c in (upload_id or "") if c in "0123456789abcdef")
    if not uid or len(uid) < 8:
        return ""
    return os.path.join(_uploads_root(), uid)


def _part_path(d: str) -> str:
    return os.path.join(d, "data.part")


def _meta_file(d: str) -> str:
    return os.path.join(d, "meta.json")


def _current_offset(d: str) -> int:
    p = _part_path(d)
    return os.path.getsize(p) if os.path.exists(p) else 0


def begin_upload(meta: dict) -> dict:
    """Create a staging dir + empty ``.part`` and return its id + offset 0."""
    uid = uuid.uuid4().hex
    d = os.path.join(_uploads_root(), uid)
    os.makedirs(d, exist_ok=True)
    with open(_meta_file(d), "w", encoding="utf-8") as fh:
        _json.dump(meta, fh)
    open(_part_path(d), "ab").close()
    return {"upload_id": uid, "offset": 0}


def append_chunk(upload_id: str, offset: int, data: bytes) -> dict:
    """Append ``data`` at ``offset``. If ``offset`` != the current on-disk size
    (a resync after navigation, or a duplicate re-send), write NOTHING and return
    the real offset so the client re-aligns — idempotent + safe."""
    d = _upload_dir(upload_id)
    if not d or not os.path.isdir(d):
        return {"unknown": True, "offset": 0}
    cur = _current_offset(d)
    if offset != cur:
        return {"offset": cur, "resync": True}
    if data:
        with open(_part_path(d), "ab") as fh:
            fh.write(data)
    return {"offset": _current_offset(d)}


def upload_status(upload_id: str) -> dict:
    d = _upload_dir(upload_id)
    if not d or not os.path.isdir(d):
        return {"unknown": True, "offset": 0, "size": 0, "done": False}
    meta = {}
    try:
        with open(_meta_file(d), encoding="utf-8") as fh:
            meta = _json.load(fh)
    except Exception:  # noqa: BLE001
        pass
    size = int(meta.get("size") or 0)
    off = _current_offset(d)
    return {"offset": off, "size": size,
            "done": bool(size and off >= size),
            "filename": meta.get("filename")}


def assemble_upload(upload_id: str, username: str = "") -> dict:
    """Turn a completed ``.part`` into a real FirmwareImage row + on-disk file.
    Request-free (``username`` passed in) so it is headless-testable. Returns
    ``{image_id, dest_path, filename, meta}``; raises on an incomplete upload."""
    d = _upload_dir(upload_id)
    if not d or not os.path.isdir(d):
        raise ValueError("unknown or expired upload")
    with open(_meta_file(d), encoding="utf-8") as fh:
        meta = _json.load(fh)
    part = _part_path(d)
    size = os.path.getsize(part) if os.path.exists(part) else 0
    declared = int(meta.get("size") or 0)
    if declared and size != declared:
        raise ValueError(f"incomplete upload: {size}/{declared} bytes on disk")
    safe_name = secure_filename(meta.get("filename") or "") or "firmware.out"
    fw = FirmwareImage(
        product=(meta.get("product") or "fortiweb"),
        platform=(meta.get("platform") or ""),
        version=(meta.get("version") or ""),
        build=(meta.get("build") or None),
        filename=safe_name, stored_path="",
        notes=(meta.get("notes") or None),
        uploaded_by=username or (meta.get("by") or ""),
    )
    db.session.add(fw)
    db.session.flush()  # assign fw.id without committing
    dest_dir = os.path.join(_firmware_root(), str(fw.id))
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, safe_name)
    shutil.move(part, dest_path)
    fw.sha256 = ""
    fw.stored_path = dest_path
    fw.size_bytes = os.path.getsize(dest_path)
    db.session.commit()
    image_id = fw.id
    shutil.rmtree(d, ignore_errors=True)   # drop the staging dir
    return {"image_id": image_id, "dest_path": dest_path,
            "filename": safe_name, "meta": meta}


def _csrf_guard():
    """Manual CSRF (token from header or form) — same rationale as ``upload()``.
    Returns an error (json, status) tuple on failure, else None."""
    tok = (request.headers.get("X-CSRFToken")
           or request.headers.get("X-CSRF-Token")
           or request.form.get("csrf_token"))
    if not current_app.config.get("WTF_CSRF_ENABLED", True):
        return None
    try:
        validate_csrf(tok)
        return None
    except Exception:
        return jsonify({"error": "Invalid or missing CSRF token — reload the "
                                 "page and try again."}), 400


@bp.route("/upload/begin", methods=["POST"])
@csrf.exempt
@login_required
@require_permission(Permission.USER_MANAGE)
def upload_begin():
    bad = _csrf_guard()
    if bad:
        return bad
    data = request.get_json(silent=True) or request.form
    filename = secure_filename((data.get("filename") or "").strip())
    version = (data.get("version") or "").strip()
    product = (data.get("product") or "fortiweb").strip().lower()
    platform = (data.get("platform") or "").strip().lower()
    if platform not in ("hw", "vm"):
        platform = ""
    build = (data.get("build") or "").strip()
    notes = (data.get("notes") or "").strip()
    try:
        size = int(data.get("size") or 0)
    except (TypeError, ValueError):
        size = 0
    if product not in _PRODUCTS:
        product = "fortiweb"
    ext = os.path.splitext(filename)[1].lower() if filename else ""

    err = None
    if not filename:
        err = "Please choose a firmware .out file to upload."
    elif not version:
        err = "A firmware version is required (e.g. 7.6.4)."
    elif ext not in _ALLOWED_EXT:
        err = f'Unsupported file type "{ext}". Firmware images must be .out files.'
    elif size <= 0:
        err = "Could not read the file size."
    elif size > current_app.config.get("MAX_CONTENT_LENGTH", 600 * 1024 * 1024):
        mb = current_app.config.get("MAX_CONTENT_LENGTH", 0) // (1024 * 1024)
        err = f"File exceeds the maximum allowed size ({mb} MB)."
    if err:
        return jsonify({"error": err}), 400

    res = begin_upload({
        "filename": filename, "version": version, "product": product,
        "platform": platform, "build": build, "notes": notes, "size": size,
        "by": getattr(current_user, "username", "") or "",
    })
    return jsonify(res), 200


@bp.route("/upload/chunk", methods=["POST"])
@csrf.exempt
@login_required
@require_permission(Permission.USER_MANAGE)
def upload_chunk():
    bad = _csrf_guard()
    if bad:
        return bad
    upload_id = request.args.get("upload_id") or ""
    try:
        offset = int(request.args.get("offset") or 0)
    except (TypeError, ValueError):
        offset = 0
    data = request.get_data(cache=False, as_text=False) or b""
    if len(data) > _MAX_CHUNK:
        return jsonify({"error": "chunk too large"}), 413
    res = append_chunk(upload_id, offset, data)
    if res.get("unknown"):
        return jsonify(res), 404
    return jsonify(res), 200


@bp.route("/upload/status", methods=["GET"])
@login_required
@require_permission(Permission.USER_MANAGE)
def upload_status_route():
    return jsonify(upload_status(request.args.get("upload_id") or "")), 200


@bp.route("/upload/finish", methods=["POST"])
@csrf.exempt
@login_required
@require_permission(Permission.USER_MANAGE)
def upload_finish():
    bad = _csrf_guard()
    if bad:
        return bad
    upload_id = (request.args.get("upload_id")
                 or (request.get_json(silent=True) or {}).get("upload_id") or "")
    try:
        info = assemble_upload(upload_id,
                               getattr(current_user, "username", "") or "")
    except Exception as exc:  # noqa: BLE001 — never 500 on a bad finalize
        return jsonify({"error": f"Finalize failed: {exc}"}), 400

    image_id = info["image_id"]
    dest_path = info["dest_path"]
    safe_name = info["filename"]
    meta = info["meta"]
    log_action(
        "firmware.upload",
        target=f"{meta.get('product')} {meta.get('version')} ({safe_name})",
        extra={"id": image_id, "size_bytes": os.path.getsize(dest_path),
               "sha256": "pending", "platform": meta.get("platform"),
               "build": meta.get("build"), "resumable": True},
    )
    uid = getattr(current_user, "id", 0) or 0
    link = url_for("firmware.index")
    job = jobsvc.create_job(
        "firmware_finalize", f"Verifying {safe_name}", cancelable=False,
        by=getattr(current_user, "username", "") or "",
        meta={"image_id": image_id, "filename": safe_name},
    )
    jobsvc.run_async(
        current_app._get_current_object(), job["id"],
        lambda app, jid: _finalize_upload(app, jid, image_id, dest_path, uid, link),
    )
    return jsonify({"job_id": job["id"], "image_id": image_id,
                    "filename": safe_name}), 202


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
