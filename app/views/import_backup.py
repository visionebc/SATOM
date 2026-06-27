"""Import Backup -- offline FortiWeb config-file parser (web port).

Upload a FortiWeb configuration backup (``.conf`` / ``.txt`` / ``.cfg`` /
``.zip`` / ``.gz``), parse it OFFLINE with :mod:`app.services.config_import`
(no appliance is contacted), and store a structured per-device snapshot under
``data/imports/<device>/``. Mirrors the desktop ImportPage.
"""
from __future__ import annotations

import os

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import config_import
from ..services.audit import log_action

bp = Blueprint("import_backup", __name__, url_prefix="/import-backup")

# Extensions the offline parser knows how to read.
_ALLOWED_EXT = {".conf", ".txt", ".cfg", ".zip", ".gz"}


def _data_dir() -> str:
    d = os.path.join(os.path.dirname(current_app.root_path), "data", "imports")
    os.makedirs(d, exist_ok=True)
    return d


@bp.route("/", methods=["GET"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def index():
    """Upload form + a table of previously imported snapshots."""
    imports = config_import.list_snapshots(_data_dir())
    return render_template("import_backup/index.html", imports=imports)


@bp.route("/", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def upload():
    """Parse the uploaded config file offline and persist its snapshot."""
    file = request.files.get("config_file")
    device_name = (request.form.get("device_name") or "").strip()

    if file is None or not file.filename:
        flash("Please choose a config backup file to import.", "warning")
        return redirect(url_for("import_backup.index"))

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in _ALLOWED_EXT:
        flash(
            f'Unsupported file type "{ext}". '
            "Allowed: .conf .txt .cfg .zip .gz",
            "warning",
        )
        return redirect(url_for("import_backup.index"))

    data = file.read()
    try:
        result = config_import.import_backup_bytes(
            data,
            root=_data_dir(),
            device_name=device_name,
            origin=file.filename,
        )
    except ValueError as exc:
        # Encrypted / unreadable / not-a-config -> clear message, no snapshot.
        flash(f'Could not import "{file.filename}": {exc}', "danger")
        return redirect(url_for("import_backup.index"))
    except Exception as exc:  # noqa: BLE001 - never 500 on a bad upload
        flash(f"Import failed: {exc}", "danger")
        return redirect(url_for("import_backup.index"))

    log_action(
        "import_backup.create",
        target=result["device"],
        extra={
            "origin": file.filename,
            "total_objects": result["total_objects"],
            "section_count": result["section_count"],
            "note": result["note"],
        },
    )

    counts = ", ".join(f"{label}: {n}" for label, n in sorted(result["sections"].items()))
    flash(
        f'Imported "{result["device"]}" - {result["total_objects"]} object(s) '
        f'across {result["section_count"]} section(s)'
        + (f" ({counts})" if counts else "")
        + ".",
        "success",
    )
    return redirect(url_for("import_backup.index"))


@bp.route("/view/<device>", methods=["GET"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def view(device):
    """Render a parsed snapshot: firmware, totals, per-section counts, raw text."""
    snapshot = config_import.load_snapshot(device, root=_data_dir())
    if snapshot is None:
        abort(404)
    raw_text = config_import.load_snapshot_text(device, root=_data_dir())
    return render_template(
        "import_backup/index.html",
        snapshot=snapshot,
        raw_text=raw_text,
        device=device,
    )
