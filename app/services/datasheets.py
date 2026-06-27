"""Storage helper for appliance datasheet PDFs.

Datasheets are stored on disk as ``<datasheet_dir>/<appliance_id>.pdf`` and the
original display filename is kept in ``Appliance.datasheet_filename``. The
directory defaults to a ``datasheets`` folder next to the SQLite database file
(overridable with the ``DATASHEET_DIR`` config key — used by tests).

We deliberately validate the PDF size *per upload* here rather than via a global
``MAX_CONTENT_LENGTH``, because the firmware-upgrade endpoint legitimately POSTs
large ``.out`` images and a global cap would break it.
"""
from __future__ import annotations

import os

from flask import current_app

ALLOWED_EXT = ".pdf"
MAX_BYTES = 25 * 1024 * 1024  # 25 MB — generous for a datasheet, far below firmware


def dir_path() -> str:
    """Return the datasheet directory, creating it if needed."""
    d = current_app.config.get("DATASHEET_DIR")
    if not d:
        uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "") or ""
        if uri.startswith("sqlite:///"):
            db_path = uri.split("sqlite:///", 1)[1]
            base = os.path.dirname(db_path) or "."
        else:
            base = current_app.instance_path
        d = os.path.join(base, "datasheets")
    os.makedirs(d, exist_ok=True)
    return d


def path_for(appliance_id: int) -> str:
    return os.path.join(dir_path(), f"{appliance_id}.pdf")


def save(appliance_id: int, file_storage) -> str:
    """Validate and persist an uploaded PDF. Returns the cleaned display name.

    Raises ``ValueError`` with a user-facing message on any validation failure.
    """
    fn = (getattr(file_storage, "filename", "") or "").strip()
    if not fn.lower().endswith(ALLOWED_EXT):
        raise ValueError("Datasheet must be a .pdf file.")
    data = file_storage.read()
    if not data:
        raise ValueError("Uploaded datasheet is empty.")
    if len(data) > MAX_BYTES:
        raise ValueError(f"Datasheet exceeds the {MAX_BYTES // (1024 * 1024)} MB limit.")
    if not data[:5].startswith(b"%PDF-"):
        raise ValueError("File does not look like a valid PDF.")
    with open(path_for(appliance_id), "wb") as fh:
        fh.write(data)
    return os.path.basename(fn)


def delete(appliance_id: int) -> None:
    """Remove the stored datasheet file if present (best-effort)."""
    try:
        p = path_for(appliance_id)
        if os.path.exists(p):
            os.remove(p)
    except OSError:
        pass
