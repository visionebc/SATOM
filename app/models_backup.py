"""Device config-backup vault model.

Self-contained module (like ``models_firmware.py``) so the feature commits
without touching the large in-flight ``models.py``. ``app.services.backup`` and
``app.views.appliances`` import it; that import runs (via ``_register_blueprints``)
*before* ``db.create_all()`` in the app factory, so the ``config_backups`` table
is auto-created at boot — no manual migration.

A row is one stored FortiWeb configuration backup file (the binary lives on disk
under ``<data>/backups/<appliance_id>/`` — never in SQLite). ``source`` is
``'device'`` (pulled off the box) or ``'upload'`` (a ``.conf`` uploaded from a
PC, FortiWeb-GUI style). NEVER holds secrets beyond the config file itself, which
FortiWeb encrypts when a backup password is set (``encrypted`` flags that).
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db


class ConfigBackup(db.Model):
    __tablename__ = "config_backups"

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(db.Integer, index=True, nullable=False)
    appliance_name = db.Column(db.String(128), nullable=False, default="")
    filename = db.Column(db.String(255), nullable=False)
    stored_path = db.Column(db.String(512), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False, default=0)
    sha256 = db.Column(db.String(64), nullable=False, default="")
    encrypted = db.Column(db.Boolean, nullable=False, default=False)
    source = db.Column(db.String(16), nullable=False, default="upload")  # device|upload
    firmware = db.Column(db.String(64))
    note = db.Column(db.Text)
    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def size_kb(self) -> int:
        return (self.size_bytes or 0) // 1024
