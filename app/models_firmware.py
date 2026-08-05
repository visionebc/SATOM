"""Firmware image repository model.

Kept in its own module (not ``models.py``) so the feature is self-contained and
commits without touching the in-flight profiles refactor that currently sits
uncommitted in ``models.py``. ``app.views.firmware`` imports it, and that import
runs (via ``_register_blueprints``) *before* ``db.create_all()`` in the app
factory, so the ``firmware_images`` table is auto-created at boot — no manual
migration. Can be folded back into ``models.py`` once the profiles work lands.
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db


class FirmwareImage(db.Model):
    __tablename__ = "firmware_images"

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False, default="fortiweb")
    model = db.Column(db.String(64))
    # "" = universal / any | "hw" = hardware appliance | "vm" = virtual machine
    platform = db.Column(db.String(8), default="")
    version = db.Column(db.String(32), nullable=False)
    build = db.Column(db.String(32))
    filename = db.Column(db.String(255), nullable=False)
    stored_path = db.Column(db.String(512), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False, default=0)
    sha256 = db.Column(db.String(64), nullable=False, default="")
    notes = db.Column(db.Text)
    uploaded_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def size_mb(self) -> int:
        return (self.size_bytes or 0) // (1024 * 1024)
