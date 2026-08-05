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
    # Fortinet publishes TWO different artefacts per release and they are not
    # interchangeable: an *upgrade* image (``.out``, applied to a running
    # appliance) and an *install* image (``.zip``/``.qcow2``/``.ova``, used to
    # build a machine from nothing). Offering one where the other is required
    # is not a validation nicety — an operator who picks the wrong file learns
    # about it from a bricked box or a VM that will not boot. Default
    # ``upgrade`` because every row that existed before this column is one.
    image_kind = db.Column(db.String(16), nullable=False, default="upgrade")
    #: Install images are hypervisor-specific; upgrade images are not.
    #: "" = not applicable / any.
    hypervisor = db.Column(db.String(16), default="")   # kvm | vmware | ""
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
