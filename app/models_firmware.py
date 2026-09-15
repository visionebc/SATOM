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


class FirmwareVersionDecl(db.Model):
    """A firmware version an operator declared BY HAND. Authored data only.

    Versions that come from a ``FirmwareImage`` row or from an appliance's
    running firmware are derived on read by
    :func:`app.services.firmware_versions.catalog` and deliberately do NOT get
    a row here: two upload paths create ``FirmwareImage`` rows, and hooking
    both would be one refactor away from a version that silently never appears
    on the API-versions page. A derived fact has a source; this table is for
    the facts that have nowhere else to live — "8.0.5 exists and we intend to
    measure it" before any image or box proves it.

    Deleting a row forgets the NOTE, never the version: a version that is also
    derived stays on the page afterwards.
    """

    __tablename__ = "firmware_version_decls"
    __table_args__ = (
        db.UniqueConstraint("product", "version", name="uq_fwverdecl_product_version"),
    )

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False, default="fortiweb")
    #: Normalised by ``firmware_versions.normalize`` before it ever gets here —
    #: ``8.0.3``, or ``8.0`` when only the line is known. A line-only string is
    #: NOT the patch ``.0`` and must never be widened into one.
    version = db.Column(db.String(32), nullable=False)
    note = db.Column(db.String(500), default="")
    declared_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):  # pragma: no cover - debugging aid
        return "<FirmwareVersionDecl %s %s>" % (self.product, self.version)
