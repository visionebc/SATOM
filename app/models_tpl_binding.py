"""Which device a template governs, and with which per-device values.

A template is the SHARED intent of an ADOM (``Template.product`` is the ADOM
key). A device does not get a copy of it: it gets a BINDING to the template
family (``kind`` + ``name``), optionally pinned to one version, plus the values
that differ per device (an IP, a host name) as ``variables``. A body spells a
per-device value as ``{{ variable }}``; the apply renders it per device and
refuses a device whose binding leaves a placeholder unresolved.

Bindings also scope the template lock. An approved Web Protection Profile
template WITHOUT bindings keeps the old rule (read-only on every device of its
ADOM); once it has bindings it is read-only only on the bound devices.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .extensions import db


class TemplateBinding(db.Model):
    __tablename__ = "template_bindings"
    __table_args__ = (
        db.UniqueConstraint("appliance_id", "kind", "name",
                            name="uq_template_binding_device_family"),
    )

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(db.Integer, db.ForeignKey("appliances.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    product = db.Column(db.String(32), nullable=False, default="fortiweb")
    kind = db.Column(db.String(64), nullable=False, index=True)
    name = db.Column(db.String(128), nullable=False, index=True)
    # NULL = follow the newest APPROVED version of the family.
    pinned_version = db.Column(db.Integer, nullable=True)
    variables = db.Column(db.Text, nullable=True, default="")  # JSON {name: value}
    note = db.Column(db.Text, nullable=True, default="")
    created_by = db.Column(db.String(64), nullable=True, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    @property
    def variables_dict(self) -> dict[str, Any]:
        try:
            data = json.loads(self.variables or "{}")
            return data if isinstance(data, dict) else {}
        except (ValueError, TypeError):
            return {}

    def __repr__(self) -> str:
        return "<TemplateBinding %s/%s -> appliance %s>" % (
            self.kind, self.name, self.appliance_id)
