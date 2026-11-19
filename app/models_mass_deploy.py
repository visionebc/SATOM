"""Operations > Automation > Mass Deploy: the history of its deploys and the
rollout scope of a template family.

A deploy row is written when the operator confirms a deploy and finished by
the background job (``services.bulk.start_apply_job`` ``on_done``). It holds
the device names and per-device results, the names of the secret fields the
operator typed in at apply time and NEVER their values.

``TemplateFamilyScope`` says which devices an approved template family governs
when it has no device binding:

* ``fleet``    (default, and the rule before 2026-10-24) — every device of the
  ADOM: the lock covers them all, and a Web Protection Profile template is
  deployed to all of them on approval;
* ``selected`` — only the devices bound to it. With no binding yet it governs
  NONE: approval deploys nothing and the operator picks the devices in Mass
  Deploy, which binds each device it deploys to.

A family with bindings is scoped to them either way (services.template_bindings).
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .extensions import db

SCOPE_FLEET = "fleet"
SCOPE_SELECTED = "selected"
SCOPES = (SCOPE_FLEET, SCOPE_SELECTED)


def _loads(raw, default):
    try:
        data = json.loads(raw or "")
    except (ValueError, TypeError):
        return default
    return data if isinstance(data, type(default)) else default


class TemplateFamilyScope(db.Model):
    __tablename__ = "template_family_scope"
    __table_args__ = (
        db.UniqueConstraint("kind", "name", name="uq_template_family_scope"),
    )

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False, default="fortiweb")
    kind = db.Column(db.String(64), nullable=False)
    name = db.Column(db.String(128), nullable=False)
    scope = db.Column(db.String(16), nullable=False, default=SCOPE_FLEET)
    set_by = db.Column(db.String(64), nullable=False, default="")
    set_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class MassDeploy(db.Model):
    __tablename__ = "mass_deploys"

    STATUS_RUNNING = "running"
    STATUS_OK = "ok"
    STATUS_FAILED = "failed"
    STATUS_ABORTED = "aborted"
    STATUS_STOPPED = "stopped"

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False, default="fortiweb", index=True)
    template_id = db.Column(db.Integer, nullable=True)
    kind = db.Column(db.String(64), nullable=False, default="")
    name = db.Column(db.String(128), nullable=False, default="")
    version = db.Column(db.Integer, nullable=False, default=1)
    # JSON [{"id": 3, "name": "fwb-a"}]
    devices = db.Column(db.Text, nullable=False, default="[]")
    # JSON [label]: the secret fields typed in at apply time. Names only.
    secrets_supplied = db.Column(db.Text, nullable=False, default="[]")
    # JSON [appliance id]: devices this deploy bound to the template family.
    bound = db.Column(db.Text, nullable=False, default="[]")
    by = db.Column(db.String(64), nullable=False, default="")
    job_id = db.Column(db.String(64), nullable=False, default="")
    status = db.Column(db.String(16), nullable=False, default=STATUS_RUNNING)
    ok_count = db.Column(db.Integer, nullable=False, default=0)
    total = db.Column(db.Integer, nullable=False, default=0)
    # JSON [{"appliance": .., "ok": .., "cancelled": .., "error": ..}]
    result = db.Column(db.Text, nullable=False, default="[]")
    message = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    finished_at = db.Column(db.DateTime, nullable=True)

    @property
    def devices_list(self) -> list[dict[str, Any]]:
        return _loads(self.devices, [])

    @property
    def secrets_list(self) -> list[str]:
        return _loads(self.secrets_supplied, [])

    @property
    def bound_list(self) -> list[int]:
        return _loads(self.bound, [])

    @property
    def result_list(self) -> list[dict[str, Any]]:
        return _loads(self.result, [])
