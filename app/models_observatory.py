"""HTTP Observatory scans — one row per graded site per run.

A row keeps what the grade was computed from (headers, statuses, redirect
routes, cookie FLAGS — never cookie values, never the page body) so the
findings can be recomputed later against the appliance's current
configuration, and so a grade that drops between two runs can be explained
from the two rows alone.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .extensions import db


class ObservatoryScan(db.Model):
    __tablename__ = "observatory_scans"
    __table_args__ = (
        db.Index("ix_observatory_scans_site", "appliance_id", "policy", "started_at"),
    )

    TRIGGERS = ("manual", "scheduled", "fix")

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(db.Integer, db.ForeignKey("appliances.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    product = db.Column(db.String(32), nullable=False, default="fortiweb")
    policy = db.Column(db.String(128), nullable=False)
    host = db.Column(db.String(255), nullable=False, default="")
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    finished_at = db.Column(db.DateTime, nullable=True)
    #: NULL when the site could not be graded (``error`` says why).
    grade = db.Column(db.String(3), nullable=True)
    score = db.Column(db.Integer, nullable=True)
    tests_passed = db.Column(db.Integer, nullable=True)
    tests_failed = db.Column(db.Integer, nullable=True)
    error = db.Column(db.Text, nullable=True, default="")
    #: JSON: ``{target, analysis, retrieval}`` from observatory_scan.scan().
    result = db.Column(db.Text, nullable=True, default="")
    trigger = db.Column(db.String(16), nullable=False, default="manual")
    username = db.Column(db.String(64), nullable=True, default="")

    @property
    def result_dict(self) -> dict[str, Any]:
        try:
            data = json.loads(self.result or "{}")
            return data if isinstance(data, dict) else {}
        except (ValueError, TypeError):
            return {}

    def summary(self) -> dict[str, Any]:
        return {"id": self.id, "appliance_id": self.appliance_id,
                "product": self.product, "policy": self.policy, "host": self.host,
                "started_at": self.started_at.isoformat() + "Z" if self.started_at else None,
                "grade": self.grade, "score": self.score,
                "tests_passed": self.tests_passed, "tests_failed": self.tests_failed,
                "error": self.error or "", "trigger": self.trigger,
                "username": self.username or ""}

    def __repr__(self) -> str:
        return "<ObservatoryScan %s %s/%s %s>" % (self.id, self.appliance_id,
                                                  self.policy, self.grade)


def _loads(raw, default):
    try:
        data = json.loads(raw or "")
        return data if isinstance(data, type(default)) else default
    except (ValueError, TypeError):
        return default


class ObservatoryFix(db.Model):
    """One applied set of Observatory fixes, kept so it can be reverted.

    ``steps`` is the plan's writes in order, each with what it found before
    (``before``: only the fields it wrote, read from the device when the plan
    was made), what it sent, the row id it created, and whether the device
    took it. :func:`app.services.observatory_fix.revert_plan` reads it
    backwards. Header values and cookie flags only — never a secret.
    """
    __tablename__ = "observatory_fixes"
    __table_args__ = (
        db.Index("ix_observatory_fixes_site", "appliance_id", "policy", "applied_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(db.Integer, db.ForeignKey("appliances.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    policy = db.Column(db.String(128), nullable=False)
    #: The scan the fixes were planned from, and the re-grade after them.
    scan_id = db.Column(db.Integer, nullable=True)
    after_scan_id = db.Column(db.Integer, nullable=True)
    applied_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    username = db.Column(db.String(64), nullable=True, default="")
    #: JSON list of fix ids, e.g. ``["hsts", "header:x-frame-options"]``.
    fixes = db.Column(db.Text, nullable=False, default="[]")
    #: JSON list of steps (see the class docstring).
    steps = db.Column(db.Text, nullable=False, default="[]")
    #: JSON list of the OTHER server policies the change reached.
    others = db.Column(db.Text, nullable=False, default="[]")
    #: Every write was accepted (a partial apply is revertable too).
    ok = db.Column(db.Boolean, nullable=False, default=True)
    reverted_at = db.Column(db.DateTime, nullable=True)
    reverted_by = db.Column(db.String(64), nullable=True)
    #: JSON: the revert's per-step outcome.
    revert_result = db.Column(db.Text, nullable=True)

    @property
    def steps_list(self) -> list:
        return _loads(self.steps, [])

    @property
    def fixes_list(self) -> list:
        return _loads(self.fixes, [])

    @property
    def others_list(self) -> list:
        return _loads(self.others, [])

    def summary(self) -> dict[str, Any]:
        return {"id": self.id, "appliance_id": self.appliance_id, "policy": self.policy,
                "scan_id": self.scan_id, "after_scan_id": self.after_scan_id,
                "applied_at": self.applied_at.isoformat() + "Z" if self.applied_at else None,
                "username": self.username or "", "fixes": self.fixes_list,
                "writes": [s.get("describe") for s in self.steps_list if s.get("ok")],
                "others": self.others_list, "ok": bool(self.ok),
                "reverted_at": self.reverted_at.isoformat() + "Z" if self.reverted_at else None,
                "reverted_by": self.reverted_by or "",
                "revert_result": _loads(self.revert_result, [])}

    def __repr__(self) -> str:
        return "<ObservatoryFix %s %s/%s>" % (self.id, self.appliance_id, self.policy)
