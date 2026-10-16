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
