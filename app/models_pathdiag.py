"""Path Diagnostics — saved walk reports.

Until 2026-10-30 a walk was rendered once and lost: the job kept the device
calls for seven days and the audit row kept only the verdict, so "why did it
say the pool was down?" had no evidence to answer it with a week later. A row
here is the report exactly as the page drew it, plus the metrics panel and the
job that carried the device calls.

Read-only history: nothing edits a row after it is written. ``product`` is
``String(32)`` from creation (see models_advisor for why never 16).
"""
from __future__ import annotations

import json
from datetime import datetime

from .extensions import db


class PathDiagReport(db.Model):
    __tablename__ = "path_diag_reports"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    username = db.Column(db.String(64), nullable=False, default="")
    product = db.Column(db.String(32), nullable=False, default="", index=True)
    appliance_id = db.Column(db.Integer, nullable=True, index=True)
    appliance_name = db.Column(db.String(128), nullable=False, default="")
    kind = db.Column(db.String(32), nullable=False, default="")
    policy = db.Column(db.String(256), nullable=False, default="")
    localised = db.Column(db.Boolean, nullable=False, default=False)
    verdict_layer = db.Column(db.String(64), nullable=False, default="")
    verdict_text = db.Column(db.String(400), nullable=False, default="")
    metrics_status = db.Column(db.String(16), nullable=False, default="")
    window_minutes = db.Column(db.Integer, nullable=False, default=0)
    job_id = db.Column(db.String(64), nullable=False, default="")
    report_json = db.Column(db.Text, nullable=False, default="{}")
    metrics_json = db.Column(db.Text, nullable=False, default="{}")

    @classmethod
    def prune(cls, older_than_days: int) -> int:
        """Delete reports older than ``older_than_days``; 0 keeps everything.
        Returns how many rows went. The caller commits."""
        if not older_than_days or older_than_days <= 0:
            return 0
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(days=int(older_than_days))
        return cls.query.filter(cls.created_at < cutoff).delete(
            synchronize_session=False)

    def report(self) -> dict:
        try:
            return json.loads(self.report_json or "{}")
        except ValueError:
            return {}

    def metrics(self) -> dict:
        try:
            return json.loads(self.metrics_json or "{}")
        except ValueError:
            return {}

    def summary(self) -> dict:
        return {"id": self.id,
                "created_at": self.created_at.isoformat(timespec="seconds") + "Z",
                "username": self.username, "appliance_id": self.appliance_id,
                "appliance": self.appliance_name, "kind": self.kind,
                "policy": self.policy, "localised": self.localised,
                "verdict_layer": self.verdict_layer,
                "verdict_text": self.verdict_text,
                "metrics_status": self.metrics_status,
                "window_minutes": self.window_minutes, "job_id": self.job_id}
