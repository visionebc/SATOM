"""Scrape targets — the configuration of the fleet metrics collection.

One row per (appliance, collector), NOT one row per series: at fleet scale
(100 devices x 750 policies) per-series rows are ~180,000 pieces of operator
configuration, which is the design error the 2026-08-05 measurement caught.
A collector yields MANY series from ONE call; the series are identified by
labels inside VictoriaMetrics, and this table only says how often each
collector runs against each device.
"""
from __future__ import annotations

import json
from datetime import datetime

from .models import db


class ScrapeTarget(db.Model):
    __tablename__ = "scrape_target"
    __table_args__ = (
        db.UniqueConstraint("appliance_id", "collector",
                            name="uq_scrape_target"),
    )

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(db.Integer,
                             db.ForeignKey("appliances.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    collector = db.Column(db.String(40), nullable=False)
    interval_min = db.Column(db.Integer, nullable=False, default=3)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    params_json = db.Column(db.Text, nullable=False, default="{}")

    last_run_at = db.Column(db.DateTime)
    last_status = db.Column(db.String(16), default="")   # ok | error | skipped
    last_detail = db.Column(db.String(300), default="")
    last_series = db.Column(db.Integer, default=0)
    last_ms = db.Column(db.Integer, default=0)

    appliance = db.relationship("Appliance")

    @property
    def params(self) -> dict:
        try:
            return json.loads(self.params_json or "{}")
        except Exception:  # noqa: BLE001
            return {}

    @params.setter
    def params(self, value: dict) -> None:
        self.params_json = json.dumps(value or {})

    def to_dict(self) -> dict:
        return {
            "id": self.id, "appliance_id": self.appliance_id,
            "device": self.appliance.name if self.appliance else "",
            "kind": self.appliance.kind if self.appliance else "",
            "collector": self.collector, "interval_min": self.interval_min,
            "enabled": bool(self.enabled), "params": self.params,
            "last_run_at": self.last_run_at.isoformat(timespec="seconds")
                           if self.last_run_at else "",
            "last_status": self.last_status or "",
            "last_detail": self.last_detail or "",
            "last_series": int(self.last_series or 0),
            "last_ms": int(self.last_ms or 0),
        }
