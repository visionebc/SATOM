"""Diagnostic batteries — what each ADOM runs, and what each build offers.

``diag_catalogs``: one row per (product, build) — the ``diagnose`` commands a
device of that build answered for when an administrator ran discovery
(:mod:`app.services.diag_tree`). Re-running discovery on the same build
replaces the row: the newest walk is the truth for that build.

``diag_batteries``: one row per ADOM key — the commands the administrator
picked (Administrator → Diagnostic Battery). Diagnose Log Collection runs
exactly this list. No row = the product default
(:data:`app.services.diag_battery.DEFAULTS`).

Both live in Postgres, so the standby replica carries them with everything
else; nothing here is a file under ``data/``.
"""
from __future__ import annotations

import json
from datetime import datetime

from .extensions import db


class DiagCatalog(db.Model):
    __tablename__ = "diag_catalogs"
    __table_args__ = (db.UniqueConstraint("product", "build",
                                          name="uq_diag_catalog_product_build"),)

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(32), nullable=False, index=True)
    build = db.Column(db.String(32), nullable=False)          # "7.6.8"
    firmware = db.Column(db.String(128), nullable=True)       # raw string
    appliance_name = db.Column(db.String(128), nullable=True)
    discovered_by = db.Column(db.String(64), nullable=True)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    duration_s = db.Column(db.Integer, nullable=True)
    probed = db.Column(db.Integer, nullable=False, default=0)
    truncated = db.Column(db.Text, nullable=True)  # why the walk stopped early
    nodes_json = db.Column(db.Text, nullable=False, default="[]")

    @property
    def nodes(self) -> list[dict]:
        try:
            return json.loads(self.nodes_json or "[]")
        except ValueError:
            return []

    @nodes.setter
    def nodes(self, value: list[dict]) -> None:
        self.nodes_json = json.dumps(value, separators=(",", ":"))

    def node_map(self) -> dict[str, dict]:
        return {n["path"]: n for n in self.nodes if n.get("path")}

    def counts(self) -> dict:
        ns = self.nodes
        return {
            "nodes": len(ns),
            "runnable": sum(1 for n in ns if n.get("runnable") and not n.get("blocked")),
            "blocked": sum(1 for n in ns if n.get("blocked")),
        }


class DiagBattery(db.Model):
    __tablename__ = "diag_batteries"

    adom_key = db.Column(db.String(64), primary_key=True)
    commands_json = db.Column(db.Text, nullable=False, default="[]")
    updated_by = db.Column(db.String(64), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    @property
    def commands(self) -> list[str]:
        try:
            v = json.loads(self.commands_json or "[]")
        except ValueError:
            return []
        return [str(c) for c in v if isinstance(c, str)]

    @commands.setter
    def commands(self, value: list[str]) -> None:
        self.commands_json = json.dumps(list(value))


__all__ = ["DiagCatalog", "DiagBattery"]
