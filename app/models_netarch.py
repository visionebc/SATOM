"""Fleet → Architecture drawings (see :mod:`app.services.netarch`).

One row per drawing. ``layout`` is the validated JSON
``{"nodes": [...], "edges": [...]}`` — the drawing only; live device data is
read on request and never stored here.
"""
from __future__ import annotations

import json
from datetime import datetime

from .extensions import db


class ArchDiagram(db.Model):
    __tablename__ = "arch_diagrams"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True, default="")
    layout = db.Column(db.Text, nullable=False, default='{"nodes": [], "edges": []}')
    created_by = db.Column(db.String(64), nullable=True, default="")
    updated_by = db.Column(db.String(64), nullable=True, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    @property
    def layout_dict(self) -> dict:
        try:
            data = json.loads(self.layout or "{}")
        except (ValueError, TypeError):
            return {"nodes": [], "edges": []}
        if not isinstance(data, dict):
            return {"nodes": [], "edges": []}
        data.setdefault("nodes", [])
        data.setdefault("edges", [])
        return data

    def __repr__(self) -> str:
        return "<ArchDiagram %s>" % self.name
