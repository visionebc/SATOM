"""Per-user notification records (the top-bar bell + /notifications page).

A small, generic notification the app can raise for ANY event — a background
job finishing (firmware verify, upgrade, bulk push…), a bug report being
resolved, a template pending approval — so the bell becomes ONE surface instead
of a per-feature conditional. Persisted in the DB (not the JSON job store) so it
is per-user, has read/unread state, survives restarts, and is worker-proof under
multi-worker gunicorn (shared Postgres).

Kept in its own module (like ``models_firmware`` / ``models_backup``); the
``views.notifications`` blueprint imports it, and it is registered BEFORE
``db.create_all()`` in the app factory, so the ``notifications`` table is created
automatically on the next boot.
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db


class Notification(db.Model):
    __tablename__ = "notifications"

    # Semantic kinds — drive the icon/colour on the page and the toast.
    KIND_INFO = "info"
    KIND_SUCCESS = "success"
    KIND_WARNING = "warning"
    KIND_ERROR = "error"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind = db.Column(db.String(16), nullable=False, default=KIND_INFO)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=True)
    # Where clicking the row takes the user (a resolved url path). Optional.
    link = db.Column(db.String(500), nullable=True)
    read = db.Column(db.Boolean, nullable=False, default=False, index=True)
    # ADOM/product that raised it ('' / NULL = unscoped -> hidden from ADC).
    product = db.Column(db.String(32), nullable=True, default="")
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False, index=True
    )

    user = db.relationship("User", foreign_keys=[user_id])

    @property
    def icon(self) -> str:
        return {
            self.KIND_SUCCESS: "bi-check-circle-fill",
            self.KIND_WARNING: "bi-exclamation-triangle-fill",
            self.KIND_ERROR: "bi-x-octagon-fill",
        }.get(self.kind, "bi-info-circle-fill")

    @property
    def color(self) -> str:
        return {
            self.KIND_SUCCESS: "#10b981",
            self.KIND_WARNING: "#fbbf24",
            self.KIND_ERROR: "#ef4444",
        }.get(self.kind, "#3b82f6")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "body": self.body,
            "link": self.link,
            "read": self.read,
            "created": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Notification u={self.user_id} {self.kind} {self.title!r}>"
