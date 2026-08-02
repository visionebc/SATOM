"""UI theme registry — named sets of the stylesheet's design tokens.

Settings -> Appearance lets an admin repaint the console: the ``--fw-*`` custom
properties the stylesheet already exposes (see ``services/theme_tokens.py``,
generated from the CSS itself) plus an optional brand logo and favicon.

Design notes that matter:

* **Only token OVERRIDES are stored.** A theme keeps the tokens it actually
  changes; everything else falls through to the stylesheet. So a stylesheet
  refresh (new default border colour, say) reaches every theme that never
  opted out of it, instead of freezing five copies of an old palette.
* **Built-ins are immutable.** ``builtin=True`` rows cannot be edited or
  deleted — they are the recovery path when a custom theme turns the console
  unreadable. Duplicate to edit.
* Exactly one row may be ``is_active``. Activation is a service-level swap so
  the constraint cannot be half-applied.

The seed is INSERT-ONLY (same contract as ``adoms``, ``registry_endpoints`` and
``acme_dns_providers``): the operator's edits always win over a redeploy.
"""
from __future__ import annotations

import json
from datetime import datetime

from .extensions import db


class UiTheme(db.Model):
    __tablename__ = "ui_themes"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    description = db.Column(db.String(300), nullable=False, default="")

    #: JSON object of token overrides, ``{"accent": "#4F46E5", ...}``.
    #: Absent keys fall through to the stylesheet default on purpose.
    tokens_json = db.Column(db.Text, nullable=False, default="{}")

    #: Optional brand overrides. Relative paths under ``data/branding/``; empty
    #: means "use the per-ADOM mark", which is the shipped behaviour.
    logo = db.Column(db.String(256), nullable=False, default="")
    favicon = db.Column(db.String(256), nullable=False, default="")

    builtin = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=False, index=True)

    created_by = db.Column(db.String(128), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    # ── tokens ─────────────────────────────────────────────────────────────
    @property
    def tokens(self) -> "dict[str, str]":
        try:
            val = json.loads(self.tokens_json or "{}")
            return {str(k): str(v) for k, v in val.items()} if isinstance(val, dict) else {}
        except Exception:
            # A corrupt row must not take the whole console down — the theme
            # simply degrades to the stylesheet defaults.
            return {}

    @tokens.setter
    def tokens(self, value: "dict[str, str]") -> None:
        self.tokens_json = json.dumps(dict(value or {}), sort_keys=True)

    @property
    def editable(self) -> bool:
        return not self.builtin

    def to_dict(self, include_tokens: bool = True) -> dict:
        d = {
            "id": self.id,
            "slug": self.slug,
            "name": self.name,
            "description": self.description or "",
            "builtin": bool(self.builtin),
            "active": bool(self.is_active),
            "editable": self.editable,
            "has_logo": bool(self.logo),
            "has_favicon": bool(self.favicon),
            "created_by": self.created_by or "",
            "updated_at": self.updated_at.isoformat(timespec="seconds") if self.updated_at else "",
        }
        if include_tokens:
            d["tokens"] = self.tokens
        return d

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<UiTheme %s%s>" % (self.slug, " active" if self.is_active else "")
