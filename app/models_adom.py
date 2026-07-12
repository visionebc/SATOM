"""ADOM registry model — the single source of truth for products/ADOMs.

Historically the set of ADOMs (``global``/``fortiweb``/``fortiadc`` and the
placeholder ``fortiauthenticator``/``fortianalyzer``) plus their *scoping* was
hardcoded in ~5 different lists scattered across the codebase (``branding.py``,
``settings_store.BANNER_PRODUCTS``, ``models_api_token.VALID_PRODUCTS``,
``firmware._PRODUCTS``, ``naming``/``regex_lab`` PRODUCTS). Adding an ADOM meant
editing every one of them, and forgetting one produced silent gaps (an ADOM in
the selector with no banner, no tokens, no firmware...).

This table makes the registry data-driven. Each row carries its identity
(name/title/tagline/description/logo) AND *capability flags* that replace those
scattered lists:

* ``cap_banner``   — carries a personal top-bar banner  (was BANNER_PRODUCTS)
* ``cap_tokens``   — API tokens can be scoped to it     (was VALID_PRODUCTS)
* ``cap_firmware`` — firmware image management applies   (was firmware._PRODUCTS)
* ``cap_naming``   — appears in the name-pattern editor  (was naming.PRODUCTS)
* ``cap_regex``    — appears in the regex lab            (was regex_lab.PRODUCTS)

``active=False`` removes the ADOM from the selector and the product gate (its
routes 404/redirect); the admin console still lists it so it can be toggled
back on. ``branding.py`` reads this table (cached, TTL) and exposes the same
``PRODUCTS`` mapping + live capability sequences the rest of the app already
imports, so nothing downstream had to change its call sites.
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db


class Adom(db.Model):
    __tablename__ = "adoms"

    id = db.Column(db.Integer, primary_key=True)
    # Stable slug used everywhere as the product key (session['product'], URLs,
    # config keys). Immutable once created (renaming would orphan settings).
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)

    name = db.Column(db.String(128), nullable=False)          # display name
    title = db.Column(db.String(128), nullable=False, default="OFortMAut")
    tagline = db.Column(db.String(200), nullable=False, default="")
    description = db.Column(db.Text, nullable=False, default="")
    mark = db.Column(db.String(256), nullable=False, default="img/global-mark.svg")

    active = db.Column(db.Boolean, nullable=False, default=True)
    placeholder = db.Column(db.Boolean, nullable=False, default=False)
    sort_order = db.Column(db.Integer, nullable=False, default=100)

    # Default banner template id (from settings_store.BANNER_TEMPLATES); only
    # meaningful when cap_banner is set.
    banner_default = db.Column(db.String(32), nullable=False, default="slate")

    # ── capability flags (replace the old hardcoded lists) ──────────────────
    cap_banner = db.Column(db.Boolean, nullable=False, default=False)
    cap_tokens = db.Column(db.Boolean, nullable=False, default=False)
    cap_firmware = db.Column(db.Boolean, nullable=False, default=False)
    cap_naming = db.Column(db.Boolean, nullable=False, default=False)
    cap_regex = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    # Capability flag name -> column, so branding can filter generically.
    CAPS = ("banner", "tokens", "firmware", "naming", "regex")

    def has_cap(self, cap: str) -> bool:
        return bool(getattr(self, "cap_" + cap, False))

    def to_branding(self) -> dict:
        """The dict shape ``branding.get_product`` / templates expect."""
        d = {
            "key": self.key,
            "name": self.name,
            "title": self.title or "OFortMAut",
            "tagline": self.tagline or "",
            "mark": self.mark or "img/global-mark.svg",
            "description": self.description or "",
            "active": bool(self.active),
            "sort_order": self.sort_order,
            "banner_default": self.banner_default or "slate",
        }
        if self.placeholder:
            d["placeholder"] = True
        for cap in self.CAPS:
            d["cap_" + cap] = self.has_cap(cap)
        return d
