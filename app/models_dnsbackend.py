"""DNS / IPAM backends — one row per configured DDI, with optional roles.

Kept out of ``models.py`` on purpose (same reasoning as ``models_provision``
and ``models_firmware``): the feature stays self-contained and commits without
touching a file other sessions are editing.

**Why rows and not the three ``AppSetting`` keys they replace.** The singleton
made one provider answer every question, so "which backend reserves the
address" and "which backend publishes the name" could not have different
answers even though :class:`~app.services.dns_providers.base.Capabilities`
already said they were different questions — ``can_allocate`` has been
deliberately separate from ``can_write`` since the day phpIPAM was added,
because phpIPAM hands out addresses and cannot write a record. With one
provider that separation was inert: if the provider could not write, nothing
could. With rows it becomes the thing the operator actually configures.

**Roles are OPTIONAL, not mandatory.** A site with one SOLIDserver that does
everything ticks both boxes on one row and never thinks about roles again;
a site with phpIPAM for pools and EfficientIP for zones splits them. Forcing
two rows on the first site would have been a tax paid by everybody to serve
the second.

**A role is a promise, so it is refused when the backend cannot keep it.**
``role_dns`` on phpIPAM is rejected at save time — its API has no record CRUD
in ANY install, so the promise is unkeepable rather than merely unverified.
``role_dns`` on NetBox is accepted, because netbox-dns may be present; whether
it is gets answered at USE time by :meth:`capabilities`, live. That split is
the whole point: a static maximum bounds what may be promised, and the live
probe reports what will actually happen.
"""
from __future__ import annotations

import json
from datetime import datetime

from .extensions import db
from .services.encryption import decrypt as _dec, encrypt as _enc


def split_list(raw: object, lower: bool = False) -> list[str]:
    """Parse a stored zone/pool list. ONE author, used by reader and writer.

    Accepts newline- or comma-separated text and a JSON list, because the
    column has been written by a form textarea and by the migration, and a
    second parser is how two callers end up disagreeing about what a row
    declares (the segments episode, 2026-08-27).

    Order is preserved and duplicates dropped.

    ``lower`` is asked for by ZONES and refused by POOLS, and the asymmetry is
    deliberate. DNS names are case-insensitive by definition, so folding
    ``Example.COM.`` onto ``example.com`` cannot lose a distinction. A pool
    identifier is an opaque provider-native string — a phpIPAM subnet name or
    a NetBox prefix — where case may be the only thing separating two pools,
    and folding it would silently point an allocation at the wrong one.
    """
    if raw is None:
        return []
    items: list[str]
    if isinstance(raw, (list, tuple)):
        items = [str(x) for x in raw]
    else:
        text = str(raw).strip()
        if text.startswith("["):
            try:
                data = json.loads(text)
                items = [str(x) for x in data] if isinstance(data, list) else []
            except (ValueError, TypeError):
                items = []
        else:
            items = text.replace(",", "\n").splitlines()
    out: list[str] = []
    for item in items:
        clean = item.strip().rstrip(".")
        if lower:
            clean = clean.lower()
        if clean and clean not in out:
            out.append(clean)
    return out


class DnsBackend(db.Model):
    """One configured IPAM/DDI endpoint."""

    __tablename__ = "dns_backends"

    id = db.Column(db.Integer, primary_key=True)
    #: Operator label. Unique because it is what audit lines and run logs
    #: name, and two backends called the same thing make those unreadable.
    name = db.Column(db.String(64), nullable=False, unique=True)
    #: Registry key: efficientip | phpipam | netbox.
    provider = db.Column(db.String(32), nullable=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)

    #: Roles. Both default ON so the common single-backend install needs no
    #: decision; ``save_backend`` clamps them to what the provider MAY do.
    role_ipam = db.Column(db.Boolean, nullable=False, default=True)
    role_dns = db.Column(db.Boolean, nullable=False, default=True)

    #: Declared scope. EMPTY MEANS CATCH-ALL, and that is a deliberate,
    #: documented default rather than "matches nothing": an install that
    #: never declares a zone keeps behaving exactly as the singleton did.
    zones = db.Column(db.Text, nullable=False, default="")
    pools = db.Column(db.Text, nullable=False, default="")

    #: Tie-break between candidates of EQUAL specificity, lowest first. It is
    #: never used to override a more specific claim — a catch-all with
    #: priority 0 does not beat a backend that names the zone.
    priority = db.Column(db.Integer, nullable=False, default=100)

    config_json = db.Column(db.Text, nullable=False, default="{}")
    secret_enc = db.Column(db.Text, nullable=False, default="")

    last_status = db.Column(db.String(16), default="unknown")
    last_checked_at = db.Column(db.DateTime)
    last_error = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # -- secret ----------------------------------------------------------
    @property
    def secret(self) -> str:
        if not self.secret_enc:
            return ""
        try:
            return _dec(self.secret_enc)
        except Exception:  # noqa: BLE001 — rotated/bad key reads as absent
            return ""

    @secret.setter
    def secret(self, plaintext: str) -> None:
        self.secret_enc = _enc(plaintext) if plaintext else ""

    # -- config ----------------------------------------------------------
    @property
    def config(self) -> dict:
        try:
            data = json.loads(self.config_json or "{}")
        except (ValueError, TypeError):
            return {}
        return data if isinstance(data, dict) else {}

    @config.setter
    def config(self, data: dict) -> None:
        self.config_json = json.dumps(data or {})

    def zone_list(self) -> list[str]:
        return split_list(self.zones, lower=True)

    def pool_list(self) -> list[str]:
        return split_list(self.pools)

    def instance(self):
        """Build the provider client for this row. Never called at import.

        **Scope and default are different questions and both are kept.**
        ``zones``/``pools`` say which questions this backend is allowed to
        answer (routing); ``default_zone``/``default_pool`` say what to use
        when the caller names none. Collapsing them looks tidy and is wrong in
        both directions: a migrated singleton that carried a default zone
        would have had that turned into a scope, silently REFUSING every other
        zone it used to serve; and a backend scoped to three zones has no
        single "the zone" unless somebody says which.

        They cannot drift, because ``save_backend`` refuses a default outside
        the declared scope, and a scoped backend with no explicit default
        falls back to its first declared entry here — one derivation, in one
        place.
        """
        from .services.dns_providers import PROVIDERS
        from .services.dns_providers.none import NoneProvider

        cfg = dict(self.config)
        cfg["secret"] = self.secret
        zones, pools = self.zone_list(), self.pool_list()
        if zones and not str(cfg.get("default_zone") or "").strip():
            cfg["default_zone"] = zones[0]
        if pools and not str(cfg.get("default_pool") or "").strip():
            cfg["default_pool"] = pools[0]
        return PROVIDERS.get(self.provider, NoneProvider)(cfg)

    def public(self) -> dict:
        """Shape handed to the browser. The secret never crosses this."""
        from .services.dns_providers import PROVIDERS

        cls = PROVIDERS.get(self.provider)
        return {
            "id": self.id,
            "name": self.name,
            "provider": self.provider,
            "provider_label": getattr(cls, "label", self.provider),
            "enabled": bool(self.enabled),
            "role_ipam": bool(self.role_ipam),
            "role_dns": bool(self.role_dns),
            "may_allocate": bool(getattr(cls, "may_allocate", False)),
            "may_write": bool(getattr(cls, "may_write", False)),
            "zones": self.zone_list(),
            "pools": self.pool_list(),
            "priority": self.priority,
            "config": {k: v for k, v in self.config.items() if k != "secret"},
            "has_secret": bool(self.secret_enc),
            "last_status": self.last_status or "unknown",
            "last_checked_at": (self.last_checked_at.isoformat()
                                if self.last_checked_at else None),
            "last_error": self.last_error or "",
        }
