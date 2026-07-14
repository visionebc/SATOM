"""DNS Records provider abstraction — the pluggable IPAM/DDI backends the
DNS & LB Lookup page writes to via the +DNS Records modal.

Only **EfficientIP SOLIDserver** manages DNS resource records natively. NetBox
needs the ``netbox-dns`` plugin (core IPAM only carries a single ``dns_name``
per IP); phpIPAM needs its PowerDNS integration. Each provider therefore
declares its :class:`Capabilities` so the modal can adapt (hide write controls,
restrict record types, require a zone/view) instead of promising CRUD it cannot
deliver against a given customer install. Detection is defensive and lazy.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class ProviderError(Exception):
    """Any provider-side failure (auth, HTTP, unsupported op)."""


@dataclass
class Capabilities:
    provider: str            # registry key: efficientip|phpipam|netbox|none
    label: str
    can_write: bool          # supports create/update/delete
    record_types: list[str]  # allowed rr_type values for create
    needs_zone: bool         # modal offers a zone field/selector
    needs_view: bool         # EfficientIP DNS view selector
    notes: str = ""          # surfaced in the modal (constraints/warnings)

    def as_dict(self) -> dict:
        return {
            "provider": self.provider, "label": self.label,
            "can_write": self.can_write, "record_types": self.record_types,
            "needs_zone": self.needs_zone, "needs_view": self.needs_view,
            "notes": self.notes,
        }


@dataclass
class DnsRecord:
    id: str = ""                     # provider-native id (for update/delete)
    name: str = ""                   # FQDN
    type: str = "A"                  # A/AAAA/CNAME/MX/TXT/...
    value: str = ""                  # rdata
    ttl: int | None = None
    zone: str = ""
    view: str = ""
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "type": self.type,
            "value": self.value, "ttl": self.ttl, "zone": self.zone,
            "view": self.view, "extra": self.extra,
        }

    @classmethod
    def from_form(cls, data: dict) -> "DnsRecord":
        ttl_raw = str(data.get("ttl") or "").strip()
        return cls(
            id=str(data.get("id") or "").strip(),
            name=str(data.get("name") or "").strip().rstrip("."),
            type=str(data.get("type") or "A").strip().upper(),
            value=str(data.get("value") or "").strip(),
            ttl=int(ttl_raw) if ttl_raw.isdigit() else None,
            zone=str(data.get("zone") or "").strip(),
            view=str(data.get("view") or "").strip(),
        )


class DnsProvider:
    """Base class. Subclasses implement the four CRUD verbs + capabilities.

    ``cfg`` is the merged non-secret config dict with ``secret`` injected
    (decrypted) by the factory in ``__init__.py``.
    """

    key = "base"
    label = "Base"

    def __init__(self, cfg: dict):
        self.cfg = cfg or {}

    # -- introspection ---------------------------------------------------
    def capabilities(self) -> Capabilities:  # pragma: no cover - abstract
        raise NotImplementedError

    def test_connection(self) -> tuple[bool, str]:  # pragma: no cover
        raise NotImplementedError

    # -- CRUD ------------------------------------------------------------
    def list_records(self, name: str = "", zone: str = "") -> list[DnsRecord]:
        raise NotImplementedError

    def create_record(self, rec: DnsRecord) -> DnsRecord:
        raise ProviderError("This provider does not support creating records.")

    def update_record(self, rec: DnsRecord) -> DnsRecord:
        raise ProviderError("This provider does not support editing records.")

    def delete_record(self, rec: DnsRecord) -> None:
        raise ProviderError("This provider does not support deleting records.")
