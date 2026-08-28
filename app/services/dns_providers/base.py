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


# --------------------------------------------------------------------------
# netmask arithmetic — ONE author, used by every provider that allocates.
# Two copies of this conversion is how a subnet ends up with two different
# masks depending on which backend answered.
# --------------------------------------------------------------------------
def prefix_from_size(size: object) -> int | None:
    """A count of addresses (SOLIDserver ``subnet_size``) -> prefix length.

    Returns None for anything that is not an exact power of two. A subnet
    cannot have a non-power-of-two size, so such a value means the field was
    not what we thought — and a guessed netmask gets pushed onto a real
    appliance at first boot.
    """
    try:
        n = int(str(size).strip())
    except (TypeError, ValueError):
        return None
    if n <= 0 or (n & (n - 1)) != 0:
        return None
    return 32 - n.bit_length() + 1


def mask_from_prefix(prefix: object) -> str:
    """Prefix length -> dotted netmask. Empty string when it is not a prefix."""
    try:
        p = int(str(prefix).strip())
    except (TypeError, ValueError):
        return ""
    if not 0 <= p <= 32:
        return ""
    bits = (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF
    return ".".join(str((bits >> s) & 0xFF) for s in (24, 16, 8, 0))


@dataclass
class Capabilities:
    provider: str            # registry key: efficientip|phpipam|netbox|none
    label: str
    can_write: bool          # supports create/update/delete
    record_types: list[str]  # allowed rr_type values for create
    needs_zone: bool         # modal offers a zone field/selector
    needs_view: bool         # EfficientIP DNS view selector
    notes: str = ""          # surfaced in the modal (constraints/warnings)
    #: Supports taking an address out of a pool and handing it back.
    #: DELIBERATELY SEPARATE FROM ``can_write``: the two are independent in
    #: every backend we support. phpIPAM allocates but cannot write a record;
    #: NetBox without ``netbox-dns`` is the same shape. Folding them into one
    #: flag would have made "this provider can reserve an address" imply "this
    #: provider will publish the name", which is the promise the provisioning
    #: DNS step used to make and could not keep.
    can_allocate: bool = False
    #: A pool/prefix/subnet identifier is required to allocate (all real DDIs).
    needs_pool: bool = False

    def as_dict(self) -> dict:
        return {
            "provider": self.provider, "label": self.label,
            "can_write": self.can_write, "record_types": self.record_types,
            "needs_zone": self.needs_zone, "needs_view": self.needs_view,
            "notes": self.notes, "can_allocate": self.can_allocate,
            "needs_pool": self.needs_pool,
        }


@dataclass
class Address:
    """One address taken from an IPAM pool.

    ``ref`` is the provider-native handle and is what :meth:`release_address`
    is driven by. Releasing by *address string* alone is a real hazard: between
    the reservation and the rollback the pool may legitimately have handed the
    same address to somebody else (a lease expiring, an operator editing the
    row), and a release keyed on the string would free THEIR entry. The handle
    names the row this run created, or nothing at all.
    """

    address: str = ""
    ref: str = ""                    # provider-native id of the reservation
    #: WHICH backend handed this out. Meaningless under a single provider and
    #: load-bearing with several: ``ref`` is only an identifier inside the
    #: system that issued it, so a release replayed against a different
    #: backend either does nothing or frees a row that backend owns. Callers
    #: persist this next to ``ref``.
    backend_id: int | None = None
    netmask: str = ""
    prefix_len: int | None = None
    gateway: str = ""
    pool: str = ""
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "address": self.address, "ref": self.ref, "netmask": self.netmask,
            "prefix_len": self.prefix_len, "gateway": self.gateway,
            "pool": self.pool, "extra": self.extra,
            "backend_id": self.backend_id,
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
    #: WHICH backend published this. Same reasoning as ``Address.backend_id``:
    #: a provider-native record id replayed against another backend can name a
    #: different record entirely.
    backend_id: int | None = None

    def as_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "type": self.type,
            "value": self.value, "ttl": self.ttl, "zone": self.zone,
            "view": self.view, "extra": self.extra,
            "backend_id": self.backend_id,
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

    #: STATIC MAXIMA — what this provider may EVER be asked to do, in any
    #: installation. They bound which roles a backend row may carry and are
    #: deliberately NOT the same thing as :meth:`capabilities`, which reports
    #: what THIS install will actually do right now and may need the network
    #: to find out (NetBox has to look for the netbox-dns plugin).
    #:
    #: The split is what lets a role be refused honestly. phpIPAM has no
    #: record CRUD in ANY install, so promising the DNS role there is a
    #: promise that can never be kept and is rejected at save time. NetBox
    #: MIGHT have the plugin, so the role is allowed and the live probe
    #: decides — refusing it up front would lock out a supported deployment,
    #: and accepting it blindly is the "reports success, publishes nothing"
    #: bug §130 was written about.
    may_write = False
    may_allocate = False

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

    # -- address allocation ----------------------------------------------
    def allocate_address(self, hostname: str = "", pool: str = "") -> Address:
        raise ProviderError(
            f"{self.label} does not expose address allocation.")

    def release_address(self, address: str, ref: str = "") -> None:
        raise ProviderError(
            f"{self.label} does not expose address release.")
