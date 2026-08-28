"""DNS Records / IPAM backends — registry, and the operations built on it.

Configuration lives in the ``dns_backends`` TABLE, one row per backend
(:class:`app.models_dnsbackend.DnsBackend`), each declaring optional
**roles** (IPAM, DNS or both) and an optional **scope** (which zones / which
pools it answers for). It replaced three global ``AppSetting`` keys —
``dnsrecords.provider`` / ``.config`` / ``.secret_enc`` — which are folded
into a row once, by :func:`store.migrate_singleton`, and then ignored.

**Why the singleton had to go.** ``Capabilities`` has separated
``can_allocate`` from ``can_write`` since phpIPAM was added, because phpIPAM
hands out addresses and cannot write a record. With one provider that
distinction could not be acted on: if the one provider could not write,
nothing could. Real installs put pools in one system and zones in another.

Two rules everything below is built on, both inherited and both load-bearing:

1. **"Not configured" is raised, never returned as success** (§130). Whether a
   missing backend is fatal is the CALLER's judgement — a run that never asked
   for a hostname does not care — and a caller cannot make that judgement on a
   value that looks identical to a real write.
2. **Which backend answers is decided in ONE place** (:mod:`.resolver`), and a
   tie is refused rather than broken by row order. Three disagreeing resolvers
   of a segment name is what built a policy on the wrong network on
   2026-08-27; the same shape here publishes into the wrong customer's zone.

A third rule is new here, and it is the one multi-backend actually forces:

3. **Undo goes back to the backend that did it.** ``allocate_address`` and
   ``create_record`` return the id of the backend that answered, callers
   RECORD it, and ``release_address``/``delete_record`` honour the recorded id
   over any re-resolution. Re-resolving at rollback time is not equivalent:
   the scope may have been edited since, and freeing an address on the wrong
   backend either does nothing or frees somebody else's entry.
"""
from __future__ import annotations

from .base import (Address, Capabilities, DnsProvider, DnsRecord,
                   ProviderError, mask_from_prefix, prefix_from_size)
from .none import NoneProvider
from .efficientip import EfficientIPProvider
from .phpipam import PhpIpamProvider
from .netbox import NetBoxProvider
from .resolver import (AMBIGUOUS, DISABLED, NO_BACKEND, NO_MATCH,
                       OUT_OF_SCOPE, UNKNOWN, WRONG_ROLE, Resolution,
                       backend_by_id, choose, claims, enabled_backends,
                       pool_matches, resolve_dns, resolve_ipam,
                       zone_specificity)

PROVIDERS: dict[str, type[DnsProvider]] = {
    "none": NoneProvider,
    "efficientip": EfficientIPProvider,
    "phpipam": PhpIpamProvider,
    "netbox": NetBoxProvider,
}

#: Providers an operator may actually add a backend for ("none" was the way
#: the singleton said "off"; with rows, "off" is having no row).
SELECTABLE = ("efficientip", "phpipam", "netbox")

# Per-provider non-secret field specs (key, label, placeholder) — drives the
# Settings form generically. The secret is handled separately, and the ROLES
# and SCOPE are per-row, not per-provider, so they are not in here.
FIELD_SPECS: dict[str, list[dict]] = {
    "efficientip": [
        {"key": "base_url", "label": "Base URL", "ph": "https://solidserver.example.com"},
        {"key": "username", "label": "Username", "ph": "ipmadmin"},
        {"key": "dns_server", "label": "DNS server (smart/appliance name)", "ph": "dns.smart"},
        {"key": "default_view", "label": "Default DNS view (optional)", "ph": "external"},
        {"key": "default_zone", "label": "Default zone (used when a caller names none)",
         "ph": "example.com"},
        {"key": "default_pool", "label": "Default IPAM pool (subnet id or name)",
         "ph": "198.51.100.0/24"},
    ],
    "phpipam": [
        {"key": "base_url", "label": "Base URL", "ph": "https://phpipam.example.com"},
        {"key": "app_id", "label": "API app id", "ph": "fortinet"},
        {"key": "default_pool", "label": "Default IPAM pool (subnet id or CIDR)",
         "ph": "198.51.100.0/24"},
    ],
    "netbox": [
        {"key": "base_url", "label": "Base URL", "ph": "https://netbox.example.com"},
        {"key": "default_zone", "label": "Default zone (used when a caller names none)",
         "ph": "example.com"},
        {"key": "default_pool", "label": "Default IPAM pool (prefix id or CIDR)",
         "ph": "198.51.100.0/24"},
    ],
}
SECRET_LABELS = {
    "efficientip": "Password", "phpipam": "API app token", "netbox": "API token",
}


# ---------------------------------------------------------------- factory

def provider_for_test(key: str, fields: dict, secret: str | None) -> DnsProvider:
    """Build a provider from UNSAVED form values for the Test button."""
    cfg = {"verify_ssl": bool(fields.get("verify_ssl", True))}
    for spec in FIELD_SPECS.get(key, []):
        cfg[spec["key"]] = str(fields.get(spec["key"]) or "").strip()
    cfg["secret"] = secret or ""
    return PROVIDERS.get(key, NoneProvider)(cfg)


def _require(res: Resolution, what: str) -> object:
    """The resolved backend, or a ProviderError that says which of the three
    things went wrong. Never returns a value that looks like success."""
    if res.ok:
        return res.backend
    raise ProviderError(f"No backend could be chosen for {what}: {res.detail}")


# ------------------------------------------------- capability questions
#
# ONE question became TWO, and that is the point rather than a cost. The old
# ``capabilities()`` answered "what can the provider do", which under a
# singleton was the same as "what will happen when I allocate" and "what will
# happen when I publish". With roles and scopes those are different questions
# with different answers, and a single function would have had to pick one to
# be wrong about.

def capabilities_of(row) -> Capabilities | None:
    """What one CHOSEN backend can do right now, or None when it did not say.

    The single author of "ask the box". Callers that already resolved use this
    instead of the two functions below, so the choice is made once: resolving
    twice in one step is how the capability answer and the thing it describes
    come from different rows.
    """
    try:
        return row.instance().capabilities()
    except Exception:  # noqa: BLE001 — probing is best-effort
        return None


def ipam_capabilities(pool: str = "") -> Capabilities | None:
    """What the backend that would serve this pool can do, or None.

    Never raises: an unreachable backend still has a row, and the caller needs
    the shape of the answer even when the box is off. ``None`` means no
    backend was chosen — use :func:`resolve_ipam` when the REASON matters.
    """
    res = resolve_ipam(pool)
    return capabilities_of(res.backend) if res.ok else None


def dns_capabilities(zone: str = "") -> Capabilities | None:
    """Same, for the backend that would publish into this zone/name."""
    res = resolve_dns(zone)
    return capabilities_of(res.backend) if res.ok else None


# ------------------------------------------------- module-level operations

def allocate_address(hostname: str = "", pool: str = "",
                     backend_id: object = None) -> Address:
    """Take the next free address out of ``pool``.

    ``backend_id`` is the operator's explicit choice and is validated, not
    trusted — see :func:`resolver.choose`. Empty means AUTO.

    The returned :class:`Address` carries ``backend_id`` — the caller must
    persist it, because it is the only handle that makes the release correct.
    """
    row = _require(choose("ipam", pool, backend_id),
                   f"an address out of pool {pool or '(default)'!r}")
    addr = row.instance().allocate_address(hostname=hostname, pool=pool)
    addr.backend_id = row.id
    return addr


def release_address(address: str, ref: str = "", backend_id: object = None,
                    pool: str = "") -> None:
    """Hand an address back to the backend that gave it out.

    ``backend_id`` is the RECORDED fact and wins over re-resolution. When the
    recorded backend is gone the release is REFUSED rather than redirected:
    handing an address to a different pool manager does not free it, and may
    delete a row that manager legitimately owns.
    """
    if backend_id not in (None, "", 0):
        row = backend_by_id(backend_id)
        if row is None:
            raise ProviderError(
                f"the backend that reserved {address} (id {backend_id}) no "
                "longer exists, so the reservation cannot be released from "
                "here — release it in that system by hand")
    else:
        row = _require(resolve_ipam(pool), f"releasing {address}")
    row.instance().release_address(address, ref=ref)


def create_record(name: str, rtype: str = "A", value: str = "",
                  zone: str = "", view: str = "",
                  ttl: int | None = None,
                  backend_id: object = None) -> DnsRecord:
    """Publish one resource record. Routed on the zone, or on the FQDN itself.

    ``backend_id`` is the operator's explicit choice, validated by
    :func:`resolver.choose`. Empty means AUTO (route on the scope).

    Routing on the name when no zone is given is what makes scopes usable:
    ``www.example.com`` finds the backend that declared ``example.com``
    without the caller having to know how the zone was cut.
    """
    row = _require(choose("dns", zone or name, backend_id),
                   f"the record {name!r}")
    rec = row.instance().create_record(DnsRecord(
        name=(name or "").rstrip("."), type=(rtype or "A").upper(),
        value=value, zone=zone, view=view, ttl=ttl))
    rec.backend_id = row.id
    return rec


def delete_record(record_id: str, name: str = "", rtype: str = "A",
                  zone: str = "", view: str = "",
                  backend_id: object = None) -> None:
    """Remove one resource record by its provider-native id.

    ``backend_id`` is the recorded fact and wins, for the same reason as
    :func:`release_address`: an id is only meaningful to the backend that
    issued it, and replaying it against another one can name a different
    record entirely.
    """
    if backend_id not in (None, "", 0):
        row = backend_by_id(backend_id)
        if row is None:
            raise ProviderError(
                f"the backend that published {name or record_id} (id "
                f"{backend_id}) no longer exists, so the record cannot be "
                "removed from here — remove it in that system by hand")
    else:
        row = _require(resolve_dns(zone or name), f"the record {name!r}")
    row.instance().delete_record(DnsRecord(
        id=str(record_id or ""), name=(name or "").rstrip("."),
        type=(rtype or "A").upper(), zone=zone, view=view))


__all__ = [
    "Address", "Capabilities", "DnsProvider", "DnsRecord", "ProviderError",
    "PROVIDERS", "SELECTABLE", "FIELD_SPECS", "SECRET_LABELS",
    "Resolution", "AMBIGUOUS", "NO_BACKEND", "NO_MATCH",
    "UNKNOWN", "DISABLED", "WRONG_ROLE", "OUT_OF_SCOPE",
    "resolve_dns", "resolve_ipam", "backend_by_id", "enabled_backends",
    "zone_specificity", "choose", "claims", "pool_matches",
    "provider_for_test", "capabilities_of",
    "ipam_capabilities", "dns_capabilities",
    "allocate_address", "release_address", "create_record", "delete_record",
    "mask_from_prefix", "prefix_from_size",
]
