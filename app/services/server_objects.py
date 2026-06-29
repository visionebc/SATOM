"""Server Objects menu catalog — the FortiWeb 7.6/8.0 GUI **Server Objects** menu,
mirrored as an ordered tree the dedicated Server Objects page renders.

FortiWeb's GUI groups these under *Server Objects* with a nested **Server**
sub-menu (Virtual Server, Server Pool, Health Check, Persistence, HTTP Content
Routing, Virtual IP), plus Protected Hostnames, Service, a **Certificates**
group, SSL Ciphers, Global objects, X-Forwarded-For and IP Group — exactly the
elements + sub-elements the operator expects, several levels deep (an object →
its by-parent sub-tables → deeper rows are edited inside the generic recursive
``objedit`` editor).

Unlike the desktop port, the web's ``categories``/``config_catalog`` only routes a
handful of endpoints to "Server Objects" (a partial categorisation), so this
module does NOT derive the SET from ``config_catalog`` — it is an EXPLICIT,
GUI-faithful menu keyed to the web registry's logical names. Each entry is
resolved against the live ``registry.loader`` (skipped when this firmware doesn't
ship the object), so the menu degrades gracefully across firmwares without
drifting: the URN comes from the registry, only the grouping + labels are curated
here. ``has_children`` is derived from the registry too (``objform.subtables_for``).

Pure data + matching: no Flask, no device. The view fetches the live objects.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# --------------------------------------------------------------------------- #
#  Menu value-objects                                                          #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ServerObjectType:
    """One leaf of the Server Objects menu (a configurable object type)."""

    logical: str             # registry logical endpoint name (e.g. "server_pool")
    label: str               # GUI label ("Server Pool")
    urn: str                 # resolved REST urn from the registry
    collection: str          # bare cmdb collection (server-policy/server-pool)
    read_only: bool = False  # predefined / system-provided (inspect-only)
    has_children: bool = False  # owns by-parent sub-tables (members, rules…)
    icon: str = "bi-box"     # bootstrap-icon for the menu leaf


@dataclass(frozen=True)
class ServerObjectGroup:
    """A Server Objects sub-menu (e.g. "Server", "Certificates")."""

    label: str
    icon: str
    items: tuple[ServerObjectType, ...] = field(default_factory=tuple)


# --------------------------------------------------------------------------- #
#  GUI grouping (mirrors the FortiWeb Server Objects menu in the screenshot)   #
# --------------------------------------------------------------------------- #
# Each group: (group label, group icon, [(logical, label, read_only, icon), …]).
# The logical names are the WEB registry's (dumped live from the loader). A
# logical absent from a firmware's registry is silently dropped at build time.
_MENU: tuple[tuple[str, str, tuple[tuple[str, str, bool, str], ...]], ...] = (
    ("Server", "bi-hdd-stack", (
        ("vserver", "Virtual Server", False, "bi-hdd-network"),
        ("server_pool", "Server Pool", False, "bi-diagram-3"),
        ("server_pool_health_check", "Health Check", False, "bi-heart-pulse"),
        ("server_pool_persistence", "Persistence", False, "bi-pin-angle"),
        ("http_content_routing", "HTTP Content Routing", False, "bi-signpost-split"),
        ("vip", "Virtual IP", False, "bi-geo"),
    )),
    ("Protected Hostnames", "bi-shield-lock", (
        ("allow_host", "Protected Hostnames", False, "bi-shield-check"),
    )),
    ("Service", "bi-hdd-rack", (
        ("services_custom", "Custom Service", False, "bi-sliders"),
        ("services_predefined", "Predefined Service", True, "bi-list-check"),
    )),
    ("Certificates", "bi-patch-check", (
        ("certificate", "Local Certificate", False, "bi-file-earmark-lock"),
        ("certificate_intermediate", "Intermediate CA", False, "bi-file-earmark-lock2"),
        ("certificate_intermediate_group", "Intermediate CA Group", False, "bi-files"),
        ("certificate_ca", "CA Certificate", False, "bi-patch-check"),
        ("certificate_ca_group", "CA Group", False, "bi-collection"),
        ("certificate_sni", "SNI Certificate", False, "bi-tags"),
        ("certificate_letsencrypt", "Let's Encrypt", False, "bi-cloud-check"),
        ("certificate_ocsp_stapling", "OCSP Stapling", False, "bi-stickies"),
        ("certificate_crl", "CRL", False, "bi-x-circle"),
        ("certificate_tsl_ca", "TSL CA", False, "bi-patch-check-fill"),
    )),
    ("SSL Ciphers", "bi-key", (
        ("ssl_cyphers_custom", "Custom Cipher", False, "bi-sliders2"),
        ("ssl_cyphers", "Predefined Cipher", True, "bi-list-check"),
    )),
    ("Global", "bi-globe2", (
        ("data_type_custom", "Custom Data Type", False, "bi-braces"),
    )),
    ("X-Forwarded-For", "bi-arrow-left-right", (
        ("x_forwarded_for", "X-Forwarded-For", False, "bi-arrow-left-right"),
    )),
    ("IP Group", "bi-collection", (
        ("ip_group", "IP Group", False, "bi-collection"),
    )),
)


# --------------------------------------------------------------------------- #
#  Registry resolution                                                         #
# --------------------------------------------------------------------------- #
def _endpoint_index() -> dict[str, dict]:
    """``logical name -> endpoint dict`` from the live registry loader."""
    from ..registry import loader

    out: dict[str, dict] = {}
    for ep in loader.get_all_endpoints():
        name = ep.get("name")
        if name and name not in out:
            out[name] = ep
    return out


def _collection_of(urn: str) -> str:
    from .objform import collection_of

    return collection_of(urn or "")


def _has_children(urn: str) -> bool:
    from .objform import subtables_for

    try:
        return bool(subtables_for(urn))
    except Exception:  # noqa: BLE001 — registry hiccup → no sub-tables
        return False


# --------------------------------------------------------------------------- #
#  Menu construction                                                           #
# --------------------------------------------------------------------------- #
def server_objects_menu() -> list[ServerObjectGroup]:
    """The ordered Server Objects menu (groups → object types) for this registry.

    Only types whose logical name resolves in the current registry are kept, so
    the menu reflects what the firmware actually ships.
    """
    eps = _endpoint_index()
    groups: list[ServerObjectGroup] = []
    for glabel, gicon, items in _MENU:
        leaves: list[ServerObjectType] = []
        for logical, label, read_only, icon in items:
            ep = eps.get(logical)
            if ep is None:
                continue  # not in this firmware's registry → drop
            urn = ep.get("urn") or ep.get("path") or ""
            leaves.append(ServerObjectType(
                logical=logical,
                label=label,
                urn=urn,
                collection=_collection_of(urn),
                read_only=read_only,
                has_children=_has_children(urn),
                icon=icon,
            ))
        if leaves:
            groups.append(ServerObjectGroup(glabel, gicon, tuple(leaves)))
    return groups


def type_for(logical: str) -> ServerObjectType | None:
    """Look up a single menu leaf by its logical name (``None`` if not in menu)."""
    for group in server_objects_menu():
        for item in group.items:
            if item.logical == logical:
                return item
    return None


def iter_types():
    """Flat iterator over every menu leaf (for coverage / tests)."""
    for group in server_objects_menu():
        for item in group.items:
            yield group.label, item


__all__ = [
    "ServerObjectType",
    "ServerObjectGroup",
    "server_objects_menu",
    "type_for",
    "iter_types",
]
