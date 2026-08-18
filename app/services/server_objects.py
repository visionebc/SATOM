"""Server Objects menu catalog — the FortiWeb GUI **Server Objects** menu,
mirrored as an ordered tree the dedicated Server Objects page renders.

THE MENU IS NOT CURATED FROM MEMORY. Its shape (entries, order, and the tabs
inside each entry) was extracted from the appliance's OWN Angular bundle
(``main.<hash>.js`` on FortiWeb 7.6.8) — the literal menu the box renders — and
corroborated entry by entry against the 7.6 admin guide's ``Server Objects > …``
GUI paths. Two independent oracles, no guessing:

* top level (9 entries): Server · Protected Hostnames · Service · Traffic Mirror ·
  Certificates · SSL Ciphers · Global · X-Forwarded-For · IP Group;
* **Certificates has TWELVE entries**, several of which are *pages with tabs*
  (Local → Local | Multi-certificate; CA → CA | TSL CA | CA Group; …);
* **Virtual IP is NOT here** — FortiWeb files it under *Network*
  (``/ng2/network/virtual-ip``), so it lives in the Network section menu
  (:mod:`app.services.config_sections`), not in Server Objects.

A GUI page and a REST collection are NOT the same unit: FortiWeb renders sibling
collections as TABS of one page (one sidebar entry). Modelling every tab as its
own sidebar entry — which this module used to do for CA Group / TSL CA /
Intermediate CA Group — inflates the menu while HIDING the tabs it never
modelled at all (Multi-certificate, Offline SNI, CRL Group, Server Certificate
Verify, the three XML Certificate tabs). Hence :class:`ServerObjectPage` (one
sidebar entry) owning one or more :class:`ServerObjectTab` (one REST collection
each). A single-tab page behaves exactly like the old flat leaf.

Each tab is resolved against the live ``registry.loader`` (dropped when this
firmware doesn't ship the object), so the menu degrades gracefully across
firmwares without drifting: the URN comes from the registry, only the grouping +
labels are curated here. ``has_children`` is derived from the registry too
(``objform.subtables_for``).

Tab ORDER is the declaration order of the routes in the same bundle
(``.../local-cert-menu/local-cert`` before ``.../multi-cert``, …) — [Probable],
the bundle does not spell the tab strip out separately; entries and labels are
[Seguro] (both oracles agree).

Pure data + matching: no Flask, no device. The view fetches the live objects.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# --------------------------------------------------------------------------- #
#  Menu value-objects                                                          #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ServerObjectTab:
    """One TAB of a Server Objects page == exactly one REST collection."""

    logical: str             # registry logical endpoint name (e.g. "server_pool")
    label: str               # GUI tab label ("Multi-certificate")
    urn: str                 # resolved REST urn from the registry
    collection: str          # bare cmdb collection (server-policy/server-pool)
    read_only: bool = False  # predefined / system-provided (inspect-only)
    has_children: bool = False  # owns by-parent sub-tables (members, rules…)
    icon: str = "bi-box"     # bootstrap-icon (defaults to the page's)


@dataclass(frozen=True)
class ServerObjectPage:
    """One ENTRY of the Server Objects menu (one sidebar row = one GUI page).

    The page mirrors its FIRST resolved tab (``logical``/``urn``/``collection``/
    ``read_only``/``has_children``) so every consumer that predates tabs — the
    sidebar, ``config_sections``, bookmarked ``?type=`` links — keeps working
    unchanged against a single-tab page.
    """

    logical: str
    label: str
    urn: str
    collection: str
    read_only: bool = False
    has_children: bool = False
    icon: str = "bi-box"
    tabs: tuple[ServerObjectTab, ...] = field(default_factory=tuple)

    @property
    def logicals(self) -> tuple[str, ...]:
        """Every logical this page owns — what "is this entry active?" must ask.

        Matching the sidebar on ``logical`` alone would light up nothing (and
        collapse the group) while the operator sits on a non-default tab.
        """
        return tuple(t.logical for t in self.tabs)

    @property
    def tabbed(self) -> bool:
        return len(self.tabs) > 1


@dataclass(frozen=True)
class ServerObjectGroup:
    """A Server Objects sub-menu (e.g. "Server", "Certificates").

    A group whose single page carries the same label is a FLAT entry in
    FortiWeb's own menu (Protected Hostnames, Service, Traffic Mirror, …) and
    renders as a direct link, not as a collapsible with one child.
    """

    label: str
    icon: str
    items: tuple[ServerObjectPage, ...] = field(default_factory=tuple)

    @property
    def flat(self) -> bool:
        return len(self.items) == 1 and self.items[0].label == self.label


#: Back-compat alias — this type was the flat leaf before pages/tabs existed.
ServerObjectType = ServerObjectPage


# --------------------------------------------------------------------------- #
#  GUI structure (extracted from the FortiWeb 7.6.8 bundle — see module docs)  #
# --------------------------------------------------------------------------- #
# (group label, group icon, pages) where
#   page = (page label, page icon, tabs) and
#   tab  = (logical, tab label, read_only[, icon])
# A single-tab page repeats the page label on its tab, so the object list header
# and the sidebar row always say the same thing.
_MENU: tuple[tuple[str, str, tuple[tuple[str, str, tuple[tuple, ...]], ...]], ...] = (
    ("Server", "bi-hdd-stack", (
        ("Virtual Server", "bi-hdd-network", (
            ("vserver", "Virtual Server", False),
        )),
        ("Server Pool", "bi-diagram-3", (
            ("server_pool", "Server Pool", False),
        )),
        ("Health Check", "bi-heart-pulse", (
            ("server_pool_health_check", "Health Check", False),
        )),
        ("Persistence", "bi-pin-angle", (
            ("server_pool_persistence", "Persistence", False),
        )),
        ("HTTP Content Routing", "bi-signpost-split", (
            ("http_content_routing", "HTTP Content Routing", False),
        )),
    )),
    ("Protected Hostnames", "bi-shield-lock", (
        ("Protected Hostnames", "bi-shield-check", (
            ("allow_host", "Protected Hostnames", False),
        )),
    )),
    ("Service", "bi-hdd-rack", (
        ("Service", "bi-hdd-rack", (
            ("services_predefined", "Predefined", True, "bi-list-check"),
            ("services_custom", "Custom", False, "bi-sliders"),
        )),
    )),
    ("Traffic Mirror", "bi-arrow-repeat", (
        ("Traffic Mirror", "bi-arrow-repeat", (
            ("traffic_mirror_profile", "Traffic Mirror", False),
        )),
    )),
    ("Certificates", "bi-patch-check", (
        ("Local", "bi-file-earmark-lock", (
            ("certificate", "Local", False),
            ("system_certificate_multi_local", "Multi-certificate", False, "bi-files"),
        )),
        ("Let's Encrypt", "bi-cloud-check", (
            ("certificate_letsencrypt", "Let's Encrypt", False),
        )),
        ("XML Certificate", "bi-filetype-xml", (
            ("xml_server_certificate", "Server Certificate", False),
            ("xml_client_certificate", "Client Certificate", False),
            ("xml_client_certificate_group", "Client Certificate Group", False, "bi-collection"),
        )),
        ("URL Certificate", "bi-link-45deg", (
            ("system_certificate_urlcert", "URL Certificate", False),
        )),
        ("SNI", "bi-tags", (
            ("certificate_sni", "Inline SNI", False),
            ("system_certificate_offline_sni", "Offline SNI", False, "bi-tag"),
        )),
        ("CA", "bi-patch-check", (
            ("certificate_ca", "CA", False),
            ("certificate_tsl_ca", "TSL CA", False, "bi-patch-check-fill"),
            ("certificate_ca_group", "CA Group", False, "bi-collection"),
        )),
        ("Sign CA", "bi-pen", (
            ("system_certificate_sign_ca", "Sign CA", False),
        )),
        ("Intermediate CA", "bi-file-earmark-lock2", (
            # certificate.intermediate-certificate — the collection that EXISTS.
            # certificate.intermediate (what this entry used to point at) is a
            # registry phantom: HTTP 500 / errcode -20001 on every FortiWeb
            # measured (fw09, fw11), and the api_matrix already says
            # verdict "absent" for it.
            ("system_certificate_intermediate_certificate", "Intermediate CA", False),
            ("certificate_intermediate_group", "Intermediate CA Group", False, "bi-files"),
        )),
        ("CRL", "bi-x-circle", (
            ("certificate_crl", "CRL", False),
            ("system_certificate_crl_group", "CRL Group", False, "bi-collection"),
        )),
        ("Certificate Verify", "bi-check2-square", (
            ("system_certificate_verify", "Certificate Verify", False),
            ("system_certificate_server_certificate_verify",
             "Server Certificate Verify", False, "bi-hdd-network"),
        )),
        ("OCSP", "bi-stickies", (
            ("certificate_ocsp_stapling", "OCSP", False),
        )),
        ("Public Key Pinning", "bi-pin-map", (
            ("system_certificate_hpkp", "Public Key Pinning", False),
        )),
    )),
    ("SSL Ciphers", "bi-key", (
        ("SSL Ciphers", "bi-key", (
            ("ssl_cyphers", "Predefined", True, "bi-list-check"),
            ("ssl_cyphers_custom", "Custom", False, "bi-sliders2"),
        )),
    )),
    ("Global", "bi-globe2", (
        ("Global Allow List", "bi-check2-circle", (
            ("global_allow_list_predefined", "Predefined", True, "bi-list-check"),
            ("global_allow_list_custom", "Custom", False, "bi-sliders"),
        )),
        ("Policy Based Allow List", "bi-list-check", (
            ("allow_list", "Policy Based Allow List", False),
        )),
        ("Data Type", "bi-braces", (
            ("data_type_custom", "Data Type", False),
        )),
        ("URL Replacer", "bi-shuffle", (
            ("url_replacer_rule", "Replacer Rule", False),
            ("url_replacer_policy", "Replacer Policy", False, "bi-file-earmark-text"),
        )),
    )),
    ("X-Forwarded-For", "bi-arrow-left-right", (
        ("X-Forwarded-For", "bi-arrow-left-right", (
            ("x_forwarded_for", "X-Forwarded-For", False),
        )),
    )),
    ("IP Group", "bi-collection", (
        ("IP Group", "bi-collection", (
            ("ip_group", "IP Group", False),
        )),
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
    """The ordered Server Objects menu (groups → pages → tabs) for this registry.

    Only tabs whose logical name resolves in the current registry are kept; a
    page with no surviving tab is dropped, and so is a group with no surviving
    page — so the menu reflects what the firmware actually ships.
    """
    eps = _endpoint_index()
    groups: list[ServerObjectGroup] = []
    for glabel, gicon, pages in _MENU:
        built: list[ServerObjectPage] = []
        for plabel, picon, tabspec in pages:
            tabs: list[ServerObjectTab] = []
            for spec in tabspec:
                logical, tlabel, read_only = spec[0], spec[1], spec[2]
                ticon = spec[3] if len(spec) > 3 else picon
                ep = eps.get(logical)
                if ep is None:
                    continue  # not in this firmware's registry → drop the tab
                urn = ep.get("urn") or ep.get("path") or ""
                tabs.append(ServerObjectTab(
                    logical=logical,
                    label=tlabel,
                    urn=urn,
                    collection=_collection_of(urn),
                    read_only=read_only,
                    has_children=_has_children(urn),
                    icon=ticon,
                ))
            if not tabs:
                continue
            head = tabs[0]
            built.append(ServerObjectPage(
                logical=head.logical,
                label=plabel,
                urn=head.urn,
                collection=head.collection,
                read_only=head.read_only,
                has_children=head.has_children,
                icon=picon,
                tabs=tuple(tabs),
            ))
        if built:
            groups.append(ServerObjectGroup(glabel, gicon, tuple(built)))
    return groups


def find(logical: str) -> tuple[ServerObjectPage, ServerObjectTab] | None:
    """``(page, tab)`` for a logical name — matches ANY tab, not just defaults."""
    for group in server_objects_menu():
        for page in group.items:
            for tab in page.tabs:
                if tab.logical == logical:
                    return page, tab
    return None


def type_for(logical: str) -> ServerObjectPage | None:
    """The menu PAGE that owns ``logical`` (``None`` if not in the menu)."""
    hit = find(logical)
    return hit[0] if hit else None


def tab_for(logical: str) -> ServerObjectTab | None:
    """The menu TAB for ``logical`` (``None`` if not in the menu)."""
    hit = find(logical)
    return hit[1] if hit else None


def iter_types():
    """Flat iterator over every menu PAGE (``group label, page``)."""
    for group in server_objects_menu():
        for page in group.items:
            yield group.label, page


def iter_tabs():
    """Flat iterator over every menu TAB (``group label, page, tab``).

    This — not :func:`iter_types` — is the coverage unit: one tab == one REST
    collection the operator can browse.
    """
    for group in server_objects_menu():
        for page in group.items:
            for tab in page.tabs:
                yield group.label, page, tab


__all__ = [
    "ServerObjectTab",
    "ServerObjectPage",
    "ServerObjectType",
    "ServerObjectGroup",
    "server_objects_menu",
    "find",
    "type_for",
    "tab_for",
    "iter_types",
    "iter_tabs",
]
