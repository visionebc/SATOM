"""FortiWeb configuration sections — GUI-faithful live-browse menus.

Generalises the **Server Objects** pattern (:mod:`app.services.server_objects`) to
EVERY FortiWeb config GUI section (API Protection, Bot Mitigation, DoS Protection,
IP Protection, Machine Learning, Tracking, …). Each section gets an explicit,
GUI-faithful menu (groups → object types) keyed to the WEB registry's logical
names — deliberately NOT derived from ``categories``/``config_catalog``, whose
partial web port mis-routes many objects (e.g. the API-Gateway / OpenAPI / gRPC /
Mobile objects are absent from the ``api_protection`` category even though the
endpoints exist in the registry). Every leaf is resolved against the live
``registry.loader`` so a type a firmware doesn't ship silently drops; the URN and
``has_children`` come from the registry too, so only the grouping + labels are
curated here (no drift).

Pure data + registry matching — no Flask, no device. The ``section_config`` view
fetches the live objects and links each leaf into the generic recursive
``objedit`` editor, so an object's by-parent sub-tables (rules, members, match
conditions, schema files…) are edited in place several levels deep.

A section WITHOUT a curated menu here returns ``[]`` from :func:`section_menu`, and
the page falls back to the static object-type catalog — so menus can be filled in
section by section with no regression for the others.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# --------------------------------------------------------------------------- #
#  Menu value-objects (mirror server_objects.ServerObjectType/Group)            #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ConfigObjectType:
    """One leaf of a section menu (a configurable object type)."""

    logical: str             # registry logical endpoint name (e.g. "api_policy")
    label: str               # GUI label ("API Gateway Policy")
    urn: str                 # resolved REST urn from the registry
    collection: str          # bare cmdb collection (waf/api-policy)
    read_only: bool = False  # predefined / system-provided (inspect-only)
    has_children: bool = False  # owns by-parent sub-tables (rules, members…)
    icon: str = "bi-box"     # bootstrap-icon for the menu leaf


@dataclass(frozen=True)
class ConfigGroup:
    """A section sub-menu (e.g. "API Gateway", "XML Protection")."""

    label: str
    icon: str
    items: tuple[ConfigObjectType, ...] = field(default_factory=tuple)


# --------------------------------------------------------------------------- #
#  GUI grouping per section (mirrors the FortiWeb 7.6/8.0 left menu).           #
#  section_key -> ( (group label, group icon,                                   #
#                    ( (logical, label, read_only, icon), … )), … )             #
#  Logical names are the WEB registry's (dumped live from the loader). A        #
#  logical absent from a firmware's registry is silently dropped at build time. #
#  Only TOP-LEVEL objects are menu leaves; their by-parent sub-tables are        #
#  reached by drilling into the objedit editor.                                 #
# --------------------------------------------------------------------------- #
_SECTION_MENUS: dict[str, tuple[tuple[str, str, tuple[tuple[str, str, bool, str], ...]], ...]] = {
    # ------------------------------------------------------------------ #
    #  API Protection (pilot) — 6 features, the API Gateway chain nests   #
    #  to 6 levels (policy → rule → user-group → user → ip/referer list). #
    # ------------------------------------------------------------------ #
    "api_protection": (
        ("API Gateway", "bi-door-open", (
            ("api_policy", "API Gateway Policy", False, "bi-hdd-network"),
            ("api_policy_rule", "API Gateway Rule", False, "bi-list-task"),
            ("api_user_group", "API User Group", False, "bi-people"),
            ("api_user", "API User", False, "bi-person-badge"),
        )),
        ("OpenAPI Validation", "bi-file-earmark-code", (
            ("openapi_policy", "OpenAPI Validation Policy", False, "bi-file-earmark-check"),
            ("openapi_file", "OpenAPI Schema File", False, "bi-file-earmark-arrow-up"),
        )),
        ("XML Protection", "bi-filetype-xml", (
            ("xml_protection_policy", "XML Protection Policy", False, "bi-filetype-xml"),
            ("xml_protection_rule", "XML Validation Rule", False, "bi-list-check"),
        )),
        ("JSON Protection", "bi-filetype-json", (
            ("json_protection_policy", "JSON Protection Policy", False, "bi-filetype-json"),
            ("json_protection_rule", "JSON Validation Rule", False, "bi-list-check"),
        )),
        ("Mobile API Protection", "bi-phone", (
            ("mobile_api_protection_policy", "Mobile API Protection Policy", False, "bi-phone"),
            ("mobile_api_protection_rule", "Mobile API Protection Rule", False, "bi-list-check"),
        )),
        ("gRPC Protection", "bi-diagram-2", (
            ("grpc_security_policy", "gRPC Security Policy", False, "bi-diagram-2"),
            ("grpc_security_rule", "gRPC Security Rule", False, "bi-list-check"),
            ("grpc_idl_file", "gRPC IDL File", False, "bi-file-earmark-arrow-up"),
        )),
    ),

    # ------------------------------------------------------------------ #
    #  System — the FortiWeb System menu (settings, admins, HA, SNMP,     #
    #  FortiGuard, automation, 8.0 firewall, integration, hardware).      #
    #  Certificates live on the Server Objects page, so they're not here. #
    # ------------------------------------------------------------------ #
    "system": (
        ("Settings", "bi-sliders", (
            ("global", "Global / Hostname", False, "bi-hdd"),
            ("system_settings", "System Settings", False, "bi-gear"),
            ("feature_visibility", "Feature Visibility", False, "bi-eye"),
            ("advanced", "Advanced", False, "bi-gear-wide-connected"),
            ("system_console", "Console", False, "bi-terminal"),
            ("system_decoding_enhancement", "Decoding Enhancement", False, "bi-code-slash"),
            ("system_encryption_method", "Encryption Method", False, "bi-shield-lock"),
        )),
        ("Time & Maintenance", "bi-clock-history", (
            ("ntp", "Time / NTP", False, "bi-clock"),
            ("backup", "Config Backup", False, "bi-download"),
            ("system_object_tagging", "Object Tagging", False, "bi-tags"),
            ("system_external_resource", "External Resource", False, "bi-link-45deg"),
        )),
        ("Administrators", "bi-person-gear", (
            ("system_admin", "Administrators", False, "bi-person-badge"),
            ("accprofile", "Admin Profile", False, "bi-person-vcard"),
            ("system_password_policy", "Password Policy", False, "bi-key"),
            ("system_sso_admin", "SSO Admin", False, "bi-box-arrow-in-right"),
            ("system_saml", "SAML", False, "bi-shield-check"),
            ("system_recaptcha_api", "reCAPTCHA API", False, "bi-robot"),
        )),
        ("High Availability", "bi-diagram-3", (
            ("system_ha", "High Availability", False, "bi-diagram-3"),
            ("system_ha_node", "HA Node", False, "bi-hdd-stack"),
        )),
        ("SNMP", "bi-broadcast", (
            ("system_snmp_sysinfo", "SNMP Sysinfo", False, "bi-info-circle"),
            ("system_snmp_community", "SNMP Community", False, "bi-people"),
            ("snmp_user", "SNMP v3 User", False, "bi-person"),
        )),
        ("FortiGuard & Updates", "bi-shield-shaded", (
            ("system_fortiguard", "FortiGuard", False, "bi-shield-shaded"),
            ("system_autoupdate_schedule", "Update Schedule", False, "bi-calendar-check"),
            ("system_autoupdate_override", "Update Override", False, "bi-sliders2"),
            ("system_autoupdate_tunneling", "Update Tunneling", False, "bi-hdd-network"),
            ("antivirus", "Antivirus", False, "bi-bug"),
        )),
        ("Replacement Messages", "bi-chat-left-text", (
            ("replacemsg", "Replacement Message", False, "bi-chat-left-text"),
            ("replacemsg_admin", "Admin Replacement Message", False, "bi-chat-left-dots"),
            ("replacemsg_image", "Replacement Image", False, "bi-image"),
        )),
        ("Automation", "bi-cpu", (
            ("system_automation_trigger", "Automation Trigger", False, "bi-lightning"),
            ("system_automation_stitch", "Automation Stitch", False, "bi-link"),
            ("system_automation_script", "Automation Script", False, "bi-file-code"),
            ("system_automation_email", "Automation Email", False, "bi-envelope"),
        )),
        ("Firewall", "bi-bricks", (
            ("system_firewall_address", "Firewall Address", False, "bi-geo"),
            ("system_firewall_service", "Firewall Service", False, "bi-hdd-network"),
            ("system_firewall_firewall_policy", "Firewall Policy", False, "bi-shield"),
            ("system_firewall_snat_policy", "SNAT Policy", False, "bi-arrow-left-right"),
            ("system_firewall_dnat_policy", "DNAT Policy", False, "bi-arrow-repeat"),
            ("system_firewall_admin_policy", "Admin Access Policy", False, "bi-person-lock"),
            ("system_firewall_fwmark_policy", "FW Mark Policy", False, "bi-bookmark"),
        )),
        ("Integration", "bi-plug", (
            ("system_fortisandbox", "FortiSandbox", False, "bi-box"),
            ("system_fortigate_integration", "FortiGate Integration", False, "bi-hdd-network"),
            ("system_central_management", "Central Management", False, "bi-diagram-2"),
            ("system_sdn_connector", "SDN Connector", False, "bi-diagram-3"),
            ("system_csf", "Security Fabric", False, "bi-shield-shaded"),
            ("system_icapserver", "ICAP Server", False, "bi-hdd-network"),
            ("system_eventhub", "Event Hub", False, "bi-broadcast-pin"),
            ("system_endpoint_control_fctems", "FortiClient EMS", False, "bi-pc-display"),
            ("system_manager", "Manager", False, "bi-display"),
            ("system_conf_sync", "Config Sync", False, "bi-arrow-repeat"),
        )),
        ("Advanced & Hardware", "bi-cpu-fill", (
            ("system_raid", "RAID", False, "bi-hdd-stack"),
            ("system_fips_cc", "FIPS-CC", False, "bi-shield-lock"),
            ("system_nethsm", "Network HSM", False, "bi-safe"),
            ("system_hsm_partition", "HSM Partition", False, "bi-safe2"),
            ("system_cpumem_monitor", "CPU / Memory Monitor", False, "bi-speedometer"),
            ("system_captcha", "CAPTCHA", False, "bi-puzzle"),
            ("system_captcha_puzzle", "CAPTCHA Puzzle", False, "bi-puzzle-fill"),
        )),
    ),

    # ------------------------------------------------------------------ #
    #  Network — interfaces, DNS, routing, V-zone, network settings.      #
    #  (Section-level DANGER banner is set in config_catalog.)            #
    # ------------------------------------------------------------------ #
    "network": (
        ("Interfaces", "bi-ethernet", (
            ("interface_2", "Interface", False, "bi-ethernet"),
            ("v_zone", "V-Zone", False, "bi-bounding-box"),
        )),
        ("DNS", "bi-globe", (
            ("dns", "DNS", False, "bi-globe"),
        )),
        ("Routing", "bi-signpost-split", (
            ("route", "Static Route", False, "bi-signpost"),
            ("route_policy", "Policy Route", False, "bi-signpost-2"),
            ("router_setting", "Routing Settings", False, "bi-gear"),
        )),
        ("Network Settings", "bi-hdd-network", (
            ("network_option", "Network Options", False, "bi-sliders"),
            ("system_ip_detection", "IP Detection", False, "bi-search"),
            ("system_fail_open", "Fail Open", False, "bi-door-open"),
            ("system_wccp", "WCCP", False, "bi-diagram-2"),
        )),
    ),

    # ------------------------------------------------------------------ #
    #  Application Delivery — caching, compression, rewriting, redirect,  #
    #  acceleration, load balancing.                                      #
    # ------------------------------------------------------------------ #
    "application_delivery": (
        ("Caching", "bi-hdd", (
            ("cache_policy", "Caching Policy", False, "bi-hdd"),
            ("web_cache_policy", "Web Cache Policy", False, "bi-hdd-fill"),
            ("waf_web_cache_rule", "Web Cache Rule", False, "bi-list-check"),
        )),
        ("Compression", "bi-file-zip", (
            ("compression_rule", "Compression Rule", False, "bi-file-zip"),
            ("compression_policy", "Compression Policy", False, "bi-file-earmark-zip"),
            ("compression_exclusion_url", "Compression Exclusion", False, "bi-x-circle"),
        )),
        ("URL Rewriting", "bi-pencil-square", (
            ("url_rewriting_policy", "URL Rewriting Policy", False, "bi-pencil-square"),
            ("url_rewriting_rule", "URL Rewriting Rule", False, "bi-list-check"),
            ("rewrite_policy", "Rewrite Policy", False, "bi-pencil"),
        )),
        ("Redirect", "bi-signpost-2", (
            ("redirect_policy", "Redirect Policy", False, "bi-signpost-2"),
        )),
        ("Acceleration", "bi-rocket", (
            ("acceleration_policy", "Web Acceleration Policy", False, "bi-rocket-takeoff"),
            ("acceleration_exception", "Acceleration Exception", False, "bi-x-circle"),
        )),
        ("Load Balancing", "bi-distribute-horizontal", (
            ("load_balance", "Load Balance", False, "bi-distribute-horizontal"),
            ("persistence_policy", "Persistence Policy", False, "bi-pin-angle"),
        )),
    ),

    # ------------------------------------------------------------------ #
    #  Bot Mitigation — policy, detection methods, allow/exceptions.      #
    # ------------------------------------------------------------------ #
    "bot_mitigation": (
        ("Bot Mitigation", "bi-robot", (
            ("bot_mitigation_policy", "Bot Mitigation Policy", False, "bi-robot"),
            ("bot_mitigation_policy_2", "Bot Mitigate Policy", False, "bi-robot"),
        )),
        ("Detection Methods", "bi-search", (
            ("bot_known_bots", "Known Bots", False, "bi-list-stars"),
            ("bot_deception", "Bot Deception", False, "bi-mask"),
            ("bot_biometric_based_detection", "Biometrics Based Detection", False, "bi-fingerprint"),
            ("bot_threshold_based_detection", "Threshold Based Detection", False, "bi-speedometer2"),
        )),
        ("Allow & Exceptions", "bi-check-circle", (
            ("bot_allow_list", "Known Good Bots", False, "bi-check2-circle"),
            ("bot_detection", "Bot Mitigation Exception", False, "bi-x-circle"),
        )),
        ("Advanced", "bi-shield-shaded", (
            ("advanced_bot_protection", "Advanced Bot Protection", False, "bi-shield-shaded"),
        )),
    ),

    # ------------------------------------------------------------------ #
    #  DoS Protection — the policy + its L7 and L4 prevention rules.      #
    # ------------------------------------------------------------------ #
    "dos_protection": (
        ("DoS Protection", "bi-shield-exclamation", (
            ("dos_policy", "DoS Protection Policy", False, "bi-shield-exclamation"),
        )),
        ("Application Layer (L7)", "bi-layers", (
            ("http_access_limit", "HTTP Access Limit", False, "bi-speedometer"),
            ("http_flood", "HTTP Flood Prevention", False, "bi-water"),
            ("ddos_http_flood_prevention", "HTTP Request Flood Rule", False, "bi-list-check"),
            ("ddos_malicious_ip", "HTTP Connection Flood Check", False, "bi-hdd-network"),
        )),
        ("Network Layer (L4)", "bi-diagram-3", (
            ("tcp_flood", "TCP Connection Flood Prevention", False, "bi-water"),
            ("ddos_http_access_limit", "Layer 4 Access Limit", False, "bi-speedometer2"),
            ("ddos_tcp_flood_prevention", "Layer 4 Connection Flood Check", False, "bi-diagram-3"),
        )),
    ),

    # ------------------------------------------------------------------ #
    #  IP Protection — IP list & reputation, Geo IP, trusted / brute.     #
    # ------------------------------------------------------------------ #
    "ip_protection": (
        ("IP List & Reputation", "bi-list-ol", (
            ("ip_list", "IP List", False, "bi-list-ol"),
            ("ip_intel", "IP Reputation", False, "bi-shield-shaded"),
            ("ip_intelligence_exception", "IP Reputation Exception", False, "bi-x-circle"),
            ("ip_intelligence_ignore_xff", "Ignore X-Forwarded-For", False, "bi-slash-circle"),
        )),
        ("Geo IP", "bi-globe-americas", (
            ("geo_block", "Geo IP Block List", False, "bi-globe-americas"),
            ("geo_ip_exception", "Geo IP Exception", False, "bi-x-circle"),
        )),
        ("Trusted IP & Brute Force", "bi-shield-check", (
            ("trusted_ip", "Trusted IP", False, "bi-shield-check"),
            ("brute_force", "Brute Force Login", False, "bi-fingerprint"),
        )),
    ),

    # ------------------------------------------------------------------ #
    #  Machine Learning — ML policy/anomaly/bot, API learning, replacer.  #
    # ------------------------------------------------------------------ #
    "machine_learning": (
        ("Machine Learning", "bi-cpu", (
            ("ml_policy", "Machine Learning Policy", False, "bi-cpu"),
            ("ml_anomaly_detection", "Anomaly Detection", False, "bi-graph-up-arrow"),
            ("bot_detection_policy", "Bot Detection", False, "bi-robot"),
        )),
        ("API Learning", "bi-mortarboard", (
            ("api_learning_policy", "API Learning Policy", False, "bi-mortarboard"),
            ("api_learning_rule", "API Learning Rule", False, "bi-list-check"),
        )),
        ("URL Replacer", "bi-arrow-left-right", (
            ("url_replacer_policy", "URL Replacer Policy", False, "bi-arrow-left-right"),
            ("url_replacer_rule", "URL Replacer Rule", False, "bi-list-check"),
        )),
    ),

    # ------------------------------------------------------------------ #
    #  Tracking — user / custom tracking, threat scoring, sessions.       #
    # ------------------------------------------------------------------ #
    "tracking": (
        ("User Tracking", "bi-person-lines-fill", (
            ("user_tracking_policy", "User Tracking Policy", False, "bi-person-lines-fill"),
            ("user_tracking_rule", "User Tracking Rule", False, "bi-list-check"),
            ("user_auth", "User Tracking", False, "bi-person-check"),
        )),
        ("Custom Tracking", "bi-binoculars", (
            ("waf_custom_tracking_policy", "Custom Tracking Policy", False, "bi-binoculars"),
        )),
        ("Threat Scoring", "bi-graph-up", (
            ("threat_score_profile", "Threat Score Profile", False, "bi-graph-up"),
            ("server_policy_pattern_threat_weight", "Threat Weight", False, "bi-sliders"),
        )),
        ("Session", "bi-window", (
            ("session_management", "Session Management", False, "bi-window"),
        )),
    ),

    # ------------------------------------------------------------------ #
    #  User & Authentication — remote auth servers, local/OAuth, groups.  #
    # ------------------------------------------------------------------ #
    "user_authentication": (
        ("Remote Auth Servers", "bi-hdd-network", (
            ("user_ldap", "LDAP User", False, "bi-diagram-2"),
            ("user_radius", "RADIUS User", False, "bi-hdd-network"),
            ("user_tacacs_user", "TACACS+ User", False, "bi-hdd-network"),
            ("user_kerberos_user", "Kerberos User", False, "bi-shield-lock"),
            ("user_saml_user", "SAML User", False, "bi-shield-check"),
            ("user_ntlm_user", "NTLM User", False, "bi-windows"),
            ("user_pki_user", "PKI User", False, "bi-key"),
        )),
        ("Local & OAuth", "bi-person", (
            ("user_local", "Local User", False, "bi-person"),
            ("user_oauth_user_server", "OAuth Server", False, "bi-hdd-network"),
            ("user_oauth_user_request", "OAuth Request", False, "bi-envelope"),
            ("user_recaptcha_user", "reCAPTCHA User", False, "bi-robot"),
        )),
        ("User Groups", "bi-people", (
            ("user_group", "User Group", False, "bi-people"),
            ("admin_user_group", "Admin User Group", False, "bi-person-gear"),
        )),
    ),

    # ------------------------------------------------------------------ #
    #  Log & Report — log settings, log policies, triggers, reports.      #
    # ------------------------------------------------------------------ #
    "log_report": (
        ("Log Settings", "bi-journal-text", (
            ("log_disk", "Disk Logging", False, "bi-hdd"),
            ("log_memory", "Memory Logging", False, "bi-memory"),
            ("log_syslog", "Syslog", False, "bi-hdd-network"),
            ("log_fortiguard", "FortiGuard Logging", False, "bi-shield-shaded"),
            ("fortianalyzer", "FortiAnalyzer", False, "bi-bar-chart"),
        )),
        ("Log Policies", "bi-card-checklist", (
            ("syslog_policy", "Syslog Policy", False, "bi-hdd-network"),
            ("fortianalyzer_policy", "FortiAnalyzer Policy", False, "bi-bar-chart-line"),
            ("log_email_policy", "Email Policy", False, "bi-envelope"),
            ("log_siem_policy", "SIEM Policy", False, "bi-diagram-3"),
            ("log_siem_message_policy", "SIEM Message Policy", False, "bi-chat-square-text"),
            ("log_ftp_policy", "FTP Policy", False, "bi-folder"),
        )),
        ("Triggers & Reports", "bi-bell", (
            ("trigger_policy", "Trigger Policy", False, "bi-bell"),
            ("log_reports", "Reports", False, "bi-file-earmark-bar-graph"),
        )),
        ("Sensitive Data", "bi-eye-slash", (
            ("sensitive", "Sensitive Data", False, "bi-eye-slash"),
            ("log_custom_sensitive_rule", "Custom Sensitive Rule", False, "bi-list-check"),
        )),
        ("Log Types", "bi-list-columns", (
            ("attack_log", "Attack Log", False, "bi-shield-exclamation"),
            ("event_log", "Event Log", False, "bi-card-list"),
            ("traffic_log", "Traffic Log", False, "bi-arrow-left-right"),
        )),
    ),
}


# --------------------------------------------------------------------------- #
#  Registry resolution (same approach as server_objects)                       #
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
def _server_objects_menu() -> list[ConfigGroup]:
    """The Server Objects section menu, reused VERBATIM from
    :mod:`app.services.server_objects` so the live Configuration → Server Objects
    browser and the dedicated Server Objects page share ONE menu (no drift)."""
    from . import server_objects as _so

    groups: list[ConfigGroup] = []
    for g in _so.server_objects_menu():
        items = tuple(
            ConfigObjectType(
                logical=it.logical, label=it.label, urn=it.urn,
                collection=it.collection, read_only=it.read_only,
                has_children=it.has_children, icon=it.icon,
            )
            for it in g.items
        )
        groups.append(ConfigGroup(g.label, g.icon, items))
    return groups


def _norm_coll(coll: str) -> str:
    """Normalised REST collection for dedupe (drop query + slashes + case)."""
    return (coll or "").split("?", 1)[0].strip("/").lower()


def _is_subrow(coll: str) -> bool:
    """A by-parent sub-table row has the shape ``<area>/<parent>/<sublist>``
    (>=2 path segments) — reached by drilling into its PARENT object's editor,
    never a top-level menu leaf (and path-style reads leak the parent collection)."""
    return _norm_coll(coll).count("/") >= 2


# Confirmed registry-phantom collections (an alias URN that returns 0 rows live
# while a sibling endpoint is the real one) -- never surfaced as a browse leaf.
# system/network.interface is a dead alias of the real system/interface (verified
# live on fw1: 0 vs 3 rows).
_PHANTOM_COLLECTIONS = frozenset({"system/network.interface"})


def _remaining_types(section_key: str, shown_colls: set[str]) -> list[ConfigObjectType]:
    """Every TOP-LEVEL cmdb object the registry files under this section that the
    curated menu doesn't already show — so the section browses EVERYTHING the
    FortiWeb has (empty types included), not just the hand-picked subset.

    Source is the complete, registry-derived ``config_catalog.section_catalog``.
    By-parent sub-rows and non-cmdb endpoints are excluded; results are deduped
    by REST collection so a logical-name alias of an already-shown object isn't
    listed twice. Pure registry — no Flask, no device."""
    from . import config_catalog

    try:
        catalog = config_catalog.section_catalog(section_key)
    except Exception:  # noqa: BLE001 - unknown/uncatalogued section -> nothing extra
        return []
    extra: list[ConfigObjectType] = []
    seen = set(shown_colls)
    for o in catalog:
        urn = o.get("urn") or o.get("path") or ""
        if "/cmdb/" not in urn:
            continue  # non-cmdb (live-status / maintenance) -> not browsable here
        coll = _collection_of(urn)
        if _norm_coll(coll) in _PHANTOM_COLLECTIONS:
            continue
        if _is_subrow(coll):
            continue
        key = _norm_coll(coll)
        if not key or key in seen:
            continue
        seen.add(key)
        extra.append(ConfigObjectType(
            logical=o["logical"],
            label=o.get("label") or o["logical"],
            urn=urn,
            collection=coll,
            read_only=bool(o.get("readonly")),
            has_children=_has_children(urn),
            icon="bi-box",
        ))
    extra.sort(key=lambda it: it.label.lower())
    return extra


def _curated_groups(section_key: str) -> list[ConfigGroup]:
    """The hand-curated, GUI-faithful groups for a section (may be empty). Only
    types whose logical name resolves in the current registry are kept."""
    if section_key == "server_objects":
        return _server_objects_menu()
    spec = _SECTION_MENUS.get(section_key)
    if not spec:
        return []
    eps = _endpoint_index()
    groups: list[ConfigGroup] = []
    for glabel, gicon, items in spec:
        leaves: list[ConfigObjectType] = []
        for logical, label, read_only, icon in items:
            ep = eps.get(logical)
            if ep is None:
                continue  # not in this firmware's registry -> drop
            urn = ep.get("urn") or ep.get("path") or ""
            leaves.append(ConfigObjectType(
                logical=logical,
                label=label,
                urn=urn,
                collection=_collection_of(urn),
                read_only=read_only,
                has_children=_has_children(urn),
                icon=icon,
            ))
        if leaves:
            groups.append(ConfigGroup(glabel, gicon, tuple(leaves)))
    return groups


def section_menu(section_key: str, complete: bool = True) -> list[ConfigGroup]:
    """The ordered GUI menu (groups -> object types) for one config section.

    The curated, GUI-faithful groups come FIRST (good labels/ordering); then —
    when ``complete`` (default) and the section is a real config browser — EVERY
    remaining top-level cmdb object the registry files under this section is
    appended in a trailing "Other Objects" group, so the browser shows the WHOLE
    FortiWeb config of the section (empty types included), never just the curated
    subset. By-parent sub-rows are excluded (reached by drilling into the parent).

    Returns ``[]`` for a section with no curated menu (e.g. read-only Monitor),
    so the page falls back to the static catalog exactly as before."""
    groups = _curated_groups(section_key)
    has_curated = section_key == "server_objects" or section_key in _SECTION_MENUS
    if complete and has_curated:
        shown = {_norm_coll(it.collection) for g in groups for it in g.items}
        extra = _remaining_types(section_key, shown)
        if extra:
            groups = list(groups) + [
                ConfigGroup("Other Objects", "bi-three-dots", tuple(extra))
            ]
    return groups

def has_menu(section_key: str) -> bool:
    """``True`` when this section has a curated GUI-faithful live-browse menu."""
    return section_key == "server_objects" or bool(_SECTION_MENUS.get(section_key))


def type_for(section_key: str, logical: str) -> ConfigObjectType | None:
    """Look up a single menu leaf by its logical name (``None`` if not in menu)."""
    for group in section_menu(section_key):
        for item in group.items:
            if item.logical == logical:
                return item
    return None


def curated_sections() -> list[str]:
    """Section keys that currently have a curated menu (for coverage/tests)."""
    return ["server_objects", *_SECTION_MENUS.keys()]


def iter_types(section_key: str):
    """Flat iterator over a section's menu leaves (for coverage / tests)."""
    for group in section_menu(section_key):
        for item in group.items:
            yield group.label, item


__all__ = [
    "ConfigObjectType",
    "ConfigGroup",
    "section_menu",
    "has_menu",
    "type_for",
    "curated_sections",
    "iter_types",
]
