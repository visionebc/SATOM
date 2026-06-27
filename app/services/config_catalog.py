"""FortiWeb configuration catalog — the admin-only **Settings → FortiWeb →
Configuration** area, web port.

Surfaces every GUI config section EXCEPT Server Policy and Web Protection (which
keep their own top-level pages) as a structured, section-keyed catalog the UI can
render. Each section is derived from the two oracles already in the web foundation:

* ``registry.loader`` enumerates every endpoint (logical-name → URN display dict);
* ``registry.categories.category_for(urn)`` partitions every endpoint into the
  FortiWeb GUI sections (the same menu the API Explorer mirrors).

Only the per-object *metadata* is curated here (GUI label, singleton-vs-keyed,
dangerous-to-write). The build is **data-only**: it returns plain JSON-friendly
dicts/lists describing each section's object TYPES; fetching the live OBJECTS of
a type is the view's job (via ``FortiWebClient`` / ``FortiWebOps``), wired in
later under each type's ``objects`` placeholder.

Pure: the registry is read lazily inside the functions, so importing this module
has no side effects (no registry load, no Flask, no network).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# --------------------------------------------------------------------------- #
#  Sections (the FortiWeb GUI left menu, minus Server Policy + Web Protection).  #
#  Order mirrors categories.SECTION_ORDER. Network is a section-level DANGER     #
#  area; Dashboard/Monitor is read-only (status, never written here).           #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Section:
    key: str            # stable id used by build_section_tree / template kind
    label: str          # GUI label (== a categories.SECTION_ORDER entry)
    emoji: str = ""
    danger: bool = False    # section-level warning (e.g. Network: can sever mgmt)
    readonly: bool = False  # Dashboard/Monitor: status, never written here


CONFIG_SECTIONS: tuple[Section, ...] = (
    Section("system", "System", "⚙"),
    Section("network", "Network", "🌐", danger=True),
    Section("server_objects", "Server Objects", "🗄"),
    Section("application_delivery", "Application Delivery", "🚀"),
    Section("api_protection", "API Protection", "🔌"),
    Section("bot_mitigation", "Bot Mitigation", "🤖"),
    Section("dos_protection", "DoS Protection", "🛡"),
    Section("ip_protection", "IP Protection", "🚦"),
    Section("machine_learning", "Machine Learning", "🧠"),
    Section("tracking", "Tracking", "👣"),
    Section("user_authentication", "User & Authentication", "👤"),
    Section("log_report", "Log & Report", "📊"),
    Section("monitor", "Dashboard / Monitor", "📈", readonly=True),
)
SECTION_BY_KEY: dict[str, Section] = {s.key: s for s in CONFIG_SECTIONS}
SECTION_BY_LABEL: dict[str, Section] = {s.label: s for s in CONFIG_SECTIONS}


# --------------------------------------------------------------------------- #
#  Curated per-object metadata (everything else is auto-derived).               #
# --------------------------------------------------------------------------- #
# Dangerous to write over REST (can sever mgmt / split the cluster / lock out).
# Still EDITABLE (the admin asked to modify), but flagged so the page warns. The
# canonical desktop logical names are kept; ``_is_danger`` also matches the web
# registry's friendly-keys via their URN.
DANGER: frozenset[str] = frozenset({
    "interface", "static_route", "policy_route", "ha", "admin",
})

# URN markers that identify a danger object regardless of its registry key
# (the web registry spells these as interface/route/route_policy/system_ha/
# system_admin, so match on the stable URN tail).
_DANGER_URN_MARKERS: tuple[str, ...] = (
    "network.interface", "/interface", "router/static", "router/policy",
    "system/ha", "system/admin",
)

# Singletons are PUT as the whole object (no mkey). Default is a keyed
# collection; only these are one-of. (Verified against FortiWeb cmdb
# conventions; covers both desktop logical names and web friendly-keys.)
_SINGLETON: frozenset[str] = frozenset({
    "global", "advanced", "feature_visibility", "network_option", "dns", "ntp",
    "antivirus", "system_fortiguard", "ha", "system_ha", "backup", "system_time",
    "system_settings", "snmp_sysinfo", "system_snmp_sysinfo", "syslogd",
    "log_syslog", "log_fortiguard", "fortianalyzer", "sensitive",
    "advanced_bot_protection", "ip_intelligence_ignore_xff",
})

# Non-cmdb endpoints that are nonetheless EDITABLE config (kept in the writable
# render set). NTP is the canonical one on registries where it is non-cmdb.
_EXTRA_EDITABLE: frozenset[str] = frozenset({"system_time", "ntp"})

# Curated GUI labels (FortiWeb docs). Covers the common desktop logical names AND
# the web registry friendly-keys; anything absent is humanised from the key.
_LABEL: dict[str, str] = {
    # System
    "global": "Global / Hostname", "advanced": "Advanced", "dns": "DNS",
    "feature_visibility": "Feature Visibility", "network_option": "Network Options",
    "antivirus": "Antivirus", "system_fortiguard": "FortiGuard", "ha": "High Availability",
    "system_ha": "High Availability", "backup": "Config Backup", "system_time": "Time / NTP",
    "ntp": "Time / NTP", "accprofile": "Access Profile", "admin": "Administrators",
    "system_admin": "Administrators", "system_settings": "System Settings",
    "system_alert_email": "Alert Email", "v_zone": "V-Zone",
    "snmp_sysinfo": "SNMP Sysinfo", "system_snmp_sysinfo": "SNMP Sysinfo",
    "snmp_community": "SNMP Community", "system_snmp_community": "SNMP Community",
    "snmp_user": "SNMP v3 User", "replacemsg": "Replacement Messages",
    "certificate": "Local Certificate", "certificate_local": "Local Certificate",
    "certificate_intermediate": "Intermediate CA", "certificate_ca": "CA Certificate",
    "certificate_letsencrypt": "Let's Encrypt", "certificate_sni": "SNI Certificate",
    # Network
    "interface": "Interface", "static_route": "Static Route", "route": "Static Route",
    "policy_route": "Policy Route", "route_policy": "Policy Route", "vip": "Virtual IP",
    # Server Objects
    "vserver": "Virtual Server", "virtual_server": "Virtual Server",
    "server_pool": "Server Pool", "server_pool_rule": "Server Balance Rule",
    "ip_group": "IP Group", "services_custom": "Custom Service",
    # Application Delivery
    "health_check": "Health Check", "persistence_policy": "Persistence Policy",
    "load_balance": "Load Balance", "compression_rule": "Compression Rule",
    "cache_policy": "Web Cache Policy", "rewrite_policy": "URL Rewriting Policy",
    "redirect_policy": "Redirect Policy", "x_forwarded_for": "X-Forwarded-For",
    "content_routing": "HTTP Content Routing",
    # API Protection
    "api_policy": "API Gateway Policy", "openapi_policy": "OpenAPI Validation Policy",
    "json_protection_policy": "JSON Protection Policy",
    "xml_protection_policy": "XML Protection Policy",
    # Bot Mitigation
    "bot_mitigation_policy": "Bot Mitigation Policy", "bot_detection": "Bot Detection",
    "bot_allow_list": "Bot Allow List",
    # DoS Protection
    "dos_policy": "Application-Layer DoS Prevention", "tcp_flood": "TCP Flood Prevention",
    "http_flood": "HTTP Flood Prevention", "http_access_limit": "HTTP Access Limit",
    # IP Protection
    "ip_list": "IP List", "geo_block": "Geo IP Block List", "ip_intel": "IP Reputation",
    "trusted_ip": "Trusted IP",
    # Machine Learning
    "ml_policy": "Machine Learning Policy", "ml_anomaly_detection": "ML Anomaly Detection",
    # Tracking
    "user_auth": "User Tracking", "session_management": "Session Management",
    # User & Authentication
    "user_group": "User Group", "user_radius": "RADIUS User", "user_ldap": "LDAP User",
    "user_local": "Local User",
    # Log & Report
    "syslogd": "Syslog", "log_syslog": "Syslog", "syslog_policy": "Syslog Policy",
    "log_fortiguard": "FortiGuard Logging", "log_disk": "Disk Logging",
    "log_memory": "Memory Logging", "fortianalyzer": "FortiAnalyzer",
    "trigger_policy": "Trigger Policy",
}


# --------------------------------------------------------------------------- #
#  Helpers                                                                       #
# --------------------------------------------------------------------------- #
def _is_config(urn: str) -> bool:
    return "/cmdb/" in (urn or "")


def _is_danger(logical: str, urn: str) -> bool:
    if logical in DANGER:
        return True
    u = (urn or "").lower()
    return any(m in u for m in _DANGER_URN_MARKERS)


def _label_for(logical: str, urn: str) -> str:
    if logical in _LABEL:
        return _LABEL[logical]
    tail = (urn or "").split("?")[0].rstrip("/").rsplit("/", 1)[-1]
    base = tail or logical
    pretty = base.replace("-", " ").replace(".", " ").replace("_", " ").strip().title()
    return pretty or logical


def config_template_kind(section_key: str) -> str:
    """The ``Template`` kind for a config section, e.g. ``config:network``."""
    from ..models import Template

    return Template.config_kind(section_key)


# --------------------------------------------------------------------------- #
#  Section catalog (registry → per-section object-type dicts)                   #
# --------------------------------------------------------------------------- #
def section_catalog(section_key: str) -> list[dict[str, Any]]:
    """Object-type dicts for one section (best-effort, data-only).

    Derives the types from the loader endpoints whose ``category_for`` section
    equals this section's GUI label (the mapping table is each ``Section.label``,
    which is a ``categories.SECTION_ORDER`` entry). Writable sections keep the
    config (``cmdb``) objects (plus ``_EXTRA_EDITABLE``); the read-only Monitor
    section keeps every endpoint as a read-only status type.

    Each dict: ``{logical, urn, label, section, singleton, danger, readonly,
    methods, template_kind}`` — plain JSON-friendly metadata, no live objects.
    """
    from ..registry import loader

    section = SECTION_BY_KEY.get(section_key)
    if section is None:
        raise ValueError(f"Unknown config section: {section_key!r}")

    kind = config_template_kind(section_key)
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ep in loader.get_endpoints_by_section(section.label):
        name = ep.get("name")
        urn = ep.get("urn") or ep.get("path") or ""
        if not name or name in seen:
            continue
        if not section.readonly and not (_is_config(urn) or name in _EXTRA_EDITABLE):
            continue  # writable sections render config (cmdb) objects only
        seen.add(name)
        out.append({
            "logical": name,
            "urn": urn,
            "label": _label_for(name, urn),
            "section": section.key,
            "singleton": name in _SINGLETON,
            "danger": False if section.readonly else _is_danger(name, urn),
            "readonly": bool(section.readonly),
            "methods": list(ep.get("methods") or []),
            "template_kind": kind,
        })
    out.sort(key=lambda o: o["label"].lower())
    return out


def build_section_tree(section_key: str) -> dict[str, Any]:
    """A nested, data-only tree the UI can render: section → object types → objects.

    The returned dict carries the section metadata and an ``object_types`` list
    (from :func:`section_catalog`); each type gets an empty ``objects`` list — the
    placeholder the view fills with live rows fetched via ``FortiWebClient``.
    Nothing here touches a device.
    """
    section = SECTION_BY_KEY.get(section_key)
    if section is None:
        raise ValueError(f"Unknown config section: {section_key!r}")

    object_types = section_catalog(section_key)
    for ot in object_types:
        ot["objects"] = []  # live rows are fetched by the view, not here
    return {
        "key": section.key,
        "label": section.label,
        "emoji": section.emoji,
        "danger": section.danger,
        "readonly": section.readonly,
        "template_kind": config_template_kind(section_key),
        "object_types": object_types,
    }


__all__ = [
    "Section",
    "CONFIG_SECTIONS",
    "SECTION_BY_KEY",
    "SECTION_BY_LABEL",
    "DANGER",
    "section_catalog",
    "build_section_tree",
    "config_template_kind",
]
