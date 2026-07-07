"""FortiADC GUI menu — a mirror of the appliance's own left menu, so operators
who know FortiADC navigate this app the same way (the ADC counterpart of
:mod:`app.services.wp_menu` / ``config_sections``).

Tree harvested from the FortiADC 8.0.3 administration guide + CLI reference
(docs.fortinet.com, Firecrawl scrape 2026-07-07), endpoint paths cross-checked
against the official terraform-provider-fortiadc SDK. Groups follow the GUI:

    Server Load Balance   Virtual Server · Real Server Pool · SSL Management ·
                          Content Management · Profiles · Advanced Profiles ·
                          Application Optimization · Scripting
    Link Load Balance     Link Group · Link Policy · Virtual Tunnel
    Global Load Balance   GLB Configuration · Zone and DNS Security ·
                          Global DNS Setting
    Web Application Firewall  (WAF Profile … Web Anti-Defacement)
    Network Security      Firewall · IPS · AntiVirus · IP Reputation · DoS · ZTNA
    Network               Interface · Routing · NAT · QoS · Packet Capture
    Shared Resources      Health Check · Schedule Group · Address · Service · ISP
    User Authentication   (Application Access Manager subset)
    System                Administrator · Settings · HA · SNMP · Certificates · …
    Log & Report          Log Setting · Report

Each menu item renders as ONE page whose TABS are the object types behind that
GUI entry (dependencies first, like the box). Every tab is a **fortiadc**
registry logical endpoint; a logical missing from the registry is silently
dropped at build time — same contract as ``wp_menu``.

No curated per-tab columns yet (no lab device to verify wire field names
against): the list page derives its columns from the live payload. Pure data +
registry matching — no Flask, no device.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class AdcTab:
    """One object type shown as a tab inside a menu-item page."""

    label: str          # tab title ("Real Server Pool")
    logical: str        # fortiadc registry logical endpoint name
    urn: str            # resolved REST path (/api/load_balance_pool)


@dataclass(frozen=True)
class AdcItem:
    """One FortiADC menu entry (a page with one or more tabs)."""

    key: str            # url slug ("real-server-pool")
    label: str
    icon: str
    tabs: tuple[AdcTab, ...]


@dataclass(frozen=True)
class AdcGroup:
    """A FortiADC top-level menu section (Server Load Balance, …)."""

    key: str
    label: str
    icon: str
    items: tuple[AdcItem, ...]

    @property
    def flat(self) -> bool:
        return len(self.items) == 1 and self.items[0].label == self.label


# (group key, label, icon, ((item key, label, icon, ((tab label, logical), …)), …))
_TREE = (
    ("slb", "Server Load Balance", "bi-diagram-3", (
        ("virtual-server", "Virtual Server", "bi-hdd-network", (
            ("Virtual Server", "load_balance_virtual_server"),
        )),
        ("real-server-pool", "Real Server Pool", "bi-server", (
            ("Real Server Pool", "load_balance_pool"),
            ("Real Server", "load_balance_real_server"),
            ("Real Server SSL Profile", "load_balance_real_server_ssl_profile"),
        )),
        ("ssl-management", "SSL Management", "bi-shield-lock", (
            ("Client SSL Profile", "load_balance_client_ssl_profile"),
            ("Certificate Caching", "load_balance_certificate_caching"),
        )),
        ("content-management", "Content Management", "bi-signpost-split", (
            ("Content Routing", "load_balance_content_routing"),
            ("Content Rewriting", "load_balance_content_rewriting"),
            ("Error Page", "load_balance_error_page"),
        )),
        ("lb-profiles", "Profiles", "bi-sliders", (
            ("Application Profile", "load_balance_profile"),
            ("Persistence", "load_balance_persistence"),
            ("Method", "load_balance_method"),
            ("HTTP/2 Profile", "load_balance_http2_profile"),
            ("HTTP/3 Profile", "load_balance_http3_profile"),
        )),
        ("lb-advanced-profiles", "Advanced Profiles", "bi-gear-wide", (
            ("Auth Policy", "load_balance_auth_policy"),
            ("Captcha Profile", "load_balance_captcha_profile"),
            ("Web Filter Profile", "load_balance_web_filter_profile"),
            ("Geo IP List", "load_balance_geoip_list"),
            ("IP Pool", "load_balance_ippool"),
            ("Clone Pool", "load_balance_clone_pool"),
            ("Connection Pool", "load_balance_connection_pool"),
            ("Schedule Pool", "load_balance_schedule_pool"),
            ("L2 Exception List", "load_balance_l2_exception_list"),
            ("Allowlist", "load_balance_allowlist"),
        )),
        ("app-optimization", "Application Optimization", "bi-speedometer2", (
            ("Caching", "load_balance_caching"),
            ("Compression", "load_balance_compression"),
            ("Decompression", "load_balance_decompression"),
            ("PageSpeed Profile", "load_balance_pagespeed_profile"),
            ("PageSpeed", "load_balance_pagespeed"),
        )),
        ("lb-scripting", "Scripting", "bi-code-slash", (
            ("Scripting", "system_scripting"),
            ("Stream Scripting", "system_stream_scripting"),
        )),
    )),
    ("llb", "Link Load Balance", "bi-ethernet", (
        ("link-group", "Link Group", "bi-diagram-2", (
            ("Link Group", "link_load_balance_link_group"),
            ("Gateway", "link_load_balance_gateway"),
        )),
        ("link-policy", "Link Policy", "bi-signpost", (
            ("Flow Policy", "link_load_balance_flow_policy"),
            ("Persistence", "link_load_balance_persistence"),
            ("Proximity Route", "link_load_balance_proximity_route"),
        )),
        ("virtual-tunnel", "Virtual Tunnel", "bi-bezier2", (
            ("Virtual Tunnel", "link_load_balance_virtual_tunnel"),
        )),
    )),
    ("glb", "Global Load Balance", "bi-globe2", (
        ("glb-configuration", "GLB Configuration", "bi-globe-americas", (
            ("Data Center", "global_load_balance_data_center"),
            ("Servers", "global_load_balance_servers"),
            ("Virtual Server Pool", "global_load_balance_virtual_server_pool"),
            ("Host", "global_load_balance_host"),
            ("Link", "global_load_balance_link"),
            ("Topology", "global_load_balance_topology"),
            ("Setting", "global_load_balance_setting"),
        )),
        ("zone-dns-security", "Zone and DNS Security", "bi-shield-shaded", (
            ("Zone", "global_dns_server_zone"),
            ("DNS Policy", "global_dns_server_policy"),
            ("Response Rate Limit", "global_dns_server_response_rate_limit"),
            ("DNS64", "global_dns_server_dns64"),
            ("DSSET Info List", "global_dns_server_dsset_info_list"),
            ("Trust Anchor Key", "global_dns_server_trust_anchor_key"),
            ("TSIG Key", "global_dns_server_tsig_key"),
        )),
        ("global-dns-setting", "Global DNS Setting", "bi-hdd-network", (
            ("General", "global_dns_server_general"),
            ("Remote DNS Server", "global_dns_server_remote_dns_server"),
            ("Address Group", "global_dns_server_address_group"),
        )),
    )),
    ("waf", "Web Application Firewall", "bi-shield-exclamation", (
        ("waf-profile", "WAF Profile", "bi-shield-fill-check", (
            ("WAF Profile", "security_waf_profile"),
            ("WAF Action", "security_waf_action"),
            ("WAF Exception", "security_waf_exception"),
        )),
        ("waf-signature", "WAF Signature", "bi-fingerprint", (
            ("Web Attack Signature", "security_waf_web_attack_signature"),
            ("Staging Signature List", "waf_staging_signature_list"),
            ("Adaptive Learning", "security_waf_adaptive_learning"),
        )),
        ("common-attacks", "Common Attacks Detection", "bi-bug", (
            ("SQL/XSS Injection Detection", "security_waf_heuristic_sql_xss_injection_detection"),
            ("HTTP Protocol Constraint", "security_waf_http_protocol_constraint"),
            ("HTTP Header Security", "security_waf_http_header_security"),
            ("Brute Force Login", "security_waf_brute_force_login"),
            ("CSRF Protection", "security_waf_csrf_protection"),
            ("Cookie Security", "security_waf_cookie_security"),
            ("Advanced Protection", "security_waf_advanced_protection"),
        )),
        ("sensitive-data", "Sensitive Data Protection", "bi-eye-slash", (
            ("Data Leak Protection", "security_waf_data_leak_protection"),
            ("Sensitive Data Type", "security_waf_sensitive_data_type"),
            ("DLP Dictionary", "security_waf_dlp_dictionary"),
            ("DLP Sensors", "security_waf_dlp_sensors"),
        )),
        ("input-validation", "Input Validation", "bi-input-cursor-text", (
            ("Input Validation Policy", "security_waf_input_validation_policy"),
            ("Parameter Validation Rule", "security_waf_parameter_validation_rule"),
            ("Hidden Field Rule", "security_waf_hidden_field_rule"),
            ("File Restriction Rule", "security_waf_file_restriction_rule"),
        )),
        ("access-protection", "Access Protection", "bi-door-closed", (
            ("URL Protection", "security_waf_url_protection"),
        )),
        ("cors-protection", "CORS Protection", "bi-arrow-left-right", (
            ("CORS Protection", "security_waf_cors_protection"),
            ("CORS Headers", "security_waf_cors_headers"),
            ("Allowed Origin", "security_waf_allowed_origin"),
        )),
        ("api-protection", "API Protection", "bi-plug", (
            ("JSON Schema File", "security_waf_json_schema_file"),
            ("JSON Validation", "security_waf_json_validation_detection"),
            ("XML Schema File", "security_waf_xml_schema_file"),
            ("XML Validation", "security_waf_xml_validation_detection"),
            ("OpenAPI Schema File", "security_waf_openapi_schema_file"),
            ("OpenAPI Validation", "security_waf_openapi_validation_detection"),
            ("API Gateway User", "security_waf_api_gateway_user"),
            ("API Gateway Rule", "security_waf_api_gateway_rule"),
            ("API Gateway Policy", "security_waf_api_gateway_policy"),
            ("API Discovery", "security_waf_api_discovery"),
        )),
        ("bot-mitigation", "Bot Mitigation", "bi-robot", (
            ("Bot Detection", "security_waf_bot_detection"),
            ("Threshold Based Detection", "security_waf_threshold_based_detection"),
            ("Biometrics Based Detection", "security_waf_biometrics_based_detection"),
            ("Fingerprint Based Detection", "security_waf_fingerprint_based_detection"),
            ("Advanced Bot Protection", "security_waf_advanced_bot_protection"),
        )),
        ("wvs", "Web Vulnerability Scanner", "bi-search-heart", (
            ("Scan Profile", "security_waf_scanner"),
        )),
        ("anti-defacement", "Web Anti-Defacement", "bi-brush", (
            ("Web Anti-Defacement", "security_wad_profile"),
        )),
    )),
    ("netsec", "Network Security", "bi-bricks", (
        ("firewall", "Firewall", "bi-bricks", (
            ("Firewall Policy", "firewall_policy"),
            ("Firewall Policy (IPv6)", "firewall_policy6"),
            ("Virtual IP", "firewall_vip"),
            ("Connection Limit", "firewall_connlimit"),
            ("Connection Limit (IPv6)", "firewall_connlimit6"),
            ("Firewall Global", "firewall_global"),
        )),
        ("ips", "Intrusion Prevention", "bi-shield-slash", (
            ("IPS Profile", "security_ips_profile"),
        )),
        ("antivirus", "AntiVirus", "bi-virus", (
            ("AntiVirus Profile", "security_antivirus_profile"),
            ("AntiVirus Settings", "security_antivirus_settings"),
            ("Quarantine", "security_antivirus_quarantine"),
        )),
        ("ip-reputation", "IP Reputation", "bi-exclamation-octagon", (
            ("IP Reputation", "load_balance_reputation"),
            ("Reputation Exception", "load_balance_reputation_exception"),
            ("Reputation Black List", "load_balance_reputation_black_list"),
        )),
        ("dos-protection", "DoS Protection", "bi-shield-fill-exclamation", (
            ("DoS Protection Profile", "security_dos_dos_protection_profile"),
            ("DoS Exception", "security_dos_exception"),
            ("HTTP Access Limit", "security_dos_http_access_limit"),
            ("HTTP Connection Flood", "security_dos_http_connection_flood_protection"),
            ("HTTP Request Flood", "security_dos_http_request_flood_protection"),
            ("DNS Query Flood", "security_dos_dns_query_flood_protection"),
            ("DNS Reverse Flood", "security_dos_dns_reverse_flood_protection"),
            ("IP Fragmentation", "security_dos_ip_fragmentation_protection"),
            ("TCP Access Flood", "security_dos_tcp_access_flood_protection"),
            ("TCP Slow Data Attack", "security_dos_tcp_slowdata_attack_protection"),
            ("TCP SYN Flood", "security_dos_tcp_synflood_protection"),
        )),
        ("ztna", "ZTNA", "bi-person-badge", (
            ("ZTNA Profile", "security_ztna_profile"),
            ("EMS Connector", "endpoint_control_fctems"),
            ("Endpoint Client", "endpoint_control_client"),
            ("Endpoint Tag", "endpoint_control_tag"),
        )),
    )),
    ("network", "Network", "bi-hdd-network", (
        ("interface", "Interface", "bi-ethernet", (
            ("Interface", "system_interface"),
        )),
        ("routing", "Routing", "bi-signpost-2", (
            ("Static Route", "router_static"),
            ("Policy Route", "router_policy"),
            ("ISP Route", "router_isp"),
            ("OSPF", "router_ospf"),
            ("OSPF (IPv6)", "router_ospf6"),
            ("OSPF MD5", "router_md5_ospf"),
            ("BGP", "router_bgp"),
            ("BFD", "router_bfd"),
            ("Access List", "router_access_list"),
            ("Access List (IPv6)", "router_access_list6"),
            ("Prefix List", "router_prefix_list"),
            ("Prefix List (IPv6)", "router_prefix_list6"),
            ("Router Setting", "router_setting"),
        )),
        ("nat", "NAT", "bi-arrow-repeat", (
            ("Source NAT", "firewall_nat_snat"),
        )),
        ("qos", "QoS", "bi-bar-chart-steps", (
            ("QoS Filter", "firewall_qos_filter"),
            ("QoS Filter (IPv6)", "firewall_qos_filter6"),
            ("QoS Queue", "firewall_qos_queue"),
        )),
        ("packet-capture", "Packet Capture", "bi-broadcast", (
            ("Packet Capture", "system_tcpdump"),
        )),
        ("overlay-tunnel", "Overlay Tunnel", "bi-bezier", (
            ("Overlay Tunnel", "system_overlay_tunnel"),
        )),
    )),
    ("shared", "Shared Resources", "bi-box-seam", (
        ("health-check", "Health Check", "bi-heart-pulse", (
            ("Health Check", "system_health_check"),
            ("Health Check Script", "system_health_check_script"),
        )),
        ("schedule-group", "Schedule Group", "bi-calendar-week", (
            ("Schedule Group", "system_schedule_group"),
        )),
        ("address", "Address", "bi-geo-alt", (
            ("Address", "system_address"),
            ("Address (IPv6)", "system_address6"),
            ("Address Group", "system_addrgrp"),
            ("Address Group (IPv6)", "system_addrgrp6"),
        )),
        ("service", "Service", "bi-plugin", (
            ("Service", "system_service"),
            ("Service Group", "system_servicegrp"),
        )),
        ("isp-address", "ISP Address Book", "bi-journal-bookmark", (
            ("ISP Address", "system_isp_addr"),
            ("ISP Province", "system_isp_province"),
        )),
    )),
    ("userauth", "User Authentication", "bi-people", (
        ("user-auth", "User Authentication", "bi-people", (
            ("Local User", "user_local"),
            ("User Group", "user_user_group"),
            ("LDAP Server", "user_ldap"),
            ("RADIUS Server", "user_radius"),
            ("Authentication Relay", "user_authentication_relay"),
            ("SAML IdP", "user_saml_idp"),
            ("SAML SP", "user_saml_sp"),
            ("OAuth", "user_oauth"),
            ("AD FS Publish", "user_adfs_publish"),
        )),
        ("app-portal", "App Portal", "bi-grid-1x2", (
            ("App Portal", "user_app_portal"),
            ("App Group", "user_app_group"),
        )),
    )),
    ("system", "System", "bi-gear", (
        ("administrator", "Administrator", "bi-person-gear", (
            ("Administrator", "system_admin"),
            ("Access Profile", "system_accprofile"),
            ("Password Policy", "system_password_policy"),
            ("SSO Admin", "system_sso_admin"),
        )),
        ("sys-settings", "Settings", "bi-sliders", (
            ("Global", "system_global"),
            ("Setting", "system_setting"),
            ("DNS", "system_dns"),
            ("NTP", "system_time_ntp"),
            ("Time (manual)", "system_time_manual"),
            ("Mail Server", "system_mailserver"),
            ("Auto Backup", "system_auto_backup"),
        )),
        ("ha", "High Availability", "bi-diagram-2-fill", (
            ("HA", "system_ha"),
            ("Traffic Group", "system_traffic_group"),
        )),
        ("snmp", "SNMP", "bi-broadcast-pin", (
            ("SNMP Sysinfo", "system_snmp_sysinfo"),
            ("SNMP Community", "system_snmp_community"),
            ("SNMP User", "system_snmp_user"),
        )),
        ("certificates", "Certificates", "bi-patch-check", (
            ("Local Certificate", "system_certificate_local"),
            ("Local Certificate Group", "system_certificate_local_cert_group"),
            ("CA Certificate", "system_certificate_ca"),
            ("CA Group", "system_certificate_ca_group"),
            ("Intermediate CA", "system_certificate_intermediate_ca"),
            ("Intermediate CA Group", "system_certificate_intermediate_ca_group"),
            ("Remote Certificate", "system_certificate_remote"),
            ("CRL", "system_certificate_crl"),
            ("OCSP", "system_certificate_ocsp"),
            ("OCSP Stapling", "system_certificate_ocsp_stapling"),
            ("Certificate Verify", "system_certificate_certificate_verify"),
        )),
        ("fortiguard", "FortiGuard", "bi-cloud-check", (
            ("FortiGuard", "system_fortiguard"),
            ("FortiSandbox", "system_fortisandbox"),
        )),
        ("vdom", "Virtual Domain", "bi-columns-gap", (
            ("Virtual Domain", "system_vdom"),
            ("VDOM Link", "system_vdom_link"),
        )),
        ("alerts", "Alerts", "bi-bell", (
            ("Alert", "system_alert"),
            ("Alert Policy", "system_alert_policy"),
            ("Alert Action", "system_alert_action"),
            ("Alert Email", "system_alert_email"),
            ("Alert SNMP Trap", "system_alert_snmp_trap"),
        )),
        ("integration", "Integration", "bi-boxes", (
            ("SDN Connector", "system_sdn_connector"),
            ("Security Fabric (CSF)", "system_csf"),
            ("Central Management", "system_central_management"),
            ("Azure", "system_azure"),
            ("Azure LB Backend", "system_azure_lb_backend_ip"),
            ("ICAP Server", "system_icapserver"),
            ("External Resource", "system_external_resource"),
            ("Config Sync List", "config_sync_list"),
        )),
    )),
    ("logreport", "Log & Report", "bi-journal-text", (
        ("log-setting", "Log Setting", "bi-journal-code", (
            ("Local Log", "log_setting_local"),
            ("Remote Log (Syslog)", "log_setting_remote"),
            ("FortiAnalyzer", "log_setting_fortianalyzer"),
            ("Fast Stats", "log_setting_fast_stats"),
        )),
        ("report", "Report", "bi-file-earmark-bar-graph", (
            ("Report", "log_report"),
            ("Report Email", "log_report_email"),
            ("Fast Report", "log_fast_report"),
            ("Report Queryset", "log_report_queryset"),
        )),
    )),
)


@lru_cache(maxsize=1)
def _build() -> tuple[AdcGroup, ...]:
    """Resolve the static tree against the fortiadc registry; a logical the
    registry doesn't carry is silently dropped (same contract as wp_menu)."""
    from ..registry import loader
    reg = loader.load_adc_registry()
    groups = []
    for gkey, glabel, gicon, items in _TREE:
        built_items = []
        for ikey, ilabel, iicon, tabs in items:
            built_tabs = tuple(
                AdcTab(label=tlabel, logical=logical, urn=reg[logical])
                for tlabel, logical in tabs if logical in reg
            )
            if built_tabs:
                built_items.append(AdcItem(key=ikey, label=ilabel,
                                           icon=iicon, tabs=built_tabs))
        if built_items:
            groups.append(AdcGroup(key=gkey, label=glabel, icon=gicon,
                                   items=tuple(built_items)))
    return tuple(groups)


def menu() -> tuple[AdcGroup, ...]:
    """The resolved FortiADC menu (cached per process)."""
    return _build()


def invalidate() -> None:
    """Drop the cached tree (after a registry edit)."""
    _build.cache_clear()


def find_item(item_key: str) -> tuple[AdcGroup, AdcItem] | None:
    for group in menu():
        for item in group.items:
            if item.key == item_key:
                return group, item
    return None
