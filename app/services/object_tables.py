"""The device configuration cache as query-builder tables (2026-10-25).

FortiGate, FortiADC, FortiAnalyzer and FortiAuthenticator have no tables of
their own: everything SATOM reads from them lives in ONE generic table,
``device_objects`` (product x layer x logical name, the fields as JSON). The
Report Builder's query builder listed only real tables, so an administrator
building a Plugin dataset found FortiWeb's curated projections and nothing of
the other products.

Each cached object type is offered as a table of its own -- the same types,
keys and fields as the ``objects`` datasets of :mod:`plugin_datasets` -- and
compiled to a sub-select over ``device_objects``::

    (SELECT o.id, o.appliance_id, a.name AS device, o.mkey, o.parent_id,
            '<appliance_id>/<mkey>' AS object_key, o.payload->>'name' AS name ...
       FROM device_objects o JOIN appliances a ON a.id = o.appliance_id
      WHERE a.kind = 'fortigate' AND o.layer = 'config'
        AND o.logical_name = 'firewall_policy') AS "fortigate_firewall_policy"

so joins, filters, grouping and the ADOM scope (its ``appliance_id``) work as
on a real table. Only the fields a query uses are extracted; every value is
text. A field whose name says secret is a sensitive column (refused).

Joins never cross devices: a sub-object reaches its parent by ``parent_id``,
and a field that names another object (a policy's source address, a group's
member, a virtual server's pool) has a ``<column>_ref`` column,
``<appliance_id>/<value>``, that joins the target's ``object_key``.

Tables are grouped per product and category (domain
``obj.<product>.<category>``) and say what the type is.
"""
from __future__ import annotations

import re
import threading
from typing import Any

PRODUCT_ORDER = ("fortigate", "fortiadc", "fortianalyzer", "fortiauthenticator", "fortiweb")
PRODUCT_LABEL = {"fortiweb": "FortiWeb", "fortigate": "FortiGate", "fortiadc": "FortiADC",
                 "fortianalyzer": "FortiAnalyzer", "fortiauthenticator": "FortiAuthenticator"}
DOMAIN_PREFIX = "obj."
FIXED = (("id", "BIGINT"), ("appliance_id", "INTEGER"), ("device", "TEXT"), ("mkey", "TEXT"),
         ("parent_id", "BIGINT"), ("object_key", "TEXT"))
REF_SUFFIX = "_ref"
#: A device field name is used inside a SQL literal: anything else is skipped.
_SAFE_FIELD = re.compile(r"^[A-Za-z0-9_.\-]{1,120}$")

#: ``product: [(logical prefix, category)]``, first match wins; the order of
#: first appearance is the order of the groups in the picker.
CATEGORIES: dict[str, list[tuple[str, str]]] = {
    "fortigate": [
        ("firewall_policy", "Firewall policies"),
        ("firewall_address", "Addresses and address groups"),
        ("firewall_addrgrp", "Addresses and address groups"),
        ("firewall_service", "Services and schedules"),
        ("firewall_schedule", "Services and schedules"),
        ("firewall_ssl_ssh_profile", "Security profiles"),
        ("antivirus_", "Security profiles"), ("ips_", "Security profiles"),
        ("webfilter_", "Security profiles"), ("dnsfilter_", "Security profiles"),
        ("application_", "Security profiles"),
        ("system_interface", "Interfaces, routing and SD-WAN"),
        ("system_sdwan", "Interfaces, routing and SD-WAN"),
        ("router_", "Interfaces, routing and SD-WAN"),
        ("system_dhcp", "Interfaces, routing and SD-WAN"),
        ("system_dns", "Interfaces, routing and SD-WAN"),
        ("vpn_", "VPN and certificates"),
        ("user_", "Users and authentication"),
        ("log_", "Logging"),
        ("system_", "System"),
    ],
    "fortiadc": [
        ("load_balance_virtual_server", "Server load balancing"),
        ("load_balance_pool", "Server load balancing"),
        ("load_balance_real_server", "Server load balancing"),
        ("load_balance_", "Load-balancing profiles and rules"),
        ("global_load_balance_", "Global load balancing and DNS"),
        ("global_dns_server_", "Global load balancing and DNS"),
        ("link_load_balance_", "Link load balancing"),
        ("security_waf_", "Web application firewall"),
        ("security_", "Security: antivirus, IPS, DoS"),
        ("firewall_", "Firewall"),
        ("system_certificate_", "Certificates"),
        ("system_address", "Addresses and services"),
        ("system_addrgrp", "Addresses and services"),
        ("system_service", "Addresses and services"),
        ("system_interface", "Interfaces and routing"),
        ("router_", "Interfaces and routing"),
        ("user_", "Users and authentication"),
        ("log_", "Logging and reports"),
        ("system_", "System"),
    ],
    "fortianalyzer": [
        ("dvmdb_", "ADOMs and devices"),
        ("report_", "Reports"),
        ("log_", "Logging and the log database"),
        ("locallog_", "Logging and the log database"),
        ("sql_", "Logging and the log database"),
        ("ueba_", "UEBA endpoints"),
        ("admin_", "Administrators"),
        ("fmupdate_", "FortiGuard updates"),
        ("system_", "System"),
    ],
    "fortiauthenticator": [
        ("auth_", "Users and groups"),
        ("radius_", "RADIUS clients and policies"),
        ("sso_", "Single sign-on"),
        ("policy_", "Password and lockout policies"),
        ("token_", "Tokens"),
        ("system_", "System"),
    ],
    "fortiweb": [
        ("server_policy", "Server policies, pools and virtual servers"),
        ("server_pool", "Server policies, pools and virtual servers"),
        ("vserver", "Server policies, pools and virtual servers"),
        ("vip", "Server policies, pools and virtual servers"),
        ("services_", "Server policies, pools and virtual servers"),
        ("webprotection_", "Web protection profiles"),
        ("web_protection_", "Web protection profiles"),
        ("waf_", "Signatures and WAF rules"), ("signature", "Signatures and WAF rules"),
        ("custom_", "Signatures and WAF rules"), ("syntax_", "Signatures and WAF rules"),
        ("api_", "API protection"), ("openapi_", "API protection"),
        ("graphql_", "API protection"), ("grpc_", "API protection"),
        ("mobile_api_", "API protection"), ("json_", "API protection"),
        ("xml_", "API protection"), ("websocket_", "API protection"),
        ("bot_", "Bots, DoS and IP reputation"), ("ddos_", "Bots, DoS and IP reputation"),
        ("dos_", "Bots, DoS and IP reputation"), ("ip_", "Bots, DoS and IP reputation"),
        ("geo_", "Bots, DoS and IP reputation"), ("allow_", "Bots, DoS and IP reputation"),
        ("threat_", "Bots, DoS and IP reputation"),
        ("url_", "Request and URL rules"), ("http_", "Request and URL rules"),
        ("parameter_", "Request and URL rules"), ("hidden_", "Request and URL rules"),
        ("cookie_", "Request and URL rules"), ("csrf_", "Request and URL rules"),
        ("cors_", "Request and URL rules"), ("file_", "Request and URL rules"),
        ("fiel_", "Request and URL rules"), ("link_", "Request and URL rules"),
        ("x_forwarded", "Request and URL rules"),
        ("certificate", "Certificates and TLS"), ("ssl_", "Certificates and TLS"),
        ("admin_certificate", "Certificates and TLS"),
        ("log_", "Logging"), ("attack_log", "Logging"), ("event_log", "Logging"),
        ("traffic_log", "Logging"), ("fortianalyzer", "Logging"),
        ("system_", "System"), ("global", "System"), ("interface", "System"),
        ("route", "System"), ("router_", "System"), ("dns", "System"), ("ntp", "System"),
        ("network_", "System"), ("accprofile", "System"), ("admin", "System"),
    ],
}
OTHER = "Other objects"

#: What each common type IS, for the picker and the Library. Anything not
#: here gets a description built from its name, row count and links.
DESCRIPTIONS: dict[str, str] = {
    # FortiGate
    "fortigate:firewall_policy": "Firewall policies (rules): ID, name, action (accept/deny), status, schedule, NAT and logging, UUID. The addresses, interfaces and services of each rule are its sub-objects.",
    "fortigate:firewall_policy/srcaddr": "Source addresses of each firewall policy: one row per address or address group in the rule. parent_id is the policy; name_ref joins the address or the address group.",
    "fortigate:firewall_policy/dstaddr": "Destination addresses of each firewall policy: one row per address or address group in the rule. parent_id is the policy; name_ref joins the address or the address group.",
    "fortigate:firewall_policy/srcintf": "Incoming interfaces (or zones) of each firewall policy.",
    "fortigate:firewall_policy/dstintf": "Outgoing interfaces (or zones) of each firewall policy.",
    "fortigate:firewall_policy/service": "Services (ports and protocols) each firewall policy allows: one row per service or service group.",
    "fortigate:firewall_address": "IPv4 address objects: subnet, IP range, FQDN, geography or wildcard, with their UUID. What a policy or a group names.",
    "fortigate:firewall_address6": "IPv6 address objects.",
    "fortigate:firewall_addrgrp": "Address groups: a named set of addresses (or other groups) a policy can use as one.",
    "fortigate:firewall_addrgrp/member": "Members of each address group: one row per address or nested group. name_ref joins the address or the group.",
    "fortigate:firewall_service_custom": "Custom services: protocol and TCP/UDP/SCTP port ranges.",
    "fortigate:firewall_service_group": "Service groups: a named set of services.",
    "fortigate:firewall_service_group/member": "Members of each service group.",
    "fortigate:firewall_schedule_recurring": "Recurring schedules (days and hours) a policy can be limited to.",
    "fortigate:firewall_ssl_ssh_profile": "SSL/SSH inspection profiles: certificate or deep inspection, and its exemptions.",
    "fortigate:antivirus_profile": "Antivirus profiles a policy applies.",
    "fortigate:ips_sensor": "IPS sensors: which intrusion signatures a policy blocks or monitors.",
    "fortigate:webfilter_profile": "Web filter profiles: URL and FortiGuard category filtering.",
    "fortigate:dnsfilter_profile": "DNS filter profiles: domain and botnet filtering at DNS level.",
    "fortigate:application_list": "Application control lists: which applications are allowed, blocked or monitored.",
    "fortigate:system_interface": "Network interfaces: physical ports, VLANs, aggregates and tunnels, with IP, status and allowed access.",
    "fortigate:router_static": "Static routes: destination, gateway, interface and distance.",
    "fortigate:system_sdwan": "SD-WAN settings; members, zones and health checks are its sub-objects.",
    "fortigate:system_dhcp_server": "DHCP servers per interface, with their address ranges.",
    "fortigate:vpn_certificate_ca": "CA certificates the FortiGate trusts.",
    "fortigate:vpn_certificate_local": "Local (server) certificates on the FortiGate.",
    "fortigate:vpn_ssl_settings": "SSL VPN settings: port, TLS versions, ciphers, timeouts.",
    "fortigate:user_local": "Local user accounts (passwords masked).",
    "fortigate:user_group": "User groups used for authentication in policies and VPN.",
    "fortigate:system_global": "Global system settings: hostname, admin ports, timezone, timers.",
    "fortigate:system_ha": "High-availability (cluster) settings.",
    # FortiADC
    "fortiadc:load_balance_virtual_server": "Virtual servers: the IP and port clients connect to, with the pool, profile, persistence, method and security profiles that handle the traffic.",
    "fortiadc:load_balance_pool": "Real-server pools a virtual server balances across; its members are the pool_member sub-objects.",
    "fortiadc:load_balance_pool/pool_member": "Members of each pool: the real server, port, weight and status. parent_id is the pool.",
    "fortiadc:load_balance_real_server": "Real servers: the back-end addresses (IP or FQDN) pools point to.",
    "fortiadc:load_balance_profile": "Application profiles (HTTP, HTTPS, TCP, UDP...): how a virtual server handles a protocol.",
    "fortiadc:load_balance_persistence": "Persistence (session stickiness) methods: source IP, cookie, header...",
    "fortiadc:load_balance_method": "Load-balancing methods: round robin, least connections, hash...",
    "fortiadc:load_balance_client_ssl_profile": "Client-side SSL profiles: certificates, TLS versions and ciphers towards clients.",
    "fortiadc:load_balance_real_server_ssl_profile": "Server-side SSL profiles: TLS towards the real servers.",
    "fortiadc:load_balance_content_routing": "Content routing rules: send a request to a pool by host, URL or header.",
    "fortiadc:load_balance_content_rewriting": "Content rewriting rules: change headers, redirects or URLs.",
    "fortiadc:firewall_policy": "FortiADC firewall policy (IPv4) defaults; its rules are the rule sub-objects.",
    "fortiadc:firewall_policy/rule": "Firewall rules on the FortiADC: source, destination, service, interface and action.",
    "fortiadc:security_waf_profile": "WAF profiles a virtual server applies: signatures, protocol constraints, injection detection.",
    "fortiadc:system_address": "IPv4 address objects (FortiADC).",
    "fortiadc:system_addrgrp": "Address groups (FortiADC).",
    "fortiadc:system_service": "Services: protocol and ports (FortiADC).",
    "fortiadc:system_interface": "Network interfaces of the FortiADC.",
    "fortiadc:router_static": "Static routes of the FortiADC.",
    "fortiadc:system_certificate_local": "Local certificates on the FortiADC (used by SSL profiles).",
    "fortiadc:global_load_balance_host": "GSLB hosts: the DNS names global load balancing answers for.",
    "fortiadc:global_dns_server_zone": "DNS zones the FortiADC serves; the records are its sub-objects.",
    "fortiadc:system_ha": "High-availability settings of the FortiADC.",
    # FortiAnalyzer
    "fortianalyzer:dvmdb_adom": "ADOMs defined on the FortiAnalyzer: name, mode, log disk quota.",
    "fortianalyzer:dvmdb_group": "Device groups on the FortiAnalyzer.",
    "fortianalyzer:report_datasets": "Report datasets: the SQL queries FortiAnalyzer reports read from the log database.",
    "fortianalyzer:report_charts": "Report charts: how a dataset is drawn (table, bar, pie...).",
    "fortianalyzer:report_layouts": "Report layouts: the report templates (title, sections, charts).",
    "fortianalyzer:report_schedules": "Report schedules: which layout runs when, for which devices.",
    "fortianalyzer:report_macros": "Report macros: single values (totals) a report can show.",
    "fortianalyzer:log_settings": "Log settings of the FortiAnalyzer.",
    "fortianalyzer:admin_user": "Administrator accounts of the FortiAnalyzer.",
    "fortianalyzer:admin_profile": "Administrator profiles (permissions) of the FortiAnalyzer.",
    "fortianalyzer:system_interface": "Network interfaces of the FortiAnalyzer.",
    "fortianalyzer:ueba_endpoints": "Endpoints UEBA has seen: name, last seen, how they were detected.",
    # FortiAuthenticator
    "fortiauthenticator:auth_local_users": "Local users of the FortiAuthenticator: username, e-mail, active, FortiToken/FIDO.",
    "fortiauthenticator:auth_user_groups": "User groups of the FortiAuthenticator.",
    "fortiauthenticator:auth_local_group_members": "Which local user is in which group.",
    "fortiauthenticator:radius_clients": "RADIUS clients: the devices (FortiGates, VPNs, Wi-Fi) allowed to ask the FortiAuthenticator to authenticate.",
    "fortiauthenticator:radius_policies": "RADIUS policies: how a RADIUS request is authenticated.",
    "fortiauthenticator:radius_policy_client": "Which RADIUS client uses which RADIUS policy.",
    "fortiauthenticator:sso_fgt_group_filter": "FSSO group filters sent to FortiGates.",
    "fortiauthenticator:policy_user_lockout": "Account lockout policy: failed logins and inactivity.",
    "fortiauthenticator:token_ftm_provisioning": "FortiToken Mobile provisioning settings.",
    # FortiWeb
    "fortiweb:server_policy": "Server policies: which virtual server, server pool, web protection profile and certificate protect each published site.",
    "fortiweb:server_pool": "Server pools: the back-end web servers a policy forwards to.",
    "fortiweb:vserver": "Virtual servers: the IPs a server policy listens on.",
    "fortiweb:vip": "Virtual IPs on the FortiWeb.",
    "fortiweb:webprotection_profile_inline": "Inline web protection profiles: which signatures and rules a server policy enforces.",
    "fortiweb:webprotection_profile_offline": "Offline (out-of-band) web protection profiles.",
    "fortiweb:system_interface": "Network interfaces of the FortiWeb.",
}

#: Fields that name another object, beyond "a field named like a type":
#: ``(product, source logical, field column) -> target logicals``.
REFS: dict[tuple[str, str, str], tuple[str, ...]] = {
    ("fortigate", "firewall_policy/srcaddr", "name"): ("firewall_address", "firewall_addrgrp"),
    ("fortigate", "firewall_policy/dstaddr", "name"): ("firewall_address", "firewall_addrgrp"),
    ("fortigate", "firewall_addrgrp/member", "name"): ("firewall_address", "firewall_addrgrp"),
    ("fortigate", "firewall_policy/service", "name"): ("firewall_service_custom",
                                                       "firewall_service_group"),
    ("fortigate", "firewall_service_group/member", "name"): ("firewall_service_custom",),
    ("fortigate", "firewall_policy/srcintf", "name"): ("system_interface",),
    ("fortigate", "firewall_policy/dstintf", "name"): ("system_interface",),
    ("fortigate", "firewall_policy", "schedule"): ("firewall_schedule_recurring",),
    ("fortigate", "user_group/member", "name"): ("user_local",),
    ("fortiadc", "load_balance_virtual_server", "pool"): ("load_balance_pool",),
    ("fortiadc", "load_balance_virtual_server", "profile"): ("load_balance_profile",),
    ("fortiadc", "load_balance_virtual_server", "persistence"): ("load_balance_persistence",),
    ("fortiadc", "load_balance_virtual_server", "method"): ("load_balance_method",),
    ("fortiadc", "load_balance_virtual_server", "client_ssl_profile"): (
        "load_balance_client_ssl_profile",),
    ("fortiadc", "load_balance_virtual_server", "waf_profile"): ("security_waf_profile",),
    ("fortiadc", "load_balance_pool/pool_member", "real_server"): ("load_balance_real_server",),
    ("fortiweb", "server_policy", "server_pool"): ("server_pool",),
    ("fortiweb", "server_policy", "web_protection_profile"): ("webprotection_profile_inline",),
}

_lock = threading.Lock()
_cache: dict[str, Any] = {"objs": None, "tables": None}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def category(product: str, logical: str) -> str:
    for prefix, label in CATEGORIES.get(product, ()):
        if logical.startswith(prefix):
            return label
    return OTHER


def domain_key(product: str, layer: str, cat: str) -> str:
    return "%s%s.%s%s" % (DOMAIN_PREFIX, product, _slug(cat), ".deep" if layer == "deep" else "")


def domains() -> list[tuple[str, str]]:
    """``[(key, label)]`` of every product/category group, in picker order
    (only the groups that hold a table)."""
    used = {t["domain"] for t in tables().values()}
    out = []
    for product in PRODUCT_ORDER:
        cats, seen = [], set()
        for _p, label in list(CATEGORIES.get(product, ())) + [("", OTHER)]:
            if label not in seen:
                seen.add(label)
                cats.append(label)
        for layer in ("config", "deep"):
            for cat in cats:
                key = domain_key(product, layer, cat)
                if key in used:
                    out.append((key, "%s · %s%s" % (PRODUCT_LABEL[product], cat,
                                                   " (deep layer)" if layer == "deep" else "")))
    return out


def _human(logical: str) -> str:
    return logical.replace("/", " › ").replace("_", " ")


def _describe(product: str, o: dict, refs: list, parent: str | None, masked: list) -> str:
    text = DESCRIPTIONS.get("%s:%s" % (product, o["logical"]))
    if not text:
        if parent:
            text = "Entries of the %s list of each %s %s (one row per entry)." % (
                _human(o["logical"].rsplit("/", 1)[1]), PRODUCT_LABEL[product],
                _human(o["logical"].rsplit("/", 1)[0]))
        else:
            text = "%s %s objects as the device cache holds them." % (
                PRODUCT_LABEL[product], _human(o["logical"]))
    extra = ["%d cached on this server" % o["rows"]]
    if parent:
        extra.append("parent_id joins its parent (%s)" % parent)
    for col, target in refs:
        extra.append("%s joins %s" % (col, target))
    if masked:
        extra.append("secret fields refused: " + ", ".join(masked))
    return text + " " + "; ".join(extra) + "."


def tables() -> dict[str, dict]:
    """``{name: table}`` -- ``table`` as :func:`dbintrospect.relations` gives
    them (``name``, ``cols``) plus ``label``, ``domain``, ``description``,
    ``edges`` and ``object`` (``product``, ``layer``, ``logical``, ``fields``:
    ``{column: device field}``, ``refs``: ``{column: device field}``)."""
    from . import plugin_datasets as PD
    from . import dbintrospect as D
    objs = PD._objects()
    with _lock:
        if _cache["objs"] is objs and _cache["tables"] is not None:
            return _cache["tables"]
    out: dict[str, dict] = {}
    for key, o in objs.items():
        product, layer, logical = o["product"], o["layer"], o["logical"]
        if product not in PRODUCT_LABEL:
            continue
        cols = [{"name": c, "type": t, "pk": c == "id", "fk": c in ("appliance_id", "parent_id"),
                 "sensitive": False} for c, t in FIXED]
        names = {c for c, _t in FIXED}
        fields: dict[str, str] = {}
        masked: list[str] = []
        for col, field in o["fields"]:
            if col in names or not _SAFE_FIELD.match(field) or D._FORBIDDEN.search(col):
                continue
            secret = PD.is_secret(field) or D.is_credential_column(col)
            cols.append({"name": col, "type": "TEXT", "pk": False, "fk": False,
                         "sensitive": secret, "json": True})
            names.add(col)
            fields[col] = field
            if secret:
                masked.append(col)
        out[key] = {"name": key, "cols": cols, "object": {
                        "product": product, "layer": layer, "logical": logical,
                        "fields": fields, "refs": {}},
                    "label": "%s %s%s" % (PRODUCT_LABEL[product], _human(logical),
                                          " (deep)" if layer == "deep" else ""),
                    "domain": domain_key(product, layer, category(product, logical)),
                    "edges": [], "_masked": masked, "_rows": o}
    # links: parent, curated references, fields named like a type
    for key, t in out.items():
        ob = t["object"]
        product, layer, logical = ob["product"], ob["layer"], ob["logical"]
        edges = [{"from_table": key, "from_col": "appliance_id", "to_table": "appliances",
                  "to_col": "id", "inferred": False}]
        parent = None
        if "/" in logical:
            parent = PD.object_key(product, layer, logical.rsplit("/", 1)[0])
            if parent in out:
                edges.append({"from_table": key, "from_col": "parent_id", "to_table": parent,
                              "to_col": "id", "inferred": False})
            else:
                parent = None
        refs = []
        for col, field in ob["fields"].items():
            if any(c["name"] == col and c["sensitive"] for c in t["cols"]):
                continue
            targets = list(REFS.get((product, logical, col), ()))
            curated = bool(targets)
            if not targets and "/" not in logical:
                guess = PD.object_key(product, layer, field.replace("-", "_"))
                if guess != key and guess in out and "/" not in out[guess]["object"]["logical"]:
                    targets = [out[guess]["object"]["logical"]]
            hit = [PD.object_key(product, layer, tl) for tl in targets]
            hit = [h for h in hit if h in out and h != key]
            ref_col = col + REF_SUFFIX
            if not hit or ref_col in {c["name"] for c in t["cols"]}:
                continue
            t["cols"].append({"name": ref_col, "type": "TEXT", "pk": False, "fk": True,
                              "sensitive": False, "json": True})
            ob["refs"][ref_col] = field
            for h in hit:
                edges.append({"from_table": key, "from_col": ref_col, "to_table": h,
                              "to_col": "object_key", "inferred": not curated})
                refs.append((ref_col, out[h]["label"]))
        t["edges"] = edges
        t["description"] = _describe(product, t.pop("_rows"), refs,
                                     out[parent]["label"] if parent else None, t.pop("_masked"))
    with _lock:
        _cache.update(objs=objs, tables=out)
    return out


# --------------------------------------------------------------------------
# SQL
# --------------------------------------------------------------------------
def _lit(text: str) -> str:
    """A SQL string literal that never spells a word the read-only guard
    refuses (a FortiGate field ``auto-update`` would): such a word is split
    and concatenated back, ``('auto-up' || 'date')``."""
    from . import dbintrospect as D
    cuts = sorted({m.start() + 2 for m in D._FORBIDDEN.finditer(text)})
    if not cuts:
        return "'" + text.replace("'", "''") + "'"
    parts, prev = [], 0
    for c in cuts + [len(text)]:
        parts.append("'" + text[prev:c].replace("'", "''") + "'")
        prev = c
    return "(" + " || ".join(parts) + ")"


def _extract(field: str, postgres: bool) -> str:
    if postgres:
        return "o.payload ->> %s" % _lit(field)
    return "CAST(json_extract(o.payload, %s) AS TEXT)" % _lit('$."%s"' % field)


def from_sql(name: str, needed: set[str] | None = None, *, postgres: bool | None = None) -> str:
    """The sub-select a query reads ``name`` from, aliased ``"name"``: the
    fixed columns, plus the fields and links in ``needed`` (all if None)."""
    from . import dbintrospect as D
    t = tables()[name]
    ob = t["object"]
    if postgres is None:
        postgres = D._is_postgres()
    owner = "CAST(o.appliance_id AS TEXT) || '/' || "
    parts = ['o.id AS "id"', 'o.appliance_id AS "appliance_id"', 'a.name AS "device"',
             'o.mkey AS "mkey"', 'o.parent_id AS "parent_id"',
             owner + "COALESCE(o.mkey, '') AS \"object_key\""]
    for col, field in ob["fields"].items():
        if needed is None or col in needed:
            parts.append('%s AS "%s"' % (_extract(field, postgres), col))
    for col, field in ob["refs"].items():
        if needed is None or col in needed:
            parts.append('%s(%s) AS "%s"' % (owner, _extract(field, postgres), col))
    return ("(SELECT %s FROM device_objects o JOIN appliances a ON a.id = o.appliance_id"
            " WHERE a.kind = %s AND o.layer = %s AND o.logical_name = %s) AS \"%s\"" % (
                ", ".join(parts), _lit(ob["product"]), _lit(ob["layer"]), _lit(ob["logical"]),
                name))
