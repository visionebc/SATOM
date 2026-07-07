"""Field metadata for the editable Server Policy workspace.

The workspace edit form is built by iterating the *device's own keys* for each
object (server policy, server pool, pool back-end, virtual IP, web-protection
profile), so every field FortiWeb returns is rendered — nothing is hard-coded
away. This module only *enriches* those keys with:

  * a friendly label + GUI group,
  * a widget kind (text / number / toggle / enum / ref),
  * enum option lists, and
  * the cmdb collection a *reference* field selects from (+ create-new flag).

Two layers, merged (overlay wins):
  1. SEED — a small curated map below.
  2. OVERLAY — an optional ``data/fortiweb_field_schema.json`` produced by the
     Firecrawl scrape of the FortiWeb 8.0.5 admin guide; lets us extend
     labels/options/widgets with no code change.

Widget decision order for any key (``descriptor``):
  metadata.widget (overlay/seed)  ->  ref (key in REF_ENDPOINTS)  ->
  toggle (value is enable/disable) ->  enum (options known) ->
  number (int / digit value)       ->  text.

The presence of a companion ``<key>_val`` on the device object is FortiWeb's own
signal that a field is a select (enum or object reference); we use it to mark
unmapped ``_val`` keys as selects so the GUI mirrors the box.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache

# ── noise: server-managed / internal keys never shown as editable fields ──────
_NOISE_EXACT = {
    "id", "_id", "seq", "flag", "mkey", "q_ref", "q_type", "q_ref_string",
    "policy-id", "server-pool-id", "profile-id", "server-id", "sub_table_id",
    "sub_table_action", "can_view", "can_clone", "host-for-deny", "url-for-deny",
}
_NOISE_PREFIX = ("q_", "sz_", "can_", "sub_table")
_NOISE_SUFFIX = ("_val", "-id")

_TOGGLE_VALS = {"enable", "disable", "enabled", "disabled", "on", "off"}
_ON_VALS = {"enable", "enabled", "on", "1", "true", "yes"}


def is_noise(key: str) -> bool:
    if key in _NOISE_EXACT:
        return True
    if any(key.startswith(p) for p in _NOISE_PREFIX):
        return True
    if any(key.endswith(s) for s in _NOISE_SUFFIX):
        return True
    return False


def is_on(v) -> bool:
    return str(v).strip().lower() in _ON_VALS


# ── reference fields → cmdb collection(s) the select draws options from ───────
# Multiple sources are merged with "|". create-new affordance is per REF_CREATE.
REF_ENDPOINTS: dict[str, str] = {
    # server policy
    "vserver": "server-policy/vserver",
    "server-pool": "server-policy/server-pool",
    "web-protection-profile": "waf/web-protection-profile.inline-protection",
    "service": "server-policy/service.custom|server-policy/service.predefined",
    "https-service": "server-policy/service.custom|server-policy/service.predefined",
    "http3-service": "server-policy/service.custom|server-policy/service.predefined",
    "replacemsg": "system/replacemsg",
    "certificate": "system/certificate.local",
    "intermediate-certificate-group": "system/certificate.intermediate-certificate-group",
    "sni-certificate": "system/certificate.sni",
    "ssl-client-verify": "system/certificate.verify",
    "hpkp-header": "system/certificate.hpkp",
    "allow-hosts": "server-policy/allow-hosts",
    "allow-list": "server-policy/allow-list",
    "ztna-profile": "server-policy/ztna-profile",
    "traffic-mirror-profile": "server-policy/traffic-mirror",
    "v-zone": "system/v-zone",
    "lets-certificate": "system/certificate.letsencrypt",
    "scripting-list": "server-policy/scripting",
    "replacemsg-on-connect-failure": "system/replacemsg",
    "ssl-ciphers-group": "server-policy/ssl-ciphers.custom|server-policy/ssl-ciphers.predefined",
    "data-capture-port": "system/interface",
    "block-port": "system/interface",
    # the vip-list row's Virtual IP names a system/vip object (a select, not text)
    "vip": "system/vip",
    # HTTP content-routing binding row → the routing policy it names
    "content-routing-policy-name": "server-policy/http-content-routing-policy",
    # server pool
    "health": "server-policy/health",
    "persistence": "server-policy/persistence-policy",
    # virtual IP
    "interface": "system/interface",
    # web-protection-profile sub-policies (best effort; empty → graceful text)
    "signature-rule": "waf/signature",
    "allow-method-policy": "waf/allow-method-policy",
    "http-protocol-parameter-restriction": "waf/http-protocol-parameter-restriction",
    "x-forwarded-for-rule": "waf/x-forwarded-for",
    "ip-list-policy": "waf/ip-list",
    "geo-block-list-policy": "waf/geo-block-list",
    "url-access-policy": "waf/url-access.url-access-policy",
    "custom-access-policy": "waf/custom-access.policy",
    "bot-mitigate-policy": "waf/bot-mitigate-policy",
    "cookie-security-policy": "waf/cookie-security",
    "csrf-protection": "waf/csrf-protection",
    "hidden-fields-protection": "waf/hidden-fields-protection",
    "parameter-validation-rule": "waf/parameter-validation-rule",
    "file-upload-policy": "waf/file-upload-restriction-policy",
    "json-validation-policy": "waf/json-validation.policy",
    "xml-validation-policy": "waf/xml-validation.policy",
    "openapi-validation-policy": "waf/openapi-validation-policy",
    "api-management-policy": "waf/api-policy",
    "url-rewrite-policy": "waf/url-rewrite.url-rewrite-policy",
    "user-tracking-policy": "waf/user-tracking.policy",
    "threat-score-profile": "server-policy/pattern.threat-score-profile",
    "http-header-security": "waf/http-header-security",
    "cors-protection-policy": "waf/cors-protection-policy",
    "padding-oracle": "waf/padding-oracle",
}

# References that offer "＋ Create New" (mirrors the FortiWeb GUI dropdown +).
# Most objects are created with just a name (then refined via ✎); a few need a
# couple of fields up front (system/vip → IP+interface, a custom Service → port),
# collected by the create modal (CREATE_FIELDS below).
REF_CREATE = {
    "web-protection-profile", "server-pool", "vserver", "health",
    "persistence", "certificate", "ftp-protection-profile",
    "allow-list", "ztna-profile", "traffic-mirror-profile",
    # added 2026-06-28 to match the desktop standalone create affordances:
    "service", "https-service", "http3-service", "allow-hosts",
    "v-zone", "sni-certificate", "scripting-list", "vip",
}

# Extra fields the create modal collects for objects a bare name can't define.
# Each entry: cmdb collection (the create endpoint's primary) → ordered field
# specs (key, label, placeholder). Anything not listed is created name-only.
CREATE_FIELDS: dict[str, list[dict]] = {
    "system/vip": [
        {"key": "vip", "label": "IP / Netmask", "placeholder": "e.g. 192.0.2.50/24",
         "required": True},
        {"key": "interface", "label": "Interface", "placeholder": "e.g. port1", "ref": "system/interface"},
    ],
    "server-policy/service.custom": [
        # Wire shape verified live on fw6 7.6.8: {name, port, protocol} — there
        # is NO "type" field; a create without port answers HTTP 500 errcode
        # -56 "Empty value isn't allowed." (protocol defaults to TCP).
        {"key": "port", "label": "Port", "placeholder": "e.g. 8080", "required": True},
    ],
}

# Blank add-row field templates for by-parent sub-tables whose parent has no
# rows yet (a brand-new object). Without a seed the generic union-of-existing-
# keys yields an EMPTY add-row form and a dead "Create row" button. Values are
# the device DEFAULTS (they drive widget inference: enable/disable → toggle) and
# are only sent when the operator changes them. Live-verified shapes only.
SUBTABLE_FIELD_SEED: dict[str, dict] = {
    # verified on fw6 7.6.8 (GET host-list of a populated Protected Hostnames)
    "server-policy/allow-hosts/host-list": {
        "host": "", "action": "allow", "ignore-port": "disable",
        "include-subdomains": "disable", "override-header": "disable",
    },
}

# ── curated enum seed (overlay from Firecrawl extends this) ───────────────────
ENUM_SEED: dict[str, list[str]] = {
    "deployment-mode": ["single-server", "server-pool", "http-content-routing",
                        "offline-protection", "transparent-servers",
                        "transparent-inspection", "wccp", "ftp-server"],
    "protocol": ["HTTP", "FTP"],
    "lb-algo": ["round-robin", "weighted-round-robin", "least-connection",
                "URI-hash", "full-uri-hash", "host-hash", "host-domain-hash",
                "source-ip-hash"],
    "type": ["reverse-proxy", "transparent-servers", "transparent-inspection",
             "offline-protection", "wccp", "ftp-server"],
    "http-reuse": ["never", "always", "safe", "aggressive"],
    "ssl-cipher": ["low", "medium", "high", "custom"],
    "server-type": ["physical", "domain", "sdn-connector"],
    "proxy-protocol-version": ["v1", "v2"],
    "internal-cookie-samesite-value": ["lax", "strict", "none"],
    "quarantined-ip-severity": ["Low", "Medium", "High"],
    "quarantined-ip-action": ["alert", "alert_deny", "block-period", "period-block"],
}

# friendly labels for the common keys (overlay extends)
LABEL_SEED: dict[str, str] = {
    "deployment-mode": "Deployment Mode", "vserver": "Virtual Server",
    "server-pool": "Server Pool", "web-protection-profile": "Web Protection Profile",
    "service": "HTTP Service", "https-service": "HTTPS Service",
    "http3-service": "HTTP/3 Service", "http2": "HTTP/2",
    "http-to-https": "Redirect HTTP to HTTPS", "client-real-ip": "Client Real IP",
    "real-ip-addr": "IP / IP Range", "lb-algo": "Load-Balancing Algorithm",
    "health": "Health Check", "persistence": "Persistence",
    "server-balance": "Server Balance", "http-reuse": "HTTP Reuse",
    "use-interface-ip": "Use Interface IP", "vip": "Virtual IP", "interface": "Interface",
    "syncookie": "SYN Cookie", "monitor-mode": "Monitor Mode", "web-cache": "Web Cache",
    "comment": "Comments", "ssl-cipher": "SSL/TLS Encryption Level",
    "ztna-profile": "ZTNA Profile", "traffic-mirror-profile": "Traffic Mirror Profile",
    "ssl-client-verify": "Certificate Verification", "hpkp-header": "HPKP Header",
    "allow-list": "Allow List", "sni-certificate": "SNI Certificate Policy",
}

# GUI group per key (keys not listed land in "Other"). Group render order below.
GROUP_SEED: dict[str, dict[str, str]] = {
    "policy": {
        "status": "Network Configuration", "deployment-mode": "Network Configuration",
        "protocol": "Network Configuration", "vserver": "Network Configuration",
        "v-zone": "Network Configuration", "service": "Network Configuration",
        "https-service": "Network Configuration", "http3-service": "Network Configuration",
        "server-pool": "Network Configuration", "allow-hosts": "Network Configuration",
        "client-real-ip": "Network Configuration", "real-ip-addr": "Network Configuration",
        "http2": "Network Configuration", "http-to-https": "Network Configuration",
        "redirect-naked-domain": "Network Configuration", "comment": "Network Configuration",
        "ssl": "HTTPS/SSL", "multi-certificate": "HTTPS/SSL", "certificate-type": "HTTPS/SSL",
        "certificate": "HTTPS/SSL", "lets-certificate": "HTTPS/SSL",
        "ssl-client-verify": "HTTPS/SSL", "sni": "HTTPS/SSL", "sni-certificate": "HTTPS/SSL",
        "tls-v10": "HTTPS/SSL", "tls-v11": "HTTPS/SSL", "tls-v12": "HTTPS/SSL",
        "tls-v13": "HTTPS/SSL", "ssl-ciphers-group": "HTTPS/SSL", "ssl-cipher": "HTTPS/SSL",
        "hsts-header": "HTTPS/SSL", "hsts-max-age": "HTTPS/SSL", "hpkp-header": "HTTPS/SSL",
        "proxy-protocol": "Application Delivery", "retry-on": "Application Delivery",
        "traffic-mirror": "Application Delivery", "traffic-mirror-profile": "Application Delivery",
        "traffic-mirror-type": "Application Delivery",
        "web-cache": "Application Delivery", "http-pipeline": "Application Delivery",
        "monitor-mode": "Security", "syncookie": "Security", "ztna-profile": "Security",
        "web-protection-profile": "Security", "ftp-protection-profile": "Security",
        "allow-list": "Security", "replacemsg": "Security", "case-sensitive": "Security",
        "tlog": "Log",
    },
}

# front-to-back order for known groups; unknown groups sort after these
# (alphabetically), then "Advanced", then "Other" always last.
GROUP_ORDER = [
    "Network Configuration", "Virtual Server", "Server Pool", "Pool Member",
    "HTTPS/SSL", "Application Delivery", "Security", "Machine Learning",
    "Standard Protection", "Client Side Security", "Input Validation", "Access",
    "API Protection", "Bot Mitigation", "IP Protection", "DoS Protection",
    "Advanced Protection", "Data Loss Prevention", "Protocol", "Tracking",
    "Redirect", "Scripting", "Log", "Tags", "General",
]


def _group_rank(g: str):
    if g == "Other":
        return (3, "")
    if g == "Advanced":
        return (2, "")
    if g in GROUP_ORDER:
        return (0, "%03d" % GROUP_ORDER.index(g))
    return (1, g.lower())


# ── overlay (Firecrawl-produced JSON) ─────────────────────────────────────────
@lru_cache(maxsize=1)
def _overlay() -> dict:
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "..", "data", "fortiweb_field_schema.json")
    path = os.path.abspath(path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception:
        return {}
    # index overlay by (kind, key) for quick merge
    idx = {}
    for kind, fields in (raw or {}).items():
        for f in fields or []:
            k = f.get("key")
            if k:
                idx[(kind, k)] = f
    return idx


_KIND_ALIAS = {"policy": "server_policy", "pool": "server_pool",
               "backend": "pool_backend", "vip": "virtual_server", "wpp": "wpp"}


def _prettify(key: str) -> str:
    return key.replace("-", " ").replace("_", " ").strip().title()


# -- per-OBJECT curated selects (ported from the desktop standalone objform.SPECS)
# Keyed by the CREATE kind (policy/pool/pserver/vip/vserver). Unlike the global
# ENUM_SEED / REF_ENDPOINTS (keyed only by field NAME), these are scoped per object
# so the SAME key (``type``, ``status``, ``protocol``) gets the right vocabulary for
# THIS object -- exactly how the standalone renders every dropdown. Tokens are
# DEVICE values (verified live on the 8.0.x reference appliance), never GUI labels.
# ``enums`` win over the enable/disable toggle heuristic, so a tri-state select like
# a pool member's status (enable/disable/maintenance) is never collapsed to a toggle.
KIND_SPECS: dict = {
    "crmatch": {
        "enums": {
            # Suggestions only (editable combos): FortiWeb 8.0 uses lowercase
            # tokens (http-host…) while 7.6 uses HTTP-host… — both are offered and
            # the field stays type-able so the firmware-correct value always goes.
            "match-object": ["http-host", "http-request", "url", "url-parameter",
                "http-referer", "http-cookie", "http-header", "source-ip",
                "x509-certificate-Subject", "x509-certificate-Extension",
                "https-sni", "geo-ip", "ztna-ems-tags",
                "HTTP-host", "HTTP-request", "HTTP-referer", "HTTP-cookie",
                "HTTP-header", "HTTPS-sni"],
            "match-condition": ["match-begin", "match-end", "match-sub",
                "match-domain", "match-dir", "match-reg", "ip-range",
                "ip-range6", "equal", "ip-list"],
            "name-match-condition": ["match-begin", "match-end", "match-sub",
                "match-reg", "equal"],
            "value-match-condition": ["match-begin", "match-end", "match-sub",
                "match-reg", "equal"],
            "concatenate": ["and", "or"],
        },
        "combos": {"match-object", "match-condition",
                   "name-match-condition", "value-match-condition"},
        "refs": {"ip-list": "server-policy/ip-group"},
        "toggles": {"reverse"},
        "labels": {
            "match-object": "Match Object", "match-condition": "Condition",
            "match-expression": "Expression / Value",
            "name": "Header / Cookie Name", "name-match-condition": "Name Condition",
            "value": "Value", "value-match-condition": "Value Condition",
            "start-ip": "Start IP", "end-ip": "End IP",
            "ip-list": "Source IP Group", "country-list": "Country List",
            "x509-subject-name": "X.509 Subject Name",
            "reverse": "Reverse (negate match)", "concatenate": "Concatenate",
        },
        "groups": {
            "match-object": "Match", "match-condition": "Match",
            "match-expression": "Match",
            "name": "Name / Value (header & cookie)",
            "name-match-condition": "Name / Value (header & cookie)",
            "value": "Name / Value (header & cookie)",
            "value-match-condition": "Name / Value (header & cookie)",
            "start-ip": "IP / Geo / Certificate",
            "end-ip": "IP / Geo / Certificate",
            "ip-list": "IP / Geo / Certificate",
            "country-list": "IP / Geo / Certificate",
            "x509-subject-name": "IP / Geo / Certificate",
            "reverse": "Logic", "concatenate": "Logic",
        },
    },
    "pool": {
        "enums": {
            "type": ["reverse-proxy", "true-transparent-proxy",
                     "transparent-inspection", "offline-protection", "wccp"],
            "protocol": ["HTTP", "HTTPS", "FTP"],
            "lb-algo": ["round-robin", "weighted-round-robin", "least-connection",
                        "uri-hash", "full-uri-hash", "host-hash",
                        "host-domain-hash", "source-ip-hash"],
            "http-reuse": ["never", "always", "safe", "aggressive"],
        },
        "refs": {
            "health": "server-policy/health",
            "persistence": "server-policy/persistence-policy",
        },
        "toggles": {"server-balance", "panic-mode"},
        "labels": {
            "type": "Type", "protocol": "Protocol",
            "lb-algo": "Load-Balancing Algorithm",
            "server-balance": "Single Server / Server Balance",
            "http-reuse": "HTTP Reuse", "health": "Health Check",
            "persistence": "Persistence", "comment": "Comments",
        },
        "groups": {
            "type": "Server Pool", "protocol": "Server Pool",
            "server-balance": "Server Pool", "lb-algo": "Server Pool",
            "health": "Server Pool", "persistence": "Server Pool",
            "comment": "Server Pool", "http-reuse": "Application Delivery",
        },
    },
    "pserver": {
        "enums": {
            "server-type": ["physical", "domain", "sdn"],
            "status": ["enable", "disable", "maintenance"],
        },
        "refs": {
            "health": "server-policy/health",
            "certificate": "system/certificate.local",
            "certificate-verify": "system/certificate.local",
        },
        "toggles": {"backup-server", "health-check-inherit", "ssl", "http2"},
        "labels": {
            "server-type": "Server Type", "status": "Status",
            "ssl": "SSL to Back-end", "http2": "HTTP/2",
            "certificate": "Client Certificate",
            "certificate-verify": "Server Certificate Verify (CA)",
            "health": "Health Check",
        },
    },
    "vip": {
        "refs": {
            "interface": "system/interface",
            "vip": "system/vip",
        },
        "toggles": {"status", "use-interface-ip"},
        "labels": {
            "interface": "Interface", "vip": "VIP Address",
            "status": "Status", "use-interface-ip": "Use Interface IP",
        },
    },
}

# Allow-list for the lazy cmdb-options endpoint: every cmdb collection any select
# (global REF_ENDPOINTS or a per-object KIND_SPECS ref) can populate from.
ALL_REF_ENDPOINTS = set(REF_ENDPOINTS.values()) | {
    r for _ks in KIND_SPECS.values() for r in _ks.get("refs", {}).values()
}


def descriptor(kind: str, key: str, value, obj: dict) -> dict:
    """Resolve one device key into a form-field descriptor."""
    ov = _overlay().get((_KIND_ALIAS.get(kind, kind), key), {})
    ks = KIND_SPECS.get(kind, {})
    k_enum = ks.get("enums", {}).get(key)
    k_ref = ks.get("refs", {}).get(key)
    k_toggle = key in ks.get("toggles", ())
    k_number = key in ks.get("numbers", ())
    label = ks.get("labels", {}).get(key) or ov.get("label") or LABEL_SEED.get(key) or _prettify(key)
    group = ks.get("groups", {}).get(key) or ov.get("group") or GROUP_SEED.get(kind, {}).get(key) or "Advanced"
    # Enum <select> options MUST be device tokens (round-robin), never the GUI
    # labels the overlay scrapes ("Round Robin") — sending a label back would be
    # rejected by FortiWeb. So options come only from the device-valued seed; the
    # overlay contributes label/group/widget-hint, not the value list.
    options = k_enum or ENUM_SEED.get(key)
    sval = str(value).strip().lower()
    empty = value in (None, "", [])

    # Device truth drives the STRUCTURAL widget; the overlay only supplies
    # label/group/options and may upgrade an *empty* field's type (an empty
    # value can't reveal whether it's a toggle/number/select).
    k_combo = key in ks.get("combos", ())
    if k_ref or key in REF_ENDPOINTS:  # we can actually populate this select
        widget = "ref"
    elif k_combo and (k_enum or options):  # editable enum (firmware-divergent tokens)
        widget = "combo"
    elif k_enum:                       # curated per-object vocabulary (wins over toggle)
        widget = "enum"
    elif k_toggle:                     # curated per-object toggle
        widget = "toggle"
    elif k_number:                     # curated per-object number
        widget = "number"
    elif sval in _TOGGLE_VALS:        # enable/disable
        widget = "toggle"
    elif options:                     # known enum vocabulary
        widget = "enum"
    elif isinstance(value, bool):
        widget = "toggle"
    elif isinstance(value, int) or (sval and sval.lstrip("-").isdigit()):
        widget = "number"
    else:
        widget = "text"
        ov_w = ov.get("widget")       # overlay hint for empty/ambiguous fields
        if empty and ov_w in ("toggle", "number"):
            widget = ov_w
        elif empty and ov_w == "enum" and options:
            widget = "enum"
    # a ref the overlay flagged but we can't source from the box stays text
    # (editable, value preserved) — never render an empty/dead dropdown.

    d = {
        "key": key, "label": label, "group": group, "widget": widget,
        "value": "" if value is None else value, "options": options or [],
    }
    if widget == "ref":
        d["ref"] = k_ref or REF_ENDPOINTS.get(key, "")
        d["create_new"] = key in REF_CREATE
    if widget == "toggle":
        d["on"] = is_on(value)
    # ── WAF-spec enrichments (waf_specs.register adds these keys to KIND_SPECS) ──
    sw = ks.get("show_when", {}).get(key)
    if sw:
        # Same rule shape the workspace vis evaluator understands: the field is
        # shown only while the controlling field's value is one of ``vals`` —
        # exactly how FortiWeb gates e.g. a signature exception's inputs by the
        # chosen Element Type.
        d["vis"] = {"t": "eq", "key": sw[0], "vals": list(sw[1])}
    if widget in ("enum", "combo"):
        vl = _value_labels().get(key)
        if vl:
            d["option_labels"] = vl
    if widget in ("text", "combo") and _is_regex_capable(key):
        d["regex"] = True
        d["rx_context"] = kind
    return d


@lru_cache(maxsize=1)
def _value_labels() -> dict:
    """Display labels for cryptic wire codes (``alert_deny`` → "Alert & Deny")."""
    from . import waf_specs
    return waf_specs.value_labels()


def _is_regex_capable(key: str) -> bool:
    from . import waf_specs
    return key in waf_specs.REGEX_KEYS


def kind_keys(kind: str) -> list:
    """Every curated field key for *kind* (enums/refs/toggles/labels/groups), so a
    blank create / add-row form can render the FULL field set even when the device
    object is empty (the generic ``build_groups`` only renders keys present in the
    value, which yields an empty form for a sub-table that has no rows yet)."""
    ks = KIND_SPECS.get(kind, {})
    keys: set = set()
    for sub in ("enums", "refs", "labels", "groups", "show_when"):
        keys |= set(ks.get(sub, {}))
    keys |= set(ks.get("toggles", ()))
    keys |= set(ks.get("numbers", ()))
    # A curated field ORDER is the FortiWeb form order — a blank form follows it.
    order = ks.get("order")
    if order:
        oidx = {k: i for i, k in enumerate(order)}
        return sorted(keys, key=lambda k: (oidx.get(k, len(order)), k))
    return sorted(keys)


def build_groups(kind: str, obj: dict, keep_name: bool = False) -> list[dict]:
    """All editable fields of an object, grouped like the FortiWeb GUI.

    ``keep_name`` keeps ``name`` as an editable attribute — correct for a
    by-parent sub-table ROW (identified by ``id``, where ``name`` is a real
    field, e.g. a content-routing header/cookie name), wrong for a top-level
    object whose ``name`` is the read-only identity shown in the header."""
    buckets: dict[str, list] = {}
    for key, value in (obj or {}).items():
        if (key == "name" and not keep_name) or is_noise(key):
            continue
        # Show EVERY non-noise field — including empty ones — so the operator can
        # edit/populate anything (the user wants the full object, not just the
        # populated rows). Advanced groups are collapsed in the template instead.
        d = descriptor(kind, key, value, obj)
        buckets.setdefault(d["group"], []).append(d)
    ks = KIND_SPECS.get(kind, {})
    # Per-kind curated ORDER (fields + groups) mirrors the FortiWeb form; keys
    # outside the curated order fall back to alphabetical after it.
    order = ks.get("order") or []
    oidx = {k: i for i, k in enumerate(order)}
    g_order = ks.get("group_order") or []
    gidx = {g: i for i, g in enumerate(g_order)}

    def _rank(g: str):
        if g in gidx:
            return (-1, "%03d" % gidx[g])
        return _group_rank(g)

    out = []
    for g in sorted(buckets, key=_rank):
        rows = sorted(buckets[g],
                      key=lambda r: (oidx.get(r["key"], len(order)), r["label"].lower()))
        out.append({"title": g, "fields": rows})
    return out


# ── CREATE forms ──────────────────────────────────────────────────────────────
# Empty (skeleton) objects can't reveal widget types from a value, so we drive
# create forms from data/server_policy_create_skeleton.json — the complete,
# live-validated field set harvested from the reference 8.0 appliance (fw1).
# Sample values resolve widget/type only; create renders blank defaults so
# nothing from another policy is silently carried over.
@lru_cache(maxsize=1)
def _create_skeleton() -> dict:
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "..", "data", "server_policy_create_skeleton.json")
    try:
        with open(os.path.abspath(path), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def create_skeleton_keys(kind: str) -> list:
    return list((_create_skeleton().get(kind) or {}).get("keys") or [])


def build_create_groups(kind: str) -> list:
    """Complete, grouped field set for CREATING a new object of *kind*
    (policy/pool/vserver/vip/pserver). All fields blank; widgets resolved from
    the live-harvested sample so toggles/enums/refs render correctly."""
    spec = _create_skeleton().get(kind) or {}
    sample = spec.get("sample") or {}
    keys = spec.get("keys") or []
    buckets: dict = {}
    for key in keys:
        if key == "name" or is_noise(key):
            continue
        d = descriptor(kind, key, sample.get(key), sample)
        d["value"] = ""
        if d.get("widget") == "toggle":
            d["on"] = False
        buckets.setdefault(d["group"], []).append(d)
    out = []
    for g in sorted(buckets, key=_group_rank):
        out.append({"title": g,
                    "fields": sorted(buckets[g], key=lambda r: r["label"].lower())})
    return out
