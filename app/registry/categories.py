"""
FortiWeb URN → UI section mapping.

category_for(urn) returns (section_path, strip_n) where:
  section_path  – one-element list matching an entry in SECTION_ORDER
  strip_n       – how many leading path segments to strip when building a
                  human-readable label from the URN tail
"""

SECTION_ORDER = [
    "Dashboard / Monitor",
    "System",
    "Network",
    "Server Policy",
    "Server Objects",
    "Application Delivery",
    "Web Protection",
    "API Protection",
    "Bot Mitigation",
    "DoS Protection",
    "IP Protection",
    "Machine Learning",
    "Tracking",
    "User & Authentication",
    "Log & Report",
    "Other",
]

# WAF sub-path prefixes that are NOT "Web Protection"
WAF_BOT = {
    "bot-mitigation-exception",
    "bot-detection",
    "bot-allow-list",
    "bot-mitigation-policy",
}

WAF_DOS = {
    "application-layer-dos-prevention",
    "dos-protection-policy",
    "tcp-connection-flood-prevention",
    "http-request-flood-prevention",
    "http-access-limit",
}

WAF_IP = {
    "ip-list",
    "geo-block-list",
    "ip-intelligence",
    "trusted-ip",
    "black-ip",
}

WAF_ML = {
    "machine-learning-policy",
    "ml-based-anomaly-detection",
    "api-discovery-policy",
}

WAF_API = {
    "api-gateway-policy",
    "openapi-validation",
    "json-validation",
    "xml-validation",
    "api-protection-profile",
}

WAF_TRACKING = {
    "user-tracking",
    "site-publish",
    "session-management",
}

WAF_AD = {
    "load-balance",
    "persistence-policy",
    "health-check",
    "compression-rule",
    "cache-policy",
    "pki",
    "certificate-chain",
    "redirect-policy",
    "rewrite-policy",
    "content-routing",
    "x-forwarded-for",
}

WAF_USER_AUTH = {
    "user-tracking",
    "user-authentication-policy",
    "sso-server",
    "ldap-server",
    "radius-server",
    "active-directory",
    "ntlm-server",
}


def _waf_section(tail: str):
    """Given the first path component after /cmdb/waf/, return the section."""
    if tail in WAF_BOT:
        return "Bot Mitigation"
    if tail in WAF_DOS:
        return "DoS Protection"
    if tail in WAF_IP:
        return "IP Protection"
    if tail in WAF_ML:
        return "Machine Learning"
    if tail in WAF_API:
        return "API Protection"
    if tail in WAF_TRACKING:
        return "Tracking"
    if tail in WAF_USER_AUTH:
        return "User & Authentication"
    if tail in WAF_AD:
        return "Application Delivery"
    return "Web Protection"


def category_for(urn: str):
    """
    Map a FortiWeb API URN to a (section_path, strip_n) tuple.

    section_path  – list with the matching SECTION_ORDER entry, or [] for unknown
    strip_n       – int, number of leading segments to strip from the URN tail
                    when constructing a display label
    """
    if not urn:
        return (["Other"], 0)

    # Normalise: remove query string and dot-suffixed action (e.g. .systemstatus)
    path = urn.split("?")[0]

    # --- Dashboard / Monitor ---
    if path.startswith("/api/v2.0/wvs/"):
        return (["Dashboard / Monitor"], 1)

    # --- Log & Report ---
    if path.startswith("/api/v2.0/log/") or path.startswith("/api/v2.0/cmdb/log/"):
        return (["Log & Report"], 1)

    # --- Router (Network sub-section) ---
    if path.startswith("/api/v2.0/cmdb/router/"):
        return (["Network"], 1)

    # --- System-level maintenance / status / management ---
    if path.startswith("/api/v2.0/system/"):
        # network interfaces live under system but belong to Network
        tail = path[len("/api/v2.0/system/"):]
        if tail.startswith("network"):
            return (["Network"], 1)
        return (["System"], 1)

    # --- CMDB paths ---
    if path.startswith("/api/v2.0/cmdb/"):
        rest = path[len("/api/v2.0/cmdb/"):]

        # System sub-tree
        if rest.startswith("system/"):
            sub = rest[len("system/"):]
            # Interfaces/DNS/NTP → Network
            if any(sub.startswith(p) for p in ("network", "dns", "ntp", "interface", "routing")):
                return (["Network"], 1)
            # Certificates / admin → System
            return (["System"], 1)

        # Server Policy sub-tree
        if rest.startswith("server-policy/"):
            sub = rest[len("server-policy/"):]
            # Items that belong to Server Objects
            if any(sub.startswith(p) for p in ("vserver", "server-pool", "virtual-server")):
                return (["Server Objects"], 1)
            return (["Server Policy"], 1)

        # WAF sub-tree
        if rest.startswith("waf/"):
            sub = rest[len("waf/"):]
            # first component before any slash or dot
            tail = sub.split("/")[0].split(".")[0]
            section = _waf_section(tail)
            return ([section], 1)

        # Firewall / ACL-style rules
        if rest.startswith("firewall/"):
            return (["IP Protection"], 1)

        # User / authentication
        if rest.startswith("user/") or rest.startswith("auth/"):
            return (["User & Authentication"], 1)

    return (["Other"], 0)
