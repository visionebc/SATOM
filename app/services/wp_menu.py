"""FortiWeb 7.6 GUI **Web Protection** menu — an exact mirror of the appliance's
own left menu, so operators who know FortiWeb navigate the web app the same way.

Tree harvested from the FortiWeb 7.6.4 administration guide (Firecrawl scrape of
the whole Web Protection chapter, every ``Go to Web Protection > …`` GUI path)
on 2026-07-04, re-validated 2026-07-06 against the guide AND live fw6 (7.6.8):

    Known Attacks        Signatures · Custom Signature
    Protocol             HTTP · WebSocket · gRPC
    Access               URL Access · Allow Method · CORS Protection
    Input Validation     Parameter Validation · Hidden Fields · File Security ·
                         Web Shell Detection
    Cookie Security
    Advanced Protection  Custom Policy · Padding Oracle Protection ·
                         CSRF Protection · HTTP Header Security ·
                         Man in the Browser Protection · URL Encryption ·
                         Link Cloaking · SQL/XSS Syntax Based Detection
    Data Loss Prevention

Each menu item renders as ONE page whose TABS are FortiWeb's own tabs, in
FortiWeb's own order (dependencies first — Rule before Policy, IDL File before
Rule, Dictionary → Sensor → Rule → Policy → Exception for DLP). Every tab is a
registry logical endpoint; a logical a firmware doesn't ship is silently
dropped at build time (same contract as ``config_sections``).

Each tab also carries its FortiWeb LIST COLUMNS (the columns the appliance's
own object table shows), keyed by the REAL wire field names verified on fw6.
Column kinds: ``text`` · ``enum`` (GUI label via waf_specs value_labels) ·
``onoff`` (enable/disable badge) · ``count`` (a ``sz_<child>`` row counter) ·
``host`` (host-status + host → "Any" when unscoped) · ``ref`` (named object).

Pure data + registry matching — no Flask, no device.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class WpCol:
    """One FortiWeb list column (wire field key + GUI label + render kind)."""

    key: str
    label: str
    kind: str = "text"   # text | enum | onoff | count | host | ref


@dataclass(frozen=True)
class WpTab:
    """One FortiWeb tab inside a menu-item page (one object type)."""

    label: str          # the FortiWeb tab title ("URL Access Rule")
    logical: str        # registry logical endpoint name
    collection: str     # bare cmdb collection (waf/url-access.url-access-rule)
    urn: str            # resolved REST urn
    columns: tuple[WpCol, ...] = ()


@dataclass(frozen=True)
class WpItem:
    """One FortiWeb menu entry (a page with one or more tabs)."""

    key: str            # url slug ("url-access")
    label: str          # the FortiWeb menu label ("URL Access")
    icon: str
    tabs: tuple[WpTab, ...]
    special: str = ""   # "signatures" → the dedicated FortiWeb-style editor


@dataclass(frozen=True)
class WpGroup:
    """A FortiWeb sub-menu (Known Attacks, Protocol, …). A group whose single
    item carries the same label renders as a DIRECT link (Cookie Security,
    Data Loss Prevention) — exactly like the appliance menu."""

    label: str
    icon: str
    items: tuple[WpItem, ...]

    @property
    def flat(self) -> bool:
        return len(self.items) == 1 and self.items[0].label == self.label


# Shorthand for the column tuples below.
def _c(key, label, kind="text"):
    return (key, label, kind)


# (group label, icon, ((item key, item label, icon, special,
#                       ((tab label, logical, columns), …)), …))
# Tab order = FortiWeb's own tab order (7.6.4 admin guide): dependencies first.
_TREE = (
    ("Known Attacks", "bi-bug", (
        ("signatures", "Signatures", "bi-fingerprint", "signatures", (
            ("Signature Policy", "signature", (
                _c("custom-protection-group", "Custom Signature Group", "ref"),
                _c("sensitivity-level", "Sensitivity Level"),
                _c("comment", "Comments"),
            )),
        )),
        ("custom-signature", "Custom Signature", "bi-pencil-square", "", (
            ("Custom Signature", "signature_group_rule", (
                _c("type", "Direction", "enum"),
                _c("action", "Action", "enum"),
                _c("severity", "Severity", "enum"),
                _c("threat-weight", "Threat Weight", "enum"),
            )),
            ("Custom Signature Group", "signature_group", (
                _c("sz_type-list", "Custom Signatures", "count"),
                _c("max-alert-interval", "Max Alert Interval"),
            )),
        )),
    )),
    ("Protocol", "bi-hdd-network", (
        ("http", "HTTP", "bi-globe", "", (
            ("HTTP Protocol Constraints", "http_protocol", (
                _c("exception_name", "Exception Name", "ref"),
            )),
            ("HTTP Constraints Exceptions", "http_constraint_exception", (
                _c("sz_http_constraints-exception-list", "Entries", "count"),
            )),
        )),
        ("websocket", "WebSocket", "bi-plug", "", (
            ("WebSocket Security Rule", "websocket_security_rule", (
                _c("host", "Host", "host"),
                _c("action", "Action", "enum"),
                _c("severity", "Severity", "enum"),
            )),
            ("WebSocket Security Policy", "websocket_security_policy", (
                _c("sz_rule-list", "Rules", "count"),
            )),
        )),
        ("grpc", "gRPC", "bi-diagram-2", "", (
            ("gRPC IDL File", "grpc_idl_file", ()),
            ("gRPC Security Rule", "grpc_security_rule", (
                _c("host", "Host", "host"),
                _c("action", "Action", "enum"),
                _c("severity", "Severity", "enum"),
            )),
            ("gRPC Security Policy", "grpc_security_policy", (
                _c("enable-signature-detection", "Signature Detection", "onoff"),
                _c("sz_rule-list", "Rules", "count"),
            )),
        )),
    )),
    ("Access", "bi-door-open", (
        ("url-access", "URL Access", "bi-link-45deg", "", (
            ("URL Access Parameter", "url_access_rules_parameter", ()),
            ("URL Access Rule", "url_access_rule", (
                _c("host", "Host", "host"),
                _c("action", "Action", "enum"),
                _c("severity", "Severity", "enum"),
                _c("trigger", "Trigger Policy", "ref"),
            )),
            ("URL Access Policy", "url_access_policy", (
                _c("sz_rule", "Rules", "count"),
            )),
        )),
        ("allow-method", "Allow Method", "bi-check2-square", "", (
            ("Allow Method Policy", "allow_method_policy", (
                _c("allow-method", "Allow Request"),
                _c("severity", "Severity", "enum"),
                _c("allow-method-exception", "Allow Method Exceptions", "ref"),
            )),
            ("Allow Method Exceptions", "allow_method_exception", (
                _c("sz_allow-method-exception-list", "Entries", "count"),
            )),
        )),
        ("cors", "CORS Protection", "bi-arrow-left-right", "", (
            ("Allowed Origin", "cors_allow_origins", (
                _c("sz_origin-list", "Origins", "count"),
            )),
            ("CORS Protection Rule", "cors_protection_rule", (
                _c("host", "Host", "host"),
                _c("request-file", "URL Pattern"),
            )),
            ("CORS Protection Policy", "cors_protection_policy", (
                _c("sz_rule-list", "Rules", "count"),
            )),
        )),
    )),
    ("Input Validation", "bi-input-cursor-text", (
        ("parameter-validation", "Parameter Validation", "bi-sliders", "", (
            ("Parameter Validation Rule", "parameter_input_rule", (
                _c("host", "Host", "host"),
                _c("request-file", "Post URL"),
                _c("action", "Action", "enum"),
                _c("severity", "Severity", "enum"),
            )),
            ("Parameter Validation Policy", "parameter_validation_policy", (
                _c("sz_input-rule-list", "Rules", "count"),
            )),
        )),
        ("hidden-fields", "Hidden Fields", "bi-eye-slash", "", (
            ("Hidden Fields Rule", "hidden_field_rule", (
                _c("host", "Host", "host"),
                _c("request-file", "Request URL"),
                _c("action", "Action", "enum"),
                _c("severity", "Severity", "enum"),
            )),
            ("Hidden Fields Policy", "hidden_field_protection_policy", (
                _c("sz_hidden_fields_list", "Rules", "count"),
            )),
        )),
        ("file-security", "File Security", "bi-file-earmark-lock", "", (
            ("File Security Rule", "file_security_rule", (
                _c("type", "Type", "enum"),
                _c("host", "Host", "host"),
                _c("request-file", "Request URL"),
                _c("file-size-limit", "File Upload Limit (KB)"),
            )),
            ("File Security Policy", "file_security_policy", (
                _c("action", "Action", "enum"),
                _c("severity", "Severity", "enum"),
                _c("av-scan", "Antivirus Scan", "onoff"),
                _c("sz_rule", "Rules", "count"),
            )),
            ("Custom File Type", "file_security_file_type", (
                _c("file-extension", "File Extension"),
            )),
            ("File Security Exception", "fiel_exception_policy", ()),
        )),
        ("web-shell", "Web Shell Detection", "bi-terminal-x", "", (
            ("Web Shell Detection Policy", "web_shell_detection_policy", (
                _c("action", "Action", "enum"),
                _c("severity", "Severity", "enum"),
                _c("fuzzy-similarity-threshold", "Fuzzy Similarity Threshold (%)"),
            )),
        )),
    )),
    ("Cookie Security", "bi-shield-lock", (
        ("cookie-security", "Cookie Security", "bi-shield-lock", "", (
            ("Cookie Security Policy", "cookie_security", (
                _c("security-mode", "Security Mode", "enum"),
                _c("action", "Action", "enum"),
                _c("severity", "Severity", "enum"),
                _c("sz_cookie-security-exception-list", "Cookie Exceptions", "count"),
            )),
        )),
    )),
    ("Advanced Protection", "bi-shield-shaded", (
        ("custom-policy", "Custom Policy", "bi-list-stars", "", (
            ("Custom Rule", "custom_rule", (
                _c("action", "Action", "enum"),
                _c("severity", "Severity", "enum"),
                _c("bot-confirmation", "Bot Confirmation", "onoff"),
            )),
            ("Custom Policy", "custom_policy", (
                _c("threat-weight", "Threat Weight", "enum"),
                _c("sz_rule", "Rules", "count"),
            )),
        )),
        ("padding-oracle", "Padding Oracle Protection", "bi-braces-asterisk", "", (
            ("Padding Oracle Protection", "padding_oracle", (
                _c("action", "Action", "enum"),
                _c("severity", "Severity", "enum"),
                _c("sz_protected-url-list", "Protected URLs", "count"),
            )),
        )),
        ("csrf", "CSRF Protection", "bi-arrow-repeat", "", (
            ("CSRF Protection", "csrf_protection", (
                _c("action", "Action", "enum"),
                _c("severity", "Severity", "enum"),
                _c("sz_csrf-page-list", "Page List", "count"),
                _c("sz_csrf-url-list", "URL List", "count"),
            )),
        )),
        ("header-security", "HTTP Header Security", "bi-card-heading", "", (
            ("HTTP Header Security Policy", "http_header_security", (
                _c("sz_http-header-security-list", "Secure Headers", "count"),
            )),
            ("HTTP Header Security Policy Exception", "http_header_security_exception", (
                _c("sz_list", "Entries", "count"),
            )),
        )),
        ("mitb", "Man in the Browser Protection", "bi-browser-chrome", "", (
            ("Man in the Browser Protection Rule", "mitb_rule", (
                _c("host", "Host", "host"),
                _c("request-file", "Request URL"),
            )),
            ("Man in the Browser Protection Policy", "mitb_protection_policy", (
                _c("sz_rule-list", "Rules", "count"),
            )),
        )),
        ("url-encryption", "URL Encryption", "bi-lock", "", (
            ("URL Encryption Rule", "url_encryption_rule", (
                _c("host", "Host", "host"),
                _c("allow-unencrypted", "Allow Unencrypted", "onoff"),
                _c("action", "Action", "enum"),
                _c("severity", "Severity", "enum"),
            )),
            ("URL Encryption Policy", "url_encryption_policy", (
                _c("full-mode", "Full Mode", "onoff"),
                _c("sz_rule-list", "Rules", "count"),
            )),
        )),
        ("link-cloaking", "Link Cloaking", "bi-incognito", "", (
            ("Link Cloaking Rule", "link_cloaking_rule", (
                _c("host", "Host", "host"),
                _c("url-pattern", "URL Pattern"),
            )),
            ("Link Cloaking Policy", "link_cloaking_policy", (
                _c("sz_rule-list", "Rules", "count"),
            )),
        )),
        ("syntax-detection", "SQL/XSS Syntax Based Detection", "bi-code-slash", "", (
            ("SQL/XSS Syntax Based Detection", "syntax_based_detection", (
                _c("detection-target-sql", "SQL Scan Target"),
                _c("detection-target-xss", "XSS Scan Target"),
            )),
        )),
    )),
    ("Data Loss Prevention", "bi-droplet-half", (
        ("dlp", "Data Loss Prevention", "bi-droplet-half", "", (
            ("DLP Dictionary", "waf_dlp_dictionary", (
                _c("match-type", "Match Type", "enum"),
                _c("sz_entries", "Entries", "count"),
                _c("comment", "Comments"),
            )),
            ("DLP Sensor", "waf_dlp_sensor", (
                _c("match-type", "Match Type", "enum"),
            )),
            ("DLP Rule", "waf_dlp_rule", (
                _c("direction", "Direction", "enum"),
                _c("sensor", "Sensor", "ref"),
                _c("action", "Action", "enum"),
                _c("severity", "Severity", "enum"),
            )),
            ("DLP Policy", "dlp_policy", (
                _c("exception", "Exception", "ref"),
                _c("sz_dlp-rules", "Rules", "count"),
            )),
            ("DLP Exception", "dlp_exception", (
                _c("sz_exception-list", "Entries", "count"),
            )),
        )),
    )),
)


@lru_cache(maxsize=1)
def _registry_index() -> dict:
    """``logical name → endpoint dict`` from the live registry loader."""
    from ..registry import loader
    return {e.get("name"): e for e in loader.get_all_endpoints()
            if isinstance(e, dict) and e.get("name")}


def _collection(urn: str) -> str:
    """Bare cmdb collection from a REST urn."""
    if "/cmdb/" in urn:
        return urn.split("/cmdb/", 1)[1].strip("/")
    return urn.strip("/")


@lru_cache(maxsize=1)
def menu() -> tuple[WpGroup, ...]:
    """The resolved menu (missing logicals dropped, empty items/groups dropped)."""
    idx = _registry_index()
    groups: list[WpGroup] = []
    for glabel, gicon, items in _TREE:
        out_items: list[WpItem] = []
        for key, label, icon, special, tabs in items:
            out_tabs: list[WpTab] = []
            for tlabel, logical, cols in tabs:
                ep = idx.get(logical)
                if not ep:
                    continue
                urn = ep.get("urn") or ep.get("path") or ""
                out_tabs.append(WpTab(
                    label=tlabel, logical=logical,
                    collection=_collection(urn), urn=urn,
                    columns=tuple(WpCol(key=k, label=l, kind=kd)
                                  for k, l, kd in cols)))
            if out_tabs:
                out_items.append(WpItem(key=key, label=label, icon=icon,
                                        tabs=tuple(out_tabs), special=special))
        if out_items:
            groups.append(WpGroup(label=glabel, icon=gicon, items=tuple(out_items)))
    return tuple(groups)


def item_for(key: str) -> WpItem | None:
    for g in menu():
        for it in g.items:
            if it.key == key:
                return it
    return None


def tab_for(item: WpItem, logical: str) -> WpTab | None:
    for t in item.tabs:
        if t.logical == logical:
            return t
    return None


def iter_items():
    for g in menu():
        yield from g.items


__all__ = ["WpCol", "WpTab", "WpItem", "WpGroup", "menu", "item_for", "tab_for",
           "iter_items"]
