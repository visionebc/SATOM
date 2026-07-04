"""FortiWeb 7.6 GUI **Web Protection** menu — an exact mirror of the appliance's
own left menu, so operators who know FortiWeb navigate the web app the same way.

Tree harvested from the FortiWeb 7.6.4 administration guide (Firecrawl scrape of
the whole Web Protection chapter, every ``Go to Web Protection > …`` GUI path)
on 2026-07-04:

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

Each menu item renders as ONE page whose TABS are FortiWeb's own tabs (e.g.
URL Access → "URL Access Policy" | "URL Access Rule" | "URL Access Parameter").
Every tab is a registry logical endpoint; a logical a firmware doesn't ship is
silently dropped at build time (same contract as ``config_sections``).

Pure data + registry matching — no Flask, no device.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class WpTab:
    """One FortiWeb tab inside a menu-item page (one object type)."""

    label: str          # the FortiWeb tab title ("URL Access Rule")
    logical: str        # registry logical endpoint name
    collection: str     # bare cmdb collection (waf/url-access.url-access-rule)
    urn: str            # resolved REST urn


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


# (group label, icon, ((item key, item label, icon, special,
#                       ((tab label, logical), …)), …))
_TREE = (
    ("Known Attacks", "bi-bug", (
        ("signatures", "Signatures", "bi-fingerprint", "signatures", (
            ("Signature Policy", "signature"),
        )),
        ("custom-signature", "Custom Signature", "bi-pencil-square", "", (
            ("Custom Signature Group", "signature_group"),
            ("Custom Signature", "signature_group_rule"),
        )),
    )),
    ("Protocol", "bi-hdd-network", (
        ("http", "HTTP", "bi-globe", "", (
            ("HTTP Protocol Constraints", "http_protocol"),
            ("HTTP Constraints Exceptions", "http_constraint_exception"),
        )),
        ("websocket", "WebSocket", "bi-plug", "", (
            ("WebSocket Security Policy", "websocket_security_policy"),
            ("WebSocket Security Rule", "websocket_security_rule"),
        )),
        ("grpc", "gRPC", "bi-diagram-2", "", (
            ("gRPC Security Policy", "grpc_security_policy"),
            ("gRPC Security Rule", "grpc_security_rule"),
            ("gRPC IDL File", "grpc_idl_file"),
        )),
    )),
    ("Access", "bi-door-open", (
        ("url-access", "URL Access", "bi-link-45deg", "", (
            ("URL Access Policy", "url_access_policy"),
            ("URL Access Rule", "url_access_rule"),
            ("URL Access Parameter", "url_access_rules_parameter"),
        )),
        ("allow-method", "Allow Method", "bi-check2-square", "", (
            ("Allow Method Policy", "allow_method_policy"),
            ("Allow Method Exceptions", "allow_method_exception"),
        )),
        ("cors", "CORS Protection", "bi-arrow-left-right", "", (
            ("CORS Protection Policy", "cors_protection_policy"),
            ("CORS Protection Rule", "cors_protection_rule"),
        )),
    )),
    ("Input Validation", "bi-input-cursor-text", (
        ("parameter-validation", "Parameter Validation", "bi-sliders", "", (
            ("Parameter Validation Policy", "parameter_validation_policy"),
            ("Parameter Validation Rule", "parameter_input_rule"),
        )),
        ("hidden-fields", "Hidden Fields", "bi-eye-slash", "", (
            ("Hidden Fields Policy", "hidden_field_protection_policy"),
            ("Hidden Fields Rule", "hidden_field_rule"),
        )),
        ("file-security", "File Security", "bi-file-earmark-lock", "", (
            ("File Security Policy", "file_security_policy"),
            ("File Security Rule", "file_security_rule"),
            ("Custom File Type", "file_security_file_type"),
            ("File Security Exception", "fiel_exception_policy"),
        )),
        ("web-shell", "Web Shell Detection", "bi-terminal-x", "", (
            ("Web Shell Detection Policy", "web_shell_detection_policy"),
        )),
    )),
    ("Cookie Security", "bi-shield-lock", (
        ("cookie-security", "Cookie Security", "bi-shield-lock", "", (
            ("Cookie Security Policy", "cookie_security"),
        )),
    )),
    ("Advanced Protection", "bi-shield-shaded", (
        ("custom-policy", "Custom Policy", "bi-list-stars", "", (
            ("Custom Policy", "custom_policy"),
            ("Custom Rule", "custom_rule"),
        )),
        ("padding-oracle", "Padding Oracle Protection", "bi-braces-asterisk", "", (
            ("Padding Oracle Protection", "padding_oracle"),
        )),
        ("csrf", "CSRF Protection", "bi-arrow-repeat", "", (
            ("CSRF Protection", "csrf_protection"),
        )),
        ("header-security", "HTTP Header Security", "bi-card-heading", "", (
            ("HTTP Header Security Policy", "http_header_security"),
            ("HTTP Header Security Policy Exception", "http_header_security_exception"),
        )),
        ("mitb", "Man in the Browser Protection", "bi-browser-chrome", "", (
            ("Man in the Browser Protection Policy", "mitb_protection_policy"),
            ("Man in the Browser Protection Rule", "mitb_rule"),
        )),
        ("url-encryption", "URL Encryption", "bi-lock", "", (
            ("URL Encryption Policy", "url_encryption_policy"),
            ("URL Encryption Rule", "url_encryption_rule"),
        )),
        ("link-cloaking", "Link Cloaking", "bi-incognito", "", (
            ("Link Cloaking Policy", "link_cloaking_policy"),
            ("Link Cloaking Rule", "link_cloaking_rule"),
        )),
        ("syntax-detection", "SQL/XSS Syntax Based Detection", "bi-code-slash", "", (
            ("SQL/XSS Syntax Based Detection", "syntax_based_detection"),
        )),
    )),
    ("Data Loss Prevention", "bi-droplet-half", (
        ("dlp", "Data Loss Prevention", "bi-droplet-half", "", (
            ("DLP Sensor", "waf_dlp_sensor"),
            ("DLP Rule", "waf_dlp_rule"),
            ("DLP Dictionary", "waf_dlp_dictionary"),
            ("DLP Exception", "dlp_exception"),
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
            for tlabel, logical in tabs:
                ep = idx.get(logical)
                if not ep:
                    continue
                urn = ep.get("urn") or ep.get("path") or ""
                out_tabs.append(WpTab(label=tlabel, logical=logical,
                                      collection=_collection(urn), urn=urn))
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


__all__ = ["WpTab", "WpItem", "WpGroup", "menu", "item_for", "tab_for",
           "iter_items"]
