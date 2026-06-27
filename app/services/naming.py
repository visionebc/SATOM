"""Naming scheme — one place to decide how every object in a Server Policy is
named, so a whole policy can be derived from a single web address.

★ Why this exists (read me). When an operator stands up a new site they should
type ONE thing — the web address (e.g. ``shop.example.com``) — and the manager
derives every dependent object's name from it: the policy, its virtual server,
VIP, server pool, health check, persistence, content-routing and Web Protection
Profile (+ its ~14 sub-policies). The *patterns* used to build those names are
team convention, so they live in config (Settings → Naming), not in code.

This module is the pure engine behind that screen:

* :data:`NAMING_ELEMENTS` — the catalog of nameable objects, each with a sensible
  default pattern that mirrors the conventions already used in
  ``services/seed_data.py`` (``vs-…``/``pool-…``/``hc-…``/``wpp-…`` …).
* :func:`slugify` — turn a web address into a FortiWeb-safe token.
* :func:`render_names` — apply a scheme to a web address → ``{key: name}``.

No Qt, no network, no I/O: the patterns are passed in by the caller (the GUI
reads/writes them on :class:`core.config.AppConfig`). Mirrors the "pure data +
helpers, headless-testable" shape of ``registry/dependencies.py``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# The single substitution token a pattern may contain: the site identifier.
TOKEN = "{name}"

# FortiWeb object names (mkey) are bounded; keep derived names within a safe
# ceiling so a long domain can't produce an illegal name.
MAX_NAME_LEN = 63


@dataclass(frozen=True)
class NamingElement:
    """One nameable object in a Server Policy / Web Protection Profile.

    ``key`` — stable id used as the config key. ``label`` — what the editor
    shows. ``section`` — grouping in the editor. ``default`` — the out-of-the-box
    pattern (must normally contain :data:`TOKEN`). ``note`` — a hint/caveat.
    """

    key: str
    label: str
    section: str
    default: str
    note: str = ""


SECTION_POLICY = "Server Policy"
SECTION_WPP = "Web Protection Profile"

# The catalog. Order = display order. Defaults match services/seed_data.py so a
# fresh install already names things the way the seed library does.
NAMING_ELEMENTS: tuple[NamingElement, ...] = (
    # ── Server Policy + server objects (mirrors build_policy) ────────────────
    NamingElement("server_policy", "Server Policy", SECTION_POLICY,
                  "pol-{name}", "The root object (server-policy/policy)."),
    NamingElement("virtual_server", "Virtual Server", SECTION_POLICY, "vs-{name}"),
    NamingElement("vip", "Virtual IP (VIP)", SECTION_POLICY, "vip-{name}"),
    NamingElement("server_pool", "Server Pool", SECTION_POLICY, "pool-{name}"),
    NamingElement("health_check", "Health Check", SECTION_POLICY, "hc-{name}"),
    NamingElement("persistence", "Persistence", SECTION_POLICY, "persist-{name}"),
    NamingElement("content_routing", "Content Routing", SECTION_POLICY, "cr-{name}"),
    NamingElement("session_cookie", "Session cookie", SECTION_POLICY, "FWB-{name}",
                  "Name of the persistence/session cookie."),
    NamingElement("certificate", "Local certificate", SECTION_POLICY, "cert-{name}",
                  "Creating/installing the cert is SSH-only; here just the reference name."),
    # ── Web Protection Profile + its sub-policies (mirrors build_wpp) ─────────
    NamingElement("web_protection_profile", "Web Protection Profile", SECTION_WPP,
                  "wpp-{name}"),
    NamingElement("http_constraint", "HTTP Protocol Constraints", SECTION_WPP,
                  "httpc-{name}"),
    NamingElement("x_forward", "X-Forwarded-For", SECTION_WPP, "xff-{name}"),
    NamingElement("allow_method", "Allow Method", SECTION_WPP, "allowm-{name}"),
    NamingElement("ip_list", "IP List", SECTION_WPP, "iplist-{name}"),
    NamingElement("geo", "Geo Block List", SECTION_WPP, "geo-{name}"),
    NamingElement("cookie_security", "Cookie Security", SECTION_WPP, "cookie-{name}"),
    NamingElement("csrf", "CSRF Protection", SECTION_WPP, "csrf-{name}"),
    NamingElement("padding_oracle", "Padding Oracle", SECTION_WPP, "padding-{name}"),
    NamingElement("http_header_security", "HTTP Header Security", SECTION_WPP,
                  "hdrsec-{name}"),
    NamingElement("parameter_validation", "Parameter Validation", SECTION_WPP,
                  "paramval-{name}"),
    NamingElement("hidden_fields", "Hidden Fields", SECTION_WPP, "hidden-{name}"),
    NamingElement("file_upload", "File Upload", SECTION_WPP, "fileup-{name}"),
    NamingElement("url_access", "URL Access", SECTION_WPP, "urlacc-{name}"),
    NamingElement("bot_mitigation", "Bot Mitigation", SECTION_WPP, "bot-{name}"),
)

_BY_KEY = {e.key: e for e in NAMING_ELEMENTS}


# --------------------------------------------------------------------------- #
#  Scheme helpers                                                             #
# --------------------------------------------------------------------------- #
def default_scheme() -> dict[str, str]:
    """The out-of-the-box ``{key: pattern}`` for every element."""
    return {e.key: e.default for e in NAMING_ELEMENTS}


def effective_scheme(overrides: dict[str, str] | None) -> dict[str, str]:
    """Defaults merged with user overrides.

    Overrides win, but only for **known** keys with a non-empty value — so a
    cleared field transparently reverts to its default and an old config missing
    a newer element still gets a name. Order follows :data:`NAMING_ELEMENTS`.
    """
    scheme = default_scheme()
    for key, val in (overrides or {}).items():
        if key in scheme and isinstance(val, str) and val.strip():
            scheme[key] = val.strip()
    return scheme


def elements_by_section() -> dict[str, list[NamingElement]]:
    """``{section: [elements…]}`` preserving catalog order — drives the editor."""
    out: dict[str, list[NamingElement]] = {}
    for e in NAMING_ELEMENTS:
        out.setdefault(e.section, []).append(e)
    return out


# --------------------------------------------------------------------------- #
#  Rendering                                                                  #
# --------------------------------------------------------------------------- #
def slugify(web_address: str) -> str:
    """Turn a web address into a FortiWeb-safe token.

    ``https://Shop.Example.com:8443/path?x=1`` → ``shop-example-com``. Lowercases,
    drops scheme/port/path/query, and collapses any run of non ``[a-z0-9]`` to a
    single ``-``. Returns ``""`` for empty/garbage input (caller decides).
    """
    s = web_address.strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)  # strip scheme
    s = s.split("/", 1)[0].split("?", 1)[0]      # drop path/query
    s = s.split(":", 1)[0]                        # drop :port
    s = re.sub(r"[^a-z0-9]+", "-", s)            # everything else → dash
    return s.strip("-")


def render_one(pattern: str, slug: str) -> str:
    """Apply one pattern to an already-computed slug (capped at the safe length)."""
    return pattern.replace(TOKEN, slug)[:MAX_NAME_LEN]


def render_names(
    web_address: str, overrides: dict[str, str] | None = None
) -> dict[str, str]:
    """``{element_key: derived_name}`` for every element, from one web address.

    This is what a "new policy from just a web address" flow consumes: the
    operator types the address, this returns the full naming map for the policy
    and all its dependencies.
    """
    slug = slugify(web_address)
    return {key: render_one(pat, slug) for key, pat in effective_scheme(overrides).items()}


__all__ = [
    "TOKEN",
    "MAX_NAME_LEN",
    "NamingElement",
    "NAMING_ELEMENTS",
    "SECTION_POLICY",
    "SECTION_WPP",
    "default_scheme",
    "effective_scheme",
    "elements_by_section",
    "slugify",
    "render_one",
    "render_names",
]
