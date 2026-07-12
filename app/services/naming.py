"""Naming scheme — one place to decide how every object is named, so a whole
policy/virtual-server can be derived from a single web address.

★ Why this exists (read me). When an operator stands up a new site they should
type ONE thing — the web address (e.g. ``shop.example.com``) — and the manager
derives every dependent object's name from it. The *patterns* used to build
those names are team convention, so they live in config (Naming page), not in
code.

★ Two products. FortiWeb and FortiADC have different object models, so the
naming catalog is split by **product**: each element declares which product it
belongs to (:data:`PRODUCTS`), and the editor shows one product at a time via a
selector. Overrides are stored per product (see ``services.settings_store``).

This module is the pure engine behind that screen:

* :data:`NAMING_ELEMENTS` — the catalog of nameable objects (both products),
  each with a sensible default pattern.
* :func:`slugify` — turn a web address into a FortiWeb/FortiADC-safe token.
* :func:`render_names` — apply a scheme to a web address → ``{key: name}``.

No Qt, no network, no I/O: the patterns are passed in by the caller.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# The single substitution token a pattern may contain: the site identifier.
TOKEN = "{name}"

# Certificate names carry MORE than the site id — the class (server/client/…),
# the CN, the issue date (so the OLD and NEW cert coexist during a maintenance
# window) and optionally a short serial. These tokens are only meaningful for the
# Certificate Manager element and are substituted by :func:`render_cert_name`.
CERT_TOKENS = ("{class}", "{cn}", "{date}", "{serial}")
# Default strftime format for the {date} token (admin-overridable in Settings →
# Certificate Manager). ``20260701`` keeps names short and lexically sortable.
DEFAULT_CERT_DATE_FORMAT = "%Y%m%d"

# Object names (mkey) are bounded; keep derived names within a safe ceiling so a
# long domain can't produce an illegal name.
MAX_NAME_LEN = 63

# ── Products ────────────────────────────────────────────────────────────────
PRODUCT_FORTIWEB = "fortiweb"
PRODUCT_FORTIADC = "fortiadc"

# (key, label) in display order — drives the product selector on the page.
# Derived LIVE from the ADOM registry (``cap_naming``); a live sequence so the
# selector reflects Settings → ADOMs edits without a code change.
from ..branding import naming_products as _naming_products  # noqa: E402

PRODUCTS = _naming_products()
DEFAULT_PRODUCT = PRODUCT_FORTIWEB


def _product_keys() -> set[str]:
    return {p for p, _ in PRODUCTS}


def valid_product(product: str | None) -> str:
    """Sanitise a product id from the request → a known product (else default)."""
    return product if product in _product_keys() else DEFAULT_PRODUCT


@dataclass(frozen=True)
class NamingElement:
    """One nameable object.

    ``key`` — stable id used as the config key (unique across all products).
    ``label`` — what the editor shows. ``section`` — grouping in the editor.
    ``default`` — the out-of-the-box pattern (must normally contain
    :data:`TOKEN`). ``product`` — which product it belongs to. ``note`` — a
    hint/caveat.
    """

    key: str
    label: str
    section: str
    default: str
    product: str = PRODUCT_FORTIWEB
    note: str = ""


# ── FortiWeb sections ─────────────────────────────────────────────────────────
SECTION_POLICY = "Server Policy"
SECTION_WPP = "Web Protection Profile"
SECTION_CERT = "Certificate Manager"

# ── FortiADC sections ─────────────────────────────────────────────────────────
SECTION_ADC_SLB = "Server Load Balance"
SECTION_ADC_SSL = "SSL"

# The catalog. Order = display order. FortiWeb defaults match
# services/seed_data.py so a fresh install already names things the way the seed
# library does; FortiADC defaults follow the same dash-prefixed convention.
NAMING_ELEMENTS: tuple[NamingElement, ...] = (
    # ─────────────────────────── FortiWeb ───────────────────────────────────
    # Server Policy + server objects (mirrors build_policy)
    NamingElement("server_policy", "Server Policy", SECTION_POLICY,
                  "pol-{name}", PRODUCT_FORTIWEB, "The root object (server-policy/policy)."),
    NamingElement("virtual_server", "Virtual Server", SECTION_POLICY, "vs-{name}", PRODUCT_FORTIWEB),
    NamingElement("vip", "Virtual IP (VIP)", SECTION_POLICY, "vip-{name}", PRODUCT_FORTIWEB),
    NamingElement("server_pool", "Server Pool", SECTION_POLICY, "pool-{name}", PRODUCT_FORTIWEB),
    NamingElement("health_check", "Health Check", SECTION_POLICY, "hc-{name}", PRODUCT_FORTIWEB),
    NamingElement("persistence", "Persistence", SECTION_POLICY, "persist-{name}", PRODUCT_FORTIWEB),
    NamingElement("content_routing", "Content Routing", SECTION_POLICY, "cr-{name}", PRODUCT_FORTIWEB),
    NamingElement("session_cookie", "Session cookie", SECTION_POLICY, "FWB-{name}", PRODUCT_FORTIWEB,
                  "Name of the persistence/session cookie."),
    NamingElement("certificate", "Local certificate", SECTION_POLICY, "cert-{name}", PRODUCT_FORTIWEB,
                  "Creating/installing the cert is SSH-only; here just the reference name."),
    # Web Protection Profile + its sub-policies (mirrors build_wpp)
    NamingElement("web_protection_profile", "Web Protection Profile", SECTION_WPP,
                  "wpp-{name}", PRODUCT_FORTIWEB),
    NamingElement("http_constraint", "HTTP Protocol Constraints", SECTION_WPP,
                  "httpc-{name}", PRODUCT_FORTIWEB),
    NamingElement("x_forward", "X-Forwarded-For", SECTION_WPP, "xff-{name}", PRODUCT_FORTIWEB),
    NamingElement("allow_method", "Allow Method", SECTION_WPP, "allowm-{name}", PRODUCT_FORTIWEB),
    NamingElement("ip_list", "IP List", SECTION_WPP, "iplist-{name}", PRODUCT_FORTIWEB),
    NamingElement("geo", "Geo Block List", SECTION_WPP, "geo-{name}", PRODUCT_FORTIWEB),
    NamingElement("cookie_security", "Cookie Security", SECTION_WPP, "cookie-{name}", PRODUCT_FORTIWEB),
    NamingElement("csrf", "CSRF Protection", SECTION_WPP, "csrf-{name}", PRODUCT_FORTIWEB),
    NamingElement("padding_oracle", "Padding Oracle", SECTION_WPP, "padding-{name}", PRODUCT_FORTIWEB),
    NamingElement("http_header_security", "HTTP Header Security", SECTION_WPP,
                  "hdrsec-{name}", PRODUCT_FORTIWEB),
    NamingElement("parameter_validation", "Parameter Validation", SECTION_WPP,
                  "paramval-{name}", PRODUCT_FORTIWEB),
    NamingElement("hidden_fields", "Hidden Fields", SECTION_WPP, "hidden-{name}", PRODUCT_FORTIWEB),
    NamingElement("file_upload", "File Upload", SECTION_WPP, "fileup-{name}", PRODUCT_FORTIWEB),
    NamingElement("url_access", "URL Access", SECTION_WPP, "urlacc-{name}", PRODUCT_FORTIWEB),
    NamingElement("bot_mitigation", "Bot Mitigation", SECTION_WPP, "bot-{name}", PRODUCT_FORTIWEB),
    NamingElement("wpp_exception", "Exception WPP (per-policy clone)", SECTION_WPP,
                  "wpp-{name}", PRODUCT_FORTIWEB,
                  "Name of the WPP clone the Exceptions page creates when a Server "
                  "Policy needs a carve-out on a template-managed profile. Here "
                  "{name} is the SERVER POLICY's name (templates stay clean; the "
                  "exception lands on the per-policy clone)."),
    # Certificate Manager — the ADCS-signed cert name. Uses the cert tokens
    # {class}/{cn}/{date}/{serial} (NOT {name}); {date} keeps the old + new cert
    # distinct so both can live on the box during a maintenance-window swap.
    NamingElement("managed_certificate", "Managed Certificate", SECTION_CERT,
                  "cert-{class}-{cn}-{date}", PRODUCT_FORTIWEB,
                  "Tokens: {class} {cn} {date} {serial}. The {date} makes the old "
                  "and new cert coexist during a maintenance-window swap."),
    # ─────────────────────────── FortiADC ───────────────────────────────────
    # Server Load Balance objects (FortiADC's SLB model)
    NamingElement("adc_virtual_server", "Virtual Server", SECTION_ADC_SLB,
                  "vs-{name}", PRODUCT_FORTIADC, "The root SLB object (load-balance/virtual-server)."),
    NamingElement("adc_real_server", "Real Server", SECTION_ADC_SLB, "rs-{name}", PRODUCT_FORTIADC),
    NamingElement("adc_real_server_pool", "Real Server Pool", SECTION_ADC_SLB,
                  "pool-{name}", PRODUCT_FORTIADC),
    NamingElement("adc_health_check", "Health Check", SECTION_ADC_SLB, "hc-{name}", PRODUCT_FORTIADC),
    NamingElement("adc_persistence", "Persistence", SECTION_ADC_SLB, "persist-{name}", PRODUCT_FORTIADC),
    NamingElement("adc_lb_method", "Load Balance Method", SECTION_ADC_SLB,
                  "method-{name}", PRODUCT_FORTIADC),
    NamingElement("adc_content_routing", "Content Routing", SECTION_ADC_SLB,
                  "cr-{name}", PRODUCT_FORTIADC),
    NamingElement("adc_content_rewriting", "Content Rewriting", SECTION_ADC_SLB,
                  "rw-{name}", PRODUCT_FORTIADC),
    NamingElement("adc_schedule_pool", "Schedule Pool", SECTION_ADC_SLB,
                  "sched-{name}", PRODUCT_FORTIADC),
    NamingElement("adc_error_page", "Error Page", SECTION_ADC_SLB, "errpage-{name}", PRODUCT_FORTIADC),
    # SSL profiles / certificate
    NamingElement("adc_client_ssl_profile", "Client SSL Profile", SECTION_ADC_SSL,
                  "csslp-{name}", PRODUCT_FORTIADC),
    NamingElement("adc_server_ssl_profile", "Server SSL Profile", SECTION_ADC_SSL,
                  "ssslp-{name}", PRODUCT_FORTIADC),
    NamingElement("adc_certificate", "Local certificate", SECTION_ADC_SSL,
                  "cert-{name}", PRODUCT_FORTIADC,
                  "Creating/installing the cert is out of band; here just the reference name."),
)

_BY_KEY = {e.key: e for e in NAMING_ELEMENTS}


# --------------------------------------------------------------------------- #
#  Product scoping                                                            #
# --------------------------------------------------------------------------- #
def products() -> tuple[tuple[str, str], ...]:
    """``((key, label), …)`` for the product selector."""
    return PRODUCTS


def elements_for_product(product: str = DEFAULT_PRODUCT) -> tuple[NamingElement, ...]:
    """The catalog filtered to one product, preserving order."""
    product = valid_product(product)
    return tuple(e for e in NAMING_ELEMENTS if e.product == product)


# --------------------------------------------------------------------------- #
#  Scheme helpers                                                             #
# --------------------------------------------------------------------------- #
def default_scheme(product: str = DEFAULT_PRODUCT) -> dict[str, str]:
    """The out-of-the-box ``{key: pattern}`` for one product's elements."""
    return {e.key: e.default for e in elements_for_product(product)}


def effective_scheme(
    overrides: dict[str, str] | None, product: str = DEFAULT_PRODUCT
) -> dict[str, str]:
    """Defaults merged with user overrides for one product.

    Overrides win, but only for **known** keys with a non-empty value — so a
    cleared field transparently reverts to its default and an old config missing
    a newer element still gets a name. Order follows :data:`NAMING_ELEMENTS`.
    """
    scheme = default_scheme(product)
    for key, val in (overrides or {}).items():
        if key in scheme and isinstance(val, str) and val.strip():
            scheme[key] = val.strip()
    return scheme


def elements_by_section(product: str = DEFAULT_PRODUCT) -> dict[str, list[NamingElement]]:
    """``{section: [elements…]}`` for one product, preserving catalog order."""
    out: dict[str, list[NamingElement]] = {}
    for e in elements_for_product(product):
        out.setdefault(e.section, []).append(e)
    return out


# --------------------------------------------------------------------------- #
#  Rendering                                                                  #
# --------------------------------------------------------------------------- #
def slugify(web_address: str) -> str:
    """Turn a web address into a safe token.

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


def render_cert_name(
    pattern: str,
    *,
    cls: str,
    cn: str,
    date_str: str,
    serial: str = "",
) -> str:
    """Render a Certificate Manager name from its multi-token pattern.

    Substitutes :data:`CERT_TOKENS` — ``{class}`` (server/clientserver/client),
    ``{cn}`` (the certificate CN/hostname, slugified), ``{date}`` (the caller
    formats "now" per the configured date format) and ``{serial}`` (optional short
    serial) — and caps at :data:`MAX_NAME_LEN`. Empty tokens collapse cleanly so a
    missing ``{serial}`` never leaves a dangling separator.
    """
    out = (pattern or "cert-{class}-{cn}-{date}")
    out = out.replace("{class}", (cls or "").strip().lower())
    out = out.replace("{cn}", slugify(cn) or (cn or "").strip().lower())
    out = out.replace("{date}", (date_str or "").strip())
    out = out.replace("{serial}", (serial or "").strip())
    # collapse any separator runs left by an empty token, then trim
    out = re.sub(r"[-_.]{2,}", "-", out).strip("-_.")
    return out[:MAX_NAME_LEN]


def render_names(
    web_address: str,
    overrides: dict[str, str] | None = None,
    product: str = DEFAULT_PRODUCT,
) -> dict[str, str]:
    """``{element_key: derived_name}`` for one product's elements, from one
    web address.

    This is what a "new object from just a web address" flow consumes: the
    operator types the address, this returns the full naming map for the chosen
    product's objects.
    """
    slug = slugify(web_address)
    return {
        key: render_one(pat, slug)
        for key, pat in effective_scheme(overrides, product).items()
    }


__all__ = [
    "TOKEN",
    "CERT_TOKENS",
    "DEFAULT_CERT_DATE_FORMAT",
    "SECTION_CERT",
    "render_cert_name",
    "MAX_NAME_LEN",
    "PRODUCT_FORTIWEB",
    "PRODUCT_FORTIADC",
    "PRODUCTS",
    "DEFAULT_PRODUCT",
    "valid_product",
    "NamingElement",
    "NAMING_ELEMENTS",
    "SECTION_POLICY",
    "SECTION_WPP",
    "SECTION_ADC_SLB",
    "SECTION_ADC_SSL",
    "products",
    "elements_for_product",
    "default_scheme",
    "effective_scheme",
    "elements_by_section",
    "slugify",
    "render_one",
    "render_names",
]
