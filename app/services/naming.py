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
* :func:`site_tokens` — the values a pattern can use for one site: the
  :data:`SITE_TOKENS` (``{name}``, ``{host}``, ``{port}``) plus the
  operator's own **variables**, each one a regular-expression rewrite of a
  token (``host_u`` = ``{host}`` with ``\\.`` → ``_``), defined per product.
* :func:`render_names` — apply a scheme to a web address → ``{key: name}``.

No Qt, no network, no I/O: the patterns and variables are passed in by the
caller.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# The site identifier: the web address, slugified. Every default pattern uses it.
TOKEN = "{name}"

#: Tokens SATOM fills in from the site itself when it builds a name:
#: ``name`` (the slug), ``host`` (the host exactly as typed, lower-cased,
#: dots kept) and ``port`` (the port the creating flow gives — the wizard's
#: Port field, the port in the address, or the flow's default).
SITE_TOKENS = ("name", "host", "port")

#: What an object name SATOM builds may contain: letters, digits, ``_`` and
#: ``-``. Operators report the devices refusing a dot in these names
#: (FA-0001), so a pattern that writes ``{host}`` as it is is refused in the
#: preview instead of being discovered on the device halfway through a run.
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")

# ── Operator variables ──────────────────────────────────────────────────────
#: A variable name: lower case, starts with a letter, no braces.
VARIABLE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
#: Names a variable may not take: the site tokens, the certificate tokens and
#: the tokens Discovery writes into the patterns it finds (a variable called
#: ``num`` would change what every discovered pattern means).
RESERVED_TOKENS = frozenset({"name", "host", "port", "class", "cn", "date", "serial",
                             "proto", "adom", "vdom", "num", "ip", "device"})
MAX_VARIABLES = 20
MAX_REGEX_LEN = 200
MAX_REPLACE_LEN = 100

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
from ..branding import _LiveSeq, naming_products as _naming_products  # noqa: E402

# Only products the catalog below has elements for: an ADOM flagged
# cap_naming with no element (FortiAuthenticator was, on a live install)
# drew an EMPTY editor. Every device ADOM still gets a Naming entry: there it
# opens Discovery (views/naming.py), which reads any product's names.
PRODUCTS = _LiveSeq(lambda: tuple((k, n) for k, n in _naming_products()
                                  if k in _catalog_products()))


def _catalog_products() -> set[str]:
    return {e.product for e in NAMING_ELEMENTS}
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
    hint/caveat. ``derives`` — a SATOM flow builds new objects' names from
    this pattern (:func:`render_names`), which fills in ``{name}`` only, so
    any other token would reach the device as literal text
    (:func:`pattern_problem` refuses it). False = the pattern documents a
    convention and is only checked against existing names.
    """

    key: str
    label: str
    section: str
    default: str
    product: str = PRODUCT_FORTIWEB
    note: str = ""
    derives: bool = True


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
                  "vs-{name}", PRODUCT_FORTIADC, "The root SLB object (load-balance/virtual-server).",
                  derives=False),
    NamingElement("adc_real_server", "Real Server", SECTION_ADC_SLB, "rs-{name}", PRODUCT_FORTIADC,
                  derives=False),
    NamingElement("adc_real_server_pool", "Real Server Pool", SECTION_ADC_SLB,
                  "pool-{name}", PRODUCT_FORTIADC,
                  derives=False),
    NamingElement("adc_health_check", "Health Check", SECTION_ADC_SLB, "hc-{name}", PRODUCT_FORTIADC,
                  derives=False),
    NamingElement("adc_persistence", "Persistence", SECTION_ADC_SLB, "persist-{name}", PRODUCT_FORTIADC,
                  derives=False),
    NamingElement("adc_lb_method", "Load Balance Method", SECTION_ADC_SLB,
                  "method-{name}", PRODUCT_FORTIADC,
                  derives=False),
    NamingElement("adc_content_routing", "Content Routing", SECTION_ADC_SLB,
                  "cr-{name}", PRODUCT_FORTIADC,
                  derives=False),
    NamingElement("adc_content_rewriting", "Content Rewriting", SECTION_ADC_SLB,
                  "rw-{name}", PRODUCT_FORTIADC,
                  derives=False),
    NamingElement("adc_schedule_pool", "Schedule Pool", SECTION_ADC_SLB,
                  "sched-{name}", PRODUCT_FORTIADC,
                  derives=False),
    NamingElement("adc_error_page", "Error Page", SECTION_ADC_SLB, "errpage-{name}", PRODUCT_FORTIADC,
                  derives=False),
    # SSL profiles / certificate
    NamingElement("adc_client_ssl_profile", "Client SSL Profile", SECTION_ADC_SSL,
                  "csslp-{name}", PRODUCT_FORTIADC,
                  derives=False),
    NamingElement("adc_server_ssl_profile", "Server SSL Profile", SECTION_ADC_SSL,
                  "ssslp-{name}", PRODUCT_FORTIADC,
                  derives=False),
    NamingElement("adc_certificate", "Local certificate", SECTION_ADC_SSL,
                  "cert-{name}", PRODUCT_FORTIADC,
                  "Creating/installing the cert is out of band; here just the reference name.",
                  derives=False),
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
#  Object types beyond the catalog                                            #
# --------------------------------------------------------------------------- #
# The catalog above is what SATOM builds names FROM. Every other object type a
# device of the product holds (the ones Discovery reads) gets a scheme entry
# too, stored in the same per-product overrides under ``table:<registry
# name>`` — a prefix no catalog key uses, so :func:`effective_scheme` (and the
# flows built on it) never see them. They carry a convention to check names
# against, so any Discovery token is allowed there.
TABLE_PREFIX = "table:"
_TOKEN_RE = re.compile(r"\{([a-z0-9_-]+)\}")


def table_key(table: str) -> str:
    return TABLE_PREFIX + table


def table_overrides(overrides: dict[str, str] | None) -> dict[str, str]:
    """``{table: pattern}`` of the object types beyond the catalog."""
    return {k[len(TABLE_PREFIX):]: v.strip() for k, v in (overrides or {}).items()
            if k.startswith(TABLE_PREFIX) and isinstance(v, str) and v.strip()}


#: Derived elements rendered from something other than a site: the
#: exception-WPP clone is named from the SERVER POLICY's name
#: (``wpp_clone_flow``), so it has a ``{name}`` and nothing else.
NAME_ONLY_ELEMENTS = frozenset({"wpp_exception"})


def allowed_tokens(key: str, variables=None) -> set[str] | None:
    """The tokens SATOM fills in for scheme entry *key* (None = not limited:
    the entry documents a convention and any Discovery token may appear)."""
    e = _BY_KEY.get(key)
    if e is None or not e.derives:
        return None
    if e.section == SECTION_CERT:
        return {"name"} | {t.strip("{}") for t in CERT_TOKENS}
    if e.key in NAME_ONLY_ELEMENTS:
        return {"name"}
    return set(SITE_TOKENS) | {v["name"] for v in normalize_variables(variables)}


def pattern_problem(key: str, pattern: str, variables=None) -> str:
    """Why *pattern* cannot be stored for scheme entry *key* ("" = it can).

    Only an element SATOM derives names from is limited: it fills in the
    :data:`SITE_TOKENS` and the product's variables (the Certificate Manager
    its cert tokens), so any other token would be written to the device
    literally."""
    pattern = (pattern or "").strip()
    if not pattern:
        return ""
    if pattern.count("{") != pattern.count("}") or "{}" in pattern:
        return "unbalanced braces"
    allowed = allowed_tokens(key, variables)
    if allowed is None:
        return ""
    extra = sorted(set(_TOKEN_RE.findall(pattern)) - allowed)
    if extra:
        return ("SATOM builds new names from this pattern and only fills in "
                + ", ".join("{" + t + "}" for t in sorted(allowed)) + "; "
                + ", ".join("{" + t + "}" for t in extra) + " would be written literally")
    return ""


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


def split_address(web_address: str) -> tuple[str, str]:
    """``(host, port)`` of a web address; port is "" when the address has none.

    ``https://Shop.Example.com:8443/x`` → ``("shop.example.com", "8443")``.
    The host keeps its dots: that is the point of ``{host}``.
    """
    s = (web_address or "").strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = s.split("/", 1)[0].split("?", 1)[0]
    host, _, port = s.partition(":")
    return host.strip("."), (port if port.isdigit() else "")


# --------------------------------------------------------------------------- #
#  Operator variables                                                         #
# --------------------------------------------------------------------------- #
def normalize_variables(raw) -> list[dict]:
    """The stored shape of a variable list, whatever arrives: a list of
    ``{name, source, regex, replace}`` with strings stripped. Rows without a
    name are dropped; nothing is validated here (see :func:`variable_problems`),
    so a list saved by an older build still reads."""
    out: list[dict] = []
    for row in raw if isinstance(raw, (list, tuple)) else ():
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip().lower()
        if not name:
            continue
        out.append({"name": name,
                    "source": str(row.get("source") or "").strip().lower().strip("{}"),
                    "regex": str(row.get("regex") or ""),
                    "replace": str(row.get("replace") or "")})
    return out


def variable_problems(variables) -> list[str]:
    """Every reason this variable list cannot be stored ([] = it can).

    A variable reads a SITE token or a variable defined ABOVE it — never one
    below, so the order on the page is the order they are computed in and a
    cycle cannot be written. The regex must compile and the replacement must
    be applicable (a ``\\2`` with one group fails here, not at the first
    policy built)."""
    rows = normalize_variables(variables)
    problems: list[str] = []
    if len(rows) > MAX_VARIABLES:
        problems.append(f"at most {MAX_VARIABLES} variables")
    known = set(SITE_TOKENS)
    for i, v in enumerate(rows, 1):
        tag = f"variable {i} ({v['name']})"
        if not VARIABLE_NAME_RE.match(v["name"]):
            problems.append(f"{tag}: a name is lower-case letters, digits and _, "
                            "starting with a letter (at most 32)")
            continue
        if v["name"] in RESERVED_TOKENS:
            problems.append(f"{tag}: {{{v['name']}}} is a token SATOM or Discovery "
                            "already fills in — pick another name")
            continue
        if v["name"] in known:
            problems.append(f"{tag}: defined twice")
            continue
        if v["source"] not in known:
            problems.append(f"{tag}: it reads {{{v['source'] or '?'}}}, which is "
                            "neither " + ", ".join("{" + t + "}" for t in SITE_TOKENS)
                            + " nor a variable defined above it")
        if not v["regex"]:
            problems.append(f"{tag}: the regular expression is empty")
        elif len(v["regex"]) > MAX_REGEX_LEN or len(v["replace"]) > MAX_REPLACE_LEN:
            problems.append(f"{tag}: regex at most {MAX_REGEX_LEN} characters, "
                            f"replacement at most {MAX_REPLACE_LEN}")
        else:
            try:
                re.compile(v["regex"]).sub(v["replace"], "shop.example.com")
            except (re.error, IndexError) as exc:
                problems.append(f"{tag}: {exc}")
        known.add(v["name"])
    return problems


def site_tokens(web_address: str, port: str | int | None = "",
                variables=None) -> dict[str, str]:
    """Every token value for one site: ``{name}``, ``{host}``, ``{port}`` and
    then each variable in order. *port* wins over the port in the address.

    A variable that fails at render time (only possible for a list stored
    around :func:`variable_problems`) renders empty rather than raising: the
    caller's empty-name and safe-name guards then refuse the plan, which is
    a clean refusal instead of a 500."""
    host, addr_port = split_address(web_address)
    tokens = {"name": slugify(web_address), "host": host,
              "port": str(port).strip() if str(port or "").strip() else addr_port}
    for v in normalize_variables(variables):
        src = tokens.get(v["source"], "")
        try:
            tokens[v["name"]] = re.sub(v["regex"], v["replace"], src) if v["regex"] else src
        except (re.error, IndexError):
            tokens[v["name"]] = ""
    return tokens


def render_pattern(pattern: str, tokens: dict[str, str]) -> str:
    """Substitute every known token of *pattern* (unknown ones stay literal —
    :func:`pattern_problem` keeps those out of the patterns SATOM builds
    from) and cap at :data:`MAX_NAME_LEN`."""
    out = _TOKEN_RE.sub(lambda m: tokens.get(m.group(1), m.group(0)), pattern or "")
    return out[:MAX_NAME_LEN]


def unsafe_name(name: str) -> str:
    """Why *name* cannot be an object name SATOM builds ("" = it can)."""
    if not name:
        return "renders empty"
    if SAFE_NAME_RE.match(name):
        return ""
    bad = sorted({c for c in name if not re.match(r"[A-Za-z0-9_-]", c)})
    return ("contains " + " ".join(repr(c) for c in bad)
            + " — only letters, digits, _ and - are allowed; rewrite it with a "
              "variable (Administrator → Naming)")


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
    *,
    port: str | int | None = "",
    variables=None,
) -> dict[str, str]:
    """``{element_key: derived_name}`` for one product's elements, from one
    web address (and the port the creating flow gives).

    This is what a "new object from just a web address" flow consumes: the
    operator types the address, this returns the full naming map for the chosen
    product's objects. *variables* are the product's own (see
    :func:`site_tokens`); with none, only ``{name}``/``{host}``/``{port}`` are
    filled in.
    """
    tokens = site_tokens(web_address, port, variables)
    return {
        key: render_pattern(pat, tokens)
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
    "TABLE_PREFIX",
    "table_key",
    "table_overrides",
    "pattern_problem",
    "allowed_tokens",
    "slugify",
    "split_address",
    "render_one",
    "render_pattern",
    "render_names",
    "SITE_TOKENS",
    "RESERVED_TOKENS",
    "normalize_variables",
    "variable_problems",
    "site_tokens",
    "unsafe_name",
]
