"""FortiWeb (and FortiADC) release-notes harvester → searchable upgrade-planning data.

Fortinet publishes, per firmware version, a *Release Notes* document at
``docs.fortinet.com`` whose sections are the raw material for an upgrade plan:

  * **Known issues**     — bugs PRESENT in this version (a two-column ``Bug ID`` /
                           ``Description`` table; the description often embeds a
                           ``Workaround:``)
  * **Resolved issues**  — bugs FIXED in this version (same table shape)
  * **What's new**, **Upgrade notes & important information**, **Upgrading from
    previous releases**, **Product integration & support** — prose sections.

The killer fact for upgrade planning: **the same Bug ID flips Known→Resolved
across versions**, so "what do I gain / what do I inherit by upgrading current →
target" is a pure diff over this data (:func:`advise`).

This module is PURE (no Qt, no DB): it builds URLs from the *stable* section ids,
fetches HTML (a duck-typed ``fetch(url)->str`` — :func:`make_fetcher` chains a
direct ``httpx`` GET with an optional Firecrawl scrape, self-hosted LAN or cloud),
parses the tables/prose with the stdlib ``html.parser``, tags each issue with a
**curated topic**, and serialises to the git-shared ``reports/_release_notes.json``
(same ethos as ``services.signature_catalog``). The DB projection + the GUI live
elsewhere (``db.store`` / ``ui.pages.release_notes_page``).

Verified live (2026-06): ``docs.fortinet.com`` serves the issue tables server-side
(no JS) so the direct httpx fetch works headless; the section ids below are stable
across FortiWeb 7.x/8.x.
"""
from __future__ import annotations

import html as _html
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable

PRODUCT_DEFAULT = "fortiweb"
MIN_SUPPORTED_VERSION = (7, 0)   # modern release-notes docset begins at 7.0;
#  older lines (5.x / 6.x) are listed in the version-history dropdown but have
#  no resolved/known-issues pages, so they must never be enumerated for a scan.
DB_NAME = "_release_notes.json"          # git-shared reference (under reports/)
_DOC_HOST = "https://docs.fortinet.com"
_UA = "Mozilla/5.0 (satom release-notes harvester)"

# Optional self-hosted Firecrawl, used as a fallback transport for pages a
# plain GET cannot retrieve. Empty by default and surfaced as a blank field in
# the UI: this endpoint is unauthenticated, so a shipped default would make
# the app POST fetch requests at whatever answers that address on the
# operator's network.
FIRECRAWL_LAN_DEFAULT = ""

# section key -> (numeric doc id, url slug), PER PRODUCT. The ids are stable
# WITHIN a product's docset (across its 7.x/8.x lines) but DIFFER across products:
# FortiWeb and FortiADC use entirely different MadCap doc-ids for the same logical
# section, so they MUST be keyed by product — pointing FortiWeb's ids at a FortiADC
# URL 302-redirects to the wrong page. A version that lacks a section 404s and is
# skipped. (FortiADC ids/slugs verified live from the 8.0.3 RN TOC, 2026-07-12.)
SECTIONS_BY_PRODUCT: dict[str, dict[str, tuple[str, str]]] = {
    "fortiweb": {
        "known":               ("54989",  "known-issues"),
        "resolved":            ("91537",  "resolved-issues"),
        "whats_new":           ("639023", "whats-new"),
        "upgrade_notes":       ("745354", "upgrade-notes-and-important-information"),
        "upgrading_from":      ("81434",  "upgrading-from-previous-releases"),
        # The REST of the *Upgrade instructions* branch (TOC node 489959). These
        # are SIBLINGS of upgrading_from, not children of it, so harvesting only
        # the two above left the blocking prerequisites out of the corpus
        # entirely: disk repartition, HA upgrade order, downgrade support,
        # image checksums and VM licence validation. Verified live 2026-09-13:
        # all five answer 200 on every FortiWeb line from 7.6 to 8.0.
        "repartitioning":      ("159021", "repartitioning-the-hard-disk"),
        "ha_upgrade":          ("903663", "upgrading-an-ha-cluster"),
        "downgrading":         ("750287", "downgrading-to-a-previous-release"),
        "image_checksums":     ("754338", "image-checksums"),
        "vm_license":          ("439600", "fortiweb-vm-license-validation"),
        "product_integration": ("756870", "product-integration-and-support"),
        "introduction":        ("950216", "introduction"),
    },
    "fortiadc": {
        "known":               ("454516", "known-issues"),
        "resolved":            ("32196",  "resolved-issues"),
        "whats_new":           ("652683", "whats-new"),
        "upgrade_notes":       ("746643", "upgrade-notes"),
        "upgrading_from":      ("765922", "supported-upgrade-paths"),
        "product_integration": ("583910", "hardware-vm-cloud-platform-and-browser-support"),
        "introduction":        ("391727", "introduction"),
    },
}
# Back-compat alias: bare ``SECTIONS`` is the FortiWeb map (the historical default).
SECTIONS: dict[str, tuple[str, str]] = SECTIONS_BY_PRODUCT["fortiweb"]

# Latest GA release-notes version per product, used only to SEED version discovery
# (that page's version-history dropdown enumerates the rest). Maintained by hand —
# bump when a newer GA ships. A stale seed keeps working until the version is
# retired from docs.fortinet.com, then discovery falls back to the introduction
# page and finally returns [].
SEED_VERSION_BY_PRODUCT: dict[str, str] = {"fortiweb": "8.0.4", "fortiadc": "8.0.3"}


def sections_for(product: str) -> dict[str, tuple[str, str]]:
    """The section map for ``product`` (FortiWeb map as the safe default)."""
    return SECTIONS_BY_PRODUCT.get(product, SECTIONS)
ISSUE_SECTIONS: tuple[str, ...] = ("known", "resolved")           # Bug ID tables

#: How many article-less sections in a row mean "this version publishes nothing".
#:
#: A version that was never released answers EVERY section with the same ~442 KB
#: landing, so probing all eleven costs ~5 MB to learn what the first two already
#: said. Two and not one: a single miss could be one section a real release
#: happens not to carry, and giving up on that would drop the other ten in
#: silence — the failure mode this whole module was just rebuilt around.
#: The give-up is ANNOUNCED, never silent, and it only applies while nothing at
#: all has been found for the version.
PROBES_BEFORE_GIVING_UP = 2
PROSE_SECTIONS: tuple[str, ...] = (
    "whats_new", "upgrade_notes", "upgrading_from",
    "repartitioning", "ha_upgrade", "downgrading", "image_checksums",
    "vm_license", "product_integration")
# The subset that carries UPGRADE-BLOCKING prose (as opposed to "what's new" or
# the support matrix). The advisor reads these; the Notes tab shows them all.
UPGRADE_SECTIONS: tuple[str, ...] = (
    "upgrade_notes", "upgrading_from", "repartitioning", "ha_upgrade",
    "downgrading", "vm_license")
DEFAULT_SECTIONS: tuple[str, ...] = ISSUE_SECTIONS + PROSE_SECTIONS

SECTION_LABEL: dict[str, str] = {
    "known": "Known issues",
    "resolved": "Resolved issues",
    "whats_new": "What's new",
    "upgrade_notes": "Upgrade notes & important information",
    "upgrading_from": "Upgrading from previous releases",
    "repartitioning": "Repartitioning the hard disk",
    "ha_upgrade": "Upgrading an HA cluster",
    "downgrading": "Downgrading to a previous release",
    "image_checksums": "Image checksums",
    "vm_license": "FortiWeb-VM license validation",
    "product_integration": "Product integration & support",
    "introduction": "Introduction",
}


# --------------------------------------------------------------------------- #
#  Data model                                                                   #
# --------------------------------------------------------------------------- #
@dataclass
class ReleaseIssue:
    """One row of a Known/Resolved issues table."""

    product: str
    version: str
    status: str            # "known" | "resolved"
    bug_id: str
    description: str
    workaround: str = ""
    topic: str = ""
    source_url: str = ""


@dataclass
class ReleaseSection:
    """One prose section of a release-notes document (text, for search)."""

    product: str
    version: str
    section: str           # one of PROSE_SECTIONS
    title: str
    content: str
    source_url: str = ""


@dataclass
class UnreadableSection:
    """A ``(version, section)`` that IS published but yielded nothing.

    The entire point of this record is that it is not a skip. The scanner used
    to ``continue`` past these, so a renderer change on Fortinet's side read
    exactly like a version that publishes no release notes — which is how the
    corpus stopped at 8.0.6 while every scan reported success."""

    product: str
    version: str
    section: str
    url: str
    reason: str


@dataclass
class ReleaseNotesDB:
    """The whole harvested corpus — the shape of ``reports/_release_notes.json``."""

    generated_at: str
    versions: list[str] = field(default_factory=list)
    issues: list[ReleaseIssue] = field(default_factory=list)
    sections: list[ReleaseSection] = field(default_factory=list)
    # Scan-time diagnostics, never persisted: the corpus records what WAS read,
    # this records what could not be — and the caller must surface it.
    unreadable: list[UnreadableSection] = field(default_factory=list)


# --------------------------------------------------------------------------- #
#  Version helpers (sortable keys + comparisons)                                #
# --------------------------------------------------------------------------- #
def version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", v or ""))


def version_key(v: str) -> str:
    """A zero-padded dotted key so plain string compare orders versions correctly
    (``'8.0.4'`` → ``'0008.0000.0004'``). Stable for SQL ``ORDER BY`` / range filters."""
    parts = re.findall(r"\d+", v or "")
    return ".".join(p.zfill(4) for p in parts) if parts else (v or "")


def major_of(v: str) -> str:
    t = version_tuple(v)
    return ".".join(str(x) for x in t[:2]) if len(t) >= 2 else (v or "")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
#  URLs                                                                          #
# --------------------------------------------------------------------------- #
def section_url(version: str, section: str, product: str = PRODUCT_DEFAULT) -> str:
    sid, slug = sections_for(product)[section]
    return f"{_DOC_HOST}/document/{product}/{version}/release-notes/{sid}/{slug}"


# --------------------------------------------------------------------------- #
#  HTML parsing (stdlib only)                                                    #
# --------------------------------------------------------------------------- #
def _clean(s: str) -> str:
    return re.sub(r"\s+", " ", _html.unescape(s or "")).strip()


class _TableExtractor(HTMLParser):
    """Collect every table as ``list[rows]`` of ``list[cell text]``."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[str]]] = []
        self._t: list[list[str]] | None = None
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag == "table":
            self._t = []
        elif tag == "tr" and self._t is not None:
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []
        elif tag == "br" and self._cell is not None:
            self._cell.append(" ")

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("p", "div", "li") and self._cell is not None:
            self._cell.append(" ")
        elif tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append(_clean("".join(self._cell)))
            self._cell = None
        elif tag == "tr" and self._row is not None and self._t is not None:
            self._t.append(self._row)
            self._row = None
        elif tag == "table" and self._t is not None:
            self.tables.append(self._t)
            self._t = None


def parse_issue_table(html: str) -> list[tuple[str, str]]:
    """Return ``[(bug_id, description), …]`` from the page's Bug ID / Description table."""
    ex = _TableExtractor()
    ex.feed(html)
    for tbl in ex.tables:
        if not tbl:
            continue
        head = [c.lower() for c in tbl[0]]
        is_bug = bool(head) and (head[0].startswith("bug id")
                                 or ("bug id" in head and "description" in head))
        if not is_bug:
            # fallback: a 2-col table whose first column is mostly numeric ids
            body = [r for r in tbl if len(r) >= 2]
            digits = sum(1 for r in body if re.fullmatch(r"\d{5,}", r[0] or ""))
            if not (len(body) >= 2 and digits >= max(1, len(body) // 2)):
                continue
            rows = [(r[0].strip(), r[1].strip()) for r in body
                    if re.fullmatch(r"\d{4,}", r[0] or "")]
            if rows:
                return rows
            continue
        rows = []
        for r in tbl[1:]:
            if len(r) >= 2 and r[0].strip():
                rows.append((r[0].strip(), r[1].strip()))
        return rows
    return []


# Require the colon ("Workaround: …", the standard release-notes form) so a
# description that merely mentions the word isn't split.
_WORKAROUND_RE = re.compile(r"\bwork[\s-]?around\s*:\s*", re.I)


def split_workaround(desc: str) -> tuple[str, str]:
    """Split a known-issue description into ``(text, workaround)`` (workaround may be '')."""
    m = _WORKAROUND_RE.search(desc or "")
    if not m:
        return (desc or "").strip(), ""
    return desc[:m.start()].strip(" .;—-"), desc[m.end():].strip()


_FOOTER_MARKERS = ('id="mc-footer"', "ftnt-footer", 'id="footer"', "</body>")
_CONTENT_MARKER = 'id="mc-main-content"'   # MadCap (src-mc) article container
_MD_MARKER = "document-content src-md"     # markdown-rendered (src-md) container
# The src-md docset repeats the WHOLE article a second time inside a
# ``mobile-content`` wrapper, so this slice must close on the first of these or
# every row and paragraph would be harvested twice.
_MD_FOOTER_MARKERS = ('class="mobile-content"', 'id="thin-footer"', "</body>")

# A page that publishes ANY article — in either renderer — carries a
# ``document-content src-XX`` wrapper. A version that was never published resolves
# to a 200 *landing* with NO such wrapper at all (verified live 2026-09-13: the
# 7.0.x / 7.2.x / 7.4.x landings are ~442 KB of pure chrome and contain the string
# zero times). This is the only reliable way to tell "not published" from
# "published but this parser could not read it" — and NOT telling them apart is
# exactly how 8.0.7 went unharvested while every scan finished green.
_ARTICLE_RE = re.compile(r"document-content\s+src-\w+")




def has_release_content(html: str) -> bool:
    """True iff the page carries an article this parser knows how to slice.

    Two containers are recognised because Fortinet changed renderers mid-docset:
    MadCap ``mc-main-content`` (FortiWeb up to 8.0.6, and FortiADC) and the
    markdown-rendered ``document-content src-md`` (FortiWeb from 8.0.7)."""
    h = html or ""
    return _CONTENT_MARKER in h or _MD_MARKER in h


def has_article(html: str) -> bool:
    """True iff the page publishes a release-notes ARTICLE at all.

    Two ways to be sure, and BOTH are needed:

    * a container this parser recognises — recognising it IS proof there is an
      article, and making the wrapper the sole evidence would skip such a page in
      silence the day Fortinet drop the wrapper;
    * failing that, the generic ``document-content src-XX`` wrapper, which is
      what lets us see an article we cannot yet read.

    ``has_article() and not has_release_content()`` is precisely the *published
    but unreadable* state :func:`scan_release_notes` must REPORT rather than skip."""
    h = html or ""
    return has_release_content(h) or bool(_ARTICLE_RE.search(h))


def _main_content(html: str) -> str:
    """Slice the article body out of the page chrome (``''`` when no recognised
    container is present).

    The MadCap branch is kept byte-for-byte as it was: the 21 versions already in
    the corpus were harvested through it, and a "harmless tidy-up" here would
    silently re-cut all of them."""
    i = html.find(_CONTENT_MARKER)
    if i >= 0:
        markers = _FOOTER_MARKERS
    else:
        i = html.find(_MD_MARKER)
        if i < 0:
            return ""
        markers = _MD_FOOTER_MARKERS
    start = html.rfind("<", 0, i)
    if start < 0:
        start = i
    end = len(html)
    for mk in markers:
        j = html.find(mk, i)
        if j >= 0:
            end = min(end, j)
    return html[start:end]


# A Known/Resolved page that legitimately has nothing SAYS so in prose ("There are
# no known issues in version 8.0.7."). Without this, an empty table and a table
# this parser cannot read look identical — and only one of them is news.
_NO_ISSUES_RE = re.compile(r"\bthere (?:are|is) no\b[^.]{0,80}\bissues?\b", re.I)


def declares_no_issues(text: str) -> bool:
    """True iff the article states outright that it has no issues to list."""
    return bool(_NO_ISSUES_RE.search(text or ""))


class _TextExtractor(HTMLParser):
    _SKIP = {"script", "style", "nav", "header", "footer", "noscript",
             "button", "select", "option", "svg", "form"}
    _BLOCK = {"p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6",
              "br", "ul", "ol", "table", "section", "thead", "tbody"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in self._SKIP:
            self._skip += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip > 0:
            self._skip -= 1
        elif tag in self._BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip == 0:
            t = data.strip()
            if t:
                self.parts.append(t + " ")


def html_to_text(html: str) -> str:
    ex = _TextExtractor()
    ex.feed(html)
    txt = _html.unescape("".join(ex.parts))
    txt = re.sub(r"[ \t]+", " ", txt)
    txt = re.sub(r"\n[ \t]*", "\n", txt)
    txt = re.sub(r"\n{3,}", "\n\n", txt)
    return txt.strip()


def parse_section_text(html: str) -> str:
    """Readable text of a prose section (article body only, chrome stripped)."""
    return html_to_text(_main_content(html))


# --------------------------------------------------------------------------- #
#  Curated topic classification (the "by topic" filter)                         #
# --------------------------------------------------------------------------- #
# Ordered most-specific → general; first match wins. Curated keyword rules so the
# tagging is deterministic + offline (no LLM needed). ``release_topics()`` in the
# store reflects the topics actually present, so tuning these never breaks the UI.
TOPIC_RULES: list[tuple[str, str]] = [
    ("High Availability",       r"\bHA\b|high[\s-]availab|failover|\bcluster\b|config[\s-]sync|sync-stat"),
    ("SSL/TLS & Certificates",  r"\bSSL\b|\bTLS\b|certificat|\bcipher|\bOCSP\b|\bSNI\b|\bHSM\b|x509|handshake|\bCRL\b|HPKP"),
    ("Authentication & SSO",    r"authentic|\bRADIUS\b|\bLDAP\b|\bSAML\b|\bSSO\b|\bMFA\b|FortiToken|kerberos|TACACS|oauth|\bNTLM\b|two-factor|\bOTP\b|admin login|password polic"),
    ("FortiGuard & Updates",    r"fortiguard|signature update|\bFDS\b|anycast|licens|fortisandbox|update server|update package"),
    ("GeoIP & IP Reputation",   r"geo[\s-]?ip|ip reputation|ip-intelligence|ip intelligence|ip list|geo block"),
    ("Logging & Reports",       r"\blog\b|logging|\breport\b|syslog|fortianalyzer|event log|attack log|traffic log"),
    ("Machine Learning",        r"machine learning|\bML\b|anomaly|api learning"),
    ("Bot Mitigation",          r"\bbot\b|biometric|threshold-based|captcha|recaptcha|deception"),
    ("API Protection",          r"\bAPI\b|openapi|graphql|\bgRPC\b|json schema|\bMCP\b|swagger"),
    ("WAF / Signatures",        r"signatur|\bWAF\b|injection|\bXSS\b|sql inj|owasp|protection profile|exception|web[\s-]shell|webshell|\bCSRF\b"),
    ("Server Policy & Pools",   r"server polic|server pool|real server|load balanc|persistenc|health check|content routing|virtual server|\bVIP\b"),
    ("Caching & Compression",   r"\bcache|caching|compress|\bgzip\b"),
    ("Networking",              r"interface|routing|\broute\b|\bVLAN\b|gateway|\bARP\b|\bDNS\b|\bDHCP\b|\bTCP\b|\bUDP\b|packet|\bNAT\b|\bMTU\b|\bproxy\b"),
    ("GUI / Web UI",            r"\bGUI\b|web ui|dashboard|web interface|widget|\bbutton\b|displays? incorrect|page (?:does|fails|cannot)"),
    ("Upgrade & Configuration", r"upgrad|downgrad|firmware|config(?:uration)? (?:lost|restore|backup|fail)|migrat|\bboot\b|partition"),
    ("System & Performance",    r"performanc|\bCPU\b|\bmemory\b|crash|reboot|kernel|daemon|\bdisk\b|hardware|leak|hang|\bcore dump\b"),
]
ALL_TOPICS: list[str] = [t for t, _ in TOPIC_RULES] + ["General"]
_TOPIC_COMPILED = [(t, re.compile(p, re.I)) for t, p in TOPIC_RULES]


def classify_topic(text: str) -> str:
    for topic, rx in _TOPIC_COMPILED:
        if rx.search(text or ""):
            return topic
    return "General"


# --------------------------------------------------------------------------- #
#  Fetch transports (duck-typed: a fetch is just ``str -> str`` returning HTML)  #
# --------------------------------------------------------------------------- #
class NotFound(Exception):
    """The document does not exist for this version (HTTP 404) — skip, don't retry."""


class FetchError(Exception):
    """A transport failed; a chained fetcher may try the next one."""


def httpx_fetch(url: str, *, timeout: float = 30.0) -> str:
    import httpx

    try:
        r = httpx.get(url, timeout=timeout, follow_redirects=True,
                      headers={"User-Agent": _UA})
    except Exception as exc:  # noqa: BLE001 — network → let the chain fall back
        raise FetchError(f"httpx: {exc}") from exc
    if r.status_code == 404:
        raise NotFound(url)
    if r.status_code >= 400:
        raise FetchError(f"httpx HTTP {r.status_code} for {url}")
    return r.text


def firecrawl_fetch(url: str, *, endpoint: str, api_key: str = "",
                    timeout: float = 90.0) -> str:
    """Scrape ``url`` via a Firecrawl service (self-hosted LAN or cloud), returning
    the raw HTML so the SAME parsers apply."""
    import httpx

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        r = httpx.post(f"{endpoint.rstrip('/')}/v1/scrape",
                       json={"url": url, "formats": ["rawHtml"],
                             "onlyMainContent": False},
                       headers=headers, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        raise FetchError(f"firecrawl: {exc}") from exc
    if r.status_code >= 400:
        raise FetchError(f"firecrawl HTTP {r.status_code} for {url}")
    data = r.json().get("data") or {}
    html = data.get("rawHtml") or data.get("html") or ""
    if not html:
        raise FetchError(f"firecrawl: empty body for {url}")
    return html


def make_fetcher(
    *,
    use_direct: bool = True,
    firecrawl_endpoint: str = "",
    firecrawl_key: str = "",
    prefer_firecrawl: bool = False,
    timeout: float = 30.0,
) -> Callable[[str], str]:
    """Build a ``fetch(url)->html`` that chains the configured transports.

    By default tries a direct ``httpx`` GET (fast, proven for docs.fortinet.com)
    then falls back to Firecrawl if an endpoint is configured. ``prefer_firecrawl``
    reverses the order. A 404 from any transport is a real absence (``NotFound``)
    and short-circuits — the chain only falls through on transport FAILURES."""
    transports: list[Callable[[str], str]] = []
    direct = (lambda u: httpx_fetch(u, timeout=timeout)) if use_direct else None
    crawl = (lambda u: firecrawl_fetch(u, endpoint=firecrawl_endpoint,
                                       api_key=firecrawl_key)) if firecrawl_endpoint else None
    if prefer_firecrawl:
        transports = [t for t in (crawl, direct) if t]
    else:
        transports = [t for t in (direct, crawl) if t]
    if not transports:
        transports = [lambda u: httpx_fetch(u, timeout=timeout)]

    def fetch(url: str) -> str:
        last: Exception | None = None
        for t in transports:
            try:
                return t(url)
            except NotFound:
                raise
            except Exception as exc:  # noqa: BLE001
                last = exc
                continue
        raise FetchError(str(last) if last else f"all transports failed for {url}")

    return fetch


# --------------------------------------------------------------------------- #
#  Version discovery + scan orchestration                                        #
# --------------------------------------------------------------------------- #
def discover_versions(fetch: Callable[[str], str], *, product: str = PRODUCT_DEFAULT,
                      seed_version: str | None = None,
                      min_version: tuple[int, int] = MIN_SUPPORTED_VERSION) -> list[str]:
    """``x.y.z`` versions referenced by a seed release-notes page (its version
    history), sorted oldest→newest, **floored at ``min_version``** so pre-modern
    lines (5.x/6.x) — which appear in the dropdown but publish no resolved/known
    issues pages — are never scanned. ``[]`` on failure. ``seed_version`` defaults
    to the product's latest GA (:data:`SEED_VERSION_BY_PRODUCT`)."""
    if not seed_version:
        seed_version = SEED_VERSION_BY_PRODUCT.get(product, "8.0.4")
    try:
        html = fetch(section_url(seed_version, "resolved", product))
    except Exception:  # noqa: BLE001
        try:
            html = fetch(section_url(seed_version, "introduction", product))
        except Exception:  # noqa: BLE001
            return []
    found = set(re.findall(rf"/document/{re.escape(product)}/(\d+\.\d+\.\d+)/", html))
    kept = [v for v in found if version_tuple(v)[:2] >= min_version]
    return sorted(kept, key=version_key)


def select_versions(versions: list[str], majors: list[str] | None) -> list[str]:
    """Keep only versions whose ``major.minor`` is in ``majors`` (None ⇒ all)."""
    if not majors:
        return list(versions)
    keep = set(majors)
    return [v for v in versions if major_of(v) in keep]


def scan_release_notes(
    fetch: Callable[[str], str],
    versions: list[str],
    *,
    product: str = PRODUCT_DEFAULT,
    sections: tuple[str, ...] = DEFAULT_SECTIONS,
    on_progress: Callable[[str], None] | None = None,
) -> ReleaseNotesDB:
    """Fetch + parse every (version, section) → a :class:`ReleaseNotesDB`.

    Pure orchestration over the duck-typed ``fetch``. A missing section (404) is
    skipped; any other transport error is logged via ``on_progress`` and skipped,
    so one bad page never sinks the scan."""
    def emit(msg: str) -> None:
        if on_progress:
            on_progress(msg)

    issues: list[ReleaseIssue] = []
    sects: list[ReleaseSection] = []
    unreadable: list[UnreadableSection] = []
    done: list[str] = []
    secmap = sections_for(product)

    def unread(v: str, sec: str, url: str, reason: str) -> None:
        unreadable.append(UnreadableSection(product=product, version=v, section=sec,
                                            url=url, reason=reason))
        emit(f"  ✗ {v}/{sec}: UNREADABLE — {reason}")

    for v in versions:
        got = False
        n_iss = 0
        blank = 0          # consecutive sections with no article at all
        seen_article = False
        gave_up = False
        for sec in sections:
            if sec not in secmap:
                continue
            # Gated on having seen an ARTICLE, not on having PARSED one. A page
            # we could not read is still proof the version exists, and spending
            # it as evidence of absence would be the original bug with a
            # stopwatch attached.
            if not seen_article and blank >= PROBES_BEFORE_GIVING_UP:
                gave_up = True
                break
            url = section_url(v, sec, product)
            try:
                html = fetch(url)
            except NotFound:
                continue
            except Exception as exc:  # noqa: BLE001
                emit(f"  ! {v}/{sec}: {exc}")
                continue
            if not has_article(html):
                # No article wrapper at all: this version genuinely does not publish
                # this section (a chrome-only landing). Silent BY DESIGN — this is
                # the only branch allowed to be silent.
                blank += 1
                continue
            # No need to reset blank: the give-up is gated on seen_article,
            # which is now permanently true for this version.
            seen_article = True
            if not has_release_content(html):
                unread(v, sec, url,
                       "the page carries an article this parser cannot slice "
                       "(unrecognised container — did the renderer change?)")
                continue
            text = parse_section_text(html)
            if sec in ISSUE_SECTIONS:
                rows = parse_issue_table(html)
                if not rows:
                    if declares_no_issues(text):
                        got = True          # read fine; it is simply empty
                        continue
                    unread(v, sec, url,
                           "an issues article with no table this parser could read "
                           "and no 'there are no issues' statement")
                    continue
                for bug_id, desc in rows:
                    _, wa = split_workaround(desc)
                    issues.append(ReleaseIssue(
                        product=product, version=v, status=sec, bug_id=bug_id,
                        description=desc, workaround=wa,
                        topic=classify_topic(desc), source_url=url))
                    n_iss += 1
                got = True
            else:
                if not text:
                    unread(v, sec, url, "a prose article that rendered to empty text")
                    continue
                sects.append(ReleaseSection(
                    product=product, version=v, section=sec,
                    title=SECTION_LABEL.get(sec, sec), content=text,
                    source_url=url))
                got = True
        if got:
            done.append(v)
            emit(f"✓ {v} — {n_iss} issue(s)")
        elif any(u.version == v for u in unreadable):
            emit(f"✗ {v} — PUBLISHED BUT UNREADABLE (see above)")
        elif gave_up:
            emit(f"·  {v} — no release notes found "
                 f"(gave up after {PROBES_BEFORE_GIVING_UP} empty probes)")
        else:
            emit(f"·  {v} — no release notes found")

    return ReleaseNotesDB(generated_at=_now(),
                          versions=sorted(done, key=version_key),
                          issues=issues, sections=sects, unreadable=unreadable)


def merge_db(old: ReleaseNotesDB | None, new: ReleaseNotesDB) -> ReleaseNotesDB:
    """Merge a freshly-scanned subset into an existing corpus, REPLACING the
    ``(product, version)`` pairs present in ``new`` and keeping the rest.

    The key MUST include ``product``: FortiWeb and FortiADC share version numbers
    (both ship 7.x/8.0.x), so a version-only key would let a FortiADC scan silently
    delete the same-numbered FortiWeb rows (and vice-versa)."""
    if old is None:
        return new
    prods = {i.product for i in new.issues} | {s.product for s in new.sections}
    fresh = {(i.product, i.version) for i in new.issues} \
        | {(s.product, s.version) for s in new.sections} \
        | {(p, v) for p in prods for v in new.versions}
    issues = [i for i in old.issues if (i.product, i.version) not in fresh] + new.issues
    sections = [s for s in old.sections if (s.product, s.version) not in fresh] + new.sections
    versions = sorted(set(old.versions) | set(new.versions), key=version_key)
    return ReleaseNotesDB(generated_at=new.generated_at, versions=versions,
                          issues=issues, sections=sections)


# --------------------------------------------------------------------------- #
#  Pure search / filter (for the JSON path + tests; the GUI uses SQL)            #
# --------------------------------------------------------------------------- #
def filter_issues(issues: list[ReleaseIssue], *, version: str | None = None,
                  status: str | None = None, topic: str | None = None,
                  query: str | None = None) -> list[ReleaseIssue]:
    q = (query or "").lower().strip()
    out = []
    for i in issues:
        if version and i.version != version:
            continue
        if status and i.status != status:
            continue
        if topic and i.topic != topic:
            continue
        if q and q not in (i.description or "").lower() and q not in (i.bug_id or "") \
                and q not in (i.workaround or "").lower():
            continue
        out.append(i)
    return out


# --------------------------------------------------------------------------- #
#  Upgrade advisory — the centrepiece: a pure diff between two versions          #
# --------------------------------------------------------------------------- #
@dataclass
class UpgradeAdvisory:
    current: str
    target: str
    is_upgrade: bool                         # target > current
    resolved: list[ReleaseIssue] = field(default_factory=list)       # fixed in range
    known_in_target: list[ReleaseIssue] = field(default_factory=list)
    notes: list[ReleaseSection] = field(default_factory=list)        # upgrade prose in range


def _in_range(v: str, lo: tuple[int, ...], hi: tuple[int, ...]) -> bool:
    """``lo < version_tuple(v) <= hi`` (the bugs you cross when moving lo→hi)."""
    t = version_tuple(v)
    return lo < t <= hi


def advise(issues: list[ReleaseIssue], sections: list[ReleaseSection],
           current: str, target: str) -> UpgradeAdvisory:
    """What an operator gains / inherits moving ``current`` → ``target``.

    * resolved — issues marked *resolved* in any version in ``(current, target]``
      (the fixes you pick up).
    * known_in_target — issues still *known* in the target (what you'd inherit).
    * notes — the Upgrade-notes / Upgrading-from prose for the versions crossed.
    """
    ct, tt = version_tuple(current), version_tuple(target)
    is_up = tt > ct
    lo, hi = (ct, tt) if is_up else (tt, ct)
    resolved = sorted(
        (i for i in issues if i.status == "resolved" and _in_range(i.version, lo, hi)),
        key=lambda i: (version_key(i.version), i.bug_id))
    known = sorted(
        (i for i in issues if i.status == "known" and version_tuple(i.version) == tt),
        key=lambda i: i.bug_id)
    notes = [s for s in sections
             if s.section in ("upgrade_notes", "upgrading_from")
             and _in_range(s.version, lo, hi)]
    notes.sort(key=lambda s: (version_key(s.version), s.section))
    return UpgradeAdvisory(current=current, target=target, is_upgrade=is_up,
                           resolved=resolved, known_in_target=known, notes=notes)


# --------------------------------------------------------------------------- #
#  Persistence — the git-shared JSON (loaded into the DB by the store)           #
# --------------------------------------------------------------------------- #
def reports_root() -> Path:
    """The web-app's git-tracked ``reports/`` dir (sibling of ``app/`` and
    ``wsgi.py``). Mirrors the desktop's git-shared reference location so the
    corpus is committed + pulled by the two Release-Notes buttons. NOTE: this is
    the repo's ``reports/`` (NOT the gitignored ``data/``), so it survives a
    ``git pull`` and can be shared with the team."""
    root = Path(__file__).resolve().parents[2] / "reports"
    root.mkdir(parents=True, exist_ok=True)
    return root


def db_path(root: Path | None = None) -> Path:
    return (root or reports_root()) / DB_NAME


def save_db(db: ReleaseNotesDB, *, root: Path | None = None) -> Path:
    path = db_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": db.generated_at,
        "versions": db.versions,
        "issues": [asdict(i) for i in db.issues],
        "sections": [asdict(s) for s in db.sections],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def load_db(*, root: Path | None = None) -> ReleaseNotesDB | None:
    try:
        raw = json.loads(db_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    issues = [ReleaseIssue(**{k: v for k, v in d.items()
                              if k in ReleaseIssue.__annotations__})
              for d in raw.get("issues") or [] if isinstance(d, dict)]
    sections = [ReleaseSection(**{k: v for k, v in d.items()
                                  if k in ReleaseSection.__annotations__})
                for d in raw.get("sections") or [] if isinstance(d, dict)]
    return ReleaseNotesDB(generated_at=raw.get("generated_at") or "",
                          versions=list(raw.get("versions") or []),
                          issues=issues, sections=sections)


__all__ = [
    "PRODUCT_DEFAULT", "MIN_SUPPORTED_VERSION", "DB_NAME", "FIRECRAWL_LAN_DEFAULT",
    "SECTIONS", "SECTIONS_BY_PRODUCT", "SEED_VERSION_BY_PRODUCT", "sections_for",
    "ISSUE_SECTIONS", "PROSE_SECTIONS", "DEFAULT_SECTIONS", "UPGRADE_SECTIONS",
    "PROBES_BEFORE_GIVING_UP",
    "SECTION_LABEL", "ALL_TOPICS", "TOPIC_RULES",
    "ReleaseIssue", "ReleaseSection", "ReleaseNotesDB", "UpgradeAdvisory",
    "UnreadableSection",
    "version_tuple", "version_key", "major_of", "section_url",
    "parse_issue_table", "split_workaround", "parse_section_text", "html_to_text",
    "has_release_content", "has_article", "declares_no_issues", "classify_topic",
    "NotFound", "FetchError", "httpx_fetch", "firecrawl_fetch", "make_fetcher",
    "discover_versions", "select_versions", "scan_release_notes", "merge_db",
    "filter_issues", "advise",
    "reports_root", "db_path", "save_db", "load_db",
]
