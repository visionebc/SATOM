"""Fortinet release notes -> searchable upgrade-planning data (display side).

Products: FortiWeb, FortiADC, FortiAuthenticator, FortiAnalyzer and FortiGate
(FortiOS) — see :data:`SECTIONS_BY_PRODUCT`.

Per firmware version, Fortinet's release notes carry the raw material of an
upgrade plan:

  * **Known issues**     — bugs PRESENT in this version (``Bug ID`` /
                           ``Description``; the description often embeds a
                           ``Workaround:``)
  * **Resolved issues**  — bugs FIXED in this version
  * **What's new**, **Upgrade notes & important information**, **Upgrading from
    previous releases**, **Product integration & support** — prose sections.

The killer fact for upgrade planning: **the same Bug ID flips Known→Resolved
across versions**, so "what do I gain / what do I inherit by upgrading current →
target" is a pure diff over this data (:func:`advise`).

Where the corpus comes from — ONE channel since SATOM 3.0: the ``docs`` section
of a signed API pack, either lane (the API pack shipped with each release, or
the rolling knowledge pack from the online feed — ``services.knowledge_fetch``).
``services.api_pack._import_release_notes`` writes it. SATOM performs no HTTP
to any vendor documentation site: the crawler lives only in the separate
knowledge harvester that builds the packs (``tests/test_no_vendor_http.py``).

This module is PURE (no DB, no network): the data model, the section map and
labels, the topic classifier, version helpers, the issue filter, the upgrade
diff, and the JSON persistence of ``reports/_release_notes.json`` (a symlink
into ``data/reports/``, not in git; the standby gets it from
``satom-ha-datasync``).

Local measurement always wins over a pack.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

PRODUCT_DEFAULT = "fortiweb"
DB_NAME = "_release_notes.json"          # local corpus (under reports/ -> data/reports/)


# section key -> (vendor doc id, url slug), PER PRODUCT: which sections a
# product's release notes publish, and the vendor's own identity of each (the
# ids the knowledge harvester reads). SATOM never fetches them; the keys decide
# which prose sections the Notes tab offers for a product. FortiAuthenticator,
# FortiAnalyzer and FortiGate call "Upgrade notes" *Special notices*; it is
# stored under ``upgrade_notes`` so the upgrade advisor reads it, and its label
# says what the vendor calls it (:data:`SECTION_LABEL_BY_PRODUCT`).
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
    "fortiauthenticator": {
        "known":               ("713049", "known-issues"),
        "resolved":            ("279684", "resolved-issues"),
        "whats_new":           ("568509", "whats-new"),
        "upgrade_notes":       ("564992", "special-notices"),
        "upgrading_from":      ("859240", "upgrade-instructions"),
        "image_checksums":     ("840416", "image-checksums"),
        "product_integration": ("869439", "product-integration-and-support"),
        "introduction":        ("355786", "introduction"),
    },
    "fortianalyzer": {
        # No "What's new" here: FortiAnalyzer publishes it as a separate
        # New Features guide, not as a release-notes page.
        "known":               ("35134",  "known-issues"),
        "resolved":            ("291684", "resolved-issues"),
        "upgrade_notes":       ("901026", "special-notices"),
        "upgrading_from":      ("903960", "upgrade-information"),
        "downgrading":         ("953575", "downgrading-to-previous-firmware-versions"),
        "image_checksums":     ("568416", "firmware-image-checksums"),
        "product_integration": ("372145", "product-integration-and-support"),
        "introduction":        ("723553", "introduction"),
    },
    "fortigate": {
        "known":               ("236526", "known-issues"),
        "resolved":            ("289806", "resolved-issues"),
        "whats_new":           ("743723", "new-features-or-enhancements"),
        "upgrade_notes":       ("708555", "special-notices"),
        "upgrading_from":      ("832438", "upgrade-information"),
        "downgrading":         ("687629", "downgrading-to-previous-firmware-versions"),
        "image_checksums":     ("399393", "firmware-image-checksums"),
        "product_integration": ("242321", "product-integration-and-support"),
        "introduction":        ("760203", "introduction-and-supported-models"),
    },
}
# Back-compat alias: bare ``SECTIONS`` is the FortiWeb map (the historical default).
SECTIONS: dict[str, tuple[str, str]] = SECTIONS_BY_PRODUCT["fortiweb"]

#: Every product with a release-notes map.
RELEASE_NOTES_PRODUCTS: tuple[str, ...] = tuple(SECTIONS_BY_PRODUCT)




def sections_for(product: str) -> dict[str, tuple[str, str]]:
    """The section map for ``product`` (FortiWeb map as the safe default)."""
    return SECTIONS_BY_PRODUCT.get(product, SECTIONS)

ISSUE_SECTIONS: tuple[str, ...] = ("known", "resolved")           # Bug ID tables

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

#: Where a product's own page title differs from the generic label above.
SECTION_LABEL_BY_PRODUCT: dict[str, dict[str, str]] = {
    "fortiauthenticator": {"upgrade_notes": "Special notices",
                           "upgrading_from": "Upgrade instructions"},
    "fortianalyzer": {"upgrade_notes": "Special notices",
                      "upgrading_from": "Upgrade information",
                      "downgrading": "Downgrading to previous firmware versions",
                      "image_checksums": "Firmware image checksums"},
    "fortigate": {"upgrade_notes": "Special notices",
                  "upgrading_from": "Upgrade information",
                  "whats_new": "New features or enhancements",
                  "downgrading": "Downgrading to previous firmware versions",
                  "image_checksums": "Firmware image checksums"},
}


def section_label(section: str, product: str = PRODUCT_DEFAULT) -> str:
    """The title a section is stored and shown under, for ``product``."""
    return (SECTION_LABEL_BY_PRODUCT.get(product, {}).get(section)
            or SECTION_LABEL.get(section, section))


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
class ReleaseNotesDB:
    """The whole harvested corpus — the shape of ``reports/_release_notes.json``."""

    generated_at: str
    versions: list[str] = field(default_factory=list)
    issues: list[ReleaseIssue] = field(default_factory=list)
    sections: list[ReleaseSection] = field(default_factory=list)


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


# --------------------------------------------------------------------------- #
#  Text helpers                                                                 #
# --------------------------------------------------------------------------- #
_WORKAROUND_RE = re.compile(r"\bwork[\s-]?around\s*:\s*", re.I)


def split_workaround(desc: str) -> tuple[str, str]:
    """Split a known-issue description into ``(text, workaround)`` (workaround may be '')."""
    m = _WORKAROUND_RE.search(desc or "")
    if not m:
        return (desc or "").strip(), ""
    return desc[:m.start()].strip(" .;—-"), desc[m.end():].strip()


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


#: Shown when a build has no release notes in the local corpus — the one case
#: where an empty list would be read as "this build has no issues".
NO_NOTES = ("No release notes for this build in the local corpus — import a newer "
            "knowledge pack (Software Update → Knowledge packs).")
#: Pre-3.0 name, kept for callers that still import it.
OFFLINE_NO_NOTES = NO_NOTES


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
#  Persistence — the corpus JSON under reports/ (data/reports/)               #
# --------------------------------------------------------------------------- #
def reports_root() -> Path:
    """Where the corpus lives: ``reports/`` beside ``app/`` and ``wsgi.py``.

    ⚠ That directory is a **symlink to ``data/reports/``** and ``/reports`` is
    in ``.gitignore`` — since the git SoT was retired (2026-08-05) this tree is
    NOT version-controlled and NOT shared by git. ``git add`` on a path under
    it does not merely get ignored, it is refused outright
    (``fatal: pathspec ... is beyond a symbolic link``).

    This docstring used to claim the opposite — that the corpus survives a
    pull and is shared with the team — and that claim is what kept two dead
    git buttons in the modal for five weeks. The corpus reaches the standby
    through ``satom-ha-datasync`` (rsync of ``data/``), and reaches a
    different installation by importing a pack there."""
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
    "PRODUCT_DEFAULT", "DB_NAME",
    "SECTIONS", "SECTIONS_BY_PRODUCT", "sections_for",
    "RELEASE_NOTES_PRODUCTS",
    "SECTION_LABEL_BY_PRODUCT", "section_label",
    "NO_NOTES", "OFFLINE_NO_NOTES",
    "ISSUE_SECTIONS", "PROSE_SECTIONS", "DEFAULT_SECTIONS", "UPGRADE_SECTIONS",
    "SECTION_LABEL", "ALL_TOPICS", "TOPIC_RULES",
    "ReleaseIssue", "ReleaseSection", "ReleaseNotesDB", "UpgradeAdvisory",
    "version_tuple", "version_key", "major_of",
    "split_workaround", "classify_topic",
    "merge_db", "filter_issues", "advise",
    "reports_root", "db_path", "save_db", "load_db",
]
