"""Guards for the two GENERATED documentation surfaces.

Both generators exist because a hand-maintained copy of something the code
already knows goes stale, and documentation goes stale silently — nobody gets
a stack trace from a manual. These tests are what makes "generated" mean
something: the suite fails when the published copy no longer matches its source.

Three properties are protected here:

1. ``docs/cli.md`` command table == the live ``deploy/satom_cli/tree.py``.
2. ``site/docs/*.html`` + ``site/docs.html`` == the Markdown in ``docs/``.
3. **No internal identifier anywhere under ``site/``.** ``site/`` is pushed to
   GitHub Pages by the release sync, so a leak here is public. This check covers
   the hand-written pages too, not just the generated ones.
"""
from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
SITE = ROOT / "site"
DOCS = ROOT / "docs"


def _load(name: str):
    """Import a deploy/ generator by path — they are scripts, not a package."""
    if str(DEPLOY) not in sys.path:
        sys.path.insert(0, str(DEPLOY))
    spec = importlib.util.spec_from_file_location(name, DEPLOY / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# 1. The CLI reference cannot drift from the registry
# ---------------------------------------------------------------------------

def test_cli_reference_matches_the_live_registry():
    gen = _load("gen_cli_reference")
    text = (DOCS / "cli.md").read_text(encoding="utf-8")
    have = gen.current_block(text)
    assert have is not None, "docs/cli.md lost its GENERATED COMMAND REFERENCE markers"
    assert have.strip() == gen.render().strip(), (
        "docs/cli.md is stale — run: python3 deploy/gen_cli_reference.py")


def test_every_runnable_command_appears_in_the_reference():
    """The table is generated, but assert the *coverage* property directly:
    a command reachable from the parser must be documented. If someone ever
    replaces the generator with hand-written prose, this still bites."""
    gen = _load("gen_cli_reference")
    text = (DOCS / "cli.md").read_text(encoding="utf-8")
    for path, _node in gen.commands():
        assert "satom " + " ".join(path) in text, (
            f"command 'satom {' '.join(path)}' is missing from docs/cli.md")


def test_no_documented_command_is_missing_from_the_registry():
    """The reverse drift. The generated table cannot invent a command, but the
    hand-written tour above it can outlive one — and a manual that names a
    command which does not exist is worse than a missing section: the missing
    section sends the reader elsewhere, the wrong command makes them trust the
    page. (Caught for real: `satom show doc` was written into a draft; the
    actual command is `satom show runbook`.)

    Rule that makes this precise instead of fuzzy: while the resolved node is a
    GROUP, the next bare word must be one of its children. Groups take no
    arguments, so at that position a word can only be a subcommand. Once a
    runnable command is reached, the remaining words are its arguments and are
    not checked.
    """
    import re as _re
    _load("gen_cli_reference")            # puts deploy/ on sys.path
    from satom_cli import tree as reg

    bad: list[str] = []
    for span in _re.findall(r"`satom ([^`]+)`", (DOCS / "cli.md").read_text(encoding="utf-8")):
        node, walked = reg.ROOT, []
        for token in span.split():
            if not _re.fullmatch(r"[a-z][a-z0-9-]*", token):
                break                      # a flag, a placeholder, an argument
            if node.run is not None:
                break                      # arguments of a real command
            if token not in node.children:
                bad.append(f"satom {' '.join(walked + [token])}")
                break
            node = node.children[token]
            walked.append(token)
    assert not bad, "documented but not in the registry: " + ", ".join(sorted(set(bad)))


# ---------------------------------------------------------------------------
# 2. The published manual cannot drift from the Markdown
# ---------------------------------------------------------------------------

def test_published_site_documentation_is_current():
    gen = _load("gen_site_docs")
    pages = gen.build()
    stale = [p.relative_to(ROOT).as_posix() for p, t in pages.items()
             if not p.is_file() or p.read_text(encoding="utf-8") != t]
    assert not stale, ("published documentation is stale: " + ", ".join(stale) +
                       " — run: python3 deploy/gen_site_docs.py")


def test_every_published_page_has_a_source_document():
    gen = _load("gen_site_docs")
    for md_name, slug, *_rest in gen.PAGES:
        # source_for(), not DOCS/: the changelog is published from the repo
        # root. One resolver so the test and the generator agree on what exists.
        assert gen.source_for(md_name).is_file(), \
            f"{md_name} is published but its source document is missing"
        assert (SITE / "docs" / f"{slug}.html").is_file(), f"site/docs/{slug}.html not generated"


def test_hub_groups_cover_every_published_page():
    """A page generated but absent from every hub group is unreachable — it
    would exist at a URL nobody links to, which is the same as not shipping it."""
    gen = _load("gen_site_docs")
    grouped = {s for _n, _l, slugs in gen.GROUPS for s in slugs}
    published = {slug for _md, slug, *_r in gen.PAGES}
    assert published == grouped, (
        f"not linked from the hub: {sorted(published - grouped)}; "
        f"linked but not published: {sorted(grouped - published)}")


# ---------------------------------------------------------------------------
# 3. Nothing internal may reach the public site — generated OR hand-written
# ---------------------------------------------------------------------------

def _site_html() -> list[pathlib.Path]:
    return sorted(p for p in SITE.rglob("*.html") if p.is_file())


def test_site_html_files_exist():
    assert _site_html(), "no site/*.html found — the leak scan would pass vacuously"


@pytest.mark.parametrize("page", _site_html(), ids=lambda p: p.name)
def test_no_internal_identifier_is_published(page):
    gen = _load("gen_site_docs")
    findings = gen.scan(page.read_text(encoding="utf-8"), page.relative_to(ROOT).as_posix())
    assert not findings, "internal identifiers would be published:\n  " + "\n  ".join(findings)


def test_the_leak_scanner_actually_matches_something():
    """A scanner whose patterns never fire is indistinguishable from no scanner.
    Feed it one sample per forbidden class and require every class to bite."""
    gen = _load("gen_site_docs")
    samples = {
        "rfc1918 address": "connect to 192.0.2.248 now",
        "internal hostname": "browse https://node-a.example.net/",
        "hypervisor name": "the container lives on hypervisor06",
        "node name": "hostname is satom-node-1",
        # A BARE prefix is still an identifier. Requiring a trailing
        # character was the same anchoring mistake the hostname rule made
        # with wildcards, and it survived a clean repo scan only to turn up
        # on a LIVE served page.
        #
        # This sample is the ONLY guard that catches it: narrowing redact()
        # and scan() together leaves the round-trip test self-consistent and
        # still green. A round trip proves the two agree, not that either is
        # right.
        "node name (bare prefix)": "the satom-node prefix",
        "backup server name": "pushes to backup-server nightly",
        "device instance name": "the appliance faz01 was down",
        "personal e-mail": "alerts go to opensource@visionebc.com",
    }
    for expected, text in samples.items():
        klass = expected.split(" (")[0]   # keys may carry a variant suffix
        found = gen.scan(text, "sample")
        assert any(klass in f for f in found), f"scanner missed {expected!r}: {text!r}"


def test_redaction_leaves_no_finding():
    """Round trip: redact() output must survive scan(). If they ever disagree the
    generator aborts on its own input and nobody can publish at all."""
    gen = _load("gen_site_docs")
    dirty = ("Node satom-node-1 at 192.0.2.248 on hypervisor06 replicates to "
             "satom-node-2 (192.0.2.249), pushes to backup-server, serves "
             "satom-1.example.net, alerts opensource@visionebc.com, device faz01. "
             # the two forms that a label-anchored pattern missed on real text
             "Wildcard *.example.net, brace form satom{,-2}.example.net, "
             "and the shorthand pair 192.0.2.248/.249. "
             # bare prefix, found on a live page after the repo scan said clean
             "Bare prefix satom-node and satom-node too.")
    assert not gen.scan(gen.redact(dirty), "sample")


def test_product_identifiers_are_not_over_redacted():
    """ADOM keys and product URL segments must survive: rewriting /fadc/api/
    would mangle route documentation while disclosing nothing."""
    gen = _load("gen_site_docs")
    kept = "Open /fadc/api/ or /faz/m/ for the fortiweb registry."
    assert gen.redact(kept) == kept


def test_public_domains_survive_redaction():
    """visionebc.com and the GitHub org are the project's PUBLIC identity — the
    footer and Source link depend on them."""
    gen = _load("gen_site_docs")
    keep = "http://satom.visionebc.com and https://github.com/visionebc/SATOM"
    assert gen.redact(keep) == keep
    assert not gen.scan(keep, "sample")


# ---------------------------------------------------------------------------
# 4. The in-app catalog stays curated
# ---------------------------------------------------------------------------

def test_every_markdown_doc_is_either_published_or_deliberately_not():
    """The in-app curated index is gone (2026-08-02).

    Publication is opt-in, so this cannot demand that everything is published.
    What it CAN demand is that every published entry has a title and a blurb —
    the absence of which is how nine documents once spent months looking like
    debris in the old catalog — and that nothing is listed twice.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "pubdoc_curation", ROOT / "app" / "services" / "doc_publication.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    slugs = [e[1] for e in mod.PUBLIC_DOCS]
    assert len(slugs) == len(set(slugs)), "duplicate slug in PUBLIC_DOCS"
    for md, slug, title, icon, blurb in mod.PUBLIC_DOCS:
        assert title.strip(), md
        assert blurb.strip(), md
        assert mod.source_for(md).is_file(), md


# ---------------------------------------------------------------------------
# 5. The ownership repair must cover the directories root actually dirties
# ---------------------------------------------------------------------------

def test_repair_permissions_covers_docs_and_tests():
    """`execute repair permissions` scans a fixed subtree allowlist. `docs/` and
    `tests/` were missing from it, which is precisely where running as root
    leaves debris — pytest writes `tests/__pycache__`, and a doc edited as root
    stays root-owned. The command reported success while leaving files the next
    `git commit` as the service account would trip over.
    """
    src = (ROOT / "deploy/satom_cli/cmd_execute.py").read_text(encoding="utf-8")
    body = src.split("def repair_permissions", 1)[1].split("\ndef ", 1)[0]
    for sub in ('"docs"', '"tests"', '".git"', '"data"', '"reports"', '"site"'):
        assert sub in body, f"repair_permissions no longer scans {sub}"
# ---------------------------------------------------------------------------
# 4. Nav integrity of the hand-written pages
# ---------------------------------------------------------------------------
#
# The five hand-written pages carry the nav as a literal copy each. Every time a
# section is added, five files get patched — and a guard that matches loosely
# ("is the word already there?") reports "already applied" while inserting a
# second copy at a different indent. That happened with the Docs link: four of
# the five pages ended up rendering it twice.
#
# The invariant is cheap and exact: inside <div class="nav-links"> every href
# appears at most once. Same for the footer link list. A duplicate is never
# intentional there.

NAV_OPEN = '<div class="nav-links">'
FOOTER_OPEN = '<div class="flinks">'
_HREF = re.compile(r'href="([^"]+)"')


def _hand_written_pages():
    return sorted(p for p in SITE.glob("*.html") if p.is_file())


def _links_in(text: str, opener: str):
    """Anchors between `opener` and its closing </div>, or None if absent."""
    if opener not in text:
        return None
    return _HREF.findall(text.split(opener, 1)[1].split("</div>", 1)[0])


@pytest.mark.parametrize("page", _hand_written_pages(), ids=lambda p: p.name)
def test_nav_block_has_no_duplicate_link(page):
    links = _links_in(page.read_text(encoding="utf-8"), NAV_OPEN)
    assert links, f"{page.name}: no nav-links block found"
    dupes = sorted({h for h in links if links.count(h) > 1})
    assert not dupes, f"{page.name}: nav renders these links twice: {dupes}"


@pytest.mark.parametrize("page", _hand_written_pages(), ids=lambda p: p.name)
def test_footer_block_has_no_duplicate_link(page):
    links = _links_in(page.read_text(encoding="utf-8"), FOOTER_OPEN)
    if links is None:
        pytest.skip("page has no footer link list")
    dupes = sorted({h for h in links if links.count(h) > 1})
    assert not dupes, f"{page.name}: footer renders these links twice: {dupes}"


def test_every_hand_written_page_offers_the_same_nav():
    """A page missing an entry is the other half of the same defect: the manual
    patch reached four files and skipped the fifth. Compare sets, not order."""
    seen = {}
    for page in _hand_written_pages():
        links = _links_in(page.read_text(encoding="utf-8"), NAV_OPEN)
        if links:
            seen[page.name] = frozenset(links)
    assert seen, "no hand-written page carries a nav block"
    variants = set(seen.values())
    assert len(variants) == 1, (
        "hand-written pages disagree on the nav: "
        + "; ".join(f"{n}={sorted(v)}" for n, v in sorted(seen.items()))
    )
