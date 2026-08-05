"""Guards for the generated Release notes section of the public site.

WHY THIS SECTION EXISTS AT ALL
------------------------------
``CHANGELOG.md`` was published whole, as one page, and answering "what shipped
in 1.3.3?" meant scrolling a thousand lines. So the site now carries one page
per version. The danger that creates is the one this project keeps re-learning:
a second copy of something the repository already knows goes stale in public,
silently, because nobody gets a stack trace from a manual.

So every fact on those pages is DERIVED — the version list is the changelog's
own headings, the dates are its own dates, the teaser lines are the bold
lead-ins of its own bullets, and the "current release" badge is the repo-root
``VERSION`` file. These tests are what makes "derived" mean something:

* a version added to the changelog without regenerating fails the suite;
* a page left behind by a renamed version fails the suite;
* a page not linked from the hub fails the suite;
* a planted internal identifier ABORTS the build rather than publishing.

The leak scan over ``site/`` already covers this tree (it rglobs), and the
theme and reveal guards were widened in the same commit — a new directory of
pages that escaped those enumerations would have been invisible to all three.
"""
from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

import html as _html
import pytest

import leak_samples

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
SITE = ROOT / "site"
RELEASES = SITE / "releases"
HUB = SITE / "releases.html"
CHANGELOG = ROOT / "CHANGELOG.md"

#: the badge is a class, not a sentence -- see the note in the badge test
NOW_BADGE = 'class="rel-badge rel-now"'
NEXT_BADGE = 'class="rel-badge rel-next"'


def _load(name: str):
    if str(DEPLOY) not in sys.path:
        sys.path.insert(0, str(DEPLOY))
    spec = importlib.util.spec_from_file_location(name, DEPLOY / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def grn():
    return _load("gen_release_notes")


def _changelog_versions() -> list[str]:
    return re.findall(r"^## \[([^\]]+)\]", CHANGELOG.read_text(encoding="utf-8"), re.M)


# ---------------------------------------------------------------------------
# 1. The published pages match the changelog, both ways
# ---------------------------------------------------------------------------

def test_the_published_release_notes_are_current(grn):
    """The whole point: edit the changelog, forget the site -> red suite."""
    assert grn.main(["--check"]) == 0


def test_every_changelog_version_has_a_page(grn):
    for version in _changelog_versions():
        page = RELEASES / f"{grn.slug_for(version)}.html"
        assert page.is_file(), f"{version} has no published page ({page.name})"


def test_no_published_page_lacks_a_changelog_section(grn):
    """A version renamed in the changelog must not leave its page serving."""
    expected = {f"{grn.slug_for(v)}.html" for v in _changelog_versions()}
    actual = {p.name for p in RELEASES.glob("*.html")}
    assert actual == expected, f"orphaned: {sorted(actual - expected)}"


def test_the_hub_links_every_version_and_only_those(grn):
    html = HUB.read_text(encoding="utf-8")
    linked = set(re.findall(r'href="releases/([^"]+)\.html"', html))
    expected = {grn.slug_for(v) for v in _changelog_versions()}
    assert linked == expected, (
        f"not linked: {sorted(expected - linked)}; "
        f"linked but absent: {sorted(linked - expected)}")


def test_the_hub_lists_versions_newest_first(grn):
    """File order IS newest-first in the changelog; the hub must not resort."""
    html = HUB.read_text(encoding="utf-8")
    order = re.findall(r'href="releases/([^"]+)\.html"', html)
    assert order == [grn.slug_for(v) for v in _changelog_versions()]


# ---------------------------------------------------------------------------
# 2. Nothing on these pages is typed by hand
# ---------------------------------------------------------------------------

def test_the_current_badge_follows_the_VERSION_file(grn):
    """A version literal is how the console footer sat at v1.0 for four
    releases. The badge has to be derived or it will lie the same way."""
    shipped = grn.shipped_version()
    page = RELEASES / f"{grn.slug_for(shipped)}.html"
    assert page.is_file(), f"the shipped version {shipped} has no page"
    # Keyed on the badge MARKUP, not on its words: the changelog entry that
    # announced this section contains the phrase "current release" in prose,
    # and the first version of this guard read that as a second page claiming
    # to be current. A guard matches the artefact, never a phrase documentation
    # is free to use.
    assert NOW_BADGE in page.read_text(encoding="utf-8")
    others = [p for p in RELEASES.glob("*.html") if p != page
              and NOW_BADGE in p.read_text(encoding="utf-8")]
    assert not others, [p.name for p in others]


def test_the_unreleased_section_is_not_dressed_as_a_release(grn):
    """Merged-but-not-cut work must say so; filing it under the shipped
    version would make the published release notes false."""
    if "Unreleased" not in _changelog_versions():
        pytest.skip("no unreleased section right now")
    page = (RELEASES / "unreleased.html").read_text(encoding="utf-8")
    assert NEXT_BADGE in page
    assert NOW_BADGE not in page


def test_hub_teasers_come_from_the_changelog_bullets(grn):
    """The teaser lines are the sections' own bold lead-ins, not a summary
    someone wrote once and will never revisit."""
    secs = grn.sections()
    rich = [s for s in secs if s["leads"]]
    assert rich, "no section has a bold lead-in -- the teaser would be empty"
    # Unescape before comparing: the renderer turns an apostrophe into
    # `&#x27;`, so a raw-Markdown substring can never match a correct page.
    # Narrowing the lead-in instead would let the guard pass on a hub that
    # dropped the teaser entirely.
    html = _html.unescape(HUB.read_text(encoding="utf-8"))
    for lead in rich[0]["leads"]:
        needle = _html.unescape(lead)[:40]
        assert needle in html, f"teaser missing from the hub: {needle!r}"


def test_subheadings_are_deduplicated(grn):
    """A version with three `### Changed` blocks was advertising
    "Changed - Changed - Changed": a count of headings dressed as a summary."""
    body = "### Added\n\n- a\n\n### Changed\n\n- b\n\n### Changed\n\n- c\n"
    assert grn.kinds_of(body) == ["Added", "Changed"]


def test_a_section_of_prose_headings_shows_one_not_five(grn):
    """Version 1.3.1 heads each defect with a sentence. Listing all five filled
    the card before the reader reached a single entry."""
    body = ("### The mirror published the network map\n\n- a\n\n"
            "### The device API was never documented\n\n- b\n\n"
            "### The manual rendered blank\n\n- c\n")
    assert grn.kinds_of(body) == ["The mirror published the network map"]
    # ...but the Keep-a-Changelog kinds are all worth showing.
    assert grn.kinds_of("### Added\n\n- a\n\n### Fixed\n\n- b\n") == ["Added", "Fixed"]
    # A short SENTENCE is still a headline, not a kind. A length threshold read
    # "The manual rendered blank" (25 characters) as one.
    assert grn.kinds_of("### The manual rendered blank\n\n- a\n") == \
        ["The manual rendered blank"]


def test_teasers_carry_no_markdown_markers(grn):
    """Teasers are rendered as escaped text, so a lead-in written with
    backticks would show its backticks."""
    # The underscore SURVIVES: it is snake_case, not emphasis.
    assert grn.plain("`server_name` and the *SAN*.") == "server_name and the SAN"
    assert grn.plain("**push_to_adguard**") == "push_to_adguard"
    for sec in grn.sections():
        for lead in sec["leads"]:
            assert not set("`*") & set(lead), (sec["version"], lead)


def test_slug_is_stable_and_url_safe(grn):
    assert grn.slug_for("1.3.5") == "v1.3.5"
    assert grn.slug_for("Unreleased") == "unreleased"
    assert grn.slug_for("1.2 RC/1") == "v1.2-rc-1"


# ---------------------------------------------------------------------------
# 3. Publication safety
# ---------------------------------------------------------------------------

def _sandbox(grn, tmp_path, monkeypatch, changelog_text: str):
    """Point the generator at a throwaway source AND a throwaway destination.

    Redirecting only the INPUT is not a sandbox: the first version of this test
    did exactly that, the scan passed, and ``main([])`` went on to rewrite the
    real ``site/releases/`` and delete the fourteen pages it exists to guard.
    A generator test has to move both ends or it is a generator run.
    """
    src = tmp_path / "CHANGELOG.md"
    src.write_text(changelog_text, encoding="utf-8")
    monkeypatch.setattr(grn, "CHANGELOG", src)
    monkeypatch.setattr(grn, "OUT_DIR", tmp_path / "out")
    monkeypatch.setattr(grn, "HUB", tmp_path / "out.html")
    return src


# Two halves, and BOTH are required. The first version of this test planted an
# identifier and expected an abort -- it got a clean build, because redact()
# had already rewritten the identifier to a placeholder. That is the pipeline
# working. But a test that only checks the round trip is satisfied by a
# redact()/scan() pair narrowed together until neither sees anything, which is
# the documented way this project has published identifiers before. So: one
# test that redaction really removes them, and one that the abort path is live
# when redaction misses.

@leak_samples.requires_corpus
@pytest.mark.parametrize("kind", sorted(leak_samples.SAMPLES["by_class"])
                         if leak_samples.SAMPLES else [])
def test_a_planted_identifier_never_reaches_the_page(grn, tmp_path, monkeypatch, kind):
    """Every forbidden class, not one: a pipeline that scrubs addresses and
    misses hostnames publishes hostnames."""
    sample = leak_samples.SAMPLES["by_class"][kind]
    _sandbox(grn, tmp_path, monkeypatch,
             f"# Changelog\n\n## [9.9] - 2026-01-01\n\n### Added\n\n- Reach {sample} now.\n")
    assert grn.main([]) == 0
    page = (tmp_path / "out" / "v9.9.html").read_text(encoding="utf-8")
    assert sample not in page, f"a {kind} was published verbatim"


@leak_samples.requires_corpus
def test_the_abort_path_is_live_when_redaction_misses(grn, tmp_path, monkeypatch):
    """Fail-closed, like the manual: never a warning and a push. Neutralise
    redaction and the build must refuse rather than write."""
    sample = leak_samples.SAMPLES["by_class"]["rfc1918 address"]
    _sandbox(grn, tmp_path, monkeypatch,
             f"# Changelog\n\n## [9.9] - 2026-01-01\n\n### Added\n\n- Reach {sample} now.\n")
    monkeypatch.setattr(grn.gsd, "redact", lambda text: text)
    assert grn.main([]) == 1, "the generator would have published the identifier"
    assert not (tmp_path / "out").exists(), "it wrote pages despite the finding"


def test_check_is_not_vacuous(grn, tmp_path, monkeypatch):
    """A --check that cannot fail is a --check that guards nothing."""
    _sandbox(grn, tmp_path, monkeypatch,
             "# Changelog\n\n## [42.0] - 2026-01-01\n\n### Added\n\n- Something.\n")
    assert grn.main(["--check"]) == 1


def test_check_writes_nothing(grn, tmp_path, monkeypatch):
    """--check is what CI runs; it must never touch the tree."""
    _sandbox(grn, tmp_path, monkeypatch,
             "# Changelog\n\n## [42.0] - 2026-01-01\n\n### Added\n\n- Something.\n")
    grn.main(["--check"])
    assert not (tmp_path / "out").exists() and not (tmp_path / "out.html").exists()


def test_release_pages_carry_no_markdown_links(grn):
    """Same defect the manual had: links that render and 404 when followed."""
    for page in RELEASES.glob("*.html"):
        dead = re.findall(r'href="[^"]*\.md(?:#[^"]*)?"', page.read_text(encoding="utf-8"))
        assert not dead, f"{page.name} links to unpublishable Markdown: {dead[:5]}"


# ---------------------------------------------------------------------------
# 4. The section is reachable, and it owns its name
# ---------------------------------------------------------------------------

def test_the_site_nav_offers_the_release_notes():
    nav = dict(_load("gen_site_docs").NAV)
    assert nav.get("releases.html") == "Releases"


@pytest.mark.parametrize("page", ["index.html", "features.html", "architecture.html",
                                  "safeguards.html", "install.html"])
def test_curated_pages_link_the_release_notes(page):
    html = (SITE / page).read_text(encoding="utf-8")
    assert html.count('href="releases.html"') == 2, f"{page}: nav and footer"


def test_the_vendor_corpus_no_longer_calls_itself_release_notes():
    """Two different things named 'Release notes' is how an operator plans an
    upgrade from the wrong document: docs/release_notes.md is FORTINET's
    known-issue corpus, not SATOM's history."""
    from app.services import doc_publication as pubdoc
    entry = next(e for e in pubdoc.PUBLIC_DOCS if e[0] == "release_notes.md")
    title = entry[2].lower()
    assert "release notes" not in title, entry[2]
    assert "vendor" in title or "advisor" in title, entry[2]


def test_the_site_page_enumerations_cover_the_release_tree():
    """The theme and reveal guards enumerate pages themselves. A directory
    they do not walk is a directory whose pages are unguarded."""
    import test_site_reveal
    import test_site_theme
    covered_reveal = {p.resolve() for p in test_site_reveal.PAGES}
    covered_theme = {p.resolve() for p in test_site_theme._pages()}
    for page in RELEASES.glob("*.html"):
        assert page.resolve() in covered_reveal, f"reveal guard skips {page.name}"
        assert page.resolve() in covered_theme, f"theme guard skips {page.name}"

