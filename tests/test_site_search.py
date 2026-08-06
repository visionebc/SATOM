"""Guards for the published site's search and its wide reading column.

WHY THESE EXIST
---------------
Both features are pure presentation, and presentation is where this project's
defects hide: the page returns 200, the HTML is complete, the leak scan is
clean, and the thing still does not work. Two real examples came out of
building exactly this:

* the release search index was assembled from the RAW changelog, so it walked
  three internal identifiers straight past ``redact()``. The publication scan
  caught it only because it re-checks the OUTPUT and aborts. Every path out of
  a source document redacts, or the one that does not is the leak;
* the clear button and the filtered version rail are toggled with the
  ``hidden`` attribute, and each carries an author ``display:`` rule. ``hidden``
  is only ``display:none`` in the UA stylesheet, so it lost — the ``×`` showed
  on an empty box and the rail never filtered. Both rendered perfectly.

So these guards assert BEHAVIOUR-BEARING artefacts (the index contents, the
CSS that makes hiding work, the class the script re-adds), not the presence of
markup.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
DOCS = SITE / "docs"
RELEASES = SITE / "releases"
CSS = (SITE / "assets" / "site.css").read_text(encoding="utf-8")
JS = (SITE / "assets" / "site.js").read_text(encoding="utf-8")


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def gsd():
    return _load("gen_site_docs")


@pytest.fixture(scope="module")
def grn():
    return _load("gen_release_notes")


_INDEX = r'<script type="application/json" id="%s">(.*?)</script>'


def _index(text: str, ident: str):
    m = re.search(_INDEX % ident, text, re.DOTALL)
    assert m, f"no #{ident} payload on the page"
    return json.loads(m.group(1))


def _uncommented_css() -> str:
    """CSS with comments removed.

    Twelve guards in this repository have matched their own explanatory
    comment. The comments here name every selector they explain, so an
    assertion over the raw text would pass with the rule deleted.
    """
    return re.sub(r"/\*.*?\*/", "", CSS, flags=re.DOTALL)


def _uncommented_js() -> str:
    out = re.sub(r"/\*.*?\*/", "", JS, flags=re.DOTALL)
    return "\n".join(ln for ln in out.splitlines()
                     if not ln.lstrip().startswith("//"))


# ---------------------------------------------------------------------------
# 1. The manual's search index
# ---------------------------------------------------------------------------

def test_the_manual_index_lists_every_published_document(gsd):
    """Derived from the registry, so a document added to PUBLIC_DOCS is
    searchable the day it is published rather than the day someone remembers
    to extend a second list."""
    idx = _index((SITE / "docs.html").read_text(encoding="utf-8"), "docsearch-index")
    assert {d["s"] for d in idx} == {slug for _md, slug, *_ in gsd.PAGES}


def test_the_manual_index_carries_section_headings():
    """Half of what an operator searches for is a numbered subsection. An index
    of 27 titles would send them to a twelve-hundred-line page and leave them
    to scroll, which is what they were already doing."""
    idx = _index((SITE / "docs.html").read_text(encoding="utf-8"), "docsearch-index")
    guide = next(d for d in idx if d["s"] == "user-guide")
    assert len(guide["h"]) >= 20, "the user guide indexed almost no headings"
    page = (DOCS / "user-guide.html").read_text(encoding="utf-8")
    for h in guide["h"][:40]:
        assert h["a"], f"heading {h['t']!r} has no anchor to link to"
        assert f'id="{h["a"]}"' in page, (
            f"anchor {h['a']!r} does not exist on the page it points at")


def test_every_indexed_document_has_the_page_it_points_at():
    idx = _index((SITE / "docs.html").read_text(encoding="utf-8"), "docsearch-index")
    missing = [d["s"] for d in idx if not (DOCS / f"{d['s']}.html").is_file()]
    assert not missing, missing


# ---------------------------------------------------------------------------
# 2. The release search index — and the redaction it must not bypass
# ---------------------------------------------------------------------------

def test_the_release_index_covers_every_version_that_has_entries(grn):
    idx = _index((SITE / "releases.html").read_text(encoding="utf-8"), "relsearch-index")
    indexed = {r["v"] for r in idx}
    expected = {s["version"] for s in grn.sections() if s["entries"]}
    assert indexed == expected, (
        f"not indexed: {sorted(expected - indexed)}; "
        f"indexed but not in the changelog: {sorted(indexed - expected)}")


def test_every_indexed_change_names_the_release_it_shipped_in():
    """The whole point of searching across releases is the answer to "which
    version was that in?". A record without a version is a result that cannot
    be labelled."""
    idx = _index((SITE / "releases.html").read_text(encoding="utf-8"), "relsearch-index")
    assert idx, "the release index is empty"
    for r in idx:
        assert r["v"], f"a change with no version: {r!r}"
        assert r["t"].strip(), f"a change with no title: {r!r}"
        assert (RELEASES / f"{r['s']}.html").is_file(), r["s"]


def test_a_planted_identifier_never_reaches_the_search_index(grn, tmp_path,
                                                             monkeypatch):
    """The index is a SECOND path out of the changelog.

    The rendered body goes through ``redact()``; the first version of the index
    was parsed from the raw Markdown and did not. This is that defect, pinned.
    """
    sample = "192.0.2.248"
    src = tmp_path / "CHANGELOG.md"
    src.write_text("# Changelog\n\n## [9.9] - 2026-01-01\n\n### Added\n\n"
                   f"- **Reachability.** The node answers on {sample} now.\n",
                   encoding="utf-8")
    monkeypatch.setattr(grn, "CHANGELOG", src)
    monkeypatch.setattr(grn, "OUT_DIR", tmp_path / "out")
    monkeypatch.setattr(grn, "HUB", tmp_path / "out.html")
    assert grn.main([]) == 0
    hub = (tmp_path / "out.html").read_text(encoding="utf-8")
    assert sample not in hub
    payload = _index(hub, "relsearch-index")
    assert sample not in json.dumps(payload), "the index published it verbatim"


# ---------------------------------------------------------------------------
# 3. The version rail
# ---------------------------------------------------------------------------

def _rail(text: str) -> str:
    return "\n".join(re.findall(r'<a class="rel-nav-item[^>]*>.*?</a>',
                                text, re.DOTALL))


def test_the_version_rail_never_wears_the_current_release_badge():
    """A neighbouring guard proves exactly one page claims to be current, by
    looking for that badge's markup. The rail appears on all eighteen pages —
    painting the badge there would make all eighteen claim it and the other
    guard would be measuring nothing."""
    for page in [SITE / "releases.html", *sorted(RELEASES.glob("*.html"))]:
        rail = _rail(page.read_text(encoding="utf-8"))
        assert rail, f"{page.name} has no version rail"
        assert 'class="rel-badge rel-now"' not in rail, page.name


@pytest.mark.parametrize("page", sorted(RELEASES.glob("*.html")),
                         ids=lambda p: p.name)
def test_every_release_page_carries_the_whole_rail(grn, page):
    """The rail is the navigation. A page that only lists its neighbours turns
    "when did this change?" back into scrolling the changelog."""
    rail = _rail(page.read_text(encoding="utf-8"))
    for sec in grn.sections():
        assert f'href="{sec["slug"]}.html"' in rail, (
            f"{page.name} does not link {sec['slug']}")


def test_the_hub_rail_is_the_only_place_it_links_a_version_page(grn):
    """Guarded next door as an ordered list-equality; asserted here as the
    reason, so a second link list fails with a message that explains itself."""
    hub = (SITE / "releases.html").read_text(encoding="utf-8")
    for sec in grn.sections():
        n = hub.count(f'href="releases/{sec["slug"]}.html"')
        assert n == 1, f"{sec['slug']} is linked {n} times, expected exactly 1"


# ---------------------------------------------------------------------------
# 4. The wide reading column
# ---------------------------------------------------------------------------

WIDE = [SITE / "docs.html", SITE / "releases.html",
        *sorted(DOCS.glob("*.html")), *sorted(RELEASES.glob("*.html"))]
NARROW = [SITE / p for p in ("index.html", "features.html", "architecture.html",
                             "safeguards.html", "install.html")]


@pytest.mark.parametrize("page", WIDE, ids=lambda p: p.name)
def test_reading_pages_opt_into_the_wide_column(page):
    assert '<body class="wide">' in page.read_text(encoding="utf-8")


@pytest.mark.parametrize("page", NARROW, ids=lambda p: p.name)
def test_marketing_pages_keep_the_narrow_column(page):
    """Prose that is not a manual reads better at 1120px, and a guard that
    accepted either would not be checking anything."""
    assert '<body class="wide">' not in page.read_text(encoding="utf-8")


def test_the_column_widens_only_above_a_laptop_screen():
    """80% of a 1280px screen is 1024px — NARROWER than the 1120px it replaces.
    Applying it unconditionally would have made the manual harder to read on
    the machines most operators actually use."""
    css = _uncommented_css()
    m = re.search(r"@media\s*\(min-width:\s*(\d+)px\)\s*\{([^{]*\{[^}]*\}\s*)+\}", css)
    assert m, "no min-width media query wrapping the wide column"
    block = m.group(0)
    assert int(m.group(1)) >= 1200, "widened below the width it replaces"
    assert re.search(r"body\.wide\s+\.wrap\s*\{[^}]*max-width:\s*80%", block), \
        "body.wide .wrap does not reach 80% inside the breakpoint"
    assert "body.wide" not in css.replace(block, ""), \
        "the wide column also applies outside the breakpoint"


# ---------------------------------------------------------------------------
# 5. The two mechanisms that make filtering actually work
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("selector", ["ss-clear", "ss-hit", "rel-nav-item"])
def test_hidden_is_re_asserted_for_every_script_toggled_element(selector):
    """`hidden` is UA-stylesheet `display:none`; any author `display:` rule
    outranks it. All three of these carry one, and all three are toggled from
    script — this is the rule that makes `el.hidden = true` mean anything."""
    css = _uncommented_css()
    rule = re.search(r"([^{}]*\[hidden\][^{}]*)\{([^}]*)\}", css)
    assert rule, "nothing re-asserts the hidden attribute"
    assert f"{selector}[hidden]" in rule.group(1).replace("\n", " ").replace(" ", ""), \
        f"{selector} is toggled from script but hidden cannot hide it"
    assert "display:none" in rule.group(2).replace(" ", "")


def test_search_puts_back_the_reveal_class_on_what_it_un_hides():
    """The browsable sections are `.reveal`. A block that was display:none
    while the intersection observer ran was never observed, so clearing the
    query would restore it at opacity 0 — permanently blank, which is the
    failure this site has already shipped once."""
    js = _uncommented_js()
    m = re.search(r"docBrowse\.forEach\(function \(el\) \{([^}]*)\}\);", js)
    assert m, "the restore path is gone"
    assert "el.hidden = false" in m.group(1)
    assert "classList.add('in')" in m.group(1)


def test_the_search_boxes_are_never_inside_a_reveal_block():
    """A reveal starts at opacity 0 and waits for an observer. A search box
    that is invisible until you scroll past it is a search box nobody finds."""
    for page, ident in ((SITE / "docs.html", "docsearch"),
                        (SITE / "releases.html", "relsearch")):
        text = page.read_text(encoding="utf-8")
        m = re.search(r'<section class="([^"]*)"[^>]*>(?:(?!</section>).)*?'
                      + ident + r"-input", text, re.DOTALL)
        assert m, f"no section wraps #{ident}-input on {page.name}"
        assert "reveal" not in m.group(1), (
            f"the {ident} box sits inside a reveal block on {page.name}")


def test_the_index_escapes_the_tag_that_would_close_its_own_block():
    """A literal `</script>` inside the JSON would end the block early and
    dump the rest of the index into the document as text."""
    for page, ident in ((SITE / "docs.html", "docsearch-index"),
                        (SITE / "releases.html", "relsearch-index")):
        raw = re.search(_INDEX % ident, page.read_text(encoding="utf-8"),
                        re.DOTALL).group(1)
        assert "<" not in raw, "an unescaped < survived into the payload"
        json.loads(raw)


# ---------------------------------------------------------------------------
# 6. Entities survive exactly one escaping pass
# ---------------------------------------------------------------------------

def test_headings_are_not_escaped_twice():
    """markdown's toc tokens arrive ALREADY HTML-escaped.

    Escaping them again shipped ``Backups &amp;amp; restore`` into the sidebar
    of every manual page — visible to a reader as a literal ``&amp;``. It only
    shows on a heading containing ``& < > "``, which is why it survived until a
    search index inherited it. One escaping pass, at render.
    """
    for page in sorted(DOCS.glob("*.html")):
        text = page.read_text(encoding="utf-8")
        for a in re.findall(r'<a href="#[^"]*">([^<]*)</a>', text):
            assert "&amp;amp;" not in a and "&amp;lt;" not in a, \
                f"{page.name}: double-escaped table-of-contents entry {a!r}"


def test_the_search_index_stores_plain_text_not_markup():
    """The script escapes on render. Storing escaped text would double it
    there too, and the reader would see the entity in a search result."""
    idx = _index((SITE / "docs.html").read_text(encoding="utf-8"), "docsearch-index")
    amp = [h["t"] for d in idx for h in d["h"] if "&" in h["t"]]
    assert amp, "no heading contains an ampersand -- this guard proves nothing"
    for t in amp:
        assert "&amp;" not in t, f"index holds escaped markup: {t!r}"


def test_release_anchor_keys_survive_an_ampersand(grn):
    """The id map is keyed on the heading text read from Markdown, so the
    escaped token would never match and every hit under that heading would
    land at the top of the page instead of at its section."""
    _body, ids = grn.render_body(
        {"body": "### Fixed & found\n\n- **A.** thing\n", "version": "9.9",
         "slug": "v9.9", "date": "2026-01-01"})
    assert "Fixed & found" in ids, ids
