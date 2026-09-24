"""Every link inside the generated site resolves, and so does its anchor.

Nothing checked this, and 25 broken links went public in 2.1.2: release pages
pointed at site/releases/cli.html (the manual is site/docs/), the changelog
linked LICENSE and NOTICE (files the site does not publish), and 14 table-of-
contents entries in the user guide pointed at ids python-markdown never
generated, because the Markdown is written against GitHub's anchors. Each page
returned 200; only following the link showed the 404.
"""
import html.parser
import pathlib
import posixpath
import re
from urllib.parse import unquote, urlsplit

import pytest

from app.services import doc_publication as pubdoc

ROOT = pathlib.Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
PAGES = sorted(p for p in SITE.rglob("*.html")
               if "shots" not in p.parts and p.name != "404.html")
# Written by the site repo's deploy.sh at deploy time, never by this tree.
ASSEMBLED_AT_DEPLOY = {"favicon.ico"}
# The index gallery links captures that may not exist yet and renders a
# "screenshot pending" tile until they do. Exempt BY NAME, from the README that
# declares them: a pattern would also excuse a typo in a real link.
_SHOTS = SITE / "assets" / "shots"
PENDING_SHOTS = {_SHOTS / n for n in re.findall(
    r"`([\w.-]+\.png)`", (_SHOTS / "README.md").read_text(encoding="utf-8"))} \
    if (_SHOTS / "README.md").exists() else set()


class _Links(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs, self.ids = [], set()

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for key in ("id", "name"):
            if a.get(key):
                self.ids.add(a[key])
        if tag == "a" and a.get("href"):
            self.hrefs.append(a["href"])


_CACHE = {}


def _parse(page: pathlib.Path) -> _Links:
    if page not in _CACHE:
        p = _Links()
        p.feed(page.read_text(encoding="utf-8"))
        _CACHE[page] = p
    return _CACHE[page]


def _broken(page: pathlib.Path) -> list[str]:
    bad = []
    for href in _parse(page).hrefs:
        u = urlsplit(href)
        if u.scheme or u.netloc or href.startswith("/"):
            continue
        rel = unquote(u.path)
        if rel:
            target = pathlib.Path(posixpath.normpath(
                posixpath.join(page.parent.as_posix(), rel)))
            if target.is_dir():
                target = target / "index.html"
            if not target.exists():
                if target.name not in ASSEMBLED_AT_DEPLOY and target not in PENDING_SHOTS:
                    bad.append("%s (no such file)" % href)
                continue
        else:
            target = page
        if u.fragment and target.suffix == ".html" and u.fragment not in _parse(target).ids:
            bad.append("%s (no id %r)" % (href, u.fragment))
    return bad


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.relative_to(SITE).as_posix())
def test_every_link_in_the_generated_site_resolves(page):
    bad = _broken(page)
    assert not bad, "%s links to %d target(s) that do not exist: %s" % (
        page.relative_to(ROOT), len(bad), bad[:10])


def test_the_link_check_actually_finds_a_broken_link(tmp_path):
    """A checker that resolves nothing reports every page clean."""
    page = SITE / "docs" / "_probe.html"
    _CACHE[page] = _Links()
    _CACHE[page].feed('<a href="cli.html#nope">x</a><a href="LICENSE">l</a>'
                      '<code>&lt;a href="missing.html"&gt;</code>')
    got = _broken(page)
    assert any("nope" in b for b in got) and any("LICENSE" in b for b in got), got
    assert not any("missing.html" in b for b in got), "text inside <code> is not a link"


def test_headings_get_githubs_ids():
    assert pubdoc.github_slug("7. Server objects & the generic object editor") == \
        "7-server-objects--the-generic-object-editor"
    assert pubdoc.github_slug("2. Core concepts") == "2-core-concepts"


def test_relink_points_release_pages_at_the_manual():
    body = pubdoc.relink('<a href="docs/cli.md#x">c</a>', base="", prefix="../docs/")
    assert 'href="../docs/cli.html#x"' in body, body


def test_relink_sends_repository_files_to_the_source():
    body = pubdoc.relink('<a href="../deploy/satom-installer.sudoers">s</a>'
                         '<a href="LICENSE">l</a>', base="docs")
    assert 'href="%s/blob/main/deploy/satom-installer.sudoers"' % pubdoc.SOURCE_URL in body
    # LICENSE relative to docs/ is docs/LICENSE, which does not exist: left alone
    # (and the site test above then fails on it) rather than guessed at.
    assert 'href="LICENSE"' in body
    root = pubdoc.relink('<a href="LICENSE">l</a>', base="")
    assert 'href="%s/blob/main/LICENSE"' % pubdoc.SOURCE_URL in root


def test_relink_leaves_external_and_in_page_links_alone():
    src = '<a href="https://x.example/a">a</a><a href="#top">t</a><a href="mailto:a@b">m</a>'
    assert pubdoc.relink(src, base="docs") == src
