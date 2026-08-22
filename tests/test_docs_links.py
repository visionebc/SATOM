"""In-product links into the published manual.

``docs_url()`` returns the HUB (``…/docs.html``); ``docs_url('slug')`` returns
one document (``…/docs/slug.html``). Two templates built the second by
CONCATENATING onto the first — ``{{ docs_url() }}/docs/ai-advisor.html`` — which
renders ``…/docs.html/docs/ai-advisor.html``, a 404 that nothing tested and
nobody would notice until they clicked it. The helper exists precisely so the
address is written once; sticking a path onto its output reintroduces the
second author it was meant to remove.
"""
import pathlib
import re

import pytest

from app.services.doc_publication import PUBLIC_DOCS, site_url

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATES = sorted((ROOT / "app" / "templates").rglob("*.html"))


def test_no_template_builds_a_document_url_by_concatenation():
    bad = []
    for p in TEMPLATES:
        for n, line in enumerate(p.read_text(errors="ignore").splitlines(), 1):
            if re.search(r"docs_url\(\s*\)\s*\}\}\s*/", line):
                bad.append("%s:%d" % (p.relative_to(ROOT), n))
    assert not bad, (
        "docs_url() is the hub URL and already ends in /docs.html; append a "
        "path to it and you get …/docs.html/docs/x.html, which is a 404. Pass "
        "the slug instead: docs_url('x'). Offenders: %s" % bad)


@pytest.mark.parametrize("slug", sorted({e[1] for e in PUBLIC_DOCS}))
def test_every_slug_the_helper_can_be_asked_for_has_a_generated_page(slug):
    """The helper cannot 404 on our side: a slug it will build a URL for must
    have a page in the generated tree."""
    assert (ROOT / "site" / "docs" / ("%s.html" % slug)).is_file(), slug
    assert site_url(slug).endswith("/docs/%s.html" % slug)
