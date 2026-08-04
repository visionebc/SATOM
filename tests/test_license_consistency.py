"""The licence has to say the same thing on every surface.

SATOM states its licence in eight places: ``LICENSE``, ``NOTICE``,
``README.md``, ``CONTRIBUTING.md``, ``DISCLAIMER``, ``SECURITY.md``, the six
hand-written pages under ``site/`` and the footer template inside
``deploy/gen_site_docs.py`` that stamps the generated documentation pages.

Nothing *fails* when one of them goes stale -- the number simply lies. That is
exactly how ``Version: 1.0`` survived four releases in the README while the
console, the pipeline and the public site all said something else. A licence
that disagrees with itself is worse: a reader who acts on the wrong surface is
relying on a grant that was never made.

These guards pin the whole set to one answer.
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

LICENSE_NAME = "Elastic License 2.0"
OLD_LICENSE = "Apache"

#: Files whose job is to state the licence. None of them may name the old one.
DECLARING = ["NOTICE", "README.md", "CONTRIBUTING.md", "DISCLAIMER", "SECURITY.md"]

#: Hand-written site pages. The generated ones under ``site/docs`` are checked
#: through their footer, because their *body* is rendered from Markdown that may
#: legitimately discuss the old licence (the changelog entry announcing the
#: change does exactly that).
CURATED_PAGES = ["index.html", "features.html", "architecture.html",
                 "install.html", "safeguards.html", "docs.html"]

FOOTER_RE = re.compile(r"©\s*<span class=\"year\">.*?</p>", re.S)


#: Affirmative claims that SATOM *is* open source. A denial ("not an OSI
#: open-source license") is correct and must not trip the guard -- matching the
#: bare phrase would ban the very sentence that sets the record straight.
OSI_CLAIMS = [
    "is open source",
    "is free, open-source",
    "open-source project",
    "open source project",
    "open-source software",
    "open source software",
]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _flat(txt: str) -> str:
    """Collapse whitespace.

    The licence body is hard-wrapped at ~80 columns, so any assertion on a
    sentence that spans a line break silently fails against text that is
    perfectly correct.
    """
    return " ".join(txt.split())


def _footer(html: str) -> str:
    m = FOOTER_RE.search(html)
    assert m, "page has no copyright footer"
    return m.group(0)


# --------------------------------------------------------------- LICENSE file
def test_license_file_is_the_elastic_license():
    flat = _flat(_read("LICENSE"))
    assert LICENSE_NAME in flat
    # Distinctive operative sentence -- a header that merely *names* ELv2 while
    # the body is still Apache would pass a name check.
    assert ("You may not provide the software to third parties as a hosted or "
            "managed service") in flat
    assert "## No Liability" in _read("LICENSE")


def test_license_file_no_longer_carries_the_apache_text():
    txt = _read("LICENSE")
    # The scope header legitimately *references* Apache-2.0 to say which terms
    # earlier copies were received under. What must be gone is the grant itself,
    # so pin the markers unique to the Apache body.
    for marker in ("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
                   "www.apache.org/licenses/LICENSE-2.0",
                   "Licensed under the Apache License, Version 2.0"):
        assert marker not in txt, f"the old licence body is still in LICENSE: {marker!r}"


def test_license_file_names_the_licensor_and_the_commercial_contact():
    txt = _read("LICENSE")
    assert "Vision EBC" in txt
    assert "licensing@visionebc.com" in txt


# ---------------------------------------------------------- declaring surfaces
@pytest.mark.parametrize("rel", DECLARING)
def test_declaring_file_names_the_current_license(rel):
    txt = _read(rel)
    assert LICENSE_NAME in txt or "Elastic License" in txt, (
        f"{rel} does not name the project licence")


@pytest.mark.parametrize("rel", DECLARING)
def test_declaring_file_does_not_name_the_old_license(rel):
    txt = _read(rel)
    assert OLD_LICENSE not in txt, (
        f"{rel} still refers to {OLD_LICENSE}; the project is under "
        f"{LICENSE_NAME}")


@pytest.mark.parametrize("rel", DECLARING)
def test_declaring_file_does_not_claim_osi_open_source(rel):
    """ELv2 is source-available. Claiming open source is a false claim."""
    txt = _read(rel).lower()
    for phrase in OSI_CLAIMS:
        assert phrase not in txt, (
            f"{rel} claims SATOM is {phrase!r}; under {LICENSE_NAME} it is "
            "source-available, not OSI open source")


# ------------------------------------------------------------------- the site
@pytest.mark.parametrize("page", CURATED_PAGES)
def test_curated_page_footer_states_the_current_license(page):
    footer = _footer(_read(f"site/{page}"))
    assert LICENSE_NAME in footer
    assert OLD_LICENSE not in footer


def test_generated_doc_pages_exist_and_agree():
    pages = sorted((ROOT / "site" / "docs").glob("*.html"))
    assert pages, "no generated documentation pages"
    for p in pages:
        footer = _footer(p.read_text(encoding="utf-8"))
        assert LICENSE_NAME in footer, f"{p.name} footer is stale"
        assert OLD_LICENSE not in footer, f"{p.name} footer names the old licence"


def test_generator_template_and_hand_written_pages_cannot_drift():
    """The generated footer and the curated footer must be the same string.

    Two authors of the same sentence is how ``index.html`` silently lost its
    Docs link once already.
    """
    gen = _read("deploy/gen_site_docs.py")
    m = re.search(r'Vision EBC · Licensed under the <a href="\{SOURCE_URL\}'
                  r'/blob/main/LICENSE">([^<]+)</a>', gen)
    assert m, "generator footer template not found or reshaped"
    assert m.group(1) == LICENSE_NAME

    template = _footer(_read("site/index.html"))
    for page in CURATED_PAGES[1:]:
        assert _footer(_read(f"site/{page}")) == template, (
            f"site/{page} footer has drifted from site/index.html")


def test_site_never_calls_the_project_open_source():
    for p in sorted((ROOT / "site").glob("*.html")):
        low = p.read_text(encoding="utf-8").lower()
        assert "open-source project" not in low and "open source project" not in low, (
            f"{p.name} calls SATOM an open-source project")
