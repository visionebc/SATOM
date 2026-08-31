"""The container shape is described in prose, and prose does not fail.

`app/runtime.py` owns the capability set. Four documentation surfaces state its
SIZE in words ("renounces four capabilities") and two of them reproduce its
CONTENTS as a table. Nothing breaks when a fifth capability is added to the
tuple: the sentences simply become false, and an operator choosing an
installation shape decides on a list that is missing an entry. That is the same
failure that left `Version: 1.0` in the README for four releases and a footer
declaring v1.12.0 under a v1.20.0 breadcrumb.

Two rules, both learned the hard way in this repository:

* Assert against the DOCUMENTS, never against a copy of the fact restated here
  -- a guard that carries its own expected list is a third author of it.
* Every pattern carries a MINIMUM count. A regex that silently matches nothing
  reports a perfect document while having inspected none of it.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from app import runtime
from app.services import doc_publication as pubdoc

DOCS = pathlib.Path(__file__).resolve().parents[1] / "docs"

NUMBER_WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five",
                6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten"}

# The surfaces that state the SIZE of the capability set in words.
COUNTING_SURFACES = ("docker.md", "INSTALL.md", "README.md")

# The surfaces that reproduce the capability set as a table.
TABLE_SURFACES = ("docker.md", "INSTALL.md")

COUNT_PHRASE = re.compile(
    r"\b(%s)\s+(?:host\s+)?capabilit(?:y|ies)\b" % "|".join(NUMBER_WORDS.values()),
    re.IGNORECASE,
)


def _read(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


def _capability_table_labels(text: str) -> list[str]:
    """First column of the table whose header column is `capability`.

    Located by its header rather than by offset: a table found by counting
    pipes would silently pick up the three-row *installation shape* table that
    sits a few lines above it in docker.md.
    """
    rows: list[str] = []
    in_table = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            in_table = False
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if not in_table:
            if cells and cells[0].lower() == "capability":
                in_table = True
            continue
        if set(cells[0]) <= {"-", ":", " "} and cells[0]:
            continue
        rows.append(re.sub(r"[*`]", "", cells[0]).strip())
    return rows


# ---------------------------------------------------------------------------
# The page is reachable at all
# ---------------------------------------------------------------------------

def test_the_container_page_is_published():
    """Absence from PUBLIC_DOCS is the opt-OUT, so a page can be written,
    committed and reachable from nowhere -- which is what happened here."""
    slugs = {entry[1] for entry in pubdoc.PUBLIC_DOCS}
    assert "docker" in slugs, (
        "docs/docker.md is not in PUBLIC_DOCS, so it is published on no public "
        "surface and every link to it from the manual is a dead end"
    )


def test_the_container_page_is_filed_in_exactly_one_group():
    groups = [name for name, _blurb, slugs in pubdoc.GROUPS if "docker" in slugs]
    assert len(groups) == 1, (
        "docs.html renders documents by group; a slug in no group is invisible "
        "on the hub and a slug in two groups is listed twice. Groups: %r" % groups
    )


def test_the_manual_map_links_every_published_document():
    """docs/README.md section 3 claims to be the map of every document.

    Scoped to that section on purpose. A whole-file substring check passes while
    the authoritative table is missing a row, because the same filename is also
    named in a reading path a hundred lines above -- which is exactly what a
    mutation of this guard demonstrated.

    README.md does not link itself, and CHANGELOG.md is published from the
    repository root rather than from `docs/`; both are excluded by name so that
    the exclusion is visible rather than baked into a loose pattern.
    """
    text = _read("README.md")
    marker = "## 3. Every document"
    assert marker in text, "docs/README.md no longer has a section 3"
    table = text.split(marker, 1)[1]
    expected = [md for md, *_ in pubdoc.PUBLIC_DOCS
                if md not in ("README.md", "CHANGELOG.md")]
    assert len(expected) >= 20, (
        "only %d documents to check -- the registry looks truncated, and a guard "
        "over an empty list proves nothing" % len(expected)
    )
    missing = [md for md in expected if "](%s)" % md not in table]
    assert not missing, (
        "docs/README.md section 3 is the manual's own index and does not list: %s"
        % ", ".join(missing)
    )


# ---------------------------------------------------------------------------
# The stated size matches the code
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("surface", COUNTING_SURFACES)
def test_the_stated_capability_count_matches_the_code(surface):
    expected = NUMBER_WORDS[len(runtime.HOST_ONLY_CAPABILITIES)]
    text = _read(surface)
    found = [m.group(1).lower() for m in COUNT_PHRASE.finditer(text)]
    assert found, (
        "docs/%s no longer states how many capabilities the container shape "
        "renounces, so this guard inspected nothing. Either restore the "
        "sentence or drop %s from COUNTING_SURFACES deliberately." % (surface, surface)
    )
    wrong = sorted({w for w in found if w != expected})
    assert not wrong, (
        "docs/%s says %s capabilit(y|ies) but app/runtime.py declares %d (%s). "
        "The prose is now false." % (
            surface, "/".join(wrong), len(runtime.HOST_ONLY_CAPABILITIES),
            ", ".join(runtime.HOST_ONLY_CAPABILITIES))
    )


# ---------------------------------------------------------------------------
# The reproduced contents match the code, and each other
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("surface", TABLE_SURFACES)
def test_the_capability_table_has_one_row_per_capability(surface):
    labels = _capability_table_labels(_read(surface))
    assert labels, "no `capability` table found in docs/%s" % surface
    assert len(labels) == len(runtime.HOST_ONLY_CAPABILITIES), (
        "docs/%s lists %d capabilities (%s) but app/runtime.py denies %d (%s)"
        % (surface, len(labels), ", ".join(labels),
           len(runtime.HOST_ONLY_CAPABILITIES),
           ", ".join(runtime.HOST_ONLY_CAPABILITIES))
    )


def test_both_tables_name_the_same_capabilities():
    """One fact, two authors is how index.html lost its Docs link."""
    tables = {s: _capability_table_labels(_read(s)) for s in TABLE_SURFACES}
    normalised = {s: [l.lower() for l in rows] for s, rows in tables.items()}
    first, *rest = list(normalised.values())
    for other in rest:
        assert other == first, (
            "the installation manual and the container page disagree on which "
            "capabilities are renounced: %r" % tables
        )


# ---------------------------------------------------------------------------
# "Ways to install" is a list with a length, and it is quoted in two places
# ---------------------------------------------------------------------------

def test_install_section_2_lists_every_shape_the_container_page_claims():
    install = _read("INSTALL.md")
    shapes = re.findall(r"^### 2\.(\d)\s+(.+)$", install, re.MULTILINE)
    assert len(shapes) >= 3, (
        "docs/INSTALL.md section 2 is the canonical list of ways to install and "
        "it names %d: %r" % (len(shapes), shapes)
    )
    numbers = [int(n) for n, _ in shapes]
    assert numbers == sorted(numbers) and numbers[0] == 1, (
        "the subsections of section 2 are misnumbered: %r" % numbers
    )
    assert any("container" in title.lower() or "docker" in title.lower()
               for _n, title in shapes), (
        "section 2 of docs/INSTALL.md never names the container shape, so the "
        "canonical list of ways to install is short by one: %r" % shapes
    )


def test_the_container_page_and_install_agree_on_the_number_of_shapes():
    docker = _read("docker.md")
    install = _read("INSTALL.md")
    shape_rows = [
        line for line in docker.splitlines()
        if line.strip().startswith("|") and "](INSTALL.md)" in line
           or (line.strip().startswith("|") and "**this page**" in line)
    ]
    assert shape_rows, "docs/docker.md no longer carries the installation-shape table"
    install_shapes = re.findall(r"^### 2\.\d\s+", install, re.MULTILINE)
    assert len(shape_rows) == len(install_shapes), (
        "docs/docker.md describes %d installation shapes while docs/INSTALL.md "
        "section 2 documents %d" % (len(shape_rows), len(install_shapes))
    )
