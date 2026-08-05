"""Guards: a flat changelog block declares each kind at most once.

Several sessions append to `## [Unreleased]` independently, and each one adds
its own `### Changed` / `### Fixed` heading.  Nothing failed when they piled
up -- the file still parsed, the site still built, and the published page for
that version simply rendered "Changed" three times.  Same failure class as a
stale version literal: no error, the artefact just stops being true, and the
reader cannot tell whether the second "Changed" continues the first or starts
something else.

Two authoring styles are in use here, and only one of them is guarded:

* **flat** -- the block's `###` headings are all Keep a Changelog kinds
  (Added / Changed / Fixed / ...).  A repeated kind is a defect.
* **narrative** -- a large release groups its entries under descriptive
  sub-headings ("The offline bundles never carried git"), each of which may
  carry its own Added/Fixed.  Repeats across sub-sections are correct, and
  gen_release_notes.py renders them as written.

The rule below therefore only fires on flat blocks.  A block that closes with
a single descriptive section after the standard kinds (several do) is normal
prose, not a defect -- flagging it would invent a problem.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"

KINDS = {"Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"}


def _blocks() -> dict[str, list[str]]:
    """Return {version heading: [### heading, ...]} in file order."""
    out: dict[str, list[str]] = {}
    current: str | None = None
    for line in CHANGELOG.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            out.setdefault(current, [])
            continue
        m = re.match(r"^### (.+?)\s*$", line)
        if m and current is not None:
            out[current].append(m.group(1).strip())
    return out


def _is_flat(headings: list[str]) -> bool:
    """A block is flat when every sub-heading is a Keep a Changelog kind."""
    return bool(headings) and all(h in KINDS for h in headings)


def test_changelog_exists_and_has_an_unreleased_block():
    assert CHANGELOG.is_file(), "CHANGELOG.md is the single source for release pages"
    assert any(b.startswith("[Unreleased]") for b in _blocks()), (
        "no [Unreleased] block -- new work has nowhere to land"
    )


def test_unreleased_is_the_first_block():
    """A version above [Unreleased] files new work under a release that shipped.

    This already happened: v1.1 sat above [Unreleased] and had to be
    restructured before 1.2.1 could be cut.
    """
    headings = list(_blocks())
    assert headings, "changelog has no ## blocks"
    assert headings[0].startswith("[Unreleased]"), (
        f"first block is `{headings[0]}`, not [Unreleased] -- entries appended to "
        "the top of the file would land inside a version that already shipped"
    )


@pytest.mark.parametrize(
    "heading", sorted(h for h, k in _blocks().items() if _is_flat(k))
)
def test_a_flat_block_declares_each_kind_at_most_once(heading):
    kinds = _blocks()[heading]
    dupes = sorted({k for k in kinds if kinds.count(k) > 1})
    assert not dupes, (
        f"`## {heading}` declares {dupes} more than once. This block uses the flat "
        "Keep a Changelog style, where one heading per kind is the whole contract; "
        "the published release page renders each heading verbatim, so a duplicate "
        "reads as a second release. Merge the entries under a single heading "
        "(order within the section does not matter). If this release is large "
        "enough to want narrative grouping, convert the WHOLE block to descriptive "
        "sub-headings instead of mixing the two."
    )


def test_the_duplicate_rule_actually_covers_something():
    """Anti-vacuity: a parametrised test with zero cases passes silently.

    If `_is_flat` ever stops recognising the flat style -- a narrowed
    vocabulary, a heading-parse change, an added guard clause -- the rule above
    would be generated with no parameters and report green while protecting
    nothing.  This repo has been burned by exactly that shape before.
    """
    blocks = _blocks()
    flat = [h for h, k in blocks.items() if _is_flat(k)]
    assert flat, (
        "no changelog block is recognised as flat, so the duplicate-section rule "
        "runs against nothing. Either every block really is narrative-grouped "
        "(check the file) or `_is_flat` / `_blocks` stopped parsing headings."
    )
    assert any(len(blocks[h]) >= 2 for h in flat), (
        "every flat block has fewer than two sections, so a duplicate could not "
        "be detected even if one were introduced"
    )
