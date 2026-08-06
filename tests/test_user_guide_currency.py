"""The user guide must name every product the app ships.

Why this file exists
--------------------
Nothing *fails* when a manual goes stale.  The app boots, the tests pass, the
page renders — the sentence simply stops being true.  That is exactly how
``docs/user-guide.md`` came to open with "the app hosts three workspaces" a
month after FortiAnalyzer shipped and a day after FortiAuthenticator did, on a
document that is **published publicly**.  A reader who trusts it concludes the
product they are looking at does not exist.

So the guard is mechanical and derived: the ADOM roster comes from
``branding._FALLBACK`` (the roster in *code*, not the DB rows an operator may
edit), and every active product in it has to be named in the guide's ADOM
table.  Declaring a sixth product without a manual entry fails the suite in the
same commit that declares it.

Deliberately NOT guarded here: prose quality.  A guard that tries to police
whether an explanation is *good* rejects correct writing — this repo already
retired one such test.  What is checkable is presence.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from app import branding
from app.models_provision import MODES
from app.services.metrics_collect import COLLECTORS

ROOT = pathlib.Path(__file__).resolve().parents[1]
GUIDE = ROOT / 'docs' / 'user-guide.md'

ACTIVE = [d for d in branding._FALLBACK if d.get('active', True)]
# Every product ADOM has an appliance kind behind it; Global does not.
PRODUCTS = [d for d in ACTIVE if d['key'] != 'global']


def guide_text() -> str:
    return GUIDE.read_text(encoding='utf-8')


def adom_table() -> str:
    """The ADOM table in section 3, and nothing else.

    Bounded by the next heading so a product named anywhere else in the manual
    cannot satisfy this guard by accident.
    """
    txt = guide_text()
    start = txt.index('## 3. Products (ADOMs)')
    end = txt.index('\n## ', start + 1)
    return txt[start:end]


@pytest.mark.parametrize('adom', ACTIVE, ids=[d['key'] for d in ACTIVE])
def test_every_active_adom_is_named_in_the_adom_table(adom):
    assert adom['name'] in adom_table(), (
        f"ADOM {adom['key']!r} ships but the user guide's ADOM table never "
        f"names it. Add a row for it in docs/user-guide.md section 3."
    )


def test_every_adom_row_carries_a_url():
    """A row without a URL tells a reader a workspace exists and not where.

    Deliberately a count, not a key-to-prefix mapping: there is no declared
    mapping in the codebase (``/faz/`` is not spelled by ``fortianalyzer``),
    and inventing one here would be a second source of truth that rots. What
    is mechanically true is that each ADOM row must carry one path.
    """
    table = adom_table()
    paths = re.findall(r'\| `(/[a-z]*/?)` \|', table)
    assert len(paths) == len(ACTIVE), (
        f'{len(ACTIVE)} ADOMs ship but the table carries {len(paths)} URL(s): '
        f'{paths} — a row was added without one.'
    )
    assert len(set(paths)) == len(paths), f'duplicate workspace URLs: {paths}'


def test_the_workspace_count_matches_the_roster():
    """A prose count is a claim, and a wrong one is worse than none.

    Anchored on the CLAIM (``<number-word> workspaces``), not on the sentence
    that carries it: the first version of this guard matched the exact string
    ``The app hosts N workspaces`` and went silent the moment an edit inserted
    an adverb -- a guard tied to the wording stops guarding the number. Every
    occurrence is checked, because the count is stated in more than one place
    (SS3 and the Settings -> ADOMs reference) and a second copy is exactly how
    one of them goes stale unnoticed.
    """
    words = {3: 'three', 4: 'four', 5: 'five', 6: 'six', 7: 'seven'}
    expected = words[len(ACTIVE)]
    found = re.findall(r'\b(%s) workspaces' % '|'.join(words.values()),
                       guide_text())
    assert found, 'the guide no longer states how many workspaces exist'
    wrong = [w for w in found if w != expected]
    assert not wrong, (
        f'the guide says {sorted(set(wrong))} workspaces; the roster has '
        f'{len(ACTIVE)} ({expected}) -- every prose count must agree'
    )


@pytest.mark.parametrize('adom', PRODUCTS, ids=[d['key'] for d in PRODUCTS])
def test_every_product_kind_is_listed_where_appliances_are_registered(adom):
    """The Add-appliance step enumerates the kinds; a missing one reads as
    'this product cannot be registered'."""
    txt = guide_text()
    start = txt.index('## 4. Registering and operating devices')
    end = txt.index('\n## ', start + 1)
    assert adom['key'] in txt[start:end], (
        f"kind {adom['key']!r} is not listed in the Add-appliance step"
    )


def test_the_roster_is_not_empty():
    """Anti-vacuity: if _FALLBACK stopped resolving, every parametrised test
    above would pass with zero cases."""
    assert len(ACTIVE) >= 3
    assert len(PRODUCTS) >= 2


# ---------------------------------------------------------------------------
# Structure: the contents list and the sections it points at
#
# Renumbering a section and forgetting the contents list breaks nothing that
# any other test can see: the file still parses, the site still builds, every
# page still returns 200 — the reader just lands somewhere else, or nowhere.
# That is the same silent-staleness failure the top of this file describes, so
# it gets the same treatment: a mechanical, derived check.
# ---------------------------------------------------------------------------

def anchor(title: str) -> str:
    """The fragment a Markdown renderer derives from a heading.

    Lower-case, drop everything that is not alphanumeric / space / hyphen,
    spaces become hyphens. Matches the fragments already written by hand in
    the contents list, which is what makes this checkable at all.
    """
    s = ''.join(c for c in title.lower() if c.isalnum() or c in ' -')
    return s.replace(' ', '-')


def numbered_headings() -> list:
    """(number, title) for every ``## N. Title`` heading, in file order."""
    return [(int(m.group(1)), m.group(2).strip())
            for m in re.finditer(r'^## (\d+)\. (.+)$', guide_text(), re.M)]


def toc_entries() -> list:
    """(number, fragment) for every numbered line of the contents list."""
    return [(int(m.group(1)), m.group(2))
            for m in re.finditer(r'^(\d+)\. \[[^\]]+\]\(#([^)]+)\)$',
                                 guide_text(), re.M)]


def test_the_manual_still_has_a_structure_to_check():
    """Anti-vacuity. Every test below iterates over these two lists; if a
    pattern stopped matching they would all pass over nothing."""
    assert len(numbered_headings()) >= 20
    assert len(toc_entries()) >= 20


def test_section_numbers_are_a_gapless_sequence():
    nums = [n for n, _ in numbered_headings()]
    assert nums == list(range(1, len(nums) + 1)), (
        f'sections are numbered {nums} — inserting a section means renumbering '
        f'the ones after it, or appending instead'
    )


def test_every_contents_entry_points_at_a_real_section():
    live = {anchor(f'{n}. {t}') for n, t in numbered_headings()}
    for num, frag in toc_entries():
        assert frag in live, (
            f'contents entry {num} links to #{frag}, which no heading '
            f'produces — the section was renamed or renumbered and the '
            f'contents list was not'
        )


def test_every_section_is_reachable_from_the_contents():
    listed = {n for n, _ in toc_entries()}
    for num, title in numbered_headings():
        assert num in listed, (
            f'section {num} ({title!r}) exists but the contents list never '
            f'mentions it'
        )


def test_every_document_the_guide_links_to_exists():
    """A link to a file that is not there degrades to plain text on the public
    site: the sentence still reads, and the reference is silently gone."""
    targets = set(re.findall(r'\]\(([A-Za-z0-9_.-]+\.md)\)', guide_text()))
    assert targets, 'the guide links to no other manual at all'
    for t in sorted(targets):
        assert (GUIDE.parent / t).exists(), (
            f'the guide links to {t}, which does not exist in docs/'
        )


# ---------------------------------------------------------------------------
# Derived rosters: the same rule as the ADOM table, applied to the two
# registries a reader has to be able to act on.
# ---------------------------------------------------------------------------

def bounded(head: str, stop: str) -> str:
    """The named section and nothing after it, so a word used elsewhere in the
    manual cannot satisfy a guard by accident."""
    txt = guide_text()
    start = txt.index(head)
    nxt = txt.find(stop, start + len(head))
    return txt[start:] if nxt == -1 else txt[start:nxt]


@pytest.mark.parametrize('key', sorted(COLLECTORS))
def test_every_collector_is_named_in_the_collection_section(key):
    body = bounded('### 14.7 Collection', '\n### ')
    assert f'`{key}`' in body, (
        f'collector {key!r} is scraped from every supported device and the '
        f'Collection section never names it, so an operator cannot know what '
        f'the interval they are editing controls'
    )


@pytest.mark.parametrize('key', sorted(MODES))
def test_every_provisioning_mode_is_named_in_the_provisioning_section(key):
    label = MODES[key].split(' — ')[0].strip()
    body = bounded('## 21. Provisioning new appliances', '\n## ')
    assert label in body, (
        f'provisioning mode {key!r} is offered in the form as {label!r} and '
        f'the manual never explains where it stops'
    )


def test_the_two_registries_are_not_empty():
    """Anti-vacuity for the two parametrised guards above."""
    assert len(COLLECTORS) >= 4
    assert len(MODES) >= 4
