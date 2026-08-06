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
    """A prose count is a claim, and a wrong one is worse than none."""
    words = {3: 'three', 4: 'four', 5: 'five', 6: 'six', 7: 'seven'}
    expected = words[len(ACTIVE)]
    m = re.search(r'The app hosts (\w+) workspaces', guide_text())
    assert m, 'the ADOM section no longer states how many workspaces exist'
    assert m.group(1) == expected, (
        f'the guide says {m.group(1)!r} workspaces; the roster has '
        f'{len(ACTIVE)} ({expected})'
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
