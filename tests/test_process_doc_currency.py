"""The Process step table in the user guide must match the catalogue.

WHY THIS EXISTS
---------------
Nothing fails when a documented surface goes stale — the sentence simply stops
being true, and it keeps being printed. That is how ``Version: 1.0`` survived
four releases in the README, how §39's counts drifted, and how a menu entry
ended up documented in an ADOM that bounced the click.

The step table in §42 is the worst kind of that: an operator planning a
recovery reads it to decide **which steps exist and which of them write**. A
row missing from the table is a capability nobody knows they have; a `no` in
the Writes column against a step that writes is the opposite, and worse.

So the table is checked against ``process_kinds.kinds()`` in both directions,
by LABEL, which is the only string the two surfaces genuinely share.
"""
from __future__ import annotations

import os
import re

import pytest

from app.services import process_kinds as pk

GUIDE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "docs", "user-guide.md")


def _section() -> str:
    """§42's body. Bounded by the NEXT top-level heading OR end of file.

    §42 is currently the last section, so a lookahead for ``## 43.`` matches
    nothing and every assertion below it raises instead of failing on its own
    terms. Bounding on ``^## `` keeps the guard correct whether or not a §43 is
    ever written.
    """
    src = open(GUIDE, encoding="utf-8").read()
    m = re.search(r"^## 42\..*?(?=^## |\Z)", src, re.S | re.M)
    assert m, "the guide no longer has a section 42 — this guard reads the wrong doc"
    return m.group(0)


def _table() -> dict[str, str]:
    """``{label: writes-cell}`` from the §42 step table.

    Parsed from the section, not the whole file: 'Start / End' and 'Decision'
    are ordinary English and appear in a dozen other tables.
    """
    body = _section()
    t = re.search(r"^\| Step \| What it asks \| Writes\? \|\n\|[^\n]*\|\n((?:\|[^\n]*\|\n)+)",
                  body, re.M)
    assert t, "section 42 no longer contains the step table"
    out: dict[str, str] = {}
    for line in t.group(1).strip().splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 3:
            out[cells[0]] = cells[2]
    return out


#: One documented row covers two catalogue entries; every other row is 1:1.
MERGED = {"Start / End": ("Start", "End")}


def _documented_labels(table: dict[str, str]) -> set[str]:
    labels: set[str] = set()
    for row in table:
        labels.update(MERGED.get(row, (row,)))
    return labels


def test_every_step_kind_appears_in_the_guide():
    table = _table()
    missing = {k.label for k in pk.kinds()} - _documented_labels(table)
    assert not missing, "steps exist that the guide never mentions: %s" % sorted(missing)


def test_the_guide_documents_no_step_that_does_not_exist():
    """A removed step whose row survives is a plan an operator cannot draw."""
    table = _table()
    extra = _documented_labels(table) - {k.label for k in pk.kinds()}
    assert not extra, "the guide documents steps that are gone: %s" % sorted(extra)


def test_the_writes_column_matches_the_catalogue():
    """The column an operator reads before pointing a plan at production."""
    table = _table()
    by_label = {k.label: k for k in pk.kinds()}
    wrong = []
    for row, cell in table.items():
        for label in MERGED.get(row, (row,)):
            kind = by_label.get(label)
            if kind is None:
                continue
            says_yes = "yes" in cell.lower()
            if says_yes != kind.writes:
                wrong.append((label, cell, kind.writes))
    assert not wrong, "the Writes column disagrees with the catalogue: %s" % wrong


def test_the_guide_says_the_two_new_steps_are_not_sent_when_unarmed():
    """The one sentence that separates a rehearsal from a repair.

    ``action`` rehearses; ``console_script`` and ``hook`` are not sent at all.
    A guide that describes only the first behaviour would have an operator
    expect a rehearsal to walk the whole plan, and read the resulting ``unknown``
    steps as a broken diagram.
    """
    flat = " ".join(_section().split())
    assert "not sent at all" in flat
    assert "stops where the repair would have been" in flat


def test_the_guide_records_what_the_console_step_does_not_protect():
    """``delete_guard`` cannot see a delete inside a CLI config block.

    An undocumented gap in a safety net is worse than no net, because the net
    is what people believe is there.
    """
    flat = " ".join(_section().split())
    assert "delete_guard" in flat
