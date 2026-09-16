"""The comparison on the API-versions page renders ONE table (2026-09-16).

The defect these guards exist for was an omission, and omissions are the hard
kind to see: the card used to hold three tables — field deltas, then the
endpoint provenance table, then the incomparable objects — and a key that only
ever produced a FIELD delta appeared in the first and was simply absent from
the second. Measured on the live installation the day it was reported:
``antivirus`` carries 8 sweep fields on 7.6.8 and 14 on 8.0.5, so it was a row
in the top table and no row at all in the bottom one. A missing row does not
look like a missing row — it looks like "no finding for antivirus", which is
the opposite of what the evidence said.

So every finding is a row of ``#versionDelta`` now. What did NOT merge is the
WORDING: a field delta is a measurement, *known on one side only* is a gap in
the evidence and *incomparable* is a refusal to subtract two kinds of evidence.
Folding those three into one verb would reinstate the 56 phantom removals that
the sweep↔schema split exists to prevent — so half of these guards check that
the rows are all present and the other half check that they still disagree.

Fixtures, not production data: every FortiWeb line on this fleet is homogeneous
and its two builds sit in different lines, so the shapes below (a schema-only
object, an incomparable key, a one-sided field set) cannot be provoked from the
live matrix at all.

Targeted suite: no network, no appliance.
"""
from __future__ import annotations

import io
import json
import os
import re

import pytest

from app.services import api_matrix as am
from tests.conftest import admin_user_id, login
from tests.test_firmware_version_axis import (  # noqa: F401 — fixtures by name
    _appliance, _archive, _ledger, isolated,
)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TPL = os.path.join(ROOT, "app/templates/registry/versions.html")

#: The two builds the fleet actually runs, so the fixture's shape is the
#: production shape and not a convenient invention.
BASE, TARGET = "7.6.8", "8.0.5"


def _schema(isolated, line, obj, fields, endpoint=None):
    """One harvested field schema — evidence keyed by LINE, never by build."""
    d = isolated["field_schemas"] / "fortiweb" / line
    d.mkdir(parents=True, exist_ok=True)
    (d / ("%s.json" % obj)).write_text(json.dumps({
        "object": obj, "endpoint": endpoint or obj,
        "fields": [{"name": f} for f in fields],
        "generated_at": "2099-01-01T00:00:00", "source": "harvest",
    }))


@pytest.fixture()
def two_builds(isolated, app):
    """One fixture, one row per bucket the comparison can produce.

    ``fielded`` is the reported defect in miniature: served on BOTH builds, so
    it is neither added nor gone, and its only finding is that its field set
    grew. Under the old layout that row existed in one table and not in the
    other.
    """
    a = _appliance("boxA", firmware=BASE)
    b = _appliance("boxB", firmware=TARGET)
    # One key per bucket, and each key in EXACTLY one bucket: a name that is
    # both "added" and "incomparable" renders two rows, and every assertion
    # below would then be answered by whichever of the two sorted first.
    led_a = _ledger(shared="ok", goes_away="ok", arrives="absent",
                    fielded="ok", onesided="ok", mixed="ok")
    led_b = _ledger(shared="ok", goes_away="absent", arrives="ok",
                    fielded="ok", onesided="ok", mixed="ok", onlyhere="ok")
    # Rows are what create a field set (RULE 1 in api_matrix): an endpoint that
    # answered ``ok`` with an empty collection has fields=None, which is how
    # ``onesided`` ends up known on one side and unmeasured on the other.
    _archive(isolated, a, BASE, led_a,
             sections={"S": {"fielded": [{"alpha": 1, "beta": 2}],
                             "onesided": [{"only": 1}]}})
    _archive(isolated, b, TARGET, led_b,
             sections={"S": {"fielded": [{"alpha": 1, "beta": 2, "gamma": 3}],
                             "mixed": [{"sweepside": 1}]}})
    # Schema evidence is per line, so these two describe 7.6 and 8.0.
    _schema(isolated, "7.6", "schemaonly", ["p", "q"])
    _schema(isolated, "8.0", "schemaonly", ["p", "q", "r"])
    # ``mixed`` is known by SCHEMA on one side and by SWEEP on the other —
    # the one pair this page must report and never subtract.
    _schema(isolated, "7.6", "mixed", ["schemaside"])
    am.rebuild("fortiweb")
    return a, b


def _page(client, app, base=BASE, target=TARGET):
    login(client, admin_user_id(app))
    return client.get("/web/registry/versions?base=%s&target=%s"
                      % (base, target)).get_data(as_text=True)


def _table(body):
    """The comparison table only. Every assertion below is scoped to it.

    A page-level ``in body`` is answered by the build table, by the flash area
    or by a Jinja comment, and this repo has now paid for that mistake
    thirteen times.
    """
    i = body.find('id="versionDelta"')
    assert i != -1, "the comparison rendered no table"
    return body[i:body.find("</table>", i)]


def _row(body, key):
    m = re.search(r"<tr><td><code>%s</code>.*?</tr>" % re.escape(key),
                  _table(body), re.S)
    assert m, "no row for %r in the comparison table" % key
    return m.group(0)


# ---------------------------------------------------------------------------
# 1. the defect: a field delta is a finding, so it is a row
# ---------------------------------------------------------------------------

def test_a_key_whose_only_finding_is_a_field_delta_is_a_row(two_builds, client, app):
    """The reported bug, pinned. ``fielded`` is served on both builds — the
    endpoint buckets say nothing about it — and it gained a field."""
    row = _row(_page(client, app), "fielded")
    assert "fields changed" in row, row
    assert "gamma" in row, "the field it gained must be named: %s" % row


def test_the_field_delta_row_says_which_evidence_and_how_many(two_builds, client, app):
    row = _row(_page(client, app), "fielded")
    assert ">sweep<" in row, "a delta must name the kind of evidence it is: %s" % row
    assert "2" in row and "3" in row, row


def test_the_comparison_renders_exactly_one_table(two_builds, client, app):
    """The change itself. Three tables is the layout that hid a row."""
    body = _page(client, app)
    start = body.find("What changes between two of them")
    assert start != -1
    card = body[start:body.find("Preflight", start)]
    assert card.count("<table") == 1, \
        "the comparison is split across %d tables again" % card.count("<table")
    assert 'id="versionDelta"' in card


@pytest.mark.parametrize("gone", ["Added on 8.0.5", "Fields known on one side only",
                                  ">Incomparable<"])
def test_the_old_split_headings_do_not_come_back(two_builds, client, app, gone):
    """Inverted on purpose: the removal is the deliverable, so it needs a guard
    that fails when the old shape reappears, not only one that passes today."""
    assert gone not in _page(client, app)


# ---------------------------------------------------------------------------
# 2. every bucket reaches the table — and none of them borrows another's verb
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key,phrase", [
    ("arrives", "added on 8.0.5"),
    ("goes_away", "gone on 8.0.5"),
    ("fielded", "fields changed"),
    ("onesided", "fields known only on 7.6.8"),
    ("mixed", "incomparable"),
    ("schemaonly", "fields changed"),
    ("onlyhere", "measured only on 8.0.5"),
])
def test_every_bucket_reaches_the_one_table(two_builds, client, app, key, phrase):
    assert phrase in _row(_page(client, app), key).lower()


@pytest.mark.parametrize("key", ["onesided", "mixed", "onlyhere"])
def test_a_gap_is_never_worded_as_a_change(two_builds, client, app, key):
    """The half of the old split that was load-bearing. "Nobody measured the
    other side" and "the other side does not have it" look identical once they
    share a table, and only one of them is a fact about the appliance."""
    row = _row(_page(client, app), key).lower()
    assert "added on" not in row and "gone on" not in row, row
    assert "fields changed" not in row, row


def test_the_two_gaps_do_not_share_one_word(two_builds, client, app):
    """``known on one side only`` and ``incomparable`` are different gaps: one
    needs a sweep, the other cannot be closed by one."""
    body = _page(client, app)
    assert "known only on" in _row(body, "onesided").lower()
    assert "incomparable" in _row(body, "mixed").lower()
    assert "incomparable" not in _row(body, "onesided").lower()


def test_an_unmeasured_side_is_reported_as_proving_nothing(two_builds, client, app):
    assert "proves nothing" in _row(_page(client, app), "onesided")


def test_incomparable_says_it_is_not_subtracted(two_builds, client, app):
    assert "never subtracted" in _row(_page(client, app), "mixed")


# ---------------------------------------------------------------------------
# 3. the Test button follows the evidence, and is never fabricated
# ---------------------------------------------------------------------------

def test_a_row_backed_by_an_endpoint_carries_its_urn_and_a_test_button(
        two_builds, client, app):
    row = _row(_page(client, app), "fielded")
    assert "cmdb/fielded" in row, "the row must carry the URN its evidence has"
    assert 'data-cli-test="api"' in row


def test_an_object_that_is_not_an_endpoint_offers_no_test_button(
        two_builds, client, app):
    """``schemaonly`` came from a harvested schema: it has no REST path. A
    button there could not work, and its presence would assert that a path
    exists — the same rule the Structure page follows for CLI-only nodes."""
    row = _row(_page(client, app), "schemaonly")
    assert 'data-cli-test' not in row, row
    assert "cmdb/" not in row, "a URN was invented for an object with none: %s" % row


def test_the_urn_comes_from_the_service_not_from_the_template():
    """One call site. The template may not go looking for a path of its own."""
    src = io.open(TPL, encoding="utf-8").read()
    delta = src.split('id="versionDelta"')[1].split("</table>")[0]
    assert "urn=r.urn" in delta or "urn=c.urn" in delta
    assert "endpoints[" not in delta and "matrix.versions" not in delta


# ---------------------------------------------------------------------------
# 4. the legend went; the capture behind each column did not
# ---------------------------------------------------------------------------

def test_the_page_no_longer_renders_the_legend_blocks():
    src = io.open(TPL, encoding="utf-8").read()
    assert "prov_legend" not in src, \
        "the legend the operator asked to remove is back"


def test_each_cli_column_still_names_the_capture_it_answers_from(
        two_builds, client, app):
    """Removed from the page body, NOT dropped. A badge whose capture is
    unnamed cannot be told from a two-month-old one, and a column with no
    capture at all has to say why its cells are em dashes rather than
    "API only"."""
    body = _page(client, app)
    heads = re.findall(r'<th title="([^"]+)">CLI on ([\w.]+)</th>', _table(body))
    assert len(heads) == 2, "both CLI columns must carry their provenance"
    for hint, scope in heads:
        assert hint.strip(), scope
        assert "em dash" in hint or "captured" in hint, (scope, hint)


def _cells(row):
    """The row's six cells. Cells nest tags but never another ``<td>``."""
    return [c.split("</td>")[0] for c in row.split("<td")[1:]]


def test_a_field_row_answers_its_cli_columns_from_its_own_provenance(
        two_builds, client, app):
    """The view annotates EVERY bucket, not only the two endpoint ones.

    Without it those cells render ``prov_badge(None)`` — a bare em dash with
    NO title, which is visually identical to the honest "nobody captured
    anything on this build" and to a measured "no CLI block here". Same glyph,
    three meanings; the title is the only thing that separates them, so the
    guard is on the title and not on the dash.
    """
    body = _page(client, app)
    for key in ("fielded", "onesided", "mixed", "schemaonly", "onlyhere"):
        cells = _cells(_row(body, key))
        assert len(cells) == 6, (key, len(cells))
        for col, cell in zip(("base", "target"), cells[3:5]):
            assert "title=" in cell, (
                "%s / CLI on %s: an em dash with no reason behind it — the "
                "bucket was not annotated: %r" % (key, col, cell))


# ---------------------------------------------------------------------------
# 5. the caption counts what the table shows
# ---------------------------------------------------------------------------

def test_the_caption_agrees_with_the_rows_it_introduces(two_builds, client, app):
    """A summary that drifts from its table is worse than no summary: it gets
    read INSTEAD of the table."""
    body = _page(client, app)
    with app.app_context():
        d = am.diff("fortiweb", BASE, TARGET)
    rows = _table(body).count("<tr><td><code>")
    total = sum(len(d[k]) for k in ("endpoints_added", "endpoints_removed",
                                    "endpoints_unknown", "fields_changed",
                                    "fields_unknown", "fields_incomparable"))
    assert total == 7, "the fixture stopped covering every bucket: %s" % {
        k: len(d[k]) for k in d if isinstance(d[k], list)}
    assert rows == total, "%d rows rendered for %d findings" % (rows, total)

    # Anchored on the caption's own first phrase, NOT on the card: the
    # paragraph above it opens with two <strong> totals of its own, so a
    # card-wide search reads those as the first two counts.
    head = body.find("endpoint(s) added")
    assert head != -1, "the caption is gone"
    cap = body[body.rfind("<div", 0, head):body.find('id="versionDelta"', head)]
    numbers = re.findall(r"<strong>(\d+)</strong>", cap)
    assert numbers[:5] == [str(len(d["endpoints_added"])),
                           str(len(d["endpoints_removed"])),
                           str(len(d["fields_changed"])),
                           str(len(d["fields_unknown"]) + len(d["endpoints_unknown"])),
                           str(len(d["fields_incomparable"]))], numbers


def test_nothing_to_report_says_so_instead_of_an_empty_table(isolated, client, app):
    """An empty table and "the two builds agree" look identical; only one of
    them is a claim about the evidence."""
    a = _appliance("boxA", firmware=BASE)
    b = _appliance("boxB", firmware=TARGET)
    led = _ledger(shared="ok")
    _archive(isolated, a, BASE, led)
    _archive(isolated, b, TARGET, led)
    am.rebuild("fortiweb")
    body = _page(client, app)
    assert "Nothing differs between" in body
    assert 'id="versionDelta"' not in body


# ===========================================================================
# 6. the Change column's three slots (2026-09-16)
#
# The column carried six different shapes and one row printed eighteen field
# names inline. It is three fixed slots now — kind badge, measurement, folded
# names — and two things moved out of plain sight. Neither may go quiet:
# a ``phrase in row`` cannot tell "moved into the badge's title" from "gone
# altogether", and a fold cannot be allowed to swallow the tally.
# ===========================================================================

def _kind_title(row):
    m = re.search(r'<div class="dv-kind"><span class="fw-badge[^"]*" title="([^"]*)"',
                  row)
    assert m, "slot 1 is not a titled badge: %s" % row
    return m.group(1)


@pytest.mark.parametrize("key,phrase", [
    ("onesided", "proves nothing"),
    ("mixed", "never subtracted"),
    ("onlyhere", "proves nothing"),
])
def test_the_sentence_that_stops_a_gap_reading_as_a_change_is_on_its_badge(
        two_builds, client, app, key, phrase):
    """One sentence per kind, against 43 rows on the live matrix — printed per
    row it was eleven copies of one of them. It moved to the badge's title and
    it has to STAY somewhere addressable: worded as a bare ``in row`` this
    would also pass with the sentence sitting in a stray comment."""
    assert phrase in _kind_title(_row(_page(client, app), key))


@pytest.mark.parametrize("key,verb", [
    ("arrives", "is a change"),
    ("goes_away", "is a change"),
    ("fielded", "is a change"),
    ("onesided", "not a change"),
    ("onlyhere", "not a change"),
    ("mixed", "never subtracted"),
])
def test_each_kind_badge_says_in_its_title_whether_it_is_a_change(
        two_builds, client, app, key, verb):
    """The split the merged table must keep. Three kinds ARE changes and three
    are gaps; once they share a column the only thing left carrying that is
    the wording."""
    assert verb in _kind_title(_row(_page(client, app), key))


def test_the_names_fold_but_the_tally_stays_on_the_fold(two_builds, client, app):
    """Folding hides the NAMES. ``+1`` is the number the rows are compared on
    — it was the one thing the old inline dump made you count by eye — so it
    sits on the summary, outside the fold, and the names stay in the row."""
    row = _row(_page(client, app), "fielded")
    m = re.search(r"<summary>(.*?)</summary>", row, re.S)
    assert m, "the field names are not folded: %s" % row
    assert "+1" in m.group(1), "the tally is not on the fold: %s" % m.group(1)
    assert "gamma" not in m.group(1), \
        "the names are ON the fold, which is what folding was supposed to stop"
    assert "gamma" in row, "the name left the row entirely: %s" % row


def test_a_row_with_no_field_names_grows_no_empty_fold(two_builds, client, app):
    """An endpoint row has no field list. A disclosure that opens onto nothing
    reads as evidence withheld."""
    assert "<details" not in _row(_page(client, app), "arrives")


def test_the_filter_can_reach_inside_a_fold():
    """A row counted as a hit while the text that matched stays folded away is
    worse than a miss — the operator sees a row with no visible reason to be
    there. The filter is ONE author (filter_box), so the opening lives there."""
    src = io.open(os.path.join(ROOT, "app/templates/partials/_cli_probe_tools.html"),
                  encoding="utf-8").read()
    assert "querySelectorAll('details')" in src, \
        "the filter no longer opens folds whose contents matched"
    assert "cliFilterOpened" in src, \
        "folds opened by hand must survive clearing the box"


def test_the_change_column_does_not_style_itself_row_by_row():
    """Six loops render this cell. Inline styles repeated per loop is how this
    page ended up with two authors of one rule before."""
    src = io.open(TPL, encoding="utf-8").read()
    i = src.find('id="versionDelta"')
    assert i != -1
    body = src[i:]
    assert 'style="font-size:12px;"' not in body, \
        "the Change cell is styling itself inline again"
