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
    assert "2 → 3" in row, "the subtraction that IS the finding is gone: %s" % row
    assert "gamma" in row, "the field it gained must be named: %s" % row


def test_the_field_delta_row_says_which_evidence_and_how_many(two_builds, client, app):
    row = _row(_page(client, app), "fielded")
    # Scoped to the Evidence cell since 2026-09-16: a row-wide search would be
    # answered by any stray occurrence, and the point of the new column is
    # that there is exactly one place that answers this.
    assert ">sweep<" in _ev_cell(row), \
        "a delta must name the kind of evidence it is: %s" % row
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
    # ``arrives`` and ``goes_away`` are not here any more: their labels
    # (``added on 8.0.5`` / ``gone on 8.0.5``) were removed on 2026-09-16 at
    # the operator's request as a restatement of the two build columns beside
    # them. They are asserted instead by
    # ``test_the_two_endpoint_changes_are_read_off_their_own_columns``, which
    # checks the thing that replaced the label rather than the label.
    #
    # The two field-delta rows lost their label in the same pass, so what they
    # are asserted BY is the subtraction itself — the only place on this page
    # where two numbers are subtracted.
    ("fielded", "2 → 3"),
    ("onesided", "fields known only on 7.6.8"),
    ("mixed", "incomparable"),
    ("schemaonly", "2 → 3"),
    ("onlyhere", "measured only on 8.0.5"),
])
def test_every_bucket_reaches_the_one_table(two_builds, client, app, key, phrase):
    assert phrase in _row(_page(client, app), key).lower()


def test_the_two_endpoint_changes_are_read_off_their_own_columns(
        two_builds, client, app):
    """What replaced ``added on 8.0.5`` / ``gone on 8.0.5``.

    The labels went because the two build columns already measure the thing
    they named. That is only true if the columns really do say it, and say it
    in OPPOSITE directions for the two buckets — a guard that merely checked
    the labels were gone would pass on a table that lost the finding too.
    """
    body = _page(client, app)
    for key, want in (("arrives", ("absent", "served")),
                      ("goes_away", ("served", "absent"))):
        base_col, target_col = _build_cols(_row(body, key))
        assert ">%s<" % want[0] in base_col, (key, base_col)
        assert ">%s<" % want[1] in target_col, (key, target_col)
        # Both sides MEASURED, which is what makes it a change and not a gap.
        assert "not measured" not in base_col + target_col, (key, base_col)


@pytest.mark.parametrize("gone", ["added on", "gone on"])
def test_the_class_labels_the_operator_removed_do_not_come_back(
        two_builds, client, app, gone):
    """Inverted, because the removal is the deliverable."""
    assert gone not in _table(_page(client, app)).lower()


@pytest.mark.parametrize("key", ["onesided", "mixed", "onlyhere"])
def test_a_gap_is_never_worded_as_a_change(two_builds, client, app, key):
    """The half of the old split that was load-bearing. "Nobody measured the
    other side" and "the other side does not have it" look identical once they
    share a table, and only one of them is a fact about the appliance.

    Reworded twice now, because the thing that told the two apart keeps
    moving. It was ``"fields changed" not in row``; that label went, which
    would have left the assertion VACUOUS. Then it was ``"added on" not in
    row``; those labels went too (2026-09-16), and that half would have gone
    vacuous in exactly the same way — passing on a page where the wording had
    been merged after all. So a gap is now pinned by what it may not show
    (a subtraction, a field fold) AND by what it must: the badge that says it
    is not a change. A badge in column 1 is the whole signal now.
    """
    row = _row(_page(client, app), key)
    assert "→" not in row, "a gap rendered a subtraction: %s" % row
    assert "<details" not in row, "a gap grew a delta's field fold: %s" % row
    assert "dv-kind" in row, \
        "a gap lost the badge that is now the ONLY thing marking it as one: %s" % row


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


def _cells(row):
    """The row's SIX cells. Cells nest tags but never another ``<td>``.

    Six since 2026-09-16: the identity (name, and the subtraction when there is
    one), the EVIDENCE KIND, the URN, then ONE COLUMN PER BUILD, then the Test
    button.
    """
    return [c.split("</td>")[0] for c in row.split("<td")[1:]]


def _build_cols(row):
    """``(base column, target column)`` — cells 4 and 5, never 3 and 4."""
    cells = _cells(row)
    assert len(cells) == 6, "the row is not six cells (%d): %s" % (len(cells), row)
    return cells[3], cells[4]


def _ev_cell(row):
    """The *Evidence* cell — second, where the operator asked for it."""
    cells = _cells(row)
    assert len(cells) == 6, "the row is not six cells (%d): %s" % (len(cells), row)
    return cells[1]


def _cli_half(col):
    """``(capture hint, verdict markup)`` of one build column's CLI half."""
    m = re.search(r'<div class="dv-t-head dv-cli-scope" title="([^"]*)">CLI</div>\s*'
                  r'<div class="dv-t-body">(.*?)</div>', col, re.S)
    assert m, "no CLI half in this build column: %r" % col[:300]
    return m.group(1), m.group(2)


def _api_half(col):
    """One build column's API half, up to where its CLI half begins."""
    m = re.search(r'>API</div>\s*<div class="dv-t-body">(.*)'
                  r'<div class="dv-t-head dv-cli-scope"', col, re.S)
    assert m, "no API half in this build column: %r" % col[:300]
    return m.group(1)


#: Every key the fixture puts in the table — one per bucket.
KEYS = ("arrives", "goes_away", "fielded", "onesided", "mixed",
        "schemaonly", "onlyhere")


def test_every_finding_gets_one_column_per_build(two_builds, client, app):
    """What the operator asked for on 2026-09-16: a column headed 7.6.8 and one
    headed 8.0.5, in place of the single *Change* cell, with each column's
    evidence indented under the transport that produced it.

    Both halves are asserted. Counting columns alone would pass on a table that
    merely renamed *Change* and kept its contents, so the old cell's absence is
    guarded too — the replacement is the deliverable.
    """
    body = _page(client, app)
    head = _table(body).split("</thead>")[0]
    # ``</th>``, not ``<th``: the latter is also a substring of ``<thead>``,
    # which is how an earlier draft of this guard counted one column too many.
    assert head.count("</th>") == 6, "the table is not six columns: %s" % head
    assert ">Change<" not in head, \
        "the cell the operator replaced is back as a column: %s" % head
    assert ">Evidence</th>" in head, \
        "the Evidence column the operator asked for is gone: %s" % head
    assert ">%s<" % BASE in head and ">%s<" % TARGET in head, \
        "the two columns are not headed by the two builds: %s" % head
    for key in KEYS:
        for col in _build_cols(_row(body, key)):
            assert ">API</div>" in col and ">CLI</div>" in col, \
                "%s: a build column is missing one of its two halves: %r" \
                % (key, col[:300])


def test_each_build_column_answers_from_its_own_capture(two_builds, client, app):
    """The rule the columns exist for.

    A dump comes from one box running one build, so the two columns can never
    cite the same capture. Side by side this is easy to get right and easy to
    stop checking — and on the day it breaks, both columns still look measured.
    """
    body = _page(client, app)
    for key in KEYS:
        base_col, target_col = _build_cols(_row(body, key))
        base_hint, _ = _cli_half(base_col)
        target_hint, _ = _cli_half(target_col)
        for hint, scope in ((base_hint, BASE), (target_hint, TARGET)):
            assert hint.strip(), (key, scope)
            assert scope in hint, (
                "%s: the %s column's CLI half does not name its own build: %r"
                % (key, scope, hint))
            # Measured or not, it has to say WHICH: a badge whose capture is
            # unnamed cannot be told from a two-month-old one, and a build with
            # no capture has to say why its verdict is an em dash.
            assert "em dash" in hint or "captured" in hint, (key, scope, hint)
        assert base_hint != target_hint, (
            "%s: both columns cite the SAME capture — the merge two columns "
            "must never make: %r" % (key, base_hint))


def test_a_field_row_answers_its_transports_from_its_own_provenance(
        two_builds, client, app):
    """The view annotates EVERY bucket, not only the two endpoint ones.

    Without it those verdicts render ``prov_badge(None)`` — a bare em dash with
    NO title, visually identical to the honest "nobody captured anything on
    this build" and to a measured "no CLI block here". Same glyph, three
    meanings; the title is the only thing separating them, so the guard is on
    the title and not on the dash.
    """
    body = _page(client, app)
    for key in ("fielded", "onesided", "mixed", "schemaonly", "onlyhere"):
        for col in _build_cols(_row(body, key)):
            _, verdict = _cli_half(col)
            assert "title=" in verdict, (
                "%s: an em dash with no reason behind it — the bucket was not "
                "annotated: %r" % (key, verdict))


def test_the_cli_half_is_a_verdict_and_never_a_field_list():
    """The one thing the operator's sketch asked for that is not rendered.

    "CLI added / CLI removed" has no evidence behind it. The dump DOES carry
    every block's ``set`` names (``CliBlock.sets``, reaching a page as
    ``rec.settings``) and subtracting them column to column is one line of
    Jinja away — which is exactly why this is guarded rather than merely
    commented. They are the fields somebody CONFIGURED on one appliance, and
    the two columns are two DIFFERENT appliances: the difference measures the
    operators, not the firmware. They are also device configuration, which this
    page is not the permission to read — the same split
    ``test_badges_render_without_backup_but_carry_no_device_configuration``
    draws on the API hub.
    """
    src = io.open(TPL, encoding="utf-8").read()
    body = re.sub(r"\{#.*?#\}", "", src, flags=re.S)   # comments may NAME it
    assert ".settings" not in body, \
        "the page reads the CLI's configured field names: %s" % \
        [ln for ln in body.splitlines() if ".settings" in ln]


def test_the_subtraction_stays_in_the_identity_cell(two_builds, client, app):
    """``2 → 3`` is a fact about the PAIR.

    Put in a build column it states the other column's number, and the two
    columns exist precisely because neither build may answer for the other.
    Pushing both counts into the columns and leaving the arrow nowhere is how
    the operator lost that number the first time — it had to be counted by eye
    off a row of pills.
    """
    cells = _cells(_row(_page(client, app), "fielded"))
    assert "2 → 3" in cells[0], \
        "the finding left the identity cell: %s" % cells[0]
    for i, side in ((3, BASE), (4, TARGET)):
        assert "→" not in cells[i], \
            "the %s column subtracted the other one's number: %s" % (side, cells[i])


def test_each_build_column_carries_its_own_field_count(two_builds, client, app):
    """Splitting the arrow out only works if each column still says how many
    fields IT holds — otherwise the row states a difference and neither side
    says of what."""
    row = _row(_page(client, app), "fielded")
    base_col, target_col = _build_cols(row)
    assert "2 field(s)" in _api_half(base_col), base_col
    assert "3 field(s)" in _api_half(target_col), target_col
    # The kind behind those counts is in the Evidence column since
    # 2026-09-16 — once per row, not once per column. Guarded from both
    # sides: a count with no kind anywhere is unjudgeable, and the kind
    # printed in both columns is the duplication the column removed.
    assert ">sweep<" in _ev_cell(row), \
        "a count with no evidence kind behind it: %s" % row
    for col in (base_col, target_col):
        assert ">sweep<" not in col and ">schema<" not in col, \
            "the evidence kind grew a second author inside a build column: %s" % col


def test_the_gained_names_fold_under_the_build_that_gained_them(
        two_builds, client, app):
    """``gamma`` is on 8.0.5 and not on 7.6.8. A column IS a build, so the name
    may only appear under the build that has it — printed in both it would read
    as a field both builds serve."""
    base_col, target_col = _build_cols(_row(_page(client, app), "fielded"))
    assert "gamma" in target_col, target_col
    assert "gamma" not in base_col, \
        "a field the base build does not have was printed in its column: %s" % base_col
    assert "<details" not in base_col, \
        "the base column grew a fold with nothing to disclose: %s" % base_col


def test_an_unmeasured_side_is_not_worded_as_a_measured_no(
        two_builds, client, app):
    """``absent`` is the appliance rejecting a URN; ``not measured`` is nobody
    having asked. One wording for both is the confusion this whole page exists
    to end, and it becomes newly tempting once both are just "the thin
    column"."""
    body = _page(client, app)
    base_col, _ = _build_cols(_row(body, "onlyhere"))
    assert "not measured on %s" % BASE in base_col, base_col
    assert ">absent<" not in base_col, \
        "an unasked side was badged as a measured rejection: %s" % base_col
    # Premise: the page DOES say ``absent`` where a build really rejected the
    # URN, or the assertion above is satisfied by a page that never says it.
    really_absent, _ = _build_cols(_row(body, "arrives"))
    assert ">absent<" in really_absent, really_absent


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
    """The sentence that says whether this row is a change or a gap.

    It hangs off slot 1's badge — except on a field delta, which has no badge
    since 2026-09-16: the label ``fields changed`` was removed as a restatement
    of the line under it. The sentence did NOT go with it, because "a gap
    worded like a change" is the single misreading this column exists to
    prevent, so there it hangs off the measure line instead.
    """
    m = re.search(r'<div class="dv-kind"><span class="fw-badge[^"]*" title="([^"]*)"',
                  row)
    if not m:
        m = re.search(r'<div class="dv-meta" title="([^"]*)"', row)
    assert m, "neither a titled kind badge nor a titled measure line: %s" % row
    return m.group(1)


def test_no_change_carries_a_kind_badge_and_every_gap_does(two_builds, client, app):
    """The rule the table is read by, guarded from BOTH directions.

    It inverted on 2026-09-16. It used to be "every row badges its class";
    with ``added on`` / ``gone on`` removed it is now **a badge in column 1
    means the row is not a change**. Half a guard would be worse than none
    here: checking only that the four change rows lost their badge passes on a
    page where the three gaps lost theirs too, and then nothing on the page
    distinguishes a measured difference from an unasked question.
    """
    body = _page(client, app)
    for key in ("arrives", "goes_away", "fielded", "schemaonly"):
        row = _row(body, key)
        assert "dv-kind" not in row, \
            "the label the operator removed is back on %s: %s" % (key, row)
        assert "fields changed" not in row.lower(), row
    for key in ("onesided", "mixed", "onlyhere"):
        assert "dv-kind" in _row(body, key), \
            "%s is not a change and nothing on its row says so" % key


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
    # ``arrives`` and ``goes_away`` carry nothing titled in column 1 any more:
    # their badge went with the label. Their change-ness is stated by the two
    # build columns, and BOTH of those badges carry their own title — which is
    # what ``test_both_sides_of_an_endpoint_change_say_they_were_measured``
    # pins, so the sentence did not simply evaporate.
    ("fielded", "is a change"),
    ("onesided", "not a change"),
    ("onlyhere", "not a change"),
    ("mixed", "never subtracted"),
])
def test_each_kind_badge_says_in_its_title_whether_it_is_a_change(
        two_builds, client, app, key, verb):
    """The split the merged table must keep. Once every finding shares a table
    the only thing left carrying "this one is a change" is the wording — and
    on a field delta the badge that used to carry it is gone, so this is the
    guard that stops the sentence going with it."""
    assert verb in _kind_title(_row(_page(client, app), key))


def test_both_sides_of_an_endpoint_change_say_they_were_measured(
        two_builds, client, app):
    """Where the sentence went when the ``added on`` badge was removed.

    A label that disappears usually takes its explanation with it — that is
    how ``fields changed`` nearly took "this one is a change" with it. Here
    the explanation had somewhere true to go: both build columns hold a
    MEASURED verdict, and each says so in its own title, which is precisely
    what makes the row a change rather than a gap. If those titles go, the
    removal did lose something after all.
    """
    body = _page(client, app)
    for key in ("arrives", "goes_away"):
        for col in _build_cols(_row(body, key)):
            half = _api_half(col)
            m = re.search(r'<span class="fw-badge[^"]*" title="([^"]*)"', half)
            assert m, "%s: a verdict with no reason behind it: %s" % (key, half)
            assert "measured" in m.group(1), (key, m.group(1))


def test_the_names_fold_but_the_tally_stays_on_the_fold(two_builds, client, app):
    """Folding hides the NAMES. ``+1`` is the number the rows are compared on
    — it was the one thing the old inline dump made you count by eye — so it
    sits on the summary, outside the fold, and the names stay in the row."""
    _, target_col = _build_cols(_row(_page(client, app), "fielded"))
    row = target_col
    # Scoped to the TARGET column: the row can hold two folds now, one per
    # build, and a bare ``first <summary> in the row`` would be answered by
    # whichever build happened to render one.
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


def test_the_build_columns_do_not_style_themselves_row_by_row():
    """Twelve cells are rendered by six loops. Inline styles repeated per loop
    is how this page ended up with two authors of one rule before."""
    src = io.open(TPL, encoding="utf-8").read()
    i = src.find('id="versionDelta"')
    assert i != -1
    body = src[i:]
    assert 'style="font-size:12px;"' not in body, \
        "a build column is styling itself inline again"


# ===========================================================================
# 7. the Evidence column (2026-09-16)
#
# Second position, at the operator's request. It is the ONLY author of the
# sweep↔schema distinction now — it used to be printed inside both build
# columns, which on every row but one is the same word twice.
# ===========================================================================

@pytest.mark.parametrize("key,kind", [
    ("arrives", "sweep"), ("goes_away", "sweep"), ("onlyhere", "sweep"),
    ("fielded", "sweep"), ("onesided", "sweep"),
    ("schemaonly", "schema"),
])
def test_every_row_names_its_evidence_kind_in_the_second_cell(
        two_builds, client, app, key, kind):
    """Including the ENDPOINT rows, which never carried a kind before.

    They are sweep evidence and the record says so; the point of asserting it
    per bucket is that the template must not be the one deciding — an endpoint
    loop that hardcodes the word would print a kind for a record that has
    none, the same fabrication as inventing a URN for a schema object.
    """
    assert ">%s<" % kind in _ev_cell(_row(_page(client, app), key))


def test_an_incomparable_row_names_both_kinds_and_which_build_holds_which(
        two_builds, client, app):
    """The one row the column cannot collapse to a single badge.

    ``mixed`` is incomparable BECAUSE the two sides hold different kinds of
    evidence. One badge there would erase the finding, and two badges with no
    build beside them would leave the reader to guess which side is which —
    on a page whose entire premise is that neither build answers for the
    other.
    """
    cell = _ev_cell(_row(_page(client, app), "mixed"))
    assert ">sweep<" in cell and ">schema<" in cell, cell
    assert BASE in cell and TARGET in cell, \
        "two kinds and no way to tell which build holds which: %s" % cell
    assert "never subtracted" in cell or "subtracts neither" in cell, \
        "the disagreement is stated without saying what follows from it: %s" % cell


def test_the_evidence_kind_comes_from_the_record_not_from_the_loop():
    """One author, and it is the service.

    Six loops render these rows. A literal ``sweep`` in any of them is a claim
    the template is not entitled to make — and it would keep rendering
    confidently against a record that lost its ``origin``.
    """
    src = io.open(TPL, encoding="utf-8").read()
    delta = src.split('id="versionDelta"')[1].split("</table>")[0]
    delta = re.sub(r"\{#.*?#\}", "", delta, flags=re.S)
    assert "evidence_slot(" in delta and "evidence_split(" in delta
    assert "'sweep'" not in delta and '"sweep"' not in delta, \
        "a row loop spells the evidence kind instead of reading it: %s" % \
        [ln for ln in delta.splitlines() if "sweep" in ln]


def test_a_record_with_no_evidence_kind_is_not_called_schema():
    """The latent defect the new column would have made visible on every row.

    ``origin_badge`` was ``if sweep / else schema`` — so anything that was not
    a sweep, INCLUDING an empty or missing origin, was badged as harvested
    schema evidence. Two branches turned a silence into a claim. Now there are
    three and the third says nothing.
    """
    src = io.open(TPL, encoding="utf-8").read()
    macro = src.split("{% macro origin_badge")[1].split("{%- endmacro %}")[0]
    assert "== 'schema'" in macro, \
        "schema is still the fall-through for every value that is not sweep"


def test_diff_stamps_the_evidence_kind_on_every_bucket(two_builds, app):
    """Because the template is forbidden from inventing it, the service has to
    supply it — for the endpoint buckets too, which had no ``origin`` key at
    all until the column was asked for."""
    with app.app_context():
        d = am.diff("fortiweb", BASE, TARGET)
    for bucket in ("endpoints_added", "endpoints_removed", "endpoints_unknown",
                   "fields_changed", "fields_unknown"):
        for r in d[bucket]:
            assert r.get("origin") in ("sweep", "schema"), (bucket, r)
    for r in d["fields_incomparable"]:
        assert r["base_origin"] != r["target_origin"], r
