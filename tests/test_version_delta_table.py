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
import csv
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


TEMPLATE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "app", "templates", "registry", "versions.html")


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


def _tbody(body):
    """The ROWS only.

    ``_table`` starts at the opening tag, so it carries the header — and the
    Evidence header legitimately spells ``incomparable`` while explaining what
    the column means. A guard that the rows no longer print a class label has
    to look below the header or it fails against a correct page.
    """
    tbl = _table(body)
    return tbl[tbl.find("<tbody>"):]


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
    # The subtraction used to be printed whole in the identity cell (``2 → 3``)
    # and the operator removed it this round: both numbers were already in the
    # build columns that measured them. So the finding is asserted where it now
    # lives — a count in each column and the signed difference beside the side
    # that moved — which is the same fact with nothing restating it.
    base_col, target_col = _build_cols(row)
    assert "2 field(s)" in _api_half(base_col), base_col
    assert "3 field(s)" in _api_half(target_col), target_col
    assert "dv-api-gap" in target_col, \
        "the signed difference that IS the finding is gone: %s" % target_col
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
    # Was ``2 → 3`` until the identity cell lost it. A field delta is now
    # recognised by the only markup a COMPUTED delta earns: the signed tally.
    ("fielded", "dv-api-gap"),
    # The last three labels went the same way on 2026-09-16 at the operator's
    # request (``measured only on X``, ``fields known only on X``,
    # ``incomparable``): each restated a cell already beside it. So each of
    # these buckets is now asserted by the marker that REPLACED its label —
    # the one piece of markup its class alone can render.
    ("onesided", "dv-unmeasured"),
    ("mixed", "dv-ev-side"),
    ("schemaonly", "dv-api-gap"),
    ("onlyhere", "dv-unmeasured"),
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


@pytest.mark.parametrize("gone", [
    "added on", "gone on",                      # removed 2026-09-16, first pass
    "measured only on", "known only on",        # removed 2026-09-16, this pass
    "incomparable", "dv-kind", "dv-meta",
])
def test_the_class_labels_the_operator_removed_do_not_come_back(
        two_builds, client, app, gone):
    """Inverted, because the removal is the deliverable.

    Scoped to the ROWS, not the table: the Evidence column header explains what
    an incomparable row is and has every right to say the word. The rule is
    about the identity cell, and the identity cell is in the body.
    """
    assert gone not in _tbody(_page(client, app)).lower()


def test_the_identity_cell_holds_the_name_and_nothing_else(two_builds, client, app):
    """What ``no labels under the object`` MEANS, for every bucket at once.

    Worded as "no ``dv-kind``" it would pass on a page that grew some other
    line under the name — which is how the slot filled up the first time (a
    badge, then a measure line, then eighteen inline field-name pills). So the
    cell is pinned by what it may CONTAIN: one ``<code>`` and no markup after
    it.
    """
    body = _page(client, app)
    for key in ("arrives", "goes_away", "fielded", "schemaonly",
                "onesided", "mixed", "onlyhere"):
        cell = _cells(_row(body, key))[0]
        after = cell[cell.find("</code>") + len("</code>"):]
        assert cell.count("<code>") == 1, (key, cell)
        assert "<" not in after, \
            "%s regrew something under its name: %r" % (key, after)


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
    (a subtraction, a field tally, a names window) AND by what it must: the
    badge that says it is not a change. A badge in column 1 is the whole
    signal now.

    Third rewording, same trap: the fold became a window on 2026-09-16, so
    ``"<details" not in row`` would have gone vacuous exactly like the two
    labels before it. What a gap may not show is now named by the markup that
    replaced the fold.
    """
    row = _row(_page(client, app), key)
    # ``"→" not in row`` lived here and is GONE on purpose, not relaxed: the
    # arrow was removed from every row this round, so asserting its absence on
    # a gap would pass on any page at all — the fourth wording of this guard to
    # go vacuous the same way. The arrow is pinned page-wide instead, by
    # ``test_no_row_prints_the_subtraction_whole``; what stays here is what
    # still separates a gap from a change.
    assert "<details" not in row, "a gap grew a delta's field fold: %s" % row
    assert "dv-api-gap" not in row, "a gap rendered a signed field tally: %s" % row
    assert "dv-names-more" not in row, "a gap grew a names window: %s" % row
    # FIFTH rewording, same trap. It was ``"fields changed" not in row``, then
    # ``"added on" not in row``, then ``"<details" not in row``, then
    # ``"dv-kind" in row`` — and that last one would have gone VACUOUS this
    # round exactly like the three before it, since the operator removed the
    # badge from every row. What marks a gap now is the cell that IS the gap:
    # a build column that was never asked, or an Evidence cell holding two
    # different kinds. One of the two, never neither.
    assert ("dv-unmeasured" in row) or ("dv-ev-side" in row), \
        "a gap lost the ONLY thing marking it as one: %s" % row


def _all(s, sub):
    i, out = s.find(sub), []
    while i != -1:
        out.append(i)
        i = s.find(sub, i + 1)
    return out


def test_the_partial_caveat_moved_to_its_column_and_was_not_dropped(
        two_builds, client, app):
    """The one thing under the object name that was NOT a restatement.

    ``partial`` says some builds of a rollup attested the URN and some stayed
    silent — a fact about that column, not a class of finding, and stated
    nowhere else on the page. Clearing the identity cell could have taken it
    with it and NOTHING would have failed: the fixture has no partial rollup,
    so the loss would only have shown on a live page, as silence where a
    qualified answer used to be.

    Asserted against the TEMPLATE, because the template is where the move is:
    exactly one call, inside a build column, and never under the name again.
    """
    tpl = io.open(TEMPLATE, encoding="utf-8").read()
    body = tpl[tpl.find("<tbody>"):]
    assert body.count("api_partial(") == 1, \
        "the partial caveat was dropped or duplicated when the cell was cleared"
    before = body[:body.find("api_partial(")]
    cell = before[before.rfind("<td>"):]
    assert "build_cell(" in cell, \
        "partial is back outside a build column: %s" % cell[-200:]
    for row_start in ("<tr><td><code>{{ r.endpoint }}</code>",
                      "<tr><td><code>{{ c.key }}</code>"):
        for i in _all(body, row_start):
            ident = body[i:body.find("</td>", i)]
            assert "api_partial" not in ident and "dv-meta" not in ident, ident


def test_the_two_gaps_do_not_share_one_marker(two_builds, client, app):
    """``known on one side only`` and ``incomparable`` are different gaps: one
    needs a sweep, the other cannot be closed by one. Merging them is the
    phantom-removal defect wearing a different hat.

    The two labels that used to say it went this round, so the distinction is
    pinned where it now lives — and pinned BOTH WAYS, because a guard that only
    checked each row for its own marker would pass on a page where every row
    grew both.
    """
    body = _page(client, app)
    onesided, mixed = _row(body, "onesided"), _row(body, "mixed")
    # unasked: exactly one build column was never measured.
    assert "dv-unmeasured" in onesided and "dv-ev-side" not in onesided, onesided
    # unsubtractable: both sides measured, by kinds that may not be subtracted.
    assert "dv-ev-side" in mixed and "dv-unmeasured" not in mixed, mixed


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


def _visible(markup):
    """What the operator can actually read. A name inside ``data-names-list``
    is stored, not shown, and the two are the whole point of the window."""
    return re.sub(r"<[^>]+>", " ", markup)


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


def test_the_template_never_does_the_subtraction_itself():
    """Repaired 2026-09-16, not relaxed.

    This guard used to forbid rendering the CLI's configured field names AT
    ALL. The operator asked for them — counts under each build's CLI head and a
    window listing the names — so the refusal is gone and what survives it is
    the reason the refusal existed: the two dumps come from two DIFFERENT
    appliances, so the subtraction measures two operators' configuration and
    not the firmware. A caveat that has to travel with a number cannot be
    re-derived at twelve call sites in Jinja, so the delta is computed once in
    ``_apiversions._cli_field_delta`` and arrives carrying its own note.

    Left as an assertion rather than a comment for the same reason as before:
    ``rec.settings`` is in the template's reach and the subtraction is one line
    of Jinja away.
    """
    src = io.open(TPL, encoding="utf-8").read()
    body = re.sub(r"\{#.*?#\}", "", src, flags=re.S)   # comments may NAME it
    assert ".settings" not in body, \
        "the page does its own CLI field arithmetic: %s" % \
        [ln for ln in body.splitlines() if ".settings" in ln]


def test_no_row_prints_the_subtraction_whole(two_builds, client, app):
    """The operator's removal, pinned — and pinned PAGE-WIDE.

    ``8 → 14`` was a third voice: both numbers are printed by the columns that
    measured them, and the cell that held the pair was the only one on the
    page stating two builds' numbers at once. Scoped to one row this would be
    a weak guard; the thing worth preventing is it creeping back into any of
    the six row loops.
    """
    body = _page(client, app)
    table = _table(body)
    assert "→" not in table, \
        "the identity cell's subtraction is back: %s" % \
        [ln for ln in table.splitlines() if "→" in ln][:4]


def test_neither_build_column_states_the_other_ones_count(two_builds, client, app):
    """What the removed arrow was protecting, kept without it.

    The two columns exist precisely because neither build may answer for the
    other. With the pair-fact gone from column 1 this is the whole invariant:
    each column prints ITS number and never the other's.
    """
    cells = _cells(_row(_page(client, app), "fielded"))
    base_col, target_col = _api_half(cells[3]), _api_half(cells[4])
    assert "2 field(s)" in base_col and "3 field(s)" not in base_col, \
        "the %s column states the other one's count: %s" % (BASE, base_col)
    assert "3 field(s)" in target_col and "2 field(s)" not in target_col, \
        "the %s column states the other one's count: %s" % (TARGET, target_col)


def test_the_identity_cell_holds_the_name_and_nothing_numeric(
        two_builds, client, app):
    """Guarded from the other direction too, or the round is half pinned: a
    field delta's first cell is the object's name and no measurement."""
    for key in ("fielded", "schemaonly"):
        cell = _cells(_row(_page(client, app), key))[0]
        assert key in cell
        assert "dv-count" not in cell, \
            "a count crept back under the object name: %s" % cell
        assert "dv-meta" not in cell, \
            "the measure line is back under the object name: %s" % cell


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


def test_the_gained_names_belong_to_the_build_that_gained_them(
        two_builds, client, app):
    """``gamma`` is on 8.0.5 and not on 7.6.8. A column IS a build, so the name
    may only appear under the build that has it — carried by both it would read
    as a field both builds serve.

    Since the fold became a window the name rides in ``data-names-list``, so
    this asserts on the column's MARKUP for presence and on its VISIBLE TEXT
    for absence — a name in the attribute is not on the page, and testing the
    raw string for both would let a printed name pass as a stored one."""
    base_col, target_col = _build_cols(_row(_page(client, app), "fielded"))
    assert "gamma" in target_col, target_col
    assert "gamma" not in base_col, \
        "a field the base build does not have was carried in its column: %s" % base_col
    assert "dv-names-more" not in base_col, \
        "the base column grew a window with nothing to list: %s" % base_col


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

    It has moved three times, always FOLLOWING the finding rather than staying
    in a slot: off the ``fields changed`` label, then off slot 1's kind badge,
    and now — with the identity cell emptied on 2026-09-16 — off the cell that
    embodies the class. Deleting it was never on the table: a gap worded like a
    change is the single misreading this table exists to prevent, and an
    unnamed one is a phantom removal.

    Addressable on purpose. A bare ``phrase in row`` cannot tell "moved into a
    title" from "deleted, with the words left behind in a comment".
    """
    for pat in (
            # a gap: the cell that IS the gap — the side nobody asked.
            r'<span class="text-muted dv-unmeasured" title="([^"]*)"',
            # an incomparable pair: the Evidence cell holding the disagreement.
            r'<div class="dv-ev" title="([^"]*)"',
            # a computed delta: the signed tally, in the column that moved.
            r'<span class="fw-badge[^"]*dv-api-gap" title="([^"]*)"'):
        m = re.search(pat, row)
        if m:
            return m.group(1)
    raise AssertionError("nothing on this row carries the sentence: %s" % row)


def test_no_change_looks_like_a_gap_and_every_gap_says_so(two_builds, client, app):
    """The rule the table is read by, guarded from BOTH directions.

    Third anchor for one rule. It was "every row badges its class", then "a
    badge in column 1 means the row is NOT a change", and now the identity cell
    is empty so the rule lives in the columns: a gap is a row with an unasked
    side or a split Evidence cell, and a change is a row with NEITHER, because
    a change is a difference between two things that were both measured.

    Half a guard is worse than none here. Checking only that the four change
    rows carry no gap marker passes on a page where the three gaps lost theirs
    too — and then nothing at all separates a measured difference from a
    question nobody asked, which is the 56-phantom-removals defect.
    """
    body = _page(client, app)
    for key in ("arrives", "goes_away", "fielded", "schemaonly"):
        row = _row(body, key)
        assert "dv-unmeasured" not in row, \
            "%s is a CHANGE and one of its sides says nobody measured it: %s" \
            % (key, row)
        assert "dv-ev-side" not in row, \
            "%s is a CHANGE and its Evidence cell split in two: %s" % (key, row)
        assert "fields changed" not in row.lower(), row
    for key in ("onesided", "mixed", "onlyhere"):
        row = _row(body, key)
        assert ("dv-unmeasured" in row) or ("dv-ev-side" in row), \
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


def test_the_api_tally_stays_in_the_cell_and_the_names_go_to_the_window(
        two_builds, client, app):
    """The window hides the NAMES. ``+1`` is the number the rows are compared
    on — the one thing the old inline dump made you count by eye — so it stays
    printed in the cell while the names move behind the button.

    Scoped to the TARGET column's API half: the row carries a tally per build
    and per half, and an unscoped search would be answered by whichever one
    happened to render."""
    _, target_col = _build_cols(_row(_page(client, app), "fielded"))
    half = _api_half(target_col)
    assert "dv-api-gap" in half, "the API tally is gone: %s" % half
    assert "+1" in _visible(half), \
        "the tally is not printed in the cell: %s" % _visible(half)
    assert "gamma" not in _visible(half), \
        "the name is printed in the cell, which is what the window replaced"
    assert 'data-names-list="gamma"' in half, \
        "the window has nothing to render from: %s" % half


def test_a_row_with_no_field_names_grows_no_empty_window(two_builds, client, app):
    """An endpoint row has no field list. A disclosure that opens onto nothing
    reads as evidence withheld."""
    row = _row(_page(client, app), "arrives")
    assert "<details" not in row
    assert "dv-names-more" not in row, "a window that would open on nothing: %s" % row


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


# ---------------------------------------------------------------------------
# 6. the CLI half prints numbers (2026-09-16, at the operator's request)
# ---------------------------------------------------------------------------

def _cli_half_macro():
    """The macro's source with its comments stripped.

    Stripped because this repo has now paid eight times for an assertion
    answered by the comment that EXPLAINS it.
    """
    src = io.open(TPL, encoding="utf-8").read()
    m = re.search(r"\{% macro cli_half\(.*?\{%- endmacro %\}", src, re.S)
    assert m, "the CLI half is no longer a macro of its own"
    return re.sub(r"\{#.*?#\}", "", m.group(0), flags=re.S)


def test_a_build_that_printed_no_block_gets_a_verdict_and_never_a_zero():
    """An absent block is not an empty one.

    A config table with nothing in it prints NO block at all — that is RULE 1
    of this whole module, and the 56 phantom removals behind it. So "no block"
    must not arrive at the page as ``0 set(s)``: it has no count, and the cell
    falls back to the transport verdict.
    """
    from app.views._apiversions import _cli_field_delta as d
    assert d(None, None, "note") is None
    assert d({"bucket": "no_block"}, {"bucket": "monitor_only"}, "note") is None

    one = d({"bucket": "both", "settings": ["a", "b"]}, {"bucket": "no_block"}, "note")
    assert one["base_count"] == 2
    assert one["target_count"] is None, "a side with no block was given a count"
    assert one["comparable"] is False
    assert one["added"] == [] and one["removed"] == [], \
        "subtracted against a side that never answered"


def test_the_subtraction_runs_only_when_both_builds_printed_a_block():
    from app.views._apiversions import _cli_field_delta as d
    both = d({"bucket": "both", "settings": ["a", "b"]},
             {"bucket": "both", "settings": ["b", "c"]}, "note")
    assert both["comparable"] is True
    assert both["removed"] == ["a"] and both["added"] == ["c"]
    assert both["base_count"] == 2 and both["target_count"] == 2


def test_the_cli_numbers_carry_the_two_appliance_warning():
    """Without it ``+3`` reads as "this firmware gained three fields"."""
    from app.views._apiversions import _cli_pair_note, _cli_field_delta

    class _P:
        measured = True

        def __init__(self, dev):
            self.device = dev

    note = _cli_pair_note("7.6.8", _P("boxA"), "8.0.5", _P("boxB"))
    for token in ("boxA", "boxB", "7.6.8", "8.0.5"):
        assert token in note, "the note does not name %s: %r" % (token, note)
    assert "firmware" in note, "the note never says what it is NOT measuring"
    assert _cli_field_delta({"bucket": "both", "settings": ["a"]},
                            {"bucket": "both", "settings": ["a"]},
                            note)["note"] == note

    # and both surfaces that print a number hang it in a title
    mac = _cli_half_macro()
    titled = [h for h in re.findall(r'title="([^"]*)"', mac) if "cd.note" in h]
    assert len(titled) >= 2, \
        "a number without the caveat: %r" % re.findall(r'title="([^"]*)"', mac)


def test_the_names_ride_in_an_attribute_and_not_in_the_row_text():
    """The row filter matches ``tr.textContent``.

    A fold whose contents match is OPENED by the filter, because a row counted
    as a hit on text the operator cannot see is worse than a miss. A modal
    cannot be opened that way — so the names must not be in the matchable text
    at all, and they are not: they ride in ``data-names-list`` and the window
    is built from it.
    """
    mac = _cli_half_macro()
    assert "data-names-list=" in mac, "the window has nothing to render from"
    assert "{% for" not in mac and "{%- for" not in mac, \
        "the names are being printed into the cell: %s" % mac


def test_the_plus_button_exists_only_when_there_is_something_to_list():
    """A window that opens on nothing reads as evidence withheld."""
    mac = _cli_half_macro()
    i = mac.find("dv-names-more")
    assert i != -1, "the window button is gone"
    guard = mac[:i]
    assert "{%- if names %}" in guard or "{% if names %}" in guard, \
        "the button is not conditioned on there being names: %s" % guard
    # and the signed number is conditioned on the comparison having run
    assert "cd.comparable" in mac, \
        "a signed number is printed for a comparison that never ran"


# ---------------------------------------------------------------------------
# 8. the API half opens the same window (2026-09-16, at the operator's request)
# ---------------------------------------------------------------------------

def _api_names_macro():
    """``api_names`` with its comments stripped — this repo has paid nine times
    for an assertion answered by the comment that explains it."""
    src = io.open(TPL, encoding="utf-8").read()
    m = re.search(r"\{% macro api_names\(.*?\{%- endmacro %\}", src, re.S)
    assert m, "the API names are no longer a macro of their own"
    return re.sub(r"\{#.*?#\}", "", m.group(0), flags=re.S)


def test_the_api_window_is_never_handed_the_cli_caveat():
    """The two halves count different things and must not share one sentence.

    The CLI number is two operators' configuration on two boxes — that caveat
    is the reason the number is allowed on the page at all. The API number is
    what a build's catalog serves, measured on that build. Pasting the CLI note
    onto the API window would relabel a firmware fact as somebody's config;
    pasting the API note onto the CLI window would do the reverse, which is
    worse.
    """
    mac = _api_names_macro()
    assert "cd.note" not in mac, \
        "the API window was handed the two-appliance caveat: %s" % mac
    note = re.search(r'data-names-note="([^"]*)"', mac)
    assert note, "the API window opens with no note at all: %s" % mac
    assert "not what an operator configured" in note.group(1), \
        "the API note does not say what it is NOT measuring: %r" % note.group(1)
    # and the CLI half still carries its own
    assert 'data-names-note="{{ cd.note }}"' in _cli_half_macro(), \
        "the CLI window lost the caveat that lets it print a number"


def test_one_window_serves_both_halves():
    """Two windows is two authors of one behaviour, which is how this page lost
    an anchor before. Both halves hang off the same hook and there is one
    modal on the page."""
    src = io.open(TPL, encoding="utf-8").read()
    assert src.count('id="dvNames"') == 1, "not exactly one names window"
    assert "dv-names-more" in _api_names_macro()
    assert "dv-names-more" in _cli_half_macro()
    assert "dv-cli-more" not in src, "a second window hook survived"


def test_the_api_names_are_never_printed_into_the_cell():
    """Same rule as the CLI half: a loop in the macro means the names are back
    in ``tr.textContent``, where the filter would count a row as a hit on text
    the window keeps shut."""
    mac = _api_names_macro()
    assert "{% for" not in mac and "{%- for" not in mac, \
        "the names are being printed into the cell: %s" % mac


# ===========================================================================
#  the CSV export                                                           #
# ===========================================================================
# What a download has to carry that the screen does not: the screen says which
# KIND of finding a row is with a badge and two columns, and it says "this is
# not a change" with a tooltip. A CSV gets pivoted, so both have to be values.


def _csv(client, app, base=BASE, target=TARGET):
    login(client, admin_user_id(app))
    r = client.get("/web/registry/versions/export.csv?base=%s&target=%s"
                   % (base, target))
    assert r.status_code == 200, r.status_code
    return r, list(csv.reader(io.StringIO(r.get_data(as_text=True))))


def _split(rows):
    """``(data including its header, legend)``.

    The legend sits BELOW a blank row on purpose: a blank row ends a
    spreadsheet's auto-detected range, so documentation cannot be summed or
    pivoted as if it were findings.
    """
    for i, r in enumerate(rows):
        if not any((c or "").strip() for c in r):
            return rows[:i], rows[i + 1:]
    return rows, []


def test_the_export_carries_every_row_the_table_shows(two_builds, client, app):
    """The defect this page was rebuilt to end, in its export form.

    ``antivirus`` — a row whose only finding is a field delta — was ABSENT
    from one of the three tables that used to say this, and an absent row
    reads as "no finding here". A download that drops a bucket does exactly
    that, to a reader who cannot see the page to notice.
    """
    _, rows = _csv(client, app)
    data, legend = _split(rows)
    keys = {r[2] for r in data[1:]}
    for k in ("arrives", "goes_away", "fielded", "schemaonly",
              "onesided", "mixed", "onlyhere"):
        assert k in keys, "%s never reached the CSV: %s" % (k, sorted(keys))
    # ...and exactly the table's rows, not a superset: a row in the file with
    # no row on screen is a finding nobody can check.
    # -1 on both sides: the CSV's first line is its header and the
    # table's first <tr> is its <thead> row.
    #
    # Counted over the DATA REGION since the column legend shipped. The point
    # of the blank separator is that the legend is not in this count — so the
    # legend has to be non-empty here, or this guard would go quiet the day
    # somebody moved the documentation back up among the findings.
    assert legend, "no column legend below the data"
    body_rows = len(re.findall(r"<tr>", _table(_page(client, app)))) - 1
    assert len(data) - 1 == body_rows, (len(data) - 1, body_rows)


def test_every_column_explains_itself_in_the_legend(two_builds, client, app):
    """Heading and explanation are emitted from one list, and this is what
    keeps them that way: a legend that documents a column the file no longer
    has — or skips one it grew — is worse than no legend, because it is read
    as authoritative. The CLI headings are compared verbatim, so the capture
    they name cannot drift away from the note that qualifies it."""
    _, rows = _csv(client, app)
    data, legend = _split(rows)
    assert legend[0][:3] == ["#", "column", "what it means"], legend[0]
    documented = [r[1] for r in legend[1:]]
    assert documented == data[0], (documented, data[0])
    for r in legend[1:]:
        assert r[0] == "#", r          # filterable by code, ignorable by eye
        assert len(r[2].strip()) > 20, r
    # and the one caveat a CSV has no tooltip for
    cli = [r for r in legend[1:] if re.match(r"^\S+ CLI (verdict|sets)\b", r[1])]
    assert cli, documented
    assert any("two different boxes" in r[2] for r in cli), cli


@pytest.mark.parametrize("key,change", [
    ("arrives", "yes"), ("goes_away", "yes"),
    ("fielded", "yes"), ("schemaonly", "yes"),
    ("onesided", "no"), ("mixed", "no"), ("onlyhere", "no"),
])
def test_the_export_says_outright_whether_a_row_is_a_change(
        two_builds, client, app, key, change):
    """Guarded from BOTH directions, because half of it is worse than none.

    A gap summed into a change count is the phantom-removal defect all over
    again — and a spreadsheet is where someone sums things. Checking only that
    the gaps say ``no`` passes on a file where the changes say ``no`` too.
    """
    _, rows = _csv(client, app)
    row = next(r for r in _split(rows)[0][1:] if r[2] == key)
    assert row[1] == change, "%s is marked %r: %s" % (key, row[1], row)


def test_the_export_names_which_bucket_each_row_came_from(two_builds, client, app):
    _, rows = _csv(client, app)
    got = {r[2]: r[0] for r in _split(rows)[0][1:]}
    assert got["arrives"] == "endpoint added"
    assert got["goes_away"] == "endpoint gone"
    assert got["fielded"] == "field delta"
    assert got["mixed"] == "incomparable"
    assert "one side only" in got["onesided"]


def test_the_export_carries_the_names_that_live_behind_the_window(
        two_builds, client, app):
    """The one thing a download is for.

    The field names left the row's text when the fold became a modal — they
    ride in a data- attribute now. An export of "the whole table" that dropped
    them would be the page's own loss, shipped.
    """
    _, rows = _csv(client, app)
    row = next(r for r in _split(rows)[0][1:] if r[2] == "fielded")
    assert "gamma" in " ".join(row), "the gained field name is not in the CSV: %s" % row


def test_neither_export_column_states_the_other_builds_count(
        two_builds, client, app):
    """The same invariant the two columns keep on screen. Flattened into one
    line of CSV it is easier to lose, not harder."""
    _, rows = _csv(client, app)
    head, row = rows[0], next(r for r in _split(rows)[0][1:] if r[2] == "fielded")
    b = head.index("%s API fields" % BASE)
    t = head.index("%s API fields" % TARGET)
    assert row[b] == "2" and row[t] == "3", row


def test_a_cli_column_heading_names_its_own_capture(two_builds, client, app):
    """A bare ``7.6.8 CLI sets`` invites the reader to subtract two columns as
    if they were one box measured twice. They are two boxes. On screen that
    caveat is a tooltip; a CSV has none, so it is in the heading, where it
    cannot be detached from the numbers it qualifies."""
    _, rows = _csv(client, app)
    # Only the headings that carry a VERDICT or a NUMBER. CLI fields only
    # on <build> is a names column and qualifies nothing on its own.
    cli = [h for h in rows[0] if re.match(r"^\S+ CLI (verdict|sets)\b", h)]
    assert cli, rows[0]
    for h in cli:
        assert ("operator configuration" in h) or ("no dump captured" in h), h


def test_the_export_refuses_rather_than_hand_back_an_empty_file(
        two_builds, client, app):
    """A header row and nothing else reads as "nothing differs". That is a
    different claim from "you have not picked two comparable builds", and the
    file cannot tell them apart, so it is not served."""
    login(client, admin_user_id(app))
    r = client.get("/web/registry/versions/export.csv?base=%s&target=%s"
                   % (BASE, BASE))
    assert r.status_code in (302, 303), r.status_code


def test_the_export_does_not_respell_the_transport_vocabulary(
        two_builds, client, app):
    """The CLI verdict words are spelled in ``_cli_provenance.html`` and
    nowhere else. The CSV carries the raw bucket key instead — a second author
    of that vocabulary is how a label drifts out of step with the badge it is
    supposed to mirror."""
    body = io.open(os.path.join(ROOT, "app/views/_apiversions.py"),
                   encoding="utf-8").read()
    body = re.sub(r"#[^\n]*", "", body)          # comments may NAME them
    for label in ("API + CLI", "API only", "CLI only"):
        assert label not in body, "the export spells %r itself" % label


def test_the_export_button_points_at_the_pair_on_screen(two_builds, client, app):
    """Not at whatever the two selects happen to say.

    As a ``formaction`` submit it would export the selects, and a select
    changed without pressing Compare says something the table does not. The
    href carries the RENDERED pair.
    """
    body = _page(client, app)
    m = re.search(r'href="([^"]*export\.csv[^"]*)"', body)
    assert m, "no export link on the page"
    assert ("base=%s" % BASE) in m.group(1) and ("target=%s" % TARGET) in m.group(1), \
        m.group(1)
