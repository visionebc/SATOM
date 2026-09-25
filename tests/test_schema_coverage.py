"""A hole in the schema catalog has to say WHY, and say it from a record.

The defect these guards exist for cost a session on 2026-09-17. The comparison
printed ``not measured on 8.0.5`` for ``user_group``; the operator had just run
a sweep against an 8.0.5 box and read that as the sweep having failed. It had
not. Schema evidence does not come from a sweep at all — it comes from an
offline harvest against ONE reference appliance per line, and that harvest can
only describe a table the appliance has populated. Five objects have no 8.0
schema because those tables are EMPTY on fortiweb17; one because 8.0.5 rejects
the URN.

Every one of those reasons existed. The harvester printed each to a terminal
and threw it away, so the page had nothing to show and the operator had no way
to reach it. Nothing failed — the sentence on screen was true — which is the
class of defect no test catches unless the test is about the sentence itself.

So: the harvest RECORDS what it could not do, and the page reads that record.
These guards pin the two halves to each other, because a writer and a reader of
one file with two ideas of what "covered" means is the same silence with more
moving parts.

Targeted suite: no network, no appliance.
"""
from __future__ import annotations

import io
import json
import os
import re

import pytest

from app.services import api_matrix as am
from app.services import field_catalog as fc

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HARVESTER = os.path.join(ROOT, "scripts", "build_field_catalog.py")


def _harvester_src():
    return io.open(HARVESTER, encoding="utf-8").read()


# ---------------------------------------------------------------------------
# 1. the writer and the reader agree on what "covered" means
# ---------------------------------------------------------------------------

def test_the_reader_and_the_writer_share_one_filename():
    """Two names for one file is one rename away from a reader that finds
    nothing and reports it as "no harvest has ever run"."""
    src = _harvester_src()
    m = re.search(r'COVERAGE_FILENAME = "([^"]+)"', src)
    assert m, "the harvester no longer names the coverage file"
    assert m.group(1) == fc.COVERAGE_FILENAME, (
        "the harvest writes %r and the app reads %r" % (m.group(1), fc.COVERAGE_FILENAME))


def test_covered_means_the_same_thing_on_both_sides():
    """The writer counts an object as covered iff it is not in its ``missing``
    list; the reader has its own set. Drifted, an object could be dropped from
    the banner's hole list and still render a reason on its row — two answers
    to one question, on one screen."""
    src = _harvester_src()
    m = re.search(r"if r\[\"status\"\] not in \(([^)]*)\)", src, re.S)
    assert m, "the harvest no longer computes its missing list by status"
    names = re.findall(r"STATUS_[A-Z_]+", m.group(1))
    values = {re.search(r'%s = "([^"]+)"' % n, src).group(1) for n in names}
    assert values == set(fc.COVERED_STATUSES), (
        "the harvest treats %s as covered and the app treats %s"
        % (sorted(values), sorted(fc.COVERED_STATUSES)))


def test_every_status_the_harvest_can_record_has_a_sentence():
    """A status with no reason renders a ``why`` affordance that opens on
    nothing — worse than no affordance, because it promises an answer."""
    src = _harvester_src()
    declared = {re.search(r'%s = "([^"]+)"' % n, src).group(1)
                for n in set(re.findall(r"^(STATUS_[A-Z_]+) =", src, re.M))}
    m = re.search(r"COVERAGE_REASON = \{(.*?)\n\}", src, re.S)
    assert m, "the harvester no longer carries a reason table"
    explained = {re.search(r'%s = "([^"]+)"' % n, src).group(1)
                 for n in re.findall(r"STATUS_[A-Z_]+", m.group(1))}
    unexplained = declared - explained - {"harvested", "kept"}
    assert not unexplained, (
        "these statuses can be recorded with no sentence to show: %s" % sorted(unexplained))


def test_an_empty_table_is_never_worded_as_a_firmware_fact():
    """THE misreading. "No schema on 8.0" is a fact about a box's
    configuration; worded as a property of the build it becomes evidence of a
    removal that nobody measured — the 56 phantom removals, re-entering
    through the prose instead of through the subtraction."""
    src = _harvester_src()
    m = re.search(r"STATUS_EMPTY_TABLE:\s*(.*?)\",\n", src, re.S)
    assert m, "the empty-table reason is gone"
    text = " ".join(m.group(1).split())
    assert "NOT about the firmware" in text or "not about the firmware" in text, \
        "the empty-table reason no longer says what it is NOT: %s" % text
    assert "re-run the harvest" in text, \
        "a reason that does not say what would fix it is a dead end: %s" % text


def test_a_rejected_urn_does_not_pick_a_side():
    """8.0.5 rejects ``user_group`` under a path 7.6.8 serves. That is equally
    consistent with the object having been dropped and with the registry path
    being wrong for the line, and the record used to assert the second."""
    src = _harvester_src()
    m = re.search(r"STATUS_URN_REJECTED:\s*(.*?)\",\n", src, re.S)
    assert m
    text = " ".join(m.group(1).split())
    assert "does not say which" in text, \
        "the rejection reason picks one reading again: %s" % text


# ---------------------------------------------------------------------------
# 2. an existing schema is coverage, whatever this run managed
# ---------------------------------------------------------------------------

def test_a_kept_file_counts_as_coverage_even_when_unverified():
    """Found by running it: line 7.6 holds fifteen schema files, five of them
    harvested in August from a box that had those tables populated. Today's
    reference box has them empty, so the run classified five EXISTING schemas
    as holes and reported 10/16 for a directory of 15. The page would have
    printed "no schema on 7.6" beside a row showing that schema's fields."""
    assert "kept_unverified" in fc.COVERED_STATUSES
    src = _harvester_src()
    assert "def _no_evidence(" in src, \
        "the harvest no longer checks the directory before calling an object a hole"
    m = re.search(r"def _no_evidence\(.*?\n\n\n", src, re.S)
    assert "os.path.exists(schema_path(" in m.group(0), \
        "the hole classifier stopped looking at what is on disk: %s" % m.group(0)


# ---------------------------------------------------------------------------
# 3. the reader
# ---------------------------------------------------------------------------

@pytest.fixture()
def tree(tmp_path):
    d = tmp_path / "fortiweb" / "8.0"
    d.mkdir(parents=True)
    (d / "dns.json").write_text(json.dumps(
        {"object": "dns", "endpoint": "dns", "fields": [{"name": "primary"}]}))
    (d / fc.COVERAGE_FILENAME).write_text(json.dumps({
        "product": "fortiweb", "line": "8.0", "appliance": "boxA",
        "device_firmware": "8.0.5", "harvested_at": "2099-01-01T00:00:00",
        "catalog_size": 3, "covered": 1,
        "objects": {
            "dns": {"status": "harvested", "detail": "1 field(s)", "reason": ""},
            "syslog": {"status": "empty_table", "detail": "no rows",
                       "reason": "the table is EMPTY on the reference appliance"},
            "user_group": {"status": "urn_rejected", "detail": "errcode=-20001",
                           "reason": "the appliance REJECTED the URN"},
        }}))
    return str(tmp_path)


def test_a_covered_object_gets_no_excuse(tree):
    """Asked about an object that HAS a schema, the reader says nothing. A
    reason attached to evidence that exists is an apology for a fact."""
    assert fc.coverage_gap("fortiweb", "8.0", "dns", root=tree) == {}


def test_a_hole_carries_its_recorded_reason(tree):
    g = fc.coverage_gap("fortiweb", "8.0", "syslog", root=tree)
    assert g["status"] == "empty_table"
    assert "EMPTY on the reference appliance" in g["reason"]
    assert g["detail"] == "no rows", "the raw observation is dropped: %r" % g


def test_never_harvested_is_not_reported_as_complete(tmp_path):
    """The pair that matters most. A line nobody has harvested has zero
    recorded holes — and rendering that as "everything is covered" is the same
    silence this whole record replaced."""
    s = fc.coverage_summary("fortiweb", "9.9", root=str(tmp_path))
    assert s["harvested"] is False
    assert s["missing"] == []
    assert s["covered"] == 0


def test_a_harvested_line_reports_its_holes_with_their_reasons(tree):
    s = fc.coverage_summary("fortiweb", "8.0", root=tree)
    assert s["harvested"] is True
    assert s["appliance"] == "boxA"
    assert [m["object"] for m in s["missing"]] == ["syslog", "user_group"]
    assert all(m["reason"] for m in s["missing"]), \
        "a hole with no sentence: %s" % s["missing"]


def test_an_unreadable_record_is_no_record_and_says_so(tmp_path):
    d = tmp_path / "fortiweb" / "8.0"
    d.mkdir(parents=True)
    (d / fc.COVERAGE_FILENAME).write_text("{ this is not json")
    assert fc.coverage("fortiweb", "8.0", root=str(tmp_path)) == {}
    assert fc.coverage_summary("fortiweb", "8.0", root=str(tmp_path))["harvested"] is False


# ---------------------------------------------------------------------------
# 4. the coverage file is bookkeeping, never an object
# ---------------------------------------------------------------------------

def test_the_coverage_file_is_never_read_as_an_object(tmp_path, monkeypatch):
    """It sits in the same directory as the schemas and this reader treats that
    directory as "one file per object". It used to be excluded only because it
    happens to carry no ``object`` key — one field away from appearing in the
    comparison as an object named after a bookkeeping file."""
    d = tmp_path / "fortiweb" / "8.0"
    d.mkdir(parents=True)
    (d / "dns.json").write_text(json.dumps(
        {"object": "dns", "fields": [{"name": "primary"}]}))
    # The hostile shape: a coverage file that DOES carry the key.
    (d / fc.COVERAGE_FILENAME).write_text(json.dumps(
        {"object": "_coverage", "fields": [{"name": "trap"}], "objects": {}}))
    from app.services import api_library as lib
    doc = lib.evidence_from_schema_dir("fortiweb", "8.0", str(d))
    assert set(doc["endpoints"]) == {"dns"}, \
        "a bookkeeping file was read as an object: %s" % sorted(doc["endpoints"])


def test_the_matrix_explains_the_holes_of_the_tree_it_read(tmp_path, monkeypatch):
    """One root for one tree. ``api_matrix`` keeps its own ``SCHEMA_ROOT`` and
    the coverage file lives inside it; reading schemas from one tree and their
    reasons from this module's default would describe one installation and
    explain another — and nothing on the page would look wrong."""
    src = io.open(os.path.join(ROOT, "app/services/api_matrix.py"), encoding="utf-8").read()
    body = src[src.index("def diff("):]

    def _call(text, at):
        """The WHOLE call, by paren balance.

        A lazy ``(.*?)\\)`` stops at the first close paren — which here is the
        one inside ``row.get("key")`` — so the first draft of this guard failed
        against correct code. A guard that reads a fragment of a call is
        reading a different call.
        """
        depth, i = 0, at
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    return text[at:i + 1]
            i += 1
        raise AssertionError("unbalanced call at %d" % at)

    seen = 0
    for call in ("coverage_gap(", "coverage_summary("):
        for m in re.finditer(re.escape(call), body):
            whole = _call(body, m.end() - 1)
            seen += 1
            assert "root=SCHEMA_ROOT" in whole, (
                "%s is resolved against the wrong tree: %s" % (call, whole[:200]))
    assert seen >= 3, "the comparison stopped reading coverage at all (%d calls)" % seen


# ---------------------------------------------------------------------------
# 4. a side with no schema is not automatically a side nobody asked
#
# The 2026-09-17 follow-up. The operator ran the sweep a SECOND time, against
# the 8.0.5 box, and the cell still said "not measured on 8.0.5". Their
# objection was exactly right and the earlier fix had not addressed it: the
# sweep HAD asked that build about that object, and the build answered
# ``absent`` (errcode -20001, "The REST API has invalid URL"). Two independent
# sources agree it is gone in 8.0 -- the API rejects the URN, and the 8.0.5 CLI
# dump has no ``config user user-group`` block while the 7.6.8 one does.
#
# So the page had a measured answer in hand and spelled it the same way it
# spells silence. These guards pin the distinction, NOT a merge: only the
# existence verdict crosses, never a field set -- crossing field sets is what
# reported 56 phantom removals.
# ---------------------------------------------------------------------------

def _matrix_with(target_endpoint: dict | None):
    """7.6 knows a schema for ``widget``; 8.0 does not. ``target_endpoint`` is
    what the sweep recorded for ``widget`` on 8.0 -- or nothing at all."""
    eps = {}
    if target_endpoint is not None:
        eps["widget"] = dict({"endpoint": "widget", "fields": None,
                              "origin": "sweep",
                              "urn": "/api/v2.0/cmdb/x/widget"}, **target_endpoint)
    return {
        "product": "fortiweb",
        "versions": {},
        "lines": {
            "7.6": {"endpoints": {}, "objects": {
                "widget": {"fields": ["a", "b"], "origin": "schema"}}},
            "8.0": {"endpoints": eps, "objects": {}},
        },
    }


def _unknown_row(matrix):
    d = am.diff("fortiweb", "7.6", "8.0", matrix=matrix)
    rows = [r for r in d["fields_unknown"] if r["key"] == "widget"]
    assert rows, "the schema-gap row vanished: %s" % d["fields_unknown"]
    return rows[0]


def test_a_rejected_build_is_reported_as_measured_not_as_silence():
    row = _unknown_row(_matrix_with(
        {"verdict": "absent", "measured_at": "2026-09-16T22:45:26",
         "devices": ["fortiweb17"]}))
    m = row.get("measured")
    assert m, ("the sweep asked this build and it said no; the row carries "
               "nothing, so the cell can only spell it as an unasked question")
    assert m["verdict"] == "absent"
    assert m["devices"] == ["fortiweb17"], "the box that answered is not named"
    assert m["scope"] == "8.0", "the verdict is attached to the wrong side"


def test_a_served_build_with_no_schema_still_reports_what_it_answered():
    """The commoner half, and the one that teaches the rule: a cmdb GET returns
    the entries somebody CONFIGURED. A populated-nowhere table answers ``ok``
    and still yields no field names, which is not a defect and must not be
    worded as one."""
    row = _unknown_row(_matrix_with({"verdict": "ok", "devices": ["fortiweb17"]}))
    assert (row.get("measured") or {}).get("verdict") == "ok"


def test_a_key_the_sweep_never_recorded_keeps_the_unqualified_phrase():
    """The guard against over-reaching: inventing a verdict for a key with no
    endpoint record would make "measured" meaningless everywhere it appears."""
    row = _unknown_row(_matrix_with(None))
    assert row.get("measured") in (None, {}), \
        "a verdict was manufactured for a key the sweep never recorded: %r" % (
            row.get("measured"),)


def test_no_field_set_crosses_the_origin_boundary():
    """The 56 phantom removals, pinned.

    NOTE the shape, which the first draft of this guard got wrong: a sweep that
    carries fields on one side against a schema on the other is not a schema
    gap at all -- it is INCOMPARABLE, and lands in its own bucket. That is the
    boundary working. What must never happen is those sweep names reaching a
    row whose evidence is ``schema``, or a field delta being computed across
    the two kinds.
    """
    m = _matrix_with({"verdict": "ok", "fields": ["zzz_sweep_only"],
                      "devices": ["fw"]})
    d = am.diff("fortiweb", "7.6", "8.0", matrix=m)
    assert not [r for r in d["fields_changed"] if r["key"] == "widget"], \
        "a delta was computed between a sweep set and a schema set"
    assert [r for r in d["fields_incomparable"] if r["key"] == "widget"], \
        "two kinds of evidence stopped declaring themselves incomparable"
    blob = json.dumps(d["fields_unknown"] + d["fields_changed"])
    assert "zzz_sweep_only" not in blob, \
        "a sweep field set leaked into a schema row: %s" % blob


def _render_blank(**kw):
    """Render ``api_blank`` ALONE, in a bare Jinja env.

    The first draft of this guard grepped the macro source for the words it
    must be able to print. That guard survived a mutation that replaced the
    whole condition with ``{% if False %}``: the branch was dead and every
    string it guarded was still in the file. A guard that reads source cannot
    see a branch that never runs -- so this one runs it.
    """
    import jinja2
    tpl = io.open(os.path.join(ROOT, "app/templates/registry/versions.html"),
                  encoding="utf-8").read()
    at = tpl.index("{% macro api_blank(")
    end = tpl.index("endmacro %}", at) + len("endmacro %}")
    src = tpl[at:end]
    kw.setdefault("gap", None)
    kw.setdefault("measured", None)
    env = jinja2.Environment(autoescape=True)
    t = env.from_string(src + "{{ api_blank(scope, gap, measured) }}")
    return t.render(**kw)


def test_the_blank_cell_renders_the_verdict_and_keeps_the_schema_statement():
    """Both halves, in one rendered cell. Printing only the verdict would claim
    the object was schema-measured; printing only the old phrase is the defect
    the operator reported. The verdict reuses the endpoint rows' two badges --
    a third vocabulary for the same two states is how this page grew two
    authors for one sentence before."""
    swept = {"verdict": "absent", "devices": ["fortiweb17"],
             "measured_at": "2026-09-16T22:45:26", "scope": "8.0.5"}
    out = _render_blank(scope="8.0.5", measured=swept)
    assert ">absent<" in out, "the measured no is not printed: %s" % out
    assert "no field names on 8.0.5" in out, "the schema statement was dropped: %s" % out
    assert "not measured on" not in out, \
        "the cell still leads with silence for a build that answered: %s" % out
    assert "fortiweb17" in out, "the box that answered is not named"
    assert "fw-badge-danger" in out, "the verdict is not wearing the endpoint badge"

    served = _render_blank(scope="8.0.5",
                          measured={"verdict": "ok", "devices": ["fortiweb17"],
                                    "measured_at": "2026-09-16T22:45:26"})
    assert ">served<" in out.replace(">absent<", ">served<") and ">served<" in served, \
        "a served build with no schema does not report what it answered"
    # Scoped to the badge's OWN title. The first draft searched the whole
    # rendered cell and was answered by the neighbouring span, which also
    # happens to use the word -- so a mutation that gutted this sentence
    # SURVIVED. Tenth assert-by-substring in this repo to match a neighbour.
    badge = served[served.index('<span class="fw-badge fw-badge-success'):]
    badge = badge[:badge.index("</span>")]
    assert "not a schema" in badge, (
        "the served badge no longer says WHY a served URN still teaches no "
        "field names -- a cmdb GET returns what somebody configured: %s" % badge)

    quiet = _render_blank(scope="8.0.5", measured=None)
    assert "not measured on 8.0.5" in quiet, \
        "a key the sweep never recorded lost its honest phrase: %s" % quiet
    assert ">absent<" not in quiet and ">served<" not in quiet, \
        "a verdict is rendered for a build nobody asked: %s" % quiet
    assert quiet != out, "the two states render identically"


def test_both_field_delta_call_sites_pass_the_verdict_through():
    """A macro that can show it and a call site that never hands it over is the
    silent half of this defect, and it looks exactly like correct code."""
    tpl = io.open(os.path.join(ROOT, "app/templates/registry/versions.html"),
                  encoding="utf-8").read()
    calls = re.findall(r"api_blank\(delta\.(?:base|target), c\.[^)]*\)", tpl)
    assert len(calls) == 2, "expected the two field-delta blanks, found %r" % calls
    for c in calls:
        assert "c.measured" in c, "a field-delta blank drops the verdict: %s" % c


def test_the_export_is_not_quieter_than_the_page():
    """The copy that leaves the building. A blank verdict column reads as "no
    finding" in a spreadsheet, which is the misreading the page was changed to
    stop."""
    from app.views import _apiversions as av
    row = {"_bucket": "fields_unknown", "_base": "7.6", "_target": "8.0",
           "key": "widget", "known_on": "7.6", "count": 2,
           "measured": {"verdict": "absent", "scope": "8.0"}}
    assert av._api_cell(row, "base") == ("served", 2)
    assert av._api_cell(row, "target")[0] == "absent", \
        "the export stayed silent where the page prints a measured no"
    quiet = dict(row); quiet.pop("measured")
    assert av._api_cell(quiet, "target") == ("", ""), \
        "the export invented a verdict for a key the sweep never recorded"


def test_a_sweep_origin_gap_gets_the_verdict_too():
    """The wider half of the same defect, and the commoner one.

    The first cut attached the verdict to schema rows only. Five rows were left
    saying "not measured on 8.0.5" about endpoints the 8.0.5 sweep had answered
    ``ok`` for -- their field names are unknown because those tables are empty,
    not because nobody asked. Same false sentence, different bucket.
    """
    m = {
        "product": "fortiweb", "versions": {},
        "lines": {
            "7.6": {"objects": {}, "endpoints": {
                "widget": {"endpoint": "widget", "origin": "sweep",
                           "fields": ["a", "b"], "verdict": "ok"}}},
            "8.0": {"objects": {}, "endpoints": {
                "widget": {"endpoint": "widget", "origin": "sweep",
                           "fields": None, "verdict": "ok",
                           "devices": ["fortiweb17"]}}},
        },
    }
    d = am.diff("fortiweb", "7.6", "8.0", matrix=m)
    rows = [r for r in d["fields_unknown"] if r["key"] == "widget"]
    assert rows, "the sweep gap row vanished"
    row = rows[0]
    assert row["origin"] == "sweep"
    assert (row.get("measured") or {}).get("verdict") == "ok", \
        "a sweep-evidence gap still spells a measured build as an unasked one"
    assert not row.get("gap_reason"), \
        "the harvest's recorded reason was lent to a sweep row, which keeps no such record"


def test_the_harvest_reason_is_never_lent_to_a_sweep_row(tmp_path, monkeypatch):
    """The previous guard asserts an absence, and an absence is free when there
    is nothing to pick up: with no coverage file on disk it passed against code
    that lends the reason to every row. So this one PUTS a record where the
    lending code would find it, and still demands the sweep row refuse it.

    Why it matters: the harvest's sentences describe a harvest ("the table is
    empty on the reference appliance"). A sweep keeps no such log, and pinning
    one of those sentences to a sweep gap explains one absence with the cause
    of another -- confidently, and in the operator's own words."""
    d = tmp_path / "fortiweb" / "8.0"
    d.mkdir(parents=True)
    (d / fc.COVERAGE_FILENAME).write_text(json.dumps({
        "line": "8.0", "appliance": "fortiweb17", "harvested": True,
        "objects": {"widget": {"status": fc.STATUS_EMPTY_TABLE
                               if hasattr(fc, "STATUS_EMPTY_TABLE") else "empty_table",
                               "detail": "the table has no rows on this device"}},
    }))
    monkeypatch.setattr(am, "SCHEMA_ROOT", str(tmp_path))
    m = {
        "product": "fortiweb", "versions": {},
        "lines": {
            "7.6": {"objects": {}, "endpoints": {
                "widget": {"endpoint": "widget", "origin": "sweep",
                           "fields": ["a", "b"], "verdict": "ok"}}},
            "8.0": {"objects": {}, "endpoints": {
                "widget": {"endpoint": "widget", "origin": "sweep",
                           "fields": None, "verdict": "ok",
                           "devices": ["fortiweb17"]}}},
        },
    }
    d2 = am.diff("fortiweb", "7.6", "8.0", matrix=m)
    row = [r for r in d2["fields_unknown"] if r["key"] == "widget"][0]
    assert row["origin"] == "sweep"
    assert not row.get("gap_reason"), (
        "a sweep gap picked up the harvest's recorded reason: %r"
        % (row.get("gap_reason"),))
    assert (row.get("measured") or {}).get("verdict") == "ok", \
        "the sweep's own verdict went missing while the harvest reason was refused"
