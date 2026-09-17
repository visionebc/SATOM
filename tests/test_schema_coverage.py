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
    monkeypatch.setattr(am, "SCHEMA_ROOT", str(tmp_path))
    lines = am._schema_evidence("fortiweb")
    assert set(lines["8.0"]) == {"dns"}, \
        "a bookkeeping file was read as an object: %s" % sorted(lines["8.0"])


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
