"""Guards for reading and writing a process as an XML file.

WHAT MAKES THIS FILE NECESSARY
------------------------------
An import is the one door in this module where a *plausible* result is the
failure. A parser that drops a parameter, flattens a script, silently widens
the ADOM list or quietly truncates a label produces a process that opens in the
editor, renders green in the diagram and runs — and does something other than
what the file said. None of that raises, none of it 500s and none of it looks
wrong on the page. Every test below fixes one of those.

The other half is the gate. ``import_xml`` must be exactly as hard to talk into
a forbidden step as the editor's save is; the guards drive the real POST with
the real validator, never a stubbed one, because "the importer calls
validate_graph" is a claim about wiring and only the wiring can be asserted.
"""
from __future__ import annotations

import io
from xml.etree import ElementTree as ET

import pytest

from app.models import db
from app.models_process import Process, ProcessNode, ProcessRun
from app.services import process_kinds as pk
from app.services import process_xml as pxml
from app.views.process import _EXAMPLE_XML
from tests.conftest import admin_user_id, login, make_user


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def doc_xml(steps="", arrows="", key="p1", name="P1", adoms="<adom>fortiweb</adom>",
            enabled="yes", description="") -> bytes:
    return ("""<?xml version="1.0" encoding="UTF-8"?>
<satom-process key="%s" name="%s" enabled="%s">
  <description>%s</description>
  <adoms>%s</adoms>
  <steps>
    <step key="start" kind="start" label="Start" x="10" y="10"/>
%s
  </steps>
  <arrows>
%s
  </arrows>
</satom-process>
""" % (key, name, enabled, description, adoms, steps, arrows)).encode()


def post_xml(client, body: bytes, replace_key: str = "", filename="p.xml"):
    return client.post("/process/import", data={
        "xml_file": (io.BytesIO(body), filename),
        "replace_key": replace_key,
    }, content_type="multipart/form-data", follow_redirects=False)


@pytest.fixture()
def admin(app, client):
    login(client, admin_user_id(app), product="global")
    return client


def processes(app):
    with app.app_context():
        return {p.key: p for p in Process.query.all()}


# ---------------------------------------------------------------------------
# the format's one structural decision
# ---------------------------------------------------------------------------

def test_xml_flattens_attributes_which_is_why_parameters_are_elements():
    """The platform rule the whole shape of this format follows from.

    XML 1.0 §3.3.3 makes a parser replace every LITERAL newline and tab inside
    an ATTRIBUTE with a space before anyone sees it. Only an escaped &#10;
    survives — so in an attribute the READABLE way to write a console script is
    the lossy one, and it fails silently: the script arrives as a single line
    that is no longer the command its author wrote and no longer classifies the
    same way. Element text keeps the newline as typed.

    Pinned here so the next reader does not "simplify" parameters into
    attributes and discover this during a migration.
    """
    flattened = ET.fromstring('<s v="config system\nset x y"/>').get("v")
    assert flattened == "config system set x y"      # the readable way, lost

    escaped = ET.fromstring('<s v="config system&#10;set x y"/>').get("v")
    assert escaped == "config system\nset x y"       # only if every newline is escaped

    # And the element path, on the same content, does not lose it.
    kept = ET.fromstring("<s><param>config system\nset x y</param></s>")
    assert kept.find("param").text == "config system\nset x y"


def test_a_multi_line_script_survives_a_round_trip(app):
    """Export → import → export, byte-identical, script intact."""
    script = "config system global\n  set hostname fw1\nend"
    graph = {"nodes": [{"key": "start", "kind": "start", "label": "Start",
                        "params": {}, "x": 1, "y": 2},
                       {"key": "fix", "kind": "console_script", "label": "Repair",
                        "params": {"script": script, "stop_on_error": "1",
                                   "confirm_name": ""},
                        "x": 3, "y": 4}],
             "edges": [{"src": "start", "dst": "fix", "branch": "always"}]}
    first = pxml.to_xml(key="p1", name="P1", description="d",
                        products=["fortiweb"], enabled=True, graph=graph)
    doc, errs = pxml.read_xml(first.encode())
    assert errs == []
    assert doc.graph["nodes"][1]["params"]["script"] == script
    assert doc.key == "p1" and doc.products == ["fortiweb"] and doc.enabled is True
    assert [(n["x"], n["y"]) for n in doc.graph["nodes"]] == [(1, 2), (3, 4)]

    # Positions are not decoration: a plan whose steps all land on (0, 0) opens
    # as a pile of boxes stacked on one another. And a DISABLED process must
    # come back disabled — an exporter hard-coding "yes" is invisible to a
    # comparison of two exports, and re-importing would arm a plan its owner
    # had switched off.
    off = pxml.to_xml(key="p1", name="P1", products=["fortiweb"], enabled=False,
                      graph=graph)
    assert pxml.read_xml(off.encode())[0].enabled is False
    again = pxml.to_xml(key=doc.key, name=doc.name, description=doc.description,
                        products=doc.products, enabled=doc.enabled, graph=doc.graph)
    assert again == first


def test_export_keeps_a_parameter_this_build_does_not_know(app):
    """An exporter that drops what it cannot name edits every plan it touches."""
    graph = {"nodes": [{"key": "start", "kind": "start", "label": "S",
                        "params": {"from_a_newer_build": "keep me"},
                        "x": 0, "y": 0}], "edges": []}
    body = pxml.to_xml(key="p1", name="P1", graph=graph)
    assert "from_a_newer_build" in body
    doc, errs = pxml.read_xml(body.encode())
    assert errs == []
    assert doc.graph["nodes"][0]["params"]["from_a_newer_build"] == "keep me"


def test_a_hand_indented_script_means_the_same_as_a_flat_one():
    """Somebody will type the file by hand, indented to match its surroundings.

    The common indent is removed and the RELATIVE indent kept: in a CLI script
    the difference between two lines can be the author's.
    """
    body = doc_xml(steps="""    <step key="fix" kind="console_script" label="Fix" x="0" y="0">
      <param name="script">
        config system global
          set hostname fw1
        end
      </param>
    </step>""")
    doc, errs = pxml.read_xml(body)
    assert errs == []
    assert (doc.graph["nodes"][1]["params"]["script"]
            == "config system global\n  set hostname fw1\nend")


# ---------------------------------------------------------------------------
# refusals — what a file may not talk this module into
# ---------------------------------------------------------------------------

def test_a_doctype_is_refused_without_being_expanded():
    """Entity expansion is how a 1 KB file becomes a gigabyte of memory.

    ``xml.etree`` does not fetch external entities but it DOES expand internal
    ones, so the refusal is on the raw bytes and happens before any parse.
    """
    bomb = (b'<?xml version="1.0"?>\n<!DOCTYPE lolz [\n'
            b'<!ENTITY a "aaaaaaaaaa">\n<!ENTITY b "&a;&a;&a;&a;&a;">\n'
            b'<!ENTITY c "&b;&b;&b;&b;&b;">\n]>\n'
            b'<satom-process key="p1" name="P"><steps/>&c;</satom-process>')
    doc, errs = pxml.read_xml(bomb)
    assert doc is None
    assert len(errs) == 1 and "DOCTYPE" in errs[0]


def test_a_drawio_file_is_named_and_never_half_read():
    doc, errs = pxml.read_xml(
        b'<mxfile host="app.diagrams.net"><diagram><mxGraphModel>'
        b'<root><mxCell id="2" value="Check the VIP"/></root>'
        b'</mxGraphModel></diagram></mxfile>')
    assert doc is None
    assert "draw.io" in errs[0]
    # The point of the refusal, stated: a shape has no kind and no parameters.
    assert "parameters" in errs[0]


def test_a_bpmn_file_is_named_through_its_namespace():
    doc, errs = pxml.read_xml(
        b'<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL">'
        b'<bpmn:process id="p"/></bpmn:definitions>')
    assert doc is None
    assert "BPMN" in errs[0]


def test_a_file_larger_than_the_cap_is_refused_before_parsing():
    doc, errs = pxml.read_xml(b"<satom-process>" + b"x" * pxml.MAX_XML)
    assert doc is None and "refused above" in errs[0]


def test_a_misspelt_attribute_is_reported_and_not_ignored():
    """``brach="fail"`` read as ``always`` is a plan that takes the wrong arrow
    on the one day it runs — and it would render as a correct diagram."""
    body = doc_xml(arrows='    <arrow from="start" to="start" brach="fail"/>')
    doc, errs = pxml.read_xml(body)
    assert any("brach" in e for e in errs)


def test_a_branch_that_is_not_an_outcome_is_refused():
    body = doc_xml(arrows='    <arrow from="start" to="start" branch="maybe"/>')
    _, errs = pxml.read_xml(body)
    assert any("maybe" in e and "outcome" in e for e in errs)


def test_enabled_is_never_guessed():
    _, errs = pxml.read_xml(doc_xml(enabled="maybe"))
    assert any("must be yes or no" in e for e in errs)


def test_the_same_parameter_twice_is_refused():
    body = doc_xml(steps="""    <step key="u" kind="http_check" label="U" x="0" y="0">
      <param name="url">https://a/</param>
      <param name="url">https://b/</param>
    </step>""")
    _, errs = pxml.read_xml(body)
    assert any("sets 'url' twice" in e for e in errs)


def test_a_label_over_the_column_is_refused_rather_than_cut():
    body = doc_xml(steps='    <step key="u" kind="end" label="%s" x="0" y="0"/>'
                         % ("x" * 161))
    _, errs = pxml.read_xml(body)
    assert any("161 characters" in e for e in errs)


def test_an_unknown_section_is_reported_rather_than_dropped():
    body = doc_xml().replace(b"<adoms>", b"<schedule>nightly</schedule><adoms>")
    _, errs = pxml.read_xml(body)
    assert any("schedule" in e for e in errs)


def test_a_file_with_no_steps_section_says_so(app):
    """``validate_graph`` would also refuse this, with two messages about a
    missing Start step. Naming the missing SECTION is the difference between an
    operator fixing a typo and one rebuilding a diagram they already have.

    The section is REMOVED rather than misspelt, and the message asserted
    whole. A misspelt one raises "not part of a process file", whose text lists
    ``<steps>`` among the sections a file holds — so a substring assertion here
    passed with this very guard deleted.
    """
    body = doc_xml()
    body = body[:body.index(b"<steps>")] + body[body.index(b"</steps>") + 8:]
    assert b"<steps>" not in body
    _, errs = pxml.read_xml(body)
    assert "The file has no <steps> section." in errs


def test_a_process_name_longer_than_its_column_is_refused(app, admin):
    """The name column is 160. Postgres REFUSES a longer value and SQLite
    accepts it, so without this the test bed and production would disagree
    about whether the import works — and production's answer would be a 500 on
    the page that had just invited the operator to upload the file."""
    resp = post_xml(admin, doc_xml(name="n" * 161))
    assert resp.status_code == 200
    assert b"the limit is 160" in resp.data
    assert processes(app) == {}


def test_a_process_key_the_form_would_refuse_is_refused_here(app, admin):
    """validate_graph checks STEP keys; nothing in it looks at the process
    key. Without this the import would be the one door that writes a key the
    New-process form rejects — and the key is what audit rows and run history
    reference forever."""
    resp = post_xml(admin, doc_xml(key="Bad Key!"))
    assert resp.status_code == 200
    assert b"not a usable process key" in resp.data
    assert processes(app) == {}


def test_no_adom_is_a_draft_and_never_everywhere():
    doc, errs = pxml.read_xml(doc_xml(adoms=""))
    assert errs == []
    assert doc.products == []


# ---------------------------------------------------------------------------
# the gate — the importer is not a second door
# ---------------------------------------------------------------------------

FORBIDDEN = doc_xml(
    steps="""    <step key="wipe" kind="console_script" label="Wipe" x="0" y="0">
      <param name="script">execute factoryreset</param>
      <param name="confirm_name">fortiweb13</param>
    </step>""",
    arrows='    <arrow from="start" to="wipe" branch="always"/>')


def test_a_forbidden_console_line_cannot_be_imported(app, admin):
    """The headline. A file looks like data, which is what would make it the
    most attractive way past the gates the editor cannot be talked out of."""
    resp = post_xml(admin, FORBIDDEN)
    assert resp.status_code == 200            # re-rendered form, not a redirect
    assert b"factoryreset" in resp.data
    assert processes(app) == {}               # and nothing at all was written


def test_the_refusal_comes_from_the_real_validator(app, admin, monkeypatch):
    """Wiring, asserted as wiring.

    Neutering ``validate_graph`` must make this import succeed — if it does not,
    the view is refusing for some private reason of its own and the two doors
    have already drifted.
    """
    monkeypatch.setattr(pk, "validate_graph", lambda graph: [])
    resp = post_xml(admin, FORBIDDEN)
    assert resp.status_code == 302
    assert "wipe" in {n.node_key for n in processes(app)["p1"].nodes}


def test_an_adom_this_installation_does_not_have_is_refused(app, admin):
    """Refused, not dropped: moving a process between installations is the case
    this feature exists for, so a missing ADOM is the LIKELY error — and
    dropping it would import the plan as a draft that looks published."""
    resp = post_xml(admin, doc_xml(adoms="<adom>fortiwob</adom>"))
    assert resp.status_code == 200
    assert b"fortiwob" in resp.data
    assert processes(app) == {}


def test_nothing_is_written_when_any_single_line_is_wrong(app, admin):
    """A file with one bad arrow and six good steps writes NOTHING."""
    body = doc_xml(
        steps="""    <step key="ok" kind="end" label="Done" x="0" y="0"/>""",
        arrows='    <arrow from="start" to="nowhere" branch="always"/>')
    assert post_xml(admin, body).status_code == 200
    assert processes(app) == {}


# ---------------------------------------------------------------------------
# creating, replacing, and what a replacement must not touch
# ---------------------------------------------------------------------------

GOOD = doc_xml(
    steps="""    <step key="ok" kind="end" label="Done" x="0" y="0">
      <param name="note">nothing to do</param>
    </step>""",
    arrows='    <arrow from="start" to="ok" branch="always"/>')


def test_a_good_file_creates_a_runnable_process(app, admin):
    assert post_xml(admin, GOOD).status_code == 302
    with app.app_context():
        proc = Process.query.filter_by(key="p1").one()
        assert proc.products == ["fortiweb"] and proc.enabled is True
        assert pk.validate_graph(proc.graph()) == []
        assert proc.graph()["nodes"][1]["params"]["note"] == "nothing to do"
        # The arrows too. A plan that kept its steps and lost its edges opens,
        # validates (edges are not required) and runs — it just stops at Start
        # and reports a clean walk of one step.
        assert proc.graph()["edges"] == [
            {"src": "start", "dst": "ok", "branch": "always"}]


def test_an_existing_key_is_refused_until_it_is_typed(app, admin):
    assert post_xml(admin, GOOD).status_code == 302
    changed = GOOD.replace(b'name="P1"', b'name="P1 rewritten"')

    resp = post_xml(admin, changed)               # no confirmation
    assert resp.status_code == 200 and b"already exists" in resp.data
    with app.app_context():
        assert Process.query.filter_by(key="p1").one().name == "P1"

    resp = post_xml(admin, changed, replace_key="wrong")
    assert resp.status_code == 200
    with app.app_context():
        assert Process.query.filter_by(key="p1").one().name == "P1"

    assert post_xml(admin, changed, replace_key="p1").status_code == 302
    with app.app_context():
        assert Process.query.filter_by(key="p1").one().name == "P1 rewritten"


def test_a_replacement_keeps_the_history_and_the_graph_that_history_walked(app, admin):
    """A run carries its own copy of the diagram. If a replacement rewrote it,
    a report saying "checked the standby" would start rendering as whatever
    that step was later changed into."""
    assert post_xml(admin, GOOD).status_code == 302
    with app.app_context():
        proc = Process.query.filter_by(key="p1").one()
        run = ProcessRun(process_id=proc.id, process_key="p1", process_name="P1",
                         graph=proc.graph(), status="done", verdict="ok")
        db.session.add(run)
        db.session.commit()
        rid, before = run.id, run.graph

    replaced = GOOD.replace(b'label="Done"', b'label="Something else"')
    assert post_xml(admin, replaced, replace_key="p1").status_code == 302
    with app.app_context():
        assert db.session.get(ProcessRun, rid).graph == before
        labels = {n.node_key: n.label for n in
                  ProcessNode.query.filter_by(
                      process_id=Process.query.filter_by(key="p1").one().id)}
        assert labels["ok"] == "Something else"


def test_a_process_this_console_cannot_see_is_not_replaceable_from_here(app, client):
    """Everywhere else in this module such a process does not exist; the import
    must not be the one door that edits a record the console cannot list."""
    login(client, admin_user_id(app), product="global")
    assert post_xml(client, GOOD).status_code == 302     # p1 is fortiweb-only

    login(client, admin_user_id(app), product="fortiadc")
    resp = post_xml(client, GOOD.replace(b'name="P1"', b'name="Hijacked"'),
                    replace_key="p1")
    assert resp.status_code == 200 and b"Global console" in resp.data
    with app.app_context():
        assert Process.query.filter_by(key="p1").one().name == "P1"


# ---------------------------------------------------------------------------
# the page, the example on it, and who may reach it
# ---------------------------------------------------------------------------

def test_the_example_printed_on_the_page_actually_imports(app, admin):
    """A documented example that does not validate is a lie told to every
    operator who copies it."""
    doc, errs = pxml.read_xml(_EXAMPLE_XML.encode())
    assert errs == []
    assert pk.validate_graph(doc.graph) == []
    assert post_xml(admin, _EXAMPLE_XML.encode()).status_code == 302


def test_export_round_trips_a_process_through_the_two_routes(app, admin):
    assert post_xml(admin, _EXAMPLE_XML.encode()).status_code == 302
    with app.app_context():
        pid = Process.query.filter_by(key="dr-failover-check").one().id
    resp = admin.get("/process/%d/export.xml" % pid)
    assert resp.status_code == 200
    assert "attachment" in resp.headers["Content-Disposition"]
    assert "process-dr-failover-check.xml" in resp.headers["Content-Disposition"]
    doc, errs = pxml.read_xml(resp.data)
    assert errs == [] and doc.key == "dr-failover-check"
    assert [n["key"] for n in doc.graph["nodes"]] == [
        "start", "vip", "health", "escalate", "ok"]


def test_importing_needs_config_write_and_exporting_only_view(app, client):
    uid = make_user(app, username="ro", role="readonly")
    login(client, uid, product="global")
    assert client.get("/process/import").status_code == 403
    assert post_xml(client, GOOD).status_code == 403
    assert processes(app) == {}

    login(client, admin_user_id(app), product="global")
    assert post_xml(client, GOOD).status_code == 302
    with app.app_context():
        pid = Process.query.filter_by(key="p1").one().id
    login(client, uid, product="global")
    assert client.get("/process/%d/export.xml" % pid).status_code == 200
