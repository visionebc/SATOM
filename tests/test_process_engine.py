"""Guards for the Process engine, its node catalogue and its ADOM scoping.

WHAT THESE TESTS ARE FOR
------------------------
Every one of them fixes a rule that, if it broke, would produce a report that
reads EXACTLY LIKE A CORRECT ONE. That is the whole failure mode of this
module: a walk that stops early and prints green underneath, a blind spot
rendered as health, a rehearsal recorded as a repair. None of those raise, none
of them 500, and none of them look wrong on the page.

The executors are exercised through the engine with the underlying services
monkeypatched, never by calling an executor directly: the thing that has to
hold is the SEQUENCE and the VERDICT, and a unit test of one adapter cannot see
either.
"""
from __future__ import annotations

import io

import pytest

from app.models import db
from app.models_process import (FAILED, OK, PARTIAL, Process, ProcessEdge,
                                ProcessNode, ProcessRun, WAITING)
from app.services import process_engine as engine
from app.services import process_kinds as pk
from tests.conftest import admin_user_id, login


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def make(app, key="p1", nodes=(), edges=(), products=("fortiweb",)):
    """Build a process from ``(key, kind, params)`` / ``(src, dst, branch)``."""
    with app.app_context():
        proc = Process(key=key, name=key.upper(), products=list(products))
        db.session.add(proc)
        db.session.flush()
        for i, (nkey, kind, params) in enumerate(nodes):
            db.session.add(ProcessNode(process_id=proc.id, node_key=nkey,
                                       kind=kind, label=nkey, params=params or {},
                                       pos_x=40, pos_y=40 + i * 70))
        for src, dst, branch in edges:
            db.session.add(ProcessEdge(process_id=proc.id, src_key=src,
                                       dst_key=dst, branch=branch))
        db.session.commit()
        return proc.id


def walk(app, pid, **kw):
    with app.app_context():
        proc = db.session.get(Process, pid)
        run = engine.start_run(proc, **kw)
        return run.id


def outcomes(app, rid):
    with app.app_context():
        run = db.session.get(ProcessRun, rid)
        return ({s.node_key: s.status for s in run.steps}, run.verdict, run.status)


def fixed(status, detail="x"):
    """A node executor that always answers the same thing."""
    return lambda node, ctx: pk.StepResult(status, detail)


def stub(monkeypatch, kind, status):
    monkeypatch.setitem(pk._RUNNERS, kind, fixed(status))


# ---------------------------------------------------------------------------
# the four engine rules
# ---------------------------------------------------------------------------

def test_a_stopped_path_never_turns_green_underneath(app, monkeypatch):
    """The rule the whole module exists for.

    A step fails, the plan has no arrow for that outcome, and the steps below it
    must be recorded ``skipped`` — never ``pass``, never absent. A green step
    under a red one is how a report gets read backwards.
    """
    stub(monkeypatch, "http_check", "fail")
    stub(monkeypatch, "tcp_check", "pass")
    pid = make(app, nodes=[("start", "start", {}),
                           ("gate", "http_check", {"url": "https://x/"}),
                           ("after", "tcp_check", {}),
                           ("last", "end", {})],
               edges=[("start", "gate", "always"), ("gate", "after", "pass"),
                      ("after", "last", "always")])
    got, verdict, _ = outcomes(app, walk(app, pid))
    assert got["gate"] == "fail"
    assert got["after"] == "skipped", "the step below a stopped path must not run"
    assert got["last"] == "skipped"
    assert verdict == FAILED


def test_a_branch_not_taken_is_not_skipped(app, monkeypatch):
    """The counterweight to the rule above.

    An ``escalate`` arm a healthy run never enters is normal control flow.
    Recording it ``skipped`` would print a blind spot on every good day until
    the word stopped meaning anything — and it would drag the verdict with it.
    """
    stub(monkeypatch, "http_check", "pass")
    stub(monkeypatch, "tcp_check", "fail")
    pid = make(app, nodes=[("start", "start", {}),
                           ("check", "http_check", {"url": "https://x/"}),
                           ("good", "end", {}),
                           ("escalate", "tcp_check", {})],
               edges=[("start", "check", "always"), ("check", "good", "pass"),
                      ("check", "escalate", "fail")])
    got, verdict, _ = outcomes(app, walk(app, pid))
    assert got["check"] == "pass" and got["good"] == "pass"
    assert "escalate" not in got, "an untaken branch is control flow, not a gap"
    assert verdict == OK


def test_unknown_is_not_health_and_not_a_failure(app, monkeypatch):
    stub(monkeypatch, "http_check", "unknown")
    pid = make(app, nodes=[("start", "start", {}),
                           ("look", "http_check", {"url": "https://x/"}),
                           ("done", "end", {})],
               edges=[("start", "look", "always"), ("look", "done", "always")])
    rid = walk(app, pid)
    got, verdict, _ = outcomes(app, rid)
    assert got["look"] == "unknown"
    assert verdict == PARTIAL, "a blind spot is neither a pass nor a fail"
    with app.app_context():
        summary = db.session.get(ProcessRun, rid).summary
    assert "partial walk" in summary and "clean bill of health" in summary


def test_an_executor_that_raises_is_unknown_not_fail(app, monkeypatch):
    """My defect is not the appliance's outage.

    Rendering a crash as ``fail`` sends somebody to repair a component that
    answered. The cost — a bug hiding as a blind spot — is why this module is
    also walked against the live system.
    """
    def boom(node, ctx):
        raise RuntimeError("kaboom")
    monkeypatch.setitem(pk._RUNNERS, "http_check", boom)
    pid = make(app, nodes=[("start", "start", {}),
                           ("look", "http_check", {"url": "https://x/"})],
               edges=[("start", "look", "always")])
    got, verdict, _ = outcomes(app, walk(app, pid))
    assert got["look"] == "unknown"
    assert verdict == PARTIAL


def test_an_explicit_outcome_arrow_beats_always(app, monkeypatch):
    """Otherwise a recovery branch is unreachable in exactly the graphs that
    need it: a catch-all ``always`` would swallow the failure."""
    stub(monkeypatch, "http_check", "fail")
    stub(monkeypatch, "tcp_check", "pass")
    stub(monkeypatch, "dns_check", "pass")
    pid = make(app, nodes=[("start", "start", {}),
                           ("check", "http_check", {"url": "https://x/"}),
                           ("carry-on", "tcp_check", {}),
                           ("repair", "dns_check", {})],
               edges=[("start", "check", "always"),
                      ("check", "carry-on", "always"),
                      ("check", "repair", "fail")])
    got, _, _ = outcomes(app, walk(app, pid))
    assert got.get("repair") == "pass", "the fail arrow must win over always"
    assert "carry-on" not in got


def test_a_loop_is_bounded_and_the_abort_says_so(app, monkeypatch):
    """Retry cycles are legitimate, so the graph is not required to be acyclic.
    An infinite one must abort with its reason rather than report a verdict
    about a walk that never finished."""
    stub(monkeypatch, "http_check", "pass")
    pid = make(app, nodes=[("start", "start", {}),
                           ("spin", "http_check", {"url": "https://x/"})],
               edges=[("start", "spin", "always"), ("spin", "spin", "always")])
    rid = walk(app, pid)
    with app.app_context():
        run = db.session.get(ProcessRun, rid)
        assert run.status == "aborted"
        assert "loops" in run.summary
        assert len(run.steps) <= engine.MAX_STEPS + 2


# ---------------------------------------------------------------------------
# manual gate
# ---------------------------------------------------------------------------

def test_a_manual_gate_parks_the_run_and_resumes_through_the_arrows(app, monkeypatch):
    """The whole position of a paused run is one node key in one column, so it
    survives a restart and can be answered hours later."""
    stub(monkeypatch, "tcp_check", "pass")
    stub(monkeypatch, "dns_check", "pass")
    pid = make(app, nodes=[("start", "start", {}),
                           ("ask", "manual_gate", {"prompt": "Cable in?"}),
                           ("yes", "tcp_check", {}),
                           ("no", "dns_check", {})],
               edges=[("start", "ask", "always"), ("ask", "yes", "pass"),
                      ("ask", "no", "fail")])
    rid = walk(app, pid)
    with app.app_context():
        run = db.session.get(ProcessRun, rid)
        assert run.status == WAITING and run.waiting_node == "ask"
        engine.resume(run, "pass")
    got, verdict, status = outcomes(app, rid)
    assert got["ask"] == "pass" and got["yes"] == "pass"
    assert "no" not in got
    assert status == "done" and verdict == OK


def test_a_decision_can_read_a_step_from_before_the_pause(app, monkeypatch):
    """A Decision addresses an earlier step BY KEY. After a gate the walk is a
    fresh call, so the outcomes of the first half have to be reloaded from the
    rows — otherwise the reference resolves to nothing and the step reports
    'did not run on this path' about a step that ran."""
    stub(monkeypatch, "http_check", "fail")
    pid = make(app, nodes=[("start", "start", {}),
                           ("probe", "http_check", {"url": "https://x/"}),
                           ("ask", "manual_gate", {"prompt": "?"}),
                           ("recall", "decision",
                            {"when_node": "probe", "when_status": "fail"}),
                           ("done", "end", {})],
               edges=[("start", "probe", "always"), ("probe", "ask", "fail"),
                      ("ask", "recall", "pass"), ("recall", "done", "pass")])
    rid = walk(app, pid)
    with app.app_context():
        engine.resume(db.session.get(ProcessRun, rid), "pass")
    got, _, _ = outcomes(app, rid)
    assert got["recall"] == "pass", "the pre-pause outcome must still be visible"
    assert got["done"] == "pass"


def test_a_decision_on_a_step_that_never_ran_is_unknown(app, monkeypatch):
    """Not ``fail``: a question that was never asked has no answer, and calling
    it a failure invents one."""
    stub(monkeypatch, "http_check", "pass")
    pid = make(app, nodes=[("start", "start", {}),
                           ("check", "http_check", {"url": "https://x/"}),
                           ("d", "decision",
                            {"when_node": "never", "when_status": "pass"})],
               edges=[("start", "check", "always"), ("check", "d", "always")])
    got, verdict, _ = outcomes(app, walk(app, pid))
    assert got["d"] == "unknown"
    assert verdict == PARTIAL


def test_a_stopped_path_and_an_untaken_branch_in_the_same_walk(app, monkeypatch):
    """The two skipped rules have to hold AT ONCE, and only a graph with both
    shapes can see it.

    ``test_a_branch_not_taken_is_not_skipped`` could not: with no stop point
    anywhere, ``_mark_skipped`` returns before it decides anything, so widening
    the rule to "everything the walk did not reach" was invisible to it. Here
    ``b`` stops the walk AND ``escalate`` was deliberately not entered, so the
    two must be recorded differently.
    """
    stub(monkeypatch, "http_check", "pass")
    stub(monkeypatch, "tcp_check", "fail")
    stub(monkeypatch, "dns_check", "pass")
    pid = make(app, nodes=[("start", "start", {}),
                           ("a", "http_check", {"url": "https://x/"}),
                           ("b", "tcp_check", {"host": "h", "port": "1"}),
                           ("c", "dns_check", {"entry": "x"}),
                           ("escalate", "dns_check", {"entry": "y"})],
               edges=[("start", "a", "always"),
                      ("a", "b", "pass"),
                      ("a", "escalate", "fail"),
                      ("b", "c", "pass")])
    got, verdict, _ = outcomes(app, walk(app, pid))
    assert got["b"] == "fail"
    assert got["c"] == "skipped", "below a stopped path"
    assert "escalate" not in got, "a branch the plan did not take is not a gap"
    assert verdict == FAILED


def test_a_gate_answered_fail_follows_the_fail_arrow(app, monkeypatch):
    """The pass case alone cannot see a resume that ignores the answer: a
    hardcoded 'pass' produces exactly the same walk."""
    stub(monkeypatch, "tcp_check", "pass")
    stub(monkeypatch, "dns_check", "pass")
    pid = make(app, nodes=[("start", "start", {}),
                           ("ask", "manual_gate", {"prompt": "Cable in?"}),
                           ("yes", "tcp_check", {"host": "h", "port": "1"}),
                           ("no", "dns_check", {"entry": "x"})],
               edges=[("start", "ask", "always"), ("ask", "yes", "pass"),
                      ("ask", "no", "fail")])
    rid = walk(app, pid)
    with app.app_context():
        engine.resume(db.session.get(ProcessRun, rid), "fail", note="loose")
    got, _, status = outcomes(app, rid)
    assert got["ask"] == "fail"
    assert got["no"] == "pass", "the fail arrow must be the one followed"
    assert "yes" not in got
    assert status == "done"
    with app.app_context():
        step = [s for s in db.session.get(ProcessRun, rid).steps
                if s.node_key == "ask"][0]
        assert "loose" in step.detail, "the operator's note belongs on the step"


def test_a_gate_answered_with_no_route_stops_the_path_and_skips_below(
        app, monkeypatch):
    """The resume path needs the same "green never appears under red" rule as
    the first half of the walk, and it is a SEPARATE line of code.

    An operator answering *failed* at a gate whose plan only drew a *passed*
    arrow is the shape this catches: the walk has nowhere to go, and everything
    the plan would have reached must be recorded ``skipped`` — not left absent,
    which reads as "the plan finished".
    """
    stub(monkeypatch, "tcp_check", "pass")
    stub(monkeypatch, "dns_check", "pass")
    pid = make(app, nodes=[("start", "start", {}),
                           ("ask", "manual_gate", {"prompt": "Cable in?"}),
                           ("yes", "tcp_check", {"host": "h", "port": "1"}),
                           ("after", "dns_check", {"entry": "x"})],
               edges=[("start", "ask", "always"), ("ask", "yes", "pass"),
                      ("yes", "after", "always")])
    rid = walk(app, pid)
    with app.app_context():
        engine.resume(db.session.get(ProcessRun, rid), "fail")
    got, verdict, status = outcomes(app, rid)
    assert got["ask"] == "fail"
    assert got["yes"] == "skipped", "not reached, and not silently absent"
    assert got["after"] == "skipped"
    assert status == "done" and verdict == FAILED


# ---------------------------------------------------------------------------
# arming
# ---------------------------------------------------------------------------

def test_an_unarmed_run_rehearses_every_write_and_the_row_says_so(app, monkeypatch):
    """A dry run recorded like a real one is a false record of a repair."""
    seen = {}

    class Spec:
        key = "backup"; label = "Backup"; danger = False
        needs_targets = False; products = ("fortiweb",)
        requires_change_request = False; summary = ""

    monkeypatch.setattr("app.services.scheduled_actions.get_spec",
                        lambda k: Spec if k == "backup" else None)

    def fake_run(spec, appliance, params, dry_run=False):
        seen["dry"] = dry_run
        return {"ok": True, "summary": "did the thing", "log": ""}
    monkeypatch.setattr("app.services.scheduled_actions.run_action", fake_run)

    pid = make(app, nodes=[("start", "start", {}),
                           ("act", "action", {"action_key": "backup"})],
               edges=[("start", "act", "always")])
    rid = walk(app, pid, armed=False)
    assert seen["dry"] is True
    with app.app_context():
        step = [s for s in db.session.get(ProcessRun, rid).steps
                if s.node_key == "act"][0]
        assert step.dry_run is True
        assert "rehearsed" in step.detail

    rid2 = walk(app, pid, armed=True)
    assert seen["dry"] is False
    with app.app_context():
        step = [s for s in db.session.get(ProcessRun, rid2).steps
                if s.node_key == "act"][0]
        assert step.dry_run is False
        assert "rehearsed" not in step.detail


def test_an_action_that_needs_a_device_without_one_is_unknown(app, monkeypatch):
    class Spec:
        key = "reboot"; label = "Reboot"; danger = True
        needs_targets = True; products = ("fortiweb",)
        requires_change_request = False; summary = ""
    monkeypatch.setattr("app.services.scheduled_actions.get_spec",
                        lambda k: Spec if k == "reboot" else None)
    pid = make(app, nodes=[("start", "start", {}),
                           ("act", "action", {"action_key": "reboot"})],
               edges=[("start", "act", "always")])
    got, verdict, _ = outcomes(app, walk(app, pid))
    assert got["act"] == "unknown"
    assert verdict == PARTIAL


# ---------------------------------------------------------------------------
# save-time validation
# ---------------------------------------------------------------------------

def test_a_mutating_ssh_command_is_refused_when_the_step_is_saved():
    """Caught at SAVE time, not at run time. A plan that only reveals it cannot
    run halfway through a recovery is worse than one that refuses to be
    written."""
    errs = pk.validate_graph({
        "nodes": [{"key": "start", "kind": "start", "params": {}},
                  {"key": "cmd", "kind": "ssh_check",
                   "params": {"command": "config system global"}}],
        "edges": [{"src": "start", "dst": "cmd", "branch": "always"}]})
    assert any("cmd" in e for e in errs), errs


def test_a_read_only_ssh_command_saves():
    errs = pk.validate_graph({
        "nodes": [{"key": "start", "kind": "start", "params": {}},
                  {"key": "cmd", "kind": "ssh_check",
                   "params": {"command": "get system status"}}],
        "edges": [{"src": "start", "dst": "cmd", "branch": "always"}]})
    assert errs == [], errs


def test_two_arrows_for_the_same_outcome_are_refused():
    """This is what keeps a run a single cursor — and therefore what makes a
    manual gate resumable from one database column."""
    errs = pk.validate_graph({
        "nodes": [{"key": "start", "kind": "start", "params": {}},
                  {"key": "a", "kind": "end", "params": {}},
                  {"key": "b", "kind": "end", "params": {}}],
        "edges": [{"src": "start", "dst": "a", "branch": "always"},
                  {"src": "start", "dst": "b", "branch": "always"}]})
    assert any("one arrow per outcome" in e for e in errs), errs


def test_two_arrows_for_different_outcomes_are_fine():
    errs = pk.validate_graph({
        "nodes": [{"key": "start", "kind": "start", "params": {}},
                  {"key": "c", "kind": "tcp_check",
                   "params": {"host": "h", "port": "443"}},
                  {"key": "a", "kind": "end", "params": {}},
                  {"key": "b", "kind": "end", "params": {}}],
        "edges": [{"src": "start", "dst": "c", "branch": "always"},
                  {"src": "c", "dst": "a", "branch": "pass"},
                  {"src": "c", "dst": "b", "branch": "fail"}]})
    assert errs == [], errs


def test_exactly_one_start_step():
    two = pk.validate_graph({
        "nodes": [{"key": "s1", "kind": "start", "params": {}},
                  {"key": "s2", "kind": "start", "params": {}}], "edges": []})
    none = pk.validate_graph({
        "nodes": [{"key": "e", "kind": "end", "params": {}}], "edges": []})
    assert any("exactly one Start" in e for e in two)
    assert any("exactly one Start" in e for e in none)


def test_every_problem_is_reported_at_once():
    """Returning the first one would make fixing a diagram whack-a-mole."""
    errs = pk.validate_graph({
        "nodes": [{"key": "start", "kind": "start", "params": {}},
                  {"key": "BAD KEY", "kind": "nope", "params": {}}],
        "edges": [{"src": "start", "dst": "ghost", "branch": "always"}]})
    assert len(errs) >= 3, errs


def test_an_arrow_to_a_step_that_does_not_exist_is_refused():
    errs = pk.validate_graph({
        "nodes": [{"key": "start", "kind": "start", "params": {}}],
        "edges": [{"src": "start", "dst": "ghost", "branch": "always"}]})
    assert any("ghost" in e for e in errs), errs


# ---------------------------------------------------------------------------
# ADOM scoping
# ---------------------------------------------------------------------------

def test_a_process_is_visible_only_in_the_adoms_it_names(app):
    make(app, key="web-only", products=("fortiweb",),
         nodes=[("start", "start", {})])
    make(app, key="both", products=("fortiweb", "fortiadc"),
         nodes=[("start", "start", {})])
    make(app, key="draft", products=(), nodes=[("start", "start", {})])
    with app.app_context():
        assert {p.key for p in engine.visible_processes("fortiweb")} == {"web-only", "both"}
        assert {p.key for p in engine.visible_processes("fortiadc")} == {"both"}
        assert {p.key for p in engine.visible_processes("fortianalyzer")} == set()
        # Global authors them, so Global sees the draft too. An empty product
        # list read as "everywhere" would publish drafts into five consoles.
        assert {p.key for p in engine.visible_processes("global")} == \
            {"web-only", "both", "draft"}


def test_a_process_from_another_adom_is_404_not_403(app, client):
    """A record this console cannot see anywhere does not exist here. '403'
    would describe a permission problem that is not the one they have."""
    pid = make(app, key="adc-only", products=("fortiadc",),
               nodes=[("start", "start", {})])
    login(client, admin_user_id(app), product="fortiweb")
    assert client.get("/process/%d" % pid).status_code == 404
    login(client, admin_user_id(app), product="fortiadc")
    assert client.get("/process/%d" % pid).status_code == 200


def test_the_process_page_is_reachable_in_every_adom(app, client):
    for product in ("global", "fortiweb", "fortiadc", "fortianalyzer",
                    "fortiauthenticator"):
        login(client, admin_user_id(app), product=product)
        r = client.get("/process/")
        assert r.status_code == 200, "%s bounced: %s" % (product, r.status_code)


def test_the_page_carries_no_dark_theme_literals(app, client):
    """safeguards §9m — this product is light, and a dark pastel lands near
    1.4:1 here: a badge that states a verdict and cannot be read."""
    login(client, admin_user_id(app), product="fortiweb")
    body = client.get("/process/").get_data(as_text=True)
    for bad in ("#080d1a", "#6ee7b7", "#fcd34d", "#fca5a5", "#93c5fd",
                "#c4b5fd", "backdrop-filter"):
        assert bad not in body, bad


# ---------------------------------------------------------------------------
# saving through the blueprint
# ---------------------------------------------------------------------------

def test_an_invalid_diagram_is_refused_whole(app, client):
    """Saving the valid half would leave a procedure that looks saved and walks
    somewhere else."""
    pid = make(app, key="p", nodes=[("start", "start", {})])
    login(client, admin_user_id(app), product="fortiweb")
    r = client.post("/process/%d/graph" % pid, json={
        "nodes": [{"key": "start", "kind": "start", "params": {}},
                  {"key": "a", "kind": "end", "params": {}},
                  {"key": "b", "kind": "end", "params": {}}],
        "edges": [{"src": "start", "dst": "a", "branch": "always"},
                  {"src": "start", "dst": "b", "branch": "always"}]})
    assert r.status_code == 400
    assert r.get_json()["ok"] is False
    with app.app_context():
        # Nothing was written: the process still holds only its Start step.
        assert [n.node_key for n in db.session.get(Process, pid).nodes] == ["start"]


def test_a_valid_diagram_replaces_the_stored_graph(app, client):
    pid = make(app, key="p", nodes=[("start", "start", {})])
    login(client, admin_user_id(app), product="fortiweb")
    r = client.post("/process/%d/graph" % pid, json={
        "nodes": [{"key": "start", "kind": "start", "params": {}, "x": 10, "y": 10},
                  {"key": "ping", "kind": "tcp_check",
                   "params": {"host": "192.0.2.1", "port": "443"}, "x": 10, "y": 90}],
        "edges": [{"src": "start", "dst": "ping", "branch": "always"}]})
    assert r.status_code == 200 and r.get_json()["ok"] is True
    with app.app_context():
        proc = db.session.get(Process, pid)
        assert sorted(n.node_key for n in proc.nodes) == ["ping", "start"]
        assert proc.graph()["edges"] == [
            {"src": "start", "dst": "ping", "branch": "always"}]


def test_deleting_a_process_keeps_its_runs(app, client, monkeypatch):
    """History that vanishes with its definition is not history."""
    stub(monkeypatch, "tcp_check", "pass")
    pid = make(app, key="p",
               nodes=[("start", "start", {}),
                      ("t", "tcp_check", {"host": "h", "port": "1"})],
               edges=[("start", "t", "always")])
    rid = walk(app, pid)
    login(client, admin_user_id(app), product="fortiweb")
    assert client.post("/process/%d/delete" % pid).status_code == 302
    with app.app_context():
        run = db.session.get(ProcessRun, rid)
        assert run is not None
        assert run.process_id is None
        assert run.process_key == "p"
        assert run.graph["nodes"], "the run keeps its own copy of the diagram"


def test_a_run_is_judged_against_the_graph_it_walked_not_the_current_one(
        app, client, monkeypatch):
    """The reason ``ProcessRun.graph`` is a snapshot: editing a process must not
    rewrite its own past."""
    stub(monkeypatch, "tcp_check", "pass")
    pid = make(app, key="p",
               nodes=[("start", "start", {}),
                      ("t", "tcp_check", {"host": "h", "port": "1"})],
               edges=[("start", "t", "always")])
    rid = walk(app, pid)
    login(client, admin_user_id(app), product="fortiweb")
    client.post("/process/%d/graph" % pid, json={
        "nodes": [{"key": "start", "kind": "start", "params": {}}], "edges": []})
    with app.app_context():
        run = db.session.get(ProcessRun, rid)
        assert [n["key"] for n in run.graph["nodes"]] == ["start", "t"]


# ---------------------------------------------------------------------------
# graph questions the run form depends on
# ---------------------------------------------------------------------------

def test_needs_appliance_sees_a_device_action_not_just_the_kind(app, monkeypatch):
    """``action`` itself does not need a device — the ActionSpec behind it does.
    Reading only the kind would let a plan start and discover three green steps
    later that it has nothing to point at."""
    class Spec:
        key = "reboot"; needs_targets = True; requires_change_request = False
        products = ("fortiweb",); label = "R"; danger = True; summary = ""
    monkeypatch.setattr("app.services.scheduled_actions.get_spec",
                        lambda k: Spec if k == "reboot" else None)
    graph = {"nodes": [{"key": "a", "kind": "action",
                        "params": {"action_key": "reboot"}}], "edges": []}
    assert pk.needs_appliance(graph) is True
    assert pk.needs_appliance({"nodes": [{"key": "s", "kind": "start",
                                          "params": {}}], "edges": []}) is False


def test_writes_is_true_only_for_write_capable_kinds():
    assert pk.writes({"nodes": [{"key": "a", "kind": "action", "params": {}}]}) is True
    assert pk.writes({"nodes": [{"key": "a", "kind": "http_check",
                                 "params": {}}]}) is False


def test_arming_a_read_only_plan_is_dropped(app, client, monkeypatch):
    """A run stamped 'armed' that could never have written anything teaches an
    operator the wrong thing about the badge."""
    stub(monkeypatch, "tcp_check", "pass")
    pid = make(app, key="p",
               nodes=[("start", "start", {}),
                      ("t", "tcp_check", {"host": "h", "port": "1"})],
               edges=[("start", "t", "always")])
    login(client, admin_user_id(app), product="fortiweb")
    client.post("/process/%d/run" % pid, data={"armed": "1"})
    with app.app_context():
        run = ProcessRun.query.order_by(ProcessRun.id.desc()).first()
        assert run.armed is False


# ---------------------------------------------------------------------------
# nav drift
# ---------------------------------------------------------------------------

def test_process_is_drawn_in_all_five_administrator_blocks():
    """base.html has FIVE Administrator blocks and they have drifted before —
    two of them were titled differently until 2026-09-08. An entry added to
    Global and forgotten in the other four is invisible without failing
    anything, so the count is pinned against the two partials that are already
    known to be in all five.
    """
    base = io.open("/opt/satom/app/templates/base.html", encoding="utf-8").read()
    assert base.count('partials/nav_process.html') == 5
    assert base.count('partials/nav_process.html') == \
        base.count('partials/nav_console.html') == \
        base.count('partials/nav_adom_assets.html')


def test_the_nav_entry_and_the_page_agree_about_the_permission():
    """A link that leads to a 403 is a bug report waiting to be filed. The
    partial shows on ``view``; the index route must therefore accept ``view``.
    """
    nav = io.open("/opt/satom/app/templates/partials/nav_process.html",
                  encoding="utf-8").read()
    view = io.open("/opt/satom/app/views/process.py", encoding="utf-8").read()
    assert "current_user.can('view')" in nav
    idx = view.index("def index():")
    head = view[view.index("@bp.route(\"/\")"):idx]
    assert 'require_permission("view")' in head


def test_a_read_only_operator_can_read_but_not_run(app, client):
    """The whole point of gating the PAGE on view and the WRITES on
    config_write: a read-only operator gets the plan and its history, not a
    403 — and cannot fire it."""
    from tests.conftest import make_user
    uid = make_user(app, username="ro", role="readonly")
    pid = make(app, key="ro-test", nodes=[("start", "start", {})])
    login(client, uid, product="fortiweb")
    assert client.get("/process/").status_code == 200
    assert client.get("/process/%d" % pid).status_code == 200
    assert client.post("/process/%d/run" % pid).status_code in (302, 403)
    with app.app_context():
        assert ProcessRun.query.count() == 0, "a read-only user started a run"
