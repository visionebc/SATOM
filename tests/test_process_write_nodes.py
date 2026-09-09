"""Guards for the two write nodes a Process may contain.

WHY THIS FILE IS SEPARATE FROM ``test_process_engine``
------------------------------------------------------
Every other node in the catalogue ASKS a question. These two CHANGE something —
``console_script`` sends CLI lines to an appliance, ``hook`` runs
operator-written Python holding real secrets. They are the generic write door
the first round deliberately held back, and the thing that has to hold is not
"does the adapter return the right dataclass" but **when does nothing happen at
all**:

  * an unarmed run must not open a session and must not write a request file,
  * a disruptive line must not go to an appliance the plan did not name,
  * a plan containing a forbidden command must not be saveable,
  * a hook nobody ran must not be reported as a hook that succeeded.

Each of those failures produces a run that reads exactly like a correct one.
A rehearsal recorded as a repair is the specific lie this file exists to
prevent, and no amount of "the page returned 200" can see it.

The executors are driven THROUGH the engine, with ``ssh_console.run_script``
and ``integration_hooks.dispatch_one`` replaced by recorders. Replacing the
service and not the classifier is deliberate: the tier blacklist, the script
parser and the timeout clamp stay REAL, because they are what the guards are
actually asserting about.
"""
from __future__ import annotations

import ast
import json

import pytest

from app.models import db
from app.models_process import Process, ProcessRun
from app.services import integration_hooks as ih
from app.services import process_engine as engine
from app.services import process_kinds as pk
from app.services import ssh_console as sc
from tests.test_process_engine import make, outcomes, walk


# ---------------------------------------------------------------------------
# doubles
# ---------------------------------------------------------------------------

class Box:
    """The smallest thing an executor can be pointed at."""

    def __init__(self, name="fortiweb13", host="192.0.2.14", kind="fortiweb"):
        self.id = 1
        self.name = name
        self.host = host
        self.kind = kind


class Recorder(list):
    """A list the fixture can hang scripted answers off."""


def rows(*specs):
    return [sc.CommandRow(command=c, status=s, detail=d, output="")
            for c, s, d in specs]


@pytest.fixture
def sent(monkeypatch):
    """Record every call to ``run_script`` and answer with a canned result."""
    calls = Recorder()
    canned = {"result": None}

    def fake(appliance, commands, *, allow_disruptive=False, stop_on_error=True,
             **kw):
        calls.append({"appliance": getattr(appliance, "name", ""),
                      "commands": list(commands),
                      "allow_disruptive": allow_disruptive,
                      "stop_on_error": stop_on_error})
        res = canned["result"]
        if res is None:
            res = sc.ScriptResult(
                appliance=getattr(appliance, "name", ""),
                rows=[sc.CommandRow(command=c, status="ok") for c in commands],
                transcript="\n".join("$ " + c for c in commands))
        return res

    monkeypatch.setattr(sc, "run_script", fake)
    calls.canned = canned
    return calls


@pytest.fixture
def queued(monkeypatch):
    """Record every ``dispatch_one`` and serve scripted status rows."""
    calls = Recorder()
    state = {"statuses": [], "hook": {"slug": "notify", "event": "alert.fired",
                                      "enabled": True, "timeout": 1,
                                      "secrets": []}}

    def fake_get(slug):
        h = state["hook"]
        return dict(h) if h and h.get("slug") == slug else None

    def fake_dispatch(slug, *, sample=True, payload=None, by="system"):
        calls.append({"slug": slug, "sample": sample, "payload": payload,
                      "by": by})
        return {"slug": slug, "request_id": "rid-1", "status": "queued"}

    def fake_result(rid):
        if not state["statuses"]:
            return {"request_id": rid, "status": "queued"}
        nxt = state["statuses"][0]
        if len(state["statuses"]) > 1:
            state["statuses"].pop(0)
        return dict(nxt, request_id=rid)

    monkeypatch.setattr(ih, "get_hook", fake_get)
    monkeypatch.setattr(ih, "dispatch_one", fake_dispatch)
    monkeypatch.setattr(ih, "result", fake_result)
    monkeypatch.setattr(pk, "HOOK_POLL_S", 0.01)
    monkeypatch.setattr(pk, "HOOK_GRACE_S", 0.0)
    calls.state = state
    return calls


def one_console(script, **params):
    p = {"script": script}
    p.update(params)
    return [("start", "start", {}), ("do", "console_script", p),
            ("fin", "end", {})]


CONSOLE_EDGES = [("start", "do", "always"), ("do", "fin", "pass")]


def one_hook(**params):
    p = {"slug": "notify"}
    p.update(params)
    return [("start", "start", {}), ("do", "hook", p), ("fin", "end", {})]


HOOK_EDGES = [("start", "do", "always"), ("do", "fin", "pass")]


def step(app, rid, key="do"):
    with app.app_context():
        run = db.session.get(ProcessRun, rid)
        return next(s for s in run.steps if s.node_key == key)


# ---------------------------------------------------------------------------
# console_script — the unarmed run
# ---------------------------------------------------------------------------

def test_an_unarmed_console_step_never_opens_a_session(app, sent):
    """THE rule. A rehearsal that sent the script would be a repair.

    Asserted by the RECORDER being empty, not by the verdict: a verdict can be
    right while the appliance was changed anyway, and that is the failure that
    would never be noticed.
    """
    pid = make(app, nodes=one_console("get system status"), edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=Box(), armed=False)
    assert sent == []
    assert step(app, rid).status == "unknown"


def test_an_unarmed_console_step_is_unknown_not_pass(app, sent):
    """A rehearsal has no evidence about the appliance, so it cannot be green.

    ``action`` may answer pass/fail unarmed because ``run_action`` has a real
    dry run; ``run_script`` has none. The verdict differs because the evidence
    differs, and the walk must stop where the repair would have been rather
    than continue down the 'and then it was fixed' branch.
    """
    pid = make(app, nodes=one_console("get system status"), edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=Box(), armed=False)
    seen, verdict, _status = outcomes(app, rid)
    assert seen["do"] == "unknown"
    assert seen.get("fin") != "pass"
    assert verdict == "partial"


def test_an_unarmed_console_step_shows_what_it_would_have_sent(app, sent):
    pid = make(app, nodes=one_console("get system status\nexecute reboot",
                                      confirm_name="fortiweb13"),
               edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=Box(), armed=False)
    out = step(app, rid).output
    assert "get system status" in out and "execute reboot" in out
    assert "disruptive" in out          # the real classifier, not a copy


def test_the_rehearsal_is_recorded_as_a_rehearsal_on_the_row(app, sent):
    pid = make(app, nodes=one_console("get system status"), edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=Box(), armed=False)
    assert step(app, rid).dry_run is True


# ---------------------------------------------------------------------------
# console_script — the armed run
# ---------------------------------------------------------------------------

def test_an_armed_console_step_sends_and_passes(app, sent):
    pid = make(app, nodes=one_console("get system status"), edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=Box(), armed=True)
    assert [c["commands"] for c in sent] == [["get system status"]]
    assert step(app, rid).status == "pass"


def test_a_failing_command_fails_the_step_and_names_the_first_one(app, sent):
    sent.canned["result"] = sc.ScriptResult(
        appliance="fortiweb13",
        rows=rows(("config system dns", "ok", ""),
                  ("set primary 1.2.3.4", "error", "invalid value"),
                  ("end", "not_run", "stopped")),
        transcript="t")
    pid = make(app, nodes=one_console("config system dns\nset primary 1.2.3.4\nend"),
               edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=Box(), armed=True)
    st = step(app, rid)
    assert st.status == "fail"
    assert "set primary 1.2.3.4" in st.detail


def test_a_session_that_never_opened_is_unknown_not_fail(app, sent):
    """SATOM could not look. That is a blind spot, not a broken appliance.

    Reported as ``fail`` it would send somebody to debug a configuration that
    was never touched.
    """
    sent.canned["result"] = sc.ScriptResult(
        appliance="fortiweb13",
        rows=rows(("get system status", "not_run", "the session never opened")),
        error="Authentication failed")
    pid = make(app, nodes=one_console("get system status"), edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=Box(), armed=True)
    st = step(app, rid)
    assert st.status == "unknown"
    assert "session did not open" in st.detail


def test_a_gate_refusal_is_not_reported_as_a_dead_session(app, sent):
    """Two different events with two different fixes.

    ``run_script`` sets ``error`` for BOTH a refused command and a dead socket.
    Collapsing them would tell an operator to check credentials when the real
    answer is that the command has no path through SATOM at any level.
    """
    sent.canned["result"] = sc.ScriptResult(
        appliance="fortiweb13",
        rows=rows(("execute factoryreset", "refused", "wipes the configuration")),
        error="refused: wipes the configuration")
    pid = make(app, nodes=one_console("get system status"), edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=Box(), armed=True)
    st = step(app, rid)
    assert st.status == "unknown"
    assert "refused to send" in st.detail
    assert "session did not open" not in st.detail


def test_a_retired_placeholder_host_is_refused_before_anything_is_sent(app, sent):
    pid = make(app, nodes=one_console("get system status"), edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=Box(host="faz01.invalid"), armed=True)
    assert sent == []
    st = step(app, rid)
    assert st.status == "unknown"
    assert "retired placeholder" in st.detail


def test_a_console_step_without_an_appliance_is_unknown(app, sent):
    pid = make(app, nodes=one_console("get system status"), edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=None, armed=True)
    assert sent == []
    assert step(app, rid).status == "unknown"


def test_stop_on_error_reaches_the_service(app, sent):
    pid = make(app, nodes=one_console("get system status", stop_on_error="0"),
               edges=CONSOLE_EDGES)
    walk(app, pid, appliance=Box(), armed=True)
    assert sent[0]["stop_on_error"] is False


# ---------------------------------------------------------------------------
# console_script — who agreed, and to what
# ---------------------------------------------------------------------------

def test_a_disruptive_step_pointed_at_another_appliance_refuses(app, sent):
    """The crux of the whole design.

    The page asks a human to type the appliance name at the moment of sending.
    A process has no human at 3 a.m., so the plan names the ONE box it may
    disrupt — and aiming the same process at a different one must refuse, not
    reboot whatever it was given.
    """
    pid = make(app, nodes=one_console("execute reboot", confirm_name="fortiweb13"),
               edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=Box(name="fortiweb08"), armed=True)
    assert sent == []
    st = step(app, rid)
    assert st.status == "unknown"
    assert "fortiweb13" in st.detail and "fortiweb08" in st.detail


def test_a_disruptive_step_on_the_named_appliance_sends_with_the_ack(app, sent):
    pid = make(app, nodes=one_console("execute reboot", confirm_name="fortiweb13"),
               edges=CONSOLE_EDGES)
    walk(app, pid, appliance=Box(name="fortiweb13"), armed=True)
    assert sent[0]["allow_disruptive"] is True


def test_a_safe_script_is_never_sent_with_the_disruptive_flag(app, sent):
    """``allow_disruptive`` is a record that a human was warned, not a mode.

    Setting it for every armed run would make the acknowledgement meaningless
    the moment a disruptive line was pasted into an existing plan.
    """
    pid = make(app, nodes=one_console("get system status",
                                      confirm_name="fortiweb13"),
               edges=CONSOLE_EDGES)
    walk(app, pid, appliance=Box(), armed=True)
    assert sent[0]["allow_disruptive"] is False


def test_a_disruptive_step_that_names_nobody_refuses(app, sent):
    """The last line of defence, and it had no guard until a mutation asked.

    ``validate_graph`` refuses to SAVE a disruptive step with no named
    appliance, so every test wrote one — and the run-time branch that handles a
    node arriving WITHOUT one (an import, a restored bundle, a hand-edited row)
    was never exercised. Relaxing it to "refuse only if a name was given and it
    differs" reads like a tidy-up and reboots whatever the run points at.
    """
    pid = make(app, nodes=one_console("execute reboot"), edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=Box(), armed=True)
    assert sent == []
    st = step(app, rid)
    assert st.status == "unknown"
    assert "'—'" in st.detail or "—" in st.detail


def test_a_console_step_with_nothing_to_send_sends_nothing(app, sent):
    """Same shape as the guard above: the save gate hides the run-time branch.

    A node whose script survives the parser as zero commands must not open a
    session. Without this, ``run_script`` is called with ``[]`` and an empty
    ScriptResult comes back with ``failed == 0`` — a step that connected to a
    production appliance and reported PASS having done nothing.
    """
    pid = make(app, nodes=one_console("# nothing\n\n   "), edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=Box(), armed=True)
    assert sent == []
    assert step(app, rid).status == "unknown"


def test_the_name_match_is_exact(app, sent):
    pid = make(app, nodes=one_console("execute reboot", confirm_name="fortiweb1"),
               edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=Box(name="fortiweb13"), armed=True)
    assert sent == []
    assert step(app, rid).status == "unknown"


def test_what_was_sent_is_audited_under_the_console_action_name(app, sent):
    """One audit name for one capability.

    An operator asking "what has been sent over the console" must not have to
    know there are two doors into it.
    """
    from app.models import AuditLog
    pid = make(app, nodes=one_console("get system status"), edges=CONSOLE_EDGES)
    rid = walk(app, pid, appliance=Box(), armed=True)
    with app.app_context():
        row = (AuditLog.query.filter_by(action="console.run")
               .order_by(AuditLog.id.desc()).first())
        assert row is not None
        # ``log_action`` stores ``str(dict)`` — a Python repr, NOT JSON, despite
        # the column comment. Read it the way it is actually written rather than
        # the way the schema claims; the mismatch is preexisting and product-wide.
        extra = row.extra if isinstance(row.extra, dict) else ast.literal_eval(row.extra)
        assert extra["via"] == "process"
        assert extra["run_id"] == rid
        assert extra["commands"] == ["get system status"]


def test_an_unarmed_run_writes_no_console_audit_row(app, sent):
    """Nothing was sent, so there is nothing to audit.

    A row saying a script ran is the same lie as a green step: it is what an
    auditor would read months later.
    """
    from app.models import AuditLog
    with app.app_context():
        before = AuditLog.query.filter_by(action="console.run").count()
    pid = make(app, nodes=one_console("get system status"), edges=CONSOLE_EDGES)
    walk(app, pid, appliance=Box(), armed=False)
    with app.app_context():
        assert AuditLog.query.filter_by(action="console.run").count() == before


# ---------------------------------------------------------------------------
# console_script — save-time validation
# ---------------------------------------------------------------------------

def graph_of(script, **params):
    p = {"script": script}
    p.update(params)
    return {"nodes": [{"key": "start", "kind": "start", "params": {}},
                      {"key": "do", "kind": "console_script", "params": p}],
            "edges": [{"src": "start", "dst": "do", "branch": "always"}]}


def test_a_forbidden_command_cannot_be_saved(app):
    """Discovered at save time, not halfway through a recovery.

    ``run_script`` re-gates before it opens the session; this gate is earlier
    still, so a plan that could never legally run cannot be written down and
    then trusted.
    """
    with app.app_context():
        errs = pk.validate_graph(graph_of("execute factoryreset"))
    assert any("refused" in e and "factoryreset" in e for e in errs)


def test_a_disruptive_command_without_a_named_appliance_cannot_be_saved(app):
    with app.app_context():
        errs = pk.validate_graph(graph_of("execute reboot"))
    assert any("Disruptive only on" in e for e in errs)


def test_a_disruptive_command_with_a_named_appliance_saves(app):
    with app.app_context():
        errs = pk.validate_graph(graph_of("execute reboot",
                                          confirm_name="fortiweb13"))
    assert errs == []


def test_a_comment_only_script_cannot_be_saved(app):
    """Blank lines and ``#`` comments are stripped by the real parser.

    A step whose script is three comments would be saved, walked, and reported
    green having done nothing.
    """
    with app.app_context():
        errs = pk.validate_graph(graph_of("# nothing to do\n\n   \n# really"))
    assert any("no commands" in e for e in errs)


def test_a_script_longer_than_the_console_allows_cannot_be_saved(app):
    """``run_script`` TRUNCATES and notes it. A note on a run nobody reads is
    not the same as refusing a 300-line plan."""
    with app.app_context():
        errs = pk.validate_graph(
            graph_of("\n".join("get system status" for _ in range(sc.MAX_COMMANDS + 1))))
    assert any("at most %d" % sc.MAX_COMMANDS in e for e in errs)


def test_the_catalogue_marks_the_console_step_as_writing_and_needing_a_box(app):
    """``writes`` drives the armed/rehearsal banner and the ``dry_run`` column;
    ``needs_appliance`` is what makes the run refuse up front instead of
    walking three green steps and then finding it has nothing to point at."""
    k = pk.get_kind("console_script")
    assert k.writes is True and k.needs_appliance is True
    assert pk.writes({"nodes": [{"kind": "console_script"}]}) is True
    assert pk.needs_appliance({"nodes": [{"kind": "console_script"}]}) is True


# ---------------------------------------------------------------------------
# hook
# ---------------------------------------------------------------------------

def test_an_unarmed_hook_step_queues_nothing(app, queued):
    """``sample=True`` is not a dry run — it runs the hook with an example
    payload. A hook is operator-written Python holding real secrets, so an
    unarmed run must not reach it at all."""
    pid = make(app, nodes=one_hook(), edges=HOOK_EDGES)
    rid = walk(app, pid, armed=False)
    assert queued == []
    assert step(app, rid).status == "unknown"


def test_an_unarmed_hook_step_shows_what_it_would_have_run(app, queued):
    pid = make(app, nodes=one_hook(), edges=HOOK_EDGES)
    rid = walk(app, pid, armed=False)
    out = step(app, rid).output
    assert "notify" in out and "alert.fired" in out


def test_a_finished_hook_passes(app, queued):
    queued.state["statuses"] = [{"status": "ok", "duration_ms": 12,
                                 "exit_code": 0, "stdout": "done"}]
    pid = make(app, nodes=one_hook(), edges=HOOK_EDGES)
    rid = walk(app, pid, armed=True)
    assert step(app, rid).status == "pass"
    assert queued[0]["sample"] is False


def test_a_failed_hook_fails(app, queued):
    queued.state["statuses"] = [{"status": "failed", "exit_code": 1,
                                 "error": "boom", "stdout": ""}]
    pid = make(app, nodes=one_hook(), edges=HOOK_EDGES)
    rid = walk(app, pid, armed=True)
    st = step(app, rid)
    assert st.status == "fail" and "boom" in st.detail


def test_a_hook_killed_at_its_timeout_fails_it_does_not_go_unknown(app, queued):
    """The runner killed it. That is an answer about the hook, not a blind spot.

    Reported ``unknown`` it would make the verdict ``partial`` and read as
    'we could not look', when in fact we looked and it hung.
    """
    queued.state["statuses"] = [{"status": "timeout", "exit_code": None,
                                 "stdout": ""}]
    pid = make(app, nodes=one_hook(), edges=HOOK_EDGES)
    rid = walk(app, pid, armed=True)
    st = step(app, rid)
    assert st.status == "fail" and "timeout" in st.detail


def test_a_request_nobody_picked_up_is_unknown_and_names_the_runner(app, queued):
    """The July 2026 failure, made visible.

    The standby node sat on ``queued`` update requests for weeks because its
    ``.path`` unit was never enabled, and 'queued forever' looked like nothing
    at all. Silence here is the observer's problem, and the step must say which
    unit on which node.
    """
    queued.state["statuses"] = []          # never leaves 'queued'
    pid = make(app, nodes=one_hook(), edges=HOOK_EDGES)
    rid = walk(app, pid, armed=True)
    st = step(app, rid)
    assert st.status == "unknown"
    assert "satom-integrations.path" in st.detail


def test_not_waiting_claims_only_that_the_request_was_written(app, queued):
    queued.state["statuses"] = []
    pid = make(app, nodes=one_hook(wait="0"), edges=HOOK_EDGES)
    rid = walk(app, pid, armed=True)
    st = step(app, rid)
    assert st.status == "pass"
    assert "not waited on" in st.detail


def test_the_wait_is_bounded_by_the_hooks_own_timeout(app, queued, monkeypatch):
    """It cannot be raised from the diagram.

    The runner kills the job at the hook's clamped timeout, so a longer wait
    cannot outlive it — it can only hold a web worker open for nothing.
    """
    seen = {}
    real = ih.clamp_timeout
    monkeypatch.setattr(ih, "clamp_timeout",
                        lambda v: seen.setdefault("v", real(v)))
    queued.state["hook"]["timeout"] = 9999      # above MAX_TIMEOUT on purpose
    queued.state["statuses"] = [{"status": "ok", "duration_ms": 1,
                                 "exit_code": 0, "stdout": ""}]
    pid = make(app, nodes=one_hook(), edges=HOOK_EDGES)
    walk(app, pid, armed=True)
    assert seen["v"] == ih.MAX_TIMEOUT


def test_the_payload_carries_provenance_the_operator_cannot_forge(app, queued):
    """Provenance is SATOM's claim about where a request came from.

    A field the plan can pre-set is a field the plan can lie in, and a forged
    stamp is worse than none because it is believed.
    """
    queued.state["statuses"] = [{"status": "ok", "duration_ms": 1,
                                 "exit_code": 0, "stdout": ""}]
    pid = make(app, nodes=one_hook(payload=json.dumps(
        {"ticket": "T-1", "satom_process": {"run_id": 999, "armed": True}})),
        edges=HOOK_EDGES)
    rid = walk(app, pid, armed=True)
    body = queued[0]["payload"]
    assert body["ticket"] == "T-1"                  # the operator's keys survive
    assert body["satom_process"]["run_id"] == rid   # ...but not this one
    assert body["satom_process"]["step"] == "do"


def test_a_hook_that_no_longer_exists_is_unknown(app, queued):
    queued.state["hook"] = None
    pid = make(app, nodes=one_hook(), edges=HOOK_EDGES)
    rid = walk(app, pid, armed=True)
    assert queued == []
    assert step(app, rid).status == "unknown"


def test_a_hook_payload_that_is_not_json_is_unknown_and_queues_nothing(app, queued):
    pid = make(app, nodes=one_hook(payload="{oops"), edges=HOOK_EDGES)
    rid = walk(app, pid, armed=True)
    assert queued == []
    assert step(app, rid).status == "unknown"


def hook_graph(**params):
    p = {"slug": "notify"}
    p.update(params)
    return {"nodes": [{"key": "start", "kind": "start", "params": {}},
                      {"key": "do", "kind": "hook", "params": p}],
            "edges": [{"src": "start", "dst": "do", "branch": "always"}]}


def test_a_hook_that_does_not_exist_cannot_be_saved(app, queued):
    queued.state["hook"] = None
    with app.app_context():
        errs = pk.validate_graph(hook_graph())
    assert any("does not exist" in e for e in errs)


def test_a_payload_that_is_not_json_cannot_be_saved(app, queued):
    with app.app_context():
        errs = pk.validate_graph(hook_graph(payload="{oops"))
    assert any("not JSON" in e for e in errs)


def test_a_payload_that_is_not_an_object_cannot_be_saved(app, queued):
    """``[1,2,3]`` is valid JSON and useless as a payload — the SDK hands the
    hook a mapping."""
    with app.app_context():
        errs = pk.validate_graph(hook_graph(payload="[1,2,3]"))
    assert any("must be a JSON object" in e for e in errs)


def test_the_catalogue_marks_the_hook_step_as_writing_but_boxless(app):
    k = pk.get_kind("hook")
    assert k.writes is True and k.needs_appliance is False


# ---------------------------------------------------------------------------
# the page names the gap it does not close
# ---------------------------------------------------------------------------

def test_a_diagram_that_sends_cli_lines_warns_that_references_are_unguarded(
        app, client):
    """``delete_guard`` cannot read a ``delete`` inside a CLI ``config`` block.

    An undocumented hole in a safety net is worse than no net, because the net
    is what people trust. The warning belongs where the decision to arm is
    made, not only in the manual.
    """
    from tests.conftest import admin_user_id, login
    login(client, admin_user_id(app))
    pid = make(app, nodes=one_console("get system status"), edges=CONSOLE_EDGES)
    page = client.get("/process/%d" % pid)
    assert page.status_code == 200
    assert b"Reference protection does not" in page.data


def test_a_writing_diagram_that_sends_no_cli_does_not_cry_wolf(app, client):
    """The same warning on every diagram is a warning nobody reads.

    The graph must WRITE, or this proves nothing: the banner lives inside the
    arming block, so a read-only diagram hides it for an unrelated reason and a
    guard built on one cannot see the banner's own condition break. A hook step
    writes and sends no CLI, which is exactly the case that separates them.
    """
    from tests.conftest import admin_user_id, login
    login(client, admin_user_id(app))
    pid = make(app, key="hookonly", nodes=one_hook(), edges=HOOK_EDGES)
    page = client.get("/process/%d" % pid)
    assert page.status_code == 200
    assert b"Arm this run" in page.data          # the block DID render
    assert b"Reference protection does not" not in page.data


def test_a_read_only_diagram_offers_no_arming_at_all(app, client):
    from tests.conftest import admin_user_id, login
    login(client, admin_user_id(app))
    pid = make(app, key="ro",
               nodes=[("start", "start", {}),
                      ("t", "tcp_check", {"host": "192.0.2.1", "port": "443"})],
               edges=[("start", "t", "always")])
    page = client.get("/process/%d" % pid)
    assert page.status_code == 200
    assert b"Arm this run" not in page.data
    assert b"Reference protection does not" not in page.data


def test_kinds_used_reads_the_graph_not_the_catalogue(app):
    assert pk.kinds_used({"nodes": [{"kind": "console_script"}, {"kind": "end"}]}) \
        == {"console_script", "end"}
    assert pk.kinds_used({}) == set()


# ---------------------------------------------------------------------------
# one author for "can this appliance be dialled"
# ---------------------------------------------------------------------------

def test_the_page_and_the_process_give_the_same_retired_reason(app, sent, client):
    """Behavioural, not by reading the source.

    Two copies of this sentence is how a page and a run start disagreeing about
    the same appliance. Asserted by driving BOTH surfaces and comparing what
    each one actually says.
    """
    from tests.conftest import admin_user_id, login
    from app.models import Appliance

    with app.app_context():
        ap = Appliance(name="faz01", host="faz01.invalid", kind="fortiweb",
                       port=443, username="admin")
        ap.password = "pw"
        db.session.add(ap)
        db.session.commit()
        ap_id, ap_name = ap.id, ap.name

    login(client, admin_user_id(app))
    page = client.post("/console/run",
                       data={"appliance_id": ap_id,
                             "script": "get system status\nget system performance"},
                       follow_redirects=True)
    assert page.status_code == 200

    pid = make(app, nodes=one_console("get system status"), edges=CONSOLE_EDGES)
    with app.app_context():
        proc = db.session.get(Process, pid)
        run = engine.start_run(proc, appliance=db.session.get(Appliance, ap_id),
                               armed=True)
        detail = next(s for s in run.steps if s.node_key == "do").detail

    assert sc.retired_placeholder(Box(host="faz01.invalid")) == detail

    # COUNTED, not merely present. The page prints the reason twice over: once
    # in the session-level banner and once on EVERY command row. A first
    # version of this guard only asked whether the sentence appeared at all,
    # and a mutation that made the rows say something else survived it — the
    # banner alone kept the assertion true. Two commands were posted, so a page
    # that agrees shows the sentence three times and one that has grown a
    # second author shows it once.
    assert page.data.count(detail.encode()) >= 2, \
        "the rows no longer carry the same reason the service gives"
    assert sc.retired_placeholder(Box(host="192.0.2.14")) == ""
    assert ap_name == "faz01"
