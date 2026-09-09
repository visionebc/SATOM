"""Process engine — walks a saved diagram and produces a verdict.

THE ENGINE OWNS THE ORDER AND THE VERDICT, AND NOTHING ELSE. Every question is
asked by the module that already owns it (see ``process_kinds``); this file
decides where to go next and what the whole walk means. It is the same division
Scout draws, for the same reason: two authors for "is this healthy" is how a
page and a mail start disagreeing.

THE WALK IS A SINGLE CURSOR
---------------------------
``validate_graph`` refuses a step with two arrows for the same outcome, and the
outcomes (``pass``/``fail``/``unknown``) are mutually exclusive. So a run is
never in two places at once. That is not a limitation that snuck in — it is
what makes a **manual gate resumable**: the whole position of a paused run is
one node key in one column, answerable tomorrow, instead of an in-memory
frontier held open by a worker that will not survive a restart.

FOUR RULES, EACH WITH A COST WRITTEN DOWN
-----------------------------------------
1. **A path that stops does not turn green underneath.** When a step's outcome
   has no arrow to follow and the step had arrows, everything the plan could
   have reached from there is recorded ``skipped`` — never ``pass``. A green
   step under a red one is how a report gets read backwards.
2. **Branches not taken are NOT skipped.** An ``escalate`` path that a healthy
   run never enters is normal control flow. Marking it ``skipped`` would print
   a blind spot on every good day until the word stopped meaning anything.
3. **``unknown`` never passes and never fails.** It makes the verdict
   ``partial``, and the summary says so in a sentence rather than a badge:
   *"nothing failed, but N steps could not be looked at — this is a partial
   walk, not a clean bill of health."*
4. **A loop is allowed and bounded.** Retry cycles are a legitimate shape, so
   the graph is not required to be acyclic; :data:`MAX_STEPS` is the backstop
   and hitting it ABORTS the run with that reason rather than reporting a
   verdict about a walk that never finished.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ..models_process import (ABORTED, DONE, FAIL, FAILED, OK, PARTIAL, PASS,
                              RUNNING, SKIPPED, UNKNOWN, WAITING, Process,
                              ProcessRun, ProcessRunStep)
from . import process_kinds as pk

#: Hard cap on executed steps in one run. A retry loop is legitimate; an
#: infinite one is a defect, and a bounded abort names it.
MAX_STEPS = 200


@dataclass
class Ctx:
    """What an executor may see. Deliberately small.

    ``run_id`` and ``user`` are provenance, not capability: the write nodes
    stamp them onto the audit row and the hook payload so a line in the console
    audit or a request in the integration queue can be traced back to the walk
    that produced it. Nothing branches on them.
    """
    appliance: object = None
    armed: bool = False
    results: dict = field(default_factory=dict)
    run_id: int = 0
    user: str = ""


# ---------------------------------------------------------------------------
# visibility
# ---------------------------------------------------------------------------

def visible_processes(product: str | None = None):
    """Processes offered in the active ADOM, newest first.

    THE ONLY AUTHORITY on that question. A template that filtered the list
    itself would be a second author of visibility, and this codebase has been
    bitten by exactly that (``calendar_plan`` drawn in the FortiADC menu while
    the gate bounced the click to ``/adc/``).

    The Global ADOM sees every process, because Global is the console from
    which processes are authored; a concrete ADOM sees only the ones that name
    it. An empty product list means the process is a draft and appears NOWHERE
    but Global — a default that meant "everywhere" would publish drafts into
    five consoles.
    """
    from .product_scope import GLOBAL, session_product
    prod = product if product is not None else session_product()
    rows = Process.query.order_by(Process.name.asc()).all()
    if prod == GLOBAL or not prod:
        return rows
    return [p for p in rows if prod in (p.products or [])]


def may_run_here(proc, product: str | None = None) -> bool:
    from .product_scope import GLOBAL, session_product
    prod = product if product is not None else session_product()
    return prod == GLOBAL or prod in (proc.products or [])


# ---------------------------------------------------------------------------
# graph helpers
# ---------------------------------------------------------------------------

def _node_map(graph: dict) -> dict:
    return {str(n.get("key")): n for n in graph.get("nodes", [])}


def _out_edges(graph: dict, key: str) -> list:
    return [e for e in graph.get("edges", []) if str(e.get("src")) == key]


def _next_key(graph: dict, key: str, status: str) -> str:
    """The one arrow to follow, or '' when the plan has no route for this
    outcome. ``always`` is the fallback, never an override: an explicit
    ``fail`` arrow must win over a catch-all or a recovery branch would be
    unreachable in exactly the graphs that need it.
    """
    edges = _out_edges(graph, key)
    for e in edges:
        if str(e.get("branch")) == status:
            return str(e.get("dst"))
    for e in edges:
        if str(e.get("branch") or "always") == "always":
            return str(e.get("dst"))
    return ""


def _reachable(graph: dict, start_keys) -> set:
    seen: set = set()
    stack = list(start_keys)
    while stack:
        k = stack.pop()
        if k in seen:
            continue
        seen.add(k)
        stack.extend(str(e.get("dst")) for e in _out_edges(graph, k))
    return seen


def start_key(graph: dict) -> str:
    for n in graph.get("nodes", []):
        if n.get("kind") == "start":
            return str(n.get("key"))
    return ""


# ---------------------------------------------------------------------------
# running
# ---------------------------------------------------------------------------

def start_run(proc, *, appliance=None, armed: bool = False,
              trigger: str = "manual", user: str = "", product: str = "") -> ProcessRun:
    """Snapshot the graph and walk it. Commits."""
    from ..models import db

    graph = proc.graph()
    run = ProcessRun(
        process_id=proc.id, process_key=proc.key, process_name=proc.name,
        product=product or "", graph=graph,
        appliance_id=getattr(appliance, "id", None),
        appliance_name=getattr(appliance, "name", "") or "",
        armed=bool(armed), status=RUNNING, trigger=trigger, started_by=user or "",
    )
    db.session.add(run)
    db.session.commit()
    return advance(run, appliance=appliance)


def resume(run: ProcessRun, answer: str, *, appliance=None, note: str = "") -> ProcessRun:
    """Answer the manual gate a run is parked on and keep walking.

    ``answer`` is an OUTCOME (pass/fail), not a yes/no, so the operator's answer
    routes through the same arrows every other step uses. An answer the plan has
    no arrow for stops the path exactly like a machine outcome would.
    """
    from ..models import db

    if run.status != WAITING:
        return run
    status = answer if answer in (PASS, FAIL) else UNKNOWN
    step = (ProcessRunStep.query.filter_by(run_id=run.id, node_key=run.waiting_node)
            .order_by(ProcessRunStep.seq.desc()).first())
    if step is not None:
        step.status = status
        step.detail = ((step.detail + " — ") if step.detail else "") + \
            ("answered %s" % status) + ((": " + note) if note else "")
        step.ended_at = datetime.utcnow()
    run.status = RUNNING
    parked = run.waiting_node
    run.waiting_node = ""
    db.session.commit()
    return advance(run, appliance=appliance, resume_from=parked,
                   resume_status=status)


def advance(run: ProcessRun, *, appliance=None, resume_from: str = "",
            resume_status: str = "") -> ProcessRun:
    """Walk from the start (or from a resumed gate) until the run settles."""
    from ..models import Appliance, db

    graph = run.graph or {}
    nodes = _node_map(graph)
    if appliance is None and run.appliance_id:
        appliance = db.session.get(Appliance, run.appliance_id)

    # Outcomes of everything already recorded, so a Decision resumed after a
    # gate can still see the steps that ran before the pause.
    ctx = Ctx(appliance=appliance, armed=bool(run.armed), run_id=run.id,
              user=run.started_by or "")
    for st in run.steps:
        ctx.results[st.node_key] = pk.StepResult(st.status, st.detail, st.output)

    seq = max([st.seq for st in run.steps], default=0)
    executed = {st.node_key for st in run.steps if st.status != SKIPPED}
    stop_points: list = []

    if resume_from:
        cursor = _next_key(graph, resume_from, resume_status or UNKNOWN)
        if not cursor:
            stop_points.append(resume_from)
    else:
        cursor = start_key(graph)
        if not cursor:
            return _finish(run, ABORTED, "this process has no Start step")

    budget = MAX_STEPS
    while cursor:
        node = nodes.get(cursor)
        if node is None:
            stop_points.append(cursor)
            break
        budget -= 1
        if budget < 0:
            _finish(run, ABORTED,
                    "the walk exceeded %d steps and was stopped — the diagram "
                    "loops without an exit" % MAX_STEPS)
            return run

        seq += 1
        started = datetime.utcnow()
        res = pk.execute(node, ctx)

        kind = pk.get_kind(str(node.get("kind") or ""))
        step = ProcessRunStep(
            run_id=run.id, seq=seq, node_key=cursor,
            kind=str(node.get("kind") or ""),
            label=str(node.get("label") or cursor),
            status=res.status, detail=res.detail, output=res.output or "",
            dry_run=bool(kind and kind.writes and not run.armed),
            started_at=started, ended_at=datetime.utcnow(),
        )
        db.session.add(step)
        ctx.results[cursor] = res
        executed.add(cursor)

        if res.gate:
            run.status = WAITING
            run.waiting_node = cursor
            db.session.commit()
            return run

        nxt = _next_key(graph, cursor, res.status)
        if not nxt:
            # No arrow to follow: the plan had no route for this outcome.
            #
            # Recorded UNCONDITIONALLY. There used to be an `if
            # _out_edges(cursor)` here, guarding against calling a natural leaf
            # a stop point — and a mutation proved it changed nothing: a node
            # with no outgoing arrows contributes no successors, so a leaf adds
            # nothing to the skipped set either way. A condition that alters no
            # behaviour reads as protection that is not there, which is worse
            # than no condition at all.
            stop_points.append(cursor)
            break
        cursor = nxt

    _mark_skipped(run, graph, stop_points, executed, seq)
    return _finish(run, DONE, "")


def _mark_skipped(run, graph, stop_points, executed, seq):
    """Record what the plan could not reach because a path stopped.

    Only successors of a STOP POINT. Branches the plan deliberately did not take
    are normal control flow, and calling them ``skipped`` would print a blind
    spot on every healthy run until the word stopped meaning anything.
    """
    from ..models import db

    if not stop_points:
        return
    starts: list = []
    for k in stop_points:
        starts.extend(str(e.get("dst")) for e in _out_edges(graph, k))
    nodes = _node_map(graph)
    for key in sorted(_reachable(graph, starts) - set(executed)):
        node = nodes.get(key) or {}
        seq += 1
        db.session.add(ProcessRunStep(
            run_id=run.id, seq=seq, node_key=key,
            kind=str(node.get("kind") or ""),
            label=str(node.get("label") or key),
            status=SKIPPED,
            detail="not reached — an earlier step stopped this path",
            ended_at=datetime.utcnow(),
        ))


def _finish(run, status: str, note: str) -> ProcessRun:
    from ..models import db

    run.status = status
    run.ended_at = datetime.utcnow()
    # Counted from the TABLE, not from ``run.steps``: the rows this walk just
    # added are pending in the session, and the relationship was loaded before
    # them. Counting the stale collection is how a run reports "0 failed" about
    # a walk that failed.
    db.session.flush()
    counts = {PASS: 0, FAIL: 0, UNKNOWN: 0, SKIPPED: 0}
    for st in ProcessRunStep.query.filter_by(run_id=run.id).all():
        if st.status in counts:
            counts[st.status] += 1

    if status == ABORTED:
        run.verdict = FAILED
        run.summary = note
    elif counts[FAIL]:
        run.verdict = FAILED
        run.summary = ("%d step(s) failed. The first failure is where the plan "
                       "stopped; anything below it was not reached."
                       % counts[FAIL])
    elif counts[UNKNOWN]:
        run.verdict = PARTIAL
        run.summary = ("Nothing failed, but %d step(s) could not be looked at. "
                       "This is a partial walk, not a clean bill of health."
                       % counts[UNKNOWN])
    else:
        run.verdict = OK
        run.summary = "%d step(s) ran and every one of them passed." % counts[PASS]
    db.session.commit()
    return run
