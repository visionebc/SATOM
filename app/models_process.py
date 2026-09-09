"""Process — operator-defined procedures the system walks and judges.

A *process* is a diagram: nodes that ask a question of the running system, and
edges that say where to go depending on the answer. Recovery plans, post-upgrade
validation, onboarding checks and incident runbooks are all the same shape, so
they are one model rather than four modules.

THE GRAPH IS EDITED AS ROWS AND EXECUTED AS A SNAPSHOT
-----------------------------------------------------
:class:`ProcessNode` / :class:`ProcessEdge` are what the editor writes and what
the next run reads. :class:`ProcessRun` copies the whole graph into
``graph_json`` the moment it starts.

That duplication is deliberate and it is the point. A run is a statement about
what *happened*; if history pointed at live rows, editing a process would
silently rewrite its own past — a step recorded as "checked the standby" would
start rendering as whatever that node was later changed to. The product already
paid for this lesson once in ``sot_store`` (content-addressed snapshots): the
identity of a thing you assert about must not be editable after the assertion.

WHY ``products_json`` IS A LIST AND NOT A COLUMN
-----------------------------------------------
Every other scoped record in SATOM carries ONE ``product`` string, because a
device belongs to one ADOM. A process does not: "fail the standby over and
prove the service came back" is the same procedure whether the appliance in
front of you is a FortiWeb or a FortiADC, and the operator said so explicitly —
a process is registered *for one or several* ADOMs and shows up in each.

The read path is :func:`app.services.process_engine.visible_processes`, which
is the only authority on that question; a template that filtered the list
itself would be a second author of visibility, and this codebase has been bitten
by that (``calendar_plan`` in the ADC menu, ``advisor`` before it).

STATUS VOCABULARY, AND WHY ``unknown`` IS NOT ``fail``
-----------------------------------------------------
A step is ``pass`` / ``fail`` / ``unknown`` / ``skipped``.

``unknown`` means *the system could not look* — SSH refused, the collector
crashed, no credentials. It is never rendered as health and it never counts as
a fail: a fail sends somebody to repair a component, and "I could not look" is
a statement about the observer. Scout learned this the hard way (2026-09-09) and
the same rule holds here, including its cost: a bug in an executor surfaces as
``unknown``, so a process must be walked against the live system, not only
against fixtures, or the rule hides the bugs of whoever wrote it.

``skipped`` is what everything downstream of a stopped path becomes. It is NOT
``pass``. A green step underneath a red one is how a report gets read backwards.
"""
from __future__ import annotations

import json
from datetime import datetime

from .models import db

# ── step outcomes ──────────────────────────────────────────────────────────
PASS = "pass"
FAIL = "fail"
UNKNOWN = "unknown"
SKIPPED = "skipped"
STEP_STATUSES = (PASS, FAIL, UNKNOWN, SKIPPED)

# ── run lifecycle ──────────────────────────────────────────────────────────
RUNNING = "running"
WAITING = "waiting"      # parked on a manual gate; a human must answer
DONE = "done"
ABORTED = "aborted"
RUN_STATUSES = (RUNNING, WAITING, DONE, ABORTED)

# ── run verdicts (only meaningful once status == DONE) ─────────────────────
OK = "ok"                # every step that ran passed, and every step ran
PARTIAL = "partial"      # nothing failed, but something could not be looked at
FAILED = "failed"        # a step failed
VERDICTS = (OK, PARTIAL, FAILED)

#: Edge branches. ``always`` is an unconditional next step; the other three
#: fire only when the source step ended with that outcome. An edge set with no
#: branch matching the outcome ends that path — see the engine.
BRANCHES = ("always", PASS, FAIL, UNKNOWN)


def _json_prop(attr: str, default):
    """A ``Text``-backed JSON property.

    Same helper as ``models_sentinel``: JSON lives in Text columns so the schema
    is byte-identical on Postgres (production) and on the SQLite the tests run
    against. A native JSON column would diverge between the two and the
    divergence would only show up in production.
    """

    def getter(self):
        try:
            return json.loads(getattr(self, attr) or "null") or default
        except Exception:  # noqa: BLE001 — a corrupt blob must not 500 a list page
            return default

    def setter(self, value):
        setattr(self, attr, json.dumps(value if value is not None else default))

    return property(getter, setter)


class Process(db.Model):
    """One operator-defined procedure."""

    __tablename__ = "processes"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")

    #: ADOM keys this process is offered in. Empty means "nowhere", which is a
    #: real state (a draft) and is NOT read as "everywhere" — a default that
    #: widened scope would publish drafts into five consoles.
    products_text = db.Column("products_json", db.Text, nullable=False, default="[]")
    products = _json_prop("products_text", [])

    enabled = db.Column(db.Boolean, nullable=False, default=True)

    created_by = db.Column(db.String(120), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    nodes = db.relationship("ProcessNode", backref="process", lazy="selectin",
                            cascade="all, delete-orphan")
    edges = db.relationship("ProcessEdge", backref="process", lazy="selectin",
                            cascade="all, delete-orphan")

    def graph(self) -> dict:
        """The editable graph, in the shape the editor and the engine share."""
        return {
            "nodes": [n.to_dict() for n in sorted(self.nodes, key=lambda n: n.id or 0)],
            "edges": [e.to_dict() for e in sorted(self.edges, key=lambda e: e.id or 0)],
        }


class ProcessNode(db.Model):
    __tablename__ = "process_nodes"

    id = db.Column(db.Integer, primary_key=True)
    process_id = db.Column(db.Integer, db.ForeignKey("processes.id", ondelete="CASCADE"),
                           nullable=False, index=True)

    #: Stable within one process; edges reference this, not the row id, so a
    #: graph can be posted whole by the editor without inventing ids.
    node_key = db.Column(db.String(64), nullable=False)
    kind = db.Column(db.String(40), nullable=False)
    label = db.Column(db.String(160), nullable=False, default="")

    params_text = db.Column("params_json", db.Text, nullable=False, default="{}")
    params = _json_prop("params_text", {})

    pos_x = db.Column(db.Integer, nullable=False, default=0)
    pos_y = db.Column(db.Integer, nullable=False, default=0)

    __table_args__ = (
        db.UniqueConstraint("process_id", "node_key", name="uq_process_node_key"),
    )

    def to_dict(self) -> dict:
        return {"key": self.node_key, "kind": self.kind, "label": self.label,
                "params": self.params, "x": self.pos_x, "y": self.pos_y}


class ProcessEdge(db.Model):
    __tablename__ = "process_edges"

    id = db.Column(db.Integer, primary_key=True)
    process_id = db.Column(db.Integer, db.ForeignKey("processes.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    src_key = db.Column(db.String(64), nullable=False)
    dst_key = db.Column(db.String(64), nullable=False)
    branch = db.Column(db.String(16), nullable=False, default="always")

    def to_dict(self) -> dict:
        return {"src": self.src_key, "dst": self.dst_key, "branch": self.branch}


class ProcessRun(db.Model):
    """One walk of one process, and the graph it walked."""

    __tablename__ = "process_runs"

    id = db.Column(db.Integer, primary_key=True)
    process_id = db.Column(db.Integer, db.ForeignKey("processes.id", ondelete="SET NULL"),
                           nullable=True, index=True)

    #: Denormalised on purpose: a run stays readable after its process is
    #: deleted. History that vanishes with its definition is not history.
    process_key = db.Column(db.String(64), nullable=False, default="")
    process_name = db.Column(db.String(160), nullable=False, default="")
    product = db.Column(db.String(32), nullable=False, default="", index=True)

    graph_text = db.Column("graph_json", db.Text, nullable=False, default="{}")
    graph = _json_prop("graph_text", {})

    #: The appliance the run was pointed at, if the process needs one. Stored by
    #: id AND name for the same reason as ``process_key``.
    appliance_id = db.Column(db.Integer, nullable=True)
    appliance_name = db.Column(db.String(160), nullable=False, default="")

    #: False = every write-capable node executes as a dry run. This is the
    #: preview/confirm split the rest of the product uses (``dns_decommission``,
    #: ``cert_manager``); an unarmed run is safe to fire at anything.
    armed = db.Column(db.Boolean, nullable=False, default=False)

    status = db.Column(db.String(16), nullable=False, default=RUNNING, index=True)
    verdict = db.Column(db.String(16), nullable=False, default="")
    summary = db.Column(db.Text, nullable=False, default="")

    trigger = db.Column(db.String(32), nullable=False, default="manual")
    started_by = db.Column(db.String(120), nullable=False, default="")
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    ended_at = db.Column(db.DateTime, nullable=True)

    #: Set while parked on a manual gate, so the resume POST knows where it is.
    waiting_node = db.Column(db.String(64), nullable=False, default="")

    steps = db.relationship("ProcessRunStep", backref="run", lazy="selectin",
                            cascade="all, delete-orphan",
                            order_by="ProcessRunStep.seq")

    def counts(self) -> dict:
        out = {s: 0 for s in STEP_STATUSES}
        for st in self.steps:
            if st.status in out:
                out[st.status] += 1
        return out


class ProcessRunStep(db.Model):
    __tablename__ = "process_run_steps"

    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, db.ForeignKey("process_runs.id", ondelete="CASCADE"),
                       nullable=False, index=True)

    seq = db.Column(db.Integer, nullable=False, default=0)
    node_key = db.Column(db.String(64), nullable=False, default="")
    kind = db.Column(db.String(40), nullable=False, default="")
    label = db.Column(db.String(160), nullable=False, default="")

    status = db.Column(db.String(16), nullable=False, default=UNKNOWN)
    detail = db.Column(db.Text, nullable=False, default="")
    output = db.Column(db.Text, nullable=False, default="")

    #: True when a write-capable node ran without arming. The row must say so:
    #: a dry run that reads like a real one is a false record of a repair.
    dry_run = db.Column(db.Boolean, nullable=False, default=False)

    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ended_at = db.Column(db.DateTime, nullable=True)
