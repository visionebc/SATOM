"""Triggers and event automations — the orchestrator's two halves.

A **trigger** (Administrator › Change Management › Triggers) is a CONDITION:
an event name from :data:`app.services.trigger_engine.EVENTS` plus a filter
that narrows which occurrences count, a cooldown per subject and an hourly
budget. A trigger does nothing on its own; it is the thing an administrator
defines once and every automation can reuse.

An **event automation** (Automation › Automations › On a trigger) is the
IMPLEMENTATION: "when trigger T matches, do X", where X is one of the things
SATOM can already run — a Process walk, a published Python Studio app, a
Script Library script, a call to an API Catalog endpoint, an integration
hook, a scheduled action run now, or a notification. Several automations
may hang off one trigger; one automation has exactly one trigger.

The split is the operator's (2026-10-22): the condition is administered,
the response is operated. Keeping them as two tables is what lets a single
"critical device alert" trigger feed a diagnostics walk, a ticket in the
CRM and a chat message without three copies of the same filter drifting.

Every match and every refusal is RECORDED (``trigger_fires`` and
``event_automation_runs``): a trigger that is silently dropped is a plan
that "never fires" with no trace of why — the lesson ``process_triggers``
already paid for. JSON lives in Text columns, as in ``models_process``, so
the schema is the same on Postgres and on the SQLite the tests use.
"""
from __future__ import annotations

import json
from datetime import datetime

from .models import db


def _loads(text, default):
    try:
        v = json.loads(text or "null")
    except (TypeError, ValueError):
        return default
    return default if v is None else v


# fire / run outcomes
FIRE_MATCHED = "matched"      # the trigger matched and its automations were queued
FIRE_SUPPRESSED = "suppressed"  # matched, refused by cooldown / budget / chain depth
FIRE_STATUSES = (FIRE_MATCHED, FIRE_SUPPRESSED)

RUN_QUEUED = "queued"
RUN_RUNNING = "running"
RUN_OK = "ok"
RUN_FAILED = "failed"
RUN_SKIPPED = "skipped"
RUN_STATUSES = (RUN_QUEUED, RUN_RUNNING, RUN_OK, RUN_FAILED, RUN_SKIPPED)


class Trigger(db.Model):
    __tablename__ = "triggers"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(48), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    #: An event name of ``trigger_engine.EVENTS``.
    event = db.Column(db.String(64), nullable=False, index=True)
    #: JSON narrowing (``trigger_engine.CONDITION_KEYS``); empty = any.
    conditions_json = db.Column(db.Text, nullable=False, default="{}")
    #: The same subject (an alert key, a CR id…) matches again only after
    #: this many minutes. 0 = every occurrence.
    cooldown_minutes = db.Column(db.Integer, nullable=False, default=60)
    #: Matches that queue automations, per hour, for this trigger.
    rate_limit_per_hour = db.Column(db.Integer, nullable=False, default=20)
    created_by = db.Column(db.String(64), nullable=False, default="")
    updated_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)
    last_fired_at = db.Column(db.DateTime, nullable=True)

    automations = db.relationship("EventAutomation", backref="trigger",
                                  lazy="selectin")

    @property
    def conditions(self) -> dict:
        v = _loads(self.conditions_json, {})
        return v if isinstance(v, dict) else {}

    @conditions.setter
    def conditions(self, value) -> None:
        self.conditions_json = json.dumps(value or {}, sort_keys=True)


class TriggerFire(db.Model):
    """One occurrence that matched a trigger — queued or refused."""
    __tablename__ = "trigger_fires"

    id = db.Column(db.Integer, primary_key=True)
    trigger_id = db.Column(db.Integer, db.ForeignKey("triggers.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    event = db.Column(db.String(64), nullable=False)
    #: What the cooldown is counted on: the alert key, the CR id, …
    subject = db.Column(db.String(200), nullable=False, default="")
    status = db.Column(db.String(16), nullable=False, default=FIRE_MATCHED)
    reason = db.Column(db.Text, nullable=False, default="")
    depth = db.Column(db.Integer, nullable=False, default=0)
    payload_json = db.Column(db.Text, nullable=False, default="{}")
    by = db.Column(db.String(64), nullable=False, default="")
    fired_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    trigger = db.relationship("Trigger")

    @property
    def payload(self) -> dict:
        v = _loads(self.payload_json, {})
        return v if isinstance(v, dict) else {}


class EventAutomation(db.Model):
    __tablename__ = "event_automations"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(48), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    trigger_id = db.Column(db.Integer, db.ForeignKey("triggers.id"), nullable=False,
                           index=True)
    #: ``trigger_engine.KINDS``: process | app | script | api_call | hook |
    #: action | notify
    kind = db.Column(db.String(24), nullable=False)
    #: The thing it runs: a process key, an app / script / connection / hook
    #: slug, a scheduled-action id; '' for notify.
    target = db.Column(db.String(120), nullable=False, default="")
    #: Kind-specific settings; text values are templates over ``event``.
    params_json = db.Column(db.Text, nullable=False, default="{}")
    #: False = a rehearsal: write steps are recorded, not executed.
    armed = db.Column(db.Boolean, nullable=False, default=False)
    #: The ADOM this automation was created in ('' = Global). The
    #: Automations page lists it there (product_scope.scope_query).
    product = db.Column(db.String(32), nullable=False, default="")
    #: Runs as this user (Studio app access, script vault, audit trail).
    owner = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)
    updated_by = db.Column(db.String(64), nullable=False, default="")
    last_run_at = db.Column(db.DateTime, nullable=True)
    last_status = db.Column(db.String(16), nullable=False, default="")

    @property
    def params(self) -> dict:
        v = _loads(self.params_json, {})
        return v if isinstance(v, dict) else {}

    @params.setter
    def params(self, value) -> None:
        self.params_json = json.dumps(value or {}, sort_keys=True)


class EventAutomationRun(db.Model):
    __tablename__ = "event_automation_runs"

    id = db.Column(db.Integer, primary_key=True)
    automation_id = db.Column(db.Integer,
                              db.ForeignKey("event_automations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    fire_id = db.Column(db.Integer, db.ForeignKey("trigger_fires.id", ondelete="SET NULL"),
                        nullable=True, index=True)
    status = db.Column(db.String(16), nullable=False, default=RUN_QUEUED)
    armed = db.Column(db.Boolean, nullable=False, default=False)
    summary = db.Column(db.Text, nullable=False, default="")
    #: Where the real work is recorded: process-run:12, app-run:5,
    #: script:<rid>, hook:<rid>, action-run:9, job:<id>.
    ref = db.Column(db.String(120), nullable=False, default="")
    job_id = db.Column(db.String(64), nullable=False, default="")
    test = db.Column(db.Boolean, nullable=False, default=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    ended_at = db.Column(db.DateTime, nullable=True)

    automation = db.relationship("EventAutomation")
