"""AI Advisor — conversations, messages, structured proposals, and the
export log for anything that leaves the LAN.

Design constraint, load-bearing for every table here: the advisor NEVER
writes to a device or to SATOM's own applied configuration directly. A
structured proposal becomes a DRAFT row in the same tables an operator would
fill in by hand — a ``WppException`` (WAF exception/signature carve-out) or a
``LuaScript`` in ``draft`` status. Same validation, same ``config_write``
permission gate, same guided-apply flow that is already audited elsewhere in
this product. This module only remembers what was said and what was
proposed; it has no write path of its own onto an appliance.

``product`` columns are ``String(32)`` from creation — the width SATOM's
schema migration (v1.5.0, ``_ensure_widths``) settled on after the
FortiAuthenticator key (18 chars) overran the old ``VARCHAR(16)``. No new
table here should ever ship at 16 again.
"""
from __future__ import annotations

import json
from datetime import datetime

from .extensions import db


class AdvisorConversation(db.Model):
    __tablename__ = "advisor_conversations"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, default="")
    username = db.Column(db.String(64), nullable=False, default="")
    product = db.Column(db.String(32), nullable=True, default="")
    provider_key = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    messages = db.relationship(
        "AdvisorMessage", backref="conversation",
        order_by="AdvisorMessage.id", cascade="all, delete-orphan")
    proposals = db.relationship(
        "AdvisorProposal", backref="conversation",
        order_by="AdvisorProposal.id", cascade="all, delete-orphan")

    def to_summary(self) -> dict:
        last = self.messages[-1] if self.messages else None
        return {
            "id": self.id,
            "title": self.title or "New conversation",
            "provider_key": self.provider_key,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "preview": (last.content[:140] if last else ""),
        }


class AdvisorMessage(db.Model):
    __tablename__ = "advisor_messages"

    ROLES = ("user", "assistant", "system", "tool")

    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(
        db.Integer, db.ForeignKey("advisor_conversations.id", ondelete="CASCADE"),
        nullable=False, index=True)
    role = db.Column(db.String(16), nullable=False, default="user")
    content = db.Column(db.Text, nullable=False, default="")
    attachments = db.Column(db.Text, nullable=False, default="[]")   # JSON list
    redacted = db.Column(db.Boolean, nullable=False, default=False)
    redaction_count = db.Column(db.Integer, nullable=False, default=0)
    tool_calls = db.Column(db.Text, nullable=False, default="[]")    # JSON list
    # Telemetry, assistant rows only. NULLABLE on purpose: NULL means "the
    # provider did not report this", which is NOT the same claim as 0. Some
    # OpenAI-COMPATIBLE gateways omit the ``usage`` block entirely, and
    # rendering a confident "0 tokens" for them would be a measurement the
    # product never made.
    duration_ms = db.Column(db.Integer, nullable=True)
    prompt_tokens = db.Column(db.Integer, nullable=True)
    completion_tokens = db.Column(db.Integer, nullable=True)
    # Set when the operator pressed Stop (or closed the tab) mid-reply. The
    # partial IS kept: throwing it away would discard tokens that were really
    # spent and leave the next page load showing nothing, which reads as "the
    # feature lost my answer" rather than "I cancelled it".
    stopped = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def attachments_list(self) -> list:
        try:
            v = json.loads(self.attachments or "[]")
            return v if isinstance(v, list) else []
        except (ValueError, TypeError):
            return []

    def tool_calls_list(self) -> list:
        try:
            v = json.loads(self.tool_calls or "[]")
            return v if isinstance(v, list) else []
        except (ValueError, TypeError):
            return []

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "role": self.role,
            "content": self.content,
            "attachments": self.attachments_list(),
            "redacted": bool(self.redacted),
            "redaction_count": self.redaction_count,
            "tool_calls": self.tool_calls_list(),
            "duration_ms": self.duration_ms,
            "stopped": bool(self.stopped),
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": (
                None if self.prompt_tokens is None and self.completion_tokens is None
                else (self.prompt_tokens or 0) + (self.completion_tokens or 0)),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AdvisorExportLog(db.Model):
    """One row per message that left the LAN to an external provider. Local
    Ollama traffic is NOT logged here — it never leaves the LAN. It is still
    covered by the normal ``AuditLog`` action ``advisor.send``, same as every
    other action in this product."""
    __tablename__ = "advisor_export_log"

    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, nullable=True, index=True)
    username = db.Column(db.String(64), nullable=False, default="")
    provider_key = db.Column(db.String(64), nullable=False, default="")
    provider_kind = db.Column(db.String(32), nullable=False, default="")
    destination_host = db.Column(db.String(200), nullable=False, default="")
    bytes_sent = db.Column(db.Integer, nullable=False, default=0)
    redaction_count = db.Column(db.Integer, nullable=False, default=0)
    summary = db.Column(db.String(300), nullable=False, default="")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)


class AdvisorRequestLog(db.Model):
    """One row for EVERY provider call — local Ollama included, failures
    included. This is the operations ledger: what was asked, how long it
    took, what it cost in tokens.

    Deliberately a SECOND table alongside ``AdvisorExportLog`` rather than a
    widened version of it. The export log answers a compliance question —
    "did data leave the LAN?" — and every row in it is an export. If local
    calls were folded in, a reviewer scanning that table would read LAN-only
    traffic as exports, and the only way to tell them apart would be a column
    they have to remember to filter on. The export log stays the strict
    subset; this table is the superset. Neither can drift, because
    ``send_message`` writes both from the same measurement.

    A FAILED call is a row here too. A provider timeout that leaves no trace
    is the failure mode this product has been bitten by repeatedly — see
    ``docs/safeguards.md`` on failures that exit 0.
    """
    __tablename__ = "advisor_request_log"

    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, nullable=True, index=True)
    message_id = db.Column(db.Integer, nullable=True)   # NULL when the call failed
    username = db.Column(db.String(64), nullable=False, default="")
    provider_key = db.Column(db.String(64), nullable=False, default="")
    provider_kind = db.Column(db.String(32), nullable=False, default="")
    model = db.Column(db.String(120), nullable=False, default="")
    destination_host = db.Column(db.String(200), nullable=False, default="")
    external = db.Column(db.Boolean, nullable=False, default=False, index=True)

    duration_ms = db.Column(db.Integer, nullable=False, default=0)
    # See AdvisorMessage: NULL means "not reported by the provider", not zero.
    prompt_tokens = db.Column(db.Integer, nullable=True)
    completion_tokens = db.Column(db.Integer, nullable=True)

    tool_rounds = db.Column(db.Integer, nullable=False, default=0)
    tool_calls = db.Column(db.Integer, nullable=False, default=0)

    ok = db.Column(db.Boolean, nullable=False, default=True, index=True)
    error = db.Column(db.String(400), nullable=False, default="")

    bytes_sent = db.Column(db.Integer, nullable=False, default=0)
    redaction_count = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def total_tokens(self):
        if self.prompt_tokens is None and self.completion_tokens is None:
            return None
        return (self.prompt_tokens or 0) + (self.completion_tokens or 0)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "conversation_id": self.conversation_id,
            "username": self.username,
            "provider_key": self.provider_key,
            "provider_kind": self.provider_kind,
            "model": self.model,
            "destination_host": self.destination_host,
            "external": bool(self.external),
            "duration_ms": self.duration_ms,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens(),
            "tool_rounds": self.tool_rounds,
            "tool_calls": self.tool_calls,
            "ok": bool(self.ok),
            "error": self.error,
            "bytes_sent": self.bytes_sent,
            "redaction_count": self.redaction_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AdvisorProposal(db.Model):
    """A structured, schema-validated suggestion the model made. Applying one
    creates a DRAFT row in the product's own table (never a device write) —
    see the module docstring."""
    __tablename__ = "advisor_proposals"

    KINDS = ("waf_exception", "lua_script")
    STATUSES = ("pending", "applied", "dismissed")

    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(
        db.Integer, db.ForeignKey("advisor_conversations.id", ondelete="CASCADE"),
        nullable=False, index=True)
    kind = db.Column(db.String(32), nullable=False, default="")
    appliance_id = db.Column(db.Integer, nullable=True, index=True)
    title = db.Column(db.String(200), nullable=False, default="")
    payload = db.Column(db.Text, nullable=False, default="{}")   # JSON, schema per kind
    rationale = db.Column(db.Text, nullable=False, default="")
    status = db.Column(db.String(16), nullable=False, default="pending")
    applied_ref = db.Column(db.String(64), nullable=False, default="")
    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    decided_at = db.Column(db.DateTime, nullable=True)
    decided_by = db.Column(db.String(64), nullable=False, default="")

    def payload_dict(self) -> dict:
        try:
            d = json.loads(self.payload or "{}")
            return d if isinstance(d, dict) else {}
        except (ValueError, TypeError):
            return {}

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "appliance_id": self.appliance_id,
            "title": self.title,
            "payload": self.payload_dict(),
            "rationale": self.rationale,
            "status": self.status,
            "applied_ref": self.applied_ref,
        }
