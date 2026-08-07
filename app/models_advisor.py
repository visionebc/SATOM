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
