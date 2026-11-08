"""Operational incidents: SATOM's own ticket (``SAT-INC-000001``).

2026-11-08, operator (FA-0008): a runbook run ends by raising an incident --
"a local ticket, that can later be joined to the company's ticket area (left
pending), and where the ticket and its history with the vendor or L3 is kept".

Not Sentinel's incidents (``models_sentinel.SentinelIncident``): those are
SECURITY incidents, keyed by appliance + source IP + attack family, absorbing
events, scored, and only alive while Sentinel is on. An appliance that does not
answer is none of that, and forcing it into that table would break its
correlation. The two share a word and nothing else; the reference prefix tells
them apart (``SAT-INC-`` here, ``INC-`` there).

* :class:`OpIncident` -- one per problem: appliance, severity P1-P4, status,
  owner, the run that opened it. ``itsm_system`` / ``itsm_ref`` are reserved
  for the company ticket system and nothing writes them yet (operator: "we
  leave that pending").
* :class:`OpIncidentEntry` -- the incident's history: created, notes, every
  status / severity / owner change, with who and when. Append-only.
* :class:`OpVendorTicket` -- a ticket opened with a vendor or L3 (Fortinet
  TAC, the customer's L3...): its number, link and status. Several per
  incident.
* :class:`OpVendorTicketEntry` -- that ticket's own history ("TAC asks for a
  debug flow", "RMA approved"). Append-only.
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db

REF_PREFIX = "SAT-INC-"


def make_ref(pk: int) -> str:
    return "%s%06d" % (REF_PREFIX, int(pk))


class OpIncident(db.Model):
    __tablename__ = "op_incidents"

    STATUSES = ("open", "in_progress", "waiting_vendor", "resolved", "closed")
    #: still somebody's work
    OPEN_STATUSES = ("open", "in_progress", "waiting_vendor")
    SEVERITIES = ("P1", "P2", "P3", "P4")
    SOURCES = ("manual", "runbook")

    id = db.Column(db.Integer, primary_key=True)
    #: SAT-INC-000001, written right after the row has its id
    ref = db.Column(db.String(24), nullable=True, unique=True, index=True)
    title = db.Column(db.String(200), nullable=False)
    summary = db.Column(db.Text, nullable=False, default="")
    status = db.Column(db.String(16), nullable=False, default="open", index=True)
    severity = db.Column(db.String(4), nullable=False, default="P3")
    owner = db.Column(db.String(64), nullable=False, default="")
    appliance_id = db.Column(db.Integer, db.ForeignKey("appliances.id", ondelete="SET NULL"),
                             nullable=True, index=True)
    #: the appliance's name when the incident was opened: it outlives the row
    appliance_name = db.Column(db.String(128), nullable=False, default="")
    source = db.Column(db.String(16), nullable=False, default="manual")
    #: the Plugin Studio run that opened it; one incident per run
    run_id = db.Column(db.Integer, db.ForeignKey("studio_app_runs.id", ondelete="SET NULL"),
                       nullable=True, unique=True)
    app_slug = db.Column(db.String(64), nullable=False, default="")
    #: reserved: the company ticket system (ServiceNow, Jira...) and its number
    itsm_system = db.Column(db.String(32), nullable=False, default="")
    itsm_ref = db.Column(db.String(64), nullable=False, default="")
    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    closed_at = db.Column(db.DateTime, nullable=True)

    entries = db.relationship("OpIncidentEntry", backref="incident", lazy="select",
                              cascade="all, delete-orphan",
                              order_by="OpIncidentEntry.id")
    vendor_tickets = db.relationship("OpVendorTicket", backref="incident", lazy="select",
                                     cascade="all, delete-orphan",
                                     order_by="OpVendorTicket.id")

    @property
    def is_open(self) -> bool:
        return self.status in self.OPEN_STATUSES


class OpIncidentEntry(db.Model):
    __tablename__ = "op_incident_entries"

    KINDS = ("created", "note", "status", "severity", "owner", "vendor")

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("op_incidents.id", ondelete="CASCADE"),
                            nullable=False, index=True)
    at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user = db.Column(db.String(64), nullable=False, default="")
    kind = db.Column(db.String(12), nullable=False, default="note")
    text = db.Column(db.Text, nullable=False, default="")


class OpVendorTicket(db.Model):
    __tablename__ = "op_vendor_tickets"

    STATUSES = ("open", "waiting_vendor", "waiting_us", "resolved", "closed")

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("op_incidents.id", ondelete="CASCADE"),
                            nullable=False, index=True)
    #: who the ticket is with: "Fortinet TAC", "L3 network team"...
    vendor = db.Column(db.String(64), nullable=False)
    ticket_no = db.Column(db.String(64), nullable=False, default="")
    #: a link to the ticket in the vendor's portal (http/https only)
    url = db.Column(db.String(500), nullable=False, default="")
    status = db.Column(db.String(16), nullable=False, default="open")
    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    entries = db.relationship("OpVendorTicketEntry", backref="ticket", lazy="select",
                              cascade="all, delete-orphan",
                              order_by="OpVendorTicketEntry.id")


class OpVendorTicketEntry(db.Model):
    __tablename__ = "op_vendor_ticket_entries"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("op_vendor_tickets.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user = db.Column(db.String(64), nullable=False, default="")
    text = db.Column(db.Text, nullable=False, default="")
