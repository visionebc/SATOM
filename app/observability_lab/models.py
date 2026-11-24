"""Tables. Live values are FACTS (latest value per source/object/layer/key);
numeric history goes to VictoriaMetrics, not here."""
from __future__ import annotations

from datetime import datetime, timezone

from flask_login import UserMixin

from .extensions import db, login_manager


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class SatomUser(UserMixin):
    """The SATOM user of this request. No user table here: SATOM authenticated
    and authorised the request (app/views/observability_lab.py) and handed the
    identity over in the WSGI environ, which a browser cannot set."""

    def __init__(self, username: str, is_admin: bool):
        self.id = username
        self.username = username
        self.is_admin = bool(is_admin)


@login_manager.request_loader
def _from_satom(req):
    who = req.environ.get("satom.user")
    if not isinstance(who, dict) or not who.get("username"):
        return None
    return SatomUser(who["username"], who.get("is_admin", False))


class Diagram(db.Model):
    __tablename__ = "diagrams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    layout = db.Column(db.JSON, nullable=False, default=dict)
    version = db.Column(db.Integer, nullable=False, default=1)
    origin = db.Column(db.String(32), nullable=False, default="drawn")
    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class Source(db.Model):
    """One connector instance (one device, one DDI, one NetBox, one API)."""
    __tablename__ = "sources"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    kind = db.Column(db.String(32), nullable=False)
    host = db.Column(db.String(255), nullable=False, default="")
    port = db.Column(db.Integer, nullable=False, default=443)
    username = db.Column(db.String(128), nullable=False, default="")
    secret_enc = db.Column(db.Text, nullable=False, default="")
    tls_verify = db.Column(db.Boolean, nullable=False, default=True)
    ca_pem = db.Column(db.Text, nullable=False, default="")
    config = db.Column(db.JSON, nullable=False, default=dict)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    interval_s = db.Column(db.Integer, nullable=False, default=300)
    build = db.Column(db.String(160), nullable=False, default="")
    last_run_at = db.Column(db.DateTime)
    last_status = db.Column(db.String(16), nullable=False, default="never")
    last_error = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class Fact(db.Model):
    __tablename__ = "facts"
    __table_args__ = (db.UniqueConstraint("source_id", "object_ref", "layer", "key",
                                          name="uq_fact"),)
    id = db.Column(db.Integer, primary_key=True)
    source_id = db.Column(db.Integer, db.ForeignKey("sources.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    object_ref = db.Column(db.String(255), nullable=False)
    layer = db.Column(db.String(8), nullable=False)
    key = db.Column(db.String(80), nullable=False)
    value = db.Column(db.JSON)
    endpoint = db.Column(db.String(160), nullable=False, default="")
    read_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class EndpointStatus(db.Model):
    """Last outcome per (source, endpoint). A failed read is shown as ERROR on
    the facts it feeds; the old values are never presented as current."""
    __tablename__ = "endpoint_status"
    __table_args__ = (db.UniqueConstraint("source_id", "endpoint", name="uq_endpoint_status"),)
    id = db.Column(db.Integer, primary_key=True)
    source_id = db.Column(db.Integer, db.ForeignKey("sources.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    endpoint = db.Column(db.String(160), nullable=False)
    layers = db.Column(db.String(64), nullable=False, default="")
    ok = db.Column(db.Boolean, nullable=False, default=False)
    absent = db.Column(db.Boolean, nullable=False, default=False)
    error = db.Column(db.Text, nullable=False, default="")
    rows = db.Column(db.Integer, nullable=False, default=0)
    read_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class Job(db.Model):
    __tablename__ = "jobs"
    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(32), nullable=False)
    source_id = db.Column(db.Integer, db.ForeignKey("sources.id", ondelete="SET NULL"))
    status = db.Column(db.String(16), nullable=False, default="running")
    summary = db.Column(db.Text, nullable=False, default="")
    created_by = db.Column(db.String(64), nullable=False, default="")
    started_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    finished_at = db.Column(db.DateTime)
    steps = db.relationship("JobStep", backref="job", order_by="JobStep.id",
                            cascade="all, delete-orphan")


class JobStep(db.Model):
    __tablename__ = "job_steps"
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("jobs.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    at = db.Column(db.DateTime, nullable=False, default=utcnow)
    name = db.Column(db.String(200), nullable=False)
    ok = db.Column(db.Boolean, nullable=False, default=True)
    detail = db.Column(db.Text, nullable=False, default="")
    elapsed_ms = db.Column(db.Integer, nullable=False, default=0)


class Audit(db.Model):
    __tablename__ = "audit"
    id = db.Column(db.Integer, primary_key=True)
    at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    user = db.Column(db.String(64), nullable=False, default="")
    action = db.Column(db.String(64), nullable=False)
    target = db.Column(db.String(200), nullable=False, default="")
    detail = db.Column(db.Text, nullable=False, default="")


def audit(user: str, action: str, target: str = "", detail: str = "") -> None:
    db.session.add(Audit(user=user or "", action=action, target=target[:200], detail=detail))


# ── events, alerts, incidents (phase 8) ───────────────────────────────────────
# An ALERT is one condition of insights.problems() while it holds (opened when
# it first appears, resolved when it is gone); an EVENT is one transition of an
# alert, so the history survives after the condition clears. An INCIDENT is
# the operator's record: alerts are linked to it, it is acknowledged, assigned,
# annotated and resolved by a person — never closed by the platform.

class Incident(db.Model):
    __tablename__ = "incidents"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(16), nullable=False, default="warning")
    status = db.Column(db.String(16), nullable=False, default="open", index=True)
    assignee = db.Column(db.String(64), nullable=False, default="")
    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    acked_by = db.Column(db.String(64), nullable=False, default="")
    acked_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.String(64), nullable=False, default="")
    resolved_at = db.Column(db.DateTime)
    notes = db.relationship("IncidentNote", backref="incident", order_by="IncidentNote.id",
                            cascade="all, delete-orphan")


class IncidentNote(db.Model):
    __tablename__ = "incident_notes"
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id", ondelete="CASCADE"),
                            nullable=False, index=True)
    at = db.Column(db.DateTime, nullable=False, default=utcnow)
    user = db.Column(db.String(64), nullable=False, default="")
    kind = db.Column(db.String(16), nullable=False, default="note")  # note|status|assign|link
    text = db.Column(db.Text, nullable=False, default="")


class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), nullable=False, index=True)
    source_id = db.Column(db.Integer, db.ForeignKey("sources.id", ondelete="SET NULL"))
    severity = db.Column(db.String(16), nullable=False)
    kind = db.Column(db.String(32), nullable=False)
    title = db.Column(db.String(300), nullable=False)
    detail = db.Column(db.Text, nullable=False, default="")
    url = db.Column(db.String(255), nullable=False, default="")
    status = db.Column(db.String(16), nullable=False, default="active", index=True)
    first_seen = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_seen = db.Column(db.DateTime, nullable=False, default=utcnow)
    resolved_at = db.Column(db.DateTime)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id", ondelete="SET NULL"), index=True)
    incident = db.relationship("Incident", backref="alerts")


class Event(db.Model):
    __tablename__ = "events"
    id = db.Column(db.Integer, primary_key=True)
    at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    source_id = db.Column(db.Integer, db.ForeignKey("sources.id", ondelete="SET NULL"))
    kind = db.Column(db.String(24), nullable=False)  # opened|resolved|escalated|deescalated
    severity = db.Column(db.String(16), nullable=False)
    title = db.Column(db.String(300), nullable=False)
    detail = db.Column(db.Text, nullable=False, default="")
