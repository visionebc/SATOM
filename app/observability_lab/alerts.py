"""Alerts and events from the problems the platform already derives
(:func:`insights.problems`), and the incident record operators keep.

``evaluate()`` runs after every collector pass (and when the Events page is
opened on the primary): a problem that appears opens an alert + an ``opened``
event; the same condition changing severity is one ``escalated`` /
``deescalated`` event on the same alert; a problem that is gone resolves its
alert. Nothing here talks to a device. On a read-only standby nothing is
written (the alerts arrive by replication)."""
from __future__ import annotations

from . import insights
from .extensions import db
from .models import Alert, Event, Incident, IncidentNote, Source, utcnow

SEVERITIES = ("critical", "warning")
INCIDENT_STATUSES = ("open", "acknowledged", "resolved")

#: The built-in rules, as the Events page lists them (what opens an alert).
RULES = [
    ("source", "critical / warning", "A source's collection fails (critical) or its data is older than "
                                      "3 collection intervals (warning)."),
    ("read", "critical", "One read of a source fails (the facts it feeds are shown as ERROR)."),
    ("licence", "critical", "The device reports an invalid licence (FortiGate licence_valid = false, "
                            "FortiWeb vmLicense = invalid)."),
    ("resource", "warning / critical", "CPU >= %d / %d %%, memory >= %d / %d %%, disk >= %d / %d %% (devices "
                                       "that report it)." % tuple(
                                           v for k in ("cpu_pct", "mem_pct", "disk_pct")
                                           for v in insights.RESOURCE_RULES[k][1:])),
    ("policy", "warning / critical", "A server policy has back-ends down (warning) or every back-end down "
                                     "(critical), by the device's health check."),
    ("interface", "critical", "An interface is administratively up without link."),
]


def evaluate(now=None) -> dict:
    """Bring the alerts in line with the current problems. Returns counts."""
    now = now or utcnow()
    current = {p["key"]: p for p in insights.problems(Source.query.all())}
    active = {a.key: a for a in Alert.query.filter_by(status="active")}
    opened = resolved = changed = 0
    for key, p in current.items():
        a = active.get(key)
        if a is None:
            a = Alert(key=key[:255], source_id=p["source_id"], severity=p["severity"], kind=p["kind"],
                      title=p["title"][:300], detail=p["detail"], url=p["url"][:255],
                      status="active", first_seen=now, last_seen=now)
            db.session.add(a)
            db.session.flush()
            db.session.add(Event(at=now, alert_id=a.id, source_id=a.source_id, kind="opened",
                                 severity=a.severity, title=a.title, detail=a.detail))
            opened += 1
            continue
        a.last_seen = now
        if a.severity != p["severity"]:
            kind = "escalated" if p["severity"] == "critical" else "deescalated"
            db.session.add(Event(at=now, alert_id=a.id, source_id=a.source_id, kind=kind,
                                 severity=p["severity"], title=p["title"][:300],
                                 detail="%s → %s · %s" % (a.severity, p["severity"], p["detail"])))
            a.severity = p["severity"]
            changed += 1
        a.title, a.detail = p["title"][:300], p["detail"]
    for key, a in active.items():
        if key in current:
            continue
        a.status, a.resolved_at = "resolved", now
        db.session.add(Event(at=now, alert_id=a.id, source_id=a.source_id, kind="resolved",
                             severity=a.severity, title=a.title, detail="condition no longer present"))
        if a.incident_id and a.incident and a.incident.status != "resolved":
            db.session.add(IncidentNote(incident_id=a.incident_id, at=now, user="", kind="link",
                                        text="Linked alert resolved by itself: %s" % a.title))
        resolved += 1
    db.session.commit()
    return {"opened": opened, "resolved": resolved, "changed": changed, "active": len(current)}


def duration_s(a: Alert, now=None) -> int:
    end = a.resolved_at or now or utcnow()
    return max(0, int((end - a.first_seen).total_seconds()))


# ── incidents ────────────────────────────────────────────────────────────────

def open_incident(user: str, title: str, alert_ids=(), assignee: str = "") -> Incident:
    alerts = Alert.query.filter(Alert.id.in_(list(alert_ids))).all() if alert_ids else []
    sev = "critical" if any(a.severity == "critical" for a in alerts) else "warning"
    inc = Incident(title=(title or (alerts[0].title if alerts else "Incident"))[:200], severity=sev,
                   created_by=user, assignee=assignee[:64])
    db.session.add(inc)
    db.session.flush()
    inc.notes.append(IncidentNote(user=user, kind="status", text="Opened"))
    for a in alerts:
        a.incident_id = inc.id
        inc.notes.append(IncidentNote(user=user, kind="link", text="Linked alert: %s" % a.title))
    if assignee:
        inc.notes.append(IncidentNote(user=user, kind="assign", text="Assigned to %s" % assignee[:64]))
    return inc


def set_status(inc: Incident, status: str, user: str) -> bool:
    if status not in INCIDENT_STATUSES or status == inc.status:
        return False
    now = utcnow()
    if status == "acknowledged" and not inc.acked_at:
        inc.acked_at, inc.acked_by = now, user
    if status == "resolved":
        inc.resolved_at, inc.resolved_by = now, user
        if not inc.acked_at:
            inc.acked_at, inc.acked_by = now, user
    if status == "open":  # reopened
        inc.resolved_at, inc.resolved_by = None, ""
    inc.notes.append(IncidentNote(user=user, kind="status", text={
        "acknowledged": "Acknowledged", "resolved": "Resolved", "open": "Reopened"}[status]))
    inc.status = status
    return True


def incident_stats(incidents) -> dict:
    """MTTA / MTTR in seconds over the given incidents (None when none qualify)."""
    acks = [(i.acked_at - i.created_at).total_seconds() for i in incidents if i.acked_at]
    fixes = [(i.resolved_at - i.created_at).total_seconds() for i in incidents if i.resolved_at]
    return {"mtta_s": int(sum(acks) / len(acks)) if acks else None,
            "mttr_s": int(sum(fixes) / len(fixes)) if fixes else None,
            "acked": len(acks), "resolved": len(fixes), "total": len(list(incidents))}
