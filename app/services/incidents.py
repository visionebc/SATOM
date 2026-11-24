"""Operational incidents (``SAT-INC-000001``): open, follow, close.

See :mod:`app.models_incidents` for why these are not Sentinel's incidents.
Every change here leaves a history row (who, when, from -> to); nothing is
edited in place without one, and nothing is ever deleted: an incident that
was a mistake is closed with a note saying so.

What the page and the runbook step share lives here, so the two cannot
disagree: who may see an incident (the appliances this session sees -- the
ADOM and maintenance mode, :func:`app.models.visible_appliances`), what a
valid status / severity / link is, and how a run's steps become the summary.
"""
from __future__ import annotations

import re
from datetime import datetime

from ..extensions import db
from ..models_incidents import (OpIncident, OpIncidentEntry, OpVendorTicket,
                                OpVendorTicketEntry, make_ref)


class IncidentError(ValueError):
    """A request the incident cannot take (bad status, empty note...)."""


MAX_TEXT = 4000
#: Steps listed in a run's summary at most (a runbook walks ~40).
MAX_SUMMARY_STEPS = 80
_URL = re.compile(r"https?://[^\s<>\"']{1,490}", re.I)


def _clean(v, n) -> str:
    return str(v if v is not None else "").strip()[:n]


def _now() -> datetime:
    return datetime.utcnow()


def label(value: str) -> str:
    """``waiting_vendor`` -> ``waiting vendor`` (status words on the page)."""
    return str(value or "").replace("_", " ")


# --------------------------------------------------------------------------- #
#  who sees what                                                               #
# --------------------------------------------------------------------------- #
def visible_query(user=None):
    """The incidents this session may see: those of an appliance it sees (its
    ADOM, maintenance mode) and those tied to no appliance. Global sees all
    the appliances, so all the incidents."""
    from ..models import Appliance, visible_appliances
    ids = visible_appliances(user=user).with_entities(Appliance.id)
    return OpIncident.query.filter(db.or_(OpIncident.appliance_id.is_(None),
                                          OpIncident.appliance_id.in_(ids)))


def get_visible(iid, user=None):
    return visible_query(user).filter(OpIncident.id == int(iid)).first()


def for_run(run_id):
    if not run_id:
        return None
    return OpIncident.query.filter_by(run_id=int(run_id)).first()


# --------------------------------------------------------------------------- #
#  history                                                                     #
# --------------------------------------------------------------------------- #
def _entry(inc: OpIncident, user: str, kind: str, text: str) -> OpIncidentEntry:
    e = OpIncidentEntry(incident=inc, user=_clean(user, 64) or "system", kind=kind,
                        text=_clean(text, MAX_TEXT), at=_now())
    db.session.add(e)
    inc.updated_at = e.at
    return e


def summary_from_steps(steps) -> str:
    """A run's steps as the incident keeps them: one line per finished step
    (``key  label: outcome -- detail``). The running row (the step opening
    the incident) is left out."""
    lines = []
    for s in list(steps or [])[:MAX_SUMMARY_STEPS]:
        if not isinstance(s, dict) or s.get("outcome") == "running":
            continue
        detail = " ".join(str(s.get("detail") or "").split())[:240]
        lines.append("%s  %s: %s%s" % (s.get("key") or "?", s.get("label") or "",
                                        s.get("outcome") or "?",
                                        (" -- " + detail) if detail else ""))
    return "\n".join(lines)[:MAX_TEXT * 4]


# --------------------------------------------------------------------------- #
#  open                                                                        #
# --------------------------------------------------------------------------- #
def create(title, *, user, severity="P3", status="open", summary="", appliance=None,
           source="manual", run_id=None, app_slug="", note="") -> OpIncident:
    """Open an incident and give it its ``SAT-INC-`` reference. *status* may
    be ``resolved`` (a runbook that solved the problem still leaves its
    record, operator 2026-11-08: always open one at the end)."""
    title = _clean(title, 200)
    if not title:
        raise IncidentError("an incident needs a title")
    if severity not in OpIncident.SEVERITIES:
        raise IncidentError("%r is not a severity (P1-P4)" % severity)
    if status not in ("open", "resolved"):
        raise IncidentError("a new incident is open or resolved, not %r" % status)
    if source not in OpIncident.SOURCES:
        raise IncidentError("%r is not a source" % source)
    if run_id and for_run(run_id) is not None:
        raise IncidentError("run #%s already opened %s" % (run_id, for_run(run_id).ref))
    now = _now()
    inc = OpIncident(title=title, summary=_clean(summary, MAX_TEXT * 4), status=status,
                     severity=severity, appliance_id=getattr(appliance, "id", None),
                     appliance_name=_clean(getattr(appliance, "name", ""), 128),
                     source=source, run_id=int(run_id) if run_id else None,
                     app_slug=_clean(app_slug, 64), created_by=_clean(user, 64) or "system",
                     created_at=now, updated_at=now,
                     resolved_at=now if status == "resolved" else None)
    db.session.add(inc)
    db.session.flush()
    inc.ref = make_ref(inc.id)
    how = ("by run #%s of %s" % (run_id, app_slug or "an app")) if run_id else "by hand"
    _entry(inc, user, "created", "opened %s as %s, %s%s" % (
        how, label(status), severity, (": " + _clean(note, 1000)) if note else ""))
    db.session.commit()
    return inc


# --------------------------------------------------------------------------- #
#  change                                                                      #
# --------------------------------------------------------------------------- #
def set_status(inc: OpIncident, status: str, *, user, note="") -> bool:
    """Move the incident; False when it already was there. Resolving or
    closing stamps the time; reopening clears it."""
    if status not in OpIncident.STATUSES:
        raise IncidentError("%r is not a status" % status)
    if status == inc.status:
        return False
    old, now = inc.status, _now()
    inc.status = status
    if status in OpIncident.OPEN_STATUSES:
        inc.resolved_at = inc.closed_at = None
    elif status == "resolved":
        inc.resolved_at, inc.closed_at = now, None
    else:  # closed
        inc.resolved_at = inc.resolved_at or now
        inc.closed_at = now
    _entry(inc, user, "status", "status %s -> %s%s" % (
        label(old), label(status), (": " + _clean(note, 1000)) if _clean(note, 1000) else ""))
    db.session.commit()
    return True


def set_severity(inc: OpIncident, severity: str, *, user) -> bool:
    if severity not in OpIncident.SEVERITIES:
        raise IncidentError("%r is not a severity (P1-P4)" % severity)
    if severity == inc.severity:
        return False
    _entry(inc, user, "severity", "severity %s -> %s" % (inc.severity, severity))
    inc.severity = severity
    db.session.commit()
    return True


def set_owner(inc: OpIncident, owner: str, *, user) -> bool:
    owner = _clean(owner, 64)
    if owner:
        from ..models import User
        if User.query.filter_by(username=owner).first() is None:
            raise IncidentError("%r is not a SATOM user" % owner)
    if owner == (inc.owner or ""):
        return False
    _entry(inc, user, "owner", "owner %s -> %s" % (inc.owner or "nobody", owner or "nobody"))
    inc.owner = owner
    db.session.commit()
    return True


def add_note(inc: OpIncident, text: str, *, user) -> OpIncidentEntry:
    text = _clean(text, MAX_TEXT)
    if not text:
        raise IncidentError("the note is empty")
    e = _entry(inc, user, "note", text)
    db.session.commit()
    return e


# --------------------------------------------------------------------------- #
#  vendor / L3 tickets                                                         #
# --------------------------------------------------------------------------- #
def clean_url(raw) -> str:
    """A ticket link: http(s) only, or "" -- it is drawn as a link, and a
    ``javascript:`` one would run in the operator's session."""
    s = _clean(raw, 500)
    if not s:
        return ""
    if not _URL.fullmatch(s):
        raise IncidentError("the ticket link must start with http:// or https://")
    return s


def add_vendor_ticket(inc: OpIncident, vendor: str, *, user, ticket_no="", url="",
                      note="") -> OpVendorTicket:
    vendor = _clean(vendor, 64)
    if not vendor:
        raise IncidentError("say who the ticket is with (vendor or L3)")
    t = OpVendorTicket(incident=inc, vendor=vendor, ticket_no=_clean(ticket_no, 64),
                       url=clean_url(url), status="open", created_by=_clean(user, 64) or "system",
                       created_at=_now(), updated_at=_now())
    db.session.add(t)
    first = "ticket %s opened" % (t.ticket_no or "(no number yet)")
    db.session.add(OpVendorTicketEntry(ticket=t, user=t.created_by, at=t.created_at,
                                       text=first + ((": " + _clean(note, MAX_TEXT)) if
                                                     _clean(note, MAX_TEXT) else "")))
    _entry(inc, user, "vendor", "%s: %s" % (vendor, first))
    db.session.commit()
    return t


def update_vendor_ticket(t: OpVendorTicket, *, user, status=None, text="",
                         ticket_no=None) -> OpVendorTicketEntry:
    """One line in the ticket's history: what the vendor or L3 said or did,
    a status change, a ticket number that arrived later -- or all three."""
    parts = []
    if ticket_no is not None and _clean(ticket_no, 64) != (t.ticket_no or ""):
        parts.append("ticket number %s -> %s" % (t.ticket_no or "none", _clean(ticket_no, 64) or "none"))
        t.ticket_no = _clean(ticket_no, 64)
    if status:
        if status not in OpVendorTicket.STATUSES:
            raise IncidentError("%r is not a ticket status" % status)
        if status != t.status:
            parts.append("status %s -> %s" % (label(t.status), label(status)))
            t.status = status
    text = _clean(text, MAX_TEXT)
    if text:
        parts.append(text)
    if not parts:
        raise IncidentError("nothing to record: write what happened or change the status")
    e = OpVendorTicketEntry(ticket=t, user=_clean(user, 64) or "system", at=_now(),
                            text="; ".join(parts))
    db.session.add(e)
    t.updated_at = e.at
    _entry(t.incident, user, "vendor", "%s %s: %s" % (t.vendor, t.ticket_no or "", e.text))
    db.session.commit()
    return e


# --------------------------------------------------------------------------- #
#  the runbook step                                                            #
# --------------------------------------------------------------------------- #
def open_from_run(*, run_id, user, title, severity, status, appliance=None, steps=(),
                  app_slug="", note="") -> tuple[OpIncident, bool]:
    """``(incident, created)``: the run's incident, opened now or -- when the
    step is walked again for the same run -- the one it already opened."""
    got = for_run(run_id)
    if got is not None:
        return got, False
    return create(title, user=user, severity=severity, status=status,
                  summary=summary_from_steps(steps), appliance=appliance,
                  source="runbook", run_id=run_id, app_slug=app_slug, note=note), True
