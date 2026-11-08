"""Operations › Incidents: SATOM's own tickets (``SAT-INC-000001``).

The list is searched and filtered in the database from the query string (a
filtered list is a bookmark), scoped to the appliances this session sees
(:func:`app.services.incidents.visible_query`). One incident's page carries
its history, the run that opened it and its tickets with a vendor or L3,
each with its own history.

Reading needs ``operations.view``; every change ``operations.apply``, and each
one writes the incident's history AND the audit log. A render never touches
an appliance: everything here is the database.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..extensions import db
from ..models import Appliance, User, visible_appliances
from ..models_incidents import OpIncident, OpVendorTicket
from ..services import incidents as svc
from ..services.audit import log_action

bp = Blueprint("incidents", __name__, url_prefix="/incidents")

PER_PAGE = 50
#: the "Active" filter: every status somebody still works on
ACTIVE = "active"
STATUS_BADGE = {"open": "fw-badge-danger", "in_progress": "fw-badge-warning",
                "waiting_vendor": "fw-badge-info", "resolved": "fw-badge-success",
                "closed": "fw-badge-secondary"}
SEVERITY_BADGE = {"P1": "fw-badge-danger", "P2": "fw-badge-warning", "P3": "fw-badge-info",
                  "P4": "fw-badge-secondary"}


def _who() -> str:
    return getattr(current_user, "username", "") or "system"


def _or_404(iid) -> OpIncident:
    inc = svc.get_visible(iid)
    if inc is None:
        abort(404)
    return inc


def _filters() -> dict:
    a = request.args
    return {k: (a.get(k) or "").strip() for k in
            ("q", "status", "severity", "device", "source", "date_from", "date_to")}


def _date(raw):
    try:
        return datetime.strptime(raw, "%Y-%m-%d")
    except (TypeError, ValueError):
        return None


def _apply(q, f: dict, skip_status=False):
    if f["q"]:
        like = "%" + f["q"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        q = q.filter(db.or_(OpIncident.ref.ilike(like, escape="\\"),
                            OpIncident.title.ilike(like, escape="\\"),
                            OpIncident.appliance_name.ilike(like, escape="\\"),
                            OpIncident.summary.ilike(like, escape="\\"),
                            OpIncident.owner.ilike(like, escape="\\"),
                            OpIncident.vendor_tickets.any(OpVendorTicket.ticket_no.ilike(
                                like, escape="\\"))))
    if not skip_status and f["status"]:
        if f["status"] == ACTIVE:
            q = q.filter(OpIncident.status.in_(OpIncident.OPEN_STATUSES))
        elif f["status"] in OpIncident.STATUSES:
            q = q.filter(OpIncident.status == f["status"])
    if f["severity"] in OpIncident.SEVERITIES:
        q = q.filter(OpIncident.severity == f["severity"])
    if f["device"].isdigit():
        q = q.filter(OpIncident.appliance_id == int(f["device"]))
    if f["source"] in OpIncident.SOURCES:
        q = q.filter(OpIncident.source == f["source"])
    d0, d1 = _date(f["date_from"]), _date(f["date_to"])
    if d0:
        q = q.filter(OpIncident.created_at >= d0)
    if d1:
        q = q.filter(OpIncident.created_at < d1 + timedelta(days=1))
    return q


@bp.route("/")
@login_required
@require_permission("operations.view")
def index():
    f = _filters()
    base = svc.visible_query()
    counts = dict(_apply(base, f, skip_status=True)
                  .with_entities(OpIncident.status, db.func.count(OpIncident.id))
                  .group_by(OpIncident.status).all())
    try:
        page = max(1, int(request.args.get("page") or 1))
    except ValueError:
        page = 1
    pagination = (_apply(base, f).order_by(OpIncident.created_at.desc(), OpIncident.id.desc())
                  .paginate(page=page, per_page=PER_PAGE, error_out=False))
    devices = (visible_appliances().with_entities(Appliance.id, Appliance.name)
               .order_by(Appliance.name).all())
    filtering = any(f.values())
    return render_template("incidents/index.html", items=pagination.items,
                           pagination=pagination, filters=f, filtering=filtering,
                           counts=counts, active_count=sum(counts.get(s, 0) for s in
                                                           OpIncident.OPEN_STATUSES),
                           statuses=OpIncident.STATUSES, severities=OpIncident.SEVERITIES,
                           sources=OpIncident.SOURCES, devices=devices, ACTIVE=ACTIVE,
                           status_badge=STATUS_BADGE, severity_badge=SEVERITY_BADGE,
                           label=svc.label)


@bp.route("/new", methods=["POST"])
@login_required
@require_permission("operations.apply")
def create():
    form = request.form
    appliance = None
    raw = (form.get("appliance_id") or "").strip()
    if raw:
        if not raw.isdigit():
            abort(400)
        appliance = visible_appliances().filter(Appliance.id == int(raw)).first()
        if appliance is None:
            abort(404)
    try:
        inc = svc.create(form.get("title"), user=_who(), severity=form.get("severity") or "P3",
                         summary=form.get("summary") or "", appliance=appliance,
                         note=form.get("note") or "")
    except svc.IncidentError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("incidents.index"))
    log_action("incident.create", target=inc.ref, extra={"severity": inc.severity,
                                                          "appliance": inc.appliance_name})
    flash("%s opened." % inc.ref, "success")
    return redirect(url_for("incidents.detail", iid=inc.id))


@bp.route("/<int:iid>")
@login_required
@require_permission("operations.view")
def detail(iid):
    inc = _or_404(iid)
    run = None
    if inc.run_id:
        from ..models_studio import StudioAppRun
        run = db.session.get(StudioAppRun, inc.run_id)
    users = [u for (u,) in User.query.filter(User.is_active.is_(True))
             .with_entities(User.username).order_by(User.username).all()]
    may_edit = current_user.can("operations.apply")
    return render_template("incidents/detail.html", inc=inc, run=run, users=users,
                           may_edit=may_edit, statuses=OpIncident.STATUSES,
                           severities=OpIncident.SEVERITIES,
                           ticket_statuses=OpVendorTicket.STATUSES,
                           status_badge=STATUS_BADGE, severity_badge=SEVERITY_BADGE,
                           label=svc.label)


def _change(iid, fn, action):
    inc = _or_404(iid)
    try:
        detail = fn(inc)
    except svc.IncidentError as exc:
        flash(str(exc), "danger")
    else:
        if detail is not None:
            log_action(action, target=inc.ref, extra=detail)
    return redirect(url_for("incidents.detail", iid=inc.id))


@bp.route("/<int:iid>/status", methods=["POST"])
@login_required
@require_permission("operations.apply")
def status(iid):
    want, note = request.form.get("status") or "", request.form.get("note") or ""

    def fn(inc):
        old = inc.status
        return {"from": old, "to": want} if svc.set_status(inc, want, user=_who(),
                                                           note=note) else None
    return _change(iid, fn, "incident.status")


@bp.route("/<int:iid>/severity", methods=["POST"])
@login_required
@require_permission("operations.apply")
def severity(iid):
    want = request.form.get("severity") or ""

    def fn(inc):
        old = inc.severity
        return {"from": old, "to": want} if svc.set_severity(inc, want, user=_who()) else None
    return _change(iid, fn, "incident.severity")


@bp.route("/<int:iid>/owner", methods=["POST"])
@login_required
@require_permission("operations.apply")
def owner(iid):
    want = request.form.get("owner") or ""

    def fn(inc):
        old = inc.owner
        return {"from": old, "to": want} if svc.set_owner(inc, want, user=_who()) else None
    return _change(iid, fn, "incident.owner")


@bp.route("/<int:iid>/note", methods=["POST"])
@login_required
@require_permission("operations.apply")
def note(iid):
    text = request.form.get("text") or ""

    def fn(inc):
        e = svc.add_note(inc, text, user=_who())
        return {"entry": e.id}
    return _change(iid, fn, "incident.note")


@bp.route("/<int:iid>/vendor", methods=["POST"])
@login_required
@require_permission("operations.apply")
def vendor_add(iid):
    f = request.form

    def fn(inc):
        t = svc.add_vendor_ticket(inc, f.get("vendor") or "", user=_who(),
                                  ticket_no=f.get("ticket_no") or "", url=f.get("url") or "",
                                  note=f.get("note") or "")
        return {"vendor": t.vendor, "ticket": t.ticket_no}
    return _change(iid, fn, "incident.vendor_ticket")


@bp.route("/<int:iid>/vendor/<int:tid>", methods=["POST"])
@login_required
@require_permission("operations.apply")
def vendor_update(iid, tid):
    f = request.form

    def fn(inc):
        t = OpVendorTicket.query.filter_by(id=tid, incident_id=inc.id).first()
        if t is None:
            abort(404)
        e = svc.update_vendor_ticket(t, user=_who(), status=f.get("status") or None,
                                     text=f.get("text") or "",
                                     ticket_no=f.get("ticket_no") if "ticket_no" in f else None)
        return {"vendor": t.vendor, "ticket": t.ticket_no, "entry": e.id}
    return _change(iid, fn, "incident.vendor_update")
