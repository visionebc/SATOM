"""User bug reports: submit (any user), inbox + resolve (admins), mark-seen."""
from __future__ import annotations

import logging

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, abort)
from flask_login import login_required, current_user

from ..models import db, BugReport
from ..auth.decorators import require_permission
from ..services import bug_reports as svc

logger = logging.getLogger(__name__)

bp = Blueprint("reports", __name__, url_prefix="/reports")


def _notify_admins_new(report: BugReport) -> None:
    """Email opted-in admins about a new report. Best-effort, never raises."""
    try:
        from ..services import email_service
        recipients = []
        for a in svc.opted_in_admins():
            addr = getattr(a, "recovery_email", None)
            if addr:
                recipients.append(addr)
        if not recipients:
            return
        subject, body = svc.new_report_email(report)
        email_service.send_email(recipients, subject, body)
    except Exception:  # pragma: no cover - notification must never break submit
        logger.exception("bug-report admin notify failed")


def _notify_reporter_resolved(report: BugReport) -> None:
    """Email the original reporter that their report was resolved."""
    try:
        from ..services import email_service
        reporter = report.reporter
        addr = getattr(reporter, "recovery_email", None) if reporter else None
        if not addr:
            return
        subject, body = svc.resolved_email(report)
        email_service.send_email(addr, subject, body)
    except Exception:  # pragma: no cover
        logger.exception("bug-report reporter notify failed")


@bp.route("", methods=["POST"])
@bp.route("/", methods=["POST"])
@login_required
def submit():
    title = (request.form.get("title") or "").strip()
    body = (request.form.get("body") or "").strip()
    if not title:
        flash("Please enter a short title for the problem.", "warning")
        return redirect(request.referrer or url_for("index"))
    report = svc.create_report(
        current_user,
        title,
        body,
        request.form.get("page_url"),
        request.form.get("user_agent"),
    )
    _notify_admins_new(report)
    flash("Thanks — your report was sent to the administrators.", "success")
    return redirect(request.referrer or url_for("index"))


@bp.route("", methods=["GET"])
@bp.route("/", methods=["GET"])
@login_required
@require_permission("user_manage")
def inbox():
    open_list = svc.open_reports()
    resolved_list = (BugReport.query
                     .filter_by(status=BugReport.STATUS_RESOLVED)
                     .order_by(BugReport.resolved_at.desc())
                     .limit(50).all())
    return render_template("reports/inbox.html",
                           open_reports=open_list,
                           resolved_reports=resolved_list)


@bp.route("/<int:report_id>/resolve", methods=["POST"])
@login_required
@require_permission("user_manage")
def resolve(report_id: int):
    report = BugReport.query.get_or_404(report_id)
    if report.status == BugReport.STATUS_RESOLVED:
        flash("That report is already resolved.", "info")
        return redirect(url_for("reports.inbox"))
    note = request.form.get("note")
    svc.resolve_report(report, current_user, note)
    _notify_reporter_resolved(report)
    flash("Report marked as resolved. The reporter has been notified.", "success")
    return redirect(url_for("reports.inbox"))


@bp.route("/mine/seen", methods=["POST"])
@login_required
def mark_mine_seen():
    svc.mark_reporter_seen(current_user.id)
    return redirect(request.referrer or url_for("index"))
