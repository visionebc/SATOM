"""Reusable logic for user bug reports: create, resolve, routing, counts.

Kept free of HTTP/request state so it is unit-testable. Notification
side-effects (email) are best-effort and live in notify_* helpers that the
view calls after a successful DB commit.
"""
from __future__ import annotations

from datetime import datetime

from ..models import db, BugReport, User, UserSetting

# Per-user opt-in flag (UserSetting key). Value "1" == opted in.
OPT_IN_KEY = "bug_reports.notify"


# --- opt-in ------------------------------------------------------------------

def is_opted_in(user_id: int) -> bool:
    return UserSetting.get(user_id, OPT_IN_KEY, "0") == "1"


def set_opted_in(user_id: int, on: bool) -> None:
    UserSetting.set(user_id, OPT_IN_KEY, "1" if on else "0")


def opted_in_admins() -> list[User]:
    """Admin-capable users who opted in to bug-report notifications."""
    admins = [u for u in User.query.filter_by(is_active=True).all()
              if u.can("user_manage")]
    return [u for u in admins if is_opted_in(u.id)]


# --- create / resolve --------------------------------------------------------

def create_report(user: User, title: str, body: str,
                  page_url: str | None, user_agent: str | None) -> BugReport:
    r = BugReport(
        reporter_id=user.id,
        reporter_username=user.username,
        title=(title or "").strip()[:200],
        body=(body or "").strip(),
        page_url=(page_url or None),
        user_agent=(user_agent or None),
    )
    db.session.add(r)
    db.session.commit()
    return r


def resolve_report(report: BugReport, admin: User, note: str | None) -> BugReport:
    report.status = BugReport.STATUS_RESOLVED
    report.resolved_by_id = admin.id
    report.resolved_at = datetime.utcnow()
    report.resolution_note = (note or "").strip() or None
    report.reporter_seen = False
    db.session.commit()
    return report


# --- queries / counts --------------------------------------------------------

def open_reports() -> list[BugReport]:
    return (BugReport.query
            .filter_by(status=BugReport.STATUS_OPEN)
            .order_by(BugReport.created_at.desc(), BugReport.id.desc())
            .all())


def open_count() -> int:
    return BugReport.query.filter_by(status=BugReport.STATUS_OPEN).count()


def unseen_resolved_count(user_id: int) -> int:
    return (BugReport.query
            .filter_by(reporter_id=user_id,
                       status=BugReport.STATUS_RESOLVED,
                       reporter_seen=False)
            .count())


def mark_reporter_seen(user_id: int) -> int:
    rows = (BugReport.query
            .filter_by(reporter_id=user_id,
                       status=BugReport.STATUS_RESOLVED,
                       reporter_seen=False)
            .all())
    for r in rows:
        r.reporter_seen = True
    db.session.commit()
    return len(rows)


# --- notification bodies (pure text; sending is done by the view) -----------

def new_report_email(report: BugReport) -> tuple[str, str]:
    subject = f"[Bug Report] {report.title}"
    body = (
        f"{report.reporter_username} filed a bug report.\n\n"
        f"Title: {report.title}\n"
        f"Page: {report.page_url or '(not captured)'}\n"
        f"Browser: {report.user_agent or '(not captured)'}\n\n"
        f"Description:\n{report.body}\n"
    )
    return subject, body


def resolved_email(report: BugReport) -> tuple[str, str]:
    subject = f"[Bug Report Resolved] {report.title}"
    note = report.resolution_note or "(no note)"
    body = (
        f"Your bug report has been marked as resolved.\n\n"
        f"Title: {report.title}\n"
        f"Resolution note:\n{note}\n"
    )
    return subject, body
