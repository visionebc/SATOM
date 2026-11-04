"""Notifications center — the /notifications page the top-bar bell links to.

Any authenticated user sees their OWN notifications (job completions, bug-report
resolutions, …). Opening the page marks them all read, so the bell badge clears
once the user has looked — the unread highlight for THIS render is captured
before the mark so the just-arrived rows still stand out.
"""
from __future__ import annotations

from flask import (Blueprint, render_template, redirect, url_for, request,
                   flash, jsonify)
from flask_login import login_required, current_user

from ..services import notifications as notify

bp = Blueprint("notifications", __name__, url_prefix="/notifications")


def _me() -> int:
    return getattr(current_user, "id", 0) or 0


#: Severity filter values -> the ``kind`` they select. ``error`` is what the
#: alert engine stores for a CRITICAL finding.
SEVERITIES = [("error", "Critical / error"), ("warning", "Warning"),
              ("info", "Info"), ("success", "Success")]

#: Upper bound on one CSV export.
EXPORT_MAX_ROWS = 20000


def _filters() -> dict:
    a = request.args
    return {"q": a.get("q", "").strip(), "kind": a.get("kind", "").strip(),
            "category": a.get("category", "").strip(),
            "date_from": a.get("date_from", "").strip(),
            "date_to": a.get("date_to", "").strip()}


def _filtered_query(uid: int, f: dict):
    """The user's notifications narrowed by the page's filters — shared by the
    list and the CSV export, so the file holds exactly what the page shows."""
    from datetime import datetime, timedelta
    from sqlalchemy import or_
    from ..models_notifications import Notification
    from ..services.product_scope import scope_query
    from ..services import notification_guide as guide
    from .audit import parse_entry_id

    query = scope_query(Notification.query.filter_by(user_id=uid),
                        Notification.product)
    if f["q"]:
        like = f"%{f['q']}%"
        terms = [Notification.title.ilike(like), Notification.body.ilike(like)]
        nid = parse_entry_id(f["q"])
        if nid is not None:
            terms.append(Notification.id == nid)
        query = query.filter(or_(*terms))
    if f["kind"] in dict(SEVERITIES):
        query = query.filter(Notification.kind == f["kind"])
    if f["category"] and (f["category"] == guide.OTHER
                          or f["category"] in guide.CATEGORY_LABEL):
        query = guide.filter_category(query, Notification.title, f["category"])
    for key, op, extra in (("date_from", "ge", 0), ("date_to", "lt", 1)):
        if f[key]:
            try:
                dt = datetime.strptime(f[key], "%Y-%m-%d") + timedelta(days=extra)
            except ValueError:
                continue
            query = query.filter(Notification.created_at >= dt if op == "ge"
                                 else Notification.created_at < dt)
    return query.order_by(Notification.created_at.desc(), Notification.id.desc())


@bp.route("", methods=["GET"])
@bp.route("/", methods=["GET"])
@login_required
def index():
    from ..services import notification_guide as guide
    from flask_babel import gettext as _gt
    from ..services.user_settings_store import muted_categories
    uid = _me()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        per_page = min(200, max(10, int(request.args.get("per_page", 50))))
    except (TypeError, ValueError):
        per_page = 50
    f = _filters()
    pagination = _filtered_query(uid, f).paginate(page=page, per_page=per_page,
                                                  error_out=False)
    # A gate (Wiki access) can hide a row after it was written; it drops out of
    # the page it would have been on rather than being counted as shown.
    items = [n for n in pagination.items if notify.shown(uid, n)]
    # Capture which are unread BEFORE marking, so they render highlighted once.
    unread_ids = {n.id for n in items if not n.read}
    notify.mark_all_read(uid)
    matched = {n.id: guide.match(n.title) for n in items}
    used = {e["slug"]: guide.public(e) for e in matched.values() if e}
    return render_template(
        "notifications/index.html", notifications=items, unread_ids=unread_ids,
        pagination=pagination, filters=f, severities=SEVERITIES,
        categories=guide.CATEGORIES + [(guide.OTHER, guide.OTHER_LABEL)],
        guide_of={nid: (e["slug"] if e else "") for nid, e in matched.items()},
        category_of={nid: guide.category_label(e["category"] if e else guide.OTHER)
                     for nid, e in matched.items()},
        guide_entries=used, open_id=request.args.get("open", type=int),
        muted_labels=[_gt(guide.category_label(k)) for k, _l in guide.CATEGORIES
                      if k in muted_categories(uid)])


@bp.route("/export.csv", methods=["GET"])
@login_required
def export_csv():
    """The filtered notifications as CSV (same filters as the page)."""
    import csv
    import io
    from flask import Response
    from ..services.csv_safe import spreadsheet_safe
    from ..services import notification_guide as guide
    uid = _me()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "created_utc", "kind", "category", "read", "title", "body", "link"])
    for n in _filtered_query(uid, _filters()).limit(EXPORT_MAX_ROWS):
        if not notify.shown(uid, n):
            continue
        w.writerow([n.id, n.created_at.isoformat(sep=" ") if n.created_at else "",
                    n.kind, guide.category_label(guide.category_of(n.title)),
                    "yes" if n.read else "no"]
                   + [spreadsheet_safe(v) for v in (n.title, n.body, n.link)])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=notifications.csv"})


@bp.route("/guide", methods=["GET"])
@login_required
def guide_page():
    """The manual: every recurring notification, what it means and how to fix
    it, with how often it reached this user in the last 30 days."""
    from datetime import datetime, timedelta
    from sqlalchemy import or_
    from ..models_notifications import Notification
    from ..services.product_scope import scope_query
    from ..services import notification_guide as guide
    uid = _me()
    category = request.args.get("category", "").strip()
    q = request.args.get("q", "").strip()
    rows = guide.entries(category if category in guide.CATEGORY_LABEL else "", q)
    since = datetime.utcnow() - timedelta(days=30)
    base = scope_query(Notification.query.filter_by(user_id=uid)
                       .filter(Notification.created_at >= since),
                       Notification.product)
    counts = {}
    for e in rows:
        try:
            counts[e["slug"]] = base.filter(
                or_(*[Notification.title.like(p) for p in e["patterns"]])).count()
        except Exception:  # noqa: BLE001 — a count never costs the manual
            counts[e["slug"]] = None
    return render_template(
        "notifications/guide.html", entries=rows, counts=counts,
        categories=guide.CATEGORIES, category=category, q=q,
        category_label=guide.category_label)


@bp.route("/unread", methods=["GET"])
@login_required
def unread():
    """Lightweight JSON count for the top-bar bell poller (base.html). Product-
    scoped exactly like the server-rendered badge, so it matches on every ADOM."""
    return jsonify({"count": notify.unread_count(_me())})


@bp.route("/clear", methods=["POST"])
@login_required
def clear():
    notify.clear_all(_me())
    flash("Notifications cleared.", "success")
    return redirect(url_for("notifications.index"))


@bp.route("/dismiss", methods=["POST"])
@login_required
def dismiss():
    """Clear the bell: mark all notifications read so the badge/dropdown empties,
    but KEEP the rows on the /notifications page (unlike /clear which deletes
    them). Redirects back to wherever the user was."""
    notify.mark_all_read(_me())
    dest = request.referrer or url_for("notifications.index")
    return redirect(dest)
