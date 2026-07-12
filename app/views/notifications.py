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


@bp.route("", methods=["GET"])
@bp.route("/", methods=["GET"])
@login_required
def index():
    uid = _me()
    items = notify.recent(uid, limit=100)
    # Capture which are unread BEFORE marking, so they render highlighted once.
    unread_ids = {n.id for n in items if not n.read}
    notify.mark_all_read(uid)
    return render_template("notifications/index.html",
                           notifications=items, unread_ids=unread_ids)


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
