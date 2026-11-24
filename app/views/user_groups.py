"""Administrator > Access > Groups -- named sets of users.

A group is who an app is shared with (Python Studio apps, ``access``) and who
reads a Wiki article (its audience), so an administrator grants an app or an
article to "Network operations" once instead of person by person, and a new
colleague gets every app and article of the team by joining it. Gated on user
management, like the user list: membership decides access, so it is not a
Wiki moderator's or an app author's to change.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request
from flask_login import login_required

from ..auth.decorators import require_permission
from ..extensions import db
from ..models import Permission, User
from ..models_studio import UserGroup
from ..services import studio_apps as SA
from ..services import wiki as WK
from ..services.audit import log_action

bp = Blueprint("user_groups", __name__, url_prefix="/groups")


@bp.route("/")
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    groups = UserGroup.query.order_by(UserGroup.name).all()
    return render_template("user_groups/index.html", groups=groups,
                           users=User.query.order_by(User.username).all(),
                           used={g.id: SA.apps_using_group(g.id) for g in groups},
                           wiki_used={g.id: WK.articles_using_group(g.id) for g in groups},
                           gdata={str(g.id): {"name": g.name, "description": g.description,
                                              "members": [u.id for u in g.members]} for g in groups})


@bp.route("/save", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def save():
    body = request.get_json(silent=True) or {}
    gid = body.get("id")
    group = db.session.get(UserGroup, int(gid)) if str(gid or "").isdigit() else None
    if gid and group is None:
        return jsonify({"ok": False, "error": "group not found"}), 404
    try:
        g = SA.save_group(group, body.get("name") or "", body.get("description") or "",
                          body.get("members") or [])
    except SA.AppError as exc:
        db.session.rollback()
        return jsonify({"ok": False, "error": str(exc)}), 400
    log_action("user_group.save", target=g.name,
               extra={"id": g.id, "members": [u.username for u in g.members]})
    return jsonify({"ok": True, "id": g.id})


@bp.route("/<int:gid>/delete", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete(gid):
    g = db.session.get(UserGroup, gid)
    if g is None:
        return jsonify({"ok": False, "error": "group not found"}), 404
    apps = SA.apps_using_group(gid)
    if apps:
        return jsonify({"ok": False, "error": "apps share with this group: %s. Remove it there "
                        "first." % ", ".join(apps)}), 409
    name = g.name
    # Wiki articles naming it stay restricted (fail closed), see wiki_access.
    articles = WK.articles_using_group(gid)
    db.session.delete(g)
    db.session.commit()
    log_action("user_group.delete", target=name, extra={"wiki_articles": articles})
    return jsonify({"ok": True})
