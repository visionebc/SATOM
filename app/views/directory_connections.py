"""Administrator > Access > Directory connections and App sign-in.

* **Directory connections** -- the AD / LDAP / RADIUS servers an app's sign-in
  may prove people against (services.directory_connections). Secrets are
  write-only here: the page learns ``has_secret``, never the value.
* **App sign-in** -- per app: who may use it (users and groups, the same list
  as Plugin Studio > app > Settings; for a script app the only one), its own
  sign-in page and its rules (services.app_signin), and the people a sign-in
  has granted it to, each revocable.

Gated on user management, like Users and Groups: both decide who gets in.
"""
from __future__ import annotations

from flask import Blueprint, abort, jsonify, render_template, request, url_for
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..extensions import db
from ..models import Permission, Profile, User
from ..models_studio import StudioApp, UserGroup
from ..services import app_signin as AS
from ..services import directory_connections as DC
from ..services import studio_apps as SA
from ..services.audit import log_action

bp = Blueprint("directory_connections", __name__, url_prefix="/access")


def _who() -> str:
    return getattr(current_user, "username", "?")


def _err(exc, code=400):
    return jsonify({"ok": False, "error": str(exc)}), code


# --------------------------------------------------------------------------- #
#  directory connections                                                       #
# --------------------------------------------------------------------------- #
@bp.route("/directory-connections/")
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    conns = [DC.public(c) for c in DC.all_connections()]
    return render_template("directory_connections/index.html", conns=conns,
                           kinds=[(k, DC.KIND_LABELS[k]) for k in DC.KINDS])


@bp.route("/directory-connections/save", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def save():
    body = request.get_json(silent=True) or {}
    cid = body.get("id")
    c = DC.get(cid) if cid else None
    if cid and c is None:
        return _err("connection not found", 404)
    try:
        c = DC.save(c, body, _who())
    except DC.ConnectionError_ as exc:
        db.session.rollback()
        return _err(exc)
    log_action("directory_connection.%s" % ("update" if cid else "create"), target=c.slug,
               extra={"kind": c.kind, "host": c.cfg.get("host", ""), "enabled": c.enabled,
                      "secret_changed": bool(body.get("secret"))})
    return jsonify({"ok": True, "id": c.id})


@bp.route("/directory-connections/<int:cid>/test", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def test(cid):
    c = DC.get(cid) or abort(404)
    body = request.get_json(silent=True) or {}
    username = str(body.get("username") or "").strip()
    ok, detail = DC.test(c, username, str(body.get("password") or ""))
    log_action("directory_connection.test", target=c.slug,
               extra={"ok": ok, "with_user": bool(username), "detail": detail[:300]})
    return jsonify({"ok": ok, "detail": detail})


@bp.route("/directory-connections/<int:cid>/delete", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete(cid):
    c = DC.get(cid) or abort(404)
    slug = c.slug
    try:
        DC.delete(c)
    except DC.ConnectionError_ as exc:
        db.session.rollback()
        return _err(exc)
    log_action("directory_connection.delete", target=slug)
    return jsonify({"ok": True})


# --------------------------------------------------------------------------- #
#  app sign-in                                                                 #
# --------------------------------------------------------------------------- #
def _apps():
    try:
        SA.adopt_scripts(_who())  # a script made before its app existed
    except Exception:  # noqa: BLE001 -- a read-only standby cannot write; list what is there
        db.session.rollback()
    return StudioApp.query.order_by(StudioApp.name).all()


@bp.route("/app-signin/")
@login_required
@require_permission(Permission.USER_MANAGE)
def signin_index():
    rows = []
    for a in _apps():
        pol = AS.policy_of(a)
        rows.append({"a": a, "policy": pol, "open": AS.is_open(a),
                     "grants": len(AS.grants_of_app(a)),
                     "runnable": SA._runnable_app(a)})
    return render_template("directory_connections/signin_index.html", rows=rows)


@bp.route("/app-signin/<slug>")
@login_required
@require_permission(Permission.USER_MANAGE)
def signin_edit(slug):
    a = SA.get(slug) or abort(404)
    pol = AS.policy_of(a)
    conns = [{"id": c.id, "slug": c.slug, "name": c.name, "kind": c.kind,
              "kind_label": DC.KIND_LABELS.get(c.kind, c.kind), "enabled": bool(c.enabled)}
             for c in DC.all_connections()]
    profiles = [p for p in Profile.query.order_by(Profile.name).all() if p.is_apps_only]
    return render_template(
        "directory_connections/signin_edit.html", a=a, policy=pol, conns=conns,
        apps_profiles=profiles, grants=AS.grants_of_app(a),
        groups=UserGroup.query.order_by(UserGroup.name).all(),
        users=User.query.filter_by(is_active=True).order_by(User.username).all(),
        open=AS.is_open(a), runnable=SA._runnable_app(a),
        login_url=url_for("apps_portal.entry", slug=a.slug, _external=True))


@bp.route("/app-signin/<slug>/save", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def signin_save(slug):
    a = SA.get(slug) or abort(404)
    body = request.get_json(silent=True) or {}
    try:
        if "access" in body:
            SA.set_access(a, body.get("access") or {})
        pol = AS.save_policy(a, body.get("policy") or {})
    except (AS.PolicyError, SA.AppError) as exc:
        db.session.rollback()
        return _err(exc)
    log_action("app.signin.save", target=slug,
               extra={"enabled": pol["enabled"], "access": a.access,
                      "rules": [{"connection": r["connection_id"],
                                 "require_2fa": r["require_2fa"]} for r in pol["rules"]],
                      "profile_id": pol["profile_id"],
                      "require_approval": pol["require_approval"]})
    return jsonify({"ok": True})


@bp.route("/app-signin/<slug>/grants/<int:uid>/revoke", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def signin_revoke(slug, uid):
    a = SA.get(slug) or abort(404)
    u = db.session.get(User, uid)
    if not AS.revoke(a, uid):
        return _err("no such grant", 404)
    log_action("app.grant.revoke", target=slug,
               extra={"user": u.username if u else uid, "by": "administrator"})
    return jsonify({"ok": True})
