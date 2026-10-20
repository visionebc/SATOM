"""Operations > Plugins > <app> -- the operator's side of Python Studio apps.

An app is opened from its own menu entry (``services.studio_apps.menu``),
runs its PUBLISHED version with the operator's form values, shows the output
and offers the app's actions on it. Who may open it is the app's access list
(users and user groups, plus Studio authors); where, the ADOMs its author
ticked. Both are answered by ``services.studio_apps``, never here.
"""
from __future__ import annotations

from flask import Blueprint, Response, abort, jsonify, render_template, request
from flask_login import current_user, login_required

from ..extensions import db
from ..models_studio import StudioApp, StudioAppRun
from ..services import studio_apps as SA
from ..services.audit import log_action

bp = Blueprint("apps", __name__, url_prefix="/apps")


def _product_key() -> str:
    from flask import g, session
    from ..branding import get_product
    return get_product(getattr(g, "product", None) or session.get("product"))["key"]


def _usable_or_404(slug) -> StudioApp:
    """404, not 403, for an app the user may not use: its name is not theirs
    to learn either."""
    a = SA.get(slug)
    if a is None or not SA.can_use(current_user, a):
        abort(404)
    if not SA.is_author(current_user) and (a.status != "published" or not a.published
                                           or not SA.shown_in(a, _product_key())):
        abort(404)
    return a


def _run_or_404(rid) -> tuple[StudioAppRun, StudioApp]:
    run = db.session.get(StudioAppRun, rid)
    if run is None or not SA.may_see_run(current_user, run):
        abort(404)
    a = db.session.get(StudioApp, run.app_id)
    if a is None or not SA.can_use(current_user, a):
        abort(404)
    if run.version == 0 and not SA.is_author(current_user):
        abort(404)
    return SA.refresh_stale(run), a


@bp.route("/<slug>")
@login_required
def page(slug):
    a = _usable_or_404(slug)
    if not a.published:
        return render_template("apps/page.html", a=a, fields=[], runs=[], unpublished=True)
    return render_template("apps/page.html", a=a, unpublished=False,
                           fields=SA.form_view(a.published.get("fields") or []),
                           runs=SA.recent_runs(a, current_user, limit=10))


@bp.route("/<slug>/run", methods=["POST"])
@login_required
def run(slug):
    a = _usable_or_404(slug)
    try:
        r = SA.start_run(a, user=current_user, product=_product_key(),
                         raw_inputs=(request.get_json(silent=True) or {}).get("inputs"))
    except SA.AppError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    log_action("studio.app.run", target=slug, extra={"run": r.id, "version": r.version})
    from flask import url_for
    return jsonify({"ok": True, "run_id": r.id, "status_url": url_for("apps.run_status", rid=r.id),
                    "url": url_for("apps.run_page", rid=r.id)})


@bp.route("/runs/<int:rid>")
@login_required
def run_page(rid):
    r, a = _run_or_404(rid)
    return render_template("apps/run.html", a=a, run=r)


@bp.route("/runs/<int:rid>.json")
@login_required
def run_status(rid):
    r, a = _run_or_404(rid)
    return jsonify(SA.run_json(r, a, current_user))


@bp.route("/runs/<int:rid>/action/<key>", methods=["POST"])
@login_required
def action(rid, key):
    r, a = _run_or_404(rid)
    try:
        res = SA.run_action(a, r, key, user=current_user, product=_product_key())
    except SA.AppError as exc:
        log_action("studio.app.action", target=a.slug, extra={"run": rid, "action": key,
                                                              "ok": False, "error": str(exc)[:300]})
        return jsonify({"ok": False, "error": str(exc)}), 400
    log_action("studio.app.action", target=a.slug, extra={"run": rid, "action": key,
                                                          "ok": res.get("ok"), "message": res.get("message")})
    return jsonify(res)


@bp.route("/runs/<int:rid>/download/<key>")
@login_required
def download(rid, key):
    r, a = _run_or_404(rid)
    try:
        name, body, mime = SA.download(a, r, key)
    except SA.AppError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    log_action("studio.app.download", target=a.slug, extra={"run": rid, "action": key})
    return Response(body, mimetype=mime,
                    headers={"Content-Disposition": "attachment; filename=%s" % name})
