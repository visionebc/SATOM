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

from ..extensions import db, limiter
from ..models_studio import StudioApp, StudioAppRun
from ..services import studio_apps as SA
from ..services.audit import log_action

bp = Blueprint("apps", __name__, url_prefix="/apps")

#: An operator's form is small. The app-wide limit (hundreds of MB, for
#: firmware uploads) would let a run request make a worker parse that much.
MAX_BODY = 1024 * 1024


@bp.before_request
def _small_bodies():
    from ..services.request_limits import refuse_larger_than
    return refuse_larger_than(MAX_BODY)


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
    if a.kind == "script":  # a script app runs from the script's own page
        abort(404)
    if not a.enabled and not SA.is_author(current_user):
        abort(404)
    # ADOMs are where a console user meets the app; an Apps-only account has
    # no console and no ADOM switcher, so only the access check above applies.
    in_adom = getattr(current_user, "is_apps_only", False) or SA.shown_in(a, _product_key())
    if not SA.is_author(current_user) and (a.status != "published" or not a.published
                                           or not in_adom):
        abort(404)
    return a


def _run_product(a: StudioApp) -> str:
    if getattr(current_user, "is_apps_only", False):
        return SA.run_product(a, _product_key())
    return _product_key()


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
    from ..services import studio_design as D
    pub = a.published
    fields = SA.form_view(pub.get("fields") or [])
    design = {}
    try:
        design = D.clean(pub.get("design") or {})
    except D.DesignError:  # a stored design the vocabulary no longer takes
        design = {}
    runs = SA.recent_runs(a, current_user, limit=15)
    return render_template("apps/page.html", a=a, unpublished=False, fields=fields,
                           runs=runs[:10], tree=D.page_tree(design, fields), D=D,
                           theme=design.get("theme") or {},
                           fields_by_name={f["name"]: f for f in fields}, all_runs=runs)


@bp.route("/<slug>/form.json")
@login_required
def form_json(slug):
    """An app's form, for a row button or an Open app action: the run page
    opens it over itself, filled in, and runs it there. The same 404 as the
    app's page for anyone who may not open it; the run checks again."""
    a = _usable_or_404(slug)
    if not a.published:
        return jsonify({"ok": False, "error": "%s has no published version yet" % a.name}), 400
    from flask import url_for
    fields = SA.form_view(a.published.get("fields") or [])
    return jsonify({"ok": True, "slug": a.slug, "name": a.name, "icon": a.icon,
                    "description": a.description or "",
                    "html": render_template("apps/_form.html", fields=fields, prefix="m-"),
                    "run_url": url_for("apps.run", slug=a.slug),
                    "page_url": url_for("apps.page", slug=a.slug)})


@bp.route("/<slug>/assets/<sha>")
@login_required
def asset(slug, sha):
    """An image of the app's design, to whoever may open the app (and its
    authors, for the editor). The type was sniffed at upload; the response
    may not be read as anything else (nosniff: the app-wide security
    headers), nor run anything (its own policy below)."""
    a = SA.get(slug)
    if a is None or not SA.can_use(current_user, a):
        abort(404)
    from ..services import studio_design as D
    row = D.get_asset(a.id, sha)
    if row is None:
        abort(404)
    return Response(row.data, mimetype=row.mime, headers={
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "Cache-Control": "private, max-age=86400, immutable",
        "Content-Disposition": "inline; filename=%s.%s" % (row.sha256[:12], D.EXT.get(row.mime, "bin"))})


@bp.route("/<slug>/run", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def run(slug):
    a = _usable_or_404(slug)
    try:
        r = SA.start_run(a, user=current_user, product=_run_product(a),
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


@bp.route("/runs/<int:rid>/answer", methods=["POST"])
@login_required
@limiter.limit("60 per minute")
def answer(rid):
    """Answer the "Ask a person" step a run waits on: the person who started
    it or a Plugin Studio author (the same people who may see the run)."""
    r, a = _run_or_404(rid)
    if not SA.may_see_run(current_user, r):
        return jsonify({"ok": False, "error": "you may not answer this run"}), 403
    body = request.get_json(silent=True) or {}
    value = str(body.get("answer") or "")
    step = (SA.waiting_step(r) or {}).get("key", "")
    try:
        SA.answer(a, r, value, user=current_user, note=str(body.get("note") or "")[:400],
                  acks=body.get("acks") if isinstance(body.get("acks"), list) else None)
    except SA.AppError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    log_action("studio.app.answer", target=a.slug, extra={
        "run": rid, "step": step, "answer": value,
        "acknowledged": len(body.get("acks") or []) if isinstance(body.get("acks"), list) else 0})
    return jsonify({"ok": True})


@bp.route("/runs/<int:rid>/action/<key>", methods=["POST"])
@login_required
def action(rid, key):
    r, a = _run_or_404(rid)
    try:
        res = SA.run_action(a, r, key, user=current_user, product=_run_product(a))
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
