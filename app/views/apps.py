"""Operations > Plugins > <app> -- the operator's side of Python Studio apps.

An app is opened from its own menu entry (``services.studio_apps.menu``),
runs its PUBLISHED version with the operator's form values, shows the output
and offers the app's actions on it. Who may open it is the app's access list
(users and user groups, plus Studio authors); where, the ADOMs its author
ticked. Both are answered by ``services.studio_apps``, never here.
"""
from __future__ import annotations

from flask import Blueprint, Response, abort, jsonify, redirect, render_template, request, url_for
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


def _used_by_view_here(via, slug: str) -> bool:
    """Whether app *via*'s published view uses *slug* and *via* is drawn in
    this ADOM for this user: an app a view uses runs wherever that view's app
    is drawn (DNS Lookup's Records and Delete dialogs, in every ADOM), without
    a menu entry of its own there."""
    v = SA.get(str(via or "")) if via else None
    if v is None or v.kind != "flow" or not v.enabled or not SA.can_use(current_user, v):
        return False
    view = (v.published or {}).get("view") or {}
    return slug in (view.get("uses") or []) and SA.shown_in(v, _product_key())


def _usable_or_404(slug, via=None) -> StudioApp:
    """404, not 403, for an app the user may not use: its name is not theirs
    to learn either. *via*: the app whose view asks (_used_by_view_here)."""
    a = SA.get(slug)
    if a is None or not SA.can_use(current_user, a):
        abort(404)
    if a.kind in ("script", "page"):  # a script app runs from the script's own page;
        abort(404)                     # a page plugin has nothing to run (see page())
    if not a.enabled and not SA.is_author(current_user):
        abort(404)
    # ADOMs are where a console user meets the app; an Apps-only account has
    # no console and no ADOM switcher, so only the access check above applies.
    in_adom = getattr(current_user, "is_apps_only", False) or SA.shown_in(a, _product_key()) \
        or _used_by_view_here(via, a.slug)
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
    pg = SA.get(slug)
    if pg is not None and pg.kind == "page":   # its SATOM page, under the page's permission
        from ..services import studio_pages as SP
        target = SP.get(pg.page_key)
        if target is None or not pg.enabled or not SA.page_allowed(current_user, pg.page_key):
            abort(404)
        return redirect(url_for(target["endpoint"]))
    a = _usable_or_404(slug)
    if not a.published:
        return render_template("apps/page.html", a=a, fields=[], runs=[], unpublished=True)
    from ..services import studio_design as D
    from ..services import studio_view as SV
    pub = a.published
    if SV.has(pub.get("view")):          # the app's own page (services.studio_view)
        return _view_host(a, pub["view"], draft=False)
    fields = SA.form_view(pub.get("fields") or [])
    design = {}
    try:
        design = D.clean(pub.get("design") or {})
    except D.DesignError:  # a stored design the vocabulary no longer takes
        design = {}
    runs = SA.recent_runs(a, current_user, limit=15)
    return render_template("apps/page.html", a=a, unpublished=False, fields=fields,
                           runs=runs[:10], tree=D.page_tree(design, fields), D=D,
                           autorun=autorun(pub),
                           theme=design.get("theme") or {},
                           fields_by_name={f["name"]: f for f in fields}, all_runs=runs)


# --------------------------------------------------------------------------- #
#  an app's own view (services.studio_view)                                    #
# --------------------------------------------------------------------------- #
_HOST_RE = __import__("re").compile(r"^[A-Za-z0-9.-]+(?::\d{1,5})?$|^\[[0-9A-Fa-f:.]+\](?::\d{1,5})?$")


def _origin() -> str:
    """The console's own origin as the browser reached it: nginx says https
    (X-Forwarded-Proto) and passes the Host it was asked for."""
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
    scheme = scheme if scheme in ("http", "https") else request.scheme
    host = request.host if _HOST_RE.match(request.host or "") else "localhost"
    return "%s://%s" % (scheme, host)


def _view_host(a: StudioApp, view: dict, *, draft: bool):
    """The console page that frames the view: the crumb and title the view
    names, the frame, and the bridge (static/js/apps_view_host.js)."""
    from ..services import studio_view as SV
    rid = request.args.get("run", type=int)
    token = SV.new_token()
    frame_url = url_for("apps.frame", slug=a.slug, **({"draft": 1} if draft else {}))
    first = frame_url + ("&" if "?" in frame_url else "?") + \
        ("run=%d&" % rid if rid else "") + "t=" + token
    return render_template("apps/view.html", a=a, view=view, token=token, frame_src=first,
                           cfg={"slug": a.slug, "uses": list(view.get("uses") or []),
                                "token": token, "frameUrl": frame_url})


@bp.route("/<slug>/frame")
@login_required
def frame(slug):
    """The ISOLATED document of an app's view (services.studio_view): served
    with its own policy for <iframe sandbox="allow-scripts allow-modals">.
    ``?run=<id>`` draws it with that run of this app (who may see the run:
    apps.run_status's rule); ``?draft=1`` the draft view, for its authors."""
    from flask_login import current_user
    from ..services import studio_view as SV
    from ..services import theme_service
    cu = current_user._get_current_object()     # the User, never the proxy (studio_dns.as_user)
    a = SA.get(slug)
    draft = request.args.get("draft") == "1"
    if draft:
        if a is None or a.kind != "flow" or not SA.is_author(cu) or not cu.can(SV.VIEW_PERMISSION):
            abort(404)
        view, fields = a.view, a.fields
    else:
        a = _usable_or_404(slug)
        pub = a.published or {}
        view, fields = pub.get("view") or {}, pub.get("fields") or []
    if not SV.has(view):
        abort(404)
    token = request.args.get("t", "")
    if not SV.TOKEN_RE.match(token):
        abort(400)
    run, outputs, form = None, {}, {}
    rid = request.args.get("run", type=int)
    if rid:
        r, ra = _run_or_404(rid)
        if ra.id != a.id:
            abort(404)
        for o in r.outputs:
            if o.get("key") and o["key"] not in outputs:
                outputs[o["key"]] = o.get("value")
        form = r.inputs
        run = {"id": r.id, "status": r.status, "error": r.error or "",
               "url": url_for("apps.run_page", rid=r.id)}
    else:
        form = {f["name"]: f.get("default", "") for f in fields if f.get("name")}
    product = _product_key()
    data, errors = SV.load_context(view, user=cu, product=product)
    html, _err = SV.render(view, form=form, outputs=outputs, run=run, data=data, errors=errors,
                           user=cu, adom=product)
    origin = _origin()
    _css, ver = SV.kit()
    kit_url = origin + url_for("apps.view_kit", version=ver)
    bootstrap_url = origin + SV.BOOTSTRAP_JS
    island = {"token": token, "slug": a.slug, "uses": list(view.get("uses") or []),
              "form": form, "outputs": outputs, "run": run, "data": data, "errors": errors}
    doc = SV.document(view, html, island, kit_url=kit_url, bootstrap_url=bootstrap_url,
                      theme_css=theme_service.active_css())
    resp = Response(doc, mimetype="text/html")
    resp.headers["Content-Security-Policy"] = SV.csp(kit_url, bootstrap_url)
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@bp.route("/view-kit/<version>.css")
def view_kit(version):
    """SATOM's own stylesheets for an app view's frame (fonts inlined).
    PUBLIC on purpose: an opaque-origin frame sends no session cookie with
    its subresources, and this is only vendored CSS -- what /static serves
    to anyone. An old version answers with the current one."""
    from ..services import studio_view as SV
    css, ver = SV.kit()
    resp = Response(css, mimetype="text/css")
    resp.headers["Cache-Control"] = ("public, max-age=31536000, immutable" if version == ver
                                     else "no-store")
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


def autorun(pub: dict) -> bool:
    """Whether a Run button marked "run when the page opens" may do so: only
    an app with no form field and no step that writes (a dashboard). Opening
    a page must never change anything, whatever the design says."""
    from ..services import studio_flow as F
    if pub.get("fields"):
        return False
    nodes = (pub.get("graph") or {}).get("nodes") or []
    return bool(nodes) and not any(F.step_writes(n) for n in nodes)


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
    body = request.get_json(silent=True) or {}
    a = _usable_or_404(slug, via=body.get("via"))
    try:
        r = SA.start_run(a, user=current_user, product=_run_product(a),
                         raw_inputs=body.get("inputs"))
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
                  acks=body.get("acks") if isinstance(body.get("acks"), list) else None,
                  typed=str(body.get("typed") or "")[:200])
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
