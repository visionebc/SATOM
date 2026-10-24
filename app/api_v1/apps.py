"""/api/v1/apps — run a Plugin Studio app from outside, and read what it did.

Until 2026-10-24 an app ran only from its page. This door is as narrow as the
Run button, and narrower in one respect:

* ``GET /apps`` lists the apps the token's OWNER may use in the token's ADOM
  (``services.studio_apps.can_use`` / ``shown_in``, the console's own rules),
  each with its form fields and whether the token may run it (``granted``).
* ``POST /apps/<slug>/run`` runs the PUBLISHED version of an app GRANTED to
  the token (``services.token_grants``: one grant per app, bound to the
  version an administrator approved; publish a different version and the
  grant pauses until it is re-approved). ``armed`` defaults to **false**: an
  unarmed run records its write steps instead of executing them, and
  ``armed: true`` needs the explicit ``app_arm`` capability on top of the
  ``write`` scope. From the console a published app always runs armed; a
  machine with nobody at the screen does not get that default.
* ``GET /app-runs/<id>`` returns the run (it runs in the background; poll it).

An app the owner may not use, of another ADOM, a script app or a missing one
are the same 404: its name is not the caller's to learn.
"""
from __future__ import annotations

from flask import g, jsonify, request

from ..extensions import limiter
from ..models import db
from ..models_studio import StudioApp, StudioAppRun
from ..services import studio_apps as SA
from ..services import token_grants as TG
from ..services.audit import log_action
from . import bp
from .auth import audit_extra, declares_capability, token_required


def _err(status: int, code: str, message: str, **extra):
    body = {"error": code, "message": message}
    body.update(extra)
    return jsonify(body), status


def _owner():
    return getattr(g, "api_token_owner", None)


def _product() -> str:
    return getattr(g, "product", "") or ""


def _reachable(a) -> bool:
    """The console's rules for the token's owner, in the token's ADOM."""
    return (a is not None and a.kind == "flow" and SA.can_use(_owner(), a)
            and SA.shown_in(a, _product()))


def _grant_state(a) -> str:
    ok, code, _msg = TG.authorize(g.api_token, "app", a)
    return "yes" if ok else ("paused" if code == "grant_paused" else "no")


def _fields(a) -> list[dict]:
    return [{"name": f.get("name"), "label": f.get("label") or f.get("name"),
             "type": f.get("type") or "text", "required": bool(f.get("required"))}
            for f in (a.published or {}).get("fields") or []]


def _app_json(a) -> dict:
    return {"slug": a.slug, "name": a.name, "description": a.description or "",
            "version": int((a.published or {}).get("version") or 0),
            "enabled": bool(a.enabled),
            "published": a.status == "published" and bool(a.published),
            "fields": _fields(a), "granted": _grant_state(a)}


@bp.route("/apps", methods=["GET"])
@token_required("read")
def apps_list():
    """The apps the token's owner may use in the token's ADOM.

    Responses: 200 ``{"apps": [...]}``.
    """
    rows = [a for a in StudioApp.query.order_by(StudioApp.name.asc()).all()
            if _reachable(a) and a.published]
    return jsonify({"apps": [_app_json(a) for a in rows]})


@bp.route("/apps/<slug>/run", methods=["POST"])
@limiter.limit("30/minute")
@token_required("write")
@declares_capability("app_arm")
def apps_run(slug):
    """Run a granted app's published version. Body: ``{"inputs": {}, "armed": bool}``.

    ``armed`` defaults to false (write steps are recorded, not executed).
    ``armed: true`` needs the explicit ``app_arm`` capability.
    Responses: 202 the run (poll ``status_url``); 400 bad inputs; 403
    ``not_granted`` / ``grant_paused`` / ``capability_denied``; 404; 409
    ``disabled`` / ``unpublished``.
    """
    a = SA.get(slug)
    if not _reachable(a):
        return _err(404, "not_found", "No such app.")
    if not a.enabled:
        return _err(409, "disabled", "This app is disabled.")
    if a.status != "published" or not a.published:
        return _err(409, "unpublished", "This app has no published version.")
    tok = g.api_token
    ok, code, msg = TG.authorize(tok, "app", a)
    if not ok:
        return _err(403, code, msg)
    body = request.get_json(silent=True)
    if body is None:
        body = {}
    inputs = (body.get("inputs") or {}) if isinstance(body, dict) else None
    if not isinstance(inputs, dict):
        return _err(400, "bad_request", "The body must be a JSON object; 'inputs' an object.")
    armed = bool(body.get("armed", False))
    if armed:
        ok, code, msg = tok.authorize_object("app_arm")
        if not ok:
            return _err(403, code, msg)
    try:
        run = SA.start_run(a, user=_owner(), product=_product(),
                           raw_inputs=inputs, rehearsal=not armed)
    except SA.AppError as exc:
        return _err(400, "app_error", str(exc))
    log_action("studio.app.run", target=a.slug,
               extra=audit_extra(run=run.id, version=run.version, armed=run.armed))
    return jsonify({"id": run.id, "app": a.slug, "version": run.version,
                    "armed": bool(run.armed), "status": run.status,
                    "status_url": "/api/v1/app-runs/%d" % run.id}), 202


@bp.route("/app-runs/<int:id>", methods=["GET"])
@token_required("read")
def app_runs_get(id):
    """One app run: status, inputs (passwords masked), outputs and steps.

    Responses: 200 the run; 404 when the token's owner cannot see it.
    """
    run = db.session.get(StudioAppRun, id)
    if run is None or not SA.may_see_run(_owner(), run):
        return _err(404, "not_found", "No such run.")
    a = db.session.get(StudioApp, run.app_id)
    if not _reachable(a) or run.version == 0:
        return _err(404, "not_found", "No such run.")
    run = SA.refresh_stale(run)
    out = SA.run_json(run, a, _owner())
    out.pop("actions", None)  # the console's buttons; not callable from here
    out.pop("layout", None)
    out["app"] = a.slug
    return jsonify(out)
