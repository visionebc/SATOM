"""Operations > Automation > Scripts -- the operator's side of the Script Library.

Lists the published scripts the user may run, draws each script's form (the
fields of its PUBLISHED version), runs it now, and keeps saved runs on a cron
schedule. Gated on ``operations.scripts_run`` (operators and administrators);
which scripts appear is decided per script by ``script_schedules.can_run``.
Runs execute in ``satom-scripts.service``, never here.
"""
from __future__ import annotations

from flask import Blueprint, abort, jsonify, render_template, request
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..services import script_library as SL
from ..services import script_schedules as SS
from ..services import script_vault as SV
from ..services.audit import log_action

bp = Blueprint("scripts", __name__, url_prefix="/automation/scripts")
PERM = "operations.scripts_run"


def _who() -> str:
    return getattr(current_user, "username", "?")


def _err(exc, code=400):
    return jsonify({"error": str(exc)}), code


def _runs_for(slug=None, limit=20):
    runs = SL.recent_runs(slug, limit=limit * 3)
    if not current_user.can("studio.script_library"):
        runs = [r for r in runs if r.get("requested_by") == _who()]
    return [r for r in runs if r.get("version") != "draft"][:limit]


@bp.route("/")
@login_required
@require_permission(PERM)
def index():
    from ..services import sandbox
    return render_template("scripts/index.html", scripts=SS.visible_scripts(current_user),
                           schedules=SS.list_for(current_user), runs=_runs_for(),
                           sandbox_ok=sandbox.available())


@bp.route("/<slug>")
@login_required
@require_permission(PERM)
def run_page(slug):
    try:
        meta, v = SS.runnable(current_user, slug)
    except SL.ScriptError:
        abort(404)
    schedules = SS.list_for(current_user, slug)
    for s in schedules:
        st = SL.run_status(s.get("last_request_id") or "")
        s["last_run_status"] = st.get("status") if st else ""
    from ..services import sandbox
    from ..services import settings_store
    return render_template("scripts/run.html", meta=meta, v=v, slug=slug,
                           schedules=schedules, runs=_runs_for(slug),
                           tz_name=settings_store.tz_name(),
                           vault_ok=SV.available(), sandbox_ok=sandbox.available())


@bp.route("/<slug>/run", methods=["POST"])
@login_required
@require_permission(PERM)
def run_now(slug):
    try:
        meta, _v = SS.runnable(current_user, slug)
        body = request.get_json(silent=True) or {}
        from .script_library import _node
        st = SL.enqueue_run(slug, version_ref=int(meta["published"]),
                            raw_inputs=body.get("inputs"), by=_who(), trigger="run",
                            node=_node(), wrap=SV.wrap_for_run)
    except SL.ScriptError as exc:
        return _err(exc)
    log_action("scripts.run", target=slug,
               extra={"request_id": st["request_id"], "version": st["version"],
                      "inputs": st["inputs"]})
    return jsonify(st)


@bp.route("/runs/<rid>")
@login_required
@require_permission(PERM)
def run_status(rid):
    st = SL.run_status(rid)
    if st is None or st.get("version") == "draft":
        return jsonify({"status": "unknown"}), 404
    if st.get("requested_by") != _who() and not current_user.can("studio.script_library"):
        return jsonify({"status": "unknown"}), 404
    return jsonify(st)


@bp.route("/cron-preview")
@login_required
@require_permission(PERM)
def cron_preview():
    from ..services import scheduler, settings_store
    expr = request.args.get("expr") or ""
    try:
        nxt = scheduler.cron_preview(expr, 5, tz=settings_store.tz_name())
    except scheduler.CronError as exc:
        return _err(exc)
    if not nxt:
        return _err(SL.ScriptError("never fires"))
    return jsonify({"next": [d.strftime("%a %Y-%m-%d %H:%M") for d in nxt],
                    "tz": settings_store.tz_name()})


@bp.route("/<slug>/schedules", methods=["POST"])
@login_required
@require_permission(PERM)
def schedule_create(slug):
    body = request.get_json(silent=True) or {}
    try:
        s = SS.create(current_user, slug, name=body.get("name") or "",
                      cron=body.get("cron") or "", raw_inputs=body.get("inputs"))
    except SL.ScriptError as exc:
        return _err(exc)
    except Exception as exc:  # noqa: BLE001 -- vault transport
        return _err(SL.ScriptError("could not save: %s" % exc), 502)
    log_action("scripts.schedule.create", target=slug,
               extra={"schedule": s["id"], "cron": s["cron"], "version": s["version"]})
    return jsonify(s)


def _schedule_or_404(sid):
    try:
        s = SS.get(sid)
    except SL.ScriptError:
        abort(404)
    if s is None or not SS.may_manage(current_user, s):
        abort(404)
    return s


@bp.route("/schedules/<sid>/toggle", methods=["POST"])
@login_required
@require_permission(PERM)
def schedule_toggle(sid):
    s = _schedule_or_404(sid)
    s = SS.set_enabled(s, not s.get("enabled"))
    log_action("scripts.schedule.toggle", target=s["slug"],
               extra={"schedule": sid, "enabled": s["enabled"]})
    return jsonify(s)


@bp.route("/schedules/<sid>/upgrade", methods=["POST"])
@login_required
@require_permission(PERM)
def schedule_upgrade(sid):
    s = _schedule_or_404(sid)
    try:
        s = SS.move_to_published(current_user, s)
    except SL.ScriptError as exc:
        return _err(exc)
    log_action("scripts.schedule.upgrade", target=s["slug"],
               extra={"schedule": sid, "version": s["version"]})
    return jsonify(s)


@bp.route("/schedules/<sid>/delete", methods=["POST"])
@login_required
@require_permission(PERM)
def schedule_delete(sid):
    s = _schedule_or_404(sid)
    SS.delete(s)
    log_action("scripts.schedule.delete", target=s["slug"], extra={"schedule": sid})
    return jsonify({"ok": True})
