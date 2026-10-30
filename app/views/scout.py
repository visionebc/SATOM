"""Scout — Operations → Troubleshooting → Scout.

GET  /scout/                    the form (+ the latest saved reports)
POST /scout/                    walk the ladder against the named object
GET  /scout/reports             saved reports this ADOM can see
GET  /scout/reports/<id>        one saved report, drawn as it was
GET  /scout/reports/<id>.json   the same, for Scout and API callers

Every walk is saved (``path_diag_reports``) with the metrics panel that sat
under it and the id of the job that carried its device calls; the audit row
names both. A report is visible exactly when its appliance is.

READ ONLY. Every rung delegates; this module reads the form, clamps what an
operator may set, and renders. It does NOT decide what a verdict means — a
second opinion here could only disagree with :mod:`app.services.scout_ladder`,
and the page would then be quoting a tool while contradicting it.

WHY THE APPLIANCE IS PICKED HERE AND NOT TAKEN FROM THE WORKSPACE
    Scout is opened during an incident, frequently from a link in a ticket, and
    frequently for a device that is not the one the operator last had selected.
    Silently diagnosing the workspace's current device would produce a report
    about the wrong box that looks exactly like a report about the right one.
    The picker is scoped by :func:`visible_appliances`, so the ADOM rules still
    hold — a picker is not a hole.
"""
from __future__ import annotations

import json

from flask import Blueprint, abort, jsonify, render_template, request
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Appliance, Permission, visible_appliances
from ..extensions import db
from ..models_pathdiag import PathDiagReport
from ..services import faz_logs
from ..services import jobs
from ..services import scout_metrics
from ..services import scout_config
from ..services import scout_objects
from ..services import scout_ladder as sl
from ..services.audit import log_action
from .cert_inspect import _may_free

bp = Blueprint("scout", __name__, url_prefix="/scout")

#: Said once, so the page, the JSON endpoint and the disabled menu entry cannot
#: drift into three different explanations of the same switch.
OFF_MESSAGE = ("Path Diagnostics is switched off for this site. An administrator can turn "
               "it back on under Settings → Path Diagnostics → Availability.")


@bp.before_request
def _gate():
    """Refuse every Scout route while the feature is off.

    On the BLUEPRINT because that is the only place that actually closes it:
    the nav entry, the bookmark and the link pasted into a ticket all arrive
    here. 503 and not 404 — the feature exists and is switched off, and those
    two are different answers to the operator's next question."""
    if scout_config.enabled():
        return None
    if request.path.rstrip("/").endswith("/objects"):
        return jsonify({"error": OFF_MESSAGE, "disabled": True}), 503
    return render_template("scout/disabled.html", message=OFF_MESSAGE), 503


def _candidates():
    """Appliances this ladder can actually walk, in the current ADOM."""
    rows = (visible_appliances()
            .filter(Appliance.kind.in_(sl.SUPPORTED_KINDS))
            .order_by(Appliance.name).all())
    return rows


def _analyzers():
    """FortiAnalyzers offered for the border rung.

    Neutralised and parked collectors are LISTED but flagged: hiding them would
    turn "your collector is retired" into "there is no collector", and the
    operator would go looking for a configuration page instead of a device.
    """
    rows = (visible_appliances()
            .filter(Appliance.kind == "fortianalyzer")
            .order_by(Appliance.name).all())
    out = []
    for a in rows:
        ok, why = faz_logs.reachable(a)
        out.append({"row": a, "ok": ok, "why": why})
    return out


def _int(name: str, default: int) -> int:
    try:
        return int(request.form.get(name) or default)
    except (TypeError, ValueError):
        return default


def _defaults() -> dict:
    """The site's answer to "where do I look and how long do I wait".

    Read ONCE per request and used for both halves — the pre-filled form and
    the values handed to the engine. Reading them twice is how a page ends up
    showing one window and walking another, with nothing to report the
    disagreement.
    """
    return scout_config.walk_defaults()


def _visible_ids() -> list[int]:
    return [a.id for a in visible_appliances().with_entities(Appliance.id).all()]


def _recent(limit: int = 10) -> list[PathDiagReport]:
    ids = _visible_ids()
    if not ids:
        return []
    return (PathDiagReport.query.filter(PathDiagReport.appliance_id.in_(ids))
            .order_by(PathDiagReport.id.desc()).limit(limit).all())


def _visible_report(rid: int) -> PathDiagReport:
    """404 for a report whose appliance this ADOM cannot see — the same answer
    as a report that does not exist, so an id cannot be probed across ADOMs."""
    row = db.session.get(PathDiagReport, rid)
    if row is None or row.appliance_id not in set(_visible_ids()):
        abort(404)
    return row


def _product() -> str:
    try:
        from ..services.product_scope import stamp
        return stamp() or ""
    except Exception:  # noqa: BLE001 — a report is never lost to scoping
        return ""


def _save(appl, target, opts, report: dict, metrics: dict) -> PathDiagReport:
    v = report.get("verdict") or {}
    row = PathDiagReport(
        username=getattr(current_user, "username", "") or "",
        product=_product(), appliance_id=appl.id,
        appliance_name=appl.name or "", kind=appl.kind or "",
        policy=target.policy or "", localised=bool(v.get("localised")),
        verdict_layer=str(v.get("layer") or ""),
        verdict_text=str(v.get("text") or "")[:400],
        metrics_status=str(metrics.get("status") or ""),
        window_minutes=int(opts.window_minutes or 0),
        job_id=jobs.current_job_id() or "",
        report_json=json.dumps(report, default=str),
        metrics_json=json.dumps(metrics, default=str))
    db.session.add(row)
    # Retention runs here, where reports are written: on the node that writes
    # them, and never on a read-only standby (Settings -> Path Diagnostics).
    try:
        PathDiagReport.prune(int(scout_config.get("report_retention_days") or 0))
    except Exception:  # noqa: BLE001 -- a report is never lost to its own pruning
        db.session.rollback()
        db.session.add(row)
    db.session.commit()
    return row


@bp.route("/objects")
@login_required
@require_permission(Permission.VIEW)
def objects():
    """What the picked appliance publishes, as JSON, for the name field.

    Scoped by :func:`visible_appliances` exactly like the walk itself: a by-id
    read that goes to the table directly is how every ADOM answered 200 for
    another product's device until 2026-08-06. A device of a kind this ladder
    cannot walk is a 404 here — from this page's point of view it does not
    exist, and 403 would tell an operator it does.

    Read-only and cheap by construction: the list comes from the same two
    adapters rung 1 reads, so the picker can never offer a name the ladder
    would then fail to look for.
    """
    try:
        aid = int(request.args.get("appliance_id") or 0)
    except (TypeError, ValueError):
        aid = 0
    appl = None
    if aid:
        appl = (visible_appliances()
                .filter(Appliance.id == aid,
                        Appliance.kind.in_(sl.SUPPORTED_KINDS)).first())
    if appl is None:
        return jsonify({"error": "no such appliance in this ADOM",
                        "appliance_id": aid, "objects": []}), 404
    return jsonify(scout_objects.offer(appl))


@bp.route("/", methods=["GET", "POST"])
@login_required
@require_permission(Permission.VIEW)
def index():
    appliances = _candidates()
    dflt = _defaults()
    posted = request.method == "POST"
    ctx = {
        "appliances": appliances,
        "analyzers": _analyzers(),
        # The "?" beside every control, from the same catalog a
        # guard holds against this template's own field list --
        # a control added later cannot ship mute.
        "field_help": scout_config.walk_help(),
        "report": None,
        "metrics": None,
        "saved": None,
        "proposal": None,
        "pd_fmt": scout_metrics.fmt,
        "recent": [],
        "error": "",
        # appliance_id/policy/hostname/port/scheme also come from the query
        # string: Fleet ->
        # Architecture links a device element straight to its Scout form.
        "form": {"appliance_id": request.values.get("appliance_id", ""),
                 "policy": request.values.get("policy", ""),
                 "hostname": request.values.get("hostname", ""),
                 "port": request.values.get("port", ""),
                 "scheme": request.values.get("scheme", "https"),
                 "path": request.values.get("path", "/"),
                 # Set when the form was opened from a Scout proposal; the
                 # walk then closes that proposal with its report.
                 "proposal": request.values.get("proposal", ""),
                 # A checkbox that was cleared and posted sends nothing,
                 # which is indistinguishable from "not on this form". On a
                 # POST the absence therefore means OFF; only a GET may fall
                 # back to the configured default, or an operator could never
                 # untick a box the site pre-ticks.
                 "use_ssh": (bool(request.form.get("use_ssh")) if posted
                             else bool(dflt["use_ssh"])),
                 "window_minutes": request.values.get(
                     "window_minutes", str(dflt["window_minutes"])),
                 "analyzer_id": request.form.get("analyzer_id", ""),
                 "faz_adom": request.form.get("faz_adom", dflt["faz_adom"]),
                 "faz_devid": request.form.get("faz_devid", dflt["faz_devid"]),
                 "faz_vdom": request.form.get("faz_vdom", dflt["faz_vdom"])},
        "PASS": sl.PASS, "FAIL": sl.FAIL, "WARN": sl.WARN,
        "UNKNOWN": sl.UNKNOWN, "SKIPPED": sl.SKIPPED,
    }
    if request.method != "POST":
        ctx["recent"] = _recent(10)
        return render_template("scout/index.html", **ctx)

    appl = None
    try:
        aid = int(request.form.get("appliance_id") or 0)
    except (TypeError, ValueError):
        aid = 0
    if aid:
        # Scoped lookup, not Appliance.query.get: a by-id route that reads the
        # table directly is how every ADOM answered 200 for another product's
        # device until 2026-08-06.
        appl = visible_appliances().filter(Appliance.id == aid).first()
    if appl is None:
        ctx["error"] = "Pick an appliance this ADOM can see."
        return render_template("scout/index.html", **ctx)

    analyzer = None
    try:
        zid = int(request.form.get("analyzer_id") or 0)
    except (TypeError, ValueError):
        zid = 0
    if zid:
        analyzer = (visible_appliances()
                    .filter(Appliance.id == zid,
                            Appliance.kind == "fortianalyzer").first())

    target = sl.Target(
        appliance=appl,
        policy=(request.form.get("policy") or "").strip(),
        hostname=(request.form.get("hostname") or "").strip(),
        port=_int("port", 0),
        scheme=("http" if request.form.get("scheme") == "http" else "https"),
        path=(request.form.get("path") or "/").strip() or "/",
        method="GET",
    )
    opts = sl.Options(
        use_ssh=bool(request.form.get("use_ssh")),
        timeout=float(dflt["probe_timeout"]),
        window_minutes=_int("window_minutes", int(dflt["window_minutes"])),
        analyzer=analyzer,
        faz_adom=((request.form.get("faz_adom") or dflt["faz_adom"]).strip()
                  or "root"),
        faz_devid=(request.form.get("faz_devid")
                   or dflt["faz_devid"] or "").strip(),
        faz_vdom=(request.form.get("faz_vdom")
                  or dflt["faz_vdom"] or "").strip(),
    )
    try:
        report = sl.run(target, opts, sl.default_ports(
            analyzer=analyzer, faz_adom=opts.faz_adom,
            faz_devid=opts.faz_devid, faz_vdom=opts.faz_vdom,
            faz_limit=int(dflt["faz_limit"]),
            faz_timeout=float(dflt["faz_timeout"]),
            may_free=_may_free()))
    except sl.ScoutRefused as exc:
        ctx["error"] = str(exc)
        return render_template("scout/index.html", **ctx)

    # Context, never a rung: the panel cannot change the verdict above it.
    metrics = scout_metrics.context(appl.name, target.policy,
                                    report["options"]["window_minutes"])
    saved = _save(appl, target, opts, report, metrics)
    from ..services import advisor as advisor_svc
    proposal = advisor_svc.link_walk(
        request.form.get("proposal"), appliance_id=appl.id, report_id=saved.id,
        username=getattr(current_user, "username", "") or "",
        may_see_all=current_user.can(Permission.USER_MANAGE))
    ctx.update(report=report, metrics=metrics, saved=saved, proposal=proposal)
    log_action("scout.walk",
               "appliance=%s object=%r verdict=%s" % (
                   appl.name, target.policy,
                   report["verdict"].get("layer") or "no fault localised"),
               {"report_id": saved.id, "job_id": saved.job_id,
                "metrics": metrics.get("status"),
                "proposal_id": proposal.id if proposal else None})
    return render_template("scout/index.html", **ctx)


@bp.route("/reports")
@login_required
@require_permission(Permission.VIEW)
def reports():
    rows = _recent(200)
    if request.args.get("format") == "json":
        return jsonify({"reports": [r.summary() for r in rows]})
    return render_template("scout/reports.html", rows=rows)


@bp.route("/reports/<int:rid>")
@login_required
@require_permission(Permission.VIEW)
def report_view(rid: int):
    row = _visible_report(rid)
    rep_ = row.report()
    form = {"appliance_id": str(row.appliance_id or ""), "policy": row.policy,
            "hostname": "", "port": "", "scheme": "https", "path": "/",
            "use_ssh": False, "window_minutes": str(row.window_minutes or ""),
            "analyzer_id": "", "faz_adom": "", "faz_devid": "", "faz_vdom": "",
            "proposal": ""}
    return render_template(
        "scout/index.html", appliances=_candidates(), analyzers=_analyzers(),
        field_help=scout_config.walk_help(), report=rep_,
        metrics=row.metrics(), saved=row, recent=[], error="", form=form,
        proposal=None,
        pd_fmt=scout_metrics.fmt,
        PASS=sl.PASS, FAIL=sl.FAIL, WARN=sl.WARN, UNKNOWN=sl.UNKNOWN,
        SKIPPED=sl.SKIPPED)


@bp.route("/reports/<int:rid>.json")
@login_required
@require_permission(Permission.VIEW)
def report_json(rid: int):
    row = _visible_report(rid)
    return jsonify({"report": row.summary() | {"walk": row.report(),
                                               "metrics": row.metrics()}})
