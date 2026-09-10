"""Scout — Operations → Troubleshooting → Scout.

GET  /scout/   the form
POST /scout/   walk the ladder against the named object

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

from flask import Blueprint, jsonify, render_template, request
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Appliance, Permission, visible_appliances
from ..services import faz_logs
from ..services import scout_config
from ..services import scout_objects
from ..services import scout_ladder as sl
from ..services.audit import log_action

bp = Blueprint("scout", __name__, url_prefix="/scout")


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
        "error": "",
        "form": {"appliance_id": request.form.get("appliance_id", ""),
                 "policy": request.form.get("policy", ""),
                 "hostname": request.form.get("hostname", ""),
                 "port": request.form.get("port", ""),
                 "scheme": request.form.get("scheme", "https"),
                 "path": request.form.get("path", "/"),
                 # A checkbox that was cleared and posted sends nothing,
                 # which is indistinguishable from "not on this form". On a
                 # POST the absence therefore means OFF; only a GET may fall
                 # back to the configured default, or an operator could never
                 # untick a box the site pre-ticks.
                 "use_ssh": (bool(request.form.get("use_ssh")) if posted
                             else bool(dflt["use_ssh"])),
                 "window_minutes": request.form.get(
                     "window_minutes", str(dflt["window_minutes"])),
                 "analyzer_id": request.form.get("analyzer_id", ""),
                 "faz_adom": request.form.get("faz_adom", dflt["faz_adom"]),
                 "faz_devid": request.form.get("faz_devid", dflt["faz_devid"]),
                 "faz_vdom": request.form.get("faz_vdom", dflt["faz_vdom"])},
        "PASS": sl.PASS, "FAIL": sl.FAIL, "WARN": sl.WARN,
        "UNKNOWN": sl.UNKNOWN, "SKIPPED": sl.SKIPPED,
    }
    if request.method != "POST":
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
            faz_timeout=float(dflt["faz_timeout"])))
    except sl.ScoutRefused as exc:
        ctx["error"] = str(exc)
        return render_template("scout/index.html", **ctx)

    ctx["report"] = report
    log_action("scout.walk",
               "appliance=%s object=%r verdict=%s" % (
                   appl.name, target.policy,
                   report["verdict"].get("layer") or "no fault localised"))
    return render_template("scout/index.html", **ctx)
