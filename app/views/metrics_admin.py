"""Monitoring → Collection — the fleet metrics collection control panel.

This page answers the operator's cadence question directly: every scrape
target (device x collector) with its OWN editable interval, plus the health
of the local VictoriaMetrics store. It exists because a probe row's declared
interval already lied once (the 5-under-3 cadence lesson): collection policy
must be visible and editable in one place, not implied by code.

Reads are DB + loopback VM only — a page load never touches an appliance.
"""
from __future__ import annotations

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import db, visible_appliances

bp = Blueprint("metrics_admin", __name__, url_prefix="/monitoring/collection")


def _visible_targets():
    from ..models_metrics import ScrapeTarget
    visible = {a.id for a in visible_appliances().all()}
    rows = ScrapeTarget.query.all()
    return [t for t in rows if t.appliance_id in visible]


@bp.route("/")
@login_required
def index():
    from ..services import metrics_collect as mc
    from ..services import vm_store
    targets = sorted(_visible_targets(),
                     key=lambda t: ((t.appliance.name if t.appliance else ""),
                                    t.collector))
    return render_template(
        "monitoring/collection.html",
        targets=[t.to_dict() for t in targets],
        collectors=mc.COLLECTORS,
        gaps=mc.coverage_gaps(visible_appliances().all()),
        vm=vm_store.health(),
    )


@bp.route("/data")
@login_required
def data():
    from ..services import metrics_collect as mc
    from ..services import vm_store
    targets = sorted(_visible_targets(),
                     key=lambda t: ((t.appliance.name if t.appliance else ""),
                                    t.collector))
    return jsonify({"targets": [t.to_dict() for t in targets],
                    "gaps": mc.coverage_gaps(visible_appliances().all()),
                    "vm": vm_store.health()})


@bp.route("/target/<int:tid>", methods=["POST"])
@login_required
@require_permission("config_write")
def update_target(tid):
    from ..models_metrics import ScrapeTarget
    from ..services import audit
    t = ScrapeTarget.query.get_or_404(tid)
    if t.appliance_id not in {a.id for a in visible_appliances().all()}:
        return jsonify({"ok": False, "error": "not visible in this ADOM"}), 404
    changed = []
    if "interval_min" in request.form:
        try:
            iv = max(1, min(1440, int(request.form["interval_min"])))
        except ValueError:
            return jsonify({"ok": False, "error": "bad interval"}), 400
        if iv != t.interval_min:
            t.interval_min = iv
            changed.append("interval=%d" % iv)
    if "enabled" in request.form:
        en = request.form["enabled"] in ("1", "true", "on")
        if en != bool(t.enabled):
            t.enabled = en
            changed.append("enabled" if en else "disabled")
    if "top_n" in request.form:
        try:
            n = max(1, min(200, int(request.form["top_n"])))
        except ValueError:
            return jsonify({"ok": False, "error": "bad top_n"}), 400
        p = t.params
        if p.get("top_n") != n:
            p["top_n"] = n
            t.params = p
            changed.append("top_n=%d" % n)
    db.session.commit()
    if changed:
        audit.log_action("metrics_target_update",
                         "%s/%s" % (t.appliance.name if t.appliance else t.appliance_id,
                                    t.collector),
                         {"changes": changed})
    if request.form.get("_redirect"):
        flash("Target %s/%s: %s" % (t.appliance.name if t.appliance else "?",
                                    t.collector,
                                    ", ".join(changed) or "no change"),
              "success")
        return redirect(url_for("metrics_admin.index"))
    return jsonify({"ok": True, "target": t.to_dict(), "changed": changed})


@bp.route("/run", methods=["POST"])
@login_required
@require_permission("config_write")
def run_now():
    """Run the sweep in the foreground of this request — the operator asked
    for it and expects the outcome in the flash, same as probe discovery."""
    from ..services import metrics_collect as mc
    res = mc.sweep()
    flash("Scrape sweep: %(ok)d/%(targets)d ok, %(errors)d error(s), "
          "%(series)d series in %(ms)d ms" % res,
          "success" if not res["errors"] else "warning")
    return redirect(url_for("metrics_admin.index"))
