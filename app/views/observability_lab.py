# app/views/observability_lab.py
"""Observability (lab) — a separate URL, ``/observability/``, that shows the
satom-observability views over SATOM's own data (operator request 2026-11-05:
"as a separate URL so nothing of SATOM changes; inventory and everything comes
from the SATOM database").

Read-only by construction: every route is GET, needs ``view``, scopes devices
through :func:`visible_appliances` / :func:`visible_appliance_or_404` (ADOM and
maintenance confinement included) and reads only the database and
VictoriaMetrics through :mod:`app.services.obs_lab`. Not in the sidebar: the
trial is reached by its URL.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import visible_appliance_or_404
from ..services import obs_lab

bp = Blueprint("observability_lab", __name__, url_prefix="/observability")


@bp.route("/")
@login_required
@require_permission("view")
def index():
    return render_template("observability_lab/index.html", inv=obs_lab.inventory())


@bp.route("/device/<int:appliance_id>")
@login_required
@require_permission("view")
def device(appliance_id):
    appl = visible_appliance_or_404(appliance_id)
    return render_template("observability_lab/device.html", a=appl,
                           kind_label=obs_lab.KIND_LABEL.get(appl.kind, appl.kind),
                           d=obs_lab.device_layers(appl))


@bp.route("/flows")
@login_required
@require_permission("view")
def flows():
    rows = obs_lab.flows()
    only = request.args.get("only", "")
    if only == "problems":
        rows = [r for r in rows if r["measured_up"] is False or r["status"] != "enable"
                or any(h["egress"] == "no route" for h in r["hops"])]
    return render_template("observability_lab/flows.html", rows=rows, only=only)


@bp.route("/search")
@login_required
@require_permission("view")
def search():
    q = request.args.get("q", "")
    hits = obs_lab.search(q)
    if request.args.get("format") == "json":
        return jsonify({"q": q, "hits": hits})
    return render_template("observability_lab/search.html", q=q, hits=hits)
