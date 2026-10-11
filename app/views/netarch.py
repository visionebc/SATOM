"""Fleet → Architecture — operator-drawn diagrams with a live device overlay.

GET  /net-architecture/                  list + the selected drawing
POST /net-architecture/new               create an empty drawing      (config_write)
POST /net-architecture/<id>/save         store the drawing (JSON)     (config_write)
POST /net-architecture/<id>/delete       remove it                    (config_write)
GET  /net-architecture/<id>/live         read the bound devices now   (view)

The page itself never calls a device: the drawing renders from the database,
and the overlay is a separate request the browser makes afterwards, so a
FortiGate that is down costs a red badge, not a page that does not load.
The logic lives in :mod:`app.services.netarch`; this module scopes, gates,
audits and renders.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from flask import (Blueprint, abort, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..extensions import db
from ..models import Appliance, Permission, visible_appliances
from ..models_netarch import ArchDiagram
from ..services import netarch as na
from ..services.audit import log_action

bp = Blueprint("netarch", __name__, url_prefix="/net-architecture")


def _visible() -> dict[int, Appliance]:
    return {a.id: a for a in visible_appliances().all()}


def _appliance_links(appl: Appliance) -> dict:
    """Where an operator goes from a device element. Scout and Sentinel are
    the tools this page exists to feed; each link is offered only when the
    route exists and the user passes its gate."""
    from flask import current_app
    may_open = current_app.jinja_env.globals.get("may_open", lambda e: True)
    links = {"detail": url_for("appliances.detail", id=appl.id)}
    if may_open("scout.index"):
        links["scout"] = url_for("scout.index", appliance_id=appl.id)
    if may_open("sentinel.index"):
        links["sentinel"] = url_for("sentinel.index")
    return links


@bp.route("/")
@login_required
@require_permission(Permission.VIEW)
def index():
    diagrams = ArchDiagram.query.order_by(ArchDiagram.name).all()
    sel = None
    want = request.args.get("id", type=int)
    if want:
        sel = next((d for d in diagrams if d.id == want), None)
    if sel is None and diagrams:
        sel = diagrams[0]
    vis = _visible()
    appliances = [{"id": a.id, "name": a.name, "kind": a.kind or "fortiweb",
                   "host": a.host, "links": _appliance_links(a)}
                  for a in sorted(vis.values(), key=lambda a: a.name or "")]
    return render_template(
        "netarch/index.html",
        diagrams=diagrams, sel=sel,
        layout=(sel.layout_dict if sel else {"nodes": [], "edges": []}),
        appliances=appliances,
        node_types=na.NODE_TYPES,
        may_edit=current_user.can(Permission.CONFIG_WRITE))


@bp.route("/new", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def create():
    name = (request.form.get("name") or "").strip()[:120]
    if not name:
        flash("A drawing needs a name.", "warning")
        return redirect(url_for("netarch.index"))
    if ArchDiagram.query.filter_by(name=name).first():
        flash("A drawing called %s already exists." % name, "warning")
        return redirect(url_for("netarch.index"))
    d = ArchDiagram(name=name,
                    description=(request.form.get("description") or "").strip()[:2000],
                    layout=json.dumps({"nodes": [], "edges": []}),
                    created_by=current_user.username, updated_by=current_user.username)
    db.session.add(d)
    db.session.commit()
    log_action("netarch.create", name, {"id": d.id})
    return redirect(url_for("netarch.index", id=d.id))


@bp.route("/<int:did>/save", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def save(did):
    d = db.session.get(ArchDiagram, did) or abort(404)
    body = request.get_json(silent=True) or {}
    layout, errors = na.validate_layout(body.get("layout"))
    if errors:
        # Nothing is stored from a drawing with errors: half of a drawing is a
        # different drawing.
        return jsonify(ok=False, errors=errors), 400
    # A binding to a device this ADOM cannot see would let the drawing name a
    # device the operator was never shown. Refused, not dropped.
    vis = _visible()
    old = {n.get("id"): n.get("appliance_id") for n in d.layout_dict["nodes"]}
    for n in layout["nodes"]:
        aid = n.get("appliance_id")
        if aid is None or aid == old.get(n["id"]):
            continue  # unchanged binding (may belong to another ADOM's view)
        a = vis.get(aid)
        if a is None:
            return jsonify(ok=False, errors=["element %s: appliance %s is not visible "
                                             "here" % (n["id"], aid)]), 400
        want = na.NODE_TYPES[n["type"]]["device"]
        if (a.kind or "fortiweb") != want:
            return jsonify(ok=False, errors=["element %s: %s is a %s, not a %s"
                                             % (n["id"], a.name, a.kind, want)]), 400
    if "name" in body:
        name = str(body.get("name") or "").strip()[:120]
        if name and name != d.name:
            if ArchDiagram.query.filter(ArchDiagram.name == name,
                                        ArchDiagram.id != d.id).first():
                return jsonify(ok=False, errors=["that name is taken"]), 400
            d.name = name
    if "description" in body:
        d.description = str(body.get("description") or "")[:2000]
    d.layout = json.dumps(layout, sort_keys=True)
    d.updated_by = current_user.username
    db.session.commit()
    log_action("netarch.save", d.name, {"id": d.id, "nodes": len(layout["nodes"]),
                                         "edges": len(layout["edges"])})
    return jsonify(ok=True, layout=layout)


@bp.route("/<int:did>/delete", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def delete(did):
    d = db.session.get(ArchDiagram, did) or abort(404)
    name = d.name
    db.session.delete(d)
    db.session.commit()
    log_action("netarch.delete", name, {"id": did})
    flash("Drawing %s removed." % name, "success")
    return redirect(url_for("netarch.index"))


def _read_fortigate(appl):
    from ..clients.fortigate import FortiGateClient
    try:
        return na.fortigate_snapshot(FortiGateClient(appl, timeout=8.0))
    except Exception as exc:  # noqa: BLE001 — a dead box is a red badge, not a 500
        return {"interfaces": [], "policies": [], "errors": [str(exc)[:300]]}


@bp.route("/<int:did>/live")
@login_required
@require_permission(Permission.VIEW)
def live(did):
    """Read every bound device of the drawing now (read-only, parallel).

    Back-end probes go only to URLs stored in the drawing — the request
    carries no address, so this route cannot be pointed anywhere else."""
    from flask import current_app

    d = db.session.get(ArchDiagram, did) or abort(404)
    layout = d.layout_dict
    vis = _visible()
    out: dict = {"devices": {}, "flows": {}, "probes": {}, "hidden": []}
    jobs = {}
    app = current_app._get_current_object()

    def in_ctx(fn, *args):
        with app.app_context():
            return fn(*args)

    with ThreadPoolExecutor(max_workers=8) as pool:
        for n in layout["nodes"]:
            aid = n.get("appliance_id")
            if aid is not None:
                a = vis.get(aid)
                if a is None:
                    out["hidden"].append(n["id"])
                    continue
                out["devices"][n["id"]] = {"appliance_id": a.id, "name": a.name,
                                           "kind": a.kind, "host": a.host,
                                           "links": _appliance_links(a)}
                if n["type"] == "fortigate" and a.kind == "fortigate":
                    jobs[("fgt", n["id"])] = pool.submit(
                        in_ctx, lambda i: _read_fortigate(db.session.get(Appliance, i)),
                        a.id)
            if n.get("url"):
                jobs[("probe", n["id"])] = pool.submit(na.probe_http, n["url"],
                                                       n.get("header") or "")
        for (kind, nid), fut in jobs.items():
            res = fut.result()
            if kind == "fgt":
                out["devices"][nid]["fortigate"] = res
                out["flows"][nid] = na.policy_flows(layout, nid, res)
            else:
                out["probes"][nid] = res
    return jsonify(out)
