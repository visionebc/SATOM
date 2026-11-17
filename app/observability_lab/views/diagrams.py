from flask import (Blueprint, Response, abort, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required

from .. import overlay
from ..extensions import db
from ..graph import NODE_TYPES, validate_layout
from ..importers import ImportError_, detect_and_parse
from ..models import Diagram, Fact, Source, audit, utcnow

bp = Blueprint("diagrams", __name__, url_prefix="/diagrams")


def _get(did) -> Diagram:
    d = db.session.get(Diagram, did)
    if d is None:
        abort(404)
    return d


@bp.route("/")
@login_required
def index():
    return render_template("diagrams/index.html",
                           diagrams=Diagram.query.order_by(Diagram.name).all())


@bp.route("/new", methods=["POST"])
@login_required
def new():
    name = (request.form.get("name") or "").strip()[:120] or "Untitled diagram"
    d = Diagram(name=name, layout={"nodes": [], "edges": []}, created_by=current_user.username)
    db.session.add(d)
    db.session.flush()
    audit(current_user.username, "diagram.create", "%s #%d" % (name, d.id))
    db.session.commit()
    return redirect(url_for("diagrams.edit", did=d.id))


@bp.route("/import", methods=["POST"])
@login_required
def import_file():
    f = request.files.get("file")
    pasted = (request.form.get("text") or "").strip()
    if (not f or not f.filename) and not pasted:
        flash("Choose a file or paste a diagram.", "warning")
        return redirect(url_for("diagrams.index"))
    data = f.read() if f and f.filename else pasted.encode()
    fname = f.filename if f and f.filename else ""
    try:
        layout, warnings, fmt = detect_and_parse(fname, data)
    except ImportError_ as exc:
        flash("Import failed: %s" % exc, "danger")
        return redirect(url_for("diagrams.index"))
    name = (request.form.get("name") or "").strip()[:120] or (fname.rsplit(".", 1)[0] if fname else "Imported diagram")
    d = Diagram(name=name, layout=layout, origin=fmt, created_by=current_user.username)
    db.session.add(d)
    db.session.flush()
    audit(current_user.username, "diagram.import", "%s #%d" % (name, d.id),
          "%s: %d elements, %d links, %d warnings" % (fmt, len(layout["nodes"]), len(layout["edges"]), len(warnings)))
    db.session.commit()
    flash("Imported from %s: %d elements, %d links." % (fmt, len(layout["nodes"]), len(layout["edges"])), "success")
    for w in warnings[:25]:
        flash(w, "warning")
    if len(warnings) > 25:
        flash("…and %d more warnings." % (len(warnings) - 25), "warning")
    return redirect(url_for("diagrams.edit", did=d.id))


@bp.route("/<int:did>")
@login_required
def edit(did):
    d = _get(did)
    sources = [{"id": s.id, "name": s.name, "kind": s.kind} for s in Source.query.order_by(Source.name)]
    return render_template("diagrams/edit.html", d=d, node_types=NODE_TYPES, sources=sources)


@bp.route("/<int:did>/layout")
@login_required
def layout(did):
    d = _get(did)
    return jsonify(layout=d.layout, version=d.version, name=d.name)


@bp.route("/<int:did>/save", methods=["POST"])
@login_required
def save(did):
    d = _get(did)
    body = request.get_json(silent=True) or {}
    if int(body.get("version") or 0) != d.version:
        return jsonify(ok=False, conflict=True, version=d.version,
                       errors=["someone else saved this diagram meanwhile — reload"]), 409
    layout, errors = validate_layout(body.get("layout"))
    if errors:
        return jsonify(ok=False, errors=errors), 400
    known = {s.id for s in Source.query.all()}
    bad = [n["id"] for n in layout["nodes"] if n.get("source_id") and n["source_id"] not in known]
    if bad:
        return jsonify(ok=False, errors=["unknown source on: %s" % ", ".join(bad)]), 400
    if body.get("name"):
        d.name = str(body["name"])[:120]
    d.layout, d.version, d.updated_at = layout, d.version + 1, utcnow()
    audit(current_user.username, "diagram.save", "%s #%d" % (d.name, d.id),
          "%d elements, %d links" % (len(layout["nodes"]), len(layout["edges"])))
    db.session.commit()
    return jsonify(ok=True, version=d.version)


@bp.route("/<int:did>/overlay")
@login_required
def live(did):
    d = _get(did)
    return jsonify(overlay.for_layout(d.layout or {}))


@bp.route("/<int:did>/objects/<int:sid>")
@login_required
def objects(did, sid):
    """Object refs a source knows (to bind a link or a node to one interface,
    policy, VIP…)."""
    _get(did)
    refs = [r[0] for r in db.session.query(Fact.object_ref).filter_by(source_id=sid).distinct()]
    return jsonify(sorted(refs))


@bp.route("/<int:did>/export")
@login_required
def export(did):
    d = _get(did)
    resp = jsonify(name=d.name, layout=d.layout, version=d.version, product="satom-observability")
    resp.headers["Content-Disposition"] = 'attachment; filename="diagram-%d.json"' % d.id
    return resp


#: Element size on the canvas (static/js/diagram.js NODE_W / NODE_H). Stored
#: positions are the element CENTRE; draw.io wants the top-left corner.
NODE_W, NODE_H = 196, 58


def drawio_model(d: Diagram) -> dict:
    """The stored drawing in the neutral shape of
    :mod:`app.services.drawio_export`. Live children (an expanded element's
    policies and back-ends) are derived from the facts on every render and
    never stored, so they are not in the file; neither is the overlay."""
    nodes = []
    for n in (d.layout or {}).get("nodes") or []:
        t = NODE_TYPES.get(n.get("type"), {})
        addr = n.get("cidr") or n.get("ip") or ""
        nodes.append({
            "id": n["id"], "label": n.get("label") or t.get("label") or n["id"],
            "sub": (t.get("label") or n.get("type") or "") + (" · " + addr if addr else ""),
            "x": float(n.get("x") or 0) - NODE_W / 2, "y": float(n.get("y") or 0) - NODE_H / 2,
            "w": NODE_W, "h": NODE_H, "shape": "round", "kind": n.get("type"),
            "fill": "#FFFFFF", "stroke": "#0A3F9F"})
    edges = [{"from": e["from"], "to": e["to"],
              "label": e.get("label") or e.get("object_ref") or "", "ends": "none"}
             for e in (d.layout or {}).get("edges") or []]
    return {"name": d.name, "nodes": nodes, "edges": edges}


@bp.route("/<int:did>/export.drawio")
@login_required
def export_drawio(did):
    from ...services import drawio_export as dx
    d = _get(did)
    try:
        data, warnings = dx.build(drawio_model(d), agent="SATOM Observability")
    except dx.ExportError as exc:
        flash("Export to draw.io: %s." % exc, "warning")
        return redirect(url_for("diagrams.edit", did=d.id))
    audit(current_user.username, "diagram.export_drawio",
          "%s #%d (%d skipped)" % (d.name, d.id, len(warnings)))
    db.session.commit()
    resp = Response(data, mimetype=dx.MIME)
    resp.headers["Content-Disposition"] = 'attachment; filename="%s"' % dx.filename(d.name)
    return resp


@bp.route("/<int:did>/delete", methods=["POST"])
@login_required
def delete(did):
    d = _get(did)
    audit(current_user.username, "diagram.delete", "%s #%d" % (d.name, d.id))
    db.session.delete(d)
    db.session.commit()
    flash("Diagram deleted.", "success")
    return redirect(url_for("diagrams.index"))
