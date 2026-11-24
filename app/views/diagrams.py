"""Published diagrams (``/diagrams/<id>``): the read-only viewer the sidebar's
Diagrams menu opens, and its "Export to" downloads.

A reader sees the PUBLISHED version of a diagram (``published_version``), never
the draft the editors are working on, and only diagrams of the current scope
(``services/diagram_studio.py``). Exporters run here over that normalised
model; no uploaded file is ever read by this blueprint.
"""
from __future__ import annotations

from flask import Blueprint, abort, jsonify, request, url_for
from flask_login import current_user

from ..auth.decorators import require_permission
from ..services import diagram_studio as S
from .diagram_studio import (EXPORT_FORMATS, base_config, export_response, render_page,
                             satom_copy_note)

bp = Blueprint("diagrams", __name__, url_prefix="/diagrams")


@bp.errorhandler(S.StudioError)
def _studio_error(exc: S.StudioError):
    body = {"error": str(exc)}
    body.update(exc.data or {})
    return jsonify(body), exc.status


def _published(diagram_id):
    try:
        d = S.get_diagram(diagram_id)
    except S.NotFound:
        abort(404)
    if not d.published or not d.published_version:
        abort(404)
    return d


@bp.route("/<int:diagram_id>")
@require_permission("diagrams.view")
def view(diagram_id):
    d = _published(diagram_id)
    may_edit = current_user.can("diagrams.edit")
    doc = S.published_doc(d)
    cfg = base_config(
        "viewer",
        diagram={"id": d.id, "name": d.name, "description": d.description,
                 "folder_id": d.folder_id, "published": True,
                 "version": d.published_version,
                 "published_at": S._iso(d.published_at)},
        doc=doc, libraries=S.library_list(), copyOf=satom_copy_note(doc),
        exportFormats=list(EXPORT_FORMATS) + ["png"],
        exportUrl=url_for("diagrams.view", diagram_id=d.id) + "/export/")
    if may_edit:
        cfg["editUrl"] = url_for("diagram_studio.editor", diagram_id=d.id)
    return render_page("diagrams/view.html", cfg)


@bp.route("/<int:diagram_id>/export/<fmt>")
@require_permission("diagrams.view")
def export(diagram_id, fmt):
    if fmt not in EXPORT_FORMATS:
        abort(404)
    d = _published(diagram_id)
    page = request.args.get("page") or None
    options = {k: request.args.get(k) for k in ("paper", "orientation") if request.args.get(k)}
    return export_response(S.published_doc(d), fmt, page, options,
                           audit_target="diagram:%d" % d.id)
