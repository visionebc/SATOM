"""Export any console diagram as a draw.io file.

POST /diagram-export/drawio   body: the page's description of what it draws
                              (see :mod:`app.services.drawio_export`)
                              → ``<name>.drawio`` as an attachment

Why one endpoint for every diagram: the pages draw with six different
scripts, but the file they produce must be built — and escaped — by one piece
of code, the one the tests hold. A per-page writer in JavaScript would be six
copies of the escaping that no test can run.

Access: the route reads NOTHING from the database. It converts what the
browser already shows (the page that posts it did its own permission and
ADOM checks before drawing it), so it asks only for the basic ``view`` key
and is reachable from every ADOM (``app/__init__.py`` lists the endpoint in
the gate's ``always`` set).
Each export is audited with the diagram name and its size.
"""
from __future__ import annotations

from flask import Blueprint, Response, jsonify, request
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import drawio_export as dx
from ..services.audit import log_action

bp = Blueprint("diagram_export", __name__, url_prefix="/diagram-export")

#: The largest description accepted. A 5,000-element diagram with labels and
#: table rows is well under this; anything bigger is not a drawing.
MAX_BODY = 8 * 1024 * 1024


@bp.route("/drawio", methods=["POST"])
@login_required
@require_permission(Permission.VIEW)
def drawio():
    if (request.content_length or 0) > MAX_BODY:
        return jsonify({"ok": False, "error": "diagram too large to export"}), 413
    payload = request.get_json(silent=True)
    try:
        from ..version import app_version
        data, warnings = dx.build(payload, agent="SATOM " + app_version())
    except dx.ExportError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    name = (payload or {}).get("name") if isinstance(payload, dict) else ""
    fname = dx.filename(name or "diagram")
    log_action("diagram.export_drawio", target=fname,
               extra={"elements": len(payload.get("nodes") or []),
                      "links": len(payload.get("edges") or []),
                      "skipped": len(warnings)})
    resp = Response(data, mimetype=dx.MIME)
    resp.headers["Content-Disposition"] = 'attachment; filename="%s"' % fname
    # What was left out travels with the file, so the page can say it.
    resp.headers["X-Export-Warnings"] = str(len(warnings))
    return resp
