"""/api/v1/ui — share this node's look with another SATOM node.

* ``GET /api/v1/ui/themes``  — the theme names, and which one is active
* ``GET /api/v1/ui/theme``   — one theme as a ``satom.ui-theme/2`` document
  (tokens + logo + favicon): the active theme, or ``?name=<theme name>``

Settings -> Appearance -> "Import from a site" -> SATOM node calls the second
one with a token minted on THIS node. A ``read`` token is enough: a theme is
brand colours and a logo the login page already shows to anyone, and nothing
here writes.
"""
from __future__ import annotations

from flask import jsonify, request

from ..extensions import limiter
from . import bp
from .auth import _err, token_required


@bp.route("/ui/themes", methods=["GET"])
@token_required("read")
def ui_themes():
    from ..models_theme import UiTheme
    rows = UiTheme.query.order_by(UiTheme.name).all()
    return jsonify({"themes": [{"name": r.name, "active": bool(r.is_active),
                                "builtin": bool(r.builtin)} for r in rows]})


@bp.route("/ui/theme", methods=["GET"])
@limiter.limit("30 per minute")
@token_required("read")
def ui_theme():
    from ..models_theme import UiTheme
    from ..services import theme_portable
    from ..services import theme_service
    from ..views.settings import _theme_dir
    name = (request.args.get("name") or "").strip()
    if name:
        row = UiTheme.query.filter_by(name=name).first()
        if row is None:
            return _err(404, "not_found", "No theme named %r on this node." % name[:128])
    else:
        row = UiTheme.query.filter_by(is_active=True).first() or \
            UiTheme.query.filter_by(slug=theme_service.BUILTIN_SLUG).first()
        if row is None:
            return _err(404, "not_found", "This node has no theme.")
    return jsonify(theme_portable.export_document(row, _theme_dir()))
