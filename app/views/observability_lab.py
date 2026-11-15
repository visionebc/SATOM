# app/views/observability_lab.py
"""Observability (lab) at ``/observability/`` — the satom-observability
application (``app/observability_lab``), served through SATOM.

Operator request 2026-11-05: "exactly what we have in the other project, as a
separate URL so nothing of SATOM changes; the inventory and everything comes
from the SATOM database". The application keeps its own pages, theme, CSP,
session cookie (``/observability`` only) and CSRF token; SATOM contributes the
gate in front of it:

* SATOM's own before-request chain runs first (hostguard, session, 2FA, the
  ADOM gate) because this is an ordinary SATOM route;
* ``login_required`` + ``view``; writes inside the app (diagrams, collect)
  additionally need ``config_write`` (handed over as ``is_admin``);
* an account confined to some ADOMs is refused: the app shows SATOM's whole
  inventory and has no ADOM filter of its own;
* the identity reaches the app in the WSGI environ (``satom.user``), which no
  browser can set — never in a header or a cookie.

SATOM's CSRF check is lifted for this one route only: the app checks its own
token (Flask-WTF, its own session), and SATOM's token is not in its forms.
Removing the trial: the blueprint line in ``app/__init__.py``, this module and
``app/observability_lab/``.
"""
from __future__ import annotations

import io
import threading
from urllib.parse import urlencode

from flask import Blueprint, abort, current_app, request
from flask_login import current_user, login_required
from werkzeug.wrappers import Response

from ..auth.decorators import require_permission
from ..extensions import csrf

bp = Blueprint("observability_lab", __name__, url_prefix="/observability")

PREFIX = "/observability"
METHODS = ["GET", "HEAD", "POST"]

_app_lock = threading.Lock()


def lab_app():
    """The Observability Flask app of THIS SATOM app, built on first use."""
    satom = current_app._get_current_object()
    lab = satom.extensions.get("observability_lab")
    if lab is None:
        with _app_lock:
            lab = satom.extensions.get("observability_lab")
            if lab is None:
                from ..observability_lab import create_app
                lab = satom.extensions["observability_lab"] = create_app(satom)
    return lab


def _confined() -> bool:
    from ..services.product_scope import restricted_adoms
    return restricted_adoms() is not None


def _body() -> tuple[bytes, str]:
    """The request body as the client sent it. A SATOM before-request hook may
    already have parsed a form (which drains the stream): the fields and files
    it parsed are then encoded again, so the app sees the same form."""
    parsed = "form" in request.__dict__ or "files" in request.__dict__
    if not parsed:
        return request.get_data(cache=True), ""
    if request.files:
        from werkzeug.datastructures import MultiDict
        from werkzeug.test import encode_multipart
        values = MultiDict(request.form.items(multi=True))
        for key, fs in request.files.items(multi=True):
            fs.stream.seek(0)
            values.add(key, fs)
        boundary, data = encode_multipart(values)
        return data, "multipart/form-data; boundary=%s" % boundary
    if request.form:
        return (urlencode(list(request.form.items(multi=True))).encode(),
                "application/x-www-form-urlencoded")
    return request.get_data(cache=True), ""


@bp.route("", methods=METHODS, strict_slashes=False)
@bp.route("/<path:rest>", methods=METHODS)
@login_required
@require_permission("view")
def proxy(rest: str = ""):
    if _confined():
        abort(403)
    body, ctype = _body()
    env = dict(request.environ)
    if ctype:
        env["CONTENT_TYPE"] = ctype
    env["SCRIPT_NAME"] = request.script_root + PREFIX
    env["PATH_INFO"] = request.path[len(PREFIX):] or "/"
    env["wsgi.input"] = io.BytesIO(body)
    env["CONTENT_LENGTH"] = str(len(body))
    env["satom.root"] = request.script_root
    env["satom.user"] = {"username": current_user.username,
                         "is_admin": bool(current_user.can("config_write"))}
    return Response.from_app(lab_app(), env, buffered=True)


csrf.exempt(proxy)
