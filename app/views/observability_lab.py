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


def in_area(path: str) -> bool:
    return path == PREFIX or path.startswith(PREFIX + "/")


def obs_asset(path: str) -> str:
    """URL of a file of the app's static tree (theme, shell script), with an
    mtime cache-buster like SATOM's own ``asset()``."""
    import os
    folder = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "observability_lab", "static")
    try:
        v = int(os.path.getmtime(os.path.join(folder, path)))
    except OSError:
        v = 0
    return "%s%s/static/%s?v=%d" % (request.script_root, PREFIX, path, v)


@bp.app_context_processor
def _shell_context():
    """``obs_shell``: this SATOM page is drawn in the Observability shell
    (base.html) because it lives under /observability/ — SATOM's Monitoring
    views since 2026-11-17. ``obs_confined``: the account is ADOM-confined,
    so the app's own pages (and their status feeds) are not offered."""
    try:
        shell = in_area(request.path)
    except RuntimeError:  # no request (a mail rendered by a job)
        return {"obs_shell": False}
    if not shell:
        return {"obs_shell": False}
    from ..services.concept_map import AREA_PERMISSION
    if not (current_user.is_authenticated and current_user.can(AREA_PERMISSION)):
        # The 403 of the area gate is drawn in SATOM's own shell: a menu of
        # the area would list pages this account cannot open.
        return {"obs_shell": False}
    from .. import observability_nav
    try:
        nav = observability_nav.build()
    except Exception:  # noqa: BLE001 — a page never 500s on its menu
        current_app.logger.exception("observability nav")
        nav = []
    from ..services.product_scope import session_product
    # "confined" for the shell = the app's own pages (and their status feeds)
    # are not offered here: an ADOM-confined account, or a device ADOM (the
    # app shows the whole inventory). shell.js reloads the page when its feed
    # is redirected, so offering the feed where the gate bounces it would loop.
    lab = observability_nav.lab_offered(session_product())
    return {"obs_shell": True, "obs_confined": not lab, "obs_nav": nav,
            "obs_asset": obs_asset, "obs_adoms": _adom_choices()}


def _adom_choices() -> list[dict]:
    """The ADOMs the Monitoring pages can be shown in, for the top bar: Global
    plus every active product ADOM the account may enter. Each links the SAME
    page with ``_adom`` — the per-tab ADOM, the way SATOM's switcher does it."""
    from urllib.parse import urlencode
    from ..services import product_scope as ps
    try:
        current = ps.session_product()
        allowed = ps.restricted_adoms()
        rows = [("global", "Global")] + [
            (k, t) for k, t in ps.device_products() if ps.adom_allowed(k, allowed)]
    except Exception:  # noqa: BLE001 — never 500 a page on its top bar
        return []
    args = [(k, v) for k, v in request.args.items(multi=True) if k != "_adom"]
    out = []
    for key, title in rows:
        qs = urlencode(args + [("_adom", key)])
        out.append({"key": key, "title": title, "current": key == current,
                    "href": request.script_root + request.path + "?" + qs})
    return out


def area_gate():
    """``observability.access`` in front of EVERYTHING under /observability/
    (operator request 2026-11-17): the proxied app and SATOM's own Monitoring
    views, which live at /observability/monitoring/. One check by path, so a
    page added under the prefix cannot forget it. Anonymous requests pass
    through to the views, whose ``login_required`` sends them to the login."""
    if not in_area(request.path) or not current_user.is_authenticated:
        return None
    from ..services.concept_map import AREA_PERMISSION
    if current_user.can(AREA_PERMISSION):
        return None
    abort(403)


@bp.route("", methods=METHODS, strict_slashes=False)
@bp.route("/<path:rest>", methods=METHODS)
@login_required
@require_permission("view")
def proxy(rest: str = ""):
    if _confined() and not rest.startswith("static/"):
        # The app has no ADOM filter, so an ADOM-confined account is refused.
        # Its stylesheets are not data: the Monitoring pages (ADOM-scoped
        # SATOM views, which such an account DOES open) are drawn with them.
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
    if not rest.startswith(("static/", "api/")):
        # The ONE sidebar of the area (app/observability_nav.py): the app
        # draws the same menu SATOM's Monitoring pages draw, Monitoring
        # entries included. Built here because only SATOM can build its URLs.
        from .. import observability_nav
        try:
            env["satom.obs_nav"] = observability_nav.build()
        except Exception:  # noqa: BLE001 — the app falls back to its own menu
            current_app.logger.exception("observability nav")
    return Response.from_app(lab_app(), env, buffered=True)


csrf.exempt(proxy)
