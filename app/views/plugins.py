"""Plugins — super-admin authored HTML/Jinja/JS views in a hard sandbox.

Author a view/widget, preview it live in an isolated iframe, promote it through
draft -> testing -> published. Published plugins appear under "Custom Views".
Every render goes through ``plugin_sandbox.safe_render`` (immutable Jinja
sandbox + curated read-only data), and the document is only ever served inside a
``sandbox="allow-scripts"`` iframe WITHOUT allow-same-origin — an opaque origin
that cannot touch the app's cookies, DOM or session.
"""
from __future__ import annotations

import json
from functools import wraps

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, abort, jsonify, Response, make_response)
from flask_login import login_required, current_user

from ..extensions import db
from ..models import Plugin, Permission
from ..services import plugin_sandbox as sandbox
from ..services import plugin_examples as examples
from ..services.audit import log_action
from ..services.product_scope import stamp, scope_query

bp = Blueprint("plugins", __name__, url_prefix="/plugins")


def _examples_json() -> str:
    """Serialize the example catalog for the editor's JSON island (neutralise
    any ``</script>`` so it can sit safely inside a <script> tag)."""
    return json.dumps(examples.all_examples()).replace("</", "<\\/")


def _dev_opts_json() -> str:
    """Live appliance options (scoped to the current ADOM) for the editor's
    device-selector builder, safe to embed in a <script> island."""
    opts = sandbox._appliance_options(stamp())
    return json.dumps(opts).replace("</", "<\\/")


def superadmin_required(fn):
    """Gate: only a super-admin may author plugins. In this app that is a user
    with the full admin capability set (``User.is_admin_capable`` — USER_MANAGE
    plus profile management), the same bar the anti-lockout guard uses."""
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if not current_user.can("studio.plugin_studio"):
            abort(403)
        return fn(*a, **kw)
    return wrapper


@bp.route("/")
@superadmin_required
def index():
    plugins = (scope_query(Plugin.query, Plugin.product)
               .order_by(Plugin.updated_at.desc()).all())
    return render_template("plugins/list.html", plugins=plugins,
                           datasets=sandbox.dataset_catalog())


@bp.route("/new")
@superadmin_required
def new():
    return render_template("plugins/editor.html", plugin=None,
                           datasets=sandbox.dataset_catalog(),
                           examples_json=_examples_json(),
                           params_json="[]",
                           device_options_json=_dev_opts_json(),
                           example_cats=examples.categories())


@bp.route("/<int:pid>/edit")
@superadmin_required
def edit(pid):
    plugin = Plugin.query.get_or_404(pid)
    return render_template("plugins/editor.html", plugin=plugin,
                           datasets=sandbox.dataset_catalog(),
                           examples_json=_examples_json(),
                           params_json=json.dumps(plugin.param_defs).replace("</", "<\\/"),
                           device_options_json=_dev_opts_json(),
                           example_cats=examples.categories())


@bp.route("/save", methods=["POST"])
@bp.route("/<int:pid>/save", methods=["POST"])
@superadmin_required
def save(pid=None):
    f = request.form
    name = (f.get("name") or "").strip()
    if not name:
        flash("A name is required.", "error")
        return redirect(url_for("plugins.new"))
    ds = f.getlist("datasets")
    ds = [k for k in ds if k in sandbox.DATASETS]  # entitlement filter
    if pid:
        plugin = Plugin.query.get_or_404(pid)
    else:
        plugin = Plugin(created_by=current_user.username, product=stamp())
        plugin.slug = _unique_slug(sandbox.slugify(name))
        db.session.add(plugin)
    plugin.name = name
    plugin.kind = f.get("kind") if f.get("kind") in Plugin.KINDS else "view"
    plugin.icon = (f.get("icon") or "bi-puzzle").strip()[:32]
    plugin.jinja = f.get("jinja") or ""
    plugin.css = f.get("css") or ""
    plugin.js = f.get("js") or ""
    plugin.data_sources = json.dumps(ds)
    plugin.params = json.dumps(sandbox.clean_param_defs(f.get("params")))
    db.session.commit()
    log_action("plugin.save", target=plugin.slug, extra={"id": plugin.id})
    flash(f"Saved “{plugin.name}”.", "success")
    return redirect(url_for("plugins.edit", pid=plugin.id))


@bp.route("/<int:pid>/status", methods=["POST"])
@superadmin_required
def set_status(pid):
    """Move a plugin through draft -> testing -> published with GATES.

    * A plugin must reach ``testing`` before it can be ``published`` — you cannot
      jump straight from draft to live.
    * Publishing is refused if the saved body does not render cleanly (its
      datasets load + the sandbox render returns no error), so a broken view can
      never be promoted to every engineer's Custom Views.
    * Demoting back to ``draft``/``testing`` is always allowed.
    """
    plugin = Plugin.query.get_or_404(pid)
    new_status = request.form.get("status")
    if new_status not in Plugin.STATUSES:
        abort(400)

    if new_status == "published":
        if plugin.status != "testing":
            flash("Move the view to “testing” and preview it before publishing.",
                  "error")
            return redirect(url_for("plugins.edit", pid=plugin.id))
        data = sandbox.load_datasets(plugin.datasets)
        params = sandbox.resolve_params(plugin.param_defs, {})
        _html, err = sandbox.safe_render(plugin.jinja, data, params)
        if err:
            flash(f"Cannot publish — the view still has a render error: {err}",
                  "error")
            return redirect(url_for("plugins.edit", pid=plugin.id))

    plugin.status = new_status
    if new_status == "published":
        from datetime import datetime
        plugin.published_at = datetime.utcnow()
    db.session.commit()
    log_action("plugin.status", target=plugin.slug, extra={"status": new_status})
    flash(f"“{plugin.name}” is now {new_status}.", "success")
    return redirect(url_for("plugins.edit", pid=plugin.id))


@bp.route("/<int:pid>/delete", methods=["POST"])
@superadmin_required
def delete(pid):
    plugin = Plugin.query.get_or_404(pid)
    slug = plugin.slug
    db.session.delete(plugin)
    db.session.commit()
    log_action("plugin.delete", target=slug)
    flash("Plugin deleted.", "success")
    return redirect(url_for("plugins.index"))


@bp.route("/<int:pid>/frame")
@login_required
def frame(pid):
    """The ISOLATED document. Rendered sandboxed, served with a hardened CSP,
    and meant to be embedded ONLY via <iframe sandbox="allow-scripts">.

    A PUBLISHED plugin is viewable by any signed-in user (the whole point is
    engineer efficiency); draft/testing stays author-only (super-admin)."""
    plugin = Plugin.query.get_or_404(pid)
    if plugin.status != "published" and not getattr(
            current_user, "is_admin_capable", False):
        abort(403)
    live = request.args.get("live")  # unsaved-body preview from the editor
    if live is not None and not getattr(current_user, "is_admin_capable", False):
        abort(403)  # live-render of arbitrary source is an author-only tool
    src = live if live is not None else plugin.jinja
    keys = plugin.datasets
    data = sandbox.load_datasets(keys)
    params = sandbox.resolve_params(plugin.param_defs, request.args)
    html, _err = sandbox.safe_render(src, data, params)
    doc = _frame_document(plugin, html, data, params)
    resp = make_response(doc)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    # The plugin's own JS is inline user code; it is safe because the iframe is
    # a sandboxed OPAQUE origin (no allow-same-origin) — it cannot reach the app.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; img-src data: https:; "
        "script-src 'unsafe-inline'; font-src data:; sandbox allow-scripts")
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    return resp


@bp.route("/preview", methods=["POST"])
@superadmin_required
def preview():
    """Render an UNSAVED body (live editor preview) and return the document."""
    src = request.form.get("jinja") or ""
    keys = [k for k in request.form.getlist("datasets") if k in sandbox.DATASETS]
    data = sandbox.load_datasets(keys)
    pdefs = sandbox.clean_param_defs(request.form.get("params"))
    params = sandbox.resolve_params(pdefs, request.form)
    html, err = sandbox.safe_render(src, data, params)
    css = request.form.get("css") or ""
    js = request.form.get("js") or ""

    class _P:  # lightweight shim so _frame_document works for unsaved content
        name = "preview"
        css = ""
        js = ""
    p = _P()
    p.css, p.js = css, js
    doc = _frame_document(p, html, data, params)
    resp = make_response(doc)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; img-src data: https:; "
        "script-src 'unsafe-inline'; font-src data:; sandbox allow-scripts")
    return resp


@bp.route("/gallery")
@login_required
def gallery():
    """Published custom views, for every signed-in user (engineer consumption)."""
    plugins = (scope_query(Plugin.query, Plugin.product)
               .filter_by(status="published")
               .order_by(Plugin.name).all())
    return render_template("plugins/gallery.html", plugins=plugins)


# --- Published render host (embeds the frame inside the app chrome) ----------
@bp.route("/view/<slug>")
@login_required
def view(slug):
    plugin = Plugin.query.filter_by(slug=slug).first_or_404()
    if plugin.status != "published" and not getattr(
            current_user, "is_admin_capable", False):
        abort(403)  # testing/draft are author-only previews
    param_defs = sandbox.param_options(plugin.param_defs, plugin.product)
    initial = sandbox.resolve_params(plugin.param_defs, request.args)
    return render_template("plugins/view.html", plugin=plugin,
                           param_defs=param_defs, initial=initial)


def _unique_slug(base: str) -> str:
    slug, n = base, 1
    while Plugin.query.filter_by(slug=slug).first() is not None:
        n += 1
        slug = f"{base}-{n}"
    return slug


def _frame_document(plugin, body_html: str, data: dict,
                    params: dict | None = None) -> str:
    css = getattr(plugin, "css", "") or ""
    js = getattr(plugin, "js", "") or ""
    # Neutralise any ``</script>`` in the injected JSON so a dataset/param value
    # (e.g. a device policy comment synced from a FortiWeb) can never break out
    # of its <script> island — the same guard the editor's JSON islands use.
    data_json = json.dumps(data).replace("</", "<\\/")
    params_json = json.dumps(params or {}).replace("</", "<\\/")
    # Datasets are ALSO exposed to the plugin JS as a JSON island (it can't fetch
    # them back — opaque origin — so we inject them here).
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<style>body{margin:0;font-family:Inter,system-ui,sans-serif;"
        "background:#080d1a;color:#e2e8f0;padding:16px}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid rgba(148,163,184,.15);padding:6px 10px;"
        "text-align:left;font-size:13px}th{text-transform:uppercase;"
        "font-size:11px;color:#94a3b8}</style>"
        f"<style>{css}</style></head><body>"
        f"{body_html}"
        f"<script id='plugin-data' type='application/json'>{data_json}</script>"
        f"<script id='plugin-params' type='application/json'>{params_json}</script>"
        "<script>window.pluginData=JSON.parse("
        "document.getElementById('plugin-data').textContent||'{}');"
        "window.pluginParams=JSON.parse("
        "document.getElementById('plugin-params').textContent||'{}');</script>"
        f"<script>{js}</script>"
        "</body></html>"
    )
