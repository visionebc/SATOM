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
from ..services import plugin_package as pkgfmt
from ..services import plugin_code
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


def _plugin_or_404(pid: int) -> Plugin:
    """One plugin by id, in THIS ADOM only -- the list is scope_query'd, so a
    by-id route that is not would serve another ADOM's plugin one URL away."""
    return (scope_query(Plugin.query, Plugin.product)
            .filter_by(id=pid).first_or_404())


def superadmin_required(fn):
    """Gate: authoring needs the granular ``studio.plugin_studio`` key (seeded
    on the admin profile only; a custom profile may carry it too)."""
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
    from flask import current_app
    return render_template("plugins/list.html", plugins=plugins,
                           datasets=sandbox.dataset_catalog(),
                           code_plugins=plugin_code.overview(current_app))


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
    plugin = _plugin_or_404(pid)
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
        plugin = _plugin_or_404(pid)
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
    plugin = _plugin_or_404(pid)
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
    plugin = _plugin_or_404(pid)
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
    engineer efficiency); draft/testing stays with the authors -- holders of
    ``studio.plugin_studio``, the same key that opens the editor."""
    plugin = _plugin_or_404(pid)
    if plugin.status != "published" and not current_user.can(
            "studio.plugin_studio"):
        abort(403)
    live = request.args.get("live")  # unsaved-body preview from the editor
    if live is not None and not current_user.can("studio.plugin_studio"):
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
    # Images are data: only: `img-src https:` let plugin JS beacon the
    # datasets it renders to any external host (an <img src> per row).
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
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
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
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
    plugin = (scope_query(Plugin.query, Plugin.product)
              .filter_by(slug=slug).first_or_404())
    if plugin.status != "published" and not current_user.can(
            "studio.plugin_studio"):
        abort(403)  # testing/draft are author-only previews
    param_defs = sandbox.param_options(plugin.param_defs, plugin.product)
    initial = sandbox.resolve_params(plugin.param_defs, request.args)
    return render_template("plugins/view.html", plugin=plugin,
                           param_defs=param_defs, initial=initial)


# --- Plugin packages (satom.plugin/1): import / export ----------------------
# A package moves a plugin between servers WITHOUT an update package. Views
# and widgets become ordinary Plugin Studio rows; code plugins (signed only)
# are written to data/plugins/code/ and mount at /x/<slug>/ after a restart.
@bp.route("/import", methods=["POST"])
@superadmin_required
def import_package():
    from ..version import app_version

    up = request.files.get("package")
    if up is None or not up.filename:
        flash("Choose a .satomplugin file to import.", "error")
        return redirect(url_for("plugins.index"))
    try:
        pk = pkgfmt.read_package(up.read(pkgfmt.MAX_PACKAGE + 1))
    except pkgfmt.PackageError as exc:
        flash(f"Import refused: {exc}", "error")
        return redirect(url_for("plugins.index"))
    need = pk.manifest.get("min_satom")
    if need and pkgfmt.version_tuple(need) > pkgfmt.version_tuple(app_version()):
        flash(f"Import refused: {pk.slug} {pk.version} needs SATOM {need} or "
              f"newer (this server runs {app_version()}).", "error")
        return redirect(url_for("plugins.index"))
    allow_down = request.form.get("allow_downgrade") == "1"
    signed = f"signed {pk.signer[:16]}" if pk.signer else "unsigned"

    if pk.kind == "app":
        # A Plugin Studio app with its data stores, connections (no secrets)
        # and API Catalog versions -- services.studio_app_package.
        from ..services import studio_app_package as SAP
        try:
            rep = SAP.install(pk, current_user.username, allow_downgrade=allow_down)
        except pkgfmt.PackageError as exc:
            flash(f"Import refused: {exc}", "error")
            return redirect(request.referrer or url_for("plugins.index"))
        log_action("studio.app.import", target=rep["app"].slug,
                   extra={"version": pk.version, "signer": pk.signer,
                          "created": rep["created"], "kept": rep["kept"]})
        flash(f"Installed app “{pk.manifest['name']}” {pk.version} ({signed}). "
              f"Created: {', '.join(rep['created']) or 'nothing'}. "
              f"Kept: {', '.join(rep['kept']) or 'nothing'}. "
              f"To do: {'; '.join(rep['todo']) or 'nothing'}.", "success")
        return redirect(url_for("studio.app_edit", slug=rep["app"].slug))

    if pk.kind == "code":
        try:
            plugin_code.install(pk, current_user.username, allow_downgrade=allow_down)
        except pkgfmt.PackageError as exc:
            flash(f"Import refused: {exc}", "error")
            return redirect(url_for("plugins.index"))
        log_action("plugin.code.install", target=pk.slug,
                   extra={"version": pk.version, "signer": pk.signer})
        flash(f"Installed code plugin “{pk.manifest['name']}” {pk.version} "
              f"({signed}). It loads at the next `satom execute restart-all`.",
              "success")
        return redirect(url_for("plugins.index") + "#code-plugins")

    existing = Plugin.query.filter_by(slug=pk.slug).first()
    if existing is not None and (scope_query(Plugin.query, Plugin.product)
                                 .filter_by(id=existing.id).first() is None):
        flash(f"Import refused: the slug {pk.slug} belongs to a plugin of "
              f"another ADOM.", "error")
        return redirect(url_for("plugins.index"))
    if (existing is not None and existing.pkg_version and not allow_down
            and pkgfmt.version_tuple(pk.version)
            < pkgfmt.version_tuple(existing.pkg_version)):
        flash(f"Import refused: {pk.slug} {existing.pkg_version} is installed and "
              f"{pk.version} is older (tick “Allow downgrade”).", "error")
        return redirect(url_for("plugins.index"))

    wanted = [str(k) for k in pk.manifest.get("datasets") or []]
    ds = [k for k in wanted if k in sandbox.DATASETS]
    dropped = [k for k in wanted if k not in sandbox.DATASETS]
    if existing is None:
        plugin = Plugin(created_by=current_user.username, product=stamp(),
                        slug=pk.slug, status="testing" if pk.signer else "draft")
        db.session.add(plugin)
    else:
        plugin = existing
    plugin.name = pk.manifest["name"].strip()[:200]
    plugin.kind = pk.kind
    plugin.icon = pk.manifest["icon"]
    plugin.jinja = pk.text("body.jinja")
    plugin.css = pk.text("style.css")
    plugin.js = pk.text("script.js")
    plugin.data_sources = json.dumps(ds)
    plugin.params = json.dumps(sandbox.clean_param_defs(pk.manifest.get("params") or []))
    plugin.pkg_version = pk.version
    plugin.pkg_signer = pk.signer or ""
    note = ""
    if plugin.status == "published":
        # The publish gate holds for an update too: a body that no longer
        # renders goes back to testing instead of breaking Custom Views.
        data = sandbox.load_datasets(plugin.datasets)
        _html, err = sandbox.safe_render(plugin.jinja, data,
                                         sandbox.resolve_params(plugin.param_defs, {}))
        if err:
            plugin.status = "testing"
            note = f" It no longer renders cleanly ({err}), so it is back in testing."
    db.session.commit()
    log_action("plugin.import", target=plugin.slug,
               extra={"id": plugin.id, "version": pk.version, "signer": pk.signer,
                      "updated": existing is not None})
    if dropped:
        note += " Datasets this server does not have were dropped: " + ", ".join(dropped) + "."
    flash(f"{'Updated' if existing is not None else 'Imported'} “{plugin.name}” "
          f"{pk.version} ({signed}) — status {plugin.status}.{note}",
          "warning" if note else "success")
    return redirect(url_for("plugins.edit", pid=plugin.id))


@bp.route("/<int:pid>/export")
@superadmin_required
def export_package(pid):
    from ..version import app_version

    plugin = _plugin_or_404(pid)
    try:
        fname, data = pkgfmt.export_plugin(plugin, app_version())
    except pkgfmt.PackageError as exc:
        flash(f"Export failed: {exc}", "error")
        return redirect(url_for("plugins.edit", pid=pid))
    log_action("plugin.export", target=plugin.slug, extra={"id": plugin.id})
    resp = make_response(data)
    resp.headers["Content-Type"] = "application/zip"
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@bp.route("/code/<slug>/<action>", methods=["POST"])
@superadmin_required
def code_action(slug, action):
    if action not in ("enable", "disable", "remove"):
        abort(404)
    try:
        if action == "remove":
            plugin_code.remove(slug)
        else:
            plugin_code.set_enabled(slug, action == "enable")
    except (pkgfmt.PackageError, OSError, ValueError) as exc:
        flash(f"{action.capitalize()} failed: {exc}", "error")
        return redirect(url_for("plugins.index") + "#code-plugins")
    log_action(f"plugin.code.{action}", target=slug)
    flash(f"Code plugin {slug}: {action}d. The change takes effect at the next "
          f"`satom execute restart-all`.", "success")
    return redirect(url_for("plugins.index") + "#code-plugins")


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
