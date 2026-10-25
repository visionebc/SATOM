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
from flask_babel import gettext as _
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
# and widgets become ordinary Plugin Studio rows; code plugins (Vision EBC
# signed only) are written to data/plugins/code/ and mount at /x/<slug>/ after
# a restart; apps bring their stores, connections and API versions.
#
# Two steps (2026-10-25): the upload is checked and shown -- problems, what
# it creates and keeps, where it lands, who signed it -- with a password box
# for every connection it creates that needs a secret; Confirm installs it
# through services.plugin_import, the code path /api/v1/builder/import uses
# too. The bytes wait under the data directory (plugin_import.stage), bound to
# the uploader, for one hour; never in the session cookie.
def _import_back():
    ref = request.referrer or ""
    return ref if "/studio" in ref else url_for("plugins.index")


@bp.route("/import", methods=["POST"])
@superadmin_required
def import_package():
    from ..services import plugin_import as PI

    up = request.files.get("package")
    if up is None or not up.filename:
        flash(_("Choose a .satomplugin file to import."), "error")
        return redirect(_import_back())
    data = up.read(pkgfmt.MAX_PACKAGE + 1)
    try:
        PI.read(data, stamp())
    except PI.ImportRefused as exc:
        flash(_("Import refused: %(why)s", why=str(exc)), "error")
        return redirect(_import_back())
    token = PI.stage(data, owner_id=current_user.id, product=stamp(), filename=up.filename,
                     allow_downgrade=request.form.get("allow_downgrade") == "1")
    return redirect(url_for("plugins.import_preview", token=token))


def _staged_or_none(token):
    from ..services import plugin_import as PI
    got = PI.load(token, current_user.id)
    if got is None:
        flash(_("That upload is no longer waiting (it expires after one hour). "
                "Upload the package again."), "error")
    return got


@bp.route("/import/<token>")
@superadmin_required
def import_preview(token):
    from ..services import plugin_import as PI

    got = _staged_or_none(token)
    if got is None:
        return redirect(url_for("plugins.index"))
    data, meta = got
    try:
        info = PI.inspect(data, user=current_user, product=meta.get("product") or "",
                          via="ui")
    except PI.ImportRefused as exc:
        PI.discard(token)
        flash(_("Import refused: %(why)s", why=str(exc)), "error")
        return redirect(url_for("plugins.index"))
    return render_template("plugins/import_preview.html", info=info, token=token,
                           meta=meta)


@bp.route("/import/<token>/confirm", methods=["POST"])
@superadmin_required
def import_confirm(token):
    from ..services import plugin_import as PI

    got = _staged_or_none(token)
    if got is None:
        return redirect(url_for("plugins.index"))
    data, meta = got
    PI.discard(token)  # one confirmation per upload, whatever its outcome
    secrets = {k[len("secret_"):]: v for k, v in request.form.items()
               if k.startswith("secret_") and v}
    try:
        rep = PI.import_package(
            data, user=current_user, product=meta.get("product") or "", via="ui",
            allow_downgrade=bool(meta.get("allow_downgrade"))
            or request.form.get("allow_downgrade") == "1",
            secrets=secrets)
    except PI.ImportRefused as exc:
        msg = "; ".join(p["message"] for p in exc.problems[:8])
        flash(_("Import refused: %(why)s", why=msg or str(exc)), "error")
        return redirect(url_for("plugins.index"))
    signed = (_("signed by %(who)s", who=rep["signer_label"]) if rep["signer"]
              else _("unsigned"))
    nothing = _("nothing")
    if rep["kind"] == "app":
        flash(_("Installed app “%(name)s” %(version)s (%(signed)s). Created: %(created)s. "
                "Kept: %(kept)s. To do: %(todo)s.", name=rep["name"], version=rep["version"],
                signed=signed, created=", ".join(rep["created"]) or nothing,
                kept=", ".join(rep["kept"]) or nothing,
                todo="; ".join(rep["todo"]) or nothing), "success")
        return redirect(url_for("studio.app_edit", slug=rep["app_slug"]))
    if rep["kind"] == "code":
        flash(_("Installed code plugin “%(name)s” %(version)s (%(signed)s). It loads at "
                "the next `satom execute restart-all`.", name=rep["name"],
                version=rep["version"], signed=signed), "success")
        return redirect(url_for("plugins.index") + "#code-plugins")
    note = " ".join(w[:1].upper() + w[1:] + "." for w in rep["warnings"])
    flash(_("%(what)s “%(name)s” %(version)s (%(signed)s) — status %(status)s.",
            what=_("Updated") if rep.get("updated") else _("Imported"), name=rep["name"],
            version=rep["version"], signed=signed, status=rep["lands_in"])
          + (" " + note if note else ""), "warning" if note else "success")
    return redirect(url_for("plugins.edit", pid=rep["plugin_id"]))


@bp.route("/import/<token>/cancel", methods=["POST"])
@superadmin_required
def import_cancel(token):
    from ..services import plugin_import as PI

    if PI.load(token, current_user.id) is not None:
        PI.discard(token)
    flash(_("Import cancelled; the upload was deleted."), "success")
    return redirect(url_for("plugins.index"))


# --- Trusted publishers (contract §8) ----------------------------------------
# Ed25519 keys a super-admin registers, on top of the Vision EBC key pinned in
# plugin_package.TRUSTED_KEYS: a SATOM Builder's publisher key, typically. A
# publisher's signature makes a view or widget land in testing; it never makes
# a code plugin acceptable (services.plugin_import). Disabled = not trusted.
@bp.route("/publishers")
@superadmin_required
def publishers():
    from ..services import plugin_publishers as PP
    return render_template("plugins/publishers.html", publishers=PP.list_publishers(),
                           vision_keys=sorted(pkgfmt.TRUSTED_KEYS),
                           adom_choices=_adom_choices())


def _adom_choices() -> list:
    try:
        from ..branding import live_products
        return [str(k) for k in live_products("tokens")]
    except Exception:  # noqa: BLE001 -- the page opens without the ADOM registry
        return []


@bp.route("/publishers", methods=["POST"])
@superadmin_required
def publisher_add():
    from ..services import plugin_publishers as PP
    try:
        row, created = PP.add(request.form.get("label"), request.form.get("public_key"),
                              current_user.username, request.form.getlist("adoms"))
    except PP.PublisherError as exc:
        flash(_("Publisher refused: %(why)s", why=str(exc)), "error")
        return redirect(url_for("plugins.publishers"))
    if created:
        log_action("plugin.publisher.add", target=row.key_id,
                   extra={"label": row.label, "adoms": row.adoms})
        flash(_("Publisher “%(label)s” registered (key %(kid)s).", label=row.label,
                kid=row.key_id[:16]), "success")
    else:
        flash(_("That key is already registered as “%(label)s”.", label=row.label), "warning")
    return redirect(url_for("plugins.publishers"))


@bp.route("/publishers/<key_id>/<action>", methods=["POST"])
@superadmin_required
def publisher_toggle(key_id, action):
    from ..services import plugin_publishers as PP
    if action not in ("enable", "disable"):
        abort(404)
    row = PP.get(key_id)
    if row is None:
        abort(404)
    PP.set_enabled(row, action == "enable")
    log_action("plugin.publisher.%s" % action, target=row.key_id, extra={"label": row.label})
    flash(_("Publisher “%(label)s” %(state)s.", label=row.label,
            state=_("enabled") if row.enabled else _("disabled")), "success")
    return redirect(url_for("plugins.publishers"))


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
