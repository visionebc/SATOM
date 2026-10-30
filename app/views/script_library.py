"""Script Library -- the administrator's side (Administrator > Studio >
Python Studio, ``views.studio``; the library list is its Scripts pane).

Write a script (a small multi-file project), define the form operators fill
in, test it in the sandbox, publish frozen versions. Storage and validation
live in ``services.script_library``; runs execute in ``satom-scripts.service``
(``services.script_runner``), never in this web process.

Gated on the granular ``studio.script_library`` key (admin profile only).
Every write is audited. Password field values never come back to the browser:
the run record shows them masked.
"""
from __future__ import annotations

from flask import (Blueprint, Response, abort, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..services import script_library as SL
from ..services import script_vault as SV
from ..services.audit import log_action

bp = Blueprint("script_library", __name__, url_prefix="/studio/scripts")
PERM = "studio.script_library"


def _who() -> str:
    return getattr(current_user, "username", "?")


def _node() -> str:
    try:
        from ..services import self_update as su
        return su.this_node_name()
    except Exception:  # noqa: BLE001
        return ""


def _err(exc: Exception, code: int = 400):
    return jsonify({"error": str(exc)}), code


@bp.route("/")
@login_required
@require_permission(PERM)
def index():
    """Every script is an app since 2026-10-23: the list is Plugin Studio's
    Apps pane."""
    return redirect(url_for("studio.index", pane="apps"))


@bp.route("/create", methods=["POST"])
@login_required
@require_permission(PERM)
def create():
    """Kept for old forms and links: a script is created with its app."""
    from ..services import studio_apps as SA
    slug = (request.form.get("slug") or "").strip()
    name = (request.form.get("name") or "").strip()
    try:
        if SA.get(slug) is not None:
            raise SL.ScriptError("an app with the id %r already exists" % slug)
        SL.create(slug, name, _who())
        SA.ensure_script_app(slug, _who())
    except SL.ScriptError as exc:
        from flask import flash
        flash(str(exc), "danger")
        return redirect(url_for("studio.index", pane="apps"))
    log_action("script_library.create", target=slug)
    return redirect(url_for("script_library.edit", slug=slug))


# ---------------------------------------------------------------------------
#  database fields (services.db_lookup)
# ---------------------------------------------------------------------------
@bp.route("/lookup/catalog")
@login_required
@require_permission(PERM)
def lookup_catalog():
    """Tables, their non-sensitive columns and the FK edges, for the field
    designer — the Report Builder's catalogue."""
    from ..services import report_builder
    return jsonify(report_builder.catalog())


@bp.route("/lookup/related")
@login_required
@require_permission(PERM)
def lookup_related():
    """Tables reachable from ``base`` in up to two joins, with the join path."""
    from ..services import report_builder
    base = (request.args.get("base") or "").strip()
    return jsonify({"related": report_builder.related_tables(base, max_hops=2)})


@bp.route("/lookup/preview", methods=["POST"])
@login_required
@require_permission(PERM)
def lookup_preview():
    """What a database field returns right now for the signed-in user's ADOMs."""
    from ..services import db_lookup
    from ..services.product_scope import adoms_of
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(db_lookup.preview(body.get("field") or {},
                                         adoms_of(current_user),
                                         as_options=bool(body.get("options"))))
    except db_lookup.LookupError_ as exc:
        return _err(exc)


@bp.route("/<slug>/lookup/<field>")
@login_required
@require_permission(PERM)
def lookup_options(slug, field):
    """Choices of a database field of the saved draft (``?version=draft``) or
    of a published version, for the Test tab and the version viewer."""
    from ..services import db_lookup
    from ..services.product_scope import adoms_of
    ref = request.args.get("version") or "draft"
    try:
        if ref == "draft":
            script = SL.get(slug)
            fields = (script or {}).get("fields") or []
        else:
            frozen = SL.version(slug, int(ref))
            fields = (frozen or {}).get("fields") or []
    except (SL.ScriptError, ValueError):
        abort(404)
    f = next((x for x in fields if x["name"] == field
              and x["type"] in db_lookup.PICK_TYPES), None)
    if f is None:
        abort(404)
    try:
        return jsonify({"options": db_lookup.options(f, adoms_of(current_user))})
    except db_lookup.LookupError_ as exc:
        return _err(exc)


@bp.route("/<slug>")
@login_required
@require_permission(PERM)
def edit(slug):
    try:
        script = SL.get(slug)
    except SL.ScriptError:
        abort(404)
    if script is None:
        abort(404)
    from ..services import sandbox, plugin_sandbox, py_examples
    from ..services import plugin_datasets as PD
    from ..services import studio_examples as EX
    console = current_user.can("studio.python_console")
    from ..models_studio import StudioApp
    from . import directory_connections as DCV
    signin_app = StudioApp.query.filter_by(kind="script", script_slug=slug).first()
    signin = DCV.signin_context(signin_app, directories_url=url_for(
        "studio.index", pane="directories")) if signin_app is not None else {}
    return render_template("script_library/edit.html", script=script,
                           signin_app=signin_app, with_access=False, **signin,
                           console=console, template=EX.is_template("script", slug),
                           datasets=PD.picker() if console else [],
                           examples=py_examples.all_examples() if console else [],
                           vault_ok=SV.available(),
                           cred_status=SV.status(slug, script.get("credentials") or []),
                           runs=SL.recent_runs(slug, limit=20),
                           limits={"files": SL.MAX_FILES, "file_kib": SL.MAX_FILE_BYTES // 1024,
                                   "fields": SL.MAX_FIELDS, "timeout_min": SL.TIMEOUT_MIN,
                                   "timeout_max": SL.TIMEOUT_MAX,
                                   "suffixes": list(SL.TEXT_SUFFIXES)},
                           field_types=SL.FIELD_TYPES, sandbox_ok=sandbox.available(),
                           studio_connections=_studio_connections())


def _studio_connections() -> list[dict]:
    """The Studio connections a script may declare (Connections card), with
    the API Catalog version a connection is pinned to and its endpoints (the
    reference the editor shows for ``connection("x").op(...)``)."""
    try:
        from ..services import studio_apis as SAPI
        from ..services import studio_connections as SC
        out = []
        for c in SC.list_connections():
            cat = SAPI.catalog_of(c)
            out.append({"slug": c.slug, "name": c.name, "kind": c.kind,
                        "secret": SC.needs_secret(c),
                        "api": ({"api": cat["api"], "version": cat["version"],
                                 "status": cat["status"], "ops": cat["operations"]}
                                if cat else None)})
        return out
    except Exception:  # noqa: BLE001 -- the editor opens without them
        return []


@bp.route("/<slug>/save", methods=["POST"])
@login_required
@require_permission(PERM)
def save(slug):
    body = request.get_json(silent=True) or {}
    # The editor saves as "save" (button, Ctrl+S, autosave) or "upload" (a
    # file it just merged in); "restore" belongs to the restore routes.
    kind = body.get("kind") if body.get("kind") in ("save", "upload") else "save"
    note = str(body.get("note") or "")[:200] if kind == "upload" else ""
    try:
        script = SL.save_draft(slug, body.get("files"), body.get("settings") or {}, _who(),
                               kind=kind, note=note)
    except SL.ScriptError as exc:
        return _err(exc)
    revs = script.get("revisions") or []
    log_action("script_library.save", target=slug,
               extra={"files": sorted(script["files"]), "fields": len(script["fields"]),
                      "network": script["network"], "problems": len(script["problems"]),
                      "kind": kind, "revision": revs[-1]["n"] if revs else None})
    return jsonify({"ok": True, "problems": script["problems"],
                    "updated_at": script["updated_at"], "revisions": revs,
                    "cred_status": SV.status(slug, script.get("credentials") or [])})


@bp.route("/<slug>/check", methods=["POST"])
@login_required
@require_permission(PERM)
def check(slug):
    """Syntax check of the editor's files without saving."""
    body = request.get_json(silent=True) or {}
    try:
        files = SL.validate_files(body.get("files"))
    except SL.ScriptError as exc:
        return _err(exc)
    return jsonify({"problems": SL.syntax_problems(files)})


@bp.route("/<slug>/upload", methods=["POST"])
@login_required
@require_permission(PERM)
def upload(slug):
    if not SL.exists(slug):
        abort(404)
    f = request.files.get("file")
    if f is None or not f.filename:
        return _err(SL.ScriptError("choose a .py or .zip file"))
    data = f.read(SL.MAX_UPLOAD_BYTES + 1)
    try:
        files = SL.files_from_upload(f.filename, data)
    except SL.ScriptError as exc:
        return _err(exc)
    log_action("script_library.upload", target=slug,
               extra={"filename": f.filename[:200], "files": sorted(files)})
    # Returned to the editor, which merges or replaces and then saves: the
    # upload itself does not touch the draft on disk.
    return jsonify({"files": files, "problems": SL.syntax_problems(files)})


@bp.route("/<slug>/download")
@login_required
@require_permission(PERM)
def download(slug):
    if request.args.get("revision"):
        ref = "r%s" % request.args["revision"]
    elif request.args.get("version"):
        ref = "v%s" % request.args["version"]
    else:
        ref = "draft"
    try:
        snap = SL.snapshot(slug, ref)
    except SL.ScriptError:
        abort(404)
    if snap is None:
        abort(404)
    files = snap["files"]
    name = "%s-%s.zip" % (slug, ref)
    return Response(SL.zip_bytes(files), mimetype="application/zip",
                    headers={"Content-Disposition": "attachment; filename=%s" % name})


@bp.route("/<slug>/test", methods=["POST"])
@login_required
@require_permission(PERM)
def test_run(slug):
    """Queue a run of the SAVED draft with the inputs typed in the Test tab."""
    body = request.get_json(silent=True) or {}
    try:
        st = SL.enqueue_run(slug, version_ref="draft", raw_inputs=body.get("inputs"),
                            by=_who(), trigger="test", node=_node(),
                            wrap=SV.wrap_for_run, user=current_user)
    except SL.ScriptError as exc:
        return _err(exc)
    log_action("script_library.test", target=slug,
               extra={"request_id": st["request_id"], "inputs": st["inputs"]})
    return jsonify(st)


@bp.route("/<slug>/publish", methods=["POST"])
@login_required
@require_permission(PERM)
def publish(slug):
    body = request.get_json(silent=True) or {}
    try:
        script = SL.publish(slug, body.get("note") or "", _who())
    except SL.ScriptError as exc:
        return _err(exc)
    log_action("script_library.publish", target=slug,
               extra={"version": script["published"], "note": (body.get("note") or "")[:200]})
    return jsonify({"ok": True, "published": script["published"],
                    "versions": script["versions"]})


@bp.route("/<slug>/version/<int:n>")
@login_required
@require_permission(PERM)
def version(slug, n):
    try:
        v = SL.version(slug, n)
    except SL.ScriptError:
        abort(404)
    if v is None:
        abort(404)
    return jsonify(v)


@bp.route("/<slug>/restore/<int:n>", methods=["POST"])
@login_required
@require_permission(PERM)
def restore(slug, n):
    try:
        SL.restore(slug, n, _who())
    except SL.ScriptError as exc:
        return _err(exc)
    log_action("script_library.restore", target=slug, extra={"version": n})
    return jsonify({"ok": True})


@bp.route("/<slug>/revision/<int:n>")
@login_required
@require_permission(PERM)
def revision(slug, n):
    try:
        r = SL.revision(slug, n)
    except SL.ScriptError:
        abort(404)
    if r is None:
        abort(404)
    return jsonify(r)


@bp.route("/<slug>/revision/<int:n>/restore", methods=["POST"])
@login_required
@require_permission(PERM)
def restore_revision(slug, n):
    try:
        SL.restore_revision(slug, n, _who())
    except SL.ScriptError as exc:
        return _err(exc)
    log_action("script_library.restore", target=slug, extra={"revision": n})
    return jsonify({"ok": True})


@bp.route("/<slug>/diff")
@login_required
@require_permission(PERM)
def diff(slug):
    """What changed from ``a`` to ``b`` (``draft``, ``v<n>`` or ``r<n>``)."""
    if not SL.exists(slug):
        abort(404)
    try:
        return jsonify(SL.diff(slug, request.args.get("a") or "", request.args.get("b") or "draft"))
    except SL.ScriptError as exc:
        return _err(exc, 404)


@bp.route("/<slug>/credential/<name>", methods=["POST"])
@login_required
@require_permission(PERM)
def credential(slug, name):
    """Replace the value of one DECLARED credential, in the vault. Write-only:
    nothing here ever returns a stored value."""
    script = SL.get(slug) if SL.exists(slug) else None
    if script is None:
        abort(404)
    cred = next((c for c in script.get("credentials") or [] if c["name"] == name), None)
    if cred is None:
        return _err(SL.ScriptError("declare %s under Settings and save first" % name))
    body = request.get_json(silent=True) or {}
    try:
        SV.store(slug, cred, body)
    except SL.ScriptError as exc:
        return _err(exc)
    except Exception as exc:  # noqa: BLE001 -- vault transport
        return _err(SL.ScriptError("vault error: %s" % exc), 502)
    log_action("script_library.credential", target=slug, extra={"credential": name})
    return jsonify({"ok": True, "status": SV.status(slug, [cred]).get(name)})


@bp.route("/<slug>/delete", methods=["POST"])
@login_required
@require_permission(PERM)
def delete(slug):
    """A script is deleted WITH its app (studio_apps.remove): templates and
    scripts another app runs in a step are refused."""
    from ..extensions import db
    from ..services import studio_apps as SA
    try:
        SL.validate_slug(slug)
        if not SL.exists(slug):
            raise SL.ScriptError("no script %r" % slug)
    except SL.ScriptError as exc:
        return _err(exc, 404)
    try:
        res = SA.remove(SA.ensure_script_app(slug, _who()))
    except SA.AppError as exc:
        db.session.rollback()
        return _err(exc, 409)
    log_action("script_library.delete", target=slug,
               extra={"credentials_forgotten": res.get("credentials") or []})
    if request.is_json:
        return jsonify({"ok": True})
    return redirect(url_for("studio.index", pane="apps"))


@bp.route("/runs/<rid>")
@login_required
@require_permission(PERM)
def run_status(rid):
    st = SL.run_status(rid)
    if st is None:
        return jsonify({"status": "unknown"}), 404
    return jsonify(st)
