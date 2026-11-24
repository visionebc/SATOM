"""Diagram Studio (``/diagram-studio``): the diagram library, the import wizard,
the editor and the symbol libraries, plus their JSON API.

Every route is stamped with ``require_permission`` (area ``diagrams`` in
app/permissions.py). Rows are ADOM-scoped in ``services/diagram_studio.py``.
Uploaded files are NEVER parsed in this process: an import is queued for
``satom-diagrams.service`` (``services/diagram_runner.py``), and the two quick
questions answered while the operator waits (page list, PDF thumbnail) and the
check of an uploaded symbol library run in the same bubblewrap jail through
``diagram_runner.run_sync``. Only exporters run here, and their input is a
normalised ``satom.diagram/1`` model, never a file.
"""
from __future__ import annotations

import json
import os
import re
import unicodedata
from urllib.parse import quote

from flask import Blueprint, Response, abort, jsonify, render_template, request, url_for
from flask_login import current_user

from ..auth.decorators import require_permission
from ..services import diagram_runner as R
from ..services import diagram_studio as S
from ..services.audit import log_action

bp = Blueprint("diagram_studio", __name__, url_prefix="/diagram-studio")

JSON_BODY_MAX = 1024 * 1024
DOC_BODY_MAX = S.MAX_DOC_BYTES + 256 * 1024
UPLOAD_BODY_MAX = R.MAX_FILES * R.MAX_FILE + 1024 * 1024
LIBRARY_FILE_MAX = 20 * 1024 * 1024
OPTIONS_MAX = 64 * 1024
EXPORT_FORMATS = ("drawio", "svg", "pdf")
SVG_CSP = "default-src 'none'; style-src 'unsafe-inline'"
_LEGACY_VISIO = (".vsd",)


# ------------------------------------------------------------------ helpers

@bp.errorhandler(S.StudioError)
def _studio_error(exc: S.StudioError):
    body = {"error": str(exc)}
    body.update(exc.data or {})
    return jsonify(body), exc.status


def _err(message: str, status: int = 400, **extra):
    body = {"error": message}
    body.update(extra)
    return jsonify(body), status


def _too_large(cap: int) -> bool:
    n = request.content_length
    return n is not None and n > cap


def _body(cap: int = JSON_BODY_MAX) -> dict:
    if _too_large(cap):
        raise S.StudioError("The request is larger than %d MiB." % (cap // (1024 * 1024)) if cap >= 1024 * 1024
                            else "The request is too large.", status=413)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise S.StudioError("Expected a JSON object.")
    return data


def flags() -> dict:
    u = current_user
    return {"mayView": u.can("diagrams.view"), "mayEdit": u.can("diagrams.edit"),
            "mayImport": u.can("diagrams.import"), "mayPublish": u.can("diagrams.publish"),
            "mayLibraries": u.can("diagrams.libraries")}


def page_limits() -> dict:
    mib = 1024 * 1024
    lim = S.limits()
    return {"files": R.MAX_FILES, "file_mb": R.MAX_FILE // mib, "pdf_pages": R.MAX_PAGES,
            "doc_mb": S.MAX_DOC_BYTES // mib, "elements": lim["elementsPerPage"],
            "connectors": lim["connectorsPerPage"], "versions": S.MAX_VERSIONS,
            "folder_depth": S.MAX_DEPTH, "folder_name": S.FOLDER_NAME_MAX}


def base_config(page: str, **extra) -> dict:
    cfg = {"page": page, "base": url_for("diagram_studio.index"),
           "user": {"id": current_user.id, "name": current_user.username},
           "limits": page_limits(),
           "symbolsUrl": url_for("diagram_studio.index") + "api/libraries/"}
    cfg.update(flags())
    cfg.update(extra)
    return cfg


def render_page(template: str, cfg: dict):
    # ``cfg`` per the backend brief, ``ds_config`` per the templates' own note
    # (_contract/UI-template-vars.md): the same dict under both names.
    return render_template(template, cfg=cfg, ds_config=cfg)


def _display_name(name: str) -> str:
    base = os.path.basename(str(name or "").replace("\\", "/"))
    return re.sub(r"[\x00-\x1f\x7f]", "", base).strip()[:255]


def _ext(name: str) -> str:
    return os.path.splitext(name.lower())[1]


def _supported_extensions() -> tuple:
    from ..services.diagram_engine.detect import SUPPORTED_EXTENSIONS
    return tuple(SUPPORTED_EXTENSIONS) + (".vsdm",)


def _refusal(name: str) -> str | None:
    ext = _ext(name)
    if ext in _LEGACY_VISIO:
        from ..services.diagram_engine.detect import VSD_MESSAGE
        return VSD_MESSAGE
    if ext not in _supported_extensions():
        return ("Unsupported file type%s. Supported: draw.io (.drawio, .xml), SVG, Visio "
                "(.vsdx, .vdx), PDF, images (PNG, JPEG, GIF, WEBP, BMP, TIFF), Mermaid (.mmd) "
                "and Graphviz DOT (.dot, .gv)." % (" " + repr(ext) if ext else ""))
    return None


def _new_import_row(name, status, *, sha="", fmt="", error="", options=None):
    from ..extensions import db
    from ..models_diagrams import DiagramImport
    row = DiagramImport(id=R.new_job_id(), status=status, filename=name, format=fmt,
                        source_sha256=sha, options_json=json.dumps(options or {}, sort_keys=True),
                        error=error[:1000], adom=S._stamp(), created_by=S._by(current_user))
    db.session.add(row)
    db.session.commit()
    return row


def _store_upload(fs):
    """``(sha, size)`` of a stored upload, or a refusal sentence."""
    try:
        sha, size = R.store_source(fs.stream, R.MAX_FILE)
    except R.TooLarge:
        return None, "The file is larger than %d MiB." % (R.MAX_FILE // (1024 * 1024))
    if size == 0:
        return None, "The file is empty."
    return (sha, size), None


# --------------------------------------------------------------------- pages

@bp.route("/")
@require_permission("diagrams.view")
def index():
    return render_page("diagram_studio/index.html", base_config("index"))


@bp.route("/import")
@require_permission("diagrams.import")
def import_page():
    return render_page("diagram_studio/import.html", base_config(
        "import", visionAvailable=S.vision_config() is not None,
        extensions=list(_supported_extensions())))


@bp.route("/import/<job_id>/review")
@require_permission("diagrams.import")
def review(job_id):
    try:
        row = S.get_import(current_user, job_id)
    except S.NotFound:
        abort(404)
    st = S.refresh_import(row)
    return render_page("diagram_studio/review.html", base_config(
        "review", jobId=row.id, job=S.import_json(row, st)))


def _themes() -> list:
    """The shipped colour themes (diagram_engine/themes.json) for the editor."""
    from ..services.diagram_engine import themes
    return themes.load()["themes"]


@bp.route("/<int:diagram_id>/edit")
@require_permission("diagrams.view")
def editor(diagram_id):
    try:
        d = S.get_diagram(diagram_id)
    except S.NotFound:
        abort(404)
    doc = S.current_doc(d)
    return render_page("diagram_studio/editor.html", base_config(
        "editor",
        diagram={"id": d.id, "name": d.name, "description": d.description,
                 "folder_id": d.folder_id, "published": bool(d.published),
                 "version": d.current_version},
        doc=doc, libraries=S.library_list(), autosave=True, themes=_themes(),
        viewUrl=url_for("diagrams.view", diagram_id=d.id) if d.published else None,
        copyOf=satom_copy_note(doc)))


@bp.route("/libraries")
@require_permission("diagrams.view")
def libraries():
    return render_page("diagram_studio/libraries.html", base_config("libraries"))


# ------------------------------------------------------------------ diagrams

@bp.route("/api/diagrams", methods=["GET"])
@require_permission("diagrams.view")
def api_diagrams():
    return jsonify(S.diagram_list())


@bp.route("/api/diagrams", methods=["POST"])
@require_permission("diagrams.edit")
def api_diagram_create():
    data = _body(DOC_BODY_MAX)
    d, warnings = S.create_diagram(current_user, data.get("name"), folder_id=data.get("folder_id"),
                                   doc=data.get("doc"), description=data.get("description") or "")
    log_action("diagram.create", target="diagram:%d" % d.id, extra={"name": d.name})
    return jsonify({"id": d.id, "version": d.current_version, "warnings": warnings,
                    "url": url_for("diagram_studio.editor", diagram_id=d.id)}), 201


@bp.route("/api/diagrams/<int:diagram_id>", methods=["GET"])
@require_permission("diagrams.view")
def api_diagram_get(diagram_id):
    d = S.get_diagram(diagram_id)
    return jsonify({"diagram": S.diagram_json(d), "doc": S.current_doc(d), "version": d.current_version})


@bp.route("/api/diagrams/<int:diagram_id>", methods=["PUT"])
@require_permission("diagrams.edit")
def api_diagram_save(diagram_id):
    d = S.get_diagram(diagram_id)
    data = _body(DOC_BODY_MAX)
    if "doc" not in data:
        raise S.StudioError("doc is required.")
    version, warnings, created = S.save_diagram(current_user, d, data.get("doc"),
                                                data.get("version"), data.get("note") or "")
    if created:
        log_action("diagram.save", target="diagram:%d" % d.id,
                   extra={"version": version, "name": d.name})
    return jsonify({"version": version, "warnings": warnings, "created": created})


@bp.route("/api/diagrams/<int:diagram_id>", methods=["PATCH"])
@require_permission("diagrams.edit")
def api_diagram_patch(diagram_id):
    d = S.get_diagram(diagram_id)
    data = _body()
    S.patch_diagram(current_user, d, data)
    log_action("diagram.update", target="diagram:%d" % d.id,
               extra={k: data.get(k) for k in ("name", "folder_id") if k in data})
    return jsonify({"diagram": S.diagram_json(d)})


@bp.route("/api/diagrams/<int:diagram_id>", methods=["DELETE"])
@require_permission("diagrams.edit")
def api_diagram_delete(diagram_id):
    d = S.get_diagram(diagram_id)
    did, name = d.id, d.name
    S.delete_diagram(current_user, d)
    log_action("diagram.delete", target="diagram:%d" % did, extra={"name": name})
    return jsonify({"ok": True})


@bp.route("/api/diagrams/<int:diagram_id>/duplicate", methods=["POST"])
@require_permission("diagrams.edit")
def api_diagram_duplicate(diagram_id):
    d = S.get_diagram(diagram_id)
    new = S.duplicate_diagram(current_user, d)
    log_action("diagram.duplicate", target="diagram:%d" % new.id, extra={"from": d.id})
    return jsonify({"id": new.id, "url": url_for("diagram_studio.editor", diagram_id=new.id)}), 201


#: The largest "Open in Diagram Studio" body: the draw.io export's own cap
#: (views/diagram_export.py), since both carry the same page description.
FROM_SATOM_BODY_MAX = 8 * 1024 * 1024

#: The live page each copy links back to ("open the live diagram").
_SATOM_PAGES = {"architecture": "netarch.index", "service-diagram": "architecture.index"}


@bp.route("/api/from-satom", methods=["POST"])
@require_permission("diagrams.edit")
def api_from_satom():
    """Copy what Architecture or the Service Diagram shows into a new diagram.

    Body ``{name, source: "architecture"|"service-diagram", payload, source_id?}``
    where ``payload`` is the page's draw.io description (static/js/netarch.js,
    fleet_map.js). The draw.io export's validation runs first, so a payload it
    refuses is refused here too; ``importers/satom_payload.py`` maps it onto the
    model. Live state is not structure: it travels as metadata
    ``snapshot_state`` of the moment of the copy."""
    from datetime import datetime, timezone

    from ..services import drawio_export as dx
    from ..services.diagram_engine.importers import ImportFailed
    from ..services.diagram_engine.importers import satom_payload as SP
    data = _body(FROM_SATOM_BODY_MAX)
    source = data.get("source")
    if source not in SP.SOURCES:
        raise S.StudioError("source must be one of: %s." % ", ".join(sorted(SP.SOURCES)))
    payload = data.get("payload")
    sid = data.get("source_id")
    sid = sid if isinstance(sid, int) and not isinstance(sid, bool) else None
    try:
        dx.normalise(payload)
        doc = SP.convert(payload, source=source, name=data.get("name") or "",
                         taken_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         source_id=sid)
    except (dx.ExportError, ImportFailed) as exc:
        raise S.StudioError(str(exc)) from None
    label = SP.SOURCES[source]
    d, warnings = S.create_diagram(current_user, doc["name"], doc=doc,
                                   note="Copied from %s" % label,
                                   source={"format": doc["source"]["format"],
                                           "sha256": doc["source"]["sha256"]})
    page = doc["pages"][0]
    log_action("diagram.copy_from_satom", target="diagram:%d" % d.id,
               extra={"source": source, "name": d.name, "elements": len(page["elements"]),
                      "connectors": len(page["connectors"])})
    return jsonify({"id": d.id, "url": url_for("diagram_studio.editor", diagram_id=d.id),
                    "warnings": (doc["recognition"]["warnings"] + warnings)[:50]}), 201


def satom_copy_note(doc) -> dict | None:
    """"Copy of Architecture taken <date> — open the live diagram" for a
    diagram copied from a live page, else ``None``. The link is built here,
    from the source NAME, never from a URL stored in the document, and only
    for a user who may open the live page."""
    from ..services.concept_map import may_open
    from ..services.diagram_engine.importers.satom_payload import SOURCES
    meta = (doc or {}).get("metadata") if isinstance(doc, dict) else None
    source = (meta or {}).get("satom_source")
    if source not in SOURCES:
        return None
    taken = str(meta.get("satom_copied_at") or "")
    when = "%s %s UTC" % (taken[:10], taken[11:16]) if len(taken) >= 16 else ""
    ep, url = _SATOM_PAGES[source], None
    try:
        if may_open(current_user, ep):
            sid = meta.get("satom_source_id")
            url = (url_for(ep, id=sid) if source == "architecture" and isinstance(sid, int)
                   and not isinstance(sid, bool) else url_for(ep))
    except Exception:  # noqa: BLE001 -- a note must never 500 the page
        url = None
    return {"source": source, "label": SOURCES[source], "taken": when, "url": url}


@bp.route("/api/diagrams/<int:diagram_id>/versions", methods=["GET"])
@require_permission("diagrams.view")
def api_versions(diagram_id):
    return jsonify(S.versions(S.get_diagram(diagram_id)))


@bp.route("/api/diagrams/<int:diagram_id>/versions/<int:number>", methods=["GET"])
@require_permission("diagrams.view")
def api_version(diagram_id, number):
    return jsonify({"doc": S.version_doc(S.get_diagram(diagram_id), number)})


@bp.route("/api/diagrams/<int:diagram_id>/versions/<int:number>/restore", methods=["POST"])
@require_permission("diagrams.edit")
def api_version_restore(diagram_id, number):
    d = S.get_diagram(diagram_id)
    version, created = S.restore_version(current_user, d, number)
    log_action("diagram.restore", target="diagram:%d" % d.id,
               extra={"restored": number, "version": version})
    return jsonify({"version": version, "created": created})


@bp.route("/api/diagrams/<int:diagram_id>/diff", methods=["GET"])
@require_permission("diagrams.view")
def api_diff(diagram_id):
    d = S.get_diagram(diagram_id)
    return jsonify(S.diff(d, request.args.get("a"), request.args.get("b")))


@bp.route("/api/diagrams/<int:diagram_id>/publish", methods=["POST"])
@require_permission("diagrams.publish")
def api_publish(diagram_id):
    d = S.get_diagram(diagram_id)
    data = _body()
    published = data.get("published")
    if not isinstance(published, bool):
        raise S.StudioError("published is true or false.")
    S.publish(current_user, d, published, data)
    log_action("diagram.publish" if published else "diagram.unpublish",
               target="diagram:%d" % d.id,
               extra={"version": d.published_version, "folder_id": d.folder_id})
    return jsonify({"diagram": S.diagram_json(d),
                    "url": url_for("diagrams.view", diagram_id=d.id) if published else None})


# ------------------------------------------------------------------- folders

@bp.route("/api/folders", methods=["GET"])
@require_permission("diagrams.view")
def api_folders():
    return jsonify(S.folder_list())


@bp.route("/api/folders", methods=["POST"])
@require_permission("diagrams.edit")
def api_folder_create():
    data = _body()
    f = S.create_folder(current_user, data.get("name"), data.get("parent_id"))
    log_action("diagram.folder_create", target="diagram_folder:%d" % f.id,
               extra={"name": f.name, "parent_id": f.parent_id})
    return jsonify({"id": f.id, "name": f.name, "parent_id": f.parent_id,
                    "position": f.position, "count": 0}), 201


@bp.route("/api/folders/<int:folder_id>", methods=["PATCH"])
@require_permission("diagrams.edit")
def api_folder_patch(folder_id):
    f = S.get_folder(folder_id)
    data = _body()
    S.update_folder(current_user, f, data)
    log_action("diagram.folder_update", target="diagram_folder:%d" % f.id,
               extra={k: data.get(k) for k in ("name", "parent_id", "position") if k in data})
    return jsonify({"id": f.id, "name": f.name, "parent_id": f.parent_id, "position": f.position})


@bp.route("/api/folders/<int:folder_id>", methods=["DELETE"])
@require_permission("diagrams.edit")
def api_folder_delete(folder_id):
    f = S.get_folder(folder_id)
    fid, name = f.id, f.name
    S.delete_folder(current_user, f)
    log_action("diagram.folder_delete", target="diagram_folder:%d" % fid, extra={"name": name})
    return jsonify({"ok": True})


# ------------------------------------------------------------------- imports

def _parse_options() -> dict:
    raw = request.form.get("options") or "{}"
    if len(raw) > OPTIONS_MAX:
        raise S.StudioError("options is too large.")
    try:
        opts = json.loads(raw)
    except ValueError:
        raise S.StudioError("options is not valid JSON.") from None
    if not isinstance(opts, dict):
        raise S.StudioError("options is a JSON object.")
    pages = opts.get("pages") if isinstance(opts.get("pages"), dict) else {}
    return {"pages": {str(k)[:255]: str(v)[:200] for k, v in list(pages.items())[:R.MAX_FILES * 2]},
            "ocr": opts.get("ocr", True) is not False,
            "classify": opts.get("classify", True) is not False,
            "vision": opts.get("vision") is True,
            "name": S._clean_text(opts.get("name") or "", S.DIAGRAM_NAME_MAX, "The name")}


@bp.route("/api/imports", methods=["POST"])
@require_permission("diagrams.import")
def api_import():
    S.purge_imports()
    if request.content_length is None:
        return _err("The upload has no Content-Length.", 411)
    if _too_large(UPLOAD_BODY_MAX):
        return _err("The upload is larger than %d MiB in total." % (UPLOAD_BODY_MAX // (1024 * 1024)), 413)
    files = [f for f in request.files.getlist("files[]") + request.files.getlist("files") if f]
    if not files:
        raise S.StudioError("No file was uploaded.")
    if len(files) > R.MAX_FILES:
        raise S.StudioError("At most %d files per import." % R.MAX_FILES)
    opts = _parse_options()
    vision = S.vision_config() if opts["vision"] else None
    libs = list(S.operator_libraries().values()) if opts["classify"] else []
    jobs = []
    for fs in files:
        name = _display_name(fs.filename) or "unnamed"
        spec = (opts["pages"].get(fs.filename) or opts["pages"].get(name) or "all").replace(" ", "")
        refusal = _refusal(name)
        stored = None
        if refusal is None and not R.PAGES_RE.match(spec):
            refusal = "Bad page selection %r: use all, or pages like 1,3-4." % spec[:40]
        if refusal is None:
            stored, refusal = _store_upload(fs)
        if refusal is not None:
            row = _new_import_row(name, "refused", error=refusal)
            log_action("diagram.import_refused", target="diagram_import:%s" % row.id,
                       extra={"filename": name, "reason": refusal[:200]})
            jobs.append({"id": row.id, "filename": name, "status": "refused", "error": refusal})
            continue
        sha, size = stored
        job_opts = {"pages": spec, "ocr": opts["ocr"], "classify": opts["classify"],
                    "vision": opts["vision"], "name": opts["name"]}
        row = _new_import_row(name, "queued", sha=sha, options=job_opts)
        try:
            R.enqueue(row.id, sha=sha, filename=name, pages=spec, ocr=opts["ocr"],
                      classify=opts["classify"], libraries=libs, vision=vision,
                      vision_requested=opts["vision"])
        except (R.RunnerError, OSError) as exc:
            from ..extensions import db
            row.status, row.error = "failed", "The import could not be queued: %s" % exc
            db.session.commit()
            jobs.append({"id": row.id, "filename": name, "status": "failed", "error": row.error})
            continue
        log_action("diagram.import", target="diagram_import:%s" % row.id,
                   extra={"filename": name, "sha256": sha, "size": size, "pages": spec,
                          "ocr": opts["ocr"], "vision": bool(vision)})
        jobs.append({"id": row.id, "filename": name, "status": "queued"})
    return jsonify({"jobs": jobs})


@bp.route("/api/imports/pages", methods=["POST"])
@require_permission("diagrams.import")
def api_import_pages():
    S.purge_imports()
    if _too_large(R.MAX_FILE + 1024 * 1024):
        return _err("The file is larger than %d MiB." % (R.MAX_FILE // (1024 * 1024)), 413)
    fs = request.files.get("file")
    if not fs:
        raise S.StudioError("No file was uploaded.")
    name = _display_name(fs.filename) or "unnamed"
    refusal = _refusal(name)
    if refusal:
        return _err(refusal, 415)
    stored, refusal = _store_upload(fs)
    if refusal:
        return _err(refusal, 413 if "larger" in refusal else 400)
    sha, _size = stored
    res = R.run_sync("pages", R.source_path(sha), {"filename": name})
    if not res["ok"]:
        return _err(res["error"], 503 if res.get("busy") else 422)
    out = res["result"]
    pages = [{"id": str(p.get("id"))[:64], "name": str(p.get("name"))[:200]}
             for p in (out.get("pages") if isinstance(out.get("pages"), list) else [])
             if isinstance(p, dict)][:500]
    fmt = str(out.get("format") or "")[:32]
    row = _new_import_row(name, "staged", sha=sha, fmt=fmt)
    return jsonify({"id": row.id, "format": fmt, "pages": pages, "thumbnails": fmt == "pdf"})


@bp.route("/api/imports/<job_id>/thumbnail/<int:page>", methods=["GET"])
@require_permission("diagrams.import")
def api_import_thumbnail(job_id, page):
    row = S.get_import(current_user, job_id)
    if row.format and row.format != "pdf":
        raise S.NotFound("Thumbnails are made for PDF files only.")
    if not 1 <= page <= R.MAX_PAGES:
        raise S.NotFound("Page not found.")
    src = R.source_path(row.source_sha256)
    if src is None:
        raise S.NotFound("The uploaded file is no longer stored.")
    cache = R.root() / "thumbs" / ("%s-%d.png" % (row.source_sha256, page))
    png = R._read_capped(cache, R.MAX_THUMB)
    if png is None:
        res = R.run_sync("thumbnail", src, {"filename": row.filename, "page_index": page - 1,
                                            "max_px": 480})
        if not res["ok"]:
            return _err(res["error"], 503 if res.get("busy") else 422)
        png = res["result"]
        try:
            R._atomic_write(cache, png, 0o600)
        except OSError:
            pass
    resp = Response(png, mimetype="image/png")
    resp.headers["Cache-Control"] = "private, max-age=3600"
    resp.headers["Content-Security-Policy"] = "default-src 'none'"
    return resp


@bp.route("/api/imports/<job_id>", methods=["GET"])
@require_permission("diagrams.import")
def api_import_status(job_id):
    row = S.get_import(current_user, job_id)
    st = S.refresh_import(row)
    return jsonify(S.import_json(row, st))


@bp.route("/api/imports/<job_id>", methods=["DELETE"])
@require_permission("diagrams.import")
def api_import_delete(job_id):
    row = S.get_import(current_user, job_id)       # the owner's, or user_manage
    info = S.delete_import(current_user, row)
    log_action("diagram.import_delete", target="diagram_import:%s" % info["id"],
               extra={"filename": info["filename"], "status": info["status"],
                      "sha256": info["sha256"], "source_removed": info["source_removed"]})
    return jsonify({"ok": True, "id": info["id"]})


@bp.route("/api/imports/<job_id>/result", methods=["GET"])
@require_permission("diagrams.import")
def api_import_result(job_id):
    row = S.get_import(current_user, job_id)
    S.refresh_import(row)
    if row.status != "ok":
        return _err("The recognition has not finished successfully (status %s)." % row.status, 409,
                    status=row.status)
    doc = R.read_result(row.id)
    if doc is None:
        return _err("The recognised diagram is no longer stored; import the file again.", 410)
    return jsonify({"doc": doc})


@bp.route("/api/imports/<job_id>/accept", methods=["POST"])
@require_permission("diagrams.import")
def api_import_accept(job_id):
    if not current_user.can("diagrams.edit"):
        abort(403)
    row = S.get_import(current_user, job_id)
    S.refresh_import(row)
    if row.status != "ok":
        return _err("The recognition has not finished successfully (status %s)." % row.status, 409,
                    status=row.status)
    if row.diagram_id:
        return _err("A diagram was already created from this import.", 409, id=row.diagram_id,
                    url=url_for("diagram_studio.editor", diagram_id=row.diagram_id))
    data = _body(DOC_BODY_MAX)
    doc = data.get("doc")
    if doc is None:
        doc = R.read_result(row.id)
        if doc is None:
            return _err("The recognised diagram is no longer stored; import the file again.", 410)
    name = data.get("name") or (doc.get("name") if isinstance(doc, dict) else "") or row.filename
    d, warnings = S.create_diagram(
        current_user, str(name)[:S.DIAGRAM_NAME_MAX], folder_id=data.get("folder_id"), doc=doc,
        note=("Imported from %s" % row.filename)[:S.NOTE_MAX],
        source={"format": row.format, "filename": row.filename, "sha256": row.source_sha256})
    from ..extensions import db
    row.diagram_id = d.id
    db.session.commit()
    log_action("diagram.import_accept", target="diagram:%d" % d.id,
               extra={"import": row.id, "filename": row.filename, "sha256": row.source_sha256})
    return jsonify({"id": d.id, "version": d.current_version, "warnings": warnings,
                    "url": url_for("diagram_studio.editor", diagram_id=d.id)}), 201


# -------------------------------------------------------------------- export

def transliterate(text: str) -> str:
    """ASCII letters for a download name: ß -> ss, NFKD, combining marks dropped
    ("Prüfung" -> "Prufung"). What has no ASCII form stays and is replaced by
    the slug rule below."""
    t = str(text or "").replace("\u00df", "ss").replace("\u1e9e", "SS")
    t = unicodedata.normalize("NFKD", t)
    return "".join(c for c in t if not unicodedata.combining(c))


def _slug(text: str, limit: int) -> str:
    # the engine's rule (exporters._common.slug_filename), on transliterated text
    return re.sub(r"[^A-Za-z0-9._-]+", "-", transliterate(text)[:limit]).strip("-.")


def download_name(name: str, ext: str, suffix: str = "") -> tuple[str, str]:
    """``(ascii fallback, original)`` file names of an export: the document
    name, plus the page name when one page of a multi-page diagram is exported."""
    clean = lambda v: re.sub(r"[\x00-\x1f\x7f]", "", str(v or "")).strip()
    ascii_name = (_slug(name, 120) or "diagram")
    if suffix:
        ascii_name += "-" + _slug(suffix, 60)
    ascii_name = ascii_name[:100] + "." + ext
    original = (clean(name)[:150] or "diagram") + ("-" + clean(suffix)[:60] if suffix else "")
    return ascii_name, original + "." + ext


def content_disposition(ascii_name: str, original: str) -> str:
    """``attachment`` with the ASCII fallback and, per RFC 6266 / 5987, the
    original name percent-encoded in ``filename*``."""
    return "attachment; filename=\"%s\"; filename*=UTF-8''%s" % (
        ascii_name.replace('"', "_"), quote(original, safe=""))


def export_response(doc: dict, fmt: str, page, options, *, audit_target: str):
    """Run an exporter over a NORMALISED model and answer the file."""
    from ..services.diagram_engine import exporters
    if fmt not in EXPORT_FORMATS:
        raise S.NotFound("Unknown export format.")
    if page not in (None, "", "all") and not (isinstance(page, (str, int)) and len(str(page)) <= 64):
        raise S.StudioError("Bad page.")
    opts = {}
    if isinstance(options, dict):
        for k in ("paper", "orientation"):
            if isinstance(options.get(k), str) and len(options[k]) <= 16:
                opts[k] = options[k]
    try:
        data, mime, filename = exporters.export(fmt, doc, page=page if page != "" else None, options=opts)
    except exporters.ExportFailed as exc:
        raise S.StudioError(str(exc)) from None
    # The engine names the file with an ASCII slug that drops accented
    # letters; the download name is rebuilt from the document's own names.
    from ..services.diagram_engine.exporters._common import slug_filename
    ext = str(filename or "").rsplit(".", 1)[-1] if "." in str(filename or "") else fmt
    name = str(doc.get("name") or "diagram")
    suffix = ""
    if len(doc.get("pages") or []) > 1:
        for pg in doc["pages"]:
            if slug_filename(name, ext, pg.get("name") or "") == filename:
                suffix = pg.get("name") or ""
                break
    resp = Response(data, mimetype=mime)
    resp.headers["Content-Disposition"] = content_disposition(*download_name(name, ext, suffix))
    resp.headers["Content-Security-Policy"] = SVG_CSP
    resp.headers["Cache-Control"] = "no-store"
    log_action("diagram.export_%s" % fmt, target=audit_target,
               extra={"page": str(page or "all"), "bytes": len(data)})
    return resp


@bp.route("/api/export/<fmt>", methods=["POST"])
@require_permission("diagrams.view")
def api_export(fmt):
    if fmt not in EXPORT_FORMATS:
        raise S.NotFound("Unknown export format.")
    data = _body(DOC_BODY_MAX)
    doc, _w = S.normalise(data.get("doc"))
    return export_response(doc, fmt, data.get("page"), data.get("options"),
                           audit_target="diagram:%s" % str(data.get("diagram_id") or "unsaved")[:20])


# ----------------------------------------------------------------- libraries

@bp.route("/api/libraries", methods=["GET"])
@require_permission("diagrams.view")
def api_libraries():
    return jsonify(S.library_list())


@bp.route("/api/libraries/<lib_id>/<sym_id>.svg", methods=["GET"])
@require_permission("diagrams.view")
def api_symbol_svg(lib_id, sym_id):
    svg = S.symbol_svg(lib_id, sym_id)
    if svg is None:
        raise S.NotFound("Symbol not found.")
    resp = Response(svg, mimetype="image/svg+xml")
    # private: the route is behind a session (no shared cache may keep an
    # operator library's icons), and Vary: Cookie for any cache in between.
    resp.headers["Cache-Control"] = "private, max-age=86400"
    resp.headers["Vary"] = "Cookie"
    resp.headers["Content-Security-Policy"] = SVG_CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@bp.route("/api/libraries", methods=["POST"])
@require_permission("diagrams.libraries")
def api_library_import():
    from ..services.diagram_engine import symbols
    if _too_large(LIBRARY_FILE_MAX + 1024 * 1024):
        return _err("The library is larger than %d MiB." % (LIBRARY_FILE_MAX // (1024 * 1024)), 413)
    fs = request.files.get("file")
    if not fs:
        raise S.StudioError("No file was uploaded.")
    lib_id = (request.form.get("id") or "").strip()
    label = (request.form.get("label") or "").strip()
    family = (request.form.get("family") or "generic").strip()
    if not symbols.LIB_ID_RE.match(lib_id):
        raise S.StudioError("The library id is 1-48 lowercase letters, digits, - or _.")
    if not 1 <= len(label) <= 80:
        raise S.StudioError("The label is 1 to 80 characters.")
    if not symbols.FAMILY_RE.match(family):
        raise S.StudioError("The family is a lowercase word (network, infra, security ...).")
    S.purge_imports()
    try:
        sha, size = R.store_source(fs.stream, LIBRARY_FILE_MAX)
    except R.TooLarge:
        return _err("The library is larger than %d MiB." % (LIBRARY_FILE_MAX // (1024 * 1024)), 413)
    try:
        res = R.run_sync("library", R.source_path(sha),
                         {"filename": _display_name(fs.filename), "lib_id": lib_id, "label": label,
                          "family": family})
    finally:
        # The ZIP is not kept: the library row holds the sanitised SVGs.
        S.discard_upload(sha)
    if not res["ok"]:
        return _err(res["error"], 503 if res.get("busy") else 422)
    row = S.store_library(current_user, res["result"])
    warnings = [str(w)[:300] for w in (res["result"].get("warnings") or [])][:50]
    log_action("diagram.library_import", target="diagram_library:%s" % row.lib_id,
               extra={"label": row.label, "sha256": sha, "size": size})
    lib = S.all_libraries().get(row.lib_id) or {}
    return jsonify({"id": row.lib_id, "label": row.label, "symbols": len(lib.get("symbols") or []),
                    "warnings": warnings}), 201


@bp.route("/api/libraries/<lib_id>", methods=["DELETE"])
@require_permission("diagrams.libraries")
def api_library_delete(lib_id):
    S.delete_library(current_user, lib_id)
    # Nothing of a library lives on disk any more; this also removes a ZIP an
    # older build kept after parsing (an unreferenced source).
    S.purge_imports(force=True)
    log_action("diagram.library_delete", target="diagram_library:%s" % lib_id[:48])
    return jsonify({"ok": True})


@bp.route("/api/categories", methods=["GET"])
@require_permission("diagrams.view")
def api_categories():
    return jsonify(S.categories())
