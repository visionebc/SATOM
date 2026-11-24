"""Diagram Studio -- the library, versions, publication, menu and symbol
libraries behind ``views/diagram_studio.py`` and ``views/diagrams.py``.

Documents are ``satom.diagram/1`` (``diagram_engine.model``): every document
that reaches the database has been through ``model.normalise`` in THIS
process, whatever produced it (the editor, the jailed recogniser, a restore).

Versions are content-addressed: the sha256 of the canonical JSON (sorted keys,
no whitespace). A save identical to the current version writes nothing and
answers the same version number. The optimistic lock is a conditional UPDATE
on ``diagrams.current_version`` -- two editors saving from the same version
cannot both win. At most :data:`MAX_VERSIONS` versions are kept per diagram,
the oldest pruned first and the published one never.

Scope: every row carries ``adom`` = ``product_scope.stamp()`` at creation and
every read goes through ``product_scope.scope_query`` -- a console sees its own
ADOM's diagrams, Global sees all of them (a confined user: those of their ADOMs).

Uploaded files are never parsed here: imports go through
``services/diagram_runner.py`` (queue + jail), and an operator symbol library
is unpacked and sanitised in the same jail (``run_sync("library")``); the
library this process stores is that jail's output, validated again by
``diagram_engine.symbols.load_library``.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
import threading
from datetime import datetime

from flask import current_app
from sqlalchemy import and_, func, update
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models_diagrams import (Diagram, DiagramFolder, DiagramImport, DiagramLibrary,
                               DiagramVersion)
from . import product_scope

MAX_VERSIONS = 100
MAX_DEPTH = 8
MAX_DOC_BYTES = 32 * 1024 * 1024
FOLDER_NAME_MAX = 64
DIAGRAM_NAME_MAX = 200
DESCRIPTION_MAX = 2000
NOTE_MAX = 500
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class StudioError(ValueError):
    """A refused request; ``status`` is the HTTP code, ``data`` extra JSON."""
    status = 400

    def __init__(self, message: str, status: int | None = None, **data):
        super().__init__(message)
        if status is not None:
            self.status = status
        self.data = data


class NotFound(StudioError):
    status = 404


class Conflict(StudioError):
    status = 409


def _now() -> datetime:
    return datetime.utcnow()


def _iso(dt) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _by(user) -> str:
    return str(getattr(user, "username", "") or "")[:64]


def _model():
    from .diagram_engine import model
    return model


# ------------------------------------------------------------- documents

def canonical(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def doc_sha(doc: dict) -> str:
    return hashlib.sha256(canonical(doc)).hexdigest()


def pack(doc: dict) -> bytes:
    return gzip.compress(canonical(doc), compresslevel=6)


def unpack(blob: bytes) -> dict:
    data = gzip.decompress(blob)
    return json.loads(data.decode("utf-8"))


def normalise(doc) -> tuple[dict, list[str]]:
    """``model.normalise`` with the size limit; StudioError on refusal."""
    model = _model()
    try:
        size = len(canonical(doc)) if isinstance(doc, dict) else 0
    except (TypeError, ValueError):
        raise StudioError("The diagram is not valid JSON.") from None
    if size > MAX_DOC_BYTES:
        raise StudioError("The diagram is larger than %d MiB." % (MAX_DOC_BYTES // (1024 * 1024)),
                          status=413)
    try:
        return model.normalise(doc)
    except model.ModelError as exc:
        raise StudioError("The diagram is not valid: %s" % exc) from None
    except RecursionError:
        raise StudioError("The diagram is nested too deeply.") from None


def _clean_text(v, limit: int, what: str, required: bool = False) -> str:
    s = _CTRL.sub("", str(v if v is not None else "")).strip()
    if required and not s:
        raise StudioError("%s is required." % what)
    if len(s) > limit:
        raise StudioError("%s is longer than %d characters." % (what, limit))
    return s


def limits() -> dict:
    from . import diagram_runner as R
    return {"filesPerImport": R.MAX_FILES, "fileBytes": R.MAX_FILE, "pdfPages": R.MAX_PAGES,
            "docBytes": MAX_DOC_BYTES, "elementsPerPage": _model().MAX_ELEMENTS,
            "connectorsPerPage": _model().MAX_CONNECTORS, "versions": MAX_VERSIONS,
            "folderDepth": MAX_DEPTH, "folderName": FOLDER_NAME_MAX}


# ----------------------------------------------------------------- scope

def _stamp() -> str:
    try:
        return product_scope.stamp()
    except product_scope.ProductScopeUnresolved as exc:
        raise Conflict(str(exc)) from None


def diagrams_query():
    return product_scope.scope_query(Diagram.query, Diagram.adom)


def folders_query():
    return product_scope.scope_query(DiagramFolder.query, DiagramFolder.adom)


def get_diagram(diagram_id) -> Diagram:
    try:
        did = int(diagram_id)
    except (TypeError, ValueError):
        raise NotFound("Diagram not found.") from None
    d = diagrams_query().filter(Diagram.id == did).first()
    if d is None:
        raise NotFound("Diagram not found.")
    return d


def get_folder(folder_id) -> DiagramFolder:
    try:
        fid = int(folder_id)
    except (TypeError, ValueError):
        raise NotFound("Folder not found.") from None
    f = folders_query().filter(DiagramFolder.id == fid).first()
    if f is None:
        raise NotFound("Folder not found.")
    return f


def _folder_or_none(folder_id):
    if folder_id in (None, "", 0, "0"):
        return None
    try:
        return get_folder(folder_id)
    except NotFound:
        raise StudioError("The folder does not exist.") from None


# ---------------------------------------------------------------- folders

def _ancestors(folder: DiagramFolder) -> list[int]:
    """Ids from *folder*'s parent up to the root (bounded: a corrupt chain
    cannot loop forever)."""
    out, seen, cur = [], {folder.id}, folder.parent_id
    while cur is not None and len(out) <= MAX_DEPTH + 2:
        if cur in seen:
            break
        seen.add(cur)
        out.append(cur)
        p = db.session.get(DiagramFolder, cur)
        cur = p.parent_id if p is not None else None
    return out


def _depth(folder: DiagramFolder | None) -> int:
    return 0 if folder is None else len(_ancestors(folder)) + 1


def _subtree_height(folder_id: int) -> int:
    """Levels of *folder_id*'s subtree, itself included."""
    height, level, seen = 0, [folder_id], set()
    while level and height <= MAX_DEPTH + 2:
        height += 1
        seen.update(level)
        level = [f.id for f in DiagramFolder.query.filter(DiagramFolder.parent_id.in_(level)).all()
                 if f.id not in seen]
    return height


def _check_sibling_name(name: str, parent_id, exclude_id=None) -> None:
    q = folders_query().filter(func.lower(DiagramFolder.name) == name.lower())
    q = q.filter(DiagramFolder.parent_id.is_(None) if parent_id is None
                 else DiagramFolder.parent_id == parent_id)
    if exclude_id is not None:
        q = q.filter(DiagramFolder.id != exclude_id)
    if q.first() is not None:
        raise Conflict("A folder named %r already exists here." % name)


def folder_list() -> list[dict]:
    rows = folders_query().order_by(DiagramFolder.position, DiagramFolder.name).all()
    counts = dict(db.session.query(Diagram.folder_id, func.count(Diagram.id))
                  .filter(Diagram.folder_id.in_([f.id for f in rows] or [-1]))
                  .group_by(Diagram.folder_id).all())
    counts_vis = {}
    for fid, n in (diagrams_query().with_entities(Diagram.folder_id, func.count(Diagram.id))
                   .group_by(Diagram.folder_id).all()):
        counts_vis[fid] = n
    visible = {f.id for f in rows}
    return [{"id": f.id, "name": f.name,
             "parent_id": f.parent_id if f.parent_id in visible else None,
             "position": f.position, "count": counts_vis.get(f.id, 0),
             "total": counts.get(f.id, 0), "adom": f.adom} for f in rows]


def create_folder(user, name, parent_id=None) -> DiagramFolder:
    name = _clean_text(name, FOLDER_NAME_MAX, "The folder name", required=True)
    parent = _folder_or_none(parent_id)
    if _depth(parent) + 1 > MAX_DEPTH:
        raise StudioError("Folders nest at most %d levels deep." % MAX_DEPTH)
    _check_sibling_name(name, parent.id if parent else None)
    pos = (db.session.query(func.max(DiagramFolder.position))
           .filter(DiagramFolder.parent_id.is_(None) if parent is None
                   else DiagramFolder.parent_id == parent.id).scalar())
    f = DiagramFolder(name=name, parent_id=parent.id if parent else None,
                      position=(pos or 0) + 1, adom=_stamp(), created_by=_by(user))
    db.session.add(f)
    db.session.commit()
    return f


def update_folder(user, folder: DiagramFolder, data: dict) -> DiagramFolder:
    name = folder.name
    parent_id = folder.parent_id
    if "name" in data:
        name = _clean_text(data.get("name"), FOLDER_NAME_MAX, "The folder name", required=True)
    if "parent_id" in data:
        parent = _folder_or_none(data.get("parent_id"))
        if parent is not None:
            if parent.id == folder.id or folder.id in _ancestors(parent):
                raise Conflict("A folder cannot be moved into itself or one of its subfolders.")
            if _depth(parent) + _subtree_height(folder.id) > MAX_DEPTH:
                raise StudioError("Folders nest at most %d levels deep." % MAX_DEPTH)
        parent_id = parent.id if parent is not None else None
    if "position" in data:
        try:
            pos = int(data.get("position"))
        except (TypeError, ValueError):
            raise StudioError("The position is a whole number.") from None
        if not -1_000_000 <= pos <= 1_000_000:
            raise StudioError("The position is out of range.")
        folder.position = pos
    if name != folder.name or parent_id != folder.parent_id:
        _check_sibling_name(name, parent_id, exclude_id=folder.id)
    folder.name, folder.parent_id = name, parent_id
    folder.updated_at = _now()
    db.session.commit()
    return folder


def delete_folder(user, folder: DiagramFolder) -> None:
    # Counted over EVERY ADOM: the row is the same whoever sees it, and a
    # folder holding another console's diagram is not empty.
    if DiagramFolder.query.filter_by(parent_id=folder.id).first() is not None \
            or Diagram.query.filter_by(folder_id=folder.id).first() is not None:
        raise Conflict("The folder is not empty: move or delete its diagrams and subfolders first.")
    db.session.delete(folder)
    db.session.commit()


# --------------------------------------------------------------- diagrams

def _version_row(d: Diagram, number: int | None = None) -> DiagramVersion | None:
    n = d.current_version if number is None else number
    return DiagramVersion.query.filter_by(diagram_id=d.id, number=n).first()


def current_doc(d: Diagram) -> dict:
    v = _version_row(d)
    if v is None:
        return _model().empty(d.name)
    return unpack(v.doc_gz)


def version_doc(d: Diagram, number: int) -> dict:
    v = _version_row(d, number)
    if v is None:
        raise NotFound("Version %s not found." % number)
    return unpack(v.doc_gz)


def published_doc(d: Diagram) -> dict:
    if not d.published or not d.published_version:
        raise NotFound("Diagram not found.")
    return version_doc(d, d.published_version)


def _stats_of(doc: dict) -> dict:
    try:
        return _model().stats(doc)
    except Exception:  # noqa: BLE001 -- stats are informative only
        return {}


def _add_version(d: Diagram, doc: dict, number: int, note: str, user) -> DiagramVersion:
    v = DiagramVersion(diagram_id=d.id, number=number, sha256=doc_sha(doc), doc_gz=pack(doc),
                       stats_json=json.dumps(_stats_of(doc), sort_keys=True),
                       note=_clean_text(note, NOTE_MAX, "The note"), created_by=_by(user))
    db.session.add(v)
    return v


def prune_versions(d: Diagram) -> int:
    """Keep the newest :data:`MAX_VERSIONS` versions and the published one."""
    keep = {n for (n,) in db.session.query(DiagramVersion.number)
            .filter(DiagramVersion.diagram_id == d.id).order_by(DiagramVersion.number.desc())
            .limit(MAX_VERSIONS).all()}
    keep.add(d.current_version)
    if d.published_version:
        keep.add(d.published_version)
    old = DiagramVersion.query.filter(DiagramVersion.diagram_id == d.id,
                                      ~DiagramVersion.number.in_(keep)).all()
    for v in old:
        db.session.delete(v)
    return len(old)


def create_diagram(user, name, *, folder_id=None, doc=None, description="", note="Created",
                   source: dict | None = None) -> tuple[Diagram, list[str]]:
    name = _clean_text(name, DIAGRAM_NAME_MAX, "The diagram name", required=True)
    description = _clean_text(description, DESCRIPTION_MAX, "The description")
    folder = _folder_or_none(folder_id)
    if doc is None:
        doc, warnings = _model().empty(name), []
    else:
        doc, warnings = normalise(doc)
    doc["name"] = name
    src = source or {}
    d = Diagram(name=name, description=description, folder_id=folder.id if folder else None,
                adom=_stamp(), owner_id=getattr(user, "id", None), published=False,
                current_version=1, source_format=str(src.get("format") or "")[:32],
                source_filename=str(src.get("filename") or "")[:255],
                source_sha256=str(src.get("sha256") or "")[:64],
                created_by=_by(user), updated_by=_by(user))
    db.session.add(d)
    db.session.flush()
    _add_version(d, doc, 1, note, user)
    db.session.commit()
    return d, warnings


def save_diagram(user, d: Diagram, doc, base_version, note="") -> tuple[int, list[str], bool]:
    """``(version, warnings, created)``. Conflict (409, ``current_version``)
    when *base_version* is not the current version."""
    try:
        base = int(base_version)
    except (TypeError, ValueError):
        raise StudioError("version is required (the version the edit started from).") from None
    if base != d.current_version:
        raise Conflict("The diagram was saved by someone else since you opened it "
                       "(version %d is current)." % d.current_version,
                       current_version=d.current_version)
    doc, warnings = normalise(doc)
    doc["name"] = d.name
    sha = doc_sha(doc)
    cur = _version_row(d)
    if cur is not None and cur.sha256 == sha:
        return d.current_version, warnings, False
    new = (db.session.query(func.max(DiagramVersion.number))
           .filter(DiagramVersion.diagram_id == d.id).scalar() or 0) + 1
    res = db.session.execute(
        update(Diagram).where(Diagram.id == d.id, Diagram.current_version == base)
        .values(current_version=new, updated_at=_now(), updated_by=_by(user)))
    if res.rowcount != 1:
        db.session.rollback()
        fresh = db.session.get(Diagram, d.id)
        raise Conflict("The diagram was saved by someone else since you opened it.",
                       current_version=fresh.current_version if fresh else None)
    _add_version(d, doc, new, note, user)
    try:
        db.session.flush()
    except IntegrityError:
        db.session.rollback()
        fresh = db.session.get(Diagram, d.id)
        raise Conflict("The diagram was saved by someone else since you opened it.",
                       current_version=fresh.current_version if fresh else None) from None
    db.session.expire(d)
    prune_versions(d)
    db.session.commit()
    return new, warnings, True


def patch_diagram(user, d: Diagram, data: dict) -> Diagram:
    if "name" in data:
        d.name = _clean_text(data.get("name"), DIAGRAM_NAME_MAX, "The diagram name", required=True)
    if "description" in data:
        d.description = _clean_text(data.get("description"), DESCRIPTION_MAX, "The description")
    if "folder_id" in data:
        f = _folder_or_none(data.get("folder_id"))
        d.folder_id = f.id if f else None
    d.updated_by = _by(user)
    d.updated_at = _now()
    db.session.commit()
    return d


def delete_diagram(user, d: Diagram) -> None:
    DiagramImport.query.filter_by(diagram_id=d.id).update({"diagram_id": None})
    DiagramVersion.query.filter_by(diagram_id=d.id).delete()
    db.session.delete(d)
    db.session.commit()


def duplicate_diagram(user, d: Diagram) -> Diagram:
    name = ("Copy of " + d.name)[:DIAGRAM_NAME_MAX]
    new, _w = create_diagram(user, name, folder_id=d.folder_id, doc=current_doc(d),
                             description=d.description, note="Duplicated from diagram %d" % d.id,
                             source={"format": d.source_format, "filename": d.source_filename,
                                     "sha256": d.source_sha256})
    return new


def restore_version(user, d: Diagram, number: int) -> tuple[int, bool]:
    doc = version_doc(d, number)
    ver, _w, created = save_diagram(user, d, doc, d.current_version,
                                    note="Restored version %d" % number)
    return ver, created


def versions(d: Diagram) -> list[dict]:
    rows = (DiagramVersion.query.filter_by(diagram_id=d.id)
            .order_by(DiagramVersion.number.desc()).all())
    out = []
    for v in rows:
        try:
            st = json.loads(v.stats_json or "{}")
        except ValueError:
            st = {}
        out.append({"number": v.number, "created_at": _iso(v.created_at), "created_by": v.created_by,
                    "note": v.note, "stats": st, "sha256": v.sha256,
                    "published": bool(d.published and d.published_version == v.number)})
    return out


def diff(d: Diagram, a, b) -> dict:
    try:
        na, nb = int(a), int(b)
    except (TypeError, ValueError):
        raise StudioError("a and b are version numbers.") from None
    from .diagram_engine import fidelity
    return fidelity.compare(version_doc(d, na), version_doc(d, nb))


def publish(user, d: Diagram, published: bool, data: dict) -> Diagram:
    if "menu_folder_id" in data:
        f = _folder_or_none(data.get("menu_folder_id"))
        d.folder_id = f.id if f else None
    if published:
        d.published = True
        d.published_version = d.current_version
        d.published_at = _now()
    else:
        d.published = False
        d.published_version = None
        d.published_at = None
    d.updated_by = _by(user)
    db.session.commit()
    return d


def _owner_names(ids) -> dict:
    from ..models import User
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return {u.id: u.username for u in User.query.filter(User.id.in_(ids)).all()}


def diagram_json(d: Diagram, *, owner: str | None = None) -> dict:
    return {"id": d.id, "name": d.name, "description": d.description, "folder_id": d.folder_id,
            "published": bool(d.published), "published_version": d.published_version,
            "published_at": _iso(d.published_at), "version": d.current_version,
            "source_format": d.source_format, "source_filename": d.source_filename,
            "adom": d.adom, "owner": owner, "created_by": d.created_by,
            "created_at": _iso(d.created_at), "updated_by": d.updated_by,
            "updated_at": _iso(d.updated_at)}


def diagram_list() -> list[dict]:
    rows = diagrams_query().order_by(Diagram.name).all()
    owners = _owner_names(r.owner_id for r in rows)
    ids = [r.id for r in rows] or [-1]
    counts = dict(db.session.query(DiagramVersion.diagram_id, func.count(DiagramVersion.id))
                  .filter(DiagramVersion.diagram_id.in_(ids)).group_by(DiagramVersion.diagram_id).all())
    stats = dict(db.session.query(DiagramVersion.diagram_id, DiagramVersion.stats_json)
                 .join(Diagram, and_(Diagram.id == DiagramVersion.diagram_id,
                                     Diagram.current_version == DiagramVersion.number))
                 .filter(DiagramVersion.diagram_id.in_(ids)).all())
    out = []
    for r in rows:
        j = diagram_json(r, owner=owners.get(r.owner_id))
        try:
            st = json.loads(stats.get(r.id) or "{}")
        except ValueError:
            st = {}
        j["elements"] = st.get("elements", 0)
        j["connectors"] = st.get("connectors", 0)
        j["versions"] = counts.get(r.id, 0)
        out.append(j)
    return out


# ------------------------------------------------------------------- menu

def menu(user, active_id=None) -> list[dict]:
    """The Diagrams menu of the current scope: published diagrams as a folder
    tree. Folders without a published diagram below them are left out;
    folders by position then name, then the diagrams by name. A folder is
    ``open`` when it holds the active diagram."""
    if user is None or not getattr(user, "is_authenticated", False) or not user.can("diagrams.view"):
        return []
    pubs = (diagrams_query().filter(Diagram.published.is_(True))
            .with_entities(Diagram.id, Diagram.name, Diagram.folder_id).all())
    if not pubs:
        return []
    folders = {f.id: f for f in folders_query().all()}
    children: dict = {}
    for f in folders.values():
        pid = f.parent_id if f.parent_id in folders else None
        children.setdefault(pid, []).append(f)
    items: dict = {}
    for did, name, fid in pubs:
        items.setdefault(fid if fid in folders else None, []).append((did, name))

    def build(pid, depth, seen) -> tuple[list, bool]:
        nodes, here = [], False
        if depth <= MAX_DEPTH + 1:
            for f in sorted(children.get(pid, []), key=lambda x: (x.position, x.name.lower(), x.id)):
                if f.id in seen:
                    continue
                kids, open_ = build(f.id, depth + 1, seen | {f.id})
                if kids:
                    nodes.append({"kind": "folder", "id": f.id, "name": f.name, "depth": depth,
                                  "open": open_, "children": kids})
                    here = here or open_
        for did, name in sorted(items.get(pid, []), key=lambda x: (x[1].lower(), x[0])):
            active = active_id is not None and did == active_id
            nodes.append({"kind": "diagram", "id": did, "name": name, "depth": depth,
                          "active": active})
            here = here or active
        return nodes, here

    return build(None, 0, frozenset())[0]


# -------------------------------------------------------------- libraries

_LIB_LOCK = threading.Lock()
_LIB_CACHE: dict = {}          # row id -> (created_at, lib)


def _builtin() -> dict:
    from .diagram_engine import symbols
    return symbols.load_builtin()


def _load_row(row: DiagramLibrary) -> dict | None:
    from .diagram_engine import symbols
    try:
        svgs = json.loads(gzip.decompress(row.svgs_gz).decode("utf-8"))
        lib = symbols.load_library(json.loads(row.library_json),
                                   {k: v.encode("utf-8") for k, v in svgs.items()})
    except Exception:  # noqa: BLE001 -- a damaged row hides one library, never the page
        current_app.logger.warning("diagram library %s could not be loaded", row.lib_id)
        return None
    lib["builtin"] = False
    return lib


def operator_libraries() -> dict:
    rows = DiagramLibrary.query.order_by(DiagramLibrary.lib_id).all()
    out = {}
    with _LIB_LOCK:
        live = {r.id for r in rows}
        for k in [k for k in _LIB_CACHE if k not in live]:
            _LIB_CACHE.pop(k, None)
        for r in rows:
            hit = _LIB_CACHE.get(r.id)
            if hit is None or hit[0] != r.created_at:
                lib = _load_row(r)
                if lib is None:
                    continue
                _LIB_CACHE[r.id] = (r.created_at, lib)
                hit = _LIB_CACHE[r.id]
            out[hit[1]["id"]] = hit[1]
    return out


def all_libraries() -> dict:
    """Built-in plus operator libraries by id; a built-in id always wins."""
    out = dict(operator_libraries())
    out.update(_builtin())
    return {k: out[k] for k in sorted(out)}


def library_list() -> list[dict]:
    out = []
    for lib in all_libraries().values():
        out.append({"id": lib["id"], "label": lib["label"], "builtin": bool(lib.get("builtin")),
                    "version": lib.get("version", ""), "license": lib.get("license", ""),
                    "families": lib.get("families", {}),
                    "variant": lib.get("variant") or "flat", "anchor": lib.get("anchor"),
                    "symbols": [{k: s.get(k) for k in ("id", "label", "category", "shape", "w", "h",
                                                       "ports", "keywords", "variants")}
                                for s in lib["symbols"]]})
    return out


def symbol_svg(lib_id: str, sym_id: str) -> str | None:
    from .diagram_engine import symbols
    if not (symbols.LIB_ID_RE.match(lib_id or "") and symbols.SYM_ID_RE.match(sym_id or "")):
        return None
    lib = all_libraries().get(lib_id)
    if lib is None:
        return None
    for s in lib["symbols"]:
        if s["id"] == sym_id:
            return s.get("svg_text")
    return None


def categories() -> dict:
    from .diagram_engine import symbols
    return symbols.categories(list(all_libraries().values()))


def store_library(user, result: dict) -> DiagramLibrary:
    """Validate the jail's library answer again and store it."""
    from .diagram_engine import symbols
    form = result.get("library") if isinstance(result, dict) else None
    svgs = result.get("svgs") if isinstance(result, dict) else None
    if not isinstance(form, dict) or not isinstance(svgs, dict) \
            or not all(isinstance(k, str) and isinstance(v, str) for k, v in svgs.items()):
        raise StudioError("The library check returned nothing usable.")
    try:
        lib = symbols.load_library(form, {k: v.encode("utf-8") for k, v in svgs.items()})
    except symbols.LibraryError as exc:
        raise StudioError("The library was refused: %s" % exc) from None
    if lib["id"] in _builtin():
        raise Conflict("%r is the id of a built-in library." % lib["id"])
    if DiagramLibrary.query.filter_by(lib_id=lib["id"]).first() is not None:
        raise Conflict("A library with id %r already exists; delete it first." % lib["id"])
    fams = list(lib.get("families") or {})
    clean_form = {"schema": symbols.SCHEMA, "id": lib["id"], "label": lib["label"],
                  "version": lib.get("version", ""), "license": lib.get("license", ""),
                  "families": lib.get("families", {}), "variant": lib.get("variant") or "flat",
                  "symbols": [{k: v for k, v in s.items() if k != "svg_text"} for s in lib["symbols"]]}
    if lib.get("anchor") is not None:
        clean_form["anchor"] = lib["anchor"]
    row = DiagramLibrary(lib_id=lib["id"], label=lib["label"], family=(fams[0] if fams else "generic")[:32],
                         library_json=json.dumps(clean_form, sort_keys=True),
                         svgs_gz=gzip.compress(json.dumps({s["svg"]: s["svg_text"] for s in lib["symbols"]},
                                                          sort_keys=True).encode("utf-8")),
                         created_by=_by(user))
    db.session.add(row)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise Conflict("A library with id %r already exists." % lib["id"]) from None
    return row


def delete_library(user, lib_id: str) -> None:
    if lib_id in _builtin():
        raise Conflict("Built-in libraries cannot be deleted.")
    row = DiagramLibrary.query.filter_by(lib_id=lib_id).first()
    if row is None:
        raise NotFound("Library not found.")
    db.session.delete(row)
    db.session.commit()


# ---------------------------------------------------------------- imports

TERMINAL = ("ok", "failed", "refused")


def get_import(user, job_id: str) -> DiagramImport:
    from . import diagram_runner as R
    if not R.JOB_RE.match(str(job_id or "")):
        raise NotFound("Import not found.")
    q = product_scope.scope_query(DiagramImport.query, DiagramImport.adom)
    row = q.filter(DiagramImport.id == job_id).first()
    # An import is its author's work in progress.
    if row is None or (row.created_by != _by(user) and not user.can("user_manage")):
        raise NotFound("Import not found.")
    return row


def refresh_import(row: DiagramImport) -> dict:
    """The status file read back into the row (lazily: the runner has no
    database). Returns the status record."""
    from . import diagram_runner as R
    st = R.read_status(row.id) if row.status not in ("refused", "staged") else {}
    changed = False
    status = st.get("status")
    if status in ("queued", "running", "ok", "failed", "refused") and status != row.status \
            and row.status not in TERMINAL:
        row.status = status
        changed = True
    if row.status in ("ok", "failed", "refused") and row.finished_at is None and st:
        row.finished_at = _now()
        row.format = str(st.get("format") or row.format or "")[:32]
        row.error = str(st.get("error") or "")[:1000]
        changed = True
    if changed:
        db.session.commit()
    return st


def import_json(row: DiagramImport, st: dict | None = None) -> dict:
    st = st or {}
    cls = st.get("classification") if isinstance(st.get("classification"), dict) else {}
    return {"id": row.id, "filename": row.filename, "format": row.format or st.get("format") or "",
            "status": row.status, "error": row.error or st.get("error") or "",
            "stats": st.get("stats") or {}, "warnings": st.get("warnings") or [],
            "classification": {"families": cls.get("families") or {},
                               "unknown": cls.get("unknown") or [],
                               "conflicts": cls.get("conflicts") or []},
            "timings": st.get("timings") or {},
            "started_at": st.get("started_at"), "finished_at": st.get("finished_at"),
            "duration_ms": st.get("duration_ms"), "diagram_id": row.diagram_id,
            "created_at": _iso(row.created_at)}


def vision_config() -> dict | None:
    """The local vision model the runner may ask, or None (not configured)."""
    import os
    ep = current_app.config.get("DIAGRAM_VISION_ENDPOINT") or os.environ.get("SATOM_DIAGRAM_VISION_ENDPOINT")
    mdl = current_app.config.get("DIAGRAM_VISION_MODEL") or os.environ.get("SATOM_DIAGRAM_VISION_MODEL")
    if ep and mdl:
        return {"endpoint": str(ep)[:500], "model": str(mdl)[:100]}
    return None


# ------------------------------------------------------- import retention

#: A page-picker probe (``staged``) that no import followed within this long.
STAGED_TTL_S = 3600
#: Every other import record, and its status/result files.
IMPORT_TTL_S = 7 * 24 * 3600
#: A stored source younger than this is never swept (an upload may be between
#: storing its bytes and committing the row that references them).
SOURCE_GRACE_S = 3600
#: How often the opportunistic purge actually runs (per node).
PURGE_EVERY_S = 600


def _referenced_sources() -> set:
    refs = {sha for (sha,) in db.session.query(DiagramImport.source_sha256).distinct() if sha}
    refs |= {sha for (sha,) in db.session.query(Diagram.source_sha256).distinct() if sha}
    return refs


def _sweep_sources(only=None, grace_s: int = SOURCE_GRACE_S) -> int:
    """Delete stored sources no import record and no diagram references.
    ``only``: the hashes to consider (default: every stored source)."""
    import os
    import time
    from . import diagram_runner as R
    refs = _referenced_sources()
    if only is not None:
        names = [sha for sha in only if sha and sha not in refs]
    else:
        d = R.root() / "sources"
        names = [p.name for p in d.iterdir()] if d.is_dir() else []
        names = [n for n in names if R.SHA_RE.match(n) and n not in refs]
    n = 0
    now = time.time()
    for sha in names:
        p = R.source_path(sha)
        if p is None:
            continue
        try:
            if grace_s and now - os.stat(p).st_mtime < grace_s:
                continue
        except OSError:
            continue
        if R.remove_source(sha):
            n += 1
    return n


def purge_imports(now: datetime | None = None, *, force: bool = False) -> dict:
    """Retention of the import area: ``staged`` probes older than an hour,
    every other import record older than seven days (with its request,
    status and result files), then the stored sources nothing references --
    which includes a symbol-library ZIP stored before 2026-11-17, when the
    upload was still kept after parsing (no row ever referenced it).
    Throttled to once per :data:`PURGE_EVERY_S` per node unless *force*.
    Audit-logged when it removed anything. Never raises."""
    import os
    import time
    from datetime import timedelta
    from . import diagram_runner as R
    out = {"staged": 0, "imports": 0, "sources": 0, "ran": False}
    # In sources/ (0700, the app's own), not in data/diagrams/ itself: a node
    # where that directory is root-owned (a1, 2026-11-17) could never write
    # the stamp, and the throttle silently never engaged.
    stamp = R.root() / "sources" / ".purge-stamp"
    try:
        if not force and time.time() - os.stat(stamp).st_mtime < PURGE_EVERY_S:
            return out
    except OSError:
        pass
    try:
        R._mkdir(stamp.parent, 0o700)
        stamp.touch()
        os.utime(stamp)
    except OSError:
        pass
    now = now or _now()
    try:
        staged = DiagramImport.query.filter(
            DiagramImport.status == "staged",
            DiagramImport.created_at < now - timedelta(seconds=STAGED_TTL_S)).all()
        old = DiagramImport.query.filter(
            DiagramImport.status != "staged",
            func.coalesce(DiagramImport.finished_at, DiagramImport.created_at)
            < now - timedelta(seconds=IMPORT_TTL_S)).all()
        for row in staged + old:
            R.forget_job(row.id)
            db.session.delete(row)
        db.session.commit()
        out.update(staged=len(staged), imports=len(old), ran=True)
        out["sources"] = _sweep_sources()
    except Exception:  # noqa: BLE001 -- retention must never break an import
        db.session.rollback()
        current_app.logger.exception("diagram import purge failed")
        return out
    if out["staged"] or out["imports"] or out["sources"]:
        from .audit import log_action
        log_action("diagram.import_purge", target="diagram_imports",
                   extra={k: out[k] for k in ("staged", "imports", "sources")})
    return out


def delete_import(user, row: DiagramImport) -> dict:
    """Discard one import (the wizard's "discard"): its record, its queued
    request, status and result files, and its source when nothing else
    references it. A recognition already running finishes; its files are
    pruned with the rest."""
    from . import diagram_runner as R
    info = {"id": row.id, "filename": row.filename, "status": row.status,
            "sha256": row.source_sha256}
    R.forget_job(row.id)
    sha = row.source_sha256
    db.session.delete(row)
    db.session.commit()
    info["source_removed"] = bool(sha) and _sweep_sources(only=[sha], grace_s=0) == 1
    return info



def discard_upload(sha: str) -> bool:
    """Delete one stored upload at once when nothing references it (a symbol
    library's ZIP after the jail parsed it: the library row keeps the
    sanitised SVGs in ``svgs_gz`` and never needs the ZIP again)."""
    try:
        return _sweep_sources(only=[sha], grace_s=0) == 1
    except Exception:  # noqa: BLE001 -- the purge catches what this misses
        current_app.logger.exception("diagram upload %s could not be removed", sha)
        return False
