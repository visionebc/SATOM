"""Python Studio > API Catalog -- APIs someone publishes, by version (FA-0006).

A team (or a vendor) publishes an API; whoever wants to use it registers it
here once and adds one *version* per release of it: ``inventory 1.0``,
``inventory 1.1``, ``inventory 2.0``. A version's endpoint list comes from an
OpenAPI 3 / Swagger 2 document, from a person typing it in, or both (import,
then correct by hand).

* **draft** -- edited freely: import again, add, change or remove endpoints,
  delete the draft.
* **published** -- frozen for good: its endpoints never change and it is
  never deleted. HTTP connections are pinned to published versions only, so a
  connection that says ``inventory 1.1`` means the same endpoints tomorrow.
* **deprecated** -- still frozen and still usable; marked so the people who
  use it move on. Publishing a new version deprecates nothing by itself.

A connection pinned to a version (``studio_connections.api_version_id``):

* app steps (``Call an API``) can call an endpoint by id; a method + path
  that is not an endpoint of that version is a problem that blocks
  publishing the app, and is refused when the step runs;
* Script Library scripts call ``connection("inv").op("getHost", ...)`` and
  list ``connection("inv").operations()``; the broker refuses a request that
  is not in the version (``studio_api_spec``, database-free).

Moving a connection to another version is one select on the connection page;
:func:`impact` says which apps would lose an endpoint they call.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from urllib.parse import urlsplit

from ..extensions import db
from ..models_studio import StudioApi, StudioApiVersion, StudioConnection
from . import studio_api_spec as S

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,47}$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,31}$")
FROZEN = ("published", "deprecated")


class ApiError(ValueError):
    """A refusal the UI shows as is."""


# --------------------------------------------------------------------------- #
#  APIs                                                                        #
# --------------------------------------------------------------------------- #
def get(slug: str) -> StudioApi | None:
    return StudioApi.query.filter_by(slug=slug).first()


def list_apis() -> list[StudioApi]:
    return StudioApi.query.order_by(StudioApi.name).all()


def create(slug: str, name: str, by: str) -> StudioApi:
    slug = (slug or "").strip()
    if not _SLUG_RE.match(slug):
        raise ApiError("Id: lowercase letters, digits, - and _, 2 to 48 characters.")
    if get(slug) is not None:
        raise ApiError("an API with id %s already exists" % slug)
    name = (name or "").strip()[:120]
    if not name:
        raise ApiError("a name is required")
    a = StudioApi(slug=slug, name=name, created_by=by, updated_by=by)
    db.session.add(a)
    db.session.commit()
    return a


def save(a: StudioApi, form: dict, by: str) -> None:
    a.name = (form.get("name") or a.name).strip()[:120] or a.name
    a.owner = (form.get("owner") or "").strip()[:120]
    a.description = (form.get("description") or "").strip()[:4000]
    url = (form.get("docs_url") or "").strip()
    if url:
        p = urlsplit(url)
        if p.scheme not in ("http", "https") or not p.hostname or len(url) > 500:
            raise ApiError("the documentation link must be an http(s) URL")
    a.docs_url = url
    a.updated_by = by
    db.session.commit()


def connections_of(a: StudioApi) -> list[StudioConnection]:
    ids = [v.id for v in a.versions]
    if not ids:
        return []
    return (StudioConnection.query.filter(StudioConnection.api_version_id.in_(ids))
            .order_by(StudioConnection.slug).all())


def delete(a: StudioApi) -> None:
    users = connections_of(a)
    if users:
        raise ApiError("pinned by connection(s) %s: move them off this API first"
                       % ", ".join(c.slug for c in users))
    db.session.delete(a)
    db.session.commit()


# --------------------------------------------------------------------------- #
#  versions                                                                    #
# --------------------------------------------------------------------------- #
def _vkey(v: str):
    """1.10 after 1.9; text parts after numbers."""
    return [(0, int(x), "") if x.isdigit() else (1, 0, x) for x in re.split(r"[._+-]", v)]


def versions(a: StudioApi) -> list[StudioApiVersion]:
    return sorted(a.versions, key=lambda v: _vkey(v.version), reverse=True)


def latest(a: StudioApi) -> StudioApiVersion | None:
    for v in versions(a):
        if v.status == "published":
            return v
    return None


def get_version(a: StudioApi, version: str) -> StudioApiVersion | None:
    return StudioApiVersion.query.filter_by(api_id=a.id, version=version).first()


def create_version(a: StudioApi, version: str, by: str, *,
                   copy_from: StudioApiVersion | None = None) -> StudioApiVersion:
    version = (version or "").strip()
    if not _VERSION_RE.match(version):
        raise ApiError("Version: letters, digits and . _ + -, up to 32 characters (e.g. 2.1.0)")
    if get_version(a, version) is not None:
        raise ApiError("%s already has a version %s" % (a.slug, version))
    v = StudioApiVersion(api_id=a.id, version=version, status="draft",
                         created_by=by, updated_by=by)
    if copy_from is not None:
        if copy_from.api_id != a.id:
            raise ApiError("a version can only start from a version of the same API")
        v.operations_json = copy_from.operations_json
        v.base_path = copy_from.base_path
        v.source = copy_from.source
    db.session.add(v)
    db.session.commit()
    return v


def _draft(v: StudioApiVersion) -> None:
    if v.status != "draft":
        raise ApiError("%s is %s: a published version never changes. Start a new "
                       "version from it instead." % (v.label, v.status))


def import_openapi(v: StudioApiVersion, text: str, by: str) -> dict:
    """Replace the draft's endpoints with the document's. Returns what the
    parser said (title, version in the document, warnings)."""
    _draft(v)
    try:
        res = S.parse_openapi(text or "")
    except S.SpecError as exc:
        raise ApiError(str(exc)) from None
    v.operations_json = json.dumps(res["operations"])
    v.base_path = res["base_path"]
    v.source = "openapi"
    v.spec_sha256 = hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()
    v.updated_by = by
    db.session.commit()
    return {"title": res["title"], "document_version": res["version"],
            "base_path": res["base_path"], "operations": len(res["operations"]),
            "warnings": res["warnings"]}


def save_draft(v: StudioApiVersion, *, operations=None, notes=None, base_path=None,
               by: str) -> None:
    _draft(v)
    if operations is not None:
        try:
            v.operations_json = json.dumps(S.clean_operations(operations))
        except S.SpecError as exc:
            raise ApiError(str(exc)) from None
        if v.source != "openapi":           # imported, then corrected: still openapi
            v.source = "manual"
    if notes is not None:
        v.notes = str(notes)[:8000]
    if base_path is not None:
        bp = str(base_path).strip().rstrip("/")
        if bp:
            try:
                bp = S.clean_path(bp)
            except S.SpecError as exc:
                raise ApiError(str(exc)) from None
        v.base_path = bp[:200]
    v.updated_by = by
    db.session.commit()


def publish(v: StudioApiVersion, by: str) -> None:
    _draft(v)
    if not v.operations:
        raise ApiError("%s has no endpoints: import a document or add them first" % v.label)
    v.status = "published"
    v.published_by = by
    v.published_at = datetime.utcnow()
    v.updated_by = by
    db.session.commit()


def set_deprecated(v: StudioApiVersion, on: bool, by: str) -> None:
    if v.status not in FROZEN:
        raise ApiError("only a published version can be deprecated")
    v.status = "deprecated" if on else "published"
    v.updated_by = by
    db.session.commit()


def delete_version(v: StudioApiVersion) -> None:
    if v.status != "draft":
        raise ApiError("%s is %s: published versions are kept for good" % (v.label, v.status))
    db.session.delete(v)
    db.session.commit()


def compare(old: StudioApiVersion, new: StudioApiVersion) -> dict:
    if old.api_id != new.api_id:
        raise ApiError("both versions must belong to the same API")
    return S.diff(old.operations, new.operations)


# --------------------------------------------------------------------------- #
#  connections                                                                 #
# --------------------------------------------------------------------------- #
def bindable() -> list[StudioApiVersion]:
    """What a connection can be pinned to: every frozen version."""
    rows = (StudioApiVersion.query.filter(StudioApiVersion.status.in_(FROZEN))
            .join(StudioApi).order_by(StudioApi.slug).all())
    return sorted(rows, key=lambda v: (v.api.slug, [_neg(k) for k in _vkey(v.version)]))


def _neg(k):
    return (k[0], -k[1], k[2])


def resolve_binding(raw) -> StudioApiVersion | None:
    """The form value (a version id, '' = none) -> the version, checked."""
    if raw in (None, "", 0, "0"):
        return None
    try:
        v = db.session.get(StudioApiVersion, int(raw))
    except (TypeError, ValueError):
        v = None
    if v is None:
        raise ApiError("that API version does not exist")
    if v.status not in FROZEN:
        raise ApiError("%s is a draft: publish it before pinning a connection to it" % v.label)
    return v


def catalog_of(c: StudioConnection) -> dict | None:
    """``{"api", "version", "status", "operations"}`` for a pinned HTTP
    connection, else None. What the broker and the app steps check against."""
    v = c.api_version if c.kind == "http" else None
    if v is None:
        return None
    return {"api": v.api.slug, "version": v.version, "status": v.status,
            "operations": S.compact(v.operations)}


def impact(c: StudioConnection, new: StudioApiVersion | None) -> list[str]:
    """The app steps that call an endpoint *new* does not have (each as
    ``app/step: GET /path``). Empty when nothing breaks."""
    from ..models_studio import StudioApp
    if new is None:
        return []
    ops = new.operations
    out = []
    for a in StudioApp.query.order_by(StudioApp.slug).all():
        graphs = [("draft", a.graph), ("published", (a.published or {}).get("graph") or {})]
        for which, g in graphs:
            for n in g.get("nodes") or []:
                p = n.get("params") or {}
                if n.get("kind") != "api_call" or p.get("connection") != c.slug:
                    continue
                miss = endpoint_problem(ops, p)
                if miss:
                    out.append("%s (%s) / %s: %s" % (a.slug, which, n.get("key"), miss))
    return sorted(set(out))


def endpoint_problem(ops: list[dict], params: dict) -> str:
    """'' when an api_call step's endpoint exists in *ops*, else what is wrong."""
    oid = str(params.get("operation") or "").strip()
    if oid:
        return "" if S.by_id(ops, oid) else "endpoint %s does not exist" % oid
    method = (params.get("method") or "GET").upper()
    path = str(params.get("path") or "")
    if S.find(ops, method, path, template=True):
        return ""
    return "%s %s is not an endpoint" % (method, path or "/")


def choices() -> dict:
    """For the app editor: ``{connection slug: {"api", "version", "ops": [...]}}``
    for every pinned HTTP connection."""
    out = {}
    for c in StudioConnection.query.filter(StudioConnection.kind == "http",
                                           StudioConnection.api_version_id.isnot(None)).all():
        cat = catalog_of(c)
        if cat:
            out[c.slug] = {"api": cat["api"], "version": cat["version"],
                           "ops": [{"id": o["id"], "method": o["method"], "path": o["path"],
                                    "summary": o["summary"]} for o in cat["operations"]]}
    return out
