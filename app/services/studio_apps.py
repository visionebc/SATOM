"""Python Studio > Apps -- a form, a diagram and an output, published into
Operations > Plugins for the ADOMs and the people the administrator picks.

LIFECYCLE
---------
The administrator edits a DRAFT (form, diagram, output actions) and tests it
from the editor -- optionally as a rehearsal, where steps that write are only
described. **Publish** freezes the draft as version N; the menu entry and
every operator run use that frozen version until the next Publish, so editing
never changes what operators run. **Unpublish** takes the entry out of the
menu; the versions stay.

WHO SEES IT, WHERE
------------------
Where: the ADOMs the administrator ticked (``["*"]`` = every ADOM, Global
included). Who: the users and the user groups the administrator picked, plus
every Studio author (``studio.script_library``). Nobody else -- an app with an
empty list is visible to its authors only. Both answers come from here
(:func:`menu`, :func:`can_use`); the sidebar and the pages ask, they never
decide on their own.

ACTIONS ON THE OUTPUT
---------------------
A finished run offers the app's actions: save to a data store, download
(CSV/JSON), send to a connection, run another app with the output, or raise a
**change request**. An ACTION never changes a device: it becomes a draft change
request through ``views.change_requests.create_change_request`` (the one
implementation of "raise a change") and goes through the existing approval.

DEVICE WRITES FROM A DIAGRAM
----------------------------
Two kinds of STEP may write to an appliance, both only in an armed run and
only for a user who holds ``config_write`` (the permission every other armed
write asks for): *Walk a process* and the SATOM steps that issue a
certificate or create / remove a server policy (``services.studio_satom``).
An armed run whose diagram writes is also a job (:func:`_job_for`), so the
change is followed on the Jobs page like every other one.
"""
from __future__ import annotations

import base64
import csv
import io
import json
import re
import threading
import time
from datetime import datetime, timedelta
from urllib.parse import quote, quote_plus

from ..extensions import db
from ..models_studio import StudioApp, StudioAppRun, UserGroup, user_group_members
from . import studio_flow as F

AUTHOR = "studio.script_library"
FIELD_TYPES = ("text", "textarea", "number", "select", "checkbox", "password", "date",
               "store_select", "api_select", "satom_select")
#: The list types; any of them may add a search box over its choices (``search``).
LIST_TYPES = ("select", "store_select", "api_select", "satom_select")
ACTION_KINDS = ("save_store", "download", "send", "run_app", "change_request")
MAX_FIELDS = 40
MAX_ACTIONS = 20
MAX_OPTIONS = 500
RUN_VARS_CAP = 256 * 1024
#: Runs in progress at once: per user, and on the whole node. Every run is a
#: thread of the web process; an operator holding the Run button must not be
#: able to take every worker (finding 2026-10-20).
MAX_RUNS_PER_USER = 2
MAX_RUNS_TOTAL = 8
#: Run records are kept this long.
RUN_KEEP_DAYS = 90
#: A list field fed by an API is fetched at most once per this many seconds
#: (form opened, form submitted, the next operator...).
OPTIONS_TTL = 60.0
_OPTIONS_CACHE: dict = {}
_OPTIONS_LOCK = threading.Lock()
#: Actions that may run again on the same run: they change nothing.
REPEATABLE_ACTIONS = ("download",)
#: Test seam: run in the request thread instead of a background thread.
RUN_INLINE = False

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,47}$")
_FIELD_RE = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")
_ICON_RE = re.compile(r"^bi-[a-z0-9-]{1,28}$")
_ACTION_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")

#: Node / action parameters that name another Studio object.
REF_PARAMS = {"store": ("store",), "connection": ("connection",), "script": ("script",),
              "app": ("app",)}


class AppError(ValueError):
    pass


# --------------------------------------------------------------------------- #
#  references                                                                  #
# --------------------------------------------------------------------------- #
def _refs(graph: dict, actions: list, fields: list, kind: str) -> set:
    names = REF_PARAMS.get(kind, ())
    out = set()
    for n in (graph or {}).get("nodes") or []:
        p = n.get("params") or {}
        for k in names:
            if p.get(k):
                out.add(str(p[k]))
    for a in actions or []:
        p = a.get("params") or {}
        for k in names:
            if p.get(k):
                out.add(str(p[k]))
    for f in fields or []:
        for k in names:
            if f.get(k):
                out.add(str(f[k]))
    return out


def used_by(kind: str, slug: str) -> list[str]:
    """Apps whose draft or published version names *slug* (a data store,
    connection, script or app). Deleting it would break them."""
    hits = []
    for a in StudioApp.query.order_by(StudioApp.slug).all():
        pub = a.published
        if slug in _refs(a.graph, a.actions, a.fields, kind) or slug in _refs(
                pub.get("graph") or {}, pub.get("actions") or [], pub.get("fields") or [], kind):
            if not (kind == "app" and a.slug == slug):
                hits.append(a.slug)
    return hits


def choices() -> dict:
    """What the pickers offer: existing data stores, connections, published
    scripts, published apps, change types."""
    from . import studio_store as SS
    from . import studio_connections as SC
    from . import script_library as SL
    out = {"stores": [s["slug"] for s in SS.list_stores()],
           "http": [c.slug for c in SC.list_connections("http")],
           "pg": [c.slug for c in SC.list_connections("postgres")],
           # script apps run from their script's page, not as "run another app"
           "scripts": [], "apps": [a.slug for a in StudioApp.query.order_by(StudioApp.slug).all()
                                   if a.kind != "script"],
           "cr_actions": []}
    try:
        out["scripts"] = [s["slug"] for s in SL.list_scripts() if s.get("published")]
    except Exception:  # noqa: BLE001 -- a broken library dir must not break the editor
        pass
    from . import studio_apis as SAPI
    out["catalog"] = SAPI.choices()
    from . import studio_satom as S
    out.update(S.choices())
    out["satom_sources"] = [{"key": k, "label": lab} for k, lab in S.SOURCES]
    try:
        from ..models_process import Process
        out["processes"] = [p.key for p in Process.query.filter_by(enabled=True)
                            .order_by(Process.key).all()]
    except Exception:  # noqa: BLE001 -- the editor must open without the table
        out["processes"] = []
    try:
        from ..views.change_requests import cr_type_entries
        out["cr_actions"] = [e["key"] for e in cr_type_entries()]
    except Exception:  # noqa: BLE001
        pass
    return out


# --------------------------------------------------------------------------- #
#  the form                                                                    #
# --------------------------------------------------------------------------- #
def clean_fields(fields, ch: dict | None = None) -> list[dict]:
    ch = ch or {}
    if not isinstance(fields, list):
        raise AppError("the form is a list of fields")
    if len(fields) > MAX_FIELDS:
        raise AppError("at most %d fields" % MAX_FIELDS)
    out, seen = [], set()
    for f in fields:
        if not isinstance(f, dict):
            raise AppError("each field is an object")
        name = str(f.get("name") or "").strip()
        if not _FIELD_RE.match(name):
            raise AppError("field %r: lowercase letters, digits and _" % name)
        if name in seen:
            raise AppError("field %s is listed twice" % name)
        seen.add(name)
        typ = str(f.get("type") or "text")
        if typ not in FIELD_TYPES:
            raise AppError("field %s: unknown type %r" % (name, typ))
        c = {"name": name, "label": str(f.get("label") or name).strip()[:120] or name,
             "type": typ, "required": bool(f.get("required")),
             "help": str(f.get("help") or "").strip()[:500],
             "default": "" if typ == "password" else str(f.get("default") or "")[:2000]}
        if typ == "select":
            opts = [o.strip() for o in str(f.get("options") or "").splitlines() if o.strip()]
            if not opts:
                raise AppError("field %s: a list needs options, one per line" % name)
            c["options"] = "\n".join(opts[:MAX_OPTIONS])
        if typ == "store_select":
            for k in ("store", "value_col"):
                if not str(f.get(k) or "").strip():
                    raise AppError("field %s: pick the data store and the value column" % name)
            if ch.get("stores") is not None and f.get("store") not in ch.get("stores", []):
                raise AppError("field %s: data store %r does not exist" % (name, f.get("store")))
            c.update(store=str(f["store"]), value_col=str(f["value_col"]).strip(),
                     label_col=str(f.get("label_col") or "").strip())
        if typ == "api_select":
            if ch.get("http") is not None and f.get("connection") not in ch.get("http", []):
                raise AppError("field %s: HTTP connection %r does not exist" % (name, f.get("connection")))
            c.update(connection=str(f.get("connection") or ""), path=str(f.get("path") or "")[:500],
                     list_path=str(f.get("list_path") or "")[:200],
                     value_key=str(f.get("value_key") or "")[:100],
                     label_key=str(f.get("label_key") or "")[:100])
        if typ == "satom_select":
            from . import studio_satom as S
            src = str(f.get("source") or "")
            if src not in S.SOURCE_KEYS:
                raise AppError("field %s: pick what the SATOM list shows" % name)
            c["source"] = src
        if typ in LIST_TYPES and f.get("search"):
            c["search"] = True
        out.append(c)
    return out


def options_for(field: dict) -> tuple[list[dict], str]:
    """``([{value, label}], problem)`` of a list field, read now."""
    typ = field.get("type")
    if typ == "select":
        return [{"value": o, "label": o} for o in (field.get("options") or "").splitlines() if o], ""
    if typ == "store_select":
        from . import studio_store as SS
        st = SS.get(field.get("store") or "")
        if st is None:
            return [], "data store %s does not exist" % field.get("store")
        try:
            rows = SS.query(st, limit=MAX_OPTIONS, order_by=field.get("label_col") or field["value_col"])
        except SS.StoreError as exc:
            return [], str(exc)
        out, seen = [], set()
        for r in rows:
            v = r.get(field["value_col"])
            if v is None or str(v) in seen:
                continue
            seen.add(str(v))
            out.append({"value": str(v), "label": str(r.get(field.get("label_col") or "") or v)})
        return out, ""
    if typ == "satom_select":
        from . import studio_satom as S
        try:
            return S.source_options(field.get("source") or "")
        except Exception as exc:  # noqa: BLE001 -- a broken source must not break the form
            return [], "%s: %s" % (field.get("source"), exc)
    if typ == "api_select":
        key = tuple(str(field.get(k) or "") for k in
                    ("connection", "path", "list_path", "value_key", "label_key"))
        now = time.monotonic()
        with _OPTIONS_LOCK:
            hit = _OPTIONS_CACHE.get(key)
            if hit and now - hit[0] < OPTIONS_TTL:
                return list(hit[1]), hit[2]
        opts, problem = _api_options(field)
        with _OPTIONS_LOCK:
            if len(_OPTIONS_CACHE) > 500:
                _OPTIONS_CACHE.clear()
            _OPTIONS_CACHE[key] = (now, opts, problem)
        return list(opts), problem
    return [], ""


def _api_options(field: dict) -> tuple[list[dict], str]:
    from . import studio_connections as SC
    c = SC.get(field.get("connection") or "")
    if c is None or c.kind != "http":
        return [], "connection %s does not exist" % field.get("connection")
    try:
        r = SC.http_call(c, "GET", field.get("path") or "")
    except SC.ConnectionError_ as exc:
        return [], str(exc)
    if not r["ok"]:
        return [], "HTTP %d from %s" % (r["status"], c.slug)
    items = SC.json_path(r.get("json"), field.get("list_path") or "")
    if not isinstance(items, list):
        return [], "the JSON path %r is not a list" % (field.get("list_path") or "$")
    out = []
    for it in items[:MAX_OPTIONS]:
        if isinstance(it, dict):
            v = it.get(field.get("value_key") or "")
            lab = it.get(field.get("label_key") or "") or v
        else:
            v = lab = it
        if v is not None:
            out.append({"value": str(v), "label": str(lab)})
    return out, ""


def form_view(fields: list) -> list[dict]:
    """The fields as the form draws them, list options resolved."""
    out = []
    for f in fields:
        v = dict(f)
        if f["type"] in ("select", "store_select", "api_select", "satom_select"):
            v["choices"], v["problem"] = options_for(f)
        out.append(v)
    return out


def resolve_inputs(fields: list, raw) -> dict:
    raw = raw if isinstance(raw, dict) else {}
    out = {}
    for f in fields:
        name, typ = f["name"], f["type"]
        v = raw.get(name)
        if typ == "checkbox":
            out[name] = v in (True, "1", "true", "on", "yes", 1)
            continue
        s = "" if v is None else str(v)
        if len(s) > 64 * 1024:
            raise AppError("%s is too long" % f["label"])
        if not s.strip():
            if f["required"]:
                raise AppError("%s is required" % f["label"])
            out[name] = None if typ in ("number", "date") else ""
            continue
        if typ == "number":
            try:
                n = float(s)
            except ValueError:
                raise AppError("%s: a number is expected" % f["label"]) from None
            out[name] = int(n) if n.is_integer() and "." not in s else n
        elif typ == "date":
            try:
                out[name] = datetime.strptime(s[:10], "%Y-%m-%d").date().isoformat()
            except ValueError:
                raise AppError("%s: a date (YYYY-MM-DD) is expected" % f["label"]) from None
        elif typ in ("select", "store_select", "api_select", "satom_select"):
            opts, problem = options_for(f)
            if s not in {o["value"] for o in opts}:
                raise AppError("%s: %r is not one of the choices%s"
                               % (f["label"], s, (" (" + problem + ")") if problem else ""))
            out[name] = s
        else:
            out[name] = s
    return out


def shown_inputs(fields: list, inputs: dict) -> dict:
    return {k: ("********" if any(f["name"] == k and f["type"] == "password" for f in fields) and v
                else v) for k, v in inputs.items()}


# --------------------------------------------------------------------------- #
#  actions                                                                     #
# --------------------------------------------------------------------------- #
def action_schema(ch: dict | None = None) -> list[dict]:
    ch = ch or {}
    T = lambda n, l, h="", d="", k="text", c=(): {"name": n, "label": l, "help": h, "default": d,  # noqa: E731
                                                   "kind": k, "choices": list(c)}
    return [
        {"key": "save_store", "label": "Save to a data store", "params": [
            T("store", "Data store", k="select", c=ch.get("stores", ())),
            T("mode", "Mode", k="select", c=("insert", "upsert"), d="insert"),
            T("match", "Upsert on columns", "Comma-separated: rows with the same values are updated."),
            T("rows", "Rows", "A row (object) or a list of rows.", "{{ outputs[0].value }}")]},
        {"key": "download", "label": "Download", "params": [
            T("format", "Format", k="select", c=("csv", "json"), d="csv"),
            T("value", "Value", "", "{{ outputs[0].value }}"),
            T("filename", "File name", d="output")]},
        {"key": "send", "label": "Send to a connection", "params": [
            T("connection", "Connection", k="select", c=ch.get("http", ())),
            T("method", "Method", k="select", c=("POST", "PUT", "PATCH"), d="POST"),
            T("path", "Path"),
            T("body", "Body (JSON)", "", '{"data": "{{ outputs[0].value }}"}', "json")]},
        {"key": "run_app", "label": "Run another app with the output", "params": [
            T("app", "App", k="select", c=ch.get("apps", ())),
            T("inputs", "Its form values (JSON)", "", '{}', "json")]},
        {"key": "change_request", "label": "Raise a change request", "params": [
            T("action", "Change type", k="select", c=ch.get("cr_actions", ())),
            T("title", "Title", d="{{ run.user }}: change from an app"),
            T("reason", "Reason", k="textarea"),
            T("devices", "Device ids", "A list of appliance ids, e.g. {{ outputs[0].value | map(attribute='id') | list }}"),
            T("risk", "Risk", k="select", c=("low", "medium", "high"), d="medium")]},
    ]


def clean_actions(actions, ch: dict | None = None) -> list[dict]:
    if not isinstance(actions, list):
        raise AppError("actions are a list")
    if len(actions) > MAX_ACTIONS:
        raise AppError("at most %d actions" % MAX_ACTIONS)
    schema = {s["key"]: s for s in action_schema(ch)}
    out, seen = [], set()
    for a in actions:
        if not isinstance(a, dict):
            raise AppError("each action is an object")
        key = str(a.get("key") or "").strip()
        if not _ACTION_RE.match(key) or key in seen:
            raise AppError("action key %r: lowercase letters, digits, - and _, unique" % key)
        seen.add(key)
        kind = a.get("kind")
        if kind not in schema:
            raise AppError("action %s: unknown kind %r" % (key, kind))
        params = {}
        for p in schema[kind]["params"]:
            v = (a.get("params") or {}).get(p["name"], p["default"])
            v = "" if v is None else str(v)
            if p["kind"] == "select" and p["choices"] and v not in p["choices"]:
                raise AppError("action %s: %s %r does not exist" % (key, p["label"], v))
            if p["kind"] == "json" and v.strip():
                try:
                    F.parse_json_param(v, p["label"])
                except F.FlowError as exc:
                    raise AppError("action %s: %s" % (key, exc)) from None
            params[p["name"]] = v[:4000]
        out.append({"key": key, "label": str(a.get("label") or key).strip()[:80] or key,
                    "kind": kind, "confirm": bool(a.get("confirm")), "params": params})
    return out


# --------------------------------------------------------------------------- #
#  CRUD and publishing                                                         #
# --------------------------------------------------------------------------- #
STARTER_GRAPH = {"nodes": [
    {"key": "start", "kind": "start", "label": "Start", "params": {}, "x": 80, "y": 40},
    {"key": "show", "kind": "output", "label": "Show the form", "x": 80, "y": 160,
     "params": {"value": "{{ form }}", "title": "You entered", "view": "keyvalue"}},
    {"key": "end", "kind": "end", "label": "End", "params": {}, "x": 80, "y": 280}],
    "edges": [{"src": "start", "dst": "show", "branch": "always"},
              {"src": "show", "dst": "end", "branch": "always"}]}


def get(slug: str) -> StudioApp | None:
    return StudioApp.query.filter_by(slug=slug).first()


def create(slug: str, name: str, by: str) -> StudioApp:
    slug = (slug or "").strip()
    if not _SLUG_RE.match(slug):
        raise AppError("Id: lowercase letters, digits, - and _, 2 to 48 characters.")
    if get(slug) is not None:
        raise AppError("an app with id %s already exists" % slug)
    name = (name or "").strip()[:120]
    if not name:
        raise AppError("a name is required")
    a = StudioApp(slug=slug, name=name, created_by=by, updated_by=by,
                  fields_json=json.dumps([{"name": "name", "label": "Name", "type": "text",
                                           "required": True, "help": "", "default": ""}]),
                  graph_json=json.dumps(STARTER_GRAPH))
    db.session.add(a)
    db.session.commit()
    return a


def save_settings(a: StudioApp, form: dict, adom_keys, by: str) -> None:
    a.name = (form.get("name") or a.name).strip()[:120] or a.name
    a.description = (form.get("description") or "").strip()[:2000]
    icon = (form.get("icon") or "bi-app-indicator").strip()
    if not _ICON_RE.match(icon):
        raise AppError("icon: a Bootstrap icon name such as bi-app-indicator")
    a.icon = icon
    adoms = [str(x) for x in form.get("adoms") or []]
    allowed = set(adom_keys) | {"*", "global"}
    bad = [x for x in adoms if x not in allowed]
    if bad:
        raise AppError("unknown ADOM(s): %s" % ", ".join(bad))
    a.adoms_json = json.dumps(["*"] if "*" in adoms else sorted(set(adoms)))
    acc = form.get("access") or {}
    gids = sorted({int(x) for x in acc.get("groups") or [] if str(x).isdigit()})
    uids = sorted({int(x) for x in acc.get("users") or [] if str(x).isdigit()})
    from ..models import User
    if gids and UserGroup.query.filter(UserGroup.id.in_(gids)).count() != len(gids):
        raise AppError("a group in the access list does not exist")
    if uids and User.query.filter(User.id.in_(uids)).count() != len(uids):
        raise AppError("a user in the access list does not exist")
    a.access_json = json.dumps({"groups": gids, "users": uids})
    a.updated_by = by
    db.session.commit()


def save_draft(a: StudioApp, *, fields=None, graph=None, actions=None, design=None,
               by: str) -> list[str]:
    """Save what was sent. Returns the diagram problems (a draft with problems
    is saved -- half-built work is never lost -- but cannot be published)."""
    from . import studio_design as D
    ch = choices()
    if fields is not None:
        a.fields_json = json.dumps(clean_fields(fields, ch))
    if graph is not None:
        if not isinstance(graph, dict) or len(json.dumps(graph)) > 512 * 1024:
            raise AppError("the diagram is not an object, or is larger than 512 KiB")
        a.graph_json = json.dumps({"nodes": graph.get("nodes") or [], "edges": graph.get("edges") or []})
    if actions is not None:
        a.actions_json = json.dumps(clean_actions(actions, ch))
    if design is not None:
        try:
            a.design_json = json.dumps(D.clean(design))
        except D.DesignError as exc:
            raise AppError("design: %s" % exc) from None
    a.updated_by = by
    db.session.commit()
    return F.validate_graph(a.graph, ch)


def problems(a: StudioApp) -> list[str]:
    ch = choices()
    errs = F.validate_graph(a.graph, ch)
    try:
        clean_fields(a.fields, ch)
        clean_actions(a.actions, ch)
    except AppError as exc:
        errs.append(str(exc))
    names = {f["name"] for f in a.fields}
    for m in re.finditer(r"form\.([a-z_][a-z0-9_]*)", a.graph_json or ""):
        if m.group(1) not in names:
            errs.append("the diagram reads form.%s, which is not a field of the form" % m.group(1))
    from . import studio_design as D
    try:
        errs += D.problems(D.clean(a.design), a.fields, a.graph, D.asset_keys(a.id))
    except D.DesignError as exc:
        errs.append("design: %s" % exc)
    return sorted(set(errs))


def publish(a: StudioApp, note: str, by: str) -> int:
    errs = problems(a)
    if errs:
        raise AppError("not published: " + " · ".join(errs))
    a.version = (a.version or 0) + 1
    a.published_json = json.dumps({"version": a.version, "fields": a.fields, "graph": a.graph,
                                   "actions": a.actions, "design": a.design, "at": datetime.utcnow().isoformat(timespec="seconds"),
                                   "by": by, "note": (note or "")[:200]})
    a.status = "published"
    a.published_at = datetime.utcnow()
    a.updated_by = by
    db.session.commit()
    return a.version


def unpublish(a: StudioApp, by: str) -> None:
    a.status = "draft"
    a.updated_by = by
    db.session.commit()


def delete(a: StudioApp) -> None:
    from . import studio_design as D
    from . import token_grants
    D.delete_assets(a.id)  # SQLite (tests) does not cascade
    token_grants.forget("app", a.id, a.slug)  # API tokens granted it lose the grant
    db.session.delete(a)
    db.session.commit()


# --------------------------------------------------------------------------- #
#  every plugin is an app (2026-10-23, operator: "everything created should    #
#  be an app, even if it is only a script")                                    #
# --------------------------------------------------------------------------- #
#: "flow": a form and a diagram, run here. "script": the entry of a Script
#: Library script -- its code, form, versions and audience stay in
#: data/scripts/<script_slug>, because the sandbox runner that executes it
#: must never hold a database connection (services.script_library).
KINDS = ("flow", "script")


def script_app(script_slug: str) -> StudioApp | None:
    return StudioApp.query.filter_by(kind="script", script_slug=script_slug).first()


def script_disabled(script_slug: str) -> bool:
    """Whether the app of this script is disabled. A lookup that fails says
    False: the script library must keep working without the table."""
    try:
        a = script_app(script_slug)
    except Exception:  # noqa: BLE001 -- no table, or no app context at all
        try:
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return False
    return a is not None and not a.enabled


def _free_slug(base: str) -> str:
    if get(base) is None:
        return base
    for i in range(1, 100):
        cand = ("%s-%d" % (base[:44], i))
        if get(cand) is None:
            return cand
    raise AppError("no free app id for %s" % base)


def ensure_script_app(script_slug: str, by: str) -> StudioApp:
    """The app of a script, created when missing (same id when it is free)."""
    from . import script_library as SL
    a = script_app(script_slug)
    if a is not None:
        return a
    meta = SL.get(script_slug) or {}
    a = StudioApp(slug=_free_slug(script_slug), name=(meta.get("name") or script_slug)[:120],
                  description=(meta.get("description") or "")[:2000], icon="bi-filetype-py",
                  kind="script", script_slug=script_slug, adoms_json=json.dumps(["global"]),
                  status="published" if meta.get("published") else "draft",
                  created_by=by, updated_by=by)
    db.session.add(a)
    db.session.commit()
    return a


def adopt_scripts(by: str = "system") -> list[str]:
    """Give every script that has no app its app. Idempotent; called where
    apps are listed, so a script made before 2026-10-23 (or restored from a
    backup) is never left outside the app list."""
    from . import script_library as SL
    have = {s for (s,) in db.session.query(StudioApp.script_slug)
            .filter(StudioApp.kind == "script").all()}
    made = []
    for s in SL.list_scripts():
        if s["slug"] not in have:
            made.append(ensure_script_app(s["slug"], by).slug)
    return made


def script_meta(a: StudioApp) -> dict:
    from . import script_library as SL
    try:
        return SL._read_json(SL._dir(a.script_slug) / "meta.json") or {}
    except Exception:  # noqa: BLE001 -- a missing or bad id reads as no script
        return {}


def is_template(a: StudioApp) -> bool:
    """Templates are the objects of Plugin Studio > Examples: they can be
    disabled, reset and downloaded, never deleted (operator, 2026-10-23)."""
    from . import studio_examples as EX
    if a.kind == "script":
        return EX.is_template("script", a.script_slug or "")
    return EX.is_template("app", a.slug)


def list_rows() -> list[dict]:
    """Plugin Studio > Apps: every app, flow and script alike, with what its
    row shows. A script app reads its version and audience from the script."""
    out = []
    for a in StudioApp.query.order_by(StudioApp.name).all():
        r = {"a": a, "kind": a.kind or "flow", "template": is_template(a),
             "enabled": a.enabled, "edit_endpoint": "studio.app_edit", "edit_slug": a.slug}
        if a.kind == "script":
            meta = script_meta(a)
            vs = [int(v.get("n") or 0) for v in meta.get("versions") or [] if isinstance(v, dict)]
            # name and description are edited in the script editor
            r.update(name=meta.get("name") or a.name, description=meta.get("description") or "",
                     published=meta.get("published"), latest=max(vs) if vs else None,
                     missing=not meta, audience=meta.get("audience") or "admins",
                     edit_endpoint="script_library.edit", edit_slug=a.script_slug)
        else:
            r.update(name=a.name, description=a.description or "",
                     published=a.version if a.status == "published" else None,
                     latest=a.version or None, missing=False, audience="")
        out.append(r)
    return out


def set_enabled(a: StudioApp, enabled: bool, by: str) -> None:
    a.enabled = bool(enabled)
    a.updated_by = by
    db.session.commit()


def stores_of(a: StudioApp) -> tuple[list[str], list[str]]:
    """(stores only this app uses, stores other apps use too) -- from the
    draft and the published version."""
    if a.kind == "script":
        return [], []
    pub = a.published
    names = _refs(a.graph, a.actions, a.fields, "store") | _refs(
        pub.get("graph") or {}, pub.get("actions") or [], pub.get("fields") or [], "store")
    own, shared = [], []
    for s in sorted(names):
        (shared if [x for x in used_by("store", s) if x != a.slug] else own).append(s)
    return own, shared


def reset(a: StudioApp) -> dict:
    """Delete the app's data: its run history and the rows of the data stores
    only it uses. Shared stores are left alone and listed. The design, the
    versions, the connections and the settings stay."""
    from . import script_library as SL
    from . import studio_store as SS
    from ..models_studio import StudioRow
    if a.kind == "script":
        return {"runs": SL.delete_runs(a.script_slug), "rows": 0, "stores": [], "shared": []}
    running = StudioAppRun.query.filter_by(app_id=a.id, status="running").count()
    if running:
        raise AppError("%d run(s) of this app are in progress; reset when they end" % running)
    runs = StudioAppRun.query.filter_by(app_id=a.id).delete(synchronize_session=False)
    own, shared = stores_of(a)
    rows = 0
    for slug in own:
        st = SS.get(slug)
        if st is not None:
            rows += StudioRow.query.filter_by(store_id=st.id).delete(synchronize_session=False)
    db.session.commit()
    return {"runs": runs, "rows": rows, "stores": own, "shared": shared}


def data_zip(a: StudioApp) -> tuple[str, bytes]:
    """Everything the app holds, as a zip: its runs (runs.json, or one JSON
    per script run) and a CSV per data store it uses."""
    import zipfile
    from . import script_library as SL
    from . import studio_store as SS
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        info = {"app": a.slug, "name": a.name, "kind": a.kind,
                "exported_at": datetime.utcnow().isoformat(timespec="seconds") + "Z"}
        if a.kind == "script":
            info["script"] = a.script_slug
            runs = SL.runs_full(a.script_slug)
            for r in runs:
                z.writestr("runs/%s.json" % r.get("request_id", "run"),
                           json.dumps(r, indent=1, default=str))
            info["runs"] = len(runs)
        else:
            runs = StudioAppRun.query.filter_by(app_id=a.id).order_by(StudioAppRun.id).all()
            z.writestr("runs.json", json.dumps([{
                "id": r.id, "status": r.status, "error": r.error, "version": r.version,
                "armed": r.armed, "user": r.user, "product": r.product, "inputs": r.inputs,
                "outputs": r.outputs, "steps": r.steps,
                "started_at": r.started_at.isoformat(timespec="seconds") if r.started_at else None,
                "finished_at": r.finished_at.isoformat(timespec="seconds") if r.finished_at else None}
                for r in runs], indent=1, default=str))
            info["runs"] = len(runs)
            own, shared = stores_of(a)
            info["stores"] = own + shared
            for slug in own + shared:
                st = SS.get(slug)
                if st is not None:
                    z.writestr("stores/%s.csv" % slug, SS.to_csv(st))
        z.writestr("app.json", json.dumps(info, indent=1))
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return "%s-data-%s.zip" % (a.slug, stamp), buf.getvalue()


def remove(a: StudioApp) -> dict:
    """Delete an app for good. Refused for a template (Examples) and for an
    app another app runs. A flow app takes its runs and the data stores only
    it uses; a script app takes the script, its versions, saved runs, run
    records and vaulted credentials. Connections and APIs are never deleted
    here: they are shared and hold secrets."""
    if is_template(a):
        raise AppError("%s is a template (Plugin Studio > Examples): disable or reset it; "
                       "templates are not deleted" % a.slug)
    users = used_by("app", a.slug)
    if users:
        raise AppError("other app(s) run it: %s" % ", ".join(users))
    if a.kind == "script":
        from . import script_library as SL
        from . import script_schedules as SSch
        from . import script_vault as SV
        callers = used_by("script", a.script_slug)
        if callers:
            raise AppError("app(s) %s run this script in a step" % ", ".join(callers))
        meta = script_meta(a)
        names = [c["name"] for c in meta.get("credentials") or []]
        for s in SSch.all_schedules():
            if s.get("slug") == a.script_slug:
                SSch.delete(s)
        runs = SL.delete_runs(a.script_slug)
        if meta:
            SL.delete(a.script_slug)
            SV.forget(a.script_slug, names)
        from . import token_grants
        token_grants.forget("app", a.id, a.slug)
        db.session.delete(a)
        db.session.commit()
        return {"script": a.script_slug, "runs": runs, "credentials": names}
    from . import studio_examples as EX
    from . import studio_store as SS
    from ..models_studio import StudioRow
    own, shared = stores_of(a)
    from . import studio_design as D
    runs = StudioAppRun.query.filter_by(app_id=a.id).delete(synchronize_session=False)
    D.delete_assets(a.id)
    from . import token_grants
    token_grants.forget("app", a.id, a.slug)  # API tokens granted it lose the grant
    db.session.delete(a)
    db.session.flush()
    gone = []
    for slug in own:
        st = SS.get(slug)
        # still unused once this app is gone (used_by reads the table), and
        # never a template's
        if st is not None and not used_by("store", slug) and not EX.is_template("store", slug):
            StudioRow.query.filter_by(store_id=st.id).delete(synchronize_session=False)
            db.session.delete(st)
            gone.append(slug)
    db.session.commit()
    return {"runs": runs, "stores": gone, "shared": shared}


# --------------------------------------------------------------------------- #
#  who, where                                                                  #
# --------------------------------------------------------------------------- #
def group_ids_of(user) -> set:
    uid = getattr(user, "id", None)
    if uid is None:
        return set()
    rows = db.session.query(user_group_members.c.group_id).filter(
        user_group_members.c.user_id == uid).all()
    return {r[0] for r in rows}


def is_author(user) -> bool:
    try:
        return bool(user is not None and user.is_authenticated and user.can(AUTHOR))
    except Exception:  # noqa: BLE001
        return False


def can_use(user, a: StudioApp) -> bool:
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if is_author(user):
        return True
    acc = a.access
    if user.id in acc["users"]:
        return True
    return bool(group_ids_of(user) & set(acc["groups"]))


def shown_in(a: StudioApp, product_key: str) -> bool:
    adoms = a.adoms
    return "*" in adoms or (product_key or "global") in adoms


def menu(user, product_key: str) -> list[dict]:
    """The enabled, published apps *user* may open in this ADOM, for the
    sidebar and the Plugins page: flow apps by their ADOMs and access list,
    script apps (Global only, like scripts always were) by the script's
    audience (script_schedules.can_run) and operations.scripts_run, the key
    of their run page. ``endpoint`` / ``target`` build the link."""
    if user is None or not getattr(user, "is_authenticated", False):
        return []
    try:
        adopt_scripts()
    except Exception:  # noqa: BLE001 -- a read-only standby cannot write; list what is there
        db.session.rollback()
    out = []
    for a in StudioApp.query.filter_by(enabled=True).order_by(StudioApp.name).all():
        if a.kind == "script":
            if (product_key or "global") != "global" or not user.can("operations.scripts_run"):
                continue
            from . import script_schedules as SSch
            meta = script_meta(a)
            if SSch.can_run(user, meta):
                out.append({"slug": a.slug, "name": meta.get("name") or a.name,
                            "description": meta.get("description") or "",
                            "icon": a.icon, "kind": "script",
                            "endpoint": "scripts.run_page", "target": a.script_slug})
        elif a.status == "published" and a.published and shown_in(a, product_key) \
                and can_use(user, a):
            out.append({"slug": a.slug, "name": a.name, "description": a.description or "",
                        "icon": a.icon, "kind": "flow",
                        "endpoint": "apps.page", "target": a.slug})
    # by name as people read it: the database's order puts "Zeta" before "alpha"
    return sorted(out, key=lambda m: m["name"].lower())


# --------------------------------------------------------------------------- #
#  runs                                                                        #
# --------------------------------------------------------------------------- #
def definition(a: StudioApp, draft: bool) -> dict:
    if draft:
        return {"version": 0, "fields": a.fields, "graph": a.graph, "actions": a.actions,
                "design": a.design}
    pub = a.published
    if not pub:
        raise AppError("%s is not published" % a.slug)
    return pub


def _running_query():
    since = datetime.utcnow() - timedelta(seconds=F.RUN_TIMEOUT + 120)
    return StudioAppRun.query.filter(StudioAppRun.status == "running",
                                     StudioAppRun.started_at >= since)


def _room_for_run(username: str) -> None:
    mine = _running_query().filter(StudioAppRun.user == username).count()
    if mine >= MAX_RUNS_PER_USER:
        raise AppError("you already have %d app runs in progress; wait for one to finish"
                       % mine)
    total = _running_query().count()
    if total >= MAX_RUNS_TOTAL:
        raise AppError("%d app runs are in progress on this node; try again in a moment"
                       % total)


def _prune_runs() -> None:
    cutoff = datetime.utcnow() - timedelta(days=RUN_KEEP_DAYS)
    StudioAppRun.query.filter(StudioAppRun.started_at < cutoff,
                              StudioAppRun.status != "running").delete(synchronize_session=False)


def start_run(a: StudioApp, *, user, product: str, raw_inputs, draft: bool = False,
              armed: bool = True, rehearsal: bool = False, inline: bool = False,
              event: dict | None = None) -> StudioAppRun:
    """Start a run. ``rehearsal`` forces even a published version to record
    its writes instead of executing them (an event automation that is not
    armed). ``inline`` runs in the caller's thread -- the event automation's
    job worker, which is already off the request. ``event`` is the payload of
    the event that started the run, ``{{ event }}`` in the diagram."""
    if not draft and not a.enabled:
        raise AppError("%s is disabled" % a.slug)
    if a.kind == "script":
        raise AppError("%s is a script app: it runs from its own page" % a.slug)
    d = definition(a, draft)
    _room_for_run(getattr(user, "username", ""))
    _prune_runs()
    fields = d.get("fields") or []
    inputs = resolve_inputs(fields, raw_inputs)
    run = StudioAppRun(app_id=a.id, version=d.get("version") or 0,
                       armed=bool(armed or not draft) and not rehearsal,
                       user=getattr(user, "username", ""), product=product or "",
                       inputs_json=json.dumps(shown_inputs(fields, inputs), default=str))
    db.session.add(run)
    db.session.commit()
    passwords = [str(inputs[f["name"]]) for f in fields
                 if f["type"] == "password" and inputs.get(f["name"])]
    if RUN_INLINE or inline:
        execute(run.id, getattr(user, "id", None), inputs, d, passwords, event=event)
        db.session.refresh(run)
    else:
        from flask import current_app
        flask_app = current_app._get_current_object()
        threading.Thread(target=_bg, args=(flask_app, run.id, getattr(user, "id", None),
                                           inputs, d, passwords, event),
                         name="studio-app-run-%d" % run.id, daemon=True).start()
    return run


def _bg(flask_app, run_id, user_id, inputs, d, passwords, event=None):
    with flask_app.app_context():
        try:
            execute(run_id, user_id, inputs, d, passwords, event=event)
        finally:
            db.session.remove()


def _spellings(secrets) -> list[str]:
    """Each password as typed and as the usual filters write it (urlencode,
    tojson, base64), longest first: ``{{ form.pw | urlencode }}`` copied
    into an output must not show it either."""
    out = set()
    for s_ in secrets:
        if not s_:
            continue
        out.update({s_, quote(s_, safe=""), quote(s_, safe="/"), quote_plus(s_),
                    json.dumps(s_)[1:-1], base64.b64encode(s_.encode()).decode()})
    return sorted((x for x in out if len(x) >= 3), key=len, reverse=True)


def _mask(obj, secrets):
    if not secrets:
        return obj
    if isinstance(obj, str):
        for s in secrets:
            obj = obj.replace(s, "********")
        return obj
    if isinstance(obj, list):
        return [_mask(x, secrets) for x in obj]
    if isinstance(obj, dict):
        return {k: _mask(v, secrets) for k, v in obj.items()}
    return obj


def _capped(obj) -> str:
    s = json.dumps(obj, default=str)
    if len(s) > RUN_VARS_CAP:
        return json.dumps({"_truncated": "larger than %d KiB" % (RUN_VARS_CAP // 1024)})
    return s


def execute(run_id: int, user_id, inputs: dict, d: dict, passwords=(),
            event: dict | None = None) -> None:
    from ..models import User
    run = db.session.get(StudioAppRun, run_id)
    if run is None:
        return
    user_obj = db.session.get(User, user_id) if user_id else None
    ctx = F.Ctx(form=inputs, armed=run.armed, user=run.user, user_obj=user_obj, run_id=run.id)
    if event is not None:
        ctx.vars["event"] = event
    secrets = _spellings([p for p in passwords if len(p) >= 3])
    job_id = _job_for(run, d)
    total = max(1, len((d.get("graph") or {}).get("nodes") or []))

    def persist(steps, c):
        run.steps_json = json.dumps(_mask(steps, secrets), default=str)
        run.outputs_json = json.dumps(_mask(c.outputs, secrets), default=str)
        run.vars_json = _capped(_mask(c.vars, secrets))
        db.session.commit()
        if job_id and steps:
            last = _mask(steps[-1], secrets)
            _job_step(job_id, min(95, int(100 * len(steps) / total)), last)

    try:
        res = F.walk(d.get("graph") or {}, ctx, on_step=persist)
    except Exception as exc:  # noqa: BLE001 -- never leave a run "running" forever
        db.session.rollback()
        res = {"status": "failed", "error": "internal error: %s" % exc, "steps": run.steps}
    run.status = res["status"]
    run.error = _mask(res.get("error") or "", secrets)[:4000]
    run.steps_json = json.dumps(_mask(res.get("steps") or [], secrets), default=str)
    run.outputs_json = json.dumps(_mask(ctx.outputs, secrets), default=str)
    run.vars_json = _capped(_mask(ctx.vars, secrets))
    run.finished_at = datetime.utcnow()
    db.session.commit()
    if job_id:
        _job_end(job_id, run)


def _job_for(run: StudioAppRun, d: dict) -> str:
    """An ARMED run whose diagram writes is also a job (Jobs page and the
    global toast), so a change made from an app is followed where every other
    change is -- with one log line per step: where it failed, and why. A
    read-only run or a rehearsal changes nothing and stays a run record."""
    graph = d.get("graph") or {}
    if not run.armed or not any(F.step_writes(n) for n in graph.get("nodes") or []):
        return ""
    try:
        from . import jobs
        a = db.session.get(StudioApp, run.app_id)
        job = jobs.create_job("studio_app", "%s — run #%d" % (a.name if a else "app", run.id),
                              by=run.user, cancelable=False,
                              meta={"app": a.slug if a else "", "run_id": run.id,
                                    "url": "/apps/runs/%d" % run.id, "steps": []})
        jobs.update_job(job["id"], status="running")
        return job["id"]
    except Exception:  # noqa: BLE001 -- the run itself must not depend on the job store
        return ""


def _job_step(job_id: str, pct: int, step: dict) -> None:
    try:
        from . import jobs
        line = "%s: %s%s" % (step.get("label") or step.get("key"), step.get("outcome"),
                             (" — " + str(step.get("detail"))[:300]) if step.get("detail") else "")

        def add(stt):
            # The Jobs page draws meta.steps as the job's step list.
            stt.setdefault("meta", {}).setdefault("steps", []).append(
                {"key": step.get("key"), "label": line[:500], "outcome": step.get("outcome"),
                 "ok": step.get("outcome") != "error", "ms": step.get("ms"),
                 "at": datetime.utcnow().isoformat(timespec="seconds"),
                 "detail": str(step.get("detail") or "")[:2000]})
        jobs.mutate_job(job_id, add)
        jobs.set_progress(job_id, pct, line)
    except Exception:  # noqa: BLE001
        pass


def _job_end(job_id: str, run: StudioAppRun) -> None:
    try:
        from . import jobs
        if run.status == "done":
            jobs.finish_success(job_id, message="run #%d done" % run.id,
                                result={"run_id": run.id, "outputs": len(run.outputs)})
        else:
            jobs.finish_error(job_id, run.error or "run #%d failed" % run.id)
    except Exception:  # noqa: BLE001
        pass


def refresh_stale(run: StudioAppRun) -> StudioAppRun:
    """A run still "running" long after the run limit died with its worker
    (a service restart): say so instead of spinning forever."""
    if run.status == "running" and run.started_at and \
            datetime.utcnow() - run.started_at > timedelta(seconds=F.RUN_TIMEOUT + 120):
        run.status = "failed"
        run.error = "interrupted: the worker running it stopped (service restart?)"
        run.finished_at = datetime.utcnow()
        db.session.commit()
    return run


def may_see_run(user, run: StudioAppRun) -> bool:
    return is_author(user) or (getattr(user, "username", None) == run.user)


def run_json(run: StudioAppRun, a: StudioApp, user) -> dict:
    author = is_author(user)
    d = {"id": run.id, "status": run.status, "error": run.error, "version": run.version,
         "armed": run.armed, "user": run.user, "inputs": run.inputs, "outputs": run.outputs,
         "steps": run.steps if author else operator_steps(run.steps),
         "started_at": run.started_at.isoformat(timespec="seconds") + "Z",
         "finished_at": run.finished_at.isoformat(timespec="seconds") + "Z" if run.finished_at else None}
    if author:
        d["vars"] = run.vars
    d["layout"] = result_layout(a, run.version)
    if run.status == "done" and run.armed:
        try:
            acts = definition(a, run.version == 0).get("actions") or []
        except AppError:
            acts = []
        d["actions"] = [{"key": x["key"], "label": x["label"], "kind": x["kind"],
                         "confirm": x.get("confirm", False)} for x in acts]
    return d


def result_layout(a: StudioApp, version: int) -> str:
    """The designed result of the version a run used ("" = the standard
    one). A run of an older published version keeps the layout it was
    published with only while it is the current one: older snapshots are not
    kept, so it falls back to the current published design."""
    from . import studio_design as D
    try:
        d = definition(a, version == 0)
    except AppError:
        return ""
    design = d.get("design") or {}
    if D.is_empty(design, "result"):
        return ""
    try:
        return D.render_result(D.clean(design), graph=d.get("graph") or {}, app=a)
    except D.DesignError:
        return ""


def operator_steps(steps: list) -> list[dict]:
    """What a non-author sees of the steps: which ran, how they ended and how
    long they took. The detail of a step (a decision prints both values it
    compared, a query its row count) is the author's debugging view and can
    hold data the app never chose to OUTPUT (finding 2026-10-20). Kept: the
    message of a Fail step and of an action, which are written for the user."""
    out = []
    for st in steps or []:
        keep = st.get("kind") in ("fail", "action")
        out.append({"key": st.get("key"), "label": st.get("label"), "kind": st.get("kind"),
                    "outcome": st.get("outcome"), "ms": st.get("ms"),
                    "detail": st.get("detail", "") if keep else ""})
    return out


def recent_runs(a: StudioApp, user, limit: int = 15) -> list[StudioAppRun]:
    q = StudioAppRun.query.filter_by(app_id=a.id)
    if not is_author(user):
        q = q.filter_by(user=user.username)
    return q.order_by(StudioAppRun.id.desc()).limit(limit).all()


# --------------------------------------------------------------------------- #
#  actions on a finished run                                                   #
# --------------------------------------------------------------------------- #
def _action(a: StudioApp, run: StudioAppRun, key: str) -> dict:
    if run.status != "done":
        raise AppError("only a finished run can be acted on")
    if not run.armed:
        raise AppError("a rehearsal run has nothing real to act on")
    d = definition(a, run.version == 0)
    if run.version and int(d.get("version") or 0) != int(run.version):
        # The published version moved on: its actions are not the ones this
        # run was made for (a new action could act on an old output).
        raise AppError("this run used version %s and the app is now at version %s: "
                       "run it again to act on the output" % (run.version, d.get("version")))
    acts = d.get("actions") or []
    act = next((x for x in acts if x["key"] == key), None)
    if act is None:
        raise AppError("action %s does not exist in version %s" % (key, run.version or "draft"))
    if act["kind"] not in REPEATABLE_ACTIONS and any(
            st.get("key") == "action:" + key and st.get("outcome") == "ok" for st in run.steps):
        raise AppError("%s was already done for this run" % act["label"])
    return act


def _scope(run: StudioAppRun) -> dict:
    s = dict(run.vars)
    s.update({"form": run.inputs, "vars": run.vars, "outputs": run.outputs,
              "run": {"id": run.id, "user": run.user}})
    return s


def _r(value, scope):
    try:
        return F.render(value, scope)
    except F.FlowError as exc:
        raise AppError(str(exc)) from None


def _log_action(run: StudioAppRun, act: dict, ok: bool, detail: str) -> None:
    steps = run.steps
    steps.append({"key": "action:" + act["key"], "label": act["label"], "kind": "action",
                  "outcome": "ok" if ok else "error", "detail": detail[:2000], "ms": 0})
    run.steps_json = json.dumps(steps, default=str)
    db.session.commit()


def download(a: StudioApp, run: StudioAppRun, key: str) -> tuple[str, bytes, str]:
    """``(filename, body, mimetype)`` of a download action."""
    act = _action(a, run, key)
    if act["kind"] != "download":
        raise AppError("%s is not a download" % key)
    p = act["params"]
    value = _r(p.get("value") or "{{ outputs[0].value }}", _scope(run))
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(_r(p.get("filename") or "output", _scope(run))))[:80] or "output"
    if p.get("format") == "json":
        return name + ".json", json.dumps(value, indent=2, default=str).encode(), "application/json"
    from .csv_safe import spreadsheet_safe
    rows = value if isinstance(value, list) else [value]
    rows = [r if isinstance(r, dict) else {"value": r} for r in rows]
    cols = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([spreadsheet_safe(json.dumps(r.get(c), default=str) if isinstance(r.get(c), (dict, list))
                                     else ("" if r.get(c) is None else r.get(c))) for c in cols])
    _log_action(run, act, True, "downloaded %s (%d rows)" % (name, len(rows)))
    return name + ".csv", buf.getvalue().encode(), "text/csv"


def run_action(a: StudioApp, run: StudioAppRun, key: str, *, user, product: str) -> dict:
    """Every action but download. ``{ok, message, url?}``."""
    act = _action(a, run, key)
    p, scope = act["params"], _scope(run)
    kind = act["kind"]
    try:
        if kind == "save_store":
            from . import studio_store as SS
            st = SS.get(p.get("store") or "")
            if st is None:
                raise AppError("data store %s does not exist" % p.get("store"))
            rows = _r(p.get("rows") or "{{ outputs[0].value }}", scope)
            rows = rows if isinstance(rows, list) else [rows]
            if not all(isinstance(r, dict) for r in rows):
                raise AppError("the rows to save must be objects of column: value")
            keys = [k.strip() for k in (p.get("match") or "").split(",") if k.strip()]
            n = 0
            for r in rows:
                clean = {k: v for k, v in r.items() if not str(k).startswith("_")}
                if p.get("mode") == "upsert" and keys:
                    SS.upsert(st, {k: clean.get(k) for k in keys}, clean, run.user)
                else:
                    SS.insert(st, clean, run.user)
                n += 1
            msg = "%d row(s) saved to %s" % (n, st.name)
            _log_action(run, act, True, msg)
            return {"ok": True, "message": msg}
        if kind == "send":
            from . import studio_connections as SC
            c = SC.get(p.get("connection") or "")
            if c is None or c.kind != "http":
                raise AppError("connection %s does not exist" % p.get("connection"))
            body = _r(F.parse_json_param(p.get("body") or "", "Body"), scope)
            try:
                path = F.render_path(p.get("path") or "", scope)
            except F.FlowError as exc:
                raise AppError(str(exc)) from None
            r = SC.http_call(c, p.get("method") or "POST", str(path), body=body)
            msg = "%s answered HTTP %d" % (c.name, r["status"])
            _log_action(run, act, r["ok"], msg)
            return {"ok": r["ok"], "message": msg}
        if kind == "run_app":
            other = get(p.get("app") or "")
            if other is None or not other.published or other.status != "published":
                raise AppError("app %s is not published" % p.get("app"))
            if not can_use(user, other):
                raise AppError("you may not use the app %s" % other.name)
            raw = _r(F.parse_json_param(p.get("inputs") or "{}", "Its form values"), scope) or {}
            new = start_run(other, user=user, product=product, raw_inputs=raw)
            from flask import url_for
            _log_action(run, act, True, "started %s run #%d" % (other.slug, new.id))
            return {"ok": True, "message": "Started %s." % other.name,
                    "url": url_for("apps.run_page", rid=new.id)}
        if kind == "change_request":
            from ..views.change_requests import create_change_request
            devices = _r(p.get("devices") or "", scope)
            if isinstance(devices, str):
                devices = [x for x in re.split(r"[\s,]+", devices) if x]
            if not isinstance(devices, list):
                devices = [devices]
            title = str(_r(p.get("title") or "", scope))[:200]
            reason = str(_r(p.get("reason") or "", scope))
            reason += "\n\nRaised from the app %s (run #%d by %s)." % (a.name, run.id, run.user)
            cr, err = create_change_request({
                "title": title, "action": p.get("action") or "", "device_ids": devices,
                "risk": p.get("risk") or "medium", "reason": reason.strip(),
                "requested_by": run.user, "params": {"studio_app": a.slug, "studio_run": run.id}})
            if cr is None:
                raise AppError(err)
            from flask import url_for
            msg = "Change request %s raised as a draft: it needs approval before anything runs" % (cr.ref or cr.id)
            _log_action(run, act, True, msg)
            return {"ok": True, "message": msg, "url": url_for("change_requests.detail", id=cr.id)}
        raise AppError("%s is not run this way" % kind)
    except AppError as exc:
        _log_action(run, act, False, str(exc))
        raise
    except Exception as exc:  # noqa: BLE001 -- store/connection errors
        _log_action(run, act, False, str(exc))
        raise AppError(str(exc)) from None


# --------------------------------------------------------------------------- #
#  groups                                                                      #
# --------------------------------------------------------------------------- #
def save_group(group: UserGroup | None, name: str, description: str, member_ids) -> UserGroup:
    from ..models import User
    name = (name or "").strip()[:64]
    if not name:
        raise AppError("a group needs a name")
    clash = UserGroup.query.filter(UserGroup.name == name).first()
    if clash is not None and (group is None or clash.id != group.id):
        raise AppError("a group named %s already exists" % name)
    ids = sorted({int(x) for x in member_ids or [] if str(x).isdigit()})
    members = User.query.filter(User.id.in_(ids)).all() if ids else []
    if len(members) != len(ids):
        raise AppError("a member does not exist")
    if group is None:
        group = UserGroup(name=name)
        db.session.add(group)
    group.name = name
    group.description = (description or "").strip()[:2000]
    group.members = members
    db.session.commit()
    return group


def apps_using_group(gid: int) -> list[str]:
    return [a.slug for a in StudioApp.query.order_by(StudioApp.slug).all() if gid in a.access["groups"]]
