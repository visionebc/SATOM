"""Rehearse a package on this server without installing it (contract §5).

``POST /api/v1/builder/rehearse`` answers "what would this package do here?"
with nothing written:

* the package is checked first (``package_check.check``, ``builder`` policy);
  its problems are returned and nothing runs;
* a **view or widget** body is rendered in the plugin sandbox with this
  server's datasets, cut to the caller (``plugin_sandbox``), like the
  editor's preview;
* an **app**'s diagram is walked **unarmed** (``studio_flow.walk`` with an
  in-memory ``Ctx``: no ``StudioAppRun`` row, no job): write steps and script
  steps are recorded as *rehearsal: not executed*, reads run for real against
  the stores, connections and secrets that exist here. An object the package
  would create and that is not here yet is a problem -- the rehearsal does
  not invent it. *Ask a person* is answered by ``answers``: ``yes``, ``no``,
  or ``stop`` (the walk stops there and returns ``waiting`` with the prompt).
"""
from __future__ import annotations

import json
import threading
import time

from . import plugin_package as P

ANSWERS = ("yes", "no", "stop")
#: A rehearsal runs in the request thread: it gets far less time than a run.
TIMEOUT_S = 60
#: Rehearsals at once in one web worker process.
MAX_PARALLEL = 2
_SLOTS = threading.BoundedSemaphore(MAX_PARALLEL)
#: The most "Ask a person" steps one rehearsal answers before it stops.
MAX_ANSWERS = 20


class Busy(RuntimeError):
    pass


def _result(**kw) -> dict:
    out = {"ok": True, "status": "done", "steps": [], "outputs": [], "waiting": None,
           "error": "", "problems": []}
    out.update(kw)
    return out


def _missing(spec: dict, body: dict) -> list[dict]:
    """Objects the app names that are not on this server."""
    from . import script_library as SL
    from . import studio_apps as SA
    from . import studio_connections as SC
    from . import studio_store as SS
    graph, actions, fields = spec.get("graph") or {}, spec.get("actions") or [], \
        spec.get("fields") or []
    out = []
    for slug in sorted(SA._refs(graph, actions, fields, "store")):
        if SS.get(slug) is None:
            out.append(("store", "data store", slug))
    for slug in sorted(SA._refs(graph, actions, fields, "connection")):
        if SC.get(slug) is None:
            out.append(("connection", "connection", slug))
    for slug in sorted(SA._refs(graph, actions, fields, "script")):
        try:
            ok = bool(SL.get(slug))
        except Exception:  # noqa: BLE001 -- an unreadable script is a missing one
            ok = False
        if not ok:
            out.append(("script", "script", slug))
    return [{"where": "%ss[%s]" % (k, slug),
             "message": "%s %s is not on this server yet: import the package first"
             % (label, slug)} for k, label, slug in out]


def _render_view(pk: P.Package, inputs: dict) -> dict:
    from . import plugin_sandbox as sandbox
    keys = [k for k in pk.manifest.get("datasets") or [] if k in sandbox.DATASETS]
    data = sandbox.load_datasets(keys)
    pdefs = sandbox.clean_param_defs(pk.manifest.get("params") or [])
    params = sandbox.resolve_params(pdefs, inputs or {})
    html, err = sandbox.safe_render(pk.text("body.jinja"), data, params)

    class _P:  # what the frame builder reads off a Plugin row
        name = pk.manifest.get("name") or pk.slug
        css = pk.text("style.css")
        js = pk.text("script.js")
    from .plugin_frame import frame_document
    doc = frame_document(_P(), html, data, params)
    problems = [{"where": "body.jinja", "message": err}] if err else []
    return {"ok": not problems, "rendered": doc, "problems": problems}


def _walk(spec: dict, user, inputs: dict, answers: str) -> dict:
    from . import studio_apps as SA
    from . import studio_flow as F
    ch = SA.choices()
    try:
        fields = SA.clean_fields(spec.get("fields") or [], ch)
        values = SA.resolve_inputs(fields, inputs or {})
    except SA.AppError as exc:
        return _result(ok=False, status="failed", error=str(exc),
                       problems=[{"where": "app.fields", "message": str(exc)}])
    passwords = [str(values[f["name"]]) for f in fields
                 if f.get("type") == "password" and values.get(f["name"])]
    secrets = SA._spellings([p for p in passwords if len(p) >= 3])
    graph = spec.get("graph") or {}
    ctx = F.Ctx(form=values, armed=False, user=getattr(user, "username", "") or "",
                user_obj=user, run_id=0, scripts=False,
                deadline=time.time() + TIMEOUT_S)
    res = F.walk(graph, ctx)
    rounds = 0
    while res.get("status") == "waiting" and answers in ("yes", "no") \
            and rounds < MAX_ANSWERS:
        rounds += 1
        res = F.walk(graph, ctx, resume={"steps": res.get("steps") or [],
                                          "key": res.get("waiting"), "answer": answers,
                                          "note": "answered by the rehearsal"})
    waiting = None
    if res.get("status") == "waiting":
        key = res.get("waiting")
        node = next((n for n in graph.get("nodes") or [] if n.get("key") == key), {})
        step = next((s for s in reversed(res.get("steps") or []) if s.get("key") == key), {})
        waiting = {"key": key, "label": node.get("label") or key,
                   "prompt": step.get("detail") or ""}
    return _result(status=res.get("status") or "failed",
                   steps=SA._mask(res.get("steps") or [], secrets),
                   outputs=json.loads(json.dumps(SA._mask(ctx.outputs, secrets), default=str)),
                   waiting=SA._mask(waiting, secrets),
                   error=SA._mask(res.get("error") or "", secrets))


def rehearse(data: bytes, *, user, product: str, inputs=None, answers: str = "yes") -> dict:
    from . import builder_target as BT
    from . import package_check
    from .plugin_import import norm_problems
    if answers not in ANSWERS:
        answers = "yes"
    res = package_check.check(data, BT.snapshot(user, product), "builder") or {}
    problems = norm_problems(res.get("problems"))
    if problems or not res.get("ok", False):
        return _result(ok=False, status="failed", problems=problems,
                       error="the package has problems: nothing was run")
    try:
        pk = P.read_package(data, keys=P.trusted_keys_with_publishers(product))
    except P.PackageError as exc:
        return _result(ok=False, status="failed", error=str(exc),
                       problems=[{"where": "package", "message": str(exc)}])
    if not _SLOTS.acquire(blocking=False):
        raise Busy("%d rehearsals are running in this worker; try again in a moment"
                   % MAX_PARALLEL)
    try:
        if pk.kind in ("view", "widget"):
            return _render_view(pk, inputs or {})
        if pk.kind != "app":
            return _result(ok=False, status="failed", error="only apps, views and widgets "
                           "can be rehearsed",
                           problems=[{"where": "manifest",
                                      "message": "a %s package cannot be rehearsed" % pk.kind}])
        try:
            body = json.loads(pk.files[P.APP_FILE].decode("utf-8"))
        except (KeyError, UnicodeDecodeError, ValueError):
            body = {}
        spec = body.get("app") if isinstance(body.get("app"), dict) else {}
        missing = _missing(spec, body)
        if missing:
            return _result(ok=False, status="failed", problems=missing,
                           error="the package needs objects this server does not have yet")
        return _walk(spec, user, inputs or {}, answers)
    finally:
        _SLOTS.release()
