"""Python Studio > Apps -- the diagram: step kinds, validation and the walk.

An app's diagram is the same shape the Process editor draws (nodes with a
``kind`` and ``params``, arrows with a ``branch``), so the editor is
``static/js/process_editor.js`` with this module's kinds and branches. What a
step does is different: Process steps return a health verdict; app steps move
DATA. Each step reads the form (``form``) and the variables earlier steps
saved, and may save its own result under a name (``save_as``).

TEMPLATES
---------
Text parameters are Jinja templates rendered in an IMMUTABLE SANDBOX
(``jinja2.sandbox``) over ``form``, ``vars``, every variable by name and
``run``. An undefined name is an error (``StrictUndefined``); an optional
value is written ``{{ x | default('') }}``. A parameter that is exactly one expression (``{{ rows }}``) keeps the
value's type -- a list stays a list -- so a query result can feed a script or
an output without passing through text. JSON parameters are parsed first and
then each string inside is rendered the same way.

THE WALK
--------
One cursor, from the single ``start`` step. A step ends ``ok`` or ``error``
(a decision: ``yes`` or ``no``). The next step is the arrow whose branch is
that outcome; else the ``always`` arrow -- EXCEPT after an error: an error
follows only an ``error`` arrow, and with none the run fails there. Falling
through ``always`` after a failure is how a flow keeps going on data it never
got. A loop is allowed and bounded by :data:`MAX_STEPS`; the whole run by
:data:`RUN_TIMEOUT`.

REHEARSAL
---------
A test run from the editor may be a rehearsal: every step that WRITES (a data
store write, SQL with writes allowed, an API call that is not GET) is recorded
with what it would have done and not executed. Runs of a published app are
always real -- that is what publishing means.
"""
from __future__ import annotations

import contextvars
import json
import re
import time
from dataclasses import dataclass, field
from urllib.parse import quote

from jinja2 import StrictUndefined, TemplateError, Undefined
from jinja2.sandbox import ImmutableSandboxedEnvironment, SecurityError

MAX_STEPS = 200
RUN_TIMEOUT = 600
MAX_VALUE_BYTES = 1024 * 1024
BRANCHES = (
    {"key": "always", "label": "always", "color": "#5E6C84"},
    {"key": "ok", "label": "ok", "color": "#15692A"},
    {"key": "error", "label": "error", "color": "#8B1C2A"},
    {"key": "yes", "label": "yes", "color": "#15692A"},
    {"key": "no", "label": "no", "color": "#7A5700"},
)
BRANCH_KEYS = tuple(b["key"] for b in BRANCHES)
RESERVED_VARS = ("form", "vars", "run", "outputs", "event")
DECISION_OPS = ("equals", "not_equals", "contains", "greater", "less", "empty",
                "not_empty", "true")
OUTPUT_VIEWS = ("auto", "table", "list", "keyvalue", "text", "json")
STORE_MODES = ("insert", "update", "upsert", "delete")

#: Items every ``range()`` of ONE rendered value may produce together. The
#: sandbox caps a single range at 100 000; two nested loops are 10^10.
MAX_TEMPLATE_ITEMS = 1_000_000
_BUDGET: contextvars.ContextVar = contextvars.ContextVar("studio_flow_budget", default=None)


def _budget_range(*args):
    r = range(*args)
    if len(r) > 100_000:
        raise SecurityError("range() is limited to 100000 items")
    left = _BUDGET.get()
    if left is not None:
        left[0] -= len(r)
        if left[0] < 0:
            raise SecurityError("a template may iterate over at most %d items"
                                % MAX_TEMPLATE_ITEMS)
    return r


class _StudioEnv(ImmutableSandboxedEnvironment):
    """The sandbox with ``**`` and ``*`` checked. Jinja's sandbox leaves
    them alone, and its optimiser folds constants at COMPILE time, so
    ``{{ 9**9**9 }}`` froze a gunicorn worker (holding the GIL) and
    ``{{ 'a' * 10**9 }}`` filled its memory before any run limit applied.
    Intercepted operators are never constant-folded."""
    intercepted_binops = frozenset({"**", "*"})

    def call_binop(self, context, operator, left, right):
        if operator == "**":
            if _number(right) and abs(right) > 64 and _number(left) and abs(left) not in (0, 1):
                raise SecurityError("an exponent above 64 is refused")
            return left ** right
        if operator == "*":
            for seq, n in ((left, right), (right, left)):
                if isinstance(seq, (str, list, tuple)) and _number(n) and \
                        len(seq) * max(int(n), 0) > MAX_VALUE_BYTES:
                    raise SecurityError("the result would be longer than %d"
                                        % MAX_VALUE_BYTES)
            return left * right
        return super().call_binop(context, operator, left, right)


def _number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _env(**kw) -> _StudioEnv:
    e = _StudioEnv(autoescape=False, undefined=StrictUndefined, **kw)
    e.filters["tojson"] = lambda v: json.dumps(v, default=str)
    e.globals["range"] = _budget_range
    return e


#: StrictUndefined: a misspelt {{ form.hots }} is an error the author sees,
#: not an empty string written into a data store. Optional values use
#: {{ x | default('') }}.
_ENV = _env()
#: For URL paths: every value a template puts in is percent-encoded, slash
#: included, so a form value such as ``1?admin=1`` or ``../../users`` stays
#: one path segment instead of becoming a query or a climb (finding
#: 2026-10-20). The literal text the author wrote is not touched.
_PATH_ENV = _env(finalize=lambda v: quote(str(v), safe=""))
_ONE_EXPR = re.compile(r"^\s*\{\{(.+?)\}\}\s*$", re.S)
_VAR_RE = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")
_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class FlowError(Exception):
    pass


# --------------------------------------------------------------------------- #
#  templates                                                                   #
# --------------------------------------------------------------------------- #
def _text(env, value: str, scope: dict) -> str:
    """Rendered piece by piece, stopping at MAX_VALUE_BYTES: a loop that
    writes a lot fails here instead of filling the worker's memory."""
    out, n = [], 0
    for chunk in env.from_string(value).generate(**scope):
        n += len(chunk)
        if n > MAX_VALUE_BYTES:
            raise FlowError("the rendered text is longer than %d KiB" % (MAX_VALUE_BYTES // 1024))
        out.append(chunk)
    return "".join(out)


def render_path(value, scope: dict):
    """A URL path template: like :func:`render`, but always text, with every
    inserted value percent-encoded (see ``_PATH_ENV``)."""
    if not isinstance(value, str) or ("{{" not in value and "{%" not in value):
        return value
    token = _BUDGET.set([MAX_TEMPLATE_ITEMS])
    try:
        return _text(_PATH_ENV, value, scope)
    except FlowError:
        raise
    except SecurityError as exc:
        raise FlowError("template refused by the sandbox: %s" % exc) from None
    except Exception as exc:  # noqa: BLE001
        raise FlowError("template error in %r: %s" % (value[:80], exc)) from None
    finally:
        _BUDGET.reset(token)


def render(value, scope: dict):
    """*value* with every template rendered against *scope*. See module doc."""
    if isinstance(value, str):
        if "{{" not in value and "{%" not in value:
            return value
        token = _BUDGET.set([MAX_TEMPLATE_ITEMS])
        try:
            m = _ONE_EXPR.match(value)
            if m and "{{" not in m.group(1) and "}}" not in m.group(1):
                rv = _ENV.compile_expression(m.group(1).strip(), undefined_to_none=False)(**scope)
                if isinstance(rv, Undefined):
                    raise FlowError("%s is not defined" % m.group(1).strip())
                return rv
            return _text(_ENV, value, scope)
        except FlowError:
            raise
        except SecurityError as exc:
            raise FlowError("template refused by the sandbox: %s" % exc) from None
        except TemplateError as exc:
            raise FlowError("template error in %r: %s" % (value[:80], exc)) from None
        except Exception as exc:  # noqa: BLE001 -- e.g. a ZeroDivisionError in an expression
            raise FlowError("template error in %r: %s" % (value[:80], exc)) from None
        finally:
            _BUDGET.reset(token)
    if isinstance(value, list):
        return [render(v, scope) for v in value]
    if isinstance(value, dict):
        return {str(render(k, scope)): render(v, scope) for k, v in value.items()}
    return value


def parse_json_param(text, what: str):
    if text is None or (isinstance(text, str) and not text.strip()):
        return None
    if not isinstance(text, str):
        return text
    try:
        return json.loads(text)
    except ValueError as exc:
        raise FlowError("%s is not valid JSON: %s" % (what, exc)) from None


def _size_ok(value) -> None:
    try:
        n = len(json.dumps(value, default=str))
    except (TypeError, ValueError):
        raise FlowError("the value cannot be stored as JSON") from None
    if n > MAX_VALUE_BYTES:
        raise FlowError("the value is larger than %d KiB" % (MAX_VALUE_BYTES // 1024))


# --------------------------------------------------------------------------- #
#  kinds                                                                       #
# --------------------------------------------------------------------------- #
@dataclass
class Param:
    name: str
    label: str
    kind: str = "text"              # text | textarea | select | json
    required: bool = False
    choices: tuple = ()
    default: str = ""
    help: str = ""


@dataclass
class Kind:
    key: str
    label: str
    group: str                      # flow | data | act
    summary: str
    params: list = field(default_factory=list)
    writes: bool = False
    #: Anything else the editor needs (api_call: the pinned connections'
    #: endpoint lists, for the endpoint picker).
    extra: dict = field(default_factory=dict)


def _save_as(default):
    return Param("save_as", "Save the result as", default=default,
                 help="A variable name later steps read as {{ %s }}." % default)


def kinds(choices: dict | None = None) -> list[Kind]:
    """The step kinds; *choices* fills the pickers ({"scripts": [...], ...})."""
    ch = choices or {}
    return [
        Kind("start", "Start", "flow", "Where the run begins. The form values are {{ form.<field> }}."),
        Kind("end", "End", "flow", "The run ends here."),
        Kind("set", "Set a variable", "flow", "Save a value (a template) under a name.",
             [Param("name", "Variable", required=True), Param("value", "Value", "textarea",
                                                               help="Text, or {{ expression }} to keep its type.")]),
        Kind("decision", "Decision", "flow", "Compare two values; continue on the yes or no arrow.",
             [Param("left", "Value", required=True, help="e.g. {{ form.env }}"),
              Param("op", "Test", "select", choices=DECISION_OPS, default="equals"),
              Param("right", "Compared with")]),
        Kind("fail", "Fail", "flow", "Stop the run as failed, with a message the user sees.",
             [Param("message", "Message", required=True)]),
        Kind("output", "Output", "flow", "Show a value to the user when the run ends.",
             [Param("value", "Value", required=True, help="e.g. {{ rows }}"),
              Param("title", "Title"),
              Param("view", "Show as", "select", choices=OUTPUT_VIEWS, default="auto")]),
        Kind("store_query", "Read a data store", "data", "Rows of a data store that match a filter.",
             [Param("store", "Data store", "select", True, tuple(ch.get("stores", ()))),
              Param("filter", "Filter (JSON)", "json",
                    help='{"column": "value"} or {"age": {"op": "gt", "value": 18}}'),
              Param("order_by", "Order by column"), Param("limit", "Row limit", default="500"),
              _save_as("rows")]),
        Kind("store_write", "Write a data store", "data", "Insert, update, upsert or delete rows.",
             [Param("store", "Data store", "select", True, tuple(ch.get("stores", ()))),
              Param("mode", "Mode", "select", choices=STORE_MODES, default="insert"),
              Param("match", "Match (JSON)", "json", help="Which rows, for update / upsert / delete."),
              Param("values", "Values (JSON)", "json", help='{"column": "{{ form.field }}"}'),
              _save_as("written")], writes=True),
        Kind("sql_query", "Query a database", "data", "SQL against a PostgreSQL connection, %(name)s parameters.",
             [Param("connection", "Connection", "select", True, tuple(ch.get("pg", ()))),
              Param("sql", "SQL", "textarea", True), Param("params", "Parameters (JSON)", "json"),
              Param("allow_writes", "Allow writes", "select", choices=("no", "yes"), default="no",
                    help="No: the query runs in a READ ONLY transaction."),
              _save_as("rows")], writes=True),
        Kind("api_call", "Call an API", "act", "A request to an HTTP connection.",
             [Param("connection", "Connection", "select", True, tuple(ch.get("http", ()))),
              Param("operation", "Endpoint (API Catalog)",
                    help="For a connection pinned to an API version: the endpoint id. "
                         "It sets the method and the path; leave empty to type them."),
              Param("path_params", "Path parameters (JSON)", "json",
                    help='For an endpoint: {"id": "{{ form.id }}"}'),
              Param("method", "Method", "select", choices=("GET", "POST", "PUT", "PATCH", "DELETE"),
                    default="GET"),
              Param("path", "Path", help="Under the base URL, e.g. /tickets/{{ form.id }}"),
              Param("query", "Query string (JSON)", "json"), Param("body", "Body (JSON)", "json"),
              Param("extract", "Keep only (JSON path)", help="e.g. items[*].name"),
              _save_as("response")], writes=True,
             extra={"catalog": dict(ch.get("catalog") or {})}),
        Kind("script", "Run a script", "act", "The published version of a Script Library script.",
             [Param("script", "Script", "select", True, tuple(ch.get("scripts", ()))),
              Param("inputs", "Form values (JSON)", "json", help='{"field": "{{ form.x }}"}'),
              _save_as("script")]),
        # A device runbook inside a data flow (2026-10-22): an app can call an
        # API, run a script AND walk a Process, so one diagram orchestrates
        # all three. A rehearsal run walks the process unarmed (its write
        # steps dry-run); an armed one walks it armed only for a user who
        # holds config_write -- running an app must not be a way around the
        # permission every other armed walk asks for.
        Kind("process", "Walk a process", "act",
             "Walk a Process (Administrator › Process) and continue on its verdict.",
             [Param("process", "Process", "select", True, tuple(ch.get("processes", ()))),
              Param("appliance", "Appliance (id or name)",
                    help="e.g. {{ form.device }} or {{ event.appliance_id }}; empty for a "
                         "process that acts on no device."),
              _save_as("process")]),
    ] + _satom_kinds(ch)


def _satom_kinds(ch) -> list:
    """The SATOM steps (DDI, capacity, certificates, FortiWeb): their own
    module, because what they act on is SATOM's, not the diagram's."""
    from . import studio_satom as S
    return S.kinds(ch)


#: Palette colour per group (the fw-badge palette, readable on white).
GROUP_COLOURS = {"flow": "#3D4550", "data": "#4C2A85", "act": "#7A5700", "satom": "#EF5424"}


def kind_map(choices=None) -> dict:
    return {k.key: k for k in kinds(choices)}


def kinds_json(choices=None) -> list[dict]:
    return [{"key": k.key, "label": k.label, "group": k.group, "summary": k.summary,
             "writes": bool(k.writes), "colour": GROUP_COLOURS.get(k.group, "#3D4550"),
             "params": [p.__dict__ for p in k.params], **k.extra} for k in kinds(choices)]


def step_writes(node: dict) -> bool:
    p = node.get("params") or {}
    kind = node.get("kind")
    if kind == "store_write":
        return True
    from . import studio_satom as S
    if S.writes(kind):
        return True
    if kind == "sql_query":
        return p.get("allow_writes") == "yes"
    if kind == "api_call":
        if str(p.get("operation") or "").strip():
            return _operation_method(p) != "GET"
        return (p.get("method") or "GET").upper() != "GET"
    return False


def _operation_method(p: dict) -> str:
    """The method of an api_call step's catalog endpoint. Anything that
    cannot be resolved counts as a write, so a rehearsal never sends it."""
    try:
        from . import studio_api_spec as SP
        from . import studio_apis as SA
        from . import studio_connections as SC
        c = SC.get(str(p.get("connection") or ""))
        cat = SA.catalog_of(c) if c is not None else None
        op = SP.by_id(cat["operations"], str(p.get("operation")).strip()) if cat else None
        return op["method"] if op else "POST"
    except Exception:  # noqa: BLE001 -- unknown = treated as a write
        return "POST"


# --------------------------------------------------------------------------- #
#  validation                                                                  #
# --------------------------------------------------------------------------- #
def validate_graph(graph: dict, choices: dict | None = None) -> list[str]:
    """Every problem, not the first one."""
    errs = []
    if not isinstance(graph, dict):
        return ["the diagram is not an object"]
    nodes, edges = graph.get("nodes") or [], graph.get("edges") or []
    km = kind_map(choices)
    keys = set()
    for n in nodes:
        k = str(n.get("key") or "")
        if not _KEY_RE.match(k):
            errs.append("step key %r: lowercase letters, digits, - and _" % k)
        if k in keys:
            errs.append("step key %s is used twice" % k)
        keys.add(k)
        kind = km.get(n.get("kind"))
        if kind is None:
            errs.append("%s: unknown step kind %r" % (k, n.get("kind")))
            continue
        p = n.get("params") or {}
        for prm in kind.params:
            v = p.get(prm.name)
            if prm.required and (v is None or str(v).strip() == ""):
                errs.append("%s: %s is required" % (k, prm.label))
            if prm.kind == "select" and v not in (None, "") and prm.choices and v not in prm.choices:
                errs.append("%s: %s %r does not exist" % (k, prm.label, v))
            if prm.kind == "json" and v not in (None, ""):
                try:
                    parse_json_param(v, prm.label)
                except FlowError as exc:
                    errs.append("%s: %s" % (k, exc))
        if n.get("kind") == "api_call" and choices is not None:
            errs.extend(_catalog_problems(k, p, choices))
        target = p.get("name") if n.get("kind") == "set" else p.get("save_as")
        if target not in (None, ""):
            v = str(target)
            if not _VAR_RE.match(v) or v in RESERVED_VARS:
                errs.append("%s: %r is not a usable variable name" % (k, v))
    starts = [n for n in nodes if n.get("kind") == "start"]
    if len(starts) != 1:
        errs.append("a diagram needs exactly one Start step (it has %d)" % len(starts))
    seen = set()
    for e in edges:
        s, d, b = e.get("src"), e.get("dst"), e.get("branch") or "always"
        if s not in keys or d not in keys:
            errs.append("an arrow points at a step that does not exist (%s → %s)" % (s, d))
            continue
        if b not in BRANCH_KEYS:
            errs.append("%s → %s: unknown branch %r" % (s, d, b))
        if (s, b) in seen:
            errs.append("%s has two %s arrows" % (s, b))
        seen.add((s, b))
    by = {n.get("key"): n for n in nodes}
    for e in edges:
        src = by.get(e.get("src")) or {}
        b = e.get("branch") or "always"
        if src.get("kind") == "decision" and b in ("ok", "error"):
            errs.append("%s is a decision: its arrows are yes, no or always" % src.get("key"))
        if src.get("kind") not in ("decision", None) and b in ("yes", "no"):
            errs.append("%s: yes/no arrows leave a decision only" % src.get("key"))
        if src.get("kind") in ("end", "fail"):
            errs.append("%s ends the run: it cannot have arrows" % src.get("key"))
    return errs


def _catalog_problems(key: str, p: dict, choices: dict) -> list[str]:
    """An api_call step against a connection pinned to an API Catalog version
    calls an endpoint of that version, or it is a problem (FA-0006)."""
    from . import studio_apis as SA
    conn = str(p.get("connection") or "")
    cat = (choices.get("catalog") or {}).get(conn)
    if cat is None:
        if str(p.get("operation") or "").strip() and conn in (choices.get("http") or ()):
            return ["%s: connection %s is not pinned to an API Catalog version, so it has "
                    "no endpoint %s" % (key, conn, p.get("operation"))]
        return []
    miss = SA.endpoint_problem(cat["ops"], p)
    if not miss:
        return []
    return ["%s: %s in API %s %s (connection %s)" % (key, miss, cat["api"], cat["version"], conn)]


def references(graph: dict) -> dict:
    """{"stores": {...}, "connections": {...}, "scripts": {...}} named by the diagram."""
    out = {"stores": set(), "connections": set(), "scripts": set(), "processes": set()}
    for n in (graph or {}).get("nodes") or []:
        p = n.get("params") or {}
        if n.get("kind") == "process" and p.get("process"):
            out["processes"].add(p["process"])
        if p.get("store"):
            out["stores"].add(p["store"])
        if p.get("connection"):
            out["connections"].add(p["connection"])
        if p.get("script"):
            out["scripts"].add(p["script"])
    return out


# --------------------------------------------------------------------------- #
#  the walk                                                                    #
# --------------------------------------------------------------------------- #
@dataclass
class Ctx:
    form: dict
    vars: dict = field(default_factory=dict)
    outputs: list = field(default_factory=list)
    armed: bool = True
    user: str = ""
    user_obj: object = None
    run_id: int = 0
    deadline: float = 0.0

    def scope(self) -> dict:
        s = dict(self.vars)
        s.update({"form": self.form, "vars": self.vars, "outputs": self.outputs,
                  "run": {"id": self.run_id, "user": self.user}})
        return s


def _p(node, name, default=""):
    v = (node.get("params") or {}).get(name)
    return default if v is None else v


def _json(node, ctx, name, what):
    return render(parse_json_param(_p(node, name, None), what), ctx.scope())


def _compare(left, op, right) -> bool:
    if op == "empty":
        return left in (None, "", [], {})
    if op == "not_empty":
        return left not in (None, "", [], {})
    if op == "true":
        return bool(left) and str(left).strip().lower() not in ("0", "false", "no", "off")
    if op == "contains":
        if isinstance(left, (list, tuple, dict)):
            return right in left or str(right) in [str(x) for x in left]
        return str(right) in str(left if left is not None else "")
    if op in ("greater", "less"):
        try:
            a, b = float(left), float(right)
        except (TypeError, ValueError):
            a, b = str(left), str(right)
        return a > b if op == "greater" else a < b
    same = left == right or (left is not None and right is not None and str(left) == str(right))
    return same if op == "equals" else not same


def _store(node):
    from . import studio_store as SS
    st = SS.get(str(_p(node, "store")))
    if st is None:
        raise FlowError("data store %r does not exist" % _p(node, "store"))
    return st


def _connection(node, kind):
    from . import studio_connections as SC
    c = SC.get(str(_p(node, "connection")))
    if c is None or c.kind != kind:
        raise FlowError("%s connection %r does not exist" % (kind, _p(node, "connection")))
    return c


def _run_step(node: dict, ctx: Ctx):
    """``(outcome, value, detail)``. Raises FlowError for an error outcome."""
    kind = node.get("kind")
    scope = ctx.scope()
    if kind in ("start", "end"):
        return "ok", None, ""
    if kind == "set":
        return "ok", render(_p(node, "value"), scope), ""
    if kind == "decision":
        left = render(_p(node, "left"), scope)
        right = render(_p(node, "right"), scope)
        op = _p(node, "op", "equals") or "equals"
        res = _compare(left, op, right)
        return ("yes" if res else "no"), None, "%r %s %r → %s" % (left, op, right, "yes" if res else "no")
    if kind == "fail":
        raise FlowError(str(render(_p(node, "message"), scope)))
    if kind == "output":
        value = render(_p(node, "value"), scope)
        _size_ok(value)
        ctx.outputs.append({"title": str(render(_p(node, "title"), scope) or ""),
                            "view": _p(node, "view", "auto") or "auto", "value": value})
        return "ok", None, ""
    if not ctx.armed and step_writes(node):
        from . import studio_satom as S
        if kind in S.KIND_KEYS:
            return S.rehearse(node, ctx)
        plan = {k: v for k, v in (node.get("params") or {}).items() if k != "save_as"}
        return "ok", {"rehearsal": True, "would": render(plan, scope)}, "rehearsal: not executed"
    if kind == "store_query":
        from . import studio_store as SS
        st = _store(node)
        try:
            rows = SS.query(st, _json(node, ctx, "filter", "Filter") or {},
                            limit=int(_p(node, "limit", "500") or 500),
                            order_by=str(render(_p(node, "order_by"), scope) or ""))
        except (SS.StoreError, ValueError) as exc:
            raise FlowError(str(exc)) from None
        return "ok", rows, "%d row(s)" % len(rows)
    if kind == "store_write":
        from . import studio_store as SS
        st = _store(node)
        mode = _p(node, "mode", "insert") or "insert"
        values = _json(node, ctx, "values", "Values") or {}
        match = _json(node, ctx, "match", "Match") or {}
        try:
            if mode == "insert":
                if isinstance(values, list):
                    res = [SS.insert(st, v, ctx.user) for v in values]
                else:
                    res = SS.insert(st, values, ctx.user)
            elif mode == "update":
                if not match:
                    raise FlowError("an update needs a match")
                res = [SS.update(st, r["_id"], values, ctx.user)
                       for r in SS.query(st, match, limit=SS.MAX_QUERY_LIMIT)]
            elif mode == "upsert":
                res = SS.upsert(st, match, values, ctx.user)
            elif mode == "delete":
                res = {"deleted": SS.delete_where(st, match)}
            else:
                raise FlowError("unknown mode %r" % mode)
        except SS.StoreError as exc:
            raise FlowError(str(exc)) from None
        return "ok", res, mode
    if kind == "sql_query":
        from . import studio_connections as SC
        c = _connection(node, "postgres")
        params = _json(node, ctx, "params", "Parameters") or {}
        if not isinstance(params, dict):
            raise FlowError("SQL parameters are an object of name: value")
        try:
            r = SC.pg_query(c, str(_p(node, "sql")), params,
                            write=_p(node, "allow_writes") == "yes")
        except SC.ConnectionError_ as exc:
            raise FlowError(str(exc)) from None
        return "ok", r["rows"], "%d row(s), %d ms" % (len(r["rows"]), r["ms"])
    if kind == "api_call":
        from . import studio_connections as SC
        c = _connection(node, "http")
        method, path = _endpoint(node, ctx, c)
        try:
            r = SC.http_call(c, method, path,
                             query=_json(node, ctx, "query", "Query string"),
                             body=_json(node, ctx, "body", "Body"))
        except SC.ConnectionError_ as exc:
            raise FlowError(str(exc)) from None
        body = r.get("json") if "json" in r else r.get("text")
        if not r["ok"]:
            ctx.vars["last_response"] = {"status": r["status"], "body": body}
            raise FlowError("HTTP %d from %s" % (r["status"], c.slug))
        ex = str(_p(node, "extract") or "")
        value = SC.json_path(body, ex) if ex else body
        return "ok", value, "HTTP %d, %d ms" % (r["status"], r["ms"])
    if kind == "script":
        return _run_script(node, ctx)
    if kind == "process":
        return _run_process(node, ctx)
    from . import studio_satom as S
    if kind in S.KIND_KEYS:
        return S.run(node, ctx)
    raise FlowError("unknown step kind %r" % kind)


def _run_process(node, ctx):
    """Walk a Process inline (the app run is already off the request). The
    result is ``{run_id, status, verdict, armed, counts}``; anything but an
    ``ok`` verdict -- or a run parked on a manual gate -- is an ``error``
    outcome, so the diagram decides what follows a red walk."""
    from ..models import Appliance, db
    from ..models_process import DONE, TRIGGER_EVENT, WAITING, Process
    from . import process_engine as engine
    from . import process_kinds as pk
    key = str(_p(node, "process"))
    proc = Process.query.filter_by(key=key).first()
    if proc is None or not proc.enabled:
        raise FlowError("process %r does not exist or is disabled" % key)
    graph = proc.graph()
    bad = pk.validate_graph(graph)
    if bad:
        raise FlowError("process %s cannot run: %s" % (key, bad[0]))
    raw = str(render(_p(node, "appliance"), ctx.scope()) or "").strip()
    appliance = None
    if raw:
        appliance = (db.session.get(Appliance, int(raw)) if raw.isdigit()
                     else Appliance.query.filter_by(name=raw).first())
        if appliance is None:
            raise FlowError("no appliance %r" % raw)
    if pk.needs_appliance(graph) and appliance is None:
        raise FlowError("process %s acts on a device: give the appliance" % key)
    user = ctx.user_obj
    may_arm = bool(user is not None and getattr(user, "can", None)
                   and user.can("config_write"))
    armed = bool(ctx.armed and may_arm and pk.writes(graph))
    run = engine.start_run(proc, appliance=appliance, armed=armed, trigger=TRIGGER_EVENT,
                           user=ctx.user or "app", product="",
                           trigger_key=("studio-app-run:%s" % ctx.run_id)[:200])
    c = run.counts()
    value = {"run_id": run.id, "status": run.status, "verdict": run.verdict,
             "armed": armed, "counts": c}
    detail = "%sprocess %s run #%d: %s (%d pass, %d fail, %d unknown)" % (
        "" if armed else "[rehearsal] ", key, run.id,
        "parked on a manual gate" if run.status == WAITING else (run.verdict or run.status),
        c["pass"], c["fail"], c["unknown"])
    if ctx.armed and pk.writes(graph) and not may_arm:
        detail += " -- walked unarmed: the user running the app lacks config_write"
    if run.status == DONE and run.verdict == "ok":
        return "ok", value, detail
    ctx.vars["last_process"] = value
    raise FlowError(detail)


def _endpoint(node, ctx, c) -> tuple[str, str]:
    """``(method, path)`` of an api_call step. With an endpoint id, both come
    from the connection's API Catalog version and the path parameters fill
    its ``{name}`` parts; without one, the typed method and path -- which,
    on a pinned connection, must still be an endpoint of that version."""
    from . import studio_api_spec as SP
    from . import studio_apis as SA
    cat = SA.catalog_of(c)
    oid = str(_p(node, "operation") or "").strip()
    where = "API %s %s (connection %s)" % (cat["api"], cat["version"], c.slug) if cat else ""
    if oid:
        if cat is None:
            raise FlowError("connection %s is not pinned to an API Catalog version, so it "
                            "has no endpoint %s" % (c.slug, oid))
        op = SP.by_id(cat["operations"], oid)
        if op is None:
            raise FlowError("endpoint %s is not in %s" % (oid, where))
        values = _json(node, ctx, "path_params", "Path parameters") or {}
        if not isinstance(values, dict):
            raise FlowError("path parameters are an object of name: value")
        try:
            return op["method"], SP.fill_path(op, values)
        except SP.SpecError as exc:
            raise FlowError(str(exc)) from None
    method = (_p(node, "method", "GET") or "GET").upper()
    path = str(render_path(_p(node, "path"), ctx.scope()) or "")
    if cat is not None and SP.find(cat["operations"], method, path) is None:
        raise FlowError("%s %s is not an endpoint of %s" % (method, path or "/", where))
    return method, path


#: Test seams: how a script step queues a run and reads its status.
def _enqueue_script(slug, version, inputs, ctx):
    from . import script_library as SL
    from . import script_vault as SV
    return SL.enqueue_run(slug, version_ref=str(version), raw_inputs=inputs, by=ctx.user,
                          trigger="app", node="", wrap=SV.wrap_for_run, user=ctx.user_obj)


def _script_status(rid):
    from . import script_library as SL
    return SL.run_status(rid)


SCRIPT_POLL_S = 1.0


def _run_script(node, ctx):
    from . import script_library as SL
    slug = str(_p(node, "script"))
    try:
        meta = SL.get(slug)
    except SL.ScriptError:
        meta = None
    if not meta or not meta.get("published"):
        raise FlowError("script %r has no published version" % slug)
    from . import studio_apps as SA
    if SA.script_disabled(slug):
        raise FlowError("script %r is disabled (Plugin Studio > Apps)" % slug)
    inputs = _json(node, ctx, "inputs", "Form values") or {}
    try:
        st = _enqueue_script(slug, meta["published"], inputs, ctx)
    except SL.ScriptError as exc:
        raise FlowError(str(exc)) from None
    rid = st["request_id"]
    wait_until = min(ctx.deadline or time.time() + RUN_TIMEOUT,
                     time.time() + int(meta.get("timeout") or 60) + 60)
    while True:
        cur = _script_status(rid) or {}
        status = cur.get("status")
        if status in ("ok", "failed", "timeout"):
            break
        if time.time() > wait_until:
            raise FlowError("script %s did not finish in time (still %s; is satom-scripts "
                            "running?)" % (slug, status or "queued"))
        time.sleep(SCRIPT_POLL_S)
    if status != "ok":
        ctx.vars["last_script"] = {"status": status, "output": (cur.get("output") or "")[-4000:],
                                   "error": cur.get("error") or ""}
        raise FlowError("script %s ended %s: %s" % (slug, status, (cur.get("error") or "")[:300]))
    res = cur.get("result")
    return "ok", res if res is not None else {"output": cur.get("output") or ""}, \
        "script %s v%s" % (slug, meta["published"])


def _next(edges, key, outcome):
    by = {(e.get("src"), e.get("branch") or "always"): e.get("dst") for e in edges}
    if (key, outcome) in by:
        return by[(key, outcome)]
    if outcome == "error":
        return None
    return by.get((key, "always"))


def walk(graph: dict, ctx: Ctx, on_step=None) -> dict:
    """Run the diagram. ``{status: done|failed, error, steps}``. *on_step*
    is called after every step (the caller persists progress)."""
    nodes = {n.get("key"): n for n in graph.get("nodes") or []}
    edges = graph.get("edges") or []
    start = [k for k, n in nodes.items() if n.get("kind") == "start"]
    if len(start) != 1:
        return {"status": "failed", "error": "the diagram has no single Start step", "steps": []}
    ctx.deadline = ctx.deadline or time.time() + RUN_TIMEOUT
    steps, key, count = [], start[0], 0
    status, error = "done", ""
    while key:
        count += 1
        if count > MAX_STEPS:
            status, error = "failed", "stopped after %d steps (a loop with no way out?)" % MAX_STEPS
            break
        if time.time() > ctx.deadline:
            status, error = "failed", "stopped: the run took longer than %d s" % RUN_TIMEOUT
            break
        node = nodes.get(key)
        if node is None:
            status, error = "failed", "an arrow points at missing step %s" % key
            break
        t0 = time.monotonic()
        try:
            outcome, value, detail = _run_step(node, ctx)
            p = node.get("params") or {}
            target = p.get("name") if node.get("kind") == "set" else p.get("save_as")
            if target and value is not None:
                if not _VAR_RE.match(str(target)) or target in RESERVED_VARS:
                    raise FlowError("%r is not a usable variable name" % target)
                _size_ok(value)
                ctx.vars[str(target)] = value
        except FlowError as exc:
            outcome, detail = "error", str(exc)
            ctx.vars["last_error"] = {"step": key, "message": detail}
        steps.append({"key": key, "label": node.get("label") or key, "kind": node.get("kind"),
                      "outcome": outcome, "detail": str(detail)[:2000],
                      "ms": int((time.monotonic() - t0) * 1000)})
        if on_step:
            on_step(steps, ctx)
        if node.get("kind") == "fail":
            status, error = "failed", detail
            break
        if node.get("kind") == "end":
            break
        nxt = _next(edges, key, outcome)
        if nxt is None and outcome == "error":
            status, error = "failed", "%s: %s" % (node.get("label") or key, detail)
            break
        key = nxt
    return {"status": status, "error": error, "steps": steps}


# --------------------------------------------------------------------------- #
#  analysis -- what the diagram does, and what a failure leaves behind         #
# --------------------------------------------------------------------------- #
_READ_RE = re.compile(r"\{\{-?\s*([a-z_][a-z0-9_]*)")
#: Names a template defines for itself ({% for r in ... %}, {% set x = ... %}).
_LOCAL_RE = re.compile(r"\{%-?\s*(?:for|set)\s+([a-z_][a-z0-9_]*)")
_UNDO_KINDS = ("ddi_release", "fortiweb_spo_remove")


def _reach(edges, start, branches=None) -> set:
    seen, todo = set(), [start]
    while todo:
        k = todo.pop()
        if k in seen:
            continue
        seen.add(k)
        for e in edges:
            if e.get("src") == k and (branches is None or (e.get("branch") or "always") in branches):
                todo.append(e.get("dst"))
    return seen


def analyze(graph: dict, choices: dict | None = None, fields=None) -> dict:
    """The diagram explained, step by step, for the person editing it.

    ``problems`` block publishing (``validate_graph``). ``warnings`` are what
    a run would do that the author probably did not mean: a step nobody
    reaches, a step that writes and has no ``error`` arrow AFTER another
    write (a failure there stops the run and leaves the earlier write in
    place), a variable read that no step saves, a decision with one way out.
    Each step says what it saves, what it reads, and where an error goes --
    for a write step, which undo steps (release / remove) that path reaches.
    """
    graph = graph if isinstance(graph, dict) else {}
    nodes = [n for n in graph.get("nodes") or [] if isinstance(n, dict)]
    edges = [e for e in graph.get("edges") or [] if isinstance(e, dict)]
    km = kind_map(choices)
    from . import studio_satom as S
    by = {n.get("key"): n for n in nodes}
    start = next((n.get("key") for n in nodes if n.get("kind") == "start"), None)
    reachable = _reach(edges, start) if start else set()
    form_names = {f.get("name") for f in fields or [] if isinstance(f, dict)}
    saved = set()
    for n in nodes:
        p = n.get("params") or {}
        t = p.get("name") if n.get("kind") == "set" else p.get("save_as")
        if t:
            saved.add(str(t))
    builtin = set(RESERVED_VARS) | {"last_error", "last_response", "last_script",
                                    "last_process", "range", "true", "false", "none"}
    writers = {n.get("key") for n in nodes if step_writes(n)}
    steps, warnings = [], []
    for n in nodes:
        k, p = n.get("key"), n.get("params") or {}
        kind = km.get(n.get("kind"))
        out = {(e.get("branch") or "always"): e.get("dst") for e in edges if e.get("src") == k}
        text = json.dumps(p, default=str)
        local = {m.group(1) for m in _LOCAL_RE.finditer(text)}
        reads = sorted({m.group(1) for m in _READ_RE.finditer(text)} - builtin - local)
        reads_form = sorted({m.group(1) for m in re.finditer(r"form\.([a-z_][a-z0-9_]*)", text)})
        w = step_writes(n)
        info = {"key": k, "label": n.get("label") or k, "kind": n.get("kind"),
                "kind_label": kind.label if kind else n.get("kind"),
                "writes": w, "device": n.get("kind") in S.DEVICE_KINDS,
                "saves": (p.get("name") if n.get("kind") == "set" else p.get("save_as")) or "",
                "reads": reads, "reads_form": reads_form, "next": out,
                "reachable": k in reachable}
        if n.get("kind") not in ("end", "fail", "decision"):
            if "error" in out:
                undo_path = _reach(edges, out["error"])
                info["on_error"] = "goes to %s" % (by.get(out["error"], {}).get("label") or out["error"])
                info["undo"] = sorted(by[x].get("label") or x for x in undo_path
                                      if x in by and by[x].get("kind") in _UNDO_KINDS)
            else:
                info["on_error"] = "stops the run as failed"
        steps.append(info)
        if start and k not in reachable:
            warnings.append("%s: no arrow leads here -- it never runs" % (n.get("label") or k))
        for v in reads:
            if v not in saved:
                warnings.append("%s reads {{ %s }}, which no step saves" % (n.get("label") or k, v))
        for v in reads_form:
            if fields is not None and v not in form_names:
                warnings.append("%s reads form.%s, which is not a field of the form"
                                % (n.get("label") or k, v))
        if n.get("kind") == "decision" and not ("yes" in out and "no" in out) and "always" not in out:
            warnings.append("%s: a decision needs a yes and a no arrow (or always)" % (n.get("label") or k))
        if w and "error" not in out and k in reachable:
            before = [x for x in writers if x != k and k in _reach(edges, x)]
            if before:
                warnings.append(
                    "%s writes and has no error arrow: if it fails the run stops, and what %s "
                    "wrote stays" % (n.get("label") or k,
                                     ", ".join(sorted(by[x].get("label") or x for x in before))))
    return {"problems": validate_graph(graph, choices), "warnings": sorted(set(warnings)),
            "steps": steps,
            "summary": {"steps": len(nodes), "writes": len(writers),
                        "device_writes": sum(1 for s in steps if s["device"]),
                        "error_arrows": sum(1 for e in edges if (e.get("branch") or "") == "error")}}
