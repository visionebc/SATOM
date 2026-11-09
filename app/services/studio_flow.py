"""Python Studio > Apps -- the diagram: step kinds, validation and the walk.

An app's diagram is nodes with a ``kind`` and ``params`` and arrows with a
``branch``; the editor is ``static/js/process_editor.js`` (named after the
Process section it was written for, removed 2026-10-25) with this module's
kinds and branches. Steps move DATA, look at appliances
(``studio_checks``) and ask people. Each step reads the form (``form``) and the variables earlier steps
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
#: One step value / Output. 8 MiB since 2026-11-09 (was 1 MiB): the DNS &
#: LB Lookup page as a plugin returns the page's whole result (~1.4 KB per LB
#: match measured on a1), and 1 MiB stopped a broad search the page draws.
MAX_VALUE_BYTES = 8 * 1024 * 1024
BRANCHES = (
    {"key": "always", "label": "always", "color": "#5E6C84"},
    {"key": "ok", "label": "ok", "color": "#15692A"},
    {"key": "error", "label": "error", "color": "#8B1C2A"},
    {"key": "yes", "label": "yes", "color": "#15692A"},
    {"key": "no", "label": "no", "color": "#7A5700"},
)
BRANCH_KEYS = tuple(b["key"] for b in BRANCHES)
#: Where a simulation keeps its scenario (the answers it still has to give).
SCENARIO_VAR = "_scenario"
RESERVED_VARS = ("form", "vars", "run", "outputs", "event", SCENARIO_VAR)
DECISION_OPS = ("equals", "not_equals", "contains", "greater", "less", "empty",
                "not_empty", "true")
#: ``plan``: a decommission plan (items, warnings, counts) -- the DNS & LB
#: Lookup page's confirmation view.
OUTPUT_VIEWS = ("auto", "table", "list", "keyvalue", "text", "json", "plan")
#: Buttons one Output row may carry (``row_actions``).
MAX_ROW_ACTIONS = 8
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


_INDEX = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*\]")


def _index_hint(expr: str, scope: dict) -> str:
    """Why ``items[i]`` found nothing, when it is the usual reason: the list
    is there and ``i`` is TEXT (a ``set`` step's literal ``"0"``)."""
    for name, idx in _INDEX.findall(expr or ""):
        seq, key = scope.get(name), scope.get(idx)
        if isinstance(seq, (list, tuple)) and isinstance(key, str):
            return (" (%s is the text %r, and a list is indexed by a number: start the "
                    "counter with a set step's value \"{{ 0 }}\", not \"0\", and grow it with "
                    "\"{{ %s + 1 }}\")" % (idx, key[:20], idx))
    return ""


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
                    raise FlowError("%s is not defined%s" % (m.group(1).strip(),
                                                            _index_hint(m.group(1), scope)))
                return rv
            return _text(_ENV, value, scope)
        except FlowError:
            raise
        except SecurityError as exc:
            raise FlowError("template refused by the sandbox: %s" % exc) from None
        except TemplateError as exc:
            # items[i].ip with a text i: "'list object' has no attribute '0'"
            raise FlowError("template error in %r: %s%s" % (value[:80], exc,
                                                          _index_hint(value, scope))) from None
        except Exception as exc:  # noqa: BLE001 -- e.g. a ZeroDivisionError in an expression
            raise FlowError("template error in %r: %s%s" % (value[:80], exc,
                                                          _index_hint(value, scope))) from None
        finally:
            _BUDGET.reset(token)
    if isinstance(value, list):
        return [render(v, scope) for v in value]
    if isinstance(value, dict):
        return {str(render(k, scope)): render(v, scope) for k, v in value.items()}
    return value


def one_expression(text) -> bool:
    """True for a parameter that is exactly ONE template expression
    (``{{ payload }}``): it is rendered whole and keeps the value's type."""
    if not isinstance(text, str):
        return False
    m = _ONE_EXPR.match(text)
    return bool(m) and "{{" not in m.group(1) and "}}" not in m.group(1)


def parse_json_param(text, what: str):
    if text is None or (isinstance(text, str) and not text.strip()):
        return None
    if not isinstance(text, str):
        return text
    if one_expression(text):
        # a whole JSON value built by an expression ({{ payload }}, or
        # {{ x | tojson }}): rendered later, see _json (2026-10-26: the
        # natural way to send a list or an object a set step built)
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
              Param("view", "Show as", "select", choices=OUTPUT_VIEWS, default="auto"),
              Param("row_actions", "Row buttons (JSON)", "json",
                    help='For a table: buttons on every row, {{ row }} being that row. '
                         '[{"label": "Edit", "app": "<app id>", "inputs": {"name": '
                         '"{{ row.name }}"}}, {"label": "Open", "url": "{{ row._url }}"}] -- '
                         'an app opens its form in a window over this page, filled in; a '
                         'url is a SATOM path. "when": "{{ row.x }}" shows a button only '
                         'where it is true. Columns starting with _ are not shown.'),
              Param("columns", "Columns",
                    help="For a table: the columns to show, in order, comma separated -- "
                         "key, or key=Label; a.b takes b from each item of the list a. A "
                         "list is shown joined by commas. Row buttons see every column. "
                         "Empty = every column.")]),
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
              Param("for_each", "For each (list)",
                    help="One request per item, {{ item }} being that item, e.g. "
                         "{{ dns.ptr }} with the path /hosts/{{ item.hostname }}. The answer "
                         "is a table: one row per item with its status, answer or error. "
                         "At most 50 items; empty = one request."),
              _save_as("response")], writes=True,
             extra={"catalog": dict(ch.get("catalog") or {})}),
        Kind("server_call", "Act on a server", "act",
             "One satom-webctl operation on a server connection: list or edit nginx/Apache "
             "virtual hosts, browse, read or change the files of a document root, manage "
             "the server's certificates (the private key is made on the server and never "
             "leaves it).",
             [Param("connection", "Connection", "select", True, tuple(ch.get("server", ()))),
              Param("operation", "Operation", "select", True, tuple(ch.get("server_ops", ())),
                    default="vhosts.list",
                    help="Reads: info, vhosts.list, vhost.get, files.list, files.read, "
                         "certs.list, cert.get. Writes (need Allow writes on the "
                         "connection): vhost.put, vhost.create, vhost.enable, vhost.disable, "
                         "vhost.delete, files.write, files.mkdir, files.rename, "
                         "files.delete, cert.csr, cert.install, cert.assign, cert.delete."),
              Param("args", "Arguments (JSON)", "json",
                    help='e.g. {"server": "nginx", "name": "{{ form.vhost }}", '
                         '"path": "{{ form.path }}"}'),
              _save_as("server")], writes=True),
        Kind("script", "Run a script", "act", "The published version of a Script Library script.",
             [Param("script", "Script", "select", True, tuple(ch.get("scripts", ()))),
              Param("inputs", "Form values (JSON)", "json", help='{"field": "{{ form.x }}"}'),
              _save_as("script")]),
    ] + _check_kinds() + _satom_kinds(ch)


def _check_kinds() -> list:
    """Runbook steps (checks, Ask a person, Activity): services.studio_checks."""
    from . import studio_checks as C
    return C.kinds()


#: Every step may carry the text of the procedure it comes from (a runbook is
#: a document first): shown on the run page and in the editor, never read by
#: the walk.
COMMON_PARAMS = (
    Param("doc", "Instructions", "textarea",
          help="The full text of this step: what the person does, the commands, "
               "what to expect. Shown on the run page."),
    Param("role", "Responsible", help="Who carries it out, e.g. Specialist."),
    Param("time", "Estimated time", help="Minutes, or free text."),
)


def _satom_kinds(ch) -> list:
    """The SATOM steps (DDI, capacity, certificates, FortiWeb): their own
    module, because what they act on is SATOM's, not the diagram's."""
    from . import studio_satom as S
    return S.kinds(ch)


#: Palette colour per group (the fw-badge palette, readable on white).
GROUP_COLOURS = {"flow": "#3D4550", "data": "#4C2A85", "act": "#7A5700", "satom": "#EF5424",
                 "check": "#15692A"}


def kind_map(choices=None) -> dict:
    return {k.key: k for k in kinds(choices)}


def _with_common(k):
    names = {p.name for p in k.params}
    return k.params + [p for p in COMMON_PARAMS if p.name not in names]


def kinds_json(choices=None) -> list[dict]:
    return [{"key": k.key, "label": k.label, "group": k.group, "summary": k.summary,
             "writes": bool(k.writes), "colour": GROUP_COLOURS.get(k.group, "#3D4550"),
             "params": [p.__dict__ for p in _with_common(k)], **k.extra} for k in kinds(choices)]


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
    if kind == "server_call":
        # An operation this list does not know counts as a write.
        from . import studio_server as SV
        return SV.OPERATIONS.get(str(p.get("operation") or ""), True)
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
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return ["the diagram's nodes and edges are lists"]
    if any(not isinstance(n, dict) for n in nodes):
        errs.append("a step of the diagram is not an object")
    if any(not isinstance(e, dict) for e in edges):
        errs.append("an arrow of the diagram is not an object")
    nodes = [n for n in nodes if isinstance(n, dict)]
    edges = [e for e in edges if isinstance(e, dict)]
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
        if not isinstance(p, dict):
            errs.append("%s: params is an object of name: value, not a %s" % (k, type(p).__name__))
            continue
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
        from . import studio_checks as C
        if n.get("kind") in C.KIND_KEYS:
            errs.extend(C.problems(k, n.get("kind"), p))
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
        from . import studio_checks as C
        yes_no = ("decision",) + C.YES_NO_KINDS
        if src.get("kind") not in yes_no + (None,) and b in ("yes", "no"):
            errs.append("%s: yes/no arrows leave a decision, a check or Ask a person only"
                        % src.get("key"))
        if src.get("kind") in C.YES_NO_KINDS and b == "ok":
            errs.append("%s answers yes or no: its arrows are yes, no, error or always"
                        % src.get("key"))
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
    out = {"stores": set(), "connections": set(), "scripts": set()}
    for n in (graph or {}).get("nodes") or []:
        p = n.get("params") or {}
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
    #: False = a ``script`` step is recorded, not run (the Builder's
    #: rehearsal: a script run would leave a run record on this server).
    scripts: bool = True
    #: While a step runs: ``progress(text)`` reports how far it is (e.g. the
    #: command 12/28 of a diagnostics battery) to the run page. None between
    #: steps; a step calls it only through :func:`report`.
    progress: object = None
    #: The steps walked so far, the running one last (set by :func:`walk`):
    #: *Open incident* keeps them as the incident's summary.
    trail: list = field(default_factory=list)
    #: The ADOM of a step run with no run row: an app view's context steps
    #: (services.studio_view). A run's ADOM is its row's ``product``.
    product: str = ""

    def scope(self) -> dict:
        s = dict(self.vars)
        s.update({"form": self.form, "vars": self.vars, "outputs": self.outputs,
                  "run": {"id": self.run_id, "user": self.user}})
        return s


def _p(node, name, default=""):
    v = (node.get("params") or {}).get(name)
    return default if v is None else v


def report(ctx, text) -> None:
    """Tell the run page how far the running step is; a no-op outside a walk."""
    cb = getattr(ctx, "progress", None)
    if callable(cb):
        cb(text)


#: The run page refreshes every 2 s: more than one save a second is wasted.
PROGRESS_EVERY_S = 1.0


def _live_progress(steps, live, ctx, on_step, t0):
    last = [0.0]

    def cb(text):
        live["detail"] = str(text if text is not None else "")[:300]
        live["ms"] = int((time.monotonic() - t0) * 1000)
        now = time.monotonic()
        if on_step and now - last[0] >= PROGRESS_EVERY_S:
            last[0] = now
            on_step(steps, ctx)
    return cb


def _json(node, ctx, name, what):
    raw = _p(node, name, None)
    val = render(parse_json_param(raw, what), ctx.scope())
    if one_expression(raw) and isinstance(val, str):
        # {{ x | tojson }} renders text: the JSON it holds is the value
        try:
            return json.loads(val)
        except ValueError:
            raise FlowError("%s: %s gave text that is not JSON" % (what, raw.strip()[:80])) from None
    return val


def _shown(v) -> bool:
    return bool(v) and str(v).strip().lower() not in ("false", "no", "0", "none")


def _apps_for_buttons(slugs, ctx) -> set | None:
    """The apps among *slugs* the person running may open here (published,
    enabled, theirs to use, shown in the run's ADOM). ``None`` = no person
    to ask (a schedule): every button stays, the click asks again."""
    u = ctx.user_obj
    if u is None:
        return None
    from . import studio_apps as SA
    from .studio_dns import run_product
    product, out = run_product(ctx), set()
    for slug in slugs:
        a = SA.get(slug)
        if a is None or a.kind == "script" or not SA.can_use(u, a):
            continue
        if SA.is_author(u) or (a.enabled and a.published and a.status == "published"
                               and SA.shown_in(a, product)):
            out.add(slug)
    return out


def row_actions(raw, value, scope: dict, ctx) -> list:
    """An Output's ``row_actions``: each row of the table gets ``_actions``,
    the buttons rendered with ``{{ row }}`` = that row. An app button opens
    that app's form, filled in with ``inputs``, over the run page; the app
    checks its own access and its steps their permissions when it RUNS --
    a button is a shortcut, never a grant. A url must be a SATOM path."""
    spec = parse_json_param(raw, "Row buttons")
    if not isinstance(spec, list) or not all(isinstance(a, dict) for a in spec):
        raise FlowError("row buttons are a list of objects")
    if len(spec) > MAX_ROW_ACTIONS:
        raise FlowError("at most %d row buttons" % MAX_ROW_ACTIONS)
    if not isinstance(value, list) or not all(isinstance(r, dict) for r in value):
        raise FlowError("row buttons need a table: a list of objects")
    for a in spec:
        if bool(a.get("app")) == bool(a.get("url")):
            raise FlowError("each row button has an app or a url (one of them)")
    usable = _apps_for_buttons({str(a["app"]) for a in spec if a.get("app")}, ctx)
    out = []
    for row in value:
        s = dict(scope, row=row)
        acts = []
        for a in spec:
            if "when" in a and not _shown(render(a["when"], s)):
                continue
            label = str(render(a.get("label") or "", s) or "").strip()[:40] or "Open"
            if a.get("app"):
                slug = str(a["app"])
                if usable is not None and slug not in usable:
                    continue
                inputs = render(a.get("inputs") or {}, s)
                if not isinstance(inputs, dict):
                    raise FlowError("row button %s: inputs are an object" % label)
                acts.append({"label": label, "app": slug, "inputs": inputs})
                continue
            url = str(render(a["url"], s) or "").strip()
            if url.startswith("/") and not url.startswith("//") and "\\" not in url:
                acts.append({"label": label, "url": url})
        out.append(dict(row, _actions=acts))
    return out


MAX_COLUMNS = 40


def _column_value(row: dict, key: str):
    head, _, rest = key.partition(".")
    v = row.get(head)
    if rest and isinstance(v, list):
        v = [x.get(rest) for x in v if isinstance(x, dict)]
    elif rest and isinstance(v, dict):
        v = v.get(rest)
    if isinstance(v, list) and all(not isinstance(x, (dict, list)) for x in v):
        v = ", ".join("" if x is None else str(x) for x in v)
    return v


def project_columns(raw, value) -> list:
    """An Output's ``columns``: a table keeps only these columns, in this
    order, renamed when written ``key=Label``; ``a.b`` takes ``b`` from each
    item of the list ``a``; a list of plain values is joined by commas. The
    row buttons (``_actions``, computed before) are kept."""
    spec = [c.strip() for c in str(raw or "").split(",") if c.strip()]
    if not spec:
        return value
    if len(spec) > MAX_COLUMNS:
        raise FlowError("at most %d columns" % MAX_COLUMNS)
    if not isinstance(value, list) or not all(isinstance(r, dict) for r in value):
        raise FlowError("columns need a table: a list of objects")
    pairs = []
    for c in spec:
        key, _, label = c.partition("=")
        key, label = key.strip(), label.strip()
        if not key:
            raise FlowError("column %r has no key" % c)
        pairs.append((key, label or key))
    out = []
    for r in value:
        row = {label: _column_value(r, key) for key, label in pairs}
        row.update({k: v for k, v in r.items() if str(k).startswith("_")})
        out.append(row)
    return out


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
    # a test the author writes as `{{ ip in ips }}` equals "true" renders a
    # boolean, and "True" == "true" is false as text: it never matched, so an
    # app on a schedule created the same entry every day (Builder lab,
    # 2026-10-26). A boolean against the words true/false compares as booleans.
    for b, t in ((left, right), (right, left)):
        if isinstance(b, bool) and isinstance(t, str) and t.strip().lower() in ("true", "false"):
            same = b == (t.strip().lower() == "true")
            return same if op == "equals" else not same
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
        if str(_p(node, "row_actions", "") or "").strip():
            value = row_actions(_p(node, "row_actions"), value, scope, ctx)
        if str(_p(node, "columns", "") or "").strip():
            value = project_columns(_p(node, "columns"), value)
        _size_ok(value)
        ctx.outputs.append({"key": node.get("key") or "",
                            "title": str(render(_p(node, "title"), scope) or ""),
                            "view": _p(node, "view", "auto") or "auto", "value": value})
        return "ok", None, ""
    from . import studio_checks as C
    if kind in C.KIND_KEYS:
        return C.run(node, ctx)
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
        c = _connection(node, "http")
        items = _for_each_items(node, ctx)
        if items is not None:
            return _api_call_each(node, ctx, c, items)
        status, value, ms = _api_request(node, ctx, c)
        return "ok", value, "HTTP %d, %d ms" % (status, ms)
    if kind == "server_call":
        from . import studio_connections as SC
        c = _connection(node, "server")
        op = str(_p(node, "operation") or "")
        args = _json(node, ctx, "args", "Arguments") or {}
        if not isinstance(args, dict):
            raise FlowError("the arguments are an object of name: value")
        try:
            res = SC.server_call(c, op, args)
        except SC.ConnectionError_ as exc:
            raise FlowError(str(exc)) from None
        return "ok", res, "%s on %s" % (op, c.slug)
    if kind == "script":
        if not ctx.scripts:
            plan = {k: v for k, v in (node.get("params") or {}).items() if k != "save_as"}
            return "ok", {"rehearsal": True, "would": render(plan, scope)}, \
                "rehearsal: script not run"
        return _run_script(node, ctx)
    from . import studio_satom as S
    if kind in S.KIND_KEYS:
        return S.run(node, ctx)
    raise FlowError("unknown step kind %r" % kind)


def run_single(node: dict, ctx: Ctx):
    """One step outside a walk: ``(outcome, value, detail)``, a FlowError for
    an error. An app view's context (services.studio_view) reads with it."""
    return _run_step(node, ctx)


def _api_request(node, ctx, c) -> tuple:
    """One request of an api_call step: ``(status, value, ms)``, the value
    narrowed by ``extract``. A non-2xx answer is a FlowError, with the answer
    left in ``last_response``."""
    from . import studio_connections as SC
    method, path = _endpoint(node, ctx, c)
    body = _json(node, ctx, "body", "Body")
    _rpc_check(c, method, path, body)
    try:
        r = SC.http_call(c, method, path,
                         query=_json(node, ctx, "query", "Query string"),
                         body=body)
    except SC.ConnectionError_ as exc:
        raise FlowError(str(exc)) from None
    body = r.get("json") if "json" in r else r.get("text")
    if not r["ok"]:
        ctx.vars["last_response"] = {"status": r["status"], "body": body}
        raise FlowError("HTTP %d from %s" % (r["status"], c.slug))
    ex = str(_p(node, "extract") or "")
    return r["status"], (SC.json_path(body, ex) if ex else body), r["ms"]


#: An api_call's For each sends at most this many requests.
MAX_FOR_EACH = 50


def _for_each_items(node, ctx):
    """The list an api_call repeats over, duplicates dropped, or ``None``
    when the step has no For each (one request). More than MAX_FOR_EACH is
    refused, never cut: a cut list would show a partial answer as whole."""
    raw = _p(node, "for_each", None)
    if raw is None or not str(raw).strip():
        return None
    val = _json(node, ctx, "for_each", "For each")
    if val in (None, ""):
        val = []
    if not isinstance(val, list):
        raise FlowError("For each is a list, e.g. {{ dns.ptr }} (it gave %s)"
                        % type(val).__name__)
    out = []
    for it in val:
        if it not in out:
            out.append(it)
    if len(out) > MAX_FOR_EACH:
        raise FlowError("For each: %d items, at most %d requests per step"
                        % (len(out), MAX_FOR_EACH))
    return out


def _api_call_each(node, ctx, c, items) -> tuple:
    """One request per item with ``{{ item }}`` = that item. The value is a
    table: the item (its keys, when it is an object, else ``Item``), then
    ``Status``, ``Answer`` and ``Error``; ``_ok`` says which rows answered.
    One item that fails is a row with its error and the others go on; the
    error arrow is taken only when every request failed. A run out of time
    stops asking and says how many were not asked."""
    had, old = "item" in ctx.vars, ctx.vars.get("item")
    rows, skipped = [], 0
    try:
        for it in items:
            if ctx.deadline and time.time() > ctx.deadline:
                skipped = len(items) - len(rows)
                break
            ctx.vars["item"] = it
            row = dict(it) if isinstance(it, dict) else {"Item": it}
            try:
                status, value, _ms = _api_request(node, ctx, c)
                row.update({"Status": status, "Answer": value, "Error": "", "_ok": True})
            except FlowError as exc:
                lr = ctx.vars.get("last_response") or {}
                row.update({"Status": lr.get("status", "") if "HTTP" in str(exc) else "",
                            "Answer": None, "Error": str(exc), "_ok": False})
            rows.append(row)
    finally:
        if had:
            ctx.vars["item"] = old
        else:
            ctx.vars.pop("item", None)
    ok = sum(1 for r in rows if r["_ok"])
    detail = "%d request(s): %d ok, %d failed" % (len(rows), ok, len(rows) - ok)
    if skipped:
        detail += ", %d not asked (run out of time)" % skipped
    if rows and not ok:
        # what each item answered stays readable on the error arrow
        ctx.vars[str(_p(node, "save_as", "") or "response")] = rows
        raise FlowError("every request failed (%d); the first: %s" % (len(rows), rows[0]["Error"]))
    if skipped and not rows:
        raise FlowError("the run ran out of time before the first request")
    return "ok", rows, detail


def _rpc_check(c, method: str, path: str, body) -> None:
    """A JSON-RPC endpoint of the connection's API Catalog version
    (FortiAnalyzer ``POST /jsonrpc``) is reached only at the urls it lists."""
    from . import studio_api_spec as SP
    from . import studio_apis as SA
    cat = SA.catalog_of(c)
    if cat is None:
        return
    miss = SP.rpc_problem(SP.find(cat["operations"], method, path), body)
    if miss:
        raise FlowError("%s in API %s %s (connection %s)"
                        % (miss, cat["api"], cat["version"], c.slug))


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


def walk(graph: dict, ctx: Ctx, on_step=None, resume: dict | None = None) -> dict:
    """Run the diagram. ``{status: done|failed|waiting, error, steps, waiting}``.
    *on_step* is called when a step starts (its row reads ``running``), while
    it reports progress (:func:`report`, at most once a second) and after it
    ends (the row gets its outcome): the caller persists, the run page shows.

    An *Ask a person* step stops the walk: the result is ``waiting`` with the
    step's key, and the step is recorded with outcome ``waiting``. *resume*
    (``{"steps", "key", "answer", "note"}``) continues from that step along
    the arrow of the answer (``yes`` / ``no``), with ``ctx`` rebuilt from the
    variables the run saved. The time limit counts from the resume."""
    from . import studio_checks as C
    nodes = {n.get("key"): n for n in graph.get("nodes") or []}
    edges = graph.get("edges") or []
    start = [k for k, n in nodes.items() if n.get("kind") == "start"]
    if len(start) != 1:
        return {"status": "failed", "error": "the diagram has no single Start step", "steps": []}
    ctx.deadline = ctx.deadline or time.time() + RUN_TIMEOUT
    steps, key, count = [], start[0], 0
    status, error = "done", ""
    ctx.trail = steps
    if resume:
        steps = list(resume.get("steps") or [])
        ctx.trail = steps
        at, answer = resume.get("key"), resume.get("answer")
        if answer not in ("yes", "no") or at not in nodes:
            return {"status": "failed", "error": "nothing to answer at %r" % at, "steps": steps}
        for st in reversed(steps):
            if st.get("key") == at and st.get("outcome") == "waiting":
                st["outcome"] = answer
                note = str(resume.get("note") or "").strip()
                st["detail"] = (str(st.get("detail") or "") + " — answered %s%s" % (
                    answer, (": " + note[:400]) if note else ""))[:2000]
                break
        if on_step:
            on_step(steps, ctx)
        key = _next(edges, at, answer)
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
        # The step is on the run page while it runs (outcome "running"), not
        # only once it is over: a diagnostics battery takes a minute.
        live = {"key": key, "label": node.get("label") or key, "kind": node.get("kind"),
                "outcome": "running", "detail": "", "ms": 0}
        steps.append(live)
        if on_step:
            on_step(steps, ctx)
        ctx.progress = _live_progress(steps, live, ctx, on_step, t0)
        try:
            outcome, value, detail = _run_step(node, ctx)
            p = node.get("params") or {}
            target = p.get("name") if node.get("kind") == "set" else p.get("save_as")
            # A runbook step whose result later steps name by default
            # ({{ appliance.host }}) saves it even when the draft never set
            # the field: the default is part of what the step promises.
            from . import studio_satom as S
            target = (target or C.DEFAULT_SAVE_AS.get(node.get("kind"))
                      or S.DEFAULT_SAVE_AS.get(node.get("kind")))
            if target and value is not None:
                if not _VAR_RE.match(str(target)) or target in RESERVED_VARS:
                    raise FlowError("%r is not a usable variable name" % target)
                _size_ok(value)
                ctx.vars[str(target)] = value
        except FlowError as exc:
            outcome, detail = "error", str(exc)
            ctx.vars["last_error"] = {"step": key, "message": detail}
        finally:
            ctx.progress = None
        # A simulation scenario picks the arrow; the step itself has RUN (a
        # check really looked), and what it found stays on the record.
        really = None
        forced = _scenario_take(ctx, key, node)
        if forced is not None:
            if outcome == C.WAIT:
                ctx.vars.pop(C.ASK_GATE, None)
                detail = "%s — answered %s (simulation)" % (detail, forced)
            else:
                really = outcome
                if outcome != forced:
                    detail = "%s — simulation takes %s" % (detail, forced)
            outcome = forced
        waiting = outcome == C.WAIT
        rec = {"key": key, "label": node.get("label") or key, "kind": node.get("kind"),
               "outcome": "waiting" if waiting else outcome,
               "detail": str(detail)[:2000],
               "ms": int((time.monotonic() - t0) * 1000)}
        if really is not None:
            rec["really"] = really
        steps[-1] = rec                     # replaces the "running" entry
        if on_step:
            on_step(steps, ctx)
        if waiting:
            return {"status": "waiting", "error": "", "steps": steps, "waiting": key}
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
#  simulation -- every arrow walked at least once (FA-0008, 2026-11-07)        #
# --------------------------------------------------------------------------- #
#: What a scenario may answer at a step.
SCENARIO_OUTCOMES = ("yes", "no", "ok", "error")
#: Scenarios one plan proposes at most.
MAX_SCENARIOS = 60


def _scenario_take(ctx: Ctx, key: str, node: dict):
    """The outcome the simulation's scenario gives *key* this time, or None
    (no scenario, an armed run, or no answer left for this step)."""
    if ctx.armed or node.get("kind") in ("start", "end", "fail"):
        return None
    sc = ctx.vars.get(SCENARIO_VAR)
    if not isinstance(sc, dict):
        return None
    q = (sc.get("answers") or {}).get(key)
    if not isinstance(q, list) or not q:
        return None
    return q.pop(0)


def clean_scenario(graph: dict, raw) -> dict:
    """A scenario as a simulation may carry it, or FlowError. ``{}`` = none."""
    if raw in (None, "", {}):
        return {}
    if not isinstance(raw, dict):
        raise FlowError("a scenario is an object")
    keys = {n.get("key") for n in graph.get("nodes") or [] if isinstance(n, dict)}
    answers = raw.get("answers")
    if not isinstance(answers, dict) or len(answers) > 500:
        raise FlowError("a scenario's answers are an object of step: [outcome, …]")
    out = {}
    for k, q in answers.items():
        if k not in keys:
            raise FlowError("the scenario answers a step that does not exist: %r" % k)
        if not isinstance(q, list) or len(q) > 50 or any(x not in SCENARIO_OUTCOMES for x in q):
            raise FlowError("the scenario's answers for %s are a list of %s"
                            % (k, ", ".join(SCENARIO_OUTCOMES)))
        out[k] = list(q)
    first = [k for k in (raw.get("first") or []) if k in keys][:500]
    return {"answers": out, "first": first, "name": str(raw.get("name") or "")[:300]}


def _forced_outcome(node: dict, branch: str, branches: set):
    """The outcome that sends a simulation along *branch* out of *node*, or
    None when the step's own result already does (a box with one arrow)."""
    from . import studio_checks as C
    kind = node.get("kind")
    if kind in ("start", "end", "fail"):
        return None
    two_way = kind == "decision" or kind in C.YES_NO_KINDS   # Ask a person included
    if branch in ("yes", "no", "error"):
        return branch
    if branch == "ok":
        return "ok" if len(branches) > 1 else None
    # always
    if two_way:
        return "yes"
    return "ok" if "error" in branches else None


def _graph_parts(graph: dict):
    nodes = {n.get("key"): n for n in graph.get("nodes") or [] if isinstance(n, dict)}
    edges = [e for e in graph.get("edges") or [] if isinstance(e, dict)
             and e.get("src") in nodes and e.get("dst") in nodes]
    starts = [k for k, n in nodes.items() if n.get("kind") == "start"]
    if len(starts) != 1:
        raise FlowError("the diagram has no single Start step")
    return nodes, edges, starts[0]


def cover(graph: dict) -> dict:
    """Scenarios that together walk EVERY arrow reachable from Start.

    Each scenario is one path from Start to an end, and the answer it forces
    at every step with a choice (a question, a check, a decision, an error
    arrow). Walked as a rehearsal, every check still really looks and every
    question shows; only the arrow followed is the scenario's. Greedy: the
    first arrow not yet walked, the shortest way to it, then new arrows while
    they still lead to an end, else the shortest way out.
    ``{scenarios: [{name, answers, first, path, ends}], arrows, unreachable}``."""
    from collections import deque
    nodes, edges, start = _graph_parts(graph)
    outs = {k: [] for k in nodes}
    rev = {k: [] for k in nodes}
    for i, e in enumerate(edges):
        outs[e["src"]].append(i)
        rev[e["dst"]].append(i)

    def terminal(k):
        return nodes[k].get("kind") in ("end", "fail") or not outs[k]

    dist = {k: 0 for k in nodes if terminal(k)}
    q = deque(dist)
    while q:
        k = q.popleft()
        for i in rev[k]:
            s = edges[i]["src"]
            if s not in dist:
                dist[s] = dist[k] + 1
                q.append(s)
    prev, order, q = {start: None}, [start], deque([start])
    while q:
        k = q.popleft()
        for i in outs[k]:
            d = edges[i]["dst"]
            if d not in prev:
                prev[d] = i
                order.append(d)
                q.append(d)

    def path_to(k):
        p = []
        while prev[k] is not None:
            p.append(prev[k])
            k = edges[prev[k]]["src"]
        return p[::-1]

    def label(k):
        return str(nodes[k].get("label") or k)

    rank = {k: n for n, k in enumerate(order)}
    todo = sorted((i for i, e in enumerate(edges) if e["src"] in prev),
                  key=lambda i: (rank[edges[i]["src"]], i))
    covered, scenarios = set(), []
    for i in todo:
        if i in covered:
            continue
        if len(scenarios) >= MAX_SCENARIOS:
            break
        p = path_to(edges[i]["src"]) + [i]
        cur, guard = edges[i]["dst"], 0
        while not terminal(cur) and cur in dist and guard < 4 * len(nodes):
            guard += 1
            cands = [j for j in outs[cur] if edges[j]["dst"] in dist]
            fresh = [j for j in cands if j not in covered and j not in p]
            j = fresh[0] if fresh else min(cands, key=lambda x: dist[edges[x]["dst"]])
            p.append(j)
            cur = edges[j]["dst"]
        covered.update(p)
        answers: dict = {}
        for j in p:
            src = edges[j]["src"]
            f = _forced_outcome(nodes[src], edges[j].get("branch") or "always",
                                {edges[x].get("branch") or "always" for x in outs[src]})
            if f is not None:
                answers.setdefault(src, []).append(f)
        e = edges[i]
        ends = ("no way out" if not terminal(cur)
                else ("fails" if nodes[cur].get("kind") == "fail" else "ends"))
        scenarios.append({"name": "%s —%s→ %s" % (label(e["src"]), e.get("branch") or "always",
                                                  label(e["dst"])),
                          "answers": answers, "path": [start] + [edges[j]["dst"] for j in p],
                          "end": label(cur), "ends": ends})
    seen: set = set()
    for sc in scenarios:
        firsts = []
        for k in sc["path"]:
            if nodes[k].get("kind") == "notify" and k not in seen and k not in firsts:
                firsts.append(k)
        seen.update(firsts)
        sc["first"] = firsts
    unreachable = ["%s → %s (%s)" % (label(e["src"]), label(e["dst"]), e.get("branch") or "always")
                   for e in edges if e["src"] not in prev]
    return {"scenarios": scenarios, "arrows": len(edges),
            "covered": len(covered), "unreachable": unreachable,
            "truncated": len(scenarios) >= MAX_SCENARIOS and len(covered) < len(todo)}


def coverage(graph: dict, runs: list) -> dict:
    """What a set of runs walked: per step how often, what it answered, what
    it really found (a check whose arrow a scenario chose); per arrow how often
    it was taken. ``runs`` = ``[{"id", "status", "steps"}]``."""
    from collections import Counter
    from . import studio_checks as C
    nodes, edges, _start = _graph_parts(graph)
    visits = {k: 0 for k in nodes}
    answered = {k: Counter() for k in nodes}
    really = {k: Counter() for k in nodes}
    taken = [0] * len(edges)
    for r in runs:
        st = [s for s in (r.get("steps") or []) if isinstance(s, dict)]
        for n, a in enumerate(st):
            k = a.get("key")
            if k not in nodes:
                continue
            visits[k] += 1
            out = a.get("outcome")
            answered[k][out] += 1
            if a.get("really"):
                really[k][a["really"]] += 1
            elif nodes[k].get("kind") != "ask" and out != "waiting":
                really[k][out] += 1
            b = st[n + 1].get("key") if n + 1 < len(st) else None
            if b is None:
                continue
            hit = None
            for want in (out, "always", None):
                hit = next((i for i, e in enumerate(edges) if e["src"] == k and e["dst"] == b
                            and (want is None or (e.get("branch") or "always") == want)), None)
                if hit is not None:
                    break
            if hit is not None:
                taken[hit] += 1
    steps = [{"key": k, "label": n.get("label") or k, "kind": n.get("kind"),
              "check": n.get("kind") in C.YES_NO_KINDS and n.get("kind") != "ask",
              "visits": visits[k], "answered": dict(answered[k]), "really": dict(really[k])}
             for k, n in nodes.items()]
    arrows = [{"src": e["src"], "dst": e["dst"], "branch": e.get("branch") or "always",
               "src_label": nodes[e["src"]].get("label") or e["src"],
               "dst_label": nodes[e["dst"]].get("label") or e["dst"], "taken": taken[i]}
              for i, e in enumerate(edges)]
    return {"steps": steps, "arrows": arrows,
            "steps_visited": sum(1 for s in steps if s["visits"]), "steps_total": len(steps),
            "arrows_taken": sum(1 for a in arrows if a["taken"]), "arrows_total": len(arrows),
            "runs": [{"id": r.get("id"), "status": r.get("status")} for r in runs]}


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
    from . import studio_checks as C
    saved = set()
    for n in nodes:
        p = n.get("params") or {}
        t = p.get("name") if n.get("kind") == "set" else p.get("save_as")
        t = t or C.DEFAULT_SAVE_AS.get(n.get("kind")) or S.DEFAULT_SAVE_AS.get(n.get("kind"))
        if t:
            saved.add(str(t))
    builtin = set(RESERVED_VARS) | {"last_error", "last_response", "last_script",
                                    "last_process", "last_answer", "range", "true",
                                    "false", "none"}
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
