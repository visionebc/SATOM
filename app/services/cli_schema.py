"""The CLI channel of the API library: the appliance's own schema, parsed.

Two read-only commands describe what a firmware build's CLI serves:

* ``tree`` at the root of the CLI prints the WHOLE schema in seconds: every
  configuration object, every field, its CLI attribute id, its type or its
  enum options. FortiWeb prints tables as ``[name(id)]``, singletons as
  ``{name(id)}`` and fields as ``name(id)`` followed by ``<type>`` or the list
  of options; the first field of a table is its key (mkey) and the table's
  other fields hang under it. FortiOS (FortiGate) prints tables as ``[name]``,
  singletons as ``<name>``, marks the key field with ``*`` and annotates a
  field with ``(lo,hi)`` (range) or ``(N)`` (size); it prints no types and no
  options.
* ``show full-configuration`` prints every field of every object that EXISTS
  on the box, defaults included — and some of them are fields ``tree`` never
  lists (the hidden fields). Only names are kept here: a configuration value
  is never part of the library (pack rule 1). :func:`parse_show_full_values`
  exists for lab evidence only, where a freshly created row's values ARE the
  defaults.

Everything in this module is a pure function over text: no device, no
database, no Flask. :mod:`app.services.schema_harvest` captures the text and
:mod:`app.services.api_library` stores what the evidence builders return.

THE KEY. CLI evidence is keyed by the canonical REST path without prefix
(``system/ntp/ntpserver``), which is what :func:`api_library.urn_key` makes of
the REST URN a sweep carries. :func:`rest_path` derives it per product:

* FortiWeb (verified on 7.6.8): ``module/`` + the namespaces and the object
  joined with ``.``; an object nested in a table or a singleton goes with
  ``/`` (``waf/web-protection-profile.inline-protection``,
  ``system/ntp/ntpserver``).
* FortiGate: ``config a b c`` -> ``a.b/c`` (path = every word but the last
  joined with ``.``, name = the last word), the form of every vendor URN in
  the library (``log.syslogd2/setting``,
  ``wireless-controller.hotspot20/anqp-venue-name``). A nested table is not a
  separate endpoint in FortiOS: it is a field of its top-level object, with
  ``children``.
* FortiADC: ``config load-balance virtual-server`` ->
  ``load_balance_virtual_server``; a table nested in a table ->
  ``<parent>_child_<table>``. NOT verified against a live box (no FortiADC in
  the lab): see :data:`PATH_RULE_STATUS`.
"""
from __future__ import annotations

import re

KIND_NAMESPACE = "namespace"
KIND_TABLE = "table"
KIND_SINGLETON = "singleton"
#: A ``show full-configuration`` block whose table/singleton nature the dump
#: cannot tell. Every product rule treats it like table/singleton.
KIND_OBJECT = "object"
OBJECT_KINDS = (KIND_TABLE, KIND_SINGLETON, KIND_OBJECT)

FORMAT_FORTIWEB = "fortiweb"     # [t(id)] {s(id)} f(id) <type>
FORMAT_FORTIOS = "fortios"       # [t] <s> --*mkey (lo,hi)

#: How far each product's CLI -> REST rule has been checked against a box.
PATH_RULE_STATUS = {
    "fortiweb": "verified",          # fortiweb17 7.6.8: 287/287 swept paths in the tree
    "fortigate": "verified",         # matches every vendor_doc URN of fortinet.fortios
    "fortiadc": "unverified",        # documented convention only; no FortiADC in the lab
    # FortiAuthenticator's CLI objects have NO REST counterpart (its REST is the
    # Tastypie directory, /api/v1/<resource>/): the FortiOS rule only names them.
    "fortiauthenticator": "cli-only",
}
#: The FortiADC rule has never been checked against a live FortiADC.
FORTIADC_RULE_UNVERIFIED = True

URN_PREFIX = {"fortiweb": "/api/v2.0/cmdb/", "fortigate": "/api/v2/cmdb/",
              "fortiadc": "/api/"}

#: FortiOS appends the COMMAND trees (``diagnose__tree__``, ``execute__tree__``)
#: to the configuration tree. They are verbs, not configuration objects.
COMMAND_TREE_SUFFIX = "__tree__"

#: Below this many objects a ``tree`` dump is not a schema, it is a fragment
#: (a read cut short, a prompt that never came back). FortiWeb 7.6.8 prints
#: 537 objects and FortiOS 8.0 several thousand.
MIN_TREE_OBJECTS = 50
#: Same for ``show full-configuration``: a real box prints hundreds of blocks.
MIN_FULL_OBJECTS = 20

# ``--``, ``|-`` or ``+-`` (optionally ``--*`` = key field), then the item.
# The item may not itself be a connector: FortiOS's first line can start with
# a doubled ``--  --``.
_CONN = re.compile(r"(\|-|\+-|--)(\*?)[ \t]*(?!--|\|-|\+-)(\S+)")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
_PROMPT_HEAD = re.compile(r"^[\w.\-]+ (?:\(\S+\) )?# ?")
_PROMPT_LINE = re.compile(r"^[\w.\-]+ (?:\(\S+\) )?# ?$")
_TABLE = re.compile(r"^\[(?P<n>[^\[\]()]+)(?:\((?P<id>\d+)\))?\]$")
_SINGLE = re.compile(r"^\{(?P<n>[^{}()]+)(?:\((?P<id>\d+)\))?\}$")
_ANGLE = re.compile(r"^<(?P<n>[^<>]+)>$")
_FIELD_ID = re.compile(r"^(?P<n>[^()\s]+)\((?P<id>\d+)\)$")
_RANGE = re.compile(r"\((-?\d+)\s*,\s*(-?\d+)\)")
_SIZE = re.compile(r"\((\d+)(?:\s+[^)]*)?\)")


# ---------------------------------------------------------------------------
# tree
# ---------------------------------------------------------------------------

class _Node:
    __slots__ = ("name", "token", "cli_id", "annot", "star", "children", "kind")

    def __init__(self, name, token="", cli_id=None, annot="", star=False):
        self.name = name
        self.token = token
        self.cli_id = cli_id
        self.annot = annot
        self.star = star
        self.children: list = []
        self.kind = ""


def _clean_lines(text: str) -> list:
    out = []
    for raw in _ANSI.sub("", text or "").replace("\r", "").split("\n"):
        if not raw.strip():
            continue
        if raw.strip() == "tree" or _PROMPT_LINE.match(raw.strip()):
            continue
        m = _PROMPT_HEAD.match(raw)
        if m and _CONN.search(raw[m.end():]):
            # A prompt glued to the first line of output: blank it out, keep
            # the columns (siblings are found by column).
            raw = " " * m.end() + raw[m.end():]
        out.append(raw)
    return out


def _raw_tree(text: str) -> _Node:
    """Column-stack parse: an item's parent is the nearest open item to its left."""
    root = _Node("", token="")
    stack: list = [(-1, root)]
    for line in _clean_lines(text):
        matches = list(_CONN.finditer(line))
        for i, m in enumerate(matches):
            col = m.start(1)
            end = matches[i + 1].start(1) if i + 1 < len(matches) else len(line)
            annot = line[m.end(3):end].strip()
            token = m.group(3)
            node = _Node(token, token=token, annot=annot, star=bool(m.group(2)))
            while stack and stack[-1][0] >= col:
                stack.pop()
            parent = stack[-1][1] if stack else root
            parent.children.append(node)
            stack.append((col, node))
    return root


def _classify(node: _Node, parent_kind: str, fmt: str) -> None:
    """Give every node a kind: table, singleton, namespace, field or value."""
    tok = node.token
    m = _TABLE.match(tok)
    if m:
        node.kind, node.name = KIND_TABLE, m.group("n")
        node.cli_id = int(m.group("id")) if m.group("id") else None
    elif _SINGLE.match(tok):
        m = _SINGLE.match(tok)
        node.kind, node.name = KIND_SINGLETON, m.group("n")
        node.cli_id = int(m.group("id")) if m.group("id") else None
    elif _ANGLE.match(tok) and (node.children or parent_kind != "field"):
        # FortiOS singleton (``<global>``; ``hardware -- <status>`` has no fields)
        node.kind, node.name = KIND_SINGLETON, _ANGLE.match(tok).group("n")
    elif _ANGLE.match(tok):
        node.kind = "value"                       # a FortiWeb <type>
    elif _FIELD_ID.match(tok):
        m = _FIELD_ID.match(tok)
        node.kind, node.name, node.cli_id = "field", m.group("n"), int(m.group("id"))
    else:
        node.kind = ""                             # decided below
    for c in node.children:
        _classify(c, node.kind, fmt)
    if node.kind:
        return
    has_objects = any(c.kind in (KIND_TABLE, KIND_SINGLETON, KIND_NAMESPACE)
                      for c in node.children)
    if has_objects:
        node.kind = KIND_NAMESPACE
    elif parent_kind == "field":
        node.kind = "value"                        # an enum option
    elif parent_kind in (KIND_TABLE, KIND_SINGLETON) or node.star:
        node.kind = "field"                        # FortiOS: plain field names
    elif node.children:
        node.kind = KIND_NAMESPACE
    else:
        node.kind = "field"


def _detect_format(root: _Node) -> str:
    def walk(n):
        yield n
        for c in n.children:
            yield from walk(c)
    for n in walk(root):
        if _FIELD_ID.match(n.token) or _SINGLE.match(n.token):
            return FORMAT_FORTIWEB
    return FORMAT_FORTIOS


def _field_spec(node: _Node) -> dict:
    """``{"type", "options", "attrs"}`` of one field node."""
    values = [c.token for c in node.children if c.kind == "value"]
    types = [v for v in values if _ANGLE.match(v)]
    options = [v for v in values if not _ANGLE.match(v)]
    attrs: dict = {}
    if node.cli_id is not None:
        attrs["cli_id"] = node.cli_id
    cli_type = types[0] if types else ""
    rng = _RANGE.search(node.annot or "")
    if rng:
        attrs["range"] = [int(rng.group(1)), int(rng.group(2))]
        cli_type = cli_type or "<integer>"
    elif _SIZE.search(node.annot or ""):
        # FortiOS ``(35)`` / ``(255 xss)``: a string's size, kept raw.
        cli_type = cli_type or _SIZE.search(node.annot).group(0)
    if cli_type:
        attrs["cli_type"] = cli_type
    if cli_type == "<datasource>":
        attrs["datasource"] = True
    if options and not types:
        ftype = "option"
    elif cli_type.startswith("<"):
        ftype = cli_type.strip("<>")
    elif rng:
        ftype = "integer"
    else:
        ftype = None
    return {"type": ftype, "options": options or None, "attrs": attrs}


def _object_parts(node: _Node, fmt: str) -> tuple:
    """``(mkey, {field: spec}, [child object nodes], [namespace nodes])``.

    FortiWeb hangs a table's other fields (and nested objects) UNDER its first
    field, the key. FortiOS lists them as siblings and marks the key with ``*``.
    """
    kids = list(node.children)
    mkey = None
    if node.kind == KIND_TABLE:
        star = next((c for c in kids if c.kind == "field" and c.star), None)
        first = next((c for c in kids if c.kind == "field"), None)
        # FortiOS marks the key with ``*``; an unmarked table has no known key.
        mk = star if fmt == FORMAT_FORTIOS else (star or first)
        if mk is not None:
            mkey = mk.name
            if fmt == FORMAT_FORTIWEB and mk is first:
                held = [c for c in mk.children if c.kind != "value"]
                kids = [c for c in kids if c is not mk] + held
                kids.insert(0, mk)
    fields: dict = {}
    subs, nss = [], []
    for c in kids:
        if c.kind == "field":
            # _field_spec reads value children only, so a FortiWeb key keeps
            # its own type/options and not the fields that hang under it.
            fields.setdefault(c.name, _field_spec(c))
        elif c.kind in (KIND_TABLE, KIND_SINGLETON):
            subs.append(c)
        elif c.kind == KIND_NAMESPACE:
            nss.append(c)
    return mkey, fields, subs, nss


def parse_tree(text: str) -> dict:
    """Parse the output of the CLI ``tree`` command.

    Returns ``{"format": "fortiweb"|"fortios", "objects": {cli_path: obj},
    "counts": {...}}`` where ``obj`` is::

        {"cli_path": "system ntp ntpserver", "kind": "table"|"singleton",
         "kind_chain": ["namespace", "singleton", "table"],
         "mkey": "id" | None, "cli_id": 123 | None,
         "parent": "system ntp" | "",          # nearest enclosing object
         "fields": {name: {"type", "options", "attrs": {cli_id, cli_type,
                                                        datasource, range}}}}

    The scope containers FortiWeb prints at the root (``{global}`` and the
    ``[vdom]`` table) are stripped, as ``config global`` / ``config vdom`` are
    in a configuration dump; an object listed under both is one object.
    """
    root = _raw_tree(text)
    fmt = _detect_format(root)
    for c in root.children:
        _classify(c, "", fmt)
    objects: dict = {}

    def visit(node, path, chain, parent_obj):
        if node.kind in (KIND_TABLE, KIND_SINGLETON):
            p, ch = path + [node.name], chain + [node.kind]
            mkey, fields, subs, nss = _object_parts(node, fmt)
            key = " ".join(p)
            if key:
                rec = objects.get(key)
                if rec is None:
                    objects[key] = {"cli_path": key, "kind": node.kind, "kind_chain": ch,
                                    "mkey": mkey, "cli_id": node.cli_id,
                                    "parent": parent_obj, "fields": fields}
                else:
                    for f, spec in fields.items():
                        rec["fields"].setdefault(f, spec)
            for s in subs + nss:
                visit(s, p, ch, key)
        elif node.kind == KIND_NAMESPACE:
            for s in node.children:
                visit(s, path + [node.name], chain + [KIND_NAMESPACE], parent_obj)
        elif node.kind == "field":
            # A namespace hung under a FortiWeb key field (the vdom table).
            for s in node.children:
                if s.kind in (KIND_TABLE, KIND_SINGLETON, KIND_NAMESPACE):
                    visit(s, path, chain, parent_obj)

    for top in root.children:
        if top.token.endswith(COMMAND_TREE_SUFFIX):
            continue      # FortiOS ``diagnose__tree__`` / ``execute__tree__``: commands
        if top.kind in (KIND_TABLE, KIND_SINGLETON) and top.name in ("global", "vdom"):
            # Scope container: its contents start a fresh path.
            _mk, _f, subs, nss = _object_parts(top, fmt)
            for s in subs + nss:
                visit(s, [], [], "")
            continue
        visit(top, [], [], "")
    nfields = sum(len(o["fields"]) for o in objects.values())
    return {"format": fmt, "objects": objects, "counts": {
        "objects": len(objects),
        "tables": sum(1 for o in objects.values() if o["kind"] == KIND_TABLE),
        "singletons": sum(1 for o in objects.values() if o["kind"] == KIND_SINGLETON),
        "fields": nfields,
        "enum_fields": sum(1 for o in objects.values() for s in o["fields"].values()
                           if s.get("options")),
        "datasource_fields": sum(1 for o in objects.values() for s in o["fields"].values()
                                 if (s.get("attrs") or {}).get("datasource")),
    }}


# ---------------------------------------------------------------------------
# show full-configuration
# ---------------------------------------------------------------------------

def _full_blocks(text: str) -> dict:
    """``{cli_path: CliBlock}`` from the coverage parser (one author of the
    dump grammar: quoted multi-line values, scope containers)."""
    from .cli_coverage import parse_config_dump
    return {blk.path: blk for blk in parse_config_dump(text).values()}


def parse_show_full(text: str) -> dict:
    """``show full-configuration`` -> ``{cli_path: set(field names)}``.

    Values are discarded: only the name after ``set``/``unset`` is kept. An
    object that is not configured prints no block, so absence here is not
    evidence of anything.
    """
    return {path: set(blk.sets) for path, blk in _full_blocks(text).items()}


def _full_kind_chain(blk) -> list:
    """Kind chain from the block's ``config`` segments: in each segment every
    word but the last is a namespace and the last is an object."""
    chain: list = []
    for n in getattr(blk, "segments", ()) or (len(blk.path.split()),):
        chain += [KIND_NAMESPACE] * (n - 1) + [KIND_OBJECT]
    return chain


#: Lab defaults are never recorded for identity or secret fields: a lab box's
#: hostname or key is not a default, and a pack carrying it would be refused
#: by the leak scan as a whole.
_LAB_DEFAULT_SKIP = re.compile(
    r"(hostname|alias|serial|pass|secret|psk|private|key|token|cert|credential)", re.I)

_SET_LINE = re.compile(r'^\s*set\s+(?P<name>\S+)(?:\s+(?P<value>.*))?$')


def parse_show_full_values(text: str) -> dict:
    """LAB ONLY: ``{cli_path: {field: value}}`` of the FIRST row of each object.

    On a freshly created lab row every value is the default, which is the one
    case the library may record a value (``summary.lab``). Never call this on
    a production dump: values are configuration. Multi-line quoted values are
    skipped (returned as ``None``).
    """
    out: dict = {}
    stack: list = []
    first_row: list = []
    in_quote = False
    for raw in (text or "").splitlines():
        if in_quote:
            if raw.count('"') % 2:
                in_quote = False
            continue
        line = raw.strip()
        if line.startswith("config "):
            stack.append(line[7:].split())
            first_row.append(True)
            continue
        if line == "end":
            if stack:
                stack.pop()
                first_row.pop()
            continue
        if line == "next":
            if first_row:
                first_row[-1] = False
            continue
        if line.startswith("edit "):
            if line.count('"') % 2:
                in_quote = True
            continue
        m = _SET_LINE.match(raw)
        if m and stack:
            value = m.group("value") or ""
            if value.count('"') % 2:
                in_quote = True
                value = None
            if not first_row[-1]:
                continue
            words = [w for seg in stack for w in seg]
            if len(stack[0]) == 1 and stack[0][0] in ("global", "vdom"):
                words = [w for seg in stack[1:] for w in seg]
            path = " ".join(words)
            rec = out.setdefault(path, {})
            if value is not None:
                v = value.strip()
                if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                    v = v[1:-1]
                rec.setdefault(m.group("name"), v)
            else:
                rec.setdefault(m.group("name"), None)
    return out


# ---------------------------------------------------------------------------
# CLI path -> REST path
# ---------------------------------------------------------------------------

def _last_object(kind_chain, upto: int) -> int:
    for i in range(upto - 1, -1, -1):
        if kind_chain[i] in OBJECT_KINDS:
            return i
    return -1


def rest_path(product: str, cli_path: str, kind_chain) -> str | None:
    """The canonical REST path (no prefix) of a CLI object, or None.

    ``kind_chain`` names the kind of every word of ``cli_path``
    (``namespace``/``table``/``singleton``/``object``). None when the product
    has no separate REST endpoint for the object (a FortiOS nested table is a
    field of its parent) or no rule at all.
    """
    words = (cli_path or "").split()
    chain = list(kind_chain or [])
    if not words or len(chain) != len(words):
        return None
    if product == "fortiweb":
        anc = _last_object(chain, len(words) - 1)
        if anc < 0:
            if len(words) == 1:
                return words[0]
            return words[0] + "/" + ".".join(words[1:])
        head = rest_path(product, " ".join(words[:anc + 1]), chain[:anc + 1])
        return None if head is None else head + "/" + ".".join(words[anc + 1:])
    if product in ("fortigate", "fortiauthenticator"):
        if _last_object(chain, len(words) - 1) >= 0 or len(words) < 2:
            return None
        return ".".join(words[:-1]) + "/" + words[-1]
    if product == "fortiadc":
        if any("+" in w for w in words):
            return None                       # ``config user tacacs+`` does not map
        anc = _last_object(chain, len(words) - 1)
        flat = lambda ws: "_".join(w.replace("-", "_") for w in ws)  # noqa: E731
        if anc < 0:
            return flat(words)
        head = rest_path(product, " ".join(words[:anc + 1]), chain[:anc + 1])
        return None if head is None else head + "_child_" + flat(words[anc + 1:])
    return None


def urn_for(product: str, key: str) -> str:
    """The full REST URN for a channel key (``system/ntp/ntpserver``)."""
    prefix = URN_PREFIX.get(product)
    return (prefix + key) if prefix and key else ""


def _top_object(product: str, cli_path: str, chain) -> tuple:
    """For a product whose nested objects are fields (FortiOS): the nearest
    ancestor that IS an endpoint, as ``(key, relative words)``."""
    words = cli_path.split()
    for i in range(len(words) - 1, 0, -1):
        if chain[i - 1] in OBJECT_KINDS:
            key = rest_path(product, " ".join(words[:i]), chain[:i])
            if key:
                return key, words[i:]
    return None, words


# ---------------------------------------------------------------------------
# evidence builders (contract-shaped documents; api_library.ingest stores them)
# ---------------------------------------------------------------------------

def _device_doc(device) -> dict | None:
    if not isinstance(device, dict):
        return None
    return {k: device.get(k) for k in ("appliance_id", "name", "serial", "model",
                                        "hw_type", "firmware_raw") if k in device}


def _doc(product, source, version, build, device, origin_ref, captured_at) -> dict:
    from . import firmware_versions as fv
    return {"product": product, "source": source,
            "captured_at": str(captured_at or "")[:19], "origin_ref": origin_ref or "",
            "device": _device_doc(device),
            "scope": {"kind": "build", "version": fv.normalize(version) or str(version or ""),
                      "build": build or ""},
            "healthy": True, "skip_reason": "", "endpoints": {}, "summary": {}}


def _fold_nested(ep: dict, rel_words: list, fields: dict, cli_id,
                 kind: str = KIND_TABLE) -> None:
    """FortiOS: a nested object becomes a field of its top-level endpoint
    (type = the object's kind, ``children`` = its field names)."""
    name = rel_words[0]
    spec = ep["fields"].setdefault(name, {"type": kind if len(rel_words) == 1 else None,
                                          "options": None, "children": [], "attrs": {}})
    if cli_id is not None:
        spec["attrs"].setdefault("cli_id", cli_id)
    if len(rel_words) == 1:
        spec["children"] = sorted(set(spec.get("children") or []) | set(fields))
    else:
        spec["children"] = sorted(set(spec.get("children") or []) | {rel_words[1]})


def evidence_from_cli_tree(product: str, version: str, build: str, tree_text: str,
                           device: dict | None, origin_ref: str, *,
                           captured_at: str = "", truncated: bool = False,
                           parsed: dict | None = None, min_objects: int | None = None) -> dict:
    """``tree`` output -> a ``cli_tree`` evidence document.

    One endpoint per CLI object that has a REST path on this product, keyed by
    that path; ``summary.objects[key]`` = ``{cli_path, kind, mkey, parent,
    cli_id}``. Stored ``healthy=False`` (kept, never folded) when the dump is
    truncated or too small to be a schema, or holds no ``system`` object.
    """
    doc = _doc(product, "cli_tree", version, build, device, origin_ref, captured_at)
    parsed = parsed if parsed is not None else parse_tree(tree_text)
    objects = parsed.get("objects") or {}
    endpoints: dict = {}
    summary_objects: dict = {}
    unmapped = []
    key_of = {}
    for path in sorted(objects, key=lambda p: (len(p.split()), p)):
        obj = objects[path]
        key = rest_path(product, path, obj["kind_chain"])
        if key is None:
            top, rel = _top_object(product, path, obj["kind_chain"])
            if top and top in endpoints:
                _fold_nested(endpoints[top], rel, obj["fields"],
                             obj.get("cli_id") if len(rel) == 1 else None, obj["kind"])
            else:
                unmapped.append(path)
            continue
        key_of[path] = key
        parent = key_of.get(obj.get("parent") or "", "")
        meta = {"cli_path": path, "kind": obj["kind"], "mkey": obj.get("mkey") or "",
                "parent": parent, "cli_id": obj.get("cli_id")}
        fields = {}
        for fname, spec in obj["fields"].items():
            fields[fname] = {"type": spec.get("type"), "options": spec.get("options"),
                             "attrs": dict(spec.get("attrs") or {})}
        ep = endpoints.get(key)
        if ep is None:
            endpoints[key] = {"urn": urn_for(product, key), "section": path.split()[0],
                              "verdict": "ok", "rows": None, "fields": fields,
                              "attrs": meta}
            summary_objects[key] = meta
        else:
            for f, spec in fields.items():
                ep["fields"].setdefault(f, spec)
    doc["endpoints"] = endpoints
    counts = dict(parsed.get("counts") or {})
    counts.update(endpoints=len(endpoints), unmapped=len(unmapped))
    doc["summary"] = {"objects": summary_objects, "format": parsed.get("format") or "",
                      "counts": counts, "unmapped": sorted(unmapped)[:200],
                      "path_rule": PATH_RULE_STATUS.get(product, "none")}
    reason = ""
    if truncated:
        reason = "the tree output was cut short (no prompt came back)"
    elif len(objects) < (MIN_TREE_OBJECTS if min_objects is None else min_objects):
        reason = ("the tree output holds %d objects (fewer than %d): a fragment, "
                  "not a schema" % (len(objects), MIN_TREE_OBJECTS if min_objects is None
                                    else min_objects))
    elif not any(p.split()[0] == "system" for p in objects):
        reason = "the tree output has no 'system' object: not a schema dump"
    elif not endpoints:
        reason = "no CLI object maps to a REST path on %s" % product
    if reason:
        doc["healthy"], doc["skip_reason"] = False, reason
    return doc


def evidence_from_cli_full(product: str, version: str, build: str, full_text: str,
                           device: dict | None, origin_ref: str, *,
                           captured_at: str = "", tree: dict | None = None,
                           lab: bool = False, min_objects: int | None = None) -> dict:
    """``show full-configuration`` -> a ``cli_full`` evidence document.

    Field NAMES per object, never values. With ``tree`` (the build's
    :func:`parse_tree` result) a name the tree does not list is marked
    ``attrs.hidden``, and objects take the tree's kind and key. ``lab=True``
    (a lab box with freshly created rows) records each field's first-row value
    as ``default`` with ``attrs.lab_default``; never set it for a production
    box. Unhealthy when the dump is empty, unbalanced, truncated, too small or
    has no ``config system`` block.
    """
    from .cli_coverage import parse_report
    doc = _doc(product, "cli_full", version, build, device, origin_ref, captured_at)
    blocks = _full_blocks(full_text)
    tree_objs = (tree or {}).get("objects") or {}
    values = parse_show_full_values(full_text) if lab else {}
    endpoints: dict = {}
    summary_objects: dict = {}
    unmapped, hidden_n = [], 0
    for path in sorted(blocks, key=lambda p: (len(p.split()), p)):
        blk = blocks[path]
        tobj = tree_objs.get(path)
        chain = tobj["kind_chain"] if tobj else _full_kind_chain(blk)
        key = rest_path(product, path, chain)
        tfields = set((tobj or {}).get("fields") or {})
        fields = {}
        for fname in sorted(blk.sets):
            spec: dict = {}
            if tree_objs and fname not in tfields:
                spec["attrs"] = {"hidden": True}
                hidden_n += 1
            lab_value = (values.get(path) or {}).get(fname) if lab else None
            if lab_value is not None and not _LAB_DEFAULT_SKIP.search(fname) \
                    and not str(lab_value).startswith("ENC "):
                spec["default"] = values[path][fname]
                spec.setdefault("attrs", {})["lab_default"] = True
            fields[fname] = spec
        if key is None:
            top, rel = _top_object(product, path, chain)
            if top and top in endpoints:
                _fold_nested(endpoints[top], rel, fields, None)
                endpoints[top]["fields"][rel[0]].pop("options", None)
                endpoints[top]["fields"][rel[0]].pop("type", None)
                endpoints[top]["fields"][rel[0]].pop("children", None)
                if not endpoints[top]["fields"][rel[0]]["attrs"]:
                    endpoints[top]["fields"][rel[0]].pop("attrs")
            else:
                unmapped.append(path)
            continue
        meta = {"cli_path": path, "kind": (tobj or {}).get("kind") or KIND_OBJECT,
                "mkey": (tobj or {}).get("mkey") or "",
                "parent": "", "cli_id": (tobj or {}).get("cli_id")}
        if tree_objs and tobj is None:
            meta["hidden_object"] = True
        parent_path = (tobj or {}).get("parent") or ""
        if parent_path:
            meta["parent"] = rest_path(product, parent_path,
                                       tree_objs[parent_path]["kind_chain"]) or ""
        ep = endpoints.get(key)
        if ep is None:
            endpoints[key] = {"urn": urn_for(product, key), "section": path.split()[0],
                              "verdict": "ok", "rows": None, "fields": fields,
                              "attrs": meta}
            summary_objects[key] = meta
        else:
            for f, spec in fields.items():
                ep["fields"].setdefault(f, spec)
    doc["endpoints"] = endpoints
    health = parse_report(full_text)
    doc["summary"] = {"objects": summary_objects,
                      "counts": {"blocks": len(blocks), "endpoints": len(endpoints),
                                 "fields": sum(len(e["fields"]) for e in endpoints.values()),
                                 "hidden": hidden_n, "unmapped": len(unmapped)},
                      "unmapped": sorted(unmapped)[:200], "tree_compared": bool(tree_objs),
                      "lab": bool(lab), "path_rule": PATH_RULE_STATUS.get(product, "none")}
    reason = ""
    if not (full_text or "").strip():
        reason = "the configuration dump is empty"
    elif not (health["balanced"] and health["ends_with_end"]):
        reason = "the configuration dump is truncated or unbalanced (%d unclosed)" \
                 % health["unclosed"]
    elif len(blocks) < (MIN_FULL_OBJECTS if min_objects is None else min_objects):
        reason = ("the configuration dump holds %d blocks (fewer than %d)"
                  % (len(blocks), MIN_FULL_OBJECTS if min_objects is None else min_objects))
    elif not any(p.split()[0] == "system" for p in blocks):
        reason = "the configuration dump has no 'config system' block"
    elif not endpoints:
        reason = "no configuration block maps to a REST path on %s" % product
    if reason:
        doc["healthy"], doc["skip_reason"] = False, reason
    return doc


__all__ = [
    "KIND_NAMESPACE", "KIND_TABLE", "KIND_SINGLETON", "KIND_OBJECT",
    "PATH_RULE_STATUS", "FORTIADC_RULE_UNVERIFIED", "URN_PREFIX",
    "MIN_TREE_OBJECTS", "MIN_FULL_OBJECTS",
    "parse_tree", "parse_show_full", "parse_show_full_values", "rest_path", "urn_for",
    "evidence_from_cli_tree", "evidence_from_cli_full",
]
