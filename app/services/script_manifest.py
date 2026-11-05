"""A script's own description of itself: the ``SATOM = {...}`` block.

A Script Library script used to live in two places: the code (``main.py``)
and its settings (form fields, connections, network, timeout), edited apart
in the UI and kept in ``meta.json``. A field renamed in one and not in the
other broke ``inputs["ip"]`` at run time. With a manifest the code says it
all, once::

    SATOM = {
        "name": "IP owner (NetBox)",
        "description": "Who owns an IP address, from NetBox.",
        "inputs": {
            "ip": {"label": "IP address", "type": "text", "required": True},
            "verbose": {"label": "Show every record", "type": "checkbox"},
        },
        "connections": ["ex-netbox"],
        "satom": ["devices"],          # read-only SATOM data (satom.devices())
        "network": "none",
        "timeout": 60,
    }

    from satom_script import inputs, connection, result

READ, NEVER RUN. The block is found in the syntax tree and evaluated with
``ast.literal_eval``: literals only (strings, numbers, booleans, None, lists,
dicts). Nothing of the script executes to read it, so a manifest can be read
on the web side, in the SATOM Builder and in the local developer kit alike.

When ``main.py`` carries the block, saving the draft takes the form, the
connections, the SATOM data, the network mode, the timeout, the credentials,
the name and the description FROM THE CODE (``script_library.save_draft``);
the editor shows them read-only. Who may run the script (``audience``) stays
an administrator's setting: it is not the author's to grant.

PURE: no Flask, no database, no SATOM import. The developer kit ships this
file next to ``satom_script.py``.
"""
from __future__ import annotations

import ast
import keyword
import re
from typing import Any

#: The name of the block.
NAME = "SATOM"
#: The read-only SATOM data a script may declare (``satom.<op>()`` in the SDK).
#: Each one answers with what the matching Plugin Studio step answers, for the
#: person who runs the script and in the ADOM it was started from.
SATOM_OPS = ("devices", "lb_lookup", "dns_lookup")
#: Keys of the block.
KEYS = ("name", "description", "inputs", "connections", "satom", "network",
        "timeout", "credentials", "id")
#: Keys of one input. Database fields (lookup / lookup_multi / dataset) carry
#: their own keys, checked by ``db_lookup.clean_field``.
INPUT_KEYS = ("type", "label", "required", "default", "help", "options")
DB_INPUT_KEYS = ("query", "value_col", "label_col")

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,47}$")


class ManifestError(ValueError):
    """A ``SATOM = {...}`` block that cannot be used. ``line`` is 1-based."""

    def __init__(self, message: str, line: int = 0):
        super().__init__(message)
        self.line = line


def find(source: str) -> ast.AST | None:
    """The value node of the module-level ``SATOM = ...`` assignment, or None.

    A syntax error in the file is not a manifest problem (the editor reports
    it already): None."""
    try:
        tree = ast.parse(source or "")
    except (SyntaxError, ValueError):
        return None
    found = None
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
        if any(isinstance(t, ast.Name) and t.id == NAME for t in targets):
            if found is not None:
                raise ManifestError("%s is assigned twice; keep one block" % NAME,
                                    getattr(node, "lineno", 0))
            found = node.value
    return found


def parse(source: str) -> dict | None:
    """The block as a dict, checked; None when the file has none.
    Raises ManifestError (with the line) when it is not usable."""
    node = find(source)
    if node is None:
        return None
    line = getattr(node, "lineno", 0)
    try:
        raw = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        raise ManifestError("%s must be written with literals only (strings, numbers, "
                            "True/False/None, lists and dicts): it is read, never run"
                            % NAME, line) from None
    return check(raw, line)


def check(raw: Any, line: int = 0) -> dict:
    """The block normalised. The shapes only: ``script_library`` applies its
    own limits (field types, names, counts) to the result."""
    if not isinstance(raw, dict):
        raise ManifestError("%s must be a dict" % NAME, line)
    unknown = sorted(str(k) for k in raw if k not in KEYS)
    if unknown:
        raise ManifestError("%s has unknown key(s): %s (allowed: %s)"
                            % (NAME, ", ".join(unknown), ", ".join(KEYS)), line)
    out: dict[str, Any] = {}
    for k in ("name", "description", "network", "id"):
        if k in raw:
            if not isinstance(raw[k], str):
                raise ManifestError("%s[%r] must be text" % (NAME, k), line)
            out[k] = raw[k].strip()
    if "id" in out and not _ID_RE.match(out["id"]):
        raise ManifestError("%s['id'] %r: lowercase letters, digits, - and _, 2 to 48 "
                            "characters" % (NAME, out["id"]), line)
    if "timeout" in raw:
        t = raw["timeout"]
        if isinstance(t, bool) or not isinstance(t, int):
            raise ManifestError("%s['timeout'] is a number of seconds" % NAME, line)
        out["timeout"] = t
    out["fields"] = _inputs(raw.get("inputs"), line) if "inputs" in raw else []
    for k in ("connections", "satom"):
        v = raw.get(k, [])
        if not isinstance(v, (list, tuple)) or not all(isinstance(x, str) for x in v):
            raise ManifestError("%s[%r] is a list of names" % (NAME, k), line)
        out[k] = [x.strip() for x in v if x.strip()]
    bad = [x for x in out["satom"] if x not in SATOM_OPS]
    if bad:
        raise ManifestError("%s['satom']: unknown %s (one of: %s)"
                            % (NAME, ", ".join(bad), ", ".join(SATOM_OPS)), line)
    out["credentials"] = _credentials(raw.get("credentials", []), line)
    return out


def _inputs(raw: Any, line: int) -> list[dict]:
    if not isinstance(raw, dict):
        raise ManifestError("%s['inputs'] is a dict of name: field" % NAME, line)
    fields = []
    for name, spec in raw.items():
        if not isinstance(name, str) or not name.isidentifier() or keyword.iskeyword(name):
            raise ManifestError("input %r is not a valid variable name" % (name,), line)
        if isinstance(spec, str):
            spec = {"label": spec}
        if not isinstance(spec, dict):
            raise ManifestError("input %r: a dict like {'label': ..., 'type': 'text'} "
                                "(or just its label)" % name, line)
        ftype = str(spec.get("type") or "text")
        allowed = INPUT_KEYS + (DB_INPUT_KEYS if ftype in ("lookup", "lookup_multi",
                                                           "dataset") else ())
        unknown = sorted(str(k) for k in spec if k not in allowed)
        if unknown:
            raise ManifestError("input %r has unknown key(s): %s (allowed: %s)"
                                % (name, ", ".join(unknown), ", ".join(allowed)), line)
        f = dict(spec)
        f["name"] = name
        f["type"] = ftype
        fields.append(f)
    return fields


def _credentials(raw: Any, line: int) -> list[dict]:
    if not isinstance(raw, (list, tuple)):
        raise ManifestError("%s['credentials'] is a list" % NAME, line)
    out = []
    for c in raw:
        if isinstance(c, str):
            c = {"name": c}
        if not isinstance(c, dict):
            raise ManifestError("a credential is a name or {'name', 'kind', 'label'}", line)
        out.append(dict(c))
    return out


def settings(man: dict) -> dict:
    """The parts of ``meta.json`` a manifest decides (script_library shape)."""
    out = {"fields": man.get("fields") or [], "connections": man.get("connections") or [],
           "satom": man.get("satom") or [], "credentials": man.get("credentials") or []}
    for k in ("name", "description", "network", "timeout"):
        if k in man and man[k] not in ("", None):
            out[k] = man[k]
    return out


def problems(files: dict, entry: str = "main.py") -> list[dict]:
    """Editor problems (``{file, line, message}``) of the entry file's block."""
    src = (files or {}).get(entry)
    if not isinstance(src, str):
        return []
    try:
        parse(src)
    except ManifestError as exc:
        return [{"file": entry, "line": exc.line or 1, "message": str(exc)}]
    return []


def example(fields: list[dict], connections: list[str], satom: list[str] = (),
            name: str = "", network: str = "none", timeout: int = 60) -> str:
    """A ``SATOM = {...}`` block that says what *fields* and *connections*
    say -- for a script that has none yet ("Move the form into the code")."""
    def lit(v):
        return repr(v)
    lines = ["SATOM = {"]
    if name:
        lines.append("    \"name\": %s," % lit(name))
    lines.append("    \"inputs\": {")
    for f in fields or []:
        spec = {"label": f.get("label") or f["name"], "type": f.get("type") or "text"}
        for k in ("required", "help", "options", "default"):
            if f.get(k) not in (None, "", False, []):
                spec[k] = f[k]
        for k in DB_INPUT_KEYS:
            if f.get(k) not in (None, "", [], {}):
                spec[k] = f[k]
        lines.append("        %s: %s," % (lit(f["name"]), lit(spec)))
    lines.append("    },")
    lines.append("    \"connections\": %s," % lit(list(connections or [])))
    if satom:
        lines.append("    \"satom\": %s," % lit(list(satom)))
    lines.append("    \"network\": %s," % lit(network or "none"))
    lines.append("    \"timeout\": %d," % int(timeout or 60))
    lines.append("}")
    return "\n".join(lines) + "\n"
