"""Process ⇄ XML — a procedure as one file.

WHY A FILE AT ALL, WHEN THERE IS AN EDITOR
------------------------------------------
A recovery plan is written down long before the night it is needed, and rarely
by the person sitting in this console. It arrives as a customer runbook, it is
kept in version control next to the rest of the installation's documentation,
and it has to travel from the lab install to the production one. Drawing it
again by hand in each console is how two installations end up with two
different plans that share a name — and the difference is discovered during the
incident.

THE IMPORTER IS NOT A SECOND DOOR
---------------------------------
Nothing here writes a row. This module turns bytes into the SAME graph dict the
editor posts, and the view hands that dict to
:func:`app.services.process_kinds.validate_graph` before anything is stored —
the same gate, in the same order. A ``factoryreset`` inside a console step is
refused on import exactly as it is refused on save.

That is not belt-and-braces: an importer that wrote straight to the tables
would be the most attractive way past the gates the editor cannot be talked out
of, precisely because a file looks like data rather than like code.

PARAMETERS ARE ELEMENTS, NEVER ATTRIBUTES
-----------------------------------------
An XML processor is *required* to normalise attribute values: every LITERAL
newline or tab inside an attribute becomes a space before the parser hands it
over (XML 1.0 §3.3.3). Only an escaped ``&#10;`` survives it — so in an
attribute the READABLE way to write a console script is the lossy one, and it
loses silently. ``<step script="config system global<newline>set x y">`` arrives
as ONE line: not the script the author wrote, and quite possibly a different
command with a different classification. Multi-line parameters (console
scripts, hook payloads, gate prompts) are exactly what this format exists to
carry, so every parameter is an element and the loss is impossible rather than
unlikely. ``test_process_xml`` pins both halves of that rule so the reason
survives the next reader.

WHAT IS DELIBERATELY NOT SUPPORTED
----------------------------------
draw.io, BPMN and Visio files are DETECTED AND NAMED, never half-read. A drawn
box carries a shape and a caption; it does not carry the step kind or the
parameters that make a step runnable. Importing one would produce a diagram
that looks like the operator's plan and cannot execute a single check — a
shape-only import is worse than no import, because it looks like it worked.
"""
from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET

from ..models_process import BRANCHES
from . import process_kinds as pk

#: Root element of a SATOM process file.
ROOT_TAG = "satom-process"

#: Refused above this, before any parsing. Larger than the editor's 512 KB JSON
#: cap because the same graph is bulkier in XML — the two guard the same thing
#: (a payload this size is not a procedure) at the size their own format needs.
MAX_XML = 1024 * 1024

#: Any DOCTYPE is refused. ``xml.etree`` does not fetch external entities, but
#: it DOES expand internal ones, which is the whole of the "billion laughs"
#: amplification; a process file has no legitimate use for a DTD. Matched on
#: the raw bytes, so a DOCTYPE inside a comment is refused too: a false refusal
#: costs one confused operator, and the other direction costs the worker.
_DOCTYPE_RE = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)

#: Root local-names of the formats an operator is most likely to try, and the
#: tool to name back at them.
_FOREIGN = {
    "mxfile": "draw.io / diagrams.net",
    "mxGraphModel": "draw.io / diagrams.net",
    "definitions": "BPMN 2.0",
    "VisioDocument": "Microsoft Visio",
    "svg": "an SVG drawing",
}

_TRUE = {"1", "yes", "y", "true", "on"}
_FALSE = {"0", "no", "n", "false", "off"}

#: Attributes each element understands. Anything else is reported rather than
#: ignored — a mistyped ``brach="fail"`` silently becoming ``always`` is a
#: recovery plan that takes the wrong arrow on the one day it runs.
_ATTRS = {
    ROOT_TAG: {"key", "name", "enabled"},
    "step": {"key", "kind", "label", "x", "y"},
    "arrow": {"from", "to", "branch"},
    "param": {"name"},
    "adom": set(),
    "description": set(),
}


@dataclass
class ProcessDoc:
    """Everything a file says about a process. Nothing installation-specific.

    ADOM keys are carried as written; whether this installation HAS an ADOM by
    that name is a database question and belongs to the view, which already
    owns the list. Resolving it here would make the parser untestable without
    an app context and would put a second author on "which consoles exist".
    """

    key: str = ""
    name: str = ""
    description: str = ""
    products: list = field(default_factory=list)
    enabled: bool = True
    graph: dict = field(default_factory=lambda: {"nodes": [], "edges": []})


# ---------------------------------------------------------------------------
# reading
# ---------------------------------------------------------------------------

def _local(tag: str) -> str:
    """``{urn:x}definitions`` -> ``definitions``."""
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _value(el) -> str:
    """The text of an element, indented XML made harmless.

    A hand-written file indents a multi-line script to match its surroundings;
    an exported one does not indent it at all. Both must yield the same script,
    so the COMMON indent is removed and relative indentation is kept — a line
    that is deeper than its siblings stays deeper, because in a CLI script that
    difference can be the author's.
    """
    raw = el.text or ""
    if "\n" not in raw:
        return raw.strip()
    return textwrap.dedent(raw.strip("\n")).rstrip()


def _attr_errors(el, where: str) -> list[str]:
    known = _ATTRS.get(_local(el.tag), set())
    return ["%s has an attribute %r that means nothing here (allowed: %s)."
            % (where, a, ", ".join(sorted(known)) or "none")
            for a in sorted(el.keys()) if a not in known]


def _bool(raw: str, where: str, errs: list[str], default: bool) -> bool:
    txt = (raw or "").strip().lower()
    if not txt:
        return default
    if txt in _TRUE:
        return True
    if txt in _FALSE:
        return False
    # NOT defaulted. ``enabled="maybe"`` read as False publishes a process
    # nobody can run and says nothing; read as True it does the opposite.
    errs.append("%s must be yes or no, not %r." % (where, raw))
    return default


def _int(raw: str, where: str, errs: list[str]) -> int:
    txt = (raw or "").strip()
    if not txt:
        return 0
    try:
        return int(txt)
    except ValueError:
        errs.append("%s must be a whole number, not %r." % (where, raw))
        return 0


def read_xml(data: bytes) -> tuple[ProcessDoc | None, list[str]]:
    """``(doc, errors)`` — never raises, and never returns a half-read doc.

    Structural problems are collected and returned TOGETHER, like
    ``validate_graph``: fixing a file one error per upload is a game of
    whack-a-mole against a text editor. A fatal problem (not XML at all, the
    wrong format, too big) returns ``(None, [one message])``, because
    everything downstream of it would be a guess.
    """
    if not data:
        return None, ["The file is empty."]
    if len(data) > MAX_XML:
        return None, ["The file is %d KB; a process file is refused above %d KB."
                      % (len(data) // 1024, MAX_XML // 1024)]
    if _DOCTYPE_RE.search(data):
        return None, ["This file declares a DOCTYPE or an ENTITY. SATOM refuses "
                      "those: entity expansion is how a small XML file becomes "
                      "a large one in memory, and a process file has no use "
                      "for a DTD."]
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        return None, ["This is not readable XML: %s" % exc]

    tag = _local(root.tag)
    if tag != ROOT_TAG:
        tool = _FOREIGN.get(tag)
        if tool:
            return None, [
                "This is %s, and SATOM cannot read one. A drawn box carries a "
                "shape and a caption; it does not carry the step kind or the "
                "parameters a step needs to run — which URL, which command, "
                "which outcome each arrow follows. Export a process from SATOM "
                "to see the format it does read." % tool]
        return None, ["The root element is <%s>; a SATOM process file starts "
                      "with <%s>." % (tag or "?", ROOT_TAG)]

    errs: list[str] = []
    doc = ProcessDoc()
    errs.extend(_attr_errors(root, "<%s>" % ROOT_TAG))

    doc.key = (root.get("key") or "").strip().lower()
    if not doc.key:
        errs.append("<%s> needs a key attribute." % ROOT_TAG)
    elif not pk.KEY_RE.match(doc.key):
        errs.append("%r is not a usable process key (lowercase letters, digits, "
                    "- and _, up to 64 characters)." % doc.key)

    doc.name = (root.get("name") or "").strip()
    if not doc.name:
        errs.append("<%s> needs a name attribute." % ROOT_TAG)
    elif len(doc.name) > 160:
        errs.append("The process name is %d characters; the limit is 160."
                    % len(doc.name))

    doc.enabled = _bool(root.get("enabled", ""), "enabled", errs, True)

    seen_sections: set = set()
    nodes: list = []
    edges: list = []
    for child in root:
        name = _local(child.tag)
        if not name:                       # a comment or a processing instruction
            continue
        if name in seen_sections:
            errs.append("There are two <%s> sections; a process file has one."
                        % name)
            continue
        seen_sections.add(name)
        if name == "description":
            errs.extend(_attr_errors(child, "<description>"))
            doc.description = _value(child)
        elif name == "adoms":
            doc.products = _read_adoms(child, errs)
        elif name == "steps":
            nodes = _read_steps(child, errs)
        elif name == "arrows":
            edges = _read_arrows(child, errs)
        else:
            # Reported, not skipped: a newer SATOM writing a section this one
            # does not understand means the file says something that would be
            # dropped, and a plan silently missing a part of itself is the one
            # outcome an import must never produce.
            errs.append("<%s> is not part of a process file (it holds "
                        "<description>, <adoms>, <steps> and <arrows>)." % name)

    if "steps" not in seen_sections:
        errs.append("The file has no <steps> section.")

    doc.graph = {"nodes": nodes, "edges": edges}
    return doc, errs


def _read_adoms(el, errs: list[str]) -> list:
    out: list = []
    errs.extend(_attr_errors(el, "<adoms>"))
    for child in el:
        name = _local(child.tag)
        if not name:
            continue
        if name != "adom":
            errs.append("<adoms> holds <adom> elements, not <%s>." % name)
            continue
        errs.extend(_attr_errors(child, "<adom>"))
        key = _value(child).lower()
        if not key:
            errs.append("An <adom> element is empty.")
        elif key not in out:
            out.append(key)
    return out


def _read_steps(el, errs: list[str]) -> list:
    out: list = []
    errs.extend(_attr_errors(el, "<steps>"))
    for child in el:
        name = _local(child.tag)
        if not name:
            continue
        if name != "step":
            errs.append("<steps> holds <step> elements, not <%s>." % name)
            continue
        key = (child.get("key") or "").strip()
        where = "Step %r" % key if key else "A <step> element"
        errs.extend(_attr_errors(child, where))
        if not key:
            errs.append("A <step> element has no key attribute.")
        kind = (child.get("kind") or "").strip()
        if not kind:
            errs.append("%s has no kind attribute." % where)
        label = (child.get("label") or "").strip()
        if len(label) > 160:
            # Refused rather than cut: a label is what the run's report calls
            # this step, and a plan whose steps were quietly renamed on the way
            # in is a plan that no longer matches the runbook it came from.
            errs.append("%s has a label of %d characters; the limit is 160."
                        % (where, len(label)))
        out.append({"key": key, "kind": kind, "label": label,
                    "params": _read_params(child, where, errs),
                    "x": _int(child.get("x", ""), "%s: x" % where, errs),
                    "y": _int(child.get("y", ""), "%s: y" % where, errs)})
    return out


def _read_params(step_el, where: str, errs: list[str]) -> dict:
    params: dict = {}
    for child in step_el:
        name = _local(child.tag)
        if not name:
            continue
        if name != "param":
            errs.append("%s holds <param> elements, not <%s>." % (where, name))
            continue
        errs.extend(_attr_errors(child, "%s: <param>" % where))
        pname = (child.get("name") or "").strip()
        if not pname:
            errs.append("%s has a <param> with no name attribute." % where)
            continue
        if pname in params:
            # Which one wins is not a question a file gets to leave open.
            errs.append("%s sets %r twice." % (where, pname))
            continue
        params[pname] = _value(child)
    return params


def _read_arrows(el, errs: list[str]) -> list:
    out: list = []
    errs.extend(_attr_errors(el, "<arrows>"))
    for child in el:
        name = _local(child.tag)
        if not name:
            continue
        if name != "arrow":
            errs.append("<arrows> holds <arrow> elements, not <%s>." % name)
            continue
        src = (child.get("from") or "").strip()
        dst = (child.get("to") or "").strip()
        where = "The arrow %s -> %s" % (src or "?", dst or "?")
        errs.extend(_attr_errors(child, where))
        if not src or not dst:
            errs.append("An <arrow> needs both a from and a to attribute.")
        branch = (child.get("branch") or "always").strip()
        if branch not in BRANCHES:
            errs.append("%s follows %r, which is not an outcome (%s)."
                        % (where, branch, ", ".join(BRANCHES)))
        out.append({"src": src, "dst": dst, "branch": branch})
    return out


# ---------------------------------------------------------------------------
# writing
# ---------------------------------------------------------------------------

def to_xml(*, key: str, name: str, description: str = "", products=(),
           enabled: bool = True, graph: dict | None = None) -> str:
    """The file :func:`read_xml` reads back unchanged.

    Round-trip is a property the guards assert, not a hope: an importer whose
    exporter drops a field is an importer that silently edits every plan that
    passes through it.
    """
    graph = graph or {"nodes": [], "edges": []}
    root = ET.Element(ROOT_TAG, {"key": str(key), "name": str(name),
                                 "enabled": "yes" if enabled else "no"})
    if description:
        ET.SubElement(root, "description").text = str(description)

    adoms = ET.SubElement(root, "adoms")
    for prod in products or []:
        ET.SubElement(adoms, "adom").text = str(prod)

    steps = ET.SubElement(root, "steps")
    for node in graph.get("nodes") or []:
        el = ET.SubElement(steps, "step", {
            "key": str(node.get("key") or ""),
            "kind": str(node.get("kind") or ""),
            "label": str(node.get("label") or ""),
            "x": str(int(node.get("x") or 0)),
            "y": str(int(node.get("y") or 0))})
        for pname, value in _ordered_params(node):
            ET.SubElement(el, "param", {"name": pname}).text = value

    arrows = ET.SubElement(root, "arrows")
    for edge in graph.get("edges") or []:
        ET.SubElement(arrows, "arrow", {
            "from": str(edge.get("src") or ""),
            "to": str(edge.get("dst") or ""),
            "branch": str(edge.get("branch") or "always")})

    ET.indent(root, space="  ")
    body = ET.tostring(root, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n%s\n' % body


def _ordered_params(node: dict):
    """Catalogue order first, then whatever else the node carries.

    Catalogue order so a file reads like the form an operator already knows.
    "Whatever else" because a parameter this build does not recognise is still
    the author's, and an exporter that drops what it does not understand turns
    every round-trip into a quiet edit.

    Empty values are omitted: absent and blank mean the same thing to every
    executor, and printing thirty empty elements buries the three that matter.
    """
    params = node.get("params") or {}
    kind = pk.get_kind(str(node.get("kind") or ""))
    order = [p.name for p in (kind.params if kind else ())]
    for extra in sorted(params):
        if extra not in order:
            order.append(extra)
    out = []
    for pname in order:
        value = params.get(pname, "")
        value = "" if value is None else str(value)
        if value.strip():
            out.append((pname, value))
    return out
