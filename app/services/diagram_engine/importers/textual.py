"""Mermaid flowchart and Graphviz DOT readers (text formats without coordinates).

Both are parsed into one small graph structure and laid out by a deterministic
layered layout written here (no layout engine is available in the sandbox):
longest-path layering after reversing the back edges that close cycles,
barycentre ordering sweeps, cluster members kept contiguous, direction
TB/LR/BT/RL. Sizes come from label length. The same input always yields the
same coordinates.

Mermaid subset: ``flowchart``/``graph`` + direction; node shapes ``[ ] ( ) (( ))
{ } {{ }} [( )] ([ ]) [[ ]] >] [/ /] [\\ \\] [/ \\] [\\ /]``; links ``-->  ---
-.-> ==> --x --o <-->`` with ``|text|`` or ``-- text -->``; chains and ``A & B``;
``subgraph ... end`` (nested, linkable); ``classDef``/``class``/``:::``/``style``
(fill, stroke, stroke-width, color, stroke-dasharray); ``%%`` comments.

DOT subset: ``graph``/``digraph``/``strict``; node, edge and graph attribute
statements; node/edge attribute lists (label, shape, color, fillcolor, style,
fontcolor, penwidth, dir, arrowhead, arrowtail); ``subgraph cluster_*`` as
containers; edge chains and subgraph endpoints; quoted/HTML ids; comments;
``rankdir``. Ports are ignored.
"""
from __future__ import annotations

import html as _html
import re

from .. import detect as _detect
from .. import model
from . import (ImportFailed, Warnings, doc_name, guarded, make_document,
               require_bytes)

MAX_TEXT_BYTES = 1024 * 1024
MAX_SUB_DEPTH = 24
MAX_TOKENS = 600000

NAMED = {"white": "#FFFFFF", "black": "#000000", "red": "#FF0000", "green": "#008000", "blue": "#0000FF",
         "yellow": "#FFFF00", "orange": "#FFA500", "purple": "#800080", "gray": "#808080", "grey": "#808080",
         "pink": "#FFC0CB", "brown": "#A52A2A", "cyan": "#00FFFF", "magenta": "#FF00FF", "gold": "#FFD700",
         "lightblue": "#ADD8E6", "lightgrey": "#D3D3D3", "lightgray": "#D3D3D3", "lightgreen": "#90EE90",
         "lightyellow": "#FFFFE0", "lightpink": "#FFB6C1", "darkgreen": "#006400", "darkblue": "#00008B",
         "darkred": "#8B0000", "navy": "#000080", "teal": "#008080", "olive": "#808000", "maroon": "#800000",
         "lime": "#00FF00", "silver": "#C0C0C0", "tomato": "#FF6347", "salmon": "#FA8072", "khaki": "#F0E68C",
         "coral": "#FF7F50", "violet": "#EE82EE", "beige": "#F5F5DC", "ivory": "#FFFFF0", "transparent": "none"}


def _color(v):
    if not v:
        return None
    v = str(v).strip()
    m = re.fullmatch(r"#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})", v)
    if m:
        h = m.group(1)
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        return "#" + h[:6].upper()
    return NAMED.get(v.lower().replace(" ", ""))


# ------------------------------------------------------------------ the graph

class Graph:
    def __init__(self, fmt: str, directed: bool = True):
        self.fmt, self.directed = fmt, directed
        self.direction = "TB"
        self.name = ""
        self.nodes: dict = {}      # id -> node dict
        self.edges: list = []
        self.clusters: dict = {}   # id -> {"id","label","parent","style"}
        self.warn = Warnings()

    def node(self, nid: str, cluster: str = "") -> dict:
        n = self.nodes.get(nid)
        if n is None:
            if len(self.nodes) >= model.MAX_ELEMENTS:
                raise ImportFailed("The diagram has more than %d nodes." % model.MAX_ELEMENTS)
            n = self.nodes[nid] = {"id": nid, "label": nid, "shape": "rect", "kind": "shape", "style": {},
                                   "cluster": cluster, "hidden": False, "native": ""}
        elif cluster and not n["cluster"]:
            n["cluster"] = cluster
        return n

    def add_edge(self, src: str, dst: str, **kw) -> None:
        if len(self.edges) >= model.MAX_CONNECTORS:
            raise ImportFailed("The diagram has more than %d links." % model.MAX_CONNECTORS)
        e = {"src": src, "dst": dst, "label": "", "dashed": False, "width": 1.0, "color": None,
             "start": "none", "end": "arrow", "hidden": False}
        e.update(kw)
        self.edges.append(e)


# ---------------------------------------------------------------- Mermaid

OPENERS = [("(((", ")))", "ellipse"), ("[[", "]]", "process"), ("[(", ")]", "cylinder"),
           ("((", "))", "ellipse"), ("([", "])", "terminator"), ("{{", "}}", "hexagon"),
           ("[/", None, "parallelogram"), ("[\\", None, "parallelogram"),
           ("{", "}", "diamond"), ("(", ")", "round"), ("[", "]", "rect"), (">", "]", "note")]
_ID_RE = re.compile(r"[\wÀ-￿]+(?:-(?=[\wÀ-￿])[\wÀ-￿]+)*")
_INLINE_RE = re.compile(
    r"(?P<b><)?(?P<o>--|==|-\.)[ \t]+(?P<t>(?:(?!-->|---|==>|===|\.->|-\.-)[^\n])+?)[ \t]+"
    r"(?P<c>-{2,}[>xo]?|={2,}[>xo]?|\.-+>?|\.+->?)")
_PLAIN_RE = re.compile(r"(?P<b><|x(?=-)|o(?=-))?(?P<c>-{2,}[>xo]?|={2,}[>xo]?|-\.+-?>?|~{3,})")
_STYLE_PAIR_RE = re.compile(r"\s*([\w-]+)\s*:\s*([^,]+)")


def _m_text(raw: str) -> str:
    s = raw.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    if len(s) >= 2 and s[0] == "`" and s[-1] == "`":
        s = s[1:-1]
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.I)
    s = re.sub(r"#(\w+);", lambda m: {"quot": '"', "amp": "&", "lt": "<", "gt": ">", "nbsp": " "}.get(
        m.group(1), chr(int(m.group(1))) if m.group(1).isdigit() and int(m.group(1)) < 0x110000 else ""), s)
    return _html.unescape(re.sub(r"<[^<>]{0,200}>", "", s)).strip()


def _split_statements(text: str) -> list:
    out, cur, depth, quote = [], [], 0, False
    for ch in text:
        if ch == '"':
            quote = not quote
        if not quote:
            if ch in "[({":
                depth += 1
            elif ch in "])}":
                depth = max(0, depth - 1)
            if ch == "\n" or (ch == ";" and depth == 0):
                out.append("".join(cur).strip())
                cur = []
                continue
        cur.append(ch)
    out.append("".join(cur).strip())
    return [s for s in out if s]


def _style_props(spec: str) -> dict:
    out = {}
    for k, v in _STYLE_PAIR_RE.findall(spec or ""):
        out[k.strip().lower()] = v.strip()
    return out


def _apply_css(style: dict, props: dict) -> None:
    f, s, c = _color(props.get("fill")), _color(props.get("stroke")), _color(props.get("color"))
    if f:
        style["fill"] = f
    if s:
        style["stroke"] = s
    if c:
        style["font_color"] = c
    sw = re.match(r"([\d.]+)", props.get("stroke-width", ""))
    if sw:
        style["stroke_width"] = min(20.0, float(sw.group(1)))
    if props.get("stroke-dasharray"):
        style["dashed"] = True


def _parse_node_ref(s: str, pos: int, g: Graph, sub: str):
    m = _ID_RE.match(s, pos)
    if not m:
        return None, pos
    nid, pos = m.group(0), m.end()
    shape, label = None, None
    for op, close, shp in OPENERS:
        if not s.startswith(op, pos):
            continue
        start = pos + len(op)
        if start < len(s) and s[start] == '"':
            q = s.find('"', start + 1)
            if q < 0:
                break
            body, after = s[start:q + 1], q + 1
            tail = s[after:].lstrip()
            consumed = len(s[after:]) - len(tail)
            if close is None:
                cl = next((c for c in ("/]", "\\]") if tail.startswith(c)), None)
            else:
                cl = close if tail.startswith(close) else None
            if cl is None:
                continue
            end = after + consumed + len(cl)
        elif close is None:
            hit = re.search(r"[/\\]\]", s[start:])
            if not hit:
                continue
            body, cl = s[start:start + hit.start()], hit.group(0)
            end = start + hit.end()
        else:
            k = s.find(close, start)
            if k < 0:
                continue
            body, cl, end = s[start:k], close, k + len(close)
        if close is None:
            shp = ("trapezoid" if (op == "[/" and cl == "\\]") or (op == "[\\" and cl == "/]") else "parallelogram")
        shape, label, pos = shp, _m_text(body), end
        break
    cls = None
    if s.startswith(":::", pos):
        cm = re.match(r":::([\w-]+)", s[pos:])
        if cm:
            cls, pos = cm.group(1), pos + cm.end()
    return (nid, shape, label, cls), pos


def _register(g: Graph, ref, sub: str, classes: dict) -> str:
    nid, shape, label, cls = ref
    if nid in g.clusters_by_id:       # a link to a whole subgraph
        return "cluster:" + nid
    n = g.node(nid, sub)
    if shape:
        n["shape"] = shape
    if label is not None:
        n["label"] = label
    if cls:
        classes.setdefault("__apply__", []).append((nid, cls))
    return nid


def parse_mermaid(text: str) -> Graph:
    g = Graph("mermaid")
    g.clusters_by_id = {}
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end > 0:
            text = text[end + 4:]
    lines = []
    for ln in text.split("\n"):
        i = ln.find("%%")
        lines.append(ln[:i] if i >= 0 else ln)
    stmts = _split_statements("\n".join(lines))
    if not stmts:
        raise ImportFailed("The Mermaid source is empty.")
    head = re.match(r"(?i)(flowchart|graph)(?:\s+(TD|TB|BT|RL|LR))?\s*$", stmts[0])
    if not head:
        raise ImportFailed("Only Mermaid flowcharts are supported (the file must start with 'flowchart' or 'graph').")
    d = (head.group(2) or "TB").upper()
    g.direction = "TB" if d == "TD" else d
    classes: dict = {}
    stack: list = []
    for st in stmts[1:]:
        low = st.lower()
        if low.startswith("subgraph") and (len(st) == 8 or st[8].isspace()):
            rest = st[8:].strip()
            m = re.match(r"([^\s\[]+)\s*\[(.*)\]\s*$", rest)
            if m:
                cid, title = m.group(1), _m_text(m.group(2))
            else:
                title = _m_text(rest)
                cid = re.sub(r"[^\w]", "_", rest.strip('"')) or "subgraph"
            base, n = cid, 2
            while cid in g.clusters:
                cid, n = "%s_%d" % (base, n), n + 1
            if len(stack) >= MAX_SUB_DEPTH:
                raise ImportFailed("Subgraphs are nested more than %d levels deep." % MAX_SUB_DEPTH)
            g.clusters[cid] = {"id": cid, "label": title or cid, "parent": stack[-1] if stack else "", "style": {}}
            g.clusters_by_id[cid] = True
            stack.append(cid)
            continue
        if low == "end":
            if stack:
                stack.pop()
            continue
        first = low.split(None, 1)[0] if low.split() else ""
        if first == "direction":
            continue
        if first == "classdef":
            m = re.match(r"(?i)classDef\s+([\w,-]+)\s+(.*)$", st)
            if m:
                for name in m.group(1).split(","):
                    classes[name] = _style_props(m.group(2))
            continue
        if first == "class":
            m = re.match(r"(?i)class\s+([^\s]+)\s+([\w-]+)\s*$", st)
            if m:
                for nid in m.group(1).split(","):
                    classes.setdefault("__apply__", []).append((nid.strip(), m.group(2)))
            continue
        if first == "style":
            m = re.match(r"(?i)style\s+([^\s]+)\s+(.*)$", st)
            if m:
                classes.setdefault("__style__", []).append((m.group(1), _style_props(m.group(2))))
            continue
        if first in ("linkstyle", "click", "accdescr", "acctitle", "title"):
            g.warn.once("mm_ignored", "Mermaid link styles, click handlers and titles were ignored.")
            continue
        _parse_chain(st, g, stack[-1] if stack else "", classes)
    for nid, cls in classes.get("__apply__", []):
        props = classes.get(cls)
        if props is None:
            continue
        if nid in g.nodes:
            _apply_css(g.nodes[nid]["style"], props)
        elif nid in g.clusters:
            _apply_css(g.clusters[nid]["style"], props)
    for nid, props in classes.get("__style__", []):
        if nid in g.nodes:
            _apply_css(g.nodes[nid]["style"], props)
        elif nid in g.clusters:
            _apply_css(g.clusters[nid]["style"], props)
    if not g.nodes:
        raise ImportFailed("The Mermaid flowchart contains no nodes.")
    return g


def _parse_group(s: str, pos: int, g: Graph, sub: str, classes: dict):
    """``A & B`` -> ([ids], pos); ([], pos) if there is no node at *pos*."""
    ids = []
    while True:
        while pos < len(s) and s[pos] in " \t":
            pos += 1
        ref, npos = _parse_node_ref(s, pos, g, sub)
        if ref is None:
            return ids, pos
        ids.append(_register(g, ref, sub, classes))
        pos = npos
        k = pos
        while k < len(s) and s[k] in " \t":
            k += 1
        if k < len(s) and s[k] == "&":
            pos = k + 1
            continue
        return ids, pos


def _parse_chain(s: str, g: Graph, sub: str, classes: dict) -> None:
    pos, prev, pending = 0, None, None
    while True:
        ids, pos = _parse_group(s, pos, g, sub, classes)
        if not ids:
            g.warn.add("Mermaid: could not read %r; skipped." % s[:60])
            return
        if prev is not None and pending is not None:
            for a in prev:
                for b in ids:
                    g.add_edge(a, b, **pending)
        prev = ids
        while pos < len(s) and s[pos] in " \t":
            pos += 1
        if pos >= len(s):
            return
        m = _INLINE_RE.match(s, pos)
        label, op, begin = "", None, ""
        if m:
            label, op, begin, pos = _m_text(m.group("t")), m.group("c"), m.group("b") or "", m.end()
            thick = m.group("o") == "=="
            dotted = m.group("o") == "-."
        else:
            m = _PLAIN_RE.match(s, pos)
            if not m:
                g.warn.add("Mermaid: could not read the link in %r; skipped." % s[:60])
                return
            op, begin, pos = m.group("c"), m.group("b") or "", m.end()
            thick, dotted = "=" in op, "." in op
            lm = re.match(r"[ \t]*\|([^|]*)\|", s[pos:])
            if lm:
                label, pos = _m_text(lm.group(1)), pos + lm.end()
        hidden = op.startswith("~")
        tail = op[-1] if op[-1] in ">xo" and len(op) > 2 else ""
        pending = {"label": label, "dashed": dotted, "width": 3.0 if thick else 1.0, "hidden": hidden,
                   "end": {">": "arrow", "x": "bar", "o": "circle_open"}.get(tail, "none"),
                   "start": {"<": "arrow", "x": "bar", "o": "circle_open"}.get(begin, "none")}
        if op.endswith(".->") or op.endswith(">"):
            pending["end"] = "arrow"


# -------------------------------------------------------------------- DOT

_DOT_SHAPES = {"box": "rect", "rect": "rect", "rectangle": "rect", "square": "rect", "ellipse": "ellipse",
               "oval": "ellipse", "circle": "ellipse", "doublecircle": "ellipse", "egg": "ellipse",
               "diamond": "diamond", "hexagon": "hexagon", "parallelogram": "parallelogram",
               "trapezium": "trapezoid", "invtrapezium": "trapezoid", "triangle": "triangle",
               "cylinder": "cylinder", "note": "note", "tab": "note", "folder": "note",
               "component": "rect", "box3d": "rect", "record": "round", "mrecord": "round",
               "plaintext": "text", "plain": "text", "none": "text", "underline": "text",
               "house": "rect", "invhouse": "rect", "octagon": "hexagon", "doubleoctagon": "hexagon"}
_DOT_ARROWS = {"normal": "arrow", "vee": "open", "open": "open", "empty": "open", "onormal": "open",
               "diamond": "diamond", "ediamond": "diamond_open", "odiamond": "diamond_open", "dot": "circle",
               "odot": "circle_open", "crow": "crowfoot", "tee": "bar", "box": "bar", "none": "none",
               "inv": "arrow", "invempty": "open"}
_NUM_RE = re.compile(r"-?(?:\.\d+|\d+(?:\.\d*)?)")
_WORD_RE = re.compile(r"[A-Za-z_\u0080-\U0010ffff][A-Za-z0-9_\u0080-\U0010ffff]*")


def _dot_tokens(text: str) -> list:
    toks, i, n, line = [], 0, len(text), 1
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
        elif ch in " \t\r\f\v﻿":
            i += 1
        elif text.startswith("//", i) or (ch == "#" and (i == 0 or text[i - 1] == "\n")):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise ImportFailed("DOT: unterminated comment (line %d)." % line)
            line += text.count("\n", i, j)
            i = j + 2
        elif ch == '"':
            buf, j = [], i + 1
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n and text[j + 1] == '"':
                    buf.append('"')
                    j += 2
                    continue
                if text[j] == "\\" and j + 1 < n and text[j + 1] == "\n":
                    j += 2
                    line += 1
                    continue
                if text[j] == "\n":
                    line += 1
                buf.append(text[j])
                j += 1
            if j >= n:
                raise ImportFailed("DOT: unterminated string (line %d)." % line)
            toks.append(("id", "".join(buf), True, line))
            i = j + 1
        elif ch == "<":
            depth, j = 0, i
            while j < n:
                if text[j] == "<":
                    depth += 1
                elif text[j] == ">":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j >= n:
                raise ImportFailed("DOT: unterminated HTML label (line %d)." % line)
            inner = re.sub(r"<\s*(?:br|/tr|/td|/p)\s*/?>", "\n", text[i + 1:j], flags=re.I)
            toks.append(("id", _html.unescape(re.sub(r"<[^<>]*>", "", inner)).strip(), True, line))
            line += text.count("\n", i, j)
            i = j + 1
        elif text.startswith("->", i) or text.startswith("--", i):
            toks.append(("p", text[i:i + 2], False, line))
            i += 2
        elif ch in "{}[];,=:+":
            toks.append(("p", ch, False, line))
            i += 1
        else:
            m = _WORD_RE.match(text, i) or _NUM_RE.match(text, i)
            if not m or m.end() == i:
                raise ImportFailed("DOT: unexpected character %r (line %d)." % (ch, line))
            toks.append(("id", m.group(0), False, line))
            i = m.end()
        if len(toks) > MAX_TOKENS:
            raise ImportFailed("The DOT source is too large.")
    return toks


class _Dot:
    def __init__(self, toks, g: Graph):
        self.t, self.i, self.g = toks, 0, g
        self.anon = 0

    def peek(self, k=0):
        j = self.i + k
        return self.t[j] if j < len(self.t) else (None, None, False, 0)

    def is_p(self, v, k=0):
        t = self.peek(k)
        return t[0] == "p" and t[1] == v

    def is_kw(self, v, k=0):
        t = self.peek(k)
        return t[0] == "id" and not t[2] and t[1].lower() == v

    def take(self):
        t = self.peek()
        self.i += 1
        return t

    def expect_p(self, v):
        t = self.take()
        if not (t[0] == "p" and t[1] == v):
            raise ImportFailed("DOT: expected %r near line %s." % (v, t[3] or "end of file"))

    def attr_list(self) -> dict:
        attrs = {}
        while self.is_p("["):
            self.take()
            while not self.is_p("]"):
                t = self.take()
                if t[0] is None:
                    raise ImportFailed("DOT: unterminated attribute list.")
                if t[0] == "p":
                    continue
                key = t[1]
                if self.is_p("="):
                    self.take()
                    v = self.take()
                    if v[0] != "id":
                        raise ImportFailed("DOT: bad attribute value near line %s." % v[3])
                    attrs[key.lower()] = v[1]
                else:
                    attrs[key.lower()] = "true"
            self.take()
        return attrs

    def parse(self):
        if self.is_kw("strict"):
            self.take()
        t = self.take()
        if not (t[0] == "id" and not t[2] and t[1].lower() in ("graph", "digraph")):
            raise ImportFailed("DOT: the file must start with 'graph' or 'digraph'.")
        self.g.directed = t[1].lower() == "digraph"
        if self.peek()[0] == "id":
            self.g.name = self.take()[1]
        self.expect_p("{")
        self.stmts({"node": {}, "edge": {}, "cluster": ""}, 0, is_root=True)
        return self.g

    def stmts(self, scope, depth, is_root=False) -> list:
        """Statements up to the closing brace; returns the node ids that appeared."""
        if depth > MAX_SUB_DEPTH:
            raise ImportFailed("DOT: subgraphs are nested more than %d levels deep." % MAX_SUB_DEPTH)
        seen = []
        while True:
            t = self.peek()
            if t[0] is None:
                raise ImportFailed("DOT: missing closing '}'.")
            if t[0] == "p" and t[1] == "}":
                self.take()
                return seen
            if t[0] == "p" and t[1] == ";":
                self.take()
                continue
            seen.extend(self.stmt(scope, depth, is_root))

    def stmt(self, scope, depth, is_root) -> list:
        g = self.g
        for kw, key in (("graph", None), ("node", "node"), ("edge", "edge")):
            if self.is_kw(kw) and self.is_p("[", 1):
                self.take()
                attrs = self.attr_list()
                if key:
                    scope[key] = {**scope[key], **attrs}
                else:
                    self.graph_attrs(scope, attrs, is_root)
                return []
        t, nxt = self.peek(), self.peek(1)
        if t[0] == "id" and nxt[0] == "p" and nxt[1] == "=":
            self.take(); self.take()
            v = self.take()
            self.graph_attrs(scope, {t[1].lower(): v[1]}, is_root)
            return []
        ends = [self.endpoint(scope, depth)]
        edge_ops = []
        while self.peek()[0] == "p" and self.peek()[1] in ("->", "--"):
            op = self.take()[1]
            if (op == "->") != g.directed:
                raise ImportFailed("DOT: %r is not valid in a %s (line %d)." % (
                    op, "digraph" if g.directed else "graph", self.peek()[3]))
            edge_ops.append(op)
            ends.append(self.endpoint(scope, depth))
        attrs = self.attr_list()
        if not edge_ops:
            nodes = ends[0]
            if len(nodes) == 1 and t[0] == "id" and not self._was_subgraph:
                self.node_attrs(nodes[0], attrs, scope)
            return nodes
        eattrs = {**scope["edge"], **attrs}
        for a, b in zip(ends, ends[1:]):
            for s in a:
                for d in b:
                    self.edge(s, d, eattrs)
        return [n for grp in ends for n in grp]

    _was_subgraph = False

    def endpoint(self, scope, depth) -> list:
        g = self.g
        self._was_subgraph = False
        if self.is_kw("subgraph") or self.is_p("{"):
            self._was_subgraph = True
            name = ""
            if self.is_kw("subgraph"):
                self.take()
                if self.peek()[0] == "id":
                    name = self.take()[1]
            self.expect_p("{")
            sc = {"node": dict(scope["node"]), "edge": dict(scope["edge"]), "cluster": scope["cluster"]}
            if name.lower().startswith("cluster"):
                cid, n = name, 2
                while cid in g.clusters:
                    cid, n = "%s_%d" % (name, n), n + 1
                g.clusters[cid] = {"id": cid, "label": "", "parent": scope["cluster"], "style": {}}
                sc["cluster"] = cid
            nodes = self.stmts(sc, depth + 1)
            return list(dict.fromkeys(nodes))
        t = self.take()
        if t[0] != "id":
            raise ImportFailed("DOT: expected a node name near line %s." % (t[3] or "end of file"))
        while self.is_p(":"):       # port / compass: ignored
            self.take()
            self.take()
        g.node(t[1], scope["cluster"])
        n = g.nodes[t[1]]
        if "_defaulted" not in n:
            n["_defaulted"] = True
            self.node_attrs(t[1], dict(scope["node"]), scope, creating=True)
        return [t[1]]

    def graph_attrs(self, scope, attrs, is_root):
        if is_root and not scope["cluster"]:
            rd = attrs.get("rankdir", "").upper()
            if rd in ("TB", "LR", "BT", "RL"):
                self.g.direction = rd
            return
        if scope["cluster"] and "label" in attrs:
            self.g.clusters[scope["cluster"]]["label"] = _dot_label(attrs["label"], "")
        if scope["cluster"]:
            st = self.g.clusters[scope["cluster"]]["style"]
            c, f = _color(attrs.get("color")), _color(attrs.get("bgcolor") or attrs.get("fillcolor"))
            if c:
                st["stroke"] = c
            if f:
                st["fill"] = f
            if "dashed" in attrs.get("style", ""):
                st["dashed"] = True

    def node_attrs(self, nid, attrs, scope, creating=False):
        n = self.g.nodes[nid]
        st = n["style"]
        if "label" in attrs:
            n["label"] = _dot_label(attrs["label"], nid)
            if attrs.get("shape", "").lower() in ("record", "mrecord"):
                n["label"] = re.sub(r"\s*\|\s*", " | ", n["label"].replace("{", "").replace("}", ""))
        shape = attrs.get("shape")
        if shape is not None:
            mapped = _DOT_SHAPES.get(shape.lower())
            if mapped == "text":
                n["kind"], n["shape"] = "text", "rect"
            elif mapped:
                n["kind"], n["shape"] = "shape", mapped
            else:
                self.g.warn.once("dot_shape", "Some DOT node shapes have no equivalent and were drawn as ellipses/boxes.")
                n["shape"] = "rect"
        elif creating and "shape" not in n.get("_set", ()):
            n["shape"] = "ellipse"
        stl = attrs.get("style", "")
        if "invis" in stl:
            n["hidden"] = True
        if "dashed" in stl or "dotted" in stl:
            st["dashed"] = True
        if "rounded" in stl and n["shape"] == "rect":
            n["shape"] = "round"
        col, fill = _color(attrs.get("color")), _color(attrs.get("fillcolor"))
        if col:
            st["stroke"] = col
        if "filled" in stl:
            st["fill"] = fill or col or "#D3D3D3"
        elif fill:
            st["fill"] = fill
        fc = _color(attrs.get("fontcolor"))
        if fc:
            st["font_color"] = fc
        for key, target in (("fontsize", "font_size"), ("penwidth", "stroke_width")):
            m = _NUM_RE.fullmatch(attrs.get(key, "") or "")
            if m:
                st[target] = float(m.group(0))
        if attrs:
            n["native"] = ";".join("%s=%s" % (k, v) for k, v in list(attrs.items())[:12])[:300]

    def edge(self, s, d, attrs):
        g = self.g
        direction = attrs.get("dir", "forward" if g.directed else "none")
        head = _DOT_ARROWS.get(attrs.get("arrowhead", "normal").lower(), "arrow")
        tail = _DOT_ARROWS.get(attrs.get("arrowtail", "normal").lower(), "arrow")
        end = head if direction in ("forward", "both") else "none"
        start = tail if direction in ("back", "both") else "none"
        stl = attrs.get("style", "")
        pw = _NUM_RE.fullmatch(attrs.get("penwidth", "") or "")
        g.add_edge(s, d, label=_dot_label(attrs.get("label", ""), ""), dashed=("dashed" in stl or "dotted" in stl),
                   color=_color(attrs.get("color")), width=float(pw.group(0)) if pw else 1.0,
                   start=start, end=end, hidden="invis" in stl)


def _dot_label(raw: str, nid: str) -> str:
    s = raw.replace("\\N", nid).replace("\\G", "")
    s = re.sub(r"\\[nlr]", "\n", s).replace("\\\\", "\\")
    return s.strip()


def parse_dot(text: str) -> Graph:
    g = Graph("dot")
    _Dot(_dot_tokens(text), g).parse()
    for n in g.nodes.values():
        n.pop("_defaulted", None)
        n.pop("_set", None)
    if not g.nodes:
        raise ImportFailed("The DOT graph contains no nodes.")
    return g


# ----------------------------------------------------------------- layout

def _size(n: dict) -> tuple:
    lines = (n["label"] or n["id"]).split("\n")
    longest = max(len(l) for l in lines)
    w = min(320.0, max(80.0, 7.2 * longest + 28.0))
    h = max(44.0, 18.0 * len(lines) + 24.0)
    if n["kind"] == "text":
        return round(w), round(h - 8)
    f = {"diamond": (1.5, 1.5), "ellipse": (1.3, 1.25), "hexagon": (1.25, 1.1), "cylinder": (1.0, 1.4),
         "parallelogram": (1.2, 1.0), "trapezoid": (1.2, 1.0), "triangle": (1.4, 1.4)}.get(n["shape"], (1.0, 1.0))
    return round(w * f[0]), round(h * f[1])


def _layout(g: Graph) -> tuple:
    """``({node id: (x, y, w, h)}, {cluster id: (x, y, w, h)})`` top-left, px."""
    ids = [i for i, n in g.nodes.items() if not n["hidden"]]
    index = {i: k for k, i in enumerate(ids)}
    size = {i: _size(g.nodes[i]) for i in ids}
    pairs, seen = [], set()
    for e in g.edges:
        s, d = e["src"], e["dst"]
        if s in index and d in index and s != d and (s, d) not in seen:
            seen.add((s, d))
            pairs.append((s, d))
    # break cycles: iterative DFS, edges to a node on the stack are reversed
    adj = {i: [] for i in ids}
    for s, d in pairs:
        adj[s].append(d)
    state, rev = {}, set()
    for root in ids:
        if root in state:
            continue
        stack = [(root, iter(adj[root]))]
        state[root] = 1
        while stack:
            node, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                state[node] = 2
                stack.pop()
            elif state.get(nxt) == 1:
                rev.add((node, nxt))
            elif nxt not in state:
                state[nxt] = 1
                stack.append((nxt, iter(adj[nxt])))
    dag = [((d, s) if (s, d) in rev else (s, d)) for s, d in pairs]
    succ, preds, indeg = {i: [] for i in ids}, {i: [] for i in ids}, {i: 0 for i in ids}
    for s, d in dag:
        succ[s].append(d); preds[d].append(s); indeg[d] += 1
    layer, queue = {i: 0 for i in ids}, [i for i in ids if indeg[i] == 0]
    while queue:
        node = queue.pop(0)
        for d in succ[node]:
            layer[d] = max(layer[d], layer[node] + 1)
            indeg[d] -= 1
            if indeg[d] == 0:
                queue.append(d)
    nlayers = (max(layer.values()) + 1) if layer else 1
    layers = [[] for _ in range(nlayers)]
    for i in ids:
        layers[layer[i]].append(i)

    def cpath(i):
        path, c = [], g.nodes[i]["cluster"]
        while c:
            path.append(c)
            c = g.clusters[c]["parent"]
        return tuple(reversed(path))

    paths = {i: cpath(i) for i in ids}

    def contiguous(order, depth=0):
        out, groups, singles = [], {}, []
        for i in order:
            p = paths[i]
            if len(p) > depth:
                if p[depth] not in groups:
                    groups[p[depth]] = []
                    singles.append(("g", p[depth]))
                groups[p[depth]].append(i)
            else:
                singles.append(("n", i))
        for kind, v in singles:
            out.extend(contiguous(groups[v], depth + 1) if kind == "g" else [v])
        return out

    for k in range(nlayers):
        layers[k] = contiguous(layers[k])

    def frac(lay):
        return {i: (p + 0.5) / len(lay) for p, i in enumerate(lay)}
    for sweep in range(8):
        down = sweep % 2 == 0
        rng = range(1, nlayers) if down else range(nlayers - 2, -1, -1)
        for k in rng:
            pos = {}
            for lay in layers:
                pos.update(frac(lay))
            nb = preds if down else succ
            cur = {i: p for p, i in enumerate(layers[k])}
            key = {}
            for i in layers[k]:
                vals = [pos[x] for x in nb[i] if x in pos]
                key[i] = (sum(vals) / len(vals)) if vals else (cur[i] + 0.5) / len(layers[k])
            layers[k] = contiguous(sorted(layers[k], key=lambda i: (key[i], cur[i])))

    horizontal = g.direction in ("LR", "RL")
    has_clusters = bool(g.clusters)
    gap_across, gap_flow = 40.0, 70.0 + (50.0 if has_clusters else 0.0)
    pad = 24.0
    across_pos, flow_pos, flow_extent = {}, {}, []
    for k, lay in enumerate(layers):
        ext = [(size[i][1] if horizontal else size[i][0]) for i in lay]
        total, x = 0.0, 0.0
        offs = []
        for p, i in enumerate(lay):
            if p:
                x += gap_across + (2 * pad if paths[lay[p - 1]] != paths[i] else 0.0)
            offs.append(x)
            x += ext[p]
        total = x
        for i, o in zip(lay, offs):
            across_pos[i] = o - total / 2.0
        flow_extent.append(max([(size[i][0] if horizontal else size[i][1]) for i in lay] or [0.0]))
    y = 0.0
    starts = []
    for k in range(nlayers):
        starts.append(y)
        y += flow_extent[k] + gap_flow
    total_flow = y - gap_flow
    for k, lay in enumerate(layers):
        for i in lay:
            along = size[i][0] if horizontal else size[i][1]
            f = starts[k] + (flow_extent[k] - along) / 2.0
            if g.direction in ("BT", "RL"):
                f = total_flow - f - along
            flow_pos[i] = f
    margin = 40.0 + (pad + 24.0 if has_clusters else 0.0)
    min_across = min(across_pos.values(), default=0.0)
    rects = {}
    for i in ids:
        a, f = across_pos[i] - min_across + margin, flow_pos[i] + margin
        w, h = size[i]
        rects[i] = (f, a, w, h) if horizontal else (a, f, w, h)
    crects = {}
    depth_of = {}
    for cid in g.clusters:
        d, c = 0, cid
        while c:
            d, c = d + 1, g.clusters[c]["parent"]
        depth_of[cid] = d
    for cid in sorted(g.clusters, key=lambda c: -depth_of[c]):
        boxes = [rects[i] for i in ids if g.nodes[i]["cluster"] == cid]
        boxes += [crects[c] for c in g.clusters if g.clusters[c]["parent"] == cid and c in crects]
        if not boxes:
            g.warn.add("Empty group %r was skipped." % g.clusters[cid]["label"][:40])
            continue
        x0, y0 = min(b[0] for b in boxes) - pad, min(b[1] for b in boxes) - pad - 22.0
        x1, y1 = max(b[0] + b[2] for b in boxes) + pad, max(b[1] + b[3] for b in boxes) + pad
        crects[cid] = (x0, y0, x1 - x0, y1 - y0)
    return rects, crects


# ------------------------------------------------------------------ output

def _eid(raw: str, used: set, prefix: str = "") -> str:
    base = re.sub(r"[^A-Za-z0-9_.:\-]", "_", prefix + raw)[:56] or prefix + "n"
    cand, n = base, 2
    while cand in used:
        cand, n = "%s_%d" % (base, n), n + 1
    used.add(cand)
    return cand


def _build_page(g: Graph, name: str) -> dict:
    g.warn.once("layout", "The source has no coordinates; the layout was generated automatically.")
    rects, crects = _layout(g)
    used: set = set()
    nid = {i: _eid(i, used) for i in g.nodes}
    cid = {c: _eid(c, used, "grp_") for c in g.clusters}
    elements = []
    for c in sorted(crects, key=lambda c: 0):
        x, y, w, h = crects[c]
        cl = g.clusters[c]
        st = {"fill": "#F8FAFC", "stroke": "#94A3B8", "dashed": True, "valign": "top", "align": "left",
              "bold": True}
        st.update(cl["style"])
        elements.append({"id": cid[c], "kind": "container", "shape": "zone", "name": cl["label"][:80],
                         "text": cl["label"], "x": x, "y": y, "w": w, "h": h, "layer": "",
                         "parent": cid[cl["parent"]] if cl["parent"] in crects else "",
                         "style": st, "source_ref": c, "confidence": 1.0,
                         "native": {"format": g.fmt, "style": "subgraph"}})
    for i, n in g.nodes.items():
        if i not in rects:
            continue
        x, y, w, h = rects[i]
        st = dict(n["style"])
        if n["kind"] == "text":
            st.setdefault("fill", "none")
            st.setdefault("stroke", "none")
        if n["shape"] == "round":
            st["rounded"] = True
        elements.append({"id": nid[i], "kind": n["kind"], "shape": n["shape"], "name": n["label"].split("\n")[0][:80],
                         "text": n["label"], "x": x, "y": y, "w": w, "h": h, "layer": "",
                         "parent": cid[n["cluster"]] if n["cluster"] in crects else "",
                         "style": st, "source_ref": i, "confidence": 1.0,
                         "native": {"format": g.fmt, "style": n["native"]}})
    conns = []
    for k, e in enumerate(g.edges):
        if e["hidden"]:
            continue
        ends = []
        for raw in (e["src"], e["dst"]):
            if raw.startswith("cluster:"):
                ends.append(cid.get(raw[8:], "") if raw[8:] in crects else "")
            else:
                ends.append(nid[raw] if raw in rects else "")
        if not ends[0] or not ends[1]:
            continue
        st = {"stroke_width": e["width"], "dashed": e["dashed"]}
        if e["color"] and e["color"] != "none":
            st["stroke"] = e["color"]
        conns.append({"id": "c%d" % (k + 1), "source": ends[0], "target": ends[1], "routing": "straight",
                      "start_arrow": e["start"], "end_arrow": e["end"], "label": e["label"],
                      "labels": [{"text": e["label"], "pos": 0.5}] if e["label"] else [], "style": st,
                      "source_ref": "%s->%s" % (e["src"], e["dst"]), "confidence": 1.0,
                      "native": {"format": g.fmt, "style": ""}})
    mx = max((e["x"] + e["w"] for e in elements), default=0.0)
    my = max((e["y"] + e["h"] for e in elements), default=0.0)
    return {"id": "page-1", "name": name or "Diagram", "width": mx + 40.0, "height": my + 40.0,
            "elements": elements, "connectors": conns}


def _decode(data: bytes) -> str:
    if len(data) > MAX_TEXT_BYTES:
        raise ImportFailed("The text diagram is larger than %d KiB." % (MAX_TEXT_BYTES // 1024))
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace")
    if b"\x00" in data[:2048]:
        raise ImportFailed("This file is binary, not a Mermaid or DOT text diagram.")
    return data.decode("utf-8", "replace")


@guarded
def list_pages(data: bytes) -> list:
    require_bytes(data)
    return [{"id": "page-1", "name": "Page 1"}]


@guarded
def read(data: bytes, *, filename: str = "", page: str | None = None) -> dict:
    data = require_bytes(data)
    fmt = _detect.detect(data, filename)
    if fmt not in ("mermaid", "dot"):
        raise ImportFailed("This is not a Mermaid or DOT text diagram (detected: %s)." % fmt)
    text = _decode(data)
    g = parse_mermaid(text) if fmt == "mermaid" else parse_dot(text)
    pg = _build_page(g, g.name)
    if page not in (None, "", "1", "page-1"):
        raise ImportFailed("Page %r not found; a text diagram has a single page." % str(page)[:40])
    return make_document(fmt=fmt, engine=fmt + "-reader", data=data, filename=filename,
                         name=doc_name(filename, g.name or "Diagram"), pages=[pg],
                         warnings=g.warn.items, page=page, metadata={"layout": "generated"})
