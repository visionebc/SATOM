"""Symbol libraries of Diagram Studio and the category registry.

A *library* is data: a ``library.json`` (schema ``satom.symbols/1``) plus loose
SVG icons. Families (``network``, ``infra``...) and classes (``firewall``...)
are not code: the category tree is derived from whatever libraries are loaded,
so adding a category means adding a library, never editing Python.

Operator-supplied libraries are hostile input. Every SVG goes through
:func:`sanitize_svg` (whitelist of geometric elements and presentation
attributes; DOCTYPE/ENTITY refused through ``xmlsafe.parse_xml``) and the JSON
is validated strictly by :func:`load_library`.

Standalone: stdlib + ``..xmlsafe`` only.
"""
from __future__ import annotations

import io
import json
import os
import re
import threading

from ..xmlsafe import UnsafeInput, open_zip, parse_xml, read_member

SCHEMA = "satom.symbols/1"
MAX_SYMBOLS = 500
MAX_SVG_BYTES = 64 * 1024
MAX_SVG_ELEMENTS = 400
MAX_SVG_DEPTH = 10

LIB_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,47}$")
SYM_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,96}$")
FAMILY_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
CLASS_RE = re.compile(r"^[a-z0-9_]{1,40}$")
SVG_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,96}\.svg$")
COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")
# Same vocabulary as model.SHAPES (kept literal: this package must not import the model).
SHAPES = ("rect", "round", "ellipse", "diamond", "hexagon", "parallelogram",
          "trapezoid", "triangle", "cylinder", "cloud", "document", "note",
          "process", "terminator", "actor", "pill", "zone", "swimlane", "table",
          "polygon", "path", "symbol", "line")
FAMILY_ORDER = ("network", "security", "infra", "devices", "data", "software", "people",
                "flow", "uml", "bpmn", "c4", "generic")
ALIAS_KEYS = ("drawio", "visio", "satom", "text")
SYMBOL_KEYS = {"id", "label", "category", "shape", "w", "h", "ports", "keywords",
               "aliases", "style", "svg", "variants"}
LIB_KEYS = {"schema", "id", "label", "version", "license", "families", "symbols", "variant", "anchor"}
#: Rendering style of a whole library. ``flat`` icons are monochrome ``currentColor``
#: strokes (the element colour paints them); ``color`` and ``iso3d`` icons carry
#: their own fills and are never recoloured. The classifier only picks ``flat``.
VARIANTS = ("flat", "color", "iso3d")
#: Ports live on the rim of a symbol: every port lies within this fraction of
#: the nearest box edge. The interior is where a drag MOVES the element (a port
#: handle there would turn every grab into a new connector). Built-in libraries
#: must obey; an operator library's interior ports are pulled onto the nearest
#: edge (with a warning) so a stored library never stops loading.
PORT_EDGE = 0.1
MAX_VARIANT_LINKS = 8

_SVG_NS = "http://www.w3.org/2000/svg"
_SHAPE_TAGS = ("path", "rect", "circle", "ellipse", "line", "polyline", "polygon")
_ALLOWED_TAGS = frozenset(_SHAPE_TAGS + ("g",))
ATTR_ORDER = ("viewBox", "fill", "fill-rule", "stroke", "stroke-width", "stroke-linecap",
              "stroke-linejoin", "stroke-dasharray", "opacity", "transform", "d", "points",
              "x", "y", "width", "height", "rx", "ry", "cx", "cy", "r", "x1", "y1", "x2", "y2")

_NUM = r"[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?"
_NUM_RE = re.compile(r"^%s(?:px|%%)?$" % _NUM)
_PAINT_RE = re.compile(r"^(?:none|currentColor|#[0-9A-Fa-f]{3,8}|[A-Za-z]{3,20})$")
_DASH_RE = re.compile(r"^[0-9.,\s]{1,60}$")
_PATH_RE = re.compile(r"^[MmLlHhVvCcSsQqTtAaZz0-9eE.,+\-\s]{0,20000}$")
_POINTS_RE = re.compile(r"^[-0-9.eE+,\s]{0,20000}$")
_TRANSFORM_RE = re.compile(r"^(?:\s*(?:translate|scale|rotate|skewX|skewY|matrix)\(\s*[-0-9.eE+,\s]+\))+\s*$")
_VIEWBOX_RE = re.compile(r"^\s*%s[\s,]+%s[\s,]+%s[\s,]+%s\s*$" % ((_NUM,) * 4))
_LINECAPS = ("butt", "round", "square")
_LINEJOINS = ("miter", "round", "bevel")
_FILLRULES = ("nonzero", "evenodd")
_GEOM_ATTRS = ("x", "y", "width", "height", "rx", "ry", "cx", "cy", "r", "x1", "y1", "x2", "y2")


class LibraryError(ValueError):
    """A library (JSON or SVG pack) was refused; ``args[0]`` lists why."""


class SvgRejected(LibraryError):
    """One SVG cannot be made safe."""


# ---------------------------------------------------------------- sanitiser

def _clean_attr(name: str, value: str, root: bool):
    v = value.strip()
    if name == "viewBox":
        return " ".join(v.replace(",", " ").split()) if root and _VIEWBOX_RE.match(v) else None
    if root and name in _GEOM_ATTRS:
        return None
    if name in ("fill", "stroke"):
        return v if _PAINT_RE.match(v) else None
    if name in ("stroke-width", "opacity") or name in _GEOM_ATTRS:
        if not _NUM_RE.match(v):
            return None
        if name == "opacity":
            try:
                if not 0 <= float(v) <= 1:
                    return None
            except ValueError:
                return None
        return v
    if name == "stroke-linecap":
        return v if v in _LINECAPS else None
    if name == "stroke-linejoin":
        return v if v in _LINEJOINS else None
    if name == "fill-rule":
        return v if v in _FILLRULES else None
    if name == "stroke-dasharray":
        return " ".join(v.replace(",", " ").split()) if _DASH_RE.match(v) else None
    if name == "transform":
        return v if len(v) <= 200 and _TRANSFORM_RE.match(v) else None
    if name == "d":
        return " ".join(v.split()) if _PATH_RE.match(v) else None
    if name == "points":
        return " ".join(v.replace(",", " ").split()) if _POINTS_RE.match(v) else None
    return None


def _emit(el, root: bool, depth: int, counter: list) -> str:
    local = el.tag.rsplit("}", 1)[-1] if isinstance(el.tag, str) else ""
    ns_ok = (not el.tag.startswith("{")) or el.tag.startswith("{%s}" % _SVG_NS)
    if not ns_ok:
        return ""
    if root:
        if local != "svg":
            raise SvgRejected("the root element must be <svg>")
    elif local not in _ALLOWED_TAGS:
        return ""      # script, style, foreignObject, image, use, text, a, filter ... dropped with their subtree
    counter[0] += 1
    if counter[0] > MAX_SVG_ELEMENTS or depth > MAX_SVG_DEPTH:
        raise SvgRejected("SVG too complex (more than %d elements or %d levels)" % (MAX_SVG_ELEMENTS, MAX_SVG_DEPTH))
    attrs = {}
    for key, val in el.attrib.items():
        if key.startswith("{"):          # xlink:href, xml:space, any foreign namespace
            continue
        if key in ATTR_ORDER:
            cleaned = _clean_attr(key, val, root)
            if cleaned is not None:
                attrs[key] = cleaned
    if root:
        if "viewBox" not in attrs:
            raise SvgRejected("the root <svg> needs a valid viewBox")
        parts = ['xmlns="%s"' % _SVG_NS]
    else:
        parts = []
    parts += ['%s="%s"' % (k, attrs[k]) for k in ATTR_ORDER if k in attrs]
    inner = "".join(_emit(ch, False, depth + 1, counter) for ch in list(el))
    if root:
        return "<svg %s>%s</svg>" % (" ".join(parts), inner)
    if local == "g":
        return "<g%s>%s</g>" % ((" " + " ".join(parts)) if parts else "", inner) if inner else ""
    return "<%s%s/>" % (local, (" " + " ".join(parts)) if parts else "")


def sanitize_svg(data) -> str:
    """Strict whitelist sanitiser: canonical SVG text or :class:`SvgRejected`.

    Idempotent: ``sanitize_svg(sanitize_svg(x).encode()) == sanitize_svg(x)``.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if len(raw) > MAX_SVG_BYTES:
        raise SvgRejected("SVG larger than %d KiB" % (MAX_SVG_BYTES // 1024))
    try:
        root = parse_xml(raw)
    except UnsafeInput as exc:
        raise SvgRejected(str(exc)) from None
    counter = [0]
    out = _emit(root, True, 0, counter)
    if not re.search(r"<(?:%s)\b" % "|".join(_SHAPE_TAGS), out):
        raise SvgRejected("the SVG has no drawable shape after sanitising")
    return out


# --------------------------------------------------------------- validation

def _text_re_ok(p: str) -> str | None:
    if not isinstance(p, str) or not p or len(p) > 240:
        return "a text pattern is 1..240 characters"
    try:
        re.compile(p, re.I)
    except re.error as exc:
        return "bad regex %r: %s" % (p[:40], exc)
    # crude catastrophic-backtracking guard: a quantified group containing a quantifier
    if re.search(r"\((?:[^()\\]|\\.)*[*+](?:[^()\\]|\\.)*\)[*+{]", p):
        return "nested quantifier in %r" % p[:40]
    return None


def port_edge_distance(x: float, y: float) -> float:
    """Distance (box fractions) from a port to the nearest edge of its symbol box."""
    return min(x, 1 - x, y, 1 - y)


def _rim_port(p: dict) -> dict:
    """*p* moved onto the nearest box edge when it lies in the interior."""
    x, y = p["x"], p["y"]
    if port_edge_distance(x, y) <= PORT_EDGE:
        return {"id": p["id"], "x": x, "y": y}
    d = {"x0": x, "x1": 1 - x, "y0": y, "y1": 1 - y}
    side = min(sorted(d), key=lambda k: d[k])       # ties: deterministic by name
    if side == "x0":
        x = 0
    elif side == "x1":
        x = 1
    elif side == "y0":
        y = 0
    else:
        y = 1
    return {"id": p["id"], "x": x, "y": y}


def _validate_symbol(s, idx: int, errs: list, builtin: bool = False, warns: list | None = None) -> dict | None:
    where = "symbols[%d]" % idx
    if not isinstance(s, dict):
        errs.append("%s: not an object" % where)
        return None
    n0 = len(errs)
    extra = set(s) - SYMBOL_KEYS
    if extra:
        errs.append("%s: unknown keys %s" % (where, sorted(extra)))
    sid = s.get("id")
    if not (isinstance(sid, str) and SYM_ID_RE.match(sid)):
        errs.append("%s: bad id %r" % (where, str(sid)[:40]))
        sid = None
    else:
        where = "symbol %s" % sid
    label = s.get("label")
    if not (isinstance(label, str) and 1 <= len(label.strip()) <= 80):
        errs.append("%s: label is 1..80 characters" % where)
    cat = s.get("category")
    parts = cat.split(".") if isinstance(cat, str) else []
    if not (len(parts) == 2 and FAMILY_RE.match(parts[0]) and CLASS_RE.match(parts[1])):
        errs.append("%s: category must be <family>.<class>, got %r" % (where, str(cat)[:40]))
    if s.get("shape") not in SHAPES:
        errs.append("%s: shape %r is not a model shape" % (where, str(s.get("shape"))[:20]))
    for k in ("w", "h"):
        v = s.get(k)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not 8 <= v <= 2000:
            errs.append("%s: %s must be a number 8..2000" % (where, k))
    ports = s.get("ports")
    pids = set()
    if not isinstance(ports, list) or not 1 <= len(ports) <= 64:
        errs.append("%s: ports is a list of 1..64 anchors" % where)
    else:
        for p in ports:
            ok = (isinstance(p, dict) and set(p) == {"id", "x", "y"} and isinstance(p["id"], str)
                  and re.match(r"^[A-Za-z0-9_.:\-]{1,64}$", p["id"]) and p["id"] not in pids
                  and all(isinstance(p[c], (int, float)) and not isinstance(p[c], bool) and 0 <= p[c] <= 1 for c in "xy"))
            if not ok:
                errs.append("%s: bad port %r" % (where, str(p)[:60]))
            else:
                pids.add(p["id"])
                if port_edge_distance(p["x"], p["y"]) > PORT_EDGE:
                    if builtin:
                        errs.append("%s: port %s lies inside the symbol (more than %g from every edge)"
                                    % (where, p["id"], PORT_EDGE))
                    elif warns is not None:
                        warns.append("%s: port %s moved onto the nearest edge" % (where, p["id"]))
    kw = s.get("keywords", [])
    if not (isinstance(kw, list) and len(kw) <= 40 and all(isinstance(k, str) and 1 <= len(k) <= 40 for k in kw)):
        errs.append("%s: keywords is a list of up to 40 short strings" % where)
    al = s.get("aliases", {})
    if not isinstance(al, dict) or set(al) - set(ALIAS_KEYS):
        errs.append("%s: aliases keys are %s" % (where, list(ALIAS_KEYS)))
    else:
        for k, lst in al.items():
            if not (isinstance(lst, list) and len(lst) <= 40 and all(isinstance(x, str) and 1 <= len(x) <= 240 for x in lst)):
                errs.append("%s: aliases.%s is a list of up to 40 strings" % (where, k))
            elif k == "text":
                for p in lst:
                    bad = _text_re_ok(p)
                    if bad:
                        errs.append("%s: %s" % (where, bad))
    st = s.get("style", {})
    if not (isinstance(st, dict) and set(st) <= {"fill", "stroke"}
            and all(isinstance(v, str) and (COLOR_RE.match(v) or v == "none") for v in st.values())):
        errs.append("%s: style is {fill, stroke} with #RRGGBB values" % where)
    svg = s.get("svg")
    if not (isinstance(svg, str) and SVG_NAME_RE.match(svg)):
        errs.append("%s: svg must be a plain *.svg file name" % where)
    var = s.get("variants", {})
    if not (isinstance(var, dict) and len(var) <= MAX_VARIANT_LINKS
            and all(isinstance(k, str) and LIB_ID_RE.match(k) and isinstance(v, str) and SYM_ID_RE.match(v)
                    for k, v in var.items())):
        errs.append("%s: variants maps up to %d library ids to symbol ids" % (where, MAX_VARIANT_LINKS))
    if len(errs) > n0 or sid is None:
        return None
    return {"id": sid, "label": label.strip(), "category": cat, "shape": s["shape"],
            "w": s["w"], "h": s["h"],
            "ports": [_rim_port(p) for p in ports],
            "keywords": list(kw),
            "aliases": {k: list(al.get(k, [])) for k in ALIAS_KEYS},
            "style": dict(st), "svg": svg, "variants": dict(sorted(var.items()))}


def _titleize(s: str) -> str:
    return s.replace("_", " ").strip().capitalize()


def _validate_families(fams, errs: list) -> dict:
    out: dict = {}
    if fams is None:
        return out
    if not isinstance(fams, dict) or len(fams) > 64:
        errs.append("families must be an object of at most 64 families")
        return out
    for fid, f in fams.items():
        if not (FAMILY_RE.match(str(fid)) and isinstance(f, dict) and set(f) <= {"label", "classes"}):
            errs.append("bad family %r" % str(fid)[:40])
            continue
        label = f.get("label", _titleize(fid))
        classes = f.get("classes", {})
        if not (isinstance(label, str) and 1 <= len(label) <= 60 and isinstance(classes, dict) and len(classes) <= 500
                and all(CLASS_RE.match(str(k)) and isinstance(v, str) and 1 <= len(v) <= 60 for k, v in classes.items())):
            errs.append("bad labels in family %r" % fid)
            continue
        out[fid] = {"label": label, "classes": dict(classes)}
    return out


def load_library(json_obj, svgs: dict, *, builtin: bool = False) -> dict:
    """Validate a library and sanitise its SVGs; returns the library or raises
    :class:`LibraryError` (message lists up to 20 problems).

    *json_obj* is a dict (or JSON text/bytes); *svgs* maps file name -> bytes.
    """
    if isinstance(json_obj, (bytes, str)):
        if len(json_obj) > 4 * 1024 * 1024:
            raise LibraryError("library.json larger than 4 MiB")
        try:
            json_obj = json.loads(json_obj)
        except ValueError as exc:
            raise LibraryError("library.json is not valid JSON: %s" % exc) from None
    if not isinstance(json_obj, dict):
        raise LibraryError("a library is a JSON object")
    errs: list = []
    extra = set(json_obj) - LIB_KEYS
    if extra:
        errs.append("unknown keys %s" % sorted(extra))
    if json_obj.get("schema") != SCHEMA:
        errs.append("schema must be %r" % SCHEMA)
    lid = json_obj.get("id")
    if not (isinstance(lid, str) and LIB_ID_RE.match(lid)):
        errs.append("bad library id %r" % str(lid)[:40])
    label = json_obj.get("label")
    if not (isinstance(label, str) and 1 <= len(label.strip()) <= 80):
        errs.append("library label is 1..80 characters")
    for k in ("version", "license"):
        v = json_obj.get(k, "")
        if not (isinstance(v, str) and len(v) <= 40):
            errs.append("%s is a short string" % k)
    variant = json_obj.get("variant", "flat")
    if variant not in VARIANTS:
        errs.append("variant is one of %s" % list(VARIANTS))
    anchor = json_obj.get("anchor")
    if anchor is not None and not (isinstance(anchor, list) and len(anchor) == 2 and all(
            isinstance(a, (int, float)) and not isinstance(a, bool) and 0 <= a <= 1 for a in anchor)):
        errs.append("anchor is [x, y] with fractions 0..1 of the icon")
    raw_syms = json_obj.get("symbols")
    if not isinstance(raw_syms, list) or not raw_syms:
        raise LibraryError("symbols is a non-empty list")
    if len(raw_syms) > MAX_SYMBOLS:
        raise LibraryError("%d symbols; the limit is %d per library" % (len(raw_syms), MAX_SYMBOLS))
    if not isinstance(svgs, dict):
        raise LibraryError("svgs is a mapping of file name to bytes")
    fams = _validate_families(json_obj.get("families"), errs)
    syms, seen, warns = [], set(), []
    for i, s in enumerate(raw_syms):
        v = _validate_symbol(s, i, errs, builtin, warns)
        if v is None:
            continue
        if v["id"] in seen:
            errs.append("duplicate symbol id %r" % v["id"])
            continue
        seen.add(v["id"])
        data = svgs.get(v["svg"])
        if data is None:
            errs.append("symbol %s: missing file %s" % (v["id"], v["svg"]))
            continue
        try:
            v["svg_text"] = sanitize_svg(data)
        except LibraryError as exc:
            errs.append("symbol %s: %s" % (v["id"], exc))
            continue
        syms.append(v)
    if errs:
        more = "" if len(errs) <= 20 else " (+%d more)" % (len(errs) - 20)
        raise LibraryError("; ".join(errs[:20]) + more)
    return {"schema": SCHEMA, "id": lid, "label": label.strip(), "version": json_obj.get("version", ""),
            "license": json_obj.get("license", ""), "builtin": builtin, "families": fams,
            "variant": variant, "anchor": list(anchor) if anchor is not None else None,
            "symbols": syms, "warnings": warns[:20]}


# --------------------------------------------------------------- SVG packs

def _slug(name: str) -> str:
    stem = name.rsplit("/", 1)[-1]
    if stem.lower().endswith(".svg"):
        stem = stem[:-4]
    s = re.sub(r"[^a-z0-9]+", "_", stem.lower()).strip("_")[:40]
    return s or "icon"


def import_svg_pack(files: dict, library_id: str, label: str, family: str = "generic") -> dict:
    """Build a library from loose SVG icons (a folder or an unpacked zip).

    Each ``*.svg`` becomes a symbol of category ``<family>.<sanitised stem>``.
    Unsafe icons are skipped and listed in ``lib["warnings"]``; more than
    :data:`MAX_SYMBOLS` icons refuses the whole pack.
    """
    if not (isinstance(library_id, str) and LIB_ID_RE.match(library_id)):
        raise LibraryError("bad library id %r" % str(library_id)[:40])
    if not (isinstance(family, str) and FAMILY_RE.match(family)):
        raise LibraryError("bad family %r" % str(family)[:40])
    if not (isinstance(label, str) and 1 <= len(label.strip()) <= 80):
        raise LibraryError("library label is 1..80 characters")
    if not isinstance(files, dict):
        raise LibraryError("files is a mapping of file name to bytes")
    names = sorted(n for n in files if isinstance(n, str) and n.lower().endswith(".svg"))
    if len(names) > MAX_SYMBOLS:
        raise LibraryError("%d icons; the limit is %d per library" % (len(names), MAX_SYMBOLS))
    warnings = ["ignored non-SVG file %r" % str(n)[:60] for n in sorted(map(str, files)) if not n.lower().endswith(".svg")][:20]
    syms, svgs, used = [], {}, set()
    for name in names:
        try:
            svg_text = sanitize_svg(files[name])
        except LibraryError as exc:
            warnings.append("skipped %r: %s" % (name[:60], exc))
            continue
        cls = _slug(name)
        base, n = cls, 2
        while cls in used:
            suffix = "_%d" % n
            cls = base[:40 - len(suffix)] + suffix
            n += 1
        used.add(cls)
        fname = cls + ".svg"
        svgs[fname] = svg_text.encode()
        syms.append({"id": cls.replace("_", "-"), "label": _titleize(cls), "category": "%s.%s" % (family, cls),
                     "shape": "symbol", "w": 48, "h": 48,
                     "ports": [{"id": "n", "x": 0.5, "y": 0}, {"id": "e", "x": 1, "y": 0.5},
                               {"id": "s", "x": 0.5, "y": 1}, {"id": "w", "x": 0, "y": 0.5}],
                     "keywords": [cls.replace("_", " ")], "aliases": {"text": [r"\b%s\b" % re.escape(cls.replace("_", " "))]},
                     "style": {}, "svg": fname})
    if not syms:
        raise LibraryError("no usable SVG icon in the pack" + ("; " + "; ".join(warnings[:5]) if warnings else ""))
    lib = load_library({"schema": SCHEMA, "id": library_id, "label": label, "version": "1",
                        "families": {family: {"label": _titleize(family)}}, "symbols": syms}, svgs)
    lib["warnings"] = warnings + lib["warnings"]
    return lib


def import_svg_zip(data: bytes, library_id: str, label: str, family: str = "generic") -> dict:
    """:func:`import_svg_pack` over a ZIP (bounded by ``xmlsafe.open_zip``)."""
    try:
        zf = open_zip(io.BytesIO(data))
    except UnsafeInput as exc:
        raise LibraryError(str(exc)) from None
    files = {}
    for info in zf.infolist():
        if info.is_dir() or not info.filename.lower().endswith(".svg"):
            continue
        if len(files) >= MAX_SYMBOLS + 1:
            break
        try:
            files[info.filename.rsplit("/", 1)[-1]] = read_member(zf, info.filename, MAX_SVG_BYTES)
        except UnsafeInput:
            continue
    return import_svg_pack(files, library_id, label, family)


# ----------------------------------------------------------------- registry

_LOCK = threading.RLock()
_BUILTIN: dict = {}
_EXTRA: dict = {}
_HERE = os.path.dirname(os.path.abspath(__file__))


def load_builtin(force: bool = False) -> dict:
    """Every ``symbols/<dir>/library.json`` shipped with SATOM, by library id."""
    with _LOCK:
        if _BUILTIN and not force:
            return dict(_BUILTIN)
        _BUILTIN.clear()
        for d in sorted(os.listdir(_HERE)):
            base = os.path.join(_HERE, d)
            jf = os.path.join(base, "library.json")
            if not (os.path.isdir(base) and os.path.isfile(jf)):
                continue
            with open(jf, "rb") as fh:
                obj = json.loads(fh.read().decode("utf-8"))
            svgs = {}
            for s in obj.get("symbols", []):
                name = s.get("svg") if isinstance(s, dict) else None
                if isinstance(name, str) and SVG_NAME_RE.match(name):
                    p = os.path.join(base, name)
                    if os.path.isfile(p):
                        with open(p, "rb") as fh:
                            svgs[name] = fh.read()
            lib = load_library(obj, svgs, builtin=True)
            _BUILTIN[lib["id"]] = lib
        return dict(_BUILTIN)


def register(lib: dict) -> None:
    """Make an operator library visible to :func:`libraries` / :func:`symbol`."""
    with _LOCK:
        load_builtin()
        if lib["id"] in _BUILTIN:
            raise LibraryError("library id %r belongs to a built-in library" % lib["id"])
        _EXTRA[lib["id"]] = lib


def unregister(lib_id: str) -> None:
    with _LOCK:
        _EXTRA.pop(lib_id, None)


def libraries() -> dict:
    """Built-in plus registered libraries (built-in ids always win)."""
    with _LOCK:
        out = dict(_EXTRA)
        out.update(load_builtin())
        return {k: out[k] for k in sorted(out)}


def symbol(lib_id: str, sym_id: str) -> dict | None:
    lib = libraries().get(lib_id)
    if not lib:
        return None
    for s in lib["symbols"]:
        if s["id"] == sym_id:
            return s
    return None


def _lib_iter(libs):
    if libs is None:
        libs = libraries()
    if isinstance(libs, dict):
        libs = [libs[k] for k in sorted(libs)]
    return list(libs)


def categories(libs=None) -> dict:
    """The category registry: ``{"families": [{id, label, classes: [{id, label,
    count, symbols: ["lib/sym"]}]}]}`` derived from the libraries' data."""
    fam_label: dict = {}
    cls_label: dict = {}
    members: dict = {}
    for lib in _lib_iter(libs):
        for fid, f in lib.get("families", {}).items():
            fam_label.setdefault(fid, f["label"])
            for cid, cl in f.get("classes", {}).items():
                cls_label.setdefault((fid, cid), cl)
        for s in lib["symbols"]:
            fid, cid = s["category"].split(".")
            members.setdefault(fid, {}).setdefault(cid, []).append("%s/%s" % (lib["id"], s["id"]))
            cls_label.setdefault((fid, cid), s["label"] if cid == s["id"].replace("-", "_") else _titleize(cid))
    order = [f for f in FAMILY_ORDER if f in members] + sorted(f for f in members if f not in FAMILY_ORDER)
    fams = []
    for fid in order:
        classes = [{"id": cid, "label": cls_label[(fid, cid)], "count": len(syms), "symbols": sorted(syms)}
                   for cid, syms in sorted(members[fid].items())]
        fams.append({"id": fid, "label": fam_label.get(fid, _titleize(fid)), "classes": classes})
    return {"families": fams}
