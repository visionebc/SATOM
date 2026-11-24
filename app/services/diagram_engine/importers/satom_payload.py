"""SATOM's own live diagrams -> ``satom.diagram/1`` ("Open in Diagram Studio").

Architecture (``static/js/netarch.js``) and the Service Diagram
(``static/js/fleet_map.js``) describe what they have on screen in the neutral
shape their "Export to draw.io" already posts (``services/drawio_export.py``)::

    {"name": "...",
     "nodes": [{"id", "label", "sub"?, "x", "y", "w", "h",
                "shape"?: box|round|pill|ellipse|cloud|zone|diamond|table,
                "fill"?, "stroke"?, "font"?: "#RRGGBB", "dashed"?: bool,
                "kind"?: the page's element type, "rows"?: [{"id"?, "text", "bold"?}],
                "meta"?: {name: scalar}   -- appliance id, host, CIDR, VLAN ...,
                "state"?: str             -- the live overlay at copy time}],
     "edges": [{"from", "to", "label"?, "dashed"?, "color"?, "ends"?: arrow|none|crowfoot}]}

:func:`convert` maps that onto the native model: shapes onto model shapes, the
page's ``kind`` onto a category and a generic symbol (:data:`KIND_MAP`), table
rows kept, zones turned into containers whose children are found by geometry
(the smallest zone that holds an element's whole box), edges with their ends,
labels, dashes and colours.

What is NOT copied as structure: the live overlay. A health colour, a probe
answer or a "data: 3 min ago" freshness label is what the page knew at the
moment of the copy; it lands in the element's ``metadata.snapshot_state`` and
the document says so (``metadata.snapshot_note``). The copy is a drawing; the
live pages stay the live view.

Validation mirrors ``drawio_export.normalise`` (the same caps, shapes, colour
and kind rules: the web route runs that function first, so both refuse the
same payloads) and then ``model.normalise`` has the last word. Element
metadata is a whitelist: scalar values only, short keys, and never a key that
names a secret.

Not a file reader: the payload is JSON the console's own page built from data
the user may already see, the same input ``POST /diagram-studio/api/diagrams``
normalises in the web process. Nothing here parses a file, so nothing needs
the jail. Standalone: stdlib and this package only.
"""
from __future__ import annotations

import hashlib
import json
import math
import re

from .. import model
from . import ImportFailed

#: The live pages that can be copied, and their label.
SOURCES = {"architecture": "Architecture", "service-diagram": "Service Diagram"}

# --- the rules of services/drawio_export.py, mirrored (this package imports
# nothing outside itself; tests/test_diagram_from_satom.py pins them equal).
MAX_NODES = 5000
MAX_EDGES = 10000
MAX_ROWS = 400
MAX_LABEL = 300
MAX_COORD = 1_000_000.0
ROW_H = 22.0
HEADER_H = 30.0
PAYLOAD_SHAPES = ("box", "round", "pill", "ellipse", "cloud", "zone", "diamond", "table")
ENDS = ("arrow", "none", "crowfoot")
_HEX = re.compile(r"^#[0-9A-Fa-f]{6}$")
_KIND = re.compile(r"^[a-z][a-z0-9-]{0,39}$")

#: payload shape -> model shape.
SHAPE_MAP = {"box": "rect", "round": "round", "pill": "pill", "ellipse": "ellipse",
             "cloud": "cloud", "zone": "zone", "diamond": "diamond", "table": "table"}

#: payload edge ends -> (start_arrow, end_arrow). Crow's foot as draw.io gets
#: it from the export: many at the start, one at the end.
ARROWS = {"arrow": ("none", "arrow"), "none": ("none", "none"), "crowfoot": ("crowfoot", "bar")}

#: The page's element type -> (category, symbol of the generic library).
#: Every kind netarch.js (NODE_TYPES of services/netarch.py) and fleet_map.js
#: (its STUDIO_KINDS list) can emit is here; the test fails when one is not.
KIND_MAP = {
    # devices (both pages)
    "fortigate": ("network.firewall", "generic/firewall"),
    "fortiweb": ("network.waf", "generic/waf"),
    "fortiadc": ("network.load_balancer", "generic/load-balancer"),
    "fortiauthenticator": ("security.authentication", "generic/authentication"),
    "fortianalyzer": ("security.siem", "generic/siem"),
    "appliance": ("infra.server", "generic/server"),
    # networks
    "internet": ("network.internet", "generic/internet"),
    "lan": ("network.lan", "generic/lan"),
    "segment": ("network.subnet", "generic/subnet"),
    # a zone is a container: no icon, it would sit on the zone's own title
    "zone": ("network.zone", ""),
    # hosts
    "backend": ("infra.server", "generic/server"),
    "management": ("infra.server", "generic/server"),
    "host": ("infra.server", "generic/server"),
    # Service Diagram tiers: published service -> pool -> back-end servers
    "vip": ("software.web_app", "generic/web-app"),
    "pool": ("infra.ha_cluster", "generic/ha-cluster"),
    "servers": ("infra.server", "generic/server"),
}

#: Element metadata the copy keeps (appliance id, host, CIDR ...): short keys,
#: scalar values, and never a key that looks like it names a secret.
META_KEY = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
SECRET_KEY = re.compile(r"pass|secret|token|cred|cookie|header|session|private|otp|apikey|api_key"
                        r"|(^|_)key($|_)|(^|_)auth($|_)", re.I)
MAX_META = 16
MAX_META_VALUE = 200
MAX_STATE = 120
_TAKEN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:\d{2})?$")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

SNAPSHOT_NOTE = ("Copied from a live SATOM diagram. Health colours and live readings are a "
                 "snapshot of the moment of the copy (metadata snapshot_state) and are not "
                 "updated; the live page shows the current state.")

MARGIN = 40.0


def _text(v, n: int = MAX_LABEL) -> str:
    if v is None:
        return ""
    return _CTRL.sub("", str(v).replace("\r", ""))[:n]


def _num(v, default: float = 0.0, lo: float = -MAX_COORD, hi: float = MAX_COORD) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(f):
        return default
    return round(max(lo, min(hi, f)), 1)


def _colour(v):
    return v.upper() if isinstance(v, str) and _HEX.match(v) else None


def _meta(raw, warn) -> dict:
    out: dict = {}
    if not isinstance(raw, dict):
        return out
    for k, v in list(raw.items())[:64]:
        if len(out) >= MAX_META:
            warn("metadata: only the first %d values of an element are kept" % MAX_META)
            break
        if not isinstance(k, str) or not META_KEY.match(k):
            continue
        if SECRET_KEY.search(k):
            warn("metadata: a value named like a secret was not copied")
            continue
        if isinstance(v, bool):
            out[k] = v
        elif isinstance(v, (int, float)) and math.isfinite(float(v)):
            out[k] = v
        elif isinstance(v, str):
            s = _text(v, MAX_META_VALUE).strip()
            if s:
                out[k] = s
    return out


def _box(e) -> tuple:
    x, w = e.get("_page_x", e["x"]), e.get("_page_w", e["w"])
    return x, e["y"], x + w, e["y"] + e["h"]


def _holds(outer, inner, tol: float = 1.0) -> bool:
    ox0, oy0, ox1, oy1 = _box(outer)
    ix0, iy0, ix1, iy1 = _box(inner)
    return ix0 >= ox0 - tol and iy0 >= oy0 - tol and ix1 <= ox1 + tol and iy1 <= oy1 + tol


def convert(payload, *, source: str, name: str = "", taken_at: str = "",
            source_id=None) -> dict:
    """The normalised ``satom.diagram/1`` document for *payload*.

    Raises :class:`ImportFailed` with a sentence an operator can act on when
    the payload cannot be drawn (not an object, no element, over the caps,
    unknown source)."""
    if source not in SOURCES:
        raise ImportFailed("Unknown source %r: expected one of %s."
                           % (str(source)[:40], ", ".join(sorted(SOURCES))))
    if not isinstance(payload, dict):
        raise ImportFailed("The diagram must be a JSON object.")
    nodes_in, edges_in = payload.get("nodes"), payload.get("edges") or []
    if not isinstance(nodes_in, list) or not isinstance(edges_in, list):
        raise ImportFailed("nodes and edges must be lists.")
    if not nodes_in:
        raise ImportFailed("There is nothing drawn to copy yet.")
    if len(nodes_in) > MAX_NODES:
        raise ImportFailed("Too many elements (%d, max %d)." % (len(nodes_in), MAX_NODES))
    if len(edges_in) > MAX_EDGES:
        raise ImportFailed("Too many links (%d, max %d)." % (len(edges_in), MAX_EDGES))

    warnings: list = []
    seen_w: set = set()

    def warn(msg):
        if msg not in seen_w and len(warnings) < 200:
            seen_w.add(msg)
            warnings.append(msg)

    label = SOURCES[source]
    elements, end_of, row_of, src_ids = [], {}, {}, set()
    page_box: dict = {}          # element id -> (x, w) as the page drew it
    for i, n in enumerate(nodes_in):
        if not isinstance(n, dict):
            warn("element %d is not an object and was skipped" % i)
            continue
        sid = _text(n.get("id"), 200)
        if not sid:
            warn("element %d has no id and was skipped" % i)
            continue
        if sid in src_ids or sid in end_of:
            warn("duplicate element id %r skipped" % sid[:40])
            continue
        src_ids.add(sid)
        shape = n.get("shape") if n.get("shape") in PAYLOAD_SHAPES else "round"
        rows_in = n.get("rows") if isinstance(n.get("rows"), list) else []
        if rows_in and shape != "table":
            shape = "table"
        kind = n.get("kind") if isinstance(n.get("kind"), str) and _KIND.match(n["kind"]) else ""
        if not kind and shape == "zone":
            kind = "zone"
        cat, sym = KIND_MAP.get(kind, ("", ""))
        if kind and not cat:
            warn("element type %r has no category in Diagram Studio; drawn without one" % kind)
        lab, sub = _text(n.get("label")), _text(n.get("sub"))
        eid = "n%d" % (len(elements) + 1)
        is_zone = shape == "zone"
        fill, stroke, font = _colour(n.get("fill")), _colour(n.get("stroke")), _colour(n.get("font"))
        for k in ("fill", "stroke", "font"):
            if n.get(k) not in (None, "") and not _colour(n.get(k)):
                warn("a colour that is not #RRGGBB was dropped")
        e = {
            "id": eid,
            "kind": "container" if is_zone else "shape",
            "shape": SHAPE_MAP[shape],
            "category": cat, "symbol": sym,
            "name": lab,
            "text": lab if (is_zone or shape == "table") else (lab + ("\n" + sub if sub else "")),
            "description": sub if (is_zone or shape == "table") else "",
            "x": _num(n.get("x")), "y": _num(n.get("y")),
            "w": _num(n.get("w"), 160.0, 4.0, 20000.0),
            "h": _num(n.get("h"), 60.0, 4.0, 20000.0),
            "style": {
                "fill": fill or ("none" if is_zone else "#FFFFFF"),
                "stroke": stroke or "#64748B",
                "font_color": font or "#0C1B33",
                "dashed": n.get("dashed") is True or is_zone,
                "rounded": shape in ("round", "pill", "zone"),
                "bold": is_zone or shape == "table",
                "align": "left" if is_zone else "center",
                "valign": "top" if is_zone else "middle",
            },
            "rows": [],
            "metadata": {},
            "source_ref": _text(sid, 300),
        }
        meta = {"satom_source": source}
        if kind:
            meta["satom_kind"] = kind
        for k, v in _meta(n.get("meta"), warn).items():
            meta.setdefault(k, v)
        state = _text(n.get("state"), MAX_STATE).strip()
        if state:
            meta["snapshot_state"] = state
        e["metadata"] = meta
        end_of[sid] = eid
        if shape == "table":
            if len(rows_in) > MAX_ROWS:
                warn("table %r: only the first %d of %d rows copied" % (lab or sid, MAX_ROWS, len(rows_in)))
            for j, r in enumerate(rows_in[:MAX_ROWS]):
                r = r if isinstance(r, dict) else {"text": r}
                rid = _text(r.get("id"), 200)
                e["rows"].append({"id": "r%d" % j, "text": _text(r.get("text")),
                                  "bold": r.get("bold") is True})
                if rid:
                    if rid in end_of or rid in src_ids:
                        warn("duplicate row id %r: its links were dropped" % rid[:40])
                    else:
                        end_of[rid] = eid
                        row_of[rid] = "r%d" % j
            e["h"] = max(e["h"], HEADER_H + ROW_H * len(e["rows"]))
            # The page draws its rows in a smaller type: keep each row on one
            # line at 11 px instead of letting the editor wrap it into the next.
            # Widened about its centre, so the links above still meet it in the
            # middle; its container is still decided by the page's own box.
            longest = max([len(r["text"]) for r in e["rows"]] + [len(lab)])
            w0 = e["w"]
            e["w"] = max(w0, min(20000.0, round(16 + 6.6 * longest, 1)))
            e["x"] = round(e["x"] - (e["w"] - w0) / 2, 1)
            page_box[eid] = (e["x"] + (e["w"] - w0) / 2, w0)
            e["style"]["font_size"] = 11
        elements.append(e)
    if not elements:
        raise ImportFailed("None of the elements could be copied.")

    # The page's own coordinates, moved so the drawing starts at the margin.
    x0 = min(e["x"] for e in elements)
    y0 = min(e["y"] for e in elements)
    for e in elements:
        e["x"] = round(e["x"] - x0 + MARGIN, 1)
        e["y"] = round(e["y"] - y0 + MARGIN, 1)
        if e["id"] in page_box:
            px, pw = page_box[e["id"]]
            e["_page_x"], e["_page_w"] = round(px - x0 + MARGIN, 1), pw

    # Containers: the smallest zone that holds an element's whole box.
    zones = [e for e in elements if e["kind"] == "container"]
    for e in elements:
        best, area = "", None
        own = e.get("_page_w", e["w"]) * e["h"]
        for z in zones:
            if z is e:
                continue
            za = z["w"] * z["h"]
            if za <= own or not _holds(z, e):
                continue
            if area is None or za < area:
                best, area = z["id"], za
        e["parent"] = best
    for e in elements:
        e.pop("_page_x", None)
        e.pop("_page_w", None)
    # Zones first: painted behind what they hold (as the draw.io export does).
    elements = zones + [e for e in elements if e["kind"] != "container"]

    connectors = []
    for i, ed in enumerate(edges_in):
        if not isinstance(ed, dict):
            warn("link %d is not an object and was skipped" % i)
            continue
        a, b = _text(ed.get("from"), 200), _text(ed.get("to"), 200)
        if a not in end_of or b not in end_of:
            warn("link %s -> %s has an end that is not drawn; skipped" % (a[:40] or "?", b[:40] or "?"))
            continue
        ends = ed.get("ends") if ed.get("ends") in ENDS else "arrow"
        sa, ea = ARROWS[ends]
        c = {"id": "c%d" % (len(connectors) + 1), "source": end_of[a], "target": end_of[b],
             "routing": "straight", "start_arrow": sa, "end_arrow": ea,
             "label": _text(ed.get("label"), model.MAX_NAME),
             "style": {"stroke": _colour(ed.get("color")) or "#475569",
                       "dashed": ed.get("dashed") is True},
             "metadata": {"satom_source": source}}
        if ed.get("color") not in (None, "") and not _colour(ed.get("color")):
            warn("a colour that is not #RRGGBB was dropped")
        if a in row_of:
            c["metadata"]["source_row"] = row_of[a]
        if b in row_of:
            c["metadata"]["target_row"] = row_of[b]
        connectors.append(c)

    width = max(e["x"] + e["w"] for e in elements) + MARGIN
    height = max(e["y"] + e["h"] for e in elements) + MARGIN
    meta = {"satom_source": source, "satom_source_label": label,
            "satom_source_name": _text(payload.get("name"), 120),
            "snapshot_note": SNAPSHOT_NOTE}
    taken = str(taken_at or "")
    if _TAKEN.match(taken):
        meta["satom_copied_at"] = taken
    if isinstance(source_id, int) and not isinstance(source_id, bool) and 0 < source_id < 2 ** 53:
        meta["satom_source_id"] = source_id
    title = _text(name, model.MAX_NAME).strip() or "Copy of %s" % label
    sha = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    doc = {"schema": model.SCHEMA, "name": title, "metadata": meta,
           "source": {"format": "satom-" + source, "filename": "", "sha256": sha, "page": ""},
           "recognition": {"engine": "satom-live", "version": "1", "warnings": [], "stats": {}},
           "pages": [{"id": "page-1", "name": label, "width": width, "height": height,
                      "elements": elements, "connectors": connectors}]}
    try:
        out, norm = model.normalise(doc)
    except model.ModelError as exc:
        raise ImportFailed("The diagram is not valid: %s" % exc) from None
    for w in norm:
        warn(w)
    out["recognition"]["warnings"] = [str(w)[:500] for w in warnings]
    st = model.stats(out)
    out["recognition"]["stats"] = {k: v for k, v in st.items() if isinstance(v, (int, float))}
    return out
