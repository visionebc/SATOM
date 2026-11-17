"""Round-trip fidelity: how much of document *a* survived into document *b*.

``compare(a, b, tol_px=1.0)`` normalises both, matches elements by id (fallback:
same text and bounding-box IoU), and reports, per category, what was missing,
extra or changed, an overall 0..100 score and the list of "not preserved"
items with the reason. Pure standard library; used by the round-trip tests and
by the editor's export dialog.
"""
from __future__ import annotations

from . import model

CATEGORIES = ("pages", "elements", "geometry", "text", "style", "connectors", "layers", "groups", "properties")
WEIGHTS = {"pages": 5, "elements": 20, "geometry": 20, "text": 15, "style": 10, "connectors": 15, "layers": 5,
           "groups": 5, "properties": 5}
MAX_ITEMS = 300
ROT_TOL = 0.5
LABEL_POS_TOL = 0.02
IOU_MIN = 0.5
OPACITY_TOL = 0.01
ANGLE_TOL = 1
PROVENANCE = ("drawio_", "svg_", "visio_", "vsdx_", "pdf_", "satom_type")


class _Report:
    def __init__(self):
        self.checked = {c: 0 for c in CATEGORIES}
        self.bad = {c: 0 for c in CATEGORIES}
        self.items: list[dict] = []
        self.detail = {c: [] for c in CATEGORIES}

    def check(self, cat: str, ok: bool, scope: str = "", what: str = "", reason: str = "", n: int = 1):
        self.checked[cat] += n
        if not ok:
            self.bad[cat] += n
            if len(self.items) < MAX_ITEMS:
                self.items.append({"category": cat, "item": scope, "what": what, "reason": reason})
            self.detail[cat].append("%s: %s" % (scope, what))


def _iou(a: dict, b: dict) -> float:
    x0, y0 = max(a["x"], b["x"]), max(a["y"], b["y"])
    x1, y1 = min(a["x"] + a["w"], b["x"] + b["w"]), min(a["y"] + a["h"], b["y"] + b["h"])
    inter = max(0.0, x1 - x0) * max(0.0, y1 - y0)
    union = a["w"] * a["h"] + b["w"] * b["h"] - inter
    return inter / union if union > 0 else (1.0 if (a["x"], a["y"]) == (b["x"], b["y"]) else 0.0)


def _norm_text(s: str) -> str:
    return " ".join(str(s or "").replace("\r", "").split())


def _labels(c: dict) -> list:
    """Every label as ``(text, pos)``; ``label`` counts once even when ``labels`` repeats it."""
    out = [(x["text"], x["pos"]) for x in c["labels"]]
    if c["label"] and not any(t == c["label"] for t, _ in out):
        out.append((c["label"], 0.5))
    return out


def _match_elements(ea: list, eb: list) -> tuple[dict, list, list]:
    ib = {e["id"]: e for e in eb}
    pairs, rest_a = {}, []
    for e in ea:
        if e["id"] in ib:
            pairs[e["id"]] = ib[e["id"]]
        else:
            rest_a.append(e)
    used = {id(v) for v in pairs.values()}
    rest_b = [e for e in eb if id(e) not in used]
    if rest_a and rest_b and len(rest_a) * len(rest_b) <= 4_000_000:
        for e in list(rest_a):
            best, best_iou = None, IOU_MIN
            for f in rest_b:
                if _norm_text(f["text"]) != _norm_text(e["text"]):
                    continue
                v = _iou(e, f)
                if v > best_iou:
                    best, best_iou = f, v
            if best is not None:
                pairs[e["id"]] = best
                rest_b.remove(best)
                rest_a.remove(e)
    return pairs, rest_a, rest_b


def _compare_effects(rep: _Report, sc: str, a: dict, b: dict, element: bool) -> None:
    """The colour-styling keys: dash pattern, shadow (+ colour when on), opacities
    (within ``OPACITY_TOL``: formats store percentages) and, for elements, the
    gradient (type; colour and, when linear, angle within ``ANGLE_TOL``)."""
    if a["dashed"] == b["dashed"]:            # on/off is the ``dashed`` check; this is the pattern itself
        rep.check("style", a["dash_pattern"] == b["dash_pattern"], sc,
                  "dash pattern %s -> %s" % (a["dash_pattern"], b["dash_pattern"]), "dash pattern not kept")
    ok = a["shadow"] == b["shadow"] and (not a["shadow"] or a["shadow_color"] == b["shadow_color"])
    rep.check("style", ok, sc, "shadow %s/%s -> %s/%s" % (a["shadow"], a["shadow_color"], b["shadow"], b["shadow_color"]),
              "shadow not kept")
    keys = ("fill_opacity", "stroke_opacity") if element else ("stroke_opacity",)
    for k in keys:
        rep.check("style", abs(a[k] - b[k]) <= OPACITY_TOL, sc, "%s %s -> %s" % (k, a[k], b[k]), "opacity not kept")
    if element:
        ga, gb = a["gradient"], b["gradient"]
        ok = ga["type"] == gb["type"]
        if ok and ga["type"] != "none":
            ok = ga["color"] == gb["color"] and (ga["type"] != "linear" or _angle_diff(ga["angle"], gb["angle"]) <= ANGLE_TOL)
        rep.check("style", ok, sc, "gradient %s -> %s" % (_grad_text(ga), _grad_text(gb)), "gradient not kept")


def _angle_diff(x: float, y: float) -> float:
    d = abs(x - y) % 360
    return min(d, 360 - d)


def _grad_text(g: dict) -> str:
    return "none" if g["type"] == "none" else "%s %s %d deg" % (g["type"], g["color"], g["angle"])


def _compare_page(pa: dict, pb: dict, tol: float, rep: _Report, label: str):
    pairs, miss, extra = _match_elements(pa["elements"], pb["elements"])
    idmap = {a_id: b["id"] for a_id, b in pairs.items()}
    for e in miss:
        rep.check("elements", False, "%s/element:%s" % (label, e["id"]), "missing",
                  "not found in the second document (%s %s)" % (e["kind"], e["shape"]))
    for e in extra:
        rep.check("elements", False, "%s/element:%s" % (label, e["id"]), "extra", "only in the second document")
    pb_by = {e["id"]: e for e in pb["elements"]}
    pa_by = {e["id"]: e for e in pa["elements"]}
    for aid, b in pairs.items():
        a = pa_by[aid]
        sc = "%s/element:%s" % (label, aid)
        rep.check("elements", True)
        for k in ("kind", "shape", "category", "symbol"):
            rep.check("elements", a[k] == b[k], sc, "%s %r -> %r" % (k, a[k], b[k]), "the format has no equivalent value")
        pa_parent = idmap.get(a["parent"], a["parent"]) if a["parent"] else ""
        rep.check("elements", pa_parent == b["parent"], sc, "parent %r -> %r" % (a["parent"], b["parent"]),
                  "container membership was not kept")
        deltas = {k: abs(a[k] - b[k]) for k in ("x", "y", "w", "h")}
        bad = {k: v for k, v in deltas.items() if v > tol}
        rep.check("geometry", not bad, sc, "moved/resized %s" % ", ".join("%s by %.1f" % kv for kv in bad.items()),
                  "geometry differs by more than %.1f px" % tol)
        rep.check("geometry", abs(a["rotation"] - b["rotation"]) <= ROT_TOL, sc,
                  "rotation %s -> %s" % (a["rotation"], b["rotation"]), "rotation not kept")
        rep.check("text", _norm_text(a["text"]) == _norm_text(b["text"]), sc,
                  "text %r -> %r" % (a["text"][:40], b["text"][:40]), "text changed")
        for k in ("fill", "stroke", "dashed"):
            va, vb = a["style"][k], b["style"][k]
            rep.check("style", va == vb, sc, "%s %r -> %r" % (k, va, vb), "style value not kept")
        _compare_effects(rep, sc, a["style"], b["style"], element=True)
        rep.check("properties", a["properties"] == b["properties"], sc,
                  "properties %s -> %s" % (sorted(a["properties"]), sorted(b["properties"])), "custom properties not kept")
        # Keys a reader adds to say where something came from (drawio_*, svg_*...) are not user data.
        extra = {k: v for k, v in b["metadata"].items() if k not in a["metadata"] and k.startswith(PROVENANCE)}
        meta_b = {k: v for k, v in b["metadata"].items() if k not in extra}
        rep.check("properties", a["metadata"] == meta_b, sc, "metadata differs", "metadata not kept")
        # An empty name is not a loss: readers derive one from the text.
        rep.check("properties", a["description"] == b["description"] and (not a["name"] or a["name"] == b["name"]), sc,
                  "name/description differ", "name or description not kept")
    # connectors
    cb_by = {c["id"]: c for c in pb["connectors"]}
    used_b: set = set()
    cpairs = {}
    rest = []
    for c in pa["connectors"]:
        if c["id"] in cb_by:
            cpairs[c["id"]] = cb_by[c["id"]]
            used_b.add(c["id"])
        else:
            rest.append(c)
    spare = [c for c in pb["connectors"] if c["id"] not in used_b]
    for c in rest:
        key = (idmap.get(c["source"], c["source"]), idmap.get(c["target"], c["target"]), c["label"])
        for f in spare:
            if (f["source"], f["target"], f["label"]) == key:
                cpairs[c["id"]] = f
                spare.remove(f)
                break
        else:
            rep.check("connectors", False, "%s/connector:%s" % (label, c["id"]), "missing", "not found in the second document")
    for f in spare:
        rep.check("connectors", False, "%s/connector:%s" % (label, f["id"]), "extra", "only in the second document")
    ca_by = {c["id"]: c for c in pa["connectors"]}
    for cid, b in cpairs.items():
        a = ca_by[cid]
        sc = "%s/connector:%s" % (label, cid)
        rep.check("connectors", True)
        for k in ("source", "target"):
            ea, eb = idmap.get(a[k], a[k]), b[k]
            rep.check("connectors", ea == eb, sc, "%s %r -> %r" % (k, a[k], b[k]), "endpoint attachment not kept")
        for k in ("start_arrow", "end_arrow"):
            rep.check("connectors", a[k] == b[k], sc, "%s %s -> %s" % (k, a[k], b[k]), "arrowhead not kept")
        rep.check("connectors", a["routing"] == b["routing"], sc, "routing %s -> %s" % (a["routing"], b["routing"]),
                  "routing style not kept")
        same_pts = len(a["points"]) == len(b["points"]) and all(
            abs(p[0] - q[0]) <= tol and abs(p[1] - q[1]) <= tol for p, q in zip(a["points"], b["points"]))
        rep.check("connectors", same_pts, sc, "waypoints differ", "waypoints not kept")
        for key in ("start", "end"):
            if a[key] or b[key]:
                ok = len(a[key]) == len(b[key]) == 2 and all(abs(p - q) <= tol for p, q in zip(a[key], b[key]))
                rep.check("connectors", ok, sc, "free %s end differs" % key, "free end position not kept")
        la, lb = _labels(a), _labels(b)
        ok = sorted(t for t, _ in la) == sorted(t for t, _ in lb) and all(
            abs(p - q) <= LABEL_POS_TOL for (_, p), (_, q) in zip(sorted(la), sorted(lb)))
        rep.check("connectors", ok, sc, "labels %s -> %s" % ([t for t, _ in la][:3], [t for t, _ in lb][:3]), "label text/position not kept")
        for k in ("stroke", "dashed"):
            rep.check("style", a["style"][k] == b["style"][k], sc, "%s %r -> %r" % (k, a["style"][k], b["style"][k]),
                      "style value not kept")
        _compare_effects(rep, sc, a["style"], b["style"], element=False)
        rep.check("properties", a["properties"] == b["properties"], sc, "properties differ", "custom properties not kept")
    # layers
    lb_by = {lr["id"]: lr for lr in pb["layers"]}
    layer_order_b = [lr["id"] for lr in pb["layers"]]
    for lr in pa["layers"]:
        sc = "%s/layer:%s" % (label, lr["id"])
        o = lb_by.get(lr["id"])
        if o is None:
            # fallback by name and position
            o = next((x for x in pb["layers"] if x["name"] == lr["name"]), None)
        rep.check("layers", o is not None, sc, "missing", "layer not found in the second document")
        if o is not None:
            for k in ("name", "visible", "locked"):
                rep.check("layers", lr[k] == o[k], sc, "%s %r -> %r" % (k, lr[k], o[k]), "layer %s not kept" % k)
    if len(pa["layers"]) != len(pb["layers"]):
        rep.check("layers", False, label + "/layers", "count %d -> %d" % (len(pa["layers"]), len(pb["layers"])), "layer list differs")
    lname_a = {lr["id"]: lr["name"] for lr in pa["layers"]}
    lname_b = {lr["id"]: lr["name"] for lr in pb["layers"]}
    for aid, b in pairs.items():
        a = pa_by[aid]
        rep.check("layers", lname_a.get(a["layer"]) == lname_b.get(b["layer"]), "%s/element:%s" % (label, aid),
                  "layer %r -> %r" % (lname_a.get(a["layer"]), lname_b.get(b["layer"])), "element moved to another layer")
    del layer_order_b
    # groups: by member set
    def gset(page, mapping):
        out = {}
        for g in page["groups"]:
            out[frozenset(mapping.get(m, m) for m in g["members"])] = g
        return out
    ga, gb = gset(pa, dict(idmap, **{cid: f["id"] for cid, f in cpairs.items()})), gset(pb, {})
    for ms, g in ga.items():
        rep.check("groups", ms in gb, "%s/group:%s" % (label, g["id"]), "missing (%d members)" % len(ms), "group not kept")
    for ms, g in gb.items():
        if ms not in ga:
            rep.check("groups", False, "%s/group:%s" % (label, g["id"]), "extra group", "only in the second document")


def compare(a, b, *, tol_px: float = 1.0) -> dict:
    """Report on what *b* kept of *a* (both ``satom.diagram/1``, normalised here)."""
    na, _ = model.normalise(a)
    nb, _ = model.normalise(b)
    rep = _Report()
    pa, pb = na["pages"], nb["pages"]
    rep.check("pages", len(pa) == len(pb), "document", "page count %d -> %d" % (len(pa), len(pb)), "pages were dropped or added")
    for i in range(min(len(pa), len(pb))):
        label = "page%d" % (i + 1)
        rep.check("pages", True)
        rep.check("pages", pa[i]["name"] == pb[i]["name"], label, "name %r -> %r" % (pa[i]["name"], pb[i]["name"]), "page name not kept")
        rep.check("pages", abs(pa[i]["width"] - pb[i]["width"]) <= tol_px and abs(pa[i]["height"] - pb[i]["height"]) <= tol_px,
                  label, "size %sx%s -> %sx%s" % (pa[i]["width"], pa[i]["height"], pb[i]["width"], pb[i]["height"]),
                  "page size not kept")
        _compare_page(pa[i], pb[i], tol_px, rep, label)
    # score: weighted share of passing checks per category that has any checks
    wsum = sum(WEIGHTS[c] for c in CATEGORIES if rep.checked[c])
    score = 100.0
    cats = {}
    for c in CATEGORIES:
        n, bad = rep.checked[c], rep.bad[c]
        cats[c] = {"checked": n, "problems": bad, "details": rep.detail[c][:50]}
        if n and wsum:
            score -= 100.0 * WEIGHTS[c] / wsum * min(1.0, bad / n)
    score = round(max(0.0, score), 2)
    if any(rep.bad.values()) and score >= 100.0:
        score = 99.99
    return {"score": score, "identical": not any(rep.bad.values()), "categories": cats,
            "not_preserved": rep.items, "truncated": sum(rep.bad.values()) > len(rep.items)}
