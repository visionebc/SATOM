"""The look of a Plugin Studio app: a page designer built from blocks.

An author lays out two surfaces of a flow app (operator, 2026-10-23: "that the
user can put in divs or cards and change the colours ... a web designer"):

* ``page``   -- the operator's page: where each form field, the Run button and
  the result go, between headings, text, cards, rows, tabs, images...;
* ``result`` -- how a run is shown: the status, each Output step of the
  diagram where the author wants it, big-number tiles, the action buttons and
  the steps.

Plus an app ``theme`` (accent, page background, text, card surface, corner
radius) applied ONLY inside the app's own area: the sidebar, the top bar and
SATOM's stylesheet stay as they are, and every block is drawn with SATOM's own
classes (``fw-card``, ``btn-fw-primary``, ``fw-table`` ...) -- the design only
recolours and spaces them.

Why blocks and not HTML (decided with the operator, 2026-10-23): an author
needs only ``studio.script_library``, not super-admin, and the page is shown
inside SATOM's origin to operators who are signed in. Author HTML there is
stored XSS; author CSS too (``img-src https:`` lets an attribute selector send
what is typed in a password field out as an image request). So the design is
JSON, every value is checked against a closed vocabulary here, and the
templates build the markup:

* colours are ``#rgb``/``#rrggbb`` and nothing else ("free hex", operator);
* every other style is a preset name mapped to a fixed CSS value below;
* text is Markdown through ``wiki_markdown.render`` (raw HTML disabled, link
  schemes filtered);
* images are files uploaded to the app (PNG/JPEG/GIF/WebP, sniffed from the
  bytes; never SVG, which can carry script), served by SATOM with a
  ``default-src 'none'`` policy -- never a URL to another site.

A design never blocks a save (half-built work is never lost); a field placed
twice or a block naming an image that is not there is a PROBLEM that blocks
Publish; a colour pair that is hard to read is a WARNING (free hex: the author
may keep it).
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import secrets
from datetime import datetime

from markupsafe import Markup

from ..extensions import db

SURFACES = ("page", "result")
MAX_BLOCKS = 300
MAX_DEPTH = 8
MAX_JSON = 256 * 1024
MAX_COLUMNS = 4
MAX_TABS = 8
MAX_ASSETS = 12
ASSET_MAX = 512 * 1024
MIN_CONTRAST = 4.5
#: What SATOM's stylesheet draws when the design does not say (fortiweb.css
#: :root) -- used to judge contrast, never written out.
BASE = {"page_bg": "#F3F6FC", "surface": "#FFFFFF", "text": "#0C1B33", "accent": "#0A3F9F"}

_HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_ID = re.compile(r"^[a-z0-9]{1,16}$")
_ICON = re.compile(r"^bi-[a-z0-9-]{1,28}$")
_KEY = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_PATH = re.compile(r"^[A-Za-z0-9_.-]{0,100}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


class DesignError(ValueError):
    pass


# --------------------------------------------------------------------------- #
#  the vocabulary                                                              #
# --------------------------------------------------------------------------- #
#: style key -> {preset: css}. The ONLY CSS a design can produce besides the
#: hex colours.
PRESETS = {
    "padding": {"none": "0", "sm": "6px", "md": "12px", "lg": "20px", "xl": "32px"},
    "mb": {"none": "0", "sm": "6px", "md": "12px", "lg": "20px", "xl": "32px"},
    "radius": {"none": "0", "sm": "4px", "md": "8px", "lg": "14px", "pill": "999px"},
    "shadow": {"none": "none", "sm": "0 1px 3px rgba(12,27,51,.10)",
               "md": "0 4px 12px rgba(12,27,51,.12)", "lg": "0 10px 28px rgba(12,27,51,.16)"},
    "border": {"none": "0", "thin": "1px", "thick": "2px"},
    "size": {"sm": "12px", "md": "14px", "lg": "17px", "xl": "21px", "xxl": "28px"},
    "weight": {"normal": "400", "medium": "500", "bold": "700"},
    "align": {"left": "left", "center": "center", "right": "right"},
    "width": {"auto": "", "25": "25%", "33": "33.333%", "50": "50%", "66": "66.666%",
              "75": "75%", "100": "100%"},
}
COLORS = ("bg", "bg2", "color", "border_color")
STYLE_KEYS = COLORS + tuple(PRESETS)
THEME_COLORS = ("accent", "page_bg", "text", "surface", "border")
THEME_PRESETS = {"radius": {"none": "0", "sm": "4px", "md": "8px", "lg": "14px", "xl": "20px"},
                 "padding": PRESETS["padding"]}

#: prop kinds: text (max len), md (Markdown), enum (choices), icon, bool,
#: int (lo, hi), field, output, asset, path, url
_T = "text"


def _p(name, label, kind=_T, *, choices=None, default="", max=200, lo=0, hi=0):
    return {"name": name, "label": label, "kind": kind, "choices": list(choices or []),
            "default": default, "max": max, "lo": lo, "hi": hi}


_TONES = ("info", "success", "warning", "danger", "neutral")
_VIEWS = ("", "auto", "table", "list", "keyvalue", "text", "json")

#: type -> {label, group, surfaces, props, container}
BLOCKS: dict[str, dict] = {
    # containers
    "section": {"label": "Section", "group": "Layout", "container": "children",
                "props": [_p("title", "Title", max=120), _p("icon", "Icon", "icon")]},
    "card": {"label": "Card", "group": "Layout", "container": "children",
             "props": [_p("title", "Title", max=120), _p("icon", "Icon", "icon")]},
    "row": {"label": "Columns", "group": "Layout", "container": "columns",
            "props": [_p("gap", "Gap", "enum", choices=("none", "sm", "md", "lg"), default="md")]},
    "tabs": {"label": "Tabs", "group": "Layout", "container": "tabs", "props": []},
    # content
    "banner": {"label": "Banner", "group": "Content",
               "props": [_p("title", "Title", max=160), _p("subtitle", "Subtitle", max=400),
                         _p("icon", "Icon", "icon")]},
    "heading": {"label": "Heading", "group": "Content",
                "props": [_p("text", "Text", max=200), _p("level", "Level", "enum",
                                                         choices=("1", "2", "3", "4"), default="2"),
                          _p("icon", "Icon", "icon")]},
    "text": {"label": "Text", "group": "Content", "props": [_p("md", "Text (Markdown)", "md", max=8000)]},
    "callout": {"label": "Callout", "group": "Content",
                "props": [_p("tone", "Tone", "enum", choices=_TONES, default="info"),
                          _p("title", "Title", max=160), _p("md", "Text (Markdown)", "md", max=4000),
                          _p("icon", "Icon", "icon")]},
    "image": {"label": "Image", "group": "Content",
              "props": [_p("asset", "Image", "asset"), _p("alt", "Description (alt text)", max=200),
                        _p("fit", "Fit", "enum", choices=("natural", "cover"), default="natural"),
                        _p("height", "Height (px, 0 = natural)", "int", lo=0, hi=800, default=0)]},
    "link": {"label": "Link button", "group": "Content",
             "props": [_p("label", "Label", max=80), _p("url", "Address", "url", max=500),
                       _p("icon", "Icon", "icon"),
                       _p("variant", "Look", "enum", choices=("primary", "outline", "link"),
                          default="outline")]},
    "divider": {"label": "Divider", "group": "Content", "props": []},
    "spacer": {"label": "Spacer", "group": "Content",
               "props": [_p("size", "Height", "enum", choices=("sm", "md", "lg", "xl"), default="md")]},
    # the page
    "description": {"label": "App description", "group": "Page", "surfaces": ("page",), "props": []},
    "field": {"label": "Form field", "group": "Page", "surfaces": ("page",),
              "props": [_p("name", "Field", "field")]},
    "run_button": {"label": "Run button", "group": "Page", "surfaces": ("page",),
                   "props": [_p("label", "Label", max=60, default="Run"),
                             _p("icon", "Icon", "icon", default="bi-play-fill"),
                             _p("full", "Full width", "bool")]},
    "result": {"label": "Result area", "group": "Page", "surfaces": ("page",),
               "props": [_p("placeholder", "Text before the first run", max=300)]},
    "recent_runs": {"label": "Recent runs", "group": "Page", "surfaces": ("page",),
                    "props": [_p("limit", "How many", "int", lo=1, hi=15, default=10)]},
    # the result
    "status": {"label": "Run status", "group": "Result", "surfaces": ("result",), "props": []},
    "output": {"label": "Output", "group": "Result", "surfaces": ("result",),
               "props": [_p("key", "Output step", "output"), _p("title", "Title (empty = the step's)", max=160),
                         _p("view", "Show as (empty = the step's)", "enum", choices=_VIEWS),
                         _p("bare", "Without a card", "bool")]},
    "stat": {"label": "Number tile", "group": "Result", "surfaces": ("result",),
             "props": [_p("key", "Output step", "output"),
                       _p("path", "Value inside it (a.b.0, empty = all; a list counts)", "path"),
                       _p("label", "Label", max=120), _p("unit", "Unit", max=20), _p("icon", "Icon", "icon")]},
    "outputs": {"label": "Other outputs", "group": "Result", "surfaces": ("result",), "props": []},
    "actions": {"label": "Action buttons", "group": "Result", "surfaces": ("result",), "props": []},
    "steps": {"label": "Steps", "group": "Result", "surfaces": ("result",),
              "props": [_p("open", "Open", "bool")]},
}
#: Blocks a surface always has: added at the end when the author left them out
#: (an operator never loses the Run button, a field, an error or an action).
REQUIRED = {"page": ("run_button", "result"), "result": ("status", "outputs", "actions", "steps")}


def schema() -> dict:
    """What the editor draws its palette and inspector from."""
    return {"blocks": {k: {"label": v["label"], "group": v["group"],
                           "surfaces": list(v.get("surfaces") or SURFACES),
                           "container": v.get("container") or "", "props": v["props"]}
                       for k, v in BLOCKS.items()},
            "presets": {k: list(v) for k, v in PRESETS.items()},
            "theme_presets": {k: list(v) for k, v in THEME_PRESETS.items()},
            "colors": list(COLORS), "theme_colors": list(THEME_COLORS),
            "limits": {"blocks": MAX_BLOCKS, "depth": MAX_DEPTH, "columns": MAX_COLUMNS,
                       "tabs": MAX_TABS, "assets": MAX_ASSETS, "asset_bytes": ASSET_MAX},
            "required": {k: list(v) for k, v in REQUIRED.items()}, "min_contrast": MIN_CONTRAST}


# --------------------------------------------------------------------------- #
#  colours                                                                     #
# --------------------------------------------------------------------------- #
def hex6(v) -> str:
    """``#rrggbb`` (upper case) for a valid hex colour, else ``""``."""
    s = str(v or "").strip()
    if not _HEX.match(s):
        return ""
    if len(s) == 4:
        s = "#" + "".join(c * 2 for c in s[1:])
    return s.upper()


def _rgb(h: str) -> tuple[int, int, int]:
    return int(h[1:3], 16), int(h[3:5], 16), int(h[5:7], 16)


def luminance(h: str) -> float:
    def ch(c):
        c = c / 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = _rgb(h)
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def contrast(a: str, b: str) -> float:
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return round((hi + 0.05) / (lo + 0.05), 2)


def _shade(h: str, f: float) -> str:
    """``h`` darkened (f < 0) or lightened (f > 0) by |f|."""
    r, g, b = _rgb(h)
    if f < 0:
        r, g, b = (int(c * (1 + f)) for c in (r, g, b))
    else:
        r, g, b = (int(c + (255 - c) * f) for c in (r, g, b))
    return "#%02X%02X%02X" % (r, g, b)


# --------------------------------------------------------------------------- #
#  cleaning                                                                    #
# --------------------------------------------------------------------------- #
def empty() -> dict:
    return {"theme": {}, "page": [], "result": []}


def _new_id(seen: set) -> str:
    while True:
        i = secrets.token_hex(4)
        if i not in seen:
            seen.add(i)
            return i


def clean_style(s) -> dict:
    out = {}
    if not isinstance(s, dict):
        return out
    for k in COLORS:
        h = hex6(s.get(k))
        if h:
            out[k] = h
        elif s.get(k):
            raise DesignError("colour %s: %r is not a hex colour such as #0A3F9F" % (k, s.get(k)))
    for k, presets in PRESETS.items():
        v = s.get(k)
        if v in (None, ""):
            continue
        v = str(v)
        if v not in presets:
            raise DesignError("style %s: %r is not one of %s" % (k, v, ", ".join(presets)))
        out[k] = v
    return out


def clean_theme(t) -> dict:
    out = {}
    if not isinstance(t, dict):
        return out
    for k in THEME_COLORS:
        h = hex6(t.get(k))
        if h:
            out[k] = h
        elif t.get(k):
            raise DesignError("theme %s: %r is not a hex colour such as #0A3F9F" % (k, t.get(k)))
    for k, presets in THEME_PRESETS.items():
        v = t.get(k)
        if v not in (None, ""):
            if str(v) not in presets:
                raise DesignError("theme %s: %r is not one of %s" % (k, v, ", ".join(presets)))
            out[k] = str(v)
    return out


def _clean_prop(p: dict, v):
    kind = p["kind"]
    if kind == "bool":
        return bool(v)
    if kind == "int":
        try:
            n = int(v if v not in (None, "") else p["default"] or 0)
        except (TypeError, ValueError):
            raise DesignError("%s: a whole number" % p["label"]) from None
        return max(p["lo"], min(p["hi"], n))
    s = "" if v is None else str(v)
    if kind == "enum":
        s = s or str(p["default"])
        if s not in p["choices"]:
            raise DesignError("%s: %r is not one of %s" % (p["label"], s, ", ".join(p["choices"]) or "''"))
        return s
    s = s.strip()
    if kind == "icon":
        if s and not _ICON.match(s):
            raise DesignError("%s: a Bootstrap icon name such as bi-star" % p["label"])
        return s
    if kind in ("field", "output"):
        if s and not _KEY.match(s):
            raise DesignError("%s: %r is not a field/step name" % (p["label"], s))
        return s
    if kind == "asset":
        if s and not _SHA.match(s):
            raise DesignError("%s: not an uploaded image" % p["label"])
        return s
    if kind == "path":
        if not _PATH.match(s):
            raise DesignError("%s: letters, digits, _, - and dots" % p["label"])
        return s
    if kind == "url":
        from .url_safety import safe_url
        if s and safe_url(s) is None:
            raise DesignError("%s: an http(s) address, a mail address or a SATOM path" % p["label"])
        return s[:p["max"]]
    return s[:p["max"]]


def _clean_list(blocks, surface: str, depth: int, seen: set, count: list) -> list:
    if blocks is None:
        return []
    if not isinstance(blocks, list):
        raise DesignError("a list of blocks was expected")
    if depth > MAX_DEPTH:
        raise DesignError("blocks are nested more than %d deep" % MAX_DEPTH)
    return [_clean_block(b, surface, depth, seen, count) for b in blocks]


def _clean_block(b, surface: str, depth: int, seen: set, count: list) -> dict:
    if not isinstance(b, dict):
        raise DesignError("each block is an object")
    count[0] += 1
    if count[0] > MAX_BLOCKS:
        raise DesignError("at most %d blocks" % MAX_BLOCKS)
    typ = str(b.get("type") or "")
    spec = BLOCKS.get(typ)
    if spec is None:
        raise DesignError("unknown block type %r" % typ)
    if surface not in (spec.get("surfaces") or SURFACES):
        raise DesignError("a %s block does not belong in the %s" % (spec["label"], surface))
    bid = str(b.get("id") or "")
    if not _ID.match(bid) or bid in seen:
        bid = _new_id(seen)
    seen.add(bid)
    props = b.get("props") if isinstance(b.get("props"), dict) else {}
    out = {"id": bid, "type": typ,
           "props": {p["name"]: _clean_prop(p, props.get(p["name"], p["default"])) for p in spec["props"]},
           "style": clean_style(b.get("style"))}
    cont = spec.get("container")
    if cont == "children":
        out["children"] = _clean_list(b.get("children"), surface, depth + 1, seen, count)
    elif cont == "columns":
        cols = b.get("columns") if isinstance(b.get("columns"), list) else []
        if not cols:
            cols = [{"w": 6}, {"w": 6}]
        if len(cols) > MAX_COLUMNS:
            raise DesignError("a row has at most %d columns" % MAX_COLUMNS)
        out["columns"] = []
        for c in cols:
            c = c if isinstance(c, dict) else {}
            try:
                w = max(1, min(12, int(c.get("w") or 0) or 12 // len(cols)))
            except (TypeError, ValueError):
                raise DesignError("a column width is a whole number from 1 to 12") from None
            out["columns"].append({"w": w, "children": _clean_list(c.get("children"), surface,
                                                                  depth + 1, seen, count)})
    elif cont == "tabs":
        tabs = b.get("tabs") if isinstance(b.get("tabs"), list) else []
        if not tabs:
            tabs = [{"label": "Tab 1"}]
        if len(tabs) > MAX_TABS:
            raise DesignError("at most %d tabs" % MAX_TABS)
        out["tabs"] = [{"label": (str((t or {}).get("label") or "").strip()[:60] or "Tab %d" % (i + 1)),
                        "children": _clean_list((t or {}).get("children"), surface, depth + 1, seen, count)}
                       for i, t in enumerate(tabs)]
    return out


def clean(design) -> dict:
    """A design as stored: every value checked, unknown keys dropped, ids made
    unique. Raises DesignError on a value outside the vocabulary."""
    if design in (None, "", {}):
        return empty()
    if not isinstance(design, dict):
        raise DesignError("the design is an object")
    if len(json.dumps(design)) > MAX_JSON:
        raise DesignError("the design is larger than %d KiB" % (MAX_JSON // 1024))
    seen, count = set(), [0]
    return {"theme": clean_theme(design.get("theme")),
            "page": _clean_list(design.get("page"), "page", 1, seen, count),
            "result": _clean_list(design.get("result"), "result", 1, seen, count)}


def walk(blocks):
    """Every block of a list, depth first."""
    for b in blocks or []:
        yield b
        for kid in b.get("children") or []:
            yield from walk([kid])
        for c in b.get("columns") or []:
            yield from walk(c.get("children"))
        for t in b.get("tabs") or []:
            yield from walk(t.get("children"))


def is_empty(design: dict | None, surface: str) -> bool:
    return not (design or {}).get(surface)


# --------------------------------------------------------------------------- #
#  problems and warnings                                                       #
# --------------------------------------------------------------------------- #
def output_keys(graph: dict) -> list[str]:
    return [n.get("key") for n in (graph or {}).get("nodes") or [] if n.get("kind") == "output"]


def problems(design: dict, fields: list, graph: dict, assets: set) -> list[str]:
    """What blocks Publish."""
    errs = []
    names = {f.get("name") for f in fields or []}
    placed = {}
    for b in walk(design.get("page")):
        if b["type"] == "field":
            n = b["props"].get("name")
            if not n:
                errs.append("design: a Form field block names no field")
            elif n not in names:
                errs.append("design: the page shows field %s, which is not in the form" % n)
            elif n in placed:
                errs.append("design: field %s is on the page twice" % n)
            placed[n] = True
    for t in ("run_button", "result"):
        if sum(1 for b in walk(design.get("page")) if b["type"] == t) > 1:
            errs.append("design: the page has more than one %s" % BLOCKS[t]["label"])
    outs = set(output_keys(graph))
    for b in walk(design.get("result")):
        if b["type"] in ("output", "stat") and not b["props"].get("key"):
            errs.append("design: a %s block names no Output step" % BLOCKS[b["type"]]["label"])
        elif b["type"] in ("output", "stat") and b["props"]["key"] not in outs:
            errs.append("design: the result shows output %s, which is not an Output step of the "
                        "diagram" % b["props"]["key"])
    for surf in SURFACES:
        for b in walk(design.get(surf)):
            if b["type"] == "image":
                if not b["props"].get("asset"):
                    errs.append("design: an Image block has no image")
                elif b["props"]["asset"] not in assets:
                    errs.append("design: an Image block names an image that is not uploaded")
    return sorted(set(errs))


def _label(b: dict) -> str:
    p = b.get("props") or {}
    name = p.get("title") or p.get("text") or p.get("label") or p.get("name") or p.get("key") or ""
    return "%s%s" % (BLOCKS[b["type"]]["label"], " '%s'" % str(name)[:40] if name else "")


def warnings(design: dict) -> list[str]:
    """Colour pairs that are hard to read (free hex: they do not block)."""
    th = design.get("theme") or {}
    page_bg = th.get("page_bg") or BASE["page_bg"]
    surface = th.get("surface") or BASE["surface"]
    text = th.get("text") or BASE["text"]
    out = []
    if th.get("accent") and contrast(th["accent"], "#FFFFFF") < 3:
        out.append("theme: white button text on the accent %s has contrast %.1f:1 (3:1 at least)"
                   % (th["accent"], contrast(th["accent"], "#FFFFFF")))
    if contrast(text, page_bg) < MIN_CONTRAST:
        out.append("theme: text %s on the page background %s has contrast %.1f:1 (%.1f:1 recommended)"
                   % (text, page_bg, contrast(text, page_bg), MIN_CONTRAST))
    if contrast(text, surface) < MIN_CONTRAST:
        out.append("theme: text %s on the card surface %s has contrast %.1f:1 (%.1f:1 recommended)"
                   % (text, surface, contrast(text, surface), MIN_CONTRAST))

    def visit(blocks, bg, fg, where):
        for b in blocks or []:
            st = b.get("style") or {}
            cards = b["type"] in ("card", "output", "stat", "recent_runs")
            mybg = st.get("bg") or (surface if cards else bg)
            myfg = st.get("color") or fg
            bgs = [mybg] + ([st["bg2"]] if st.get("bg") and st.get("bg2") else [])
            if (st.get("bg") or st.get("color")) and b["type"] not in ("divider", "spacer"):
                worst = min(contrast(myfg, x) for x in bgs)
                if worst < MIN_CONTRAST:
                    out.append("%s: %s, text %s on %s has contrast %.1f:1 (%.1f:1 recommended)"
                               % (where, _label(b), myfg, " → ".join(bgs), worst, MIN_CONTRAST))
            visit(b.get("children"), mybg, myfg, where)
            for c in b.get("columns") or []:
                visit(c.get("children"), mybg, myfg, where)
            for t in b.get("tabs") or []:
                visit(t.get("children"), mybg, myfg, where)
    visit(design.get("page"), page_bg, text, "page")
    visit(design.get("result"), page_bg, text, "result")
    return out


# --------------------------------------------------------------------------- #
#  what the templates draw                                                     #
# --------------------------------------------------------------------------- #
def css(style: dict | None, *, kind: str = "") -> str:
    """The inline style of a block. Only checked hex colours and the preset
    table above can reach it -- ``clean_style`` already refused anything
    else, and this re-checks so a stored row edited by hand cannot inject."""
    s = style or {}
    out = []
    bg, bg2 = hex6(s.get("bg")), hex6(s.get("bg2"))
    if bg and bg2:
        out.append("background:linear-gradient(135deg,%s,%s)" % (bg, bg2))
    elif bg:
        out.append("background:%s" % bg)
    color = hex6(s.get("color"))
    if color:
        out.append("color:%s;--fw-text-primary:%s;--fw-text-secondary:%s" % (color, color, color))
    width = PRESETS["border"].get(str(s.get("border") or ""))
    if width and width != "0":
        out.append("border:%s solid %s" % (width, hex6(s.get("border_color")) or "var(--fw-border)"))
    elif width == "0":
        out.append("border:0")
    elif hex6(s.get("border_color")):
        out.append("border-color:%s" % hex6(s["border_color"]))
    for key, prop in (("padding", "padding"), ("mb", "margin-bottom"), ("radius", "border-radius"),
                      ("shadow", "box-shadow"), ("size", "font-size"), ("weight", "font-weight"),
                      ("align", "text-align")):
        v = PRESETS[key].get(str(s.get(key) or ""))
        if v is not None and str(s.get(key) or ""):
            out.append("%s:%s" % (prop, v))
    w = PRESETS["width"].get(str(s.get("width") or ""))
    if w:
        out.append("width:%s;max-width:100%%" % w)
        if s.get("align") == "center":
            out.append("margin-left:auto;margin-right:auto")
        elif s.get("align") == "right":
            out.append("margin-left:auto")
    return ";".join(out)


def theme_css(theme: dict | None) -> str:
    """CSS custom properties for the app's own area: SATOM's classes read
    them (``.btn-fw-primary`` → ``--fw-accent``, ``.fw-card`` →
    ``--fw-surface`` ...), so the app is recoloured without new CSS."""
    t = theme or {}
    out = []
    acc = hex6(t.get("accent"))
    if acc:
        r, g, b = _rgb(acc)
        out.append("--fw-accent:%s;--fw-accent-hover:%s;--fw-accent-light:rgba(%d,%d,%d,.10)"
                   % (acc, _shade(acc, -0.25), r, g, b))
    if hex6(t.get("page_bg")):
        out.append("--sapp-page-bg:%s" % hex6(t["page_bg"]))
        if not t.get("padding"):
            out.append("--sapp-pad:16px")
    if hex6(t.get("text")):
        out.append("--fw-text-primary:%s;color:%s" % (hex6(t["text"]), hex6(t["text"])))
    if hex6(t.get("surface")):
        s = hex6(t["surface"])
        out.append("--fw-surface:%s;--fw-surface-alt:%s" % (s, _shade(s, -0.03)))
    if hex6(t.get("border")):
        out.append("--fw-border:%s;--fw-border-light:%s" % (hex6(t["border"]), hex6(t["border"])))
    rad = THEME_PRESETS["radius"].get(str(t.get("radius") or ""))
    if rad is not None and t.get("radius"):
        out.append("--fw-radius-lg:%s;--fw-radius:%s" % (rad, rad))
    pad = THEME_PRESETS["padding"].get(str(t.get("padding") or ""))
    if pad is not None and t.get("padding"):
        out.append("--sapp-pad:%s" % pad)
    return ";".join(out)


def md(text: str) -> Markup:
    from .wiki_markdown import render
    return render(text)


def safe_href(url: str) -> str:
    from .url_safety import safe_url
    return safe_url(url) or ""


def _first(blocks, typ):
    for b in walk(blocks):
        if b["type"] == typ:
            return b
    return None


def _parent_list(blocks, target):
    """The list that holds block ``target`` (by identity)."""
    for i, b in enumerate(blocks):
        if b is target:
            return blocks
    for b in blocks:
        for lst in ([b.get("children")] if b.get("children") is not None else []) + \
                   [c["children"] for c in b.get("columns") or []] + \
                   [t["children"] for t in b.get("tabs") or []]:
            found = _parent_list(lst, target)
            if found is not None:
                return found
    return None


def _auto(typ: str, seen: set, **props) -> dict:
    spec = BLOCKS[typ]
    p = {x["name"]: x["default"] for x in spec["props"]}
    p.update(props)
    return {"id": _new_id(seen), "type": typ, "props": p, "style": {}, "auto": True}


def page_tree(design: dict, fields: list) -> list | None:
    """The page as drawn: ``None`` for an app without a page design (the
    standard layout). Fields the design does not place go just before the
    Run button, so a required field can never be left off; a missing Run
    button or result area is added at the end."""
    if is_empty(design, "page"):
        return None
    tree = copy.deepcopy(design["page"])
    seen = {b["id"] for b in walk(tree)}
    placed = {b["props"].get("name") for b in walk(tree) if b["type"] == "field"}
    run = _first(tree, "run_button")
    if run is None:
        run = _auto("run_button", seen)
        tree.append(run)
    missing = [_auto("field", seen, name=f["name"]) for f in fields if f["name"] not in placed]
    if missing:
        host = _parent_list(tree, run)
        i = host.index(run)
        host[i:i] = missing
    if _first(tree, "result") is None:
        tree.append(_auto("result", seen))
    return tree


def result_tree(design: dict) -> list | None:
    if is_empty(design, "result"):
        return None
    tree = copy.deepcopy(design["result"])
    seen = {b["id"] for b in walk(tree)}
    if _first(tree, "status") is None:
        tree.insert(0, _auto("status", seen))
    for typ in ("outputs", "actions", "steps"):
        if _first(tree, typ) is None:
            tree.append(_auto(typ, seen))
    return tree


def starter(fields: list, graph: dict) -> dict:
    """The standard layout as a design: what "Start from the current layout"
    gives the editor."""
    seen: set = set()
    left = [_auto("field", seen, name=f["name"]) for f in fields] + [_auto("run_button", seen)]
    for b in left:
        b.pop("auto", None)
    card = {"id": _new_id(seen), "type": "card", "props": {"title": "", "icon": ""}, "style": {},
            "children": left}
    runs = _auto("recent_runs", seen)
    res = _auto("result", seen, placeholder="Fill in the form and press Run. The result appears here.")
    page = [{"id": _new_id(seen), "type": "row", "props": {"gap": "md"}, "style": {},
             "columns": [{"w": 4, "children": [card, runs]}, {"w": 8, "children": [res]}]}]
    result = [_auto("status", seen)] + [_auto("output", seen, key=k) for k in output_keys(graph)] + \
        [_auto("outputs", seen), _auto("actions", seen), _auto("steps", seen)]
    for b in walk(page + result):
        b.pop("auto", None)
    return {"theme": {}, "page": page, "result": result}


def output_titles(graph: dict) -> dict:
    return {n.get("key"): str((n.get("params") or {}).get("title") or n.get("label") or n.get("key"))
            for n in (graph or {}).get("nodes") or [] if n.get("kind") == "output"}


def render_result(design: dict, *, graph: dict | None = None, editing: bool = False,
                  app=None) -> str:
    """The result layout (slots the run page fills in), or "" without one."""
    from flask import render_template
    tree = result_tree(design) if not editing else copy.deepcopy(design.get("result") or [])
    if tree is None:
        return ""
    import sys
    return render_template("apps/_design_result.html", tree=tree, theme=design.get("theme") or {},
                           editing=editing, titles=output_titles(graph or {}), a=app,
                           D=sys.modules[__name__],
                           stamp=hashlib.sha1(json.dumps(design.get("result"), sort_keys=True)
                                              .encode(), usedforsecurity=False).hexdigest()[:12])


# --------------------------------------------------------------------------- #
#  images                                                                      #
# --------------------------------------------------------------------------- #
def sniff(data: bytes) -> str:
    """The image type from the bytes, or "" -- never from the file name or
    the browser's Content-Type. SVG is not an image here: it carries script."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if len(data) > 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return ""


EXT = {"image/png": "png", "image/jpeg": "jpg", "image/gif": "gif", "image/webp": "webp"}


def assets_of(app_id: int) -> list:
    from ..models_studio import StudioAppAsset
    return StudioAppAsset.query.filter_by(app_id=app_id).order_by(StudioAppAsset.id).all()


def asset_keys(app_id: int) -> set:
    from ..models_studio import StudioAppAsset
    return {r[0] for r in db.session.query(StudioAppAsset.sha256).filter_by(app_id=app_id)}


def add_asset(app_id: int, name: str, data: bytes, by: str):
    from ..models_studio import StudioAppAsset
    if not data:
        raise DesignError("the file is empty")
    if len(data) > ASSET_MAX:
        raise DesignError("an image is at most %d KiB" % (ASSET_MAX // 1024))
    mime = sniff(data)
    if not mime:
        raise DesignError("only PNG, JPEG, GIF and WebP images (SVG is not accepted)")
    sha = hashlib.sha256(data).hexdigest()
    row = StudioAppAsset.query.filter_by(app_id=app_id, sha256=sha).first()
    if row is not None:
        return row
    if StudioAppAsset.query.filter_by(app_id=app_id).count() >= MAX_ASSETS:
        raise DesignError("an app holds at most %d images: remove one first" % MAX_ASSETS)
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", str(name or ""))[:120] or "%s.%s" % (sha[:12], EXT[mime])
    row = StudioAppAsset(app_id=app_id, sha256=sha, mime=mime, name=name, size=len(data),
                         data=data, created_by=by, created_at=datetime.utcnow())
    db.session.add(row)
    db.session.commit()
    return row


def get_asset(app_id: int, sha: str):
    from ..models_studio import StudioAppAsset
    if not _SHA.match(str(sha or "")):
        return None
    return StudioAppAsset.query.filter_by(app_id=app_id, sha256=sha).first()


def used_assets(a) -> set:
    """Images the draft or the published version shows."""
    used = set()
    for d in (a.design, (a.published or {}).get("design") or {}):
        for surf in SURFACES:
            for b in walk(d.get(surf)):
                if b["type"] == "image" and b["props"].get("asset"):
                    used.add(b["props"]["asset"])
    return used


def remove_asset(a, sha: str) -> None:
    row = get_asset(a.id, sha)
    if row is None:
        raise DesignError("no such image")
    if sha in used_assets(a):
        raise DesignError("the draft or the published version shows this image: take it out of "
                          "the design (and publish) first")
    db.session.delete(row)
    db.session.commit()


def delete_assets(app_id: int) -> int:
    from ..models_studio import StudioAppAsset
    return StudioAppAsset.query.filter_by(app_id=app_id).delete(synchronize_session=False)
