"""Build a SATOM theme from a website: its brand colours, its mark and its favicon.

Settings -> Appearance -> "Import from a site" -> Website. The operator gives a
URL; this module reads the page and its stylesheets and returns the same shape
an imported theme file produces (:class:`theme_portable.Parsed`) plus a report
of where every value came from.

What it can and cannot take — said in the UI too, because the gap is the first
thing an operator will notice:

* SATOM's layout is fixed. A website's look arrives as **SATOM's tokens**:
  sidebar and top-bar colours, accent, brand gradients and glows. The page
  canvas, text and status colours stay on the shipped values (a dark canvas is
  not supported yet, see docs/theming.md §8), and so does the font: a web font
  would be blocked by the console's CSP and is missing on offline nodes.
* **The mark is a square.** The top bar shows the logo in a 28 x 28 slot, so a
  site's square icon (apple-touch-icon, then the largest icon) is preferred
  over its wide header wordmark, which is also usually drawn dark-on-white
  and would vanish on a dark top bar. The header image is the fallback.

Colour selection, in order of evidence:

1. the ``theme-color`` meta (a site states it on purpose);
2. brand-named custom properties (``--primary``, ``--brand-*``, ``--accent``…);
3. the most used saturated colour across backgrounds, text and borders.

A dark background on a header/nav/sidebar rule becomes the sidebar colour, so
a site with a dark navigation keeps it. Every derived pair is pushed to WCAG
AA (4.5:1) before it is returned: an import must never be the reason the
console became unreadable.
"""
from __future__ import annotations

import base64
import colorsys
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import unquote_to_bytes, urljoin, urlsplit

from . import theme_portable as tp
from . import theme_service

MAX_HTML_BYTES = 2 * 1024 * 1024
MAX_CSS_BYTES = 1536 * 1024
MAX_STYLESHEETS = 6
MAX_IMAGE_BYTES = tp.MAX_RASTER_BYTES

_ICON_RELS = {"icon", "shortcut", "apple-touch-icon", "apple-touch-icon-precomposed",
              "mask-icon"}
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
         "meta", "source", "track", "wbr"}
_CHROME_SEL = re.compile(r"header|\bnav|navbar|sidebar|side-bar|sidenav|topbar|top-bar"
                         r"|masthead|app-bar|appbar|menu", re.I)
_BRAND_VAR = re.compile(r"^--[\w-]*(primary|brand|accent|main|theme)[\w-]*$", re.I)
_SECOND_VAR = re.compile(r"^--[\w-]*(secondary|highlight|complement)[\w-]*$", re.I)


class _PageScan(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta: dict = {}
        self.icons: list = []
        self.stylesheets: list = []
        self.css: list = []
        self.imgs: list = []
        self.title = ""
        self.base = ""
        self._in_style = self._in_title = False
        self._header = 0
        self._logo_stack: list = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        hint = ("%s %s" % (a.get("class", ""), a.get("id", ""))).lower()
        if tag == "base" and a.get("href") and not self.base:
            self.base = a["href"]
        elif tag == "meta":
            key = (a.get("name") or a.get("property") or "").lower()
            if key and key not in self.meta:
                self.meta[key] = a.get("content", "")
        elif tag == "link":
            rels = set(a.get("rel", "").lower().split())
            href = a.get("href", "")
            if href and "stylesheet" in rels:
                self.stylesheets.append(href)
            if href and rels & _ICON_RELS:
                self.icons.append({"rels": rels, "href": href,
                                   "sizes": a.get("sizes", "").lower(),
                                   "type": a.get("type", "").lower(),
                                   "color": a.get("color", "")})
        elif tag == "style":
            self._in_style = True
        elif tag == "title":
            self._in_title = True
        elif tag == "img":
            src = a.get("src") or a.get("data-src") or ""
            if src:
                text = "%s %s %s" % (hint, a.get("alt", "").lower(), src.lower())
                self.imgs.append({"src": src,
                                  "logo": "logo" in text or bool(self._logo_stack),
                                  "header": self._header > 0})
        if a.get("style"):
            self.css.append("x{%s}" % a["style"])
        if tag in ("header", "nav"):
            self._header += 1
        if "logo" in hint and tag not in _VOID:
            self._logo_stack.append(tag)

    def handle_endtag(self, tag):
        if tag == "style":
            self._in_style = False
        elif tag == "title":
            self._in_title = False
        if tag in ("header", "nav") and self._header:
            self._header -= 1
        if self._logo_stack and self._logo_stack[-1] == tag:
            self._logo_stack.pop()

    def handle_data(self, data):
        if self._in_style:
            self.css.append(data)
        elif self._in_title and len(self.title) < 200:
            self.title += data


# ── colour helpers ──────────────────────────────────────────────────────────
_HEX_RE = re.compile(r"#([0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3,4})\b")
_FUNC_RE = re.compile(r"\b(rgba?|hsla?)\(([^)]*)\)", re.I)


def _parse(value: str) -> "tuple | None":
    """First colour in a CSS value as ``(r, g, b, alpha)``, or ``None``."""
    found = []
    for m in _HEX_RE.finditer(value):
        h = m.group(1)
        if len(h) in (3, 4):
            h = "".join(c * 2 for c in h)
        r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
        a = int(h[6:8], 16) / 255 if len(h) == 8 else 1.0
        found.append((m.start(), (r, g, b, a)))
    for m in _FUNC_RE.finditer(value):
        nums = re.findall(r"-?\d*\.?\d+%?", m.group(2))
        if len(nums) < 3:
            continue

        def num(s, scale):
            return float(s[:-1]) * scale / 100 if s.endswith("%") else float(s)
        try:
            if m.group(1).lower().startswith("rgb"):
                r, g, b = (max(0, min(255, num(n, 255))) for n in nums[:3])
            else:
                hue = float(nums[0].rstrip("%")) % 360 / 360
                sat = num(nums[1], 1) / (100 if not nums[1].endswith("%") else 1)
                lig = num(nums[2], 1) / (100 if not nums[2].endswith("%") else 1)
                rr, gg, bb = colorsys.hls_to_rgb(hue, max(0, min(1, lig)), max(0, min(1, sat)))
                r, g, b = rr * 255, gg * 255, bb * 255
            a = num(nums[3], 1) if len(nums) > 3 else 1.0
            if len(nums) > 3 and nums[3].endswith("%"):
                a = float(nums[3][:-1]) / 100
        except ValueError:
            continue
        found.append((m.start(), (int(round(r)), int(round(g)), int(round(b)), float(a))))
    if not found:
        return None
    return sorted(found)[0][1]


def _hls(rgb):
    return colorsys.rgb_to_hls(*(c / 255 for c in rgb[:3]))


def _from_hls(h, l, s):
    return tuple(int(round(c * 255)) for c in colorsys.hls_to_rgb(h, max(0, min(1, l)), s))


def _hex(rgb) -> str:
    return "#%02X%02X%02X" % tuple(int(c) for c in rgb[:3])


def _lum(rgb) -> float:
    def ch(c):
        c = c / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(c) for c in rgb[:3])
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast(a, b) -> float:
    la, lb = _lum(a), _lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _mix(a, b, t):
    """``t`` of *b* over *a* (t=1 -> b)."""
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))


def _scale_l(rgb, factor):
    h, l, s = _hls(rgb)
    return _from_hls(h, l * factor, s)


def _darken_until(rgb, against, target):
    h, l, s = _hls(rgb)
    out = tuple(rgb[:3])
    while _contrast(out, against) < target and l > 0.01:
        l -= 0.02
        out = _from_hls(h, l, s)
    return out


def _lighten_until(rgb, against, target):
    """Mix toward white until *target* contrast against *against*."""
    for t in [i / 20 for i in range(0, 21)]:
        out = _mix(rgb, (255, 255, 255), t)
        if _contrast(out, against) >= target:
            return out
    return (255, 255, 255)


def _is_brand(rgb_a) -> bool:
    if rgb_a[3] < 0.5:
        return False
    h, l, s = _hls(rgb_a)
    return s >= 0.22 and 0.07 <= l <= 0.93


def _hue_gap(a, b) -> float:
    ha, hb = _hls(a)[0] * 360, _hls(b)[0] * 360
    d = abs(ha - hb) % 360
    return min(d, 360 - d)


# ── CSS scanning ────────────────────────────────────────────────────────────
_RULE_RE = re.compile(r"([^{}]*)\{([^{}]*)\}")
_DECL_RE = re.compile(r"(--[\w-]+|[a-zA-Z-]+)\s*:\s*([^;]+)")
_WEIGHT = {"background": 3.0, "background-color": 3.0, "color": 1.0, "fill": 1.0,
           "border-color": 1.0, "border": 0.6, "border-top": 0.4, "border-bottom": 0.6,
           "border-left": 0.4, "border-right": 0.4, "outline-color": 0.5,
           "stroke": 0.6, "text-decoration-color": 0.5}


def _scan_css(texts: list) -> dict:
    """Weighted colour evidence from stylesheet text."""
    usage: dict = {}
    brand_vars: dict = {}
    second_vars: dict = {}
    chrome: dict = {}
    for text in texts:
        text = re.sub(r"(?s)/\*.*?\*/", "", text)
        for sel, body in _RULE_RE.findall(text):
            is_chrome = bool(_CHROME_SEL.search(sel))
            for prop, value in _DECL_RE.findall(body):
                prop = prop.strip().lower()
                if "var(" in value:
                    continue
                c = _parse(value)
                if c is None:
                    continue
                rgb = c[:3]
                if prop.startswith("--"):
                    if _BRAND_VAR.match(prop) and _is_brand(c):
                        brand_vars[rgb] = brand_vars.get(rgb, 0) + 1
                    elif _SECOND_VAR.match(prop) and _is_brand(c):
                        second_vars[rgb] = second_vars.get(rgb, 0) + 1
                    continue
                w = _WEIGHT.get(prop)
                if w is None:
                    continue
                if is_chrome and prop in ("background", "background-color") and c[3] >= 0.9:
                    chrome[rgb] = chrome.get(rgb, 0) + 1
                if _is_brand(c):
                    usage[rgb] = usage.get(rgb, 0) + w
    return {"usage": usage, "brand_vars": brand_vars,
            "second_vars": second_vars, "chrome": chrome}


def _cluster(weights: dict) -> list:
    """Group near-identical colours; ``[(representative, weight), ...]`` heaviest first."""
    clusters: list = []
    for rgb, w in sorted(weights.items(), key=lambda kv: -kv[1]):
        h, l, s = _hls(rgb)
        for cl in clusters:
            ch, cll, cs = _hls(cl[0])
            if _hue_gap(rgb, cl[0]) < 15 and abs(l - cll) < 0.18 and abs(s - cs) < 0.35:
                cl[1] += w
                break
        else:
            clusters.append([rgb, w])
    clusters.sort(key=lambda c: -c[1])
    return [(tuple(c[0]), c[1]) for c in clusters]


def pick_colours(meta: dict, scan: dict) -> dict:
    """Choose ``primary``/``secondary``/``chrome`` with the evidence for each."""
    out = {"primary": None, "secondary": None, "chrome": None,
           "why_primary": "", "why_secondary": "", "why_chrome": ""}
    tc = _parse(meta.get("theme-color", "") or "")
    candidates = _cluster(scan["usage"])
    if tc and _is_brand(tc):
        out["primary"], out["why_primary"] = tc[:3], 'the page\'s "theme-color"'
    elif scan["brand_vars"]:
        best = _cluster(scan["brand_vars"])[0][0]
        out["primary"], out["why_primary"] = best, "a brand-named CSS variable"
    elif candidates:
        out["primary"], out["why_primary"] = candidates[0][0], "the most used colour in its stylesheets"
    if out["primary"] is not None:
        pool = _cluster(scan["second_vars"]) + candidates
        for rgb, _w in pool:
            if _hue_gap(rgb, out["primary"]) >= 35:
                out["secondary"] = rgb
                out["why_secondary"] = ("a secondary-named CSS variable"
                                        if rgb in scan["second_vars"]
                                        else "the next most used colour")
                break
    dark = {rgb: n for rgb, n in scan["chrome"].items()
            if _contrast(rgb, (255, 255, 255)) >= 4.5}
    if dark:
        best = max(dark.items(), key=lambda kv: kv[1])[0]
        out["chrome"], out["why_chrome"] = best, "the background of its header/navigation"
    return out


def palette(primary, secondary=None, chrome=None) -> dict:
    """SATOM tokens for a brand colour (+ optional secondary and dark chrome).

    Every text/background pair the contrast auditor checks is pushed to AA here,
    so the result never needs the "apply anyway" confirmation.
    """
    white = (255, 255, 255)
    primary = tuple(primary[:3])
    accent = _darken_until(primary, white, 4.6)
    side = tuple(chrome[:3]) if chrome else accent
    top = _scale_l(side, 0.55) if _hls(side)[1] > 0.08 else side
    if _contrast(top, white) < 4.6:
        top = _darken_until(top, white, 4.6)
    side_text = _lighten_until(_mix(side, white, 0.75), side, 4.6)
    section = _lighten_until(_mix(side, white, 0.6), side, 4.6)
    bright = _from_hls(_hls(primary)[0], max(_hls(primary)[1], 0.55), _hls(primary)[2])
    second = tuple(secondary[:3]) if secondary else _mix(bright, white, 0.35)
    active = second if _contrast(second, side) >= 2.0 else _lighten_until(second, side, 3.0)
    r, g, b = accent
    return {
        "accent": _hex(accent),
        "accent-hover": _hex(_scale_l(accent, 0.75)),
        "accent-light": "rgba(%d, %d, %d, 0.10)" % (r, g, b),
        "sidebar-bg": _hex(side),
        "sidebar-text": _hex(side_text),
        "sidebar-text-hover": "#FFFFFF",
        "sidebar-section": _hex(section),
        "sidebar-active": _hex(active),
        "topbar-bg": _hex(top),
        "topbar-text": "#FFFFFF",
        "glow": _hex(bright),
        "glow-accent": _hex(second),
        "gradient-brand": "linear-gradient(135deg, %s 0%%, %s 35%%, %s 75%%, %s 100%%)" % (
            _hex(top), _hex(side), _hex(bright), _hex(_mix(bright, white, 0.3))),
        "gradient-accent": "linear-gradient(135deg, %s 0%%, %s 45%%, %s 100%%)" % (
            _hex(_scale_l(second, 0.8)), _hex(second), _hex(_mix(second, white, 0.35))),
    }


# ── icons and logo ──────────────────────────────────────────────────────────
def _size_of(icon: dict) -> int:
    best = 0
    for part in icon.get("sizes", "").split():
        m = re.match(r"(\d+)x(\d+)", part)
        if m:
            best = max(best, int(m.group(1)))
        elif part == "any":
            best = max(best, 512)
    if icon.get("type") == "image/svg+xml" or icon["href"].lower().split("?")[0].endswith(".svg"):
        best = max(best, 512)
    return best


def _logo_candidates(scan: _PageScan, base: str) -> list:
    """``[(url, label)]`` in preference order for the 28 px square mark."""
    out = []
    apple = [i for i in scan.icons if i["rels"] & {"apple-touch-icon", "apple-touch-icon-precomposed"}]
    for i in sorted(apple, key=_size_of, reverse=True):
        out.append((urljoin(base, i["href"]), "its apple-touch-icon"))
    plain = [i for i in scan.icons if "icon" in i["rels"] and _size_of(i) >= 64]
    for i in sorted(plain, key=_size_of, reverse=True):
        out.append((urljoin(base, i["href"]), "its largest icon"))
    for img in sorted(scan.imgs, key=lambda m: (not m["logo"], not m["header"])):
        if img["logo"]:
            out.append((urljoin(base, img["src"]), "the logo image in its header"))
    return out


def _favicon_candidates(scan: _PageScan, base: str) -> list:
    icons = [i for i in scan.icons if "icon" in i["rels"]]

    def rank(i):
        n = _size_of(i)
        return (0 if 32 <= n <= 256 else 1, abs(n - 64))
    out = [(urljoin(base, i["href"]), "its icon link") for i in sorted(icons, key=rank)]
    parts = urlsplit(base)
    out.append(("%s://%s/favicon.ico" % (parts.scheme, parts.netloc), "/favicon.ico"))
    return out


def _load_image(url: str) -> "tuple[bytes, str] | None":
    """``(raw, ext)`` for an image URL (``data:`` included), or ``None``."""
    if url.startswith("data:"):
        head, _, body = url.partition(",")
        try:
            raw = base64.b64decode(body) if ";base64" in head else unquote_to_bytes(body)
        except Exception:  # noqa: BLE001
            return None
        ctype = head[5:].split(";")[0]
    else:
        got = tp.fetch(url, max_bytes=MAX_IMAGE_BYTES, accept="image/*,*/*;q=0.5")
        raw, ctype = got.body, got.content_type
    ext = tp.sniff_ext(raw, url if not url.startswith("data:") else "", ctype)
    return (raw, ext) if ext else None


def _square_enough(raw: bytes, ext: str) -> bool:
    """A wordmark squeezed into the 28 px square is unreadable: refuse wide images."""
    if ext == ".svg":
        m = re.search(rb'viewBox\s*=\s*["\']\s*[-\d.]+[\s,]+[-\d.]+[\s,]+([\d.]+)[\s,]+([\d.]+)', raw)
        if not m:
            return True
        w, h = float(m.group(1)), float(m.group(2))
    else:
        try:
            import io

            from PIL import Image
            w, h = Image.open(io.BytesIO(raw)).size
        except Exception:  # noqa: BLE001
            return False
    return h > 0 and w / h <= 1.6


# ── entry point ─────────────────────────────────────────────────────────────
def build(url: str) -> "tuple[tp.Parsed, list]":
    """Fetch *url* and build a theme. Returns ``(parsed, report)``.

    Raises :class:`theme_portable.FetchError` only when the PAGE cannot be read;
    a stylesheet or icon that fails is reported and skipped.
    """
    url = (url or "").strip()
    if url and "://" not in url:
        url = "https://" + url
    if url and not urlsplit(url).path:
        url += "/"
    page = tp.fetch(url, max_bytes=MAX_HTML_BYTES,
                    accept="text/html,application/xhtml+xml;q=0.9,*/*;q=0.5")
    ctype = page.content_type.split(";")[0].strip().lower()
    if ctype and "html" not in ctype:
        raise tp.FetchError("%s is not a web page (%s)." % (page.url[:120], ctype))
    scan = _PageScan()
    try:
        scan.feed(page.body.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 — HTMLParser rarely raises; keep what it read
        pass
    base = urljoin(page.url, scan.base) if scan.base else page.url
    host = urlsplit(page.url).hostname or ""
    report: list = []

    css_texts = list(scan.css)
    sheets = scan.stylesheets[:MAX_STYLESHEETS]
    for href in sheets:
        try:
            css_texts.append(tp.fetch(urljoin(base, href), max_bytes=MAX_CSS_BYTES,
                                      accept="text/css,*/*;q=0.5").body.decode("utf-8", "replace"))
        except tp.FetchError as exc:
            report.append("Skipped a stylesheet: %s" % exc)
    if len(scan.stylesheets) > MAX_STYLESHEETS:
        report.append("Read the first %d of %d stylesheets." % (MAX_STYLESHEETS, len(scan.stylesheets)))

    picked = pick_colours(scan.meta, _scan_css(css_texts))
    tokens: dict = {}
    if picked["primary"] is None:
        report.append("No brand colour found (the site looks monochrome or styles "
                      "itself from script): colours stay on the SATOM defaults.")
    else:
        raw = palette(picked["primary"], picked["secondary"], picked["chrome"])
        tokens, errors = theme_service.validate_tokens(raw)
        if errors:  # pragma: no cover — palette() only emits validator shapes
            report.extend("Dropped: %s" % e for e in errors)
        report.append("Brand colour %s, from %s." % (_hex(picked["primary"]), picked["why_primary"]))
        if picked["secondary"] is not None:
            report.append("Second colour %s, from %s." % (_hex(picked["secondary"]),
                                                        picked["why_secondary"]))
        if picked["chrome"] is not None and picked["chrome"] != picked["primary"]:
            report.append("Sidebar colour %s, from %s." % (_hex(picked["chrome"]), picked["why_chrome"]))
        if raw["accent"] != _hex(picked["primary"]):
            report.append("Accent darkened to %s so buttons and links stay readable "
                          "on white (4.5:1)." % raw["accent"])

    assets: dict = {}
    for kind, candidates in (("logo", _logo_candidates(scan, base)),
                             ("favicon", _favicon_candidates(scan, base))):
        seen = set()
        for cand_url, label in candidates:
            if cand_url in seen:
                continue
            seen.add(cand_url)
            try:
                got = _load_image(cand_url)
            except tp.FetchError as exc:
                report.append("Skipped a %s candidate: %s" % (kind, exc))
                continue
            if got is None:
                continue
            if kind == "logo" and not _square_enough(*got):
                report.append("Skipped %s as the logo: too wide for the square top-bar mark."
                              % cand_url[:120])
                continue
            assets[kind] = got
            shown = cand_url if not cand_url.startswith("data:") else "an inline image"
            report.append("%s: %s (%s)." % (kind.capitalize(), shown[:160], label))
            break
        else:
            report.append("No usable %s found: the theme keeps the SATOM %s."
                          % (kind, "mark" if kind == "logo" else "favicon"))

    site = " ".join((scan.meta.get("og:site_name") or scan.title or host).split())[:60] or host
    name = "%s (from %s)" % (site, host) if site != host else "From %s" % host
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    desc = "Imported from %s on %s." % (page.url[:200], when)
    return tp.Parsed(name[:100], desc[:300], tokens, assets, []), report
