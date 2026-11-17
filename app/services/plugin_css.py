"""Plugin CSS rules — the linter for a plugin's ``style.css``.

This docstring is the AUTHORITATIVE text of the rules; the user guide
(Report Studio, "Plugin CSS rules") and ``docs/theming.md`` quote it.

A view or widget renders in a sandboxed iframe whose Content-Security-Policy is
``default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:``.
The frame carries SATOM's light look on its own: the current theme's ``--fw-*``
tokens (Settings > Appearance, so a customer theme reaches every plugin) and a
small class kit — ``.fw-card`` (``-header``, ``-title``, ``-body``,
``-footer``), ``.fw-badge-{primary,secondary,success,danger,warning,info}``,
``.fw-table``, ``.btn-fw-{primary,secondary,outline,danger}``,
``.fw-alert-{success,danger,warning,info}`` and base typography.
A plugin's own CSS is added after the kit, so it can refine it.

Write plugin CSS like this:

- use the tokens (``var(--fw-text-primary)``, ``var(--fw-surface)``,
  ``var(--fw-border)``, ``var(--fw-accent)`` ...) instead of fixed colours, so
  the view follows the customer's theme;
- take status colours from the ``.fw-badge-*`` set (success ``#15692A``,
  warning ``#7A5700``, danger ``#8B1C2A``, neutral ``#3D4550``; ``#4C2A85``
  for a fifth category) — they are calibrated against white;
- images and fonts are ``data:`` URIs only; nothing is fetched from anywhere.

ERRORS — the package is refused (Builder policy) and the CSS does not work
under the frame's CSP anyway:

- ``@import``;
- ``url(...)`` (or a string in ``image-set(...)``) whose target is not a
  ``data:`` URI;
- ``expression(``;
- ``javascript:``;
- the ``behavior`` and ``-moz-binding`` properties;
- ``position: fixed`` (an overlay pinned over the frame);
- ``@font-face`` whose ``src`` is anything but ``url(data:...)``
  (``local(...)`` included);
- a stylesheet larger than 256 KiB.

WARNINGS — shown to the author, never a refusal:

- more than 20 ``!important``;
- ``color:`` set to a hex colour whose contrast against white is below
  4.5:1 (WCAG AA for body text; translucent colours are composited over
  white first). A rule that also sets its own opaque ``background`` is not
  checked — white text on your own fill is read on the fill, not on white;
- ``z-index`` above 1000;
- ``</style`` in the CSS (the frame neutralises it, but it means HTML was
  pasted into the stylesheet).

Comments and the contents of quoted strings never trigger a rule (``content:
"@import"`` is fine), and CSS escapes are decoded first, so ``@\\69mport`` or
``u\\72l(...)`` are still caught.

Public API (kept stable; the module is pure stdlib so it can be copied verbatim
into the rules pack and run without SATOM)::

    lint(css: str) -> list[dict]
    # [{"level": "error" | "warning", "message": str, "line": int}, ...]
    # sorted by line, errors before warnings on the same line; [] = clean.
    # Never raises; non-string input is treated as "".
"""
from __future__ import annotations

import bisect
import re

__all__ = ["lint", "MAX_BYTES", "MAX_IMPORTANT", "MAX_Z_INDEX", "MIN_CONTRAST",
           "contrast_on_white"]

#: Largest accepted stylesheet, in bytes (UTF-8).
MAX_BYTES = 256 * 1024
#: More ``!important`` than this is a warning.
MAX_IMPORTANT = 20
#: A ``z-index`` above this is a warning.
MAX_Z_INDEX = 1000
#: ``color:`` below this contrast against white is a warning (WCAG AA).
MIN_CONTRAST = 4.5

_IDENT_CHARS = re.compile(r"[A-Za-z0-9_\-]")
_HEX_ESC = re.compile(r"[0-9A-Fa-f]{1,6}")


# ── tokenising ──────────────────────────────────────────────────────────────
def _decode_escape(css: str, i: int) -> "tuple[str, int]":
    """Decode the CSS escape whose backslash is at ``css[i]``.

    Returns ``(char, next_index)``. A backslash before a newline (or at EOF) is
    not an escape outside strings; the caller handles that case.
    """
    m = _HEX_ESC.match(css, i + 1)
    if m:
        j = m.end()
        if j < len(css) and css[j] in " \t\n\r\f":
            j += 2 if css[j:j + 2] == "\r\n" else 1
        cp = int(m.group(0), 16)
        if cp == 0 or cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
            return "�", j
        return chr(cp), j
    return css[i + 1], i + 2


def _mask(css: str) -> "tuple[str, list[str]]":
    """Return ``(masked, strings)``.

    ``masked`` is the stylesheet with comments blanked, every quoted string and
    every unquoted ``url(...)`` body replaced by a placeholder ``"S<n>"``, and
    escapes outside strings decoded (a decoded character that is not an
    identifier character becomes ``_`` so an escaped ``{`` cannot invent
    structure). Every newline survives, so line numbers in ``masked`` are line
    numbers in ``css``. ``strings[n]`` holds the decoded contents.
    """
    out: "list[str]" = []
    strings: "list[str]" = []
    n = len(css)
    i = 0
    while i < n:
        c = css[i]
        # comment
        if c == "/" and css.startswith("*", i + 1):
            end = css.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out.append(" " + "\n" * css.count("\n", i, end))
            i = end
            continue
        # quoted string
        if c in "\"'":
            buf: "list[str]" = []
            nl = 0
            j = i + 1
            while j < n:
                d = css[j]
                if d == c:
                    j += 1
                    break
                if d == "\n":  # unescaped newline ends a (bad) string
                    break
                if d == "\\":
                    if j + 1 >= n:
                        j += 1
                        break
                    if css[j + 1] == "\n":
                        nl += 1
                        j += 2
                        continue
                    ch, j = _decode_escape(css, j)
                    buf.append(ch)
                    continue
                buf.append(d)
                j += 1
            strings.append("".join(buf))
            out.append('"S%d"' % (len(strings) - 1) + "\n" * nl)
            i = j
            continue
        # escape outside a string
        if c == "\\":
            if i + 1 >= n or css[i + 1] == "\n":
                out.append("_")
                i += 1
                continue
            ch, i = _decode_escape(css, i)
            out.append(ch if _IDENT_CHARS.match(ch) or ord(ch) > 127 else "_")
            continue
        # function opener: an unquoted url( body is one token, comments and all
        if c == "(":
            tail = "".join(out[-12:])[-12:]
            m = re.search(r"(?:^|[^A-Za-z0-9_\-])url$", tail, re.I)
            if m:
                k = i + 1
                while k < n and css[k] in " \t\n\r\f":
                    k += 1
                if k >= n or css[k] not in "\"'":
                    buf = []
                    nl = css.count("\n", i + 1, k)
                    j = k
                    while j < n and css[j] != ")":
                        if css[j] == "\\" and j + 1 < n and css[j + 1] != "\n":
                            ch, j = _decode_escape(css, j)
                            buf.append(ch)
                            continue
                        if css[j] == "\n":
                            nl += 1
                        buf.append(css[j])
                        j += 1
                    strings.append("".join(buf).strip())
                    out.append('("S%d"' % (len(strings) - 1) + "\n" * nl)
                    if j < n:
                        out.append(")")
                    i = j + 1
                    continue
        out.append(c)
        i += 1
    return "".join(out), strings


# ── colour maths (WCAG 2.1; same formula as studio_design.contrast) ─────────
def _hex_rgba(value: str) -> "tuple[float, float, float, float] | None":
    h = value.strip().lstrip("#")
    if len(h) in (3, 4):
        h = "".join(ch * 2 for ch in h)
    if len(h) not in (6, 8) or not re.fullmatch(r"[0-9A-Fa-f]+", h):
        return None
    r, g, b = (int(h[k:k + 2], 16) for k in (0, 2, 4))
    a = int(h[6:8], 16) / 255 if len(h) == 8 else 1.0
    return float(r), float(g), float(b), a


def _luminance(r: float, g: float, b: float) -> float:
    def ch(c: float) -> float:
        c = c / 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def contrast_on_white(hex_colour: str) -> "float | None":
    """Contrast ratio of ``hex_colour`` on ``#FFFFFF``, alpha composited."""
    rgba = _hex_rgba(hex_colour)
    if rgba is None:
        return None
    r, g, b, a = rgba
    if a < 1.0:
        r, g, b = (c * a + 255.0 * (1 - a) for c in (r, g, b))
    lum = _luminance(r, g, b)
    return (1.0 + 0.05) / (lum + 0.05)


# ── rules ───────────────────────────────────────────────────────────────────
_DECL = re.compile(
    r"(?:^|(?<=[{;]))\s*(-?[A-Za-z_][-A-Za-z0-9_]*)\s*:\s*([^;{}]*)(?=[;}]|\Z)")
_IMPORTANT = re.compile(r"!\s*important\b", re.I)
_URL = re.compile(r"(?<![A-Za-z0-9_\-])url\(\s*(?:\"S(\d+)\")?", re.I)
_IMAGE_SET = re.compile(r"(?<![A-Za-z0-9_\-])(?:-webkit-)?image-set\(([^;{}]*)", re.I)
_PLACEHOLDER = re.compile(r"\"S(\d+)\"")
_FONT_FACE = re.compile(r"@font-face\b[^{]*\{([^}]*)\}?", re.I)
_SRC_ITEM_OK = re.compile(
    r"^url\(\s*\"S\d+\"\s*\)(?:\s+(?:format|tech)\([^)]*\))*$", re.I)
_HEX_VALUE = re.compile(r"^#([0-9A-Fa-f]{3,8})$")


def _split_commas(value: str) -> "list[str]":
    items, depth, cur = [], 0, []
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            items.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    items.append("".join(cur).strip())
    return [x for x in items if x]


_BG_DECL = re.compile(
    r"(?:^|(?<=[{;]))\s*background(?:-color|-image)?\s*:\s*([^;{}]*)", re.I)
_TRANSLUCENT_FN = re.compile(
    r"^(?:rgba?|hsla?)\(\s*[^)]*?(?:,|/)\s*(0?\.\d+|0|\d{1,2}%)\s*\)", re.I)


def _opaque(value: str) -> bool:
    """Best-effort: does this background value paint an opaque fill?"""
    v = _IMPORTANT.sub("", value).strip().lower()
    if not v or v.split()[0] in ("transparent", "none", "inherit", "initial",
                                 "unset", "currentcolor", "revert"):
        return False
    if v.startswith("#"):
        rgba = _hex_rgba(v.split()[0])
        return bool(rgba) and rgba[3] >= 1.0
    if _TRANSLUCENT_FN.match(v):
        return False
    return True  # var(--fw-*), gradients, rgb(), named colours


def _own_opaque_background(masked: str, pos: int) -> bool:
    """True when the rule holding the declaration at ``pos`` sets an opaque
    background -- its text is then read on that fill, not on white."""
    start = masked.rfind("{", 0, pos)
    end = masked.find("}", pos)
    block = masked[start + 1:end if end >= 0 else len(masked)]
    return any(_opaque(m.group(1)) for m in _BG_DECL.finditer(block))


def lint(css: str) -> "list[dict]":
    """Check a plugin stylesheet against the Plugin CSS rules (module doc)."""
    if not isinstance(css, str):
        css = ""
    found: "list[dict]" = []

    def add(level: str, message: str, line: int) -> None:
        found.append({"level": level, "message": message, "line": int(line)})

    size = len(css.encode("utf-8", "replace"))
    if size > MAX_BYTES:
        add("error", "the stylesheet is %d bytes; the limit is %d (256 KiB)"
            % (size, MAX_BYTES), 1)

    masked, strings = _mask(css)

    newlines = [k for k, ch in enumerate(masked) if ch == "\n"]

    def line_at(pos: int) -> int:
        return bisect.bisect_left(newlines, pos) + 1

    def string(idx: "str | None") -> str:
        try:
            return strings[int(idx)] if idx is not None else ""
        except (ValueError, IndexError):
            return ""

    for m in re.finditer(r"@import\b", masked, re.I):
        add("error", "@import is not allowed: inline the rules instead "
            "(the frame cannot load other stylesheets)", line_at(m.start()))

    def check_target(target: str, pos: int, what: str) -> None:
        t = target.strip().lower()
        if t.startswith("data:"):
            return
        if t.startswith("javascript:"):
            add("error", "javascript: is not allowed in CSS", line_at(pos))
            return
        shown = target.strip()[:80] or "(empty)"
        add("error", "%s %s is not a data: URI; images and fonts must be "
            "inlined as data: (the frame fetches nothing)" % (what, shown),
            line_at(pos))

    for m in _URL.finditer(masked):
        check_target(string(m.group(1)), m.start(), "url()")
    for m in _IMAGE_SET.finditer(masked):
        for p in _PLACEHOLDER.finditer(m.group(1)):
            # url("S<n>") inside image-set is already checked by _URL
            before = m.group(1)[:p.start()].rstrip()
            if before.lower().endswith("url("):
                continue
            check_target(string(p.group(1)), m.start(), "image-set()")

    for m in re.finditer(r"(?<![A-Za-z0-9_\-])expression\s*\(", masked, re.I):
        add("error", "expression() is not allowed", line_at(m.start()))
    for m in re.finditer(r"(?<![A-Za-z0-9_\-.#])javascript\s*:", masked, re.I):
        add("error", "javascript: is not allowed in CSS", line_at(m.start()))
    for m in re.finditer(r"-moz-binding\b", masked, re.I):
        add("error", "-moz-binding is not allowed", line_at(m.start()))

    for m in _FONT_FACE.finditer(masked):
        body, base = m.group(1), m.start(1)
        for d in _DECL.finditer(body):
            if d.group(1).lower() != "src":
                continue
            for item in _split_commas(d.group(2)):
                if not _SRC_ITEM_OK.match(item):
                    shown = _PLACEHOLDER.sub(
                        lambda p: '"%s"' % string(p.group(1)), item)
                    add("error", "@font-face src %s is not allowed: a font must "
                        "be url(data:...)" % shown[:80], line_at(base + d.start(1)))

    important = 0
    for m in _DECL.finditer(masked):
        prop = m.group(1).lower()
        raw = m.group(2)
        line = line_at(m.start(1))
        value = _IMPORTANT.sub("", raw).strip()
        low = value.lower()
        for _ in _IMPORTANT.finditer(raw):
            important += 1
            if important == MAX_IMPORTANT + 1:
                add("warning", "more than %d !important declarations; the kit "
                    "is meant to be refined, not overpowered" % MAX_IMPORTANT,
                    line)
        if prop == "behavior":
            add("error", "the behavior property is not allowed", line)
        elif prop == "position" and re.match(r"fixed\b", low):
            add("error", "position: fixed is not allowed: it pins an overlay "
                "over the frame; use absolute or sticky", line)
        elif prop == "z-index":
            try:
                z = int(low)
            except ValueError:
                z = None
            if z is not None and z > MAX_Z_INDEX:
                add("warning", "z-index %d is above %d" % (z, MAX_Z_INDEX), line)
        elif prop == "color":
            hm = _HEX_VALUE.match(value)
            if hm and not _own_opaque_background(masked, m.start(1)):
                ratio = contrast_on_white(value)
                if ratio is not None and ratio < MIN_CONTRAST:
                    add("warning", "color %s has %.2f:1 contrast on white "
                        "(needs %.1f:1); use var(--fw-text-primary), "
                        "var(--fw-text-secondary) or a .fw-badge-* colour"
                        % (value, ratio, MIN_CONTRAST), line)

    for m in re.finditer(r"</style", css, re.I):
        add("warning", "</style found: HTML does not belong in the stylesheet",
            css.count("\n", 0, m.start()) + 1)

    found.sort(key=lambda f: (f["line"], f["level"] != "error"))
    return found
