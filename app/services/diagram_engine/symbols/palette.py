"""Family colour palette shared by the ``color`` and ``iso3d`` symbol libraries.

Build-time data (the generators import it); documented in ``color/PALETTE.md``.
Every family has five steps: ``tint`` (body fill of flat colour icons),
``light``, ``base``, ``dark`` and ``ink`` (glyph/outline). Accents are shared.

Standalone: stdlib only.
"""
from __future__ import annotations

FAMILIES = {
    # family:   tint       light      base       dark       ink
    "network":  ("#DCEBFF", "#8DB8FA", "#3B7DED", "#1F56C7", "#173A80"),
    "security": ("#FFE5E0", "#F9A894", "#E8513A", "#B5301F", "#7A1D12"),
    "infra":    ("#E3E9F0", "#9EAEC2", "#62748C", "#3B4A5E", "#1F2937"),
    "devices":  ("#D5F5EF", "#6FD6C6", "#18A391", "#0E7365", "#0B4A42"),
    "data":     ("#EEE8FF", "#BFADF8", "#8A63E8", "#6236C4", "#40207F"),
    "software": ("#DDF6E4", "#83DCA0", "#2EAD5B", "#1C7E40", "#134F29"),
    "people":   ("#FFF1D0", "#F8CD6A", "#E79B12", "#AD6608", "#6E3F07"),
    "generic":  ("#E9EDF3", "#B4BFCD", "#7D8BA0", "#4B596D", "#253041"),
}
STEPS = ("tint", "light", "base", "dark", "ink")

ACCENTS = {
    "ok": "#22C55E",       # status LED
    "warn": "#F59E0B",
    "alert": "#EF4444",
    "info": "#38BDF8",
    "glass": "#1E293B",    # screens
    "glass_hi": "#475569",
    "port": "#0F172A",
    "white": "#FFFFFF",
    "shadow": "#0F172A",
}

#: Which palette family a symbol family uses (flow/uml/bpmn/c4 share ``generic``).
FAMILY_OF = {"network": "network", "security": "security", "infra": "infra", "devices": "devices",
             "data": "data", "software": "software", "people": "people",
             "flow": "generic", "uml": "generic", "bpmn": "generic", "c4": "generic", "generic": "generic"}


def colour(family: str, step: str) -> str:
    return FAMILIES[FAMILY_OF.get(family, family)][STEPS.index(step)]


def _rgb(h: str):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def to_hex(rgb) -> str:
    return "#%02X%02X%02X" % tuple(max(0, min(255, int(round(c)))) for c in rgb)


def mix(a: str, b: str, t: float) -> str:
    """``a`` moved a fraction ``t`` toward ``b``."""
    ra, rb = _rgb(a), _rgb(b)
    return to_hex(tuple(x + (y - x) * t for x, y in zip(ra, rb)))


def luminance(h: str) -> float:
    def ch(c):
        c /= 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(c) for c in _rgb(h))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    """WCAG contrast ratio of two #RRGGBB colours."""
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)
