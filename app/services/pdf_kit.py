"""Shared reportlab primitives: one chart renderer, one table renderer.

WHY THIS MODULE EXISTS
----------------------
``services/db_reports`` grew a perfectly good pair of PDF flowables (a
bar/line/pie chart and a paginated table) while it was the only thing in SATOM
that produced a PDF. The WAF fleet export needs exactly those two, and the
tempting move — copy them over and leave a comment saying the two copies are
identical — is the antipattern §127 had to undo for ``verdict_of``. A promise
is not a mechanism. So they live here, and both callers import them.

Rendering is pure reportlab: no browser, no headless Chromium, no external
binary. That matters because SATOM installs into isolated management networks
and an export that needs a browser is an export that does not run on the node.

WHAT IS *NOT* SHARED, ON PURPOSE
--------------------------------
The palette. ``db_reports`` renders a user-authored report in the fleet blue;
the WAF export renders a FortiWeb page whose on-screen colours come from the
``.fw-badge-*`` set calibrated against white (safeguards §9m). Passing the
colours in keeps one renderer without forcing one look — a shared *constant*
here would have quietly repainted the DB reports the day WAF picked its own.
"""
from __future__ import annotations

from typing import Any, Sequence

# The DB-reports look. Kept here because that module's PDFs used these exact
# values before the extraction and must keep using them.
ACCENT = "#3b82f6"
ACCENT2 = "#8b5cf6"
PALETTE: list[str] = ["#3b82f6", "#8b5cf6", "#10b981", "#fbbf24", "#ef4444",
                      "#06b6d4", "#f472b6", "#84cc16"]

#: Past this many points a bar chart's category labels overlap into mush.
DEFAULT_MAX_POINTS = 24
#: Past this many rows a PDF table stops being something a human reads.
DEFAULT_MAX_ROWS = 40


def esc(s: Any) -> str:
    """Escape for reportlab's mini-HTML. NOT optional.

    Device banners, signature descriptions and FortiWeb comments routinely
    contain ``&`` and ``<``; an unescaped one raises inside ``doc.build`` and
    takes down the whole export, not just the cell.
    """
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def table_flowable(widget: dict, avail_w: float, cell_style, *,
                   max_rows: int = DEFAULT_MAX_ROWS,
                   accent: str = ACCENT,
                   header_bg: str = "#eef2ff"):
    """A table from ``{columns: [...], rows: [[...], ...]}``.

    Columns beyond the tenth are dropped rather than squeezed: eleven columns
    across A4 gives each one ~16mm, which renders as a column of single
    characters. The caller is expected to say so in a footnote — this function
    returns the flowable, not the caveat.
    """
    from reportlab.lib import colors
    from reportlab.platypus import Paragraph, Table, TableStyle

    cols = list(widget["columns"])
    rows = list(widget["rows"][:max_rows])
    max_cols = 10
    if len(cols) > max_cols:
        cols = cols[:max_cols]
        rows = [r[:max_cols] for r in rows]

    data = [[Paragraph("<b>%s</b>" % esc(c), cell_style) for c in cols]]
    for r in rows:
        data.append([Paragraph(esc(v)[:300], cell_style) for v in r])

    t = Table(data, colWidths=[avail_w / len(cols)] * len(cols), repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_bg)),
        ("LINEBELOW", (0, 0), (-1, 0), 0.75, colors.HexColor(accent)),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


def chart_flowable(widget: dict, viz: str, avail_w: float, *,
                   max_points: int = DEFAULT_MAX_POINTS,
                   palette: Sequence[str] = PALETTE,
                   accent: str = ACCENT,
                   accent2: str = ACCENT2,
                   colours: Sequence[str] | None = None,
                   height: float = 200):
    """A bar / line / pie ``Drawing`` from ``{labels: [...], values: [...]}``.

    ``colours`` overrides the per-bar / per-slice colour ONE FOR ONE with
    ``values`` — that is how the export paints "blocking" green and "disabled"
    grey using the same mapping the on-screen chart uses, instead of whatever
    position the series happens to be in.

    An empty series draws the words "no numeric data" ON the canvas. A blank
    chart and a chart of zeros look identical in a PDF and mean opposite
    things; the same rule the on-screen renderer follows (waf.js, rule 2).
    """
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.linecharts import HorizontalLineChart
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.shapes import Drawing, String
    from reportlab.lib import colors

    labels = list(widget.get("labels", []))[:max_points]
    values = [_num(v) for v in list(widget.get("values", []))[:max_points]]
    picked = list(colours or ())[:max_points]

    d = Drawing(avail_w, height)

    if viz == "pie":
        # A pie of nothing is a filled circle claiming 100% of something.
        if not values or sum(values) <= 0:
            d.add(String(avail_w / 2, height / 2, "no numeric data",
                         fontSize=9, fillColor=colors.HexColor("#94a3b8"),
                         textAnchor="middle"))
            return d
        pie = Pie()
        pie.x, pie.y = 40, 20
        pie.width = pie.height = height - 50
        pie.data = values
        pie.labels = [str(l)[:22] for l in labels] or [""]
        pie.sideLabels = True
        pie.slices.strokeWidth = 0.5
        pie.slices.strokeColor = colors.white
        pie.slices.fontSize = 7
        for i in range(len(pie.data)):
            hexc = picked[i] if i < len(picked) else palette[i % len(palette)]
            pie.slices[i].fillColor = colors.HexColor(hexc)
        d.add(pie)
        return d

    chart_cls = VerticalBarChart if viz == "bar" else HorizontalLineChart
    ch = chart_cls()
    ch.x, ch.y = 35, 30
    ch.width, ch.height = avail_w - 60, height - 55
    ch.data = [values or [0]]
    ch.categoryAxis.categoryNames = [str(l)[:14] for l in labels] or [""]
    ch.categoryAxis.labels.fontSize = 6.5
    ch.categoryAxis.labels.angle = 30
    ch.categoryAxis.labels.boxAnchor = "ne"
    ch.valueAxis.labels.fontSize = 7
    ch.valueAxis.valueMin = min(0, min(values or [0]))
    if viz == "bar":
        ch.bars[0].fillColor = colors.HexColor(picked[0] if picked else accent)
        ch.bars[0].strokeColor = None
        # Per-bar colours: reportlab indexes bars as (series, category).
        for i in range(len(values)):
            if i < len(picked):
                ch.bars[(0, i)].fillColor = colors.HexColor(picked[i])
    else:
        ch.lines[0].strokeColor = colors.HexColor(picked[0] if picked
                                                  else accent2)
        ch.lines[0].strokeWidth = 1.6
    d.add(ch)
    if not values:
        d.add(String(avail_w / 2, height / 2, "no numeric data",
                     fontSize=9, fillColor=colors.HexColor("#94a3b8"),
                     textAnchor="middle"))
    return d


def _num(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


__all__ = ["ACCENT", "ACCENT2", "PALETTE", "DEFAULT_MAX_POINTS",
           "DEFAULT_MAX_ROWS", "esc", "table_flowable", "chart_flowable"]
