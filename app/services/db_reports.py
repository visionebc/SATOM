"""User-authored DB reports & dashboards over the read-only SQL layer.

A report is a list of WIDGETS, each = one SELECT + a visualization
(table / bar / line / pie / stat). Every query executes through
``dbintrospect.run_query`` — the same SELECT-only, sensitive-column-masking,
rolled-back-transaction guard the SQL console uses — so a report can never
mutate the DB or reveal more than the console can.

PDF rendering is pure reportlab (no browser, no external binaries), so it
works headless inside the LXC.
"""
from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from typing import Any

from . import dbintrospect

VIZ_KINDS = ("table", "bar", "line", "pie", "stat")
WIDGET_WIDTHS = ("half", "full")
MAX_WIDGETS = 20
MAX_ROWS_PER_WIDGET = 500
PDF_MAX_TABLE_ROWS = 40
PDF_MAX_CHART_POINTS = 24


# --------------------------------------------------------------------------
# Definition validation
# --------------------------------------------------------------------------

def validate_definition(definition: Any) -> tuple[dict, list[str]]:
    """Validate a report definition. Returns (clean_definition, errors).

    ``definition`` may be a dict or a JSON string. On errors the first
    element is still the best-effort cleaned dict.
    """
    errors: list[str] = []
    if isinstance(definition, str):
        try:
            definition = json.loads(definition or "{}")
        except Exception:
            return {"widgets": []}, ["definition is not valid JSON"]
    if not isinstance(definition, dict):
        return {"widgets": []}, ["definition must be an object"]

    widgets_in = definition.get("widgets")
    if not isinstance(widgets_in, list) or not widgets_in:
        return {"widgets": []}, ["a report needs at least one widget"]
    if len(widgets_in) > MAX_WIDGETS:
        errors.append(f"too many widgets (max {MAX_WIDGETS})")
        widgets_in = widgets_in[:MAX_WIDGETS]

    clean: list[dict] = []
    for i, w in enumerate(widgets_in, start=1):
        if not isinstance(w, dict):
            errors.append(f"widget {i}: must be an object")
            continue
        title = str(w.get("title") or f"Widget {i}").strip()[:120]
        sql = str(w.get("sql") or "").strip()
        ok, why = dbintrospect.is_read_only(sql)
        if not ok:
            errors.append(f"widget {i} ({title}): {why}")
        viz = str(w.get("viz") or "table").lower()
        if viz not in VIZ_KINDS:
            errors.append(f"widget {i} ({title}): unknown viz '{viz}'")
            viz = "table"
        try:
            limit = int(w.get("limit") or 100)
        except Exception:
            limit = 100
        limit = max(1, min(limit, MAX_ROWS_PER_WIDGET))
        width = str(w.get("width") or "half").lower()
        if width not in WIDGET_WIDTHS:
            width = "half"
        clean.append({
            "title": title, "sql": sql, "viz": viz, "limit": limit,
            "width": width,
            "x": str(w.get("x") or "").strip()[:64],
            "y": str(w.get("y") or "").strip()[:64],
        })
    return {"widgets": clean}, errors


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------

def _pick_axes(columns: list[str], rows: list[list], x: str, y: str):
    """Resolve label/value column indexes for chart widgets.

    x = named column else the first column; y = named column else the first
    column whose values parse as numbers (excluding the x column).
    """
    xi = columns.index(x) if x in columns else 0

    def _numeric(idx: int) -> bool:
        seen = False
        for r in rows[:20]:
            v = r[idx]
            if v in ("", None):
                continue
            seen = True
            try:
                float(str(v).replace(",", ""))
            except Exception:
                return False
        return seen

    if y in columns:
        yi = columns.index(y)
    else:
        yi = next((i for i in range(len(columns))
                   if i != xi and _numeric(i)), None)
        if yi is None:
            yi = 1 if len(columns) > 1 else 0
    return xi, yi


def _num(v) -> float:
    try:
        return float(str(v).replace(",", ""))
    except Exception:
        return 0.0


def run_widget(widget: dict) -> dict:
    """Execute one widget's SQL and shape the result for its viz kind."""
    res = dbintrospect.run_query(widget.get("sql", ""),
                                 max_rows=int(widget.get("limit") or 100))
    out = {
        "title": widget.get("title", ""), "viz": widget.get("viz", "table"),
        "width": widget.get("width", "half"),
        "columns": res["columns"], "rows": res["rows"],
        "row_count": res.get("row_count", len(res["rows"])),
        "truncated": res.get("truncated", False), "error": res.get("error", ""),
        "labels": [], "values": [], "stat": None,
    }
    if out["error"] or not res["rows"]:
        return out
    viz = out["viz"]
    if viz in ("bar", "line", "pie"):
        xi, yi = _pick_axes(res["columns"], res["rows"],
                            widget.get("x", ""), widget.get("y", ""))
        out["labels"] = [str(r[xi]) for r in res["rows"]]
        out["values"] = [_num(r[yi]) for r in res["rows"]]
        out["x_col"] = res["columns"][xi] if res["columns"] else ""
        out["y_col"] = res["columns"][yi] if res["columns"] else ""
    elif viz == "stat":
        out["stat"] = res["rows"][0][0] if res["rows"][0] else ""
    return out


def run_report(report) -> dict:
    """Execute every widget of a DbReport → dict ready for JSON / PDF."""
    return {
        "id": report.id, "name": report.name,
        "description": report.description or "",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "widgets": [run_widget(w) for w in report.widgets],
    }


# --------------------------------------------------------------------------
# PDF rendering (reportlab — pure python, headless)
# --------------------------------------------------------------------------

_ACCENT = "#3b82f6"
_ACCENT2 = "#8b5cf6"
_PALETTE = ["#3b82f6", "#8b5cf6", "#10b981", "#fbbf24", "#ef4444",
            "#06b6d4", "#f97316", "#84cc16", "#ec4899", "#64748b"]


def build_pdf(result: dict, *, author: str = "") -> bytes:
    """Render an executed report (``run_report`` output) to PDF bytes."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (HRFlowable, Paragraph, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=16 * mm, bottomMargin=14 * mm,
        title=result.get("name", "Report"), author=author or "OFortMAuT")
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("RptH1", parent=styles["Title"], fontSize=20,
                        textColor=colors.HexColor("#0f172a"), spaceAfter=2)
    sub = ParagraphStyle("RptSub", parent=styles["Normal"], fontSize=9,
                         textColor=colors.HexColor("#64748b"), spaceAfter=8)
    h2 = ParagraphStyle("RptH2", parent=styles["Heading2"], fontSize=13,
                        textColor=colors.HexColor("#1e293b"),
                        spaceBefore=12, spaceAfter=4)
    small = ParagraphStyle("RptSmall", parent=styles["Normal"], fontSize=8,
                           textColor=colors.HexColor("#64748b"))
    err_style = ParagraphStyle("RptErr", parent=styles["Normal"], fontSize=9,
                               textColor=colors.HexColor("#b91c1c"))
    cell = ParagraphStyle("RptCell", parent=styles["Normal"], fontSize=7.5,
                          leading=9)

    story = [Paragraph(_esc(result.get("name", "Report")), h1)]
    meta = f"Generated {result.get('generated_at', '')}"
    if author:
        meta += f" · by {_esc(author)}"
    meta += " · OFortMAuT — Database reports"
    story.append(Paragraph(meta, sub))
    if result.get("description"):
        story.append(Paragraph(_esc(result["description"]), styles["Normal"]))
        story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1,
                            color=colors.HexColor(_ACCENT)))

    avail_w = doc.width
    for w in result.get("widgets", []):
        story.append(Paragraph(_esc(w.get("title", "")), h2))
        if w.get("error"):
            story.append(Paragraph("Query error: " + _esc(w["error"]),
                                   err_style))
            continue
        if not w.get("rows"):
            story.append(Paragraph("No data.", small))
            continue
        viz = w.get("viz", "table")
        if viz == "stat":
            stat = ParagraphStyle("RptStat", parent=styles["Normal"],
                                  fontSize=26, leading=30,
                                  textColor=colors.HexColor(_ACCENT))
            story.append(Paragraph(_esc(str(w.get("stat") or "")), stat))
            if w.get("columns"):
                story.append(Paragraph(_esc(w["columns"][0]), small))
        elif viz in ("bar", "line", "pie"):
            story.append(_chart_flowable(w, viz, avail_w))
            story.append(Paragraph(
                f"{_esc(w.get('y_col', ''))} by {_esc(w.get('x_col', ''))}"
                f" · {w.get('row_count', 0)} rows", small))
        else:  # table
            story.append(_table_flowable(w, avail_w, cell, colors,
                                         Table, TableStyle))
            note = f"{w.get('row_count', 0)} rows"
            if w.get("row_count", 0) > PDF_MAX_TABLE_ROWS:
                note += f" · first {PDF_MAX_TABLE_ROWS} shown"
            if w.get("truncated"):
                note += " · result truncated by row limit"
            story.append(Paragraph(note, small))
        story.append(Spacer(1, 4))

    doc.build(story)
    return buf.getvalue()


def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def _table_flowable(w, avail_w, cell_style, colors, Table, TableStyle):
    from reportlab.platypus import Paragraph
    cols = w["columns"]
    rows = w["rows"][:PDF_MAX_TABLE_ROWS]
    # cap very wide tables so they stay legible
    max_cols = 10
    if len(cols) > max_cols:
        cols = cols[:max_cols]
        rows = [r[:max_cols] for r in rows]
    data = [[Paragraph(f"<b>{_esc(c)}</b>", cell_style) for c in cols]]
    for r in rows:
        data.append([Paragraph(_esc(v)[:300], cell_style) for v in r])
    t = Table(data, colWidths=[avail_w / len(cols)] * len(cols),
              repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2ff")),
        ("LINEBELOW", (0, 0), (-1, 0), 0.75, colors.HexColor(_ACCENT)),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


def _chart_flowable(w, viz, avail_w):
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.linecharts import HorizontalLineChart
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.shapes import Drawing, String
    from reportlab.lib import colors

    labels = w.get("labels", [])[:PDF_MAX_CHART_POINTS]
    values = w.get("values", [])[:PDF_MAX_CHART_POINTS]
    height = 200
    d = Drawing(avail_w, height)

    if viz == "pie":
        pie = Pie()
        pie.x, pie.y = 40, 20
        pie.width = pie.height = height - 50
        pie.data = values or [1]
        pie.labels = [str(l)[:22] for l in labels] or [""]
        pie.sideLabels = True
        pie.slices.strokeWidth = 0.5
        pie.slices.strokeColor = colors.white
        pie.slices.fontSize = 7
        for i in range(len(pie.data)):
            pie.slices[i].fillColor = colors.HexColor(
                _PALETTE[i % len(_PALETTE)])
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
    lo = min(values or [0])
    ch.valueAxis.valueMin = min(0, lo)
    if viz == "bar":
        ch.bars[0].fillColor = colors.HexColor(_ACCENT)
        ch.bars[0].strokeColor = None
    else:
        ch.lines[0].strokeColor = colors.HexColor(_ACCENT2)
        ch.lines[0].strokeWidth = 1.6
    d.add(ch)
    if not values:
        d.add(String(avail_w / 2, height / 2, "no numeric data",
                     fontSize=9, fillColor=colors.HexColor("#94a3b8")))
    return d
