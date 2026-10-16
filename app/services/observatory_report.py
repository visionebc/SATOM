# app/services/observatory_report.py
"""HTTP Observatory exports — the grades leave the console.

* :func:`sites_csv` — one line per published site of an appliance with its
  latest grade and the result code of every test (a spreadsheet of the
  fleet's posture, the shape an auditor asks for).
* :func:`scan_pdf` — one graded scan as a report: the grade, what was graded
  and against which preload list, and per test who produced the result and
  what fixes it. The same findings the page shows (the caller passes the
  page's own view), so the PDF can never say something the page does not.

What a scan stores is what an export can carry: headers, statuses, routes,
cookie flags — never cookie values or page bodies. Cells go through
:func:`app.services.csv_safe.spreadsheet_safe` (device object names and
header values are text someone else typed). Pure reportlab, no browser.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime

from . import header_observatory as ho
from .csv_safe import spreadsheet_safe

#: The .fw-badge-* colours, calibrated against white (safeguards §9m).
_GOOD, _WARN, _BAD, _INFO, _MUTED = "#15692A", "#7A5700", "#8B1C2A", "#4C2A85", "#3D4550"
_ACCENT = "#EF5424"
WHO_LABEL = {"fortiweb": "FortiWeb", "application": "Application",
             "certificate": "Certificate", "missing": "Not sent", "none": ""}


def _grade_colour(grade: str | None) -> str:
    if not grade:
        return _MUTED
    return {"A": _GOOD, "B": _INFO, "C": _WARN}.get(grade[0], _BAD)


def _test_names() -> list[str]:
    return [name for name, _title in ho.TESTS]


def sites_csv(appliance, targets, latest: dict, *, listing_error: str = "") -> str:
    """CSV of every published site (*targets*, :class:`Target` list) with its
    newest scan (*latest*: ``{policy: ObservatoryScan}``). When the device
    could not be listed, *targets* is empty and the stored scans are the
    rows — the ``note`` column says so instead of the file looking complete."""
    names = _test_names()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["appliance", "policy", "vip", "site_name", "http_port", "https_port",
                "scannable", "grade", "score", "tests_passed", "tests_failed",
                "graded_at_utc", "trigger", "error"] + names + ["note"])
    rows = []
    if targets:
        for t in targets:
            scan = latest.get(t.policy)
            rows.append((t.policy, t.vip, (scan.host if scan else "") or t.default_host,
                         t.http_port, t.https_port, t.scannable, t.note, scan))
    else:
        for policy, scan in sorted(latest.items()):
            tgt = (scan.result_dict.get("target") or {})
            rows.append((policy, tgt.get("vip", ""), scan.host, tgt.get("http_port"),
                         tgt.get("https_port"), tgt.get("scannable", ""),
                         listing_error or "not listed", scan))
    for policy, vip, host, http_port, https_port, scannable, note, scan in rows:
        results = {}
        if scan is not None:
            for t in ((scan.result_dict.get("analysis") or {}).get("tests") or []):
                results[t.get("name")] = t.get("result")
        cells = [appliance.name, policy, vip or "", host or "", http_port or "", https_port or "",
                 "yes" if scannable is True else ("no" if scannable is False else scannable),
                 scan.grade if scan else "", scan.score if scan and scan.score is not None else "",
                 scan.tests_passed if scan and scan.tests_passed is not None else "",
                 scan.tests_failed if scan and scan.tests_failed is not None else "",
                 scan.started_at.strftime("%Y-%m-%d %H:%M:%S") if scan and scan.started_at else "",
                 scan.trigger if scan else "", (scan.error or "") if scan else ""]
        cells += [results.get(n, "") for n in names]
        cells.append(note or "")
        w.writerow([spreadsheet_safe(c) for c in cells])
    return buf.getvalue()


def scan_pdf(view: dict, *, appliance_name: str, generated_by: str = "") -> bytes:
    """One scan as an A4 PDF. *view* is the page's ``_view()`` of the scan
    (scan summary, target, retrieval, analysis, findings)."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    from .pdf_kit import esc

    scan = view.get("scan") or {}
    tgt = view.get("target") or {}
    ret = view.get("retrieval") or {}
    styles = getSampleStyleSheet()
    body = ParagraphStyle("obs-body", parent=styles["BodyText"], fontSize=8.5, leading=11,
                          alignment=TA_LEFT)
    small = ParagraphStyle("obs-small", parent=body, fontSize=7.5, leading=9.5,
                           textColor=colors.HexColor(_MUTED))
    h1 = ParagraphStyle("obs-h1", parent=styles["Heading1"], fontSize=16, leading=20,
                        textColor=colors.HexColor("#1F2937"))
    out = io.BytesIO()
    doc = SimpleDocTemplate(out, pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm,
                            title="HTTP Observatory — %s" % (scan.get("policy") or ""),
                            author="SATOM")
    story = [Paragraph("HTTP Observatory report", h1)]
    site = "%s · %s · %s" % (appliance_name, scan.get("policy") or "", scan.get("host") or "")
    story.append(Paragraph(esc(site), body))
    grade = scan.get("grade")
    gtxt = ('<font color="%s" size="20"><b>%s</b></font>' % (_grade_colour(grade), esc(grade or "—")))
    if grade:
        gtxt += "&nbsp;&nbsp;<b>%s / 100</b> — %s of %s tests passed" % (
            esc(scan.get("score")), esc(scan.get("tests_passed")),
            esc((scan.get("tests_passed") or 0) + (scan.get("tests_failed") or 0)))
    else:
        gtxt += "&nbsp;&nbsp;Not graded: %s" % esc(scan.get("error") or "")
    story += [Spacer(1, 3 * mm), Paragraph(gtxt, body), Spacer(1, 2 * mm)]
    facts = ["Graded %s UTC (%s%s)" % (esc((scan.get("started_at") or "").replace("T", " ")[:19]),
                                        esc(scan.get("trigger") or ""),
                                        (", " + esc(scan.get("username"))) if scan.get("username") else "")]
    if tgt.get("vip"):
        facts.append("VIP %s · HTTP %s · HTTPS %s" % (esc(tgt.get("vip")), esc(tgt.get("http_port") or "—"),
                                                     esc(tgt.get("https_port") or "—")))
    tls = ret.get("tls") or {}
    if tls and tls.get("verified") is False:
        facts.append("Certificate not trusted by the SATOM node: %s" % esc(tls.get("verify_error") or "?"))
    pl = ret.get("hsts_preload_list") or {}
    if pl:
        facts.append("HSTS preload list: %s" % (
            "%s names" % esc(pl.get("count")) if pl.get("available") else "not on this node (no +5 for preloaded sites)"))
    prev = view.get("previous") or {}
    if prev.get("grade"):
        facts.append("Previous grade: %s (%s)" % (esc(prev.get("grade")), esc(prev.get("score"))))
    if view.get("if_certificate_trusted"):
        c = view["if_certificate_trusted"]
        facts.append("With a trusted certificate: %s (%s)" % (esc(c.get("grade")), esc(c.get("score"))))
    for f in facts:
        story.append(Paragraph(f, small))
    story.append(Spacer(1, 4 * mm))

    tests = {t.get("name"): t for t in ((view.get("analysis") or {}).get("tests") or [])}
    findings = view.get("findings") or [
        {"test": n, "title": t.get("title"), "result": t.get("result"),
         "modifier": t.get("modifier"), "pass": t.get("pass"), "who": "", "explain": "", "fixes": []}
        for n, t in tests.items()]
    head = [Paragraph("<b>%s</b>" % h, body) for h in ("Test", "Score", "Result", "Who", "Why and what to do")]
    data = [head]
    for f in findings:
        t = tests.get(f.get("test")) or {}
        mod = f.get("modifier") or 0
        mcol = _GOOD if mod > 0 else (_BAD if mod < 0 else _MUTED)
        status = ('<font color="%s">pass</font>' % _GOOD if f.get("pass")
                  else '<font color="%s">fail</font>' % _BAD)
        why = esc(f.get("explain") or "")
        for fx in f.get("fixes") or []:
            if fx.get("available"):
                why += "<br/>• Fix: %s" % esc(fx.get("label"))
            else:
                why += "<br/>• %s: %s" % (esc(fx.get("label")), esc(fx.get("why_not") or ""))
        result = esc(t.get("description") or f.get("result") or "")
        if t.get("recommendation"):
            result += '<br/><font color="%s">%s</font>' % (_MUTED, esc(t.get("recommendation")))
        data.append([Paragraph("<b>%s</b><br/>%s" % (esc(f.get("title") or f.get("test")), status), body),
                     Paragraph('<font color="%s"><b>%s%s</b></font>' % (mcol, "+" if mod > 0 else "", esc(mod)), body),
                     Paragraph(result, body),
                     Paragraph(esc(WHO_LABEL.get(f.get("who") or "", f.get("who") or "")), body),
                     Paragraph(why, body)])
    avail = A4[0] - 28 * mm
    table = Table(data, colWidths=[avail * x for x in (0.18, 0.07, 0.30, 0.11, 0.34)], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F3F6FC")),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, colors.HexColor(_ACCENT)),
        ("LINEBELOW", (0, 1), (-1, -1), 0.25, colors.HexColor("#D9DEE8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(table)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "Scoring: MDN HTTP Observatory, algorithm version %d. Redirects are followed only while "
        "they stay on the scanned policy. Generated %s UTC by SATOM%s." % (
            ho.ALGORITHM_VERSION, datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
            (" for " + esc(generated_by)) if generated_by else ""), small))
    doc.build(story)
    return out.getvalue()


__all__ = ["sites_csv", "scan_pdf"]
