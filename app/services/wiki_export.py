"""Operations › Wiki — export an article as Markdown or PDF, or a list as ZIP.

What is exported is a RELEASED version (the current one, or ``rev=N`` from
the history): an unpublished draft never leaves SATOM through here, and an
article that was never published has nothing to export. Who may export is who
may read (services/wiki_access.py); the views ask before calling this module,
and the ZIP is built from :func:`wiki_access.visible_query` with the list's
own filters.

* Markdown: the text exactly as written, under a YAML front matter (title,
  description, topic, tags, audience, version, author, dates, source link).
  Every string is written JSON-quoted, which YAML reads as a plain string —
  a title holding ``: `` or ``#`` cannot break the header.
* PDF: built from the SAME sanitised HTML the article page shows
  (services/wiki_markdown.render), so the PDF can hold nothing the page
  would not: no raw HTML, no ``javascript:`` link. Pure reportlab (no
  browser), like every SATOM PDF. **Images are not fetched**: SATOM does not
  reach out to an address an author typed (that is a request from the
  management network to anywhere); the PDF shows the image's text and link.
  Text uses DejaVu Sans when the node has it (wide Unicode coverage), else
  Bitstream Vera, which ships with reportlab.
"""
from __future__ import annotations

import io
import json
import os
import re
import zipfile
from datetime import datetime
from html.parser import HTMLParser

from ..models_wiki import WikiArticle, WikiRevision
from . import wiki_markdown as wmd
from .pdf_kit import esc

#: A ZIP holds at most this many articles (the rest is said in its README).
MAX_ZIP = 500


class ExportError(ValueError):
    """Nothing to export; the message is shown to the user."""


def version_of(article: WikiArticle, rev: int | None = None) -> WikiRevision:
    """The released version to export: ``rev`` or the current one."""
    if not article.revision:
        raise ExportError("This article has never been published: there is nothing to export.")
    number = int(rev) if rev else article.revision
    row = WikiRevision.query.filter_by(article_id=article.id, number=number).first()
    if row is None:
        raise ExportError("Version %s of this article does not exist." % number)
    return row


def _q(value) -> str:
    return json.dumps(str(value if value is not None else ""), ensure_ascii=False)


def audience_text(article: WikiArticle, adom_names: dict) -> str:
    where = ", ".join(adom_names.get(k, k) for k in article.adoms) or "Global"
    if not article.audience_restricted:
        return where
    who = [p.name for p in article.profiles] + [g.name for g in article.groups]
    return "%s; restricted to %s" % (where, ", ".join(who) or "its author and the moderators")


def markdown_document(article: WikiArticle, rev: WikiRevision, *, adom_names: dict,
                      source_url: str = "") -> str:
    lines = ["---",
             "title: " + _q(rev.title)]
    if rev.summary:
        lines.append("description: " + _q(rev.summary))
    if article.topic is not None:
        lines.append("topic: " + _q(article.topic.label))
    tags = [t.name for t in article.tags]
    if tags:
        lines.append("tags: [" + ", ".join(_q(t) for t in tags) + "]")
    lines += ["audience: " + _q(audience_text(article, adom_names)),
              "version: %d" % rev.number,
              "status: " + _q(article.status),
              "author: " + _q(article.author.username if article.author else ""),
              "edited_by: " + _q(rev.edited_by),
              "edited_at: " + _q(rev.edited_at.strftime("%Y-%m-%dT%H:%M:%SZ"))]
    if source_url:
        lines.append("source: " + _q(source_url))
    lines += ["exported_at: " + _q(datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
              "---", "", "# " + rev.title, ""]
    if rev.summary:
        lines += ["> " + rev.summary, ""]
    body = (rev.body or "").rstrip("\n")
    return "\n".join(lines) + "\n" + body + "\n"


def filename(article: WikiArticle, rev: WikiRevision, ext: str) -> str:
    return "%s-v%d.%s" % (article.slug or "article", rev.number, ext)


# ── PDF ──────────────────────────────────────────────────────────────────────

_FONT_DIRS = ("/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/dejavu",
              "/usr/share/fonts/TTF", "/usr/share/fonts/truetype")
_FONTS: dict | None = None


def _fonts() -> dict:
    """Register the body/bold/italic/mono fonts once: DejaVu if present,
    else Vera from reportlab's own font folder."""
    global _FONTS
    if _FONTS is not None:
        return _FONTS
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    import reportlab
    sets = [("WikiDejaVu", {"": "DejaVuSans.ttf", "B": "DejaVuSans-Bold.ttf",
                            "I": "DejaVuSans-Oblique.ttf", "BI": "DejaVuSans-BoldOblique.ttf",
                            "M": "DejaVuSansMono.ttf"}, _FONT_DIRS),
            ("WikiVera", {"": "Vera.ttf", "B": "VeraBd.ttf", "I": "VeraIt.ttf",
                          "BI": "VeraBI.ttf", "M": "VeraMono.ttf"},
             (os.path.join(os.path.dirname(reportlab.__file__), "fonts"),))]
    for family, files, dirs in sets:
        found = {}
        for style, name in files.items():
            for d in dirs:
                path = os.path.join(d, name)
                if os.path.isfile(path):
                    found[style] = path
                    break
        if not all(k in found for k in ("", "B")):
            continue
        # Debian's fonts-dejavu-core ships no oblique faces: italic falls back
        # to the upright one rather than losing DejaVu's Unicode coverage.
        found.setdefault("I", found[""])
        found.setdefault("BI", found["B"])
        names = {}
        for style, path in found.items():
            names[style] = family + style
            pdfmetrics.registerFont(TTFont(names[style], path))
        pdfmetrics.registerFontFamily(family, normal=names[""], bold=names["B"],
                                      italic=names["I"], boldItalic=names["BI"])
        _FONTS = {"body": names[""], "bold": names["B"], "mono": names.get("M", "Courier")}
        return _FONTS
    _FONTS = {"body": "Helvetica", "bold": "Helvetica-Bold", "mono": "Courier"}
    return _FONTS


class _Node:
    __slots__ = ("tag", "attrs", "children")

    def __init__(self, tag, attrs=None):
        self.tag, self.attrs, self.children = tag, dict(attrs or {}), []


class _Tree(HTMLParser):
    VOID = {"br", "hr", "img"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _Node("root")
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = _Node(tag, attrs)
        self.stack[-1].children.append(node)
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.stack[-1].children.append(_Node(tag, attrs))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        self.stack[-1].children.append(data)


def _parse(html: str) -> _Node:
    t = _Tree()
    t.feed(html)
    t.close()
    return t.root


def _inline(node, fonts) -> str:
    """reportlab Paragraph mini-markup for the inline content of ``node``.
    Every text run goes through :func:`esc`."""
    out = []
    for ch in node.children:
        if isinstance(ch, str):
            out.append(esc(ch))
            continue
        tag = ch.tag
        inner = _inline(ch, fonts)
        if tag in ("strong", "b"):
            out.append("<b>%s</b>" % inner)
        elif tag in ("em", "i"):
            out.append("<i>%s</i>" % inner)
        elif tag == "del":
            out.append("<strike>%s</strike>" % inner)
        elif tag == "code":
            out.append('<font face="%s" color="#8B1C2A">%s</font>' % (fonts["mono"], inner))
        elif tag == "br":
            out.append("<br/>")
        elif tag == "a":
            href = wmd.safe_url(ch.attrs.get("href"))
            if href and re.match(r"^(https?:|mailto:)", href, re.I):
                out.append('<a href="%s" color="#1D4ED8">%s</a>' % (esc(href).replace('"', "&quot;"),
                                                                   inner))
            else:
                out.append(inner)
        elif tag == "img":
            alt = ch.attrs.get("alt") or "image"
            src = wmd.safe_url(ch.attrs.get("src"), image=True) or ""
            out.append('<i>[%s]</i>%s' % (esc(alt), (" " + esc(src)) if src else ""))
        else:
            out.append(inner)
    return "".join(out)


def _text(node) -> str:
    if isinstance(node, str):
        return node
    return "".join(_text(c) for c in node.children)


def _wrap_code(text: str, width: int = 92) -> str:
    lines = []
    for line in text.rstrip("\n").split("\n"):
        while len(line) > width:
            lines.append(line[:width])
            line = "  " + line[width:]
        lines.append(line)
    return "\n".join(lines)


def _flowables(node, st, fonts, avail_w, depth=0) -> list:
    from reportlab.lib import colors
    from reportlab.platypus import (HRFlowable, Paragraph, Preformatted, Spacer, Table,
                                    TableStyle)
    out: list = []
    loose = []

    def flush():
        txt = "".join(loose).strip()
        if txt:
            out.append(Paragraph(txt, st["body"]))
        loose.clear()

    for ch in node.children:
        if isinstance(ch, str):
            if ch.strip():
                loose.append(esc(ch))
            continue
        tag = ch.tag
        if tag in ("strong", "b", "em", "i", "code", "a", "del", "br", "img", "span"):
            wrapper = _Node("span")
            wrapper.children = [ch]
            loose.append(_inline(wrapper, fonts))
            continue
        flush()
        if re.fullmatch(r"h[1-6]", tag):
            level = min(int(tag[1]), 4)
            out.append(Paragraph(_inline(ch, fonts), st["h%d" % level]))
        elif tag == "p":
            out.append(Paragraph(_inline(ch, fonts), st["body"]))
        elif tag in ("ul", "ol"):
            n = 0
            for li in ch.children:
                if isinstance(li, str) or li.tag != "li":
                    continue
                n += 1
                bullet = "%d." % n if tag == "ol" else "•"
                inline_part = _Node("span")
                blocks = _Node("div")
                for c in li.children:
                    if not isinstance(c, str) and c.tag in ("ul", "ol", "pre", "table",
                                                            "blockquote"):
                        blocks.children.append(c)
                    elif not isinstance(c, str) and c.tag == "p":
                        inline_part.children.extend(c.children + [" "])
                    else:
                        inline_part.children.append(c)
                style = st["li"].clone("li%d" % depth, leftIndent=14 + 14 * depth,
                                       bulletIndent=4 + 14 * depth)
                out.append(Paragraph(_inline(inline_part, fonts), style, bulletText=bullet))
                out.extend(_flowables(blocks, st, fonts, avail_w, depth + 1))
        elif tag == "pre":
            out.append(Preformatted(_wrap_code(_text(ch)), st["code"]))
        elif tag == "blockquote":
            grey = colors.HexColor("#3D4550")
            quoted = dict(st)
            for k in ("body", "li"):
                quoted[k] = st[k].clone(k + "q", leftIndent=st[k].leftIndent + 12, textColor=grey)
            out.extend(_flowables(ch, quoted, fonts, avail_w - 12, depth))
        elif tag == "hr":
            out.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#CBD2DC"),
                                  spaceBefore=4, spaceAfter=6))
        elif tag == "table":
            rows = []
            head_rows = 0
            for section in ch.children:
                if isinstance(section, str):
                    continue
                trs = section.children if section.tag in ("thead", "tbody") else [section]
                for tr in trs:
                    if isinstance(tr, str) or tr.tag != "tr":
                        continue
                    cells = [c for c in tr.children if not isinstance(c, str)
                             and c.tag in ("td", "th")]
                    if section.tag == "thead":
                        head_rows += 1
                    rows.append([Paragraph(_inline(c, fonts),
                                           st["cellh"] if c.tag == "th" else st["cell"])
                                 for c in cells])
            if rows:
                ncols = max(len(r) for r in rows)
                rows = [r + [""] * (ncols - len(r)) for r in rows]
                t = Table(rows, colWidths=[avail_w / ncols] * ncols, repeatRows=head_rows)
                style = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD2DC")),
                         ("VALIGN", (0, 0), (-1, -1), "TOP")]
                if head_rows:
                    style.append(("BACKGROUND", (0, 0), (-1, head_rows - 1),
                                  colors.HexColor("#F3F6FC")))
                t.setStyle(TableStyle(style))
                out += [t, Spacer(1, 6)]
        else:
            out.extend(_flowables(ch, st, fonts, avail_w, depth))
    flush()
    return out


def _styles(fonts):
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    base = ParagraphStyle("body", fontName=fonts["body"], fontSize=10, leading=14,
                          spaceAfter=6, textColor=colors.HexColor("#1F2933"))
    st = {"body": base,
          "title": base.clone("title", fontName=fonts["bold"], fontSize=18, leading=22,
                              spaceAfter=4),
          "meta": base.clone("meta", fontSize=8, leading=11, textColor=colors.HexColor("#5B6573")),
          "summary": base.clone("summary", fontSize=11, leading=15,
                                textColor=colors.HexColor("#3D4550")),
          "li": base.clone("li", spaceAfter=2),
          "code": base.clone("code", fontName=fonts["mono"], fontSize=8, leading=10.5,
                             backColor=colors.HexColor("#F3F6FC"), borderPadding=4,
                             spaceBefore=2, spaceAfter=8),
          "cell": base.clone("cell", fontSize=8.5, leading=11, spaceAfter=0),
          "cellh": base.clone("cellh", fontName=fonts["bold"], fontSize=8.5, leading=11,
                              spaceAfter=0)}
    for n, size in ((1, 15), (2, 13), (3, 11.5), (4, 10.5)):
        st["h%d" % n] = base.clone("h%d" % n, fontName=fonts["bold"], fontSize=size,
                                   leading=size + 4, spaceBefore=8, spaceAfter=4)
    return st


def pdf_document(article: WikiArticle, rev: WikiRevision, *, adom_names: dict,
                 exported_by: str = "", source_url: str = "") -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate
    fonts = _fonts()
    st = _styles(fonts)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title=rev.title, author=(article.author.username
                                                     if article.author else ""),
                            subject="SATOM Wiki", creator="SATOM")
    avail = A4[0] - 36 * mm
    meta = ["Version %d" % rev.number,
            "edited %s UTC by %s" % (rev.edited_at.strftime("%Y-%m-%d %H:%M"),
                                     rev.edited_by or "?"),
            audience_text(article, adom_names)]
    if article.topic is not None:
        meta.insert(0, article.topic.label)
    tags = " ".join("#" + t.name for t in article.tags)
    story = [Paragraph(esc(rev.title), st["title"]),
             Paragraph(esc(" · ".join(meta)) + ("<br/>" + esc(tags) if tags else ""), st["meta"])]
    if rev.summary:
        story.append(Paragraph(esc(rev.summary), st["summary"]))
    story += _flowables(_parse(str(wmd.render(rev.body))), st, fonts, avail)
    stamp = "SATOM Wiki · %s · version %d · exported %s UTC%s" % (
        rev.title[:60], rev.number, datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
        (" by " + exported_by) if exported_by else "")

    def footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont(fonts["body"], 7)
        canvas.setFillColorRGB(0.36, 0.40, 0.45)
        canvas.drawString(18 * mm, 9 * mm, stamp)
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, "page %d" % canvas.getPageNumber())
        if source_url:
            canvas.drawString(18 * mm, 6 * mm, source_url[:140])
        canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


# ── ZIP ──────────────────────────────────────────────────────────────────────

def _folder(article: WikiArticle) -> str:
    from .wiki import slugify
    if article.topic is None:
        return "_no-topic"
    return "/".join(slugify(t.name) for t in article.topic.path)


def zip_document(articles, fmt: str, *, adom_names: dict, exported_by: str = "",
                 url_for_article=None, total: int | None = None) -> bytes:
    """``articles`` (already narrowed to what the user may read) as one ZIP,
    one file per article in a folder per topic; drafts are skipped."""
    if fmt not in ("md", "pdf"):
        raise ExportError("Unknown format.")
    buf = io.BytesIO()
    done = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for art in articles:
            if len(done) >= MAX_ZIP:
                break
            if not art.revision:
                continue
            rev = version_of(art)
            src = url_for_article(art) if url_for_article else ""
            path = "%s/%s" % (_folder(art), filename(art, rev, fmt))
            if fmt == "md":
                zf.writestr(path, markdown_document(art, rev, adom_names=adom_names,
                                                    source_url=src))
            else:
                zf.writestr(path, pdf_document(art, rev, adom_names=adom_names,
                                               exported_by=exported_by, source_url=src))
            done.append("- %s (version %d) — %s" % (rev.title, rev.number, path))
        readme = ["SATOM Wiki export", "",
                  "Exported %s UTC%s. %d article(s), released versions only "
                  "(unpublished drafts are never exported)." % (
                      datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
                      (" by " + exported_by) if exported_by else "", len(done))]
        skipped = max(0, (total or 0) - len(done))
        if skipped:
            readme.append("%d more article(s) were left out: one ZIP holds at most %d. "
                          "Narrow the list and export again." % (skipped, MAX_ZIP))
        zf.writestr("README.txt", "\n".join(readme + [""] + done) + "\n")
    return buf.getvalue()
