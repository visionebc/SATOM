"""Minimal XLSX (SpreadsheetML) writer built on the Python standard library only.

WHY THIS EXISTS
---------------
SATOM ships as an offline bundle: the target LXCs have no PyPI access and the
wheel set is frozen at install time. ``openpyxl`` / ``xlsxwriter`` are NOT
installed and MUST NOT be added — pulling either one in would drag lxml/Pillow
style transitive weight into an air-gapped image for the sake of "export to
Excel". Everything an operator export needs (a header row, typed cells, a few
sheets) is a few hundred lines of zipfile + XML, so we write it ourselves.

Only ``zipfile``, ``xml.sax.saxutils``, ``datetime``, ``re`` and ``math`` are
used — all stdlib, all import-side-effect-free. No Flask, no DB, no disk I/O:
every entry point returns ``bytes`` the caller can hand to ``send_file``.

DESIGN NOTES (the WHYs that are easy to get wrong)
--------------------------------------------------
* **Inline strings, no sharedStrings table.** ``t="inlineStr"`` costs a few
  bytes per repeated string but removes the shared-string index entirely.
  Index drift between the table and the cells is the classic way a hand-rolled
  writer produces a file that opens with the wrong text in every cell; we make
  that failure mode unrepresentable.
* **Escaping and control-char stripping are not optional.** Device banners,
  FortiWeb signature descriptions and attack-log payloads routinely contain
  ``&``, ``<`` and raw 0x00/0x1F bytes. A single unescaped ``&`` or an illegal
  control char makes Excel refuse the file with "unreadable content" and no
  indication of which cell is at fault. Everything that reaches XML goes
  through :func:`_clean` then :func:`escape`.
* **Dates are written as ISO-8601 *strings*, not Excel serials.** A serial
  needs a matching ``numFmt`` in styles.xml *and* the 1900-leap-year fudge, and
  it silently renders as a 5-digit integer in any reader that loses the style.
  The trade-off: you cannot do date arithmetic on the exported column in Excel.
  That is accepted — this is an export for humans to read and filter, not a
  spreadsheet model.
* **Deterministic bytes.** Every ``ZipInfo`` gets a fixed timestamp instead of
  ``datetime.now()``, so identical input yields byte-identical output. That is
  what makes regression/guard tests on the produced file possible at all.
"""
from __future__ import annotations

import math
import re
import zipfile
from datetime import date, datetime
from io import BytesIO
from typing import Any, Iterable, Sequence
from xml.sax.saxutils import escape

# Hard cap on rows per sheet, header included.
#
# Excel's own sheet limit is 1_048_576 rows, but this writer buffers the whole
# workbook in memory as a str/bytes blob; a million rows of inline strings is
# hundreds of MB in a Flask worker. 100k rows is far more than any SATOM report
# a human will read, and anything larger belongs in the CSV export instead.
# Exceeding it raises — we never silently truncate an operator's data.
MAX_ROWS = 100_000

# Sheet-name rules enforced by Excel itself.
MAX_SHEET_NAME = 31
_BAD_SHEET_CHARS = re.compile(r"[\[\]:*?/\\]")

# Characters that are illegal in XML 1.0 even when escaped as a numeric
# reference: C0 controls other than TAB/LF/CR, the surrogate block, and the two
# non-characters. There is no way to represent these in an XLSX part, so they
# are dropped rather than mangled.
_ILLEGAL_XML = re.compile(
    "[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\ud800-\\udfff\\ufffe\\uffff]"
)

_ZIP_DATE = (1980, 1, 1, 0, 0, 0)  # fixed => deterministic archive bytes

_NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_NS_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_NS_CT = "http://schemas.openxmlformats.org/package/2006/content-types"

_XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'

STYLE_NORMAL = 0
STYLE_BOLD = 1


# --------------------------------------------------------------------------
# Text hygiene
# --------------------------------------------------------------------------

def _clean(text: str) -> str:
    """Strip characters that XML 1.0 cannot represent at all.

    Kept separate from escaping because the two guard different failures:
    escaping fixes ``&``/``<``; this fixes the 0x00 a device banner smuggles in.
    """
    return _ILLEGAL_XML.sub("", text)


def _text(value: Any) -> str:
    """Clean + XML-escape an arbitrary value's text form."""
    return escape(_clean(value if isinstance(value, str) else str(value)))


def _attr(value: str) -> str:
    """Escape for use inside a double-quoted XML attribute."""
    return escape(_clean(value), {'"': "&quot;"})


# --------------------------------------------------------------------------
# Column references
# --------------------------------------------------------------------------

def col_letter(index: int) -> str:
    """0-based column index -> Excel column letters.

    0 -> A, 25 -> Z, 26 -> AA, 701 -> ZZ, 702 -> AAA. This is bijective base-26
    (no zero digit), which is why the loop subtracts one before each divmod
    instead of doing a plain base conversion.
    """
    if not isinstance(index, int) or isinstance(index, bool):
        raise TypeError("column index must be an int")
    if index < 0:
        raise ValueError(f"column index must be >= 0, got {index}")
    out = ""
    n = index + 1
    while n > 0:
        n, rem = divmod(n - 1, 26)
        out = chr(ord("A") + rem) + out
    return out


# --------------------------------------------------------------------------
# Sheet names
# --------------------------------------------------------------------------

def sanitize_sheet_name(name: Any, fallback: str = "Sheet1") -> str:
    """Coerce ``name`` into something Excel will actually accept.

    Excel rejects ``[ ] : * ? / \\``, rejects empty names, rejects names that
    begin or end with an apostrophe, and truncates past 31 chars. A workbook
    that violates any of these opens as "repaired" at best.
    """
    if name is None:
        text = ""
    elif isinstance(name, str):
        text = name
    else:
        text = str(name)
    text = _clean(text).replace("\n", " ").replace("\r", " ").replace("\t", " ")
    text = _BAD_SHEET_CHARS.sub("_", text).strip()
    text = text[:MAX_SHEET_NAME].strip().strip("'")
    return text or fallback


def _dedupe(names: Sequence[str]) -> list[str]:
    """Make sheet names unique. Two identical names = a corrupt workbook.

    Excel compares sheet names case-insensitively, so the seen-set is folded.
    The ``(n)`` suffix is appended *after* trimming the base so the result still
    fits in 31 characters.
    """
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        candidate = name
        n = 1
        while candidate.casefold() in seen:
            n += 1
            suffix = f" ({n})"
            base = name[: MAX_SHEET_NAME - len(suffix)].rstrip()
            candidate = f"{base}{suffix}"
        seen.add(candidate.casefold())
        out.append(candidate)
    return out


# --------------------------------------------------------------------------
# Cells
# --------------------------------------------------------------------------

def _cell(ref: str, value: Any, style: int) -> str:
    """Render one ``<c>`` element.

    Order matters: ``bool`` is a subclass of ``int``, so it must be tested
    first or True would export as the number 1 with no type. Likewise
    ``datetime`` subclasses ``date``.
    """
    s_attr = f' s="{style}"' if style else ""

    if value is None:
        # Empty cell, NOT the string "None" — an exported "None" reads as data.
        return f'<c r="{ref}"{s_attr}/>'

    if isinstance(value, bool):
        return f'<c r="{ref}"{s_attr} t="b"><v>{1 if value else 0}</v></c>'

    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            # NaN/inf have no numeric representation in SpreadsheetML; fall
            # through to a string so the file still opens.
            return _inline(ref, s_attr, repr(value))
        return f'<c r="{ref}"{s_attr} t="n"><v>{value!r}</v></c>'

    if isinstance(value, datetime):
        return _inline(ref, s_attr, value.isoformat(sep=" "))
    if isinstance(value, date):
        return _inline(ref, s_attr, value.isoformat())

    return _inline(ref, s_attr, value if isinstance(value, str) else str(value))


def _inline(ref: str, s_attr: str, raw: str) -> str:
    text = _text(raw)
    if not text:
        return f'<c r="{ref}"{s_attr}/>'
    # xml:space="preserve" keeps leading/trailing spaces that matter in config
    # excerpts; without it the reader is free to collapse them.
    return (
        f'<c r="{ref}"{s_attr} t="inlineStr">'
        f'<is><t xml:space="preserve">{text}</t></is></c>'
    )


# --------------------------------------------------------------------------
# Parts
# --------------------------------------------------------------------------

def _sheet_xml(rows: Sequence[Sequence[Any]]) -> str:
    parts = [
        _XML_DECL,
        f'<worksheet xmlns="{_NS_MAIN}" xmlns:r="{_NS_R}">',
    ]
    if rows:
        # Freeze the header row so it stays visible while scrolling a long
        # attack/config export.
        parts.append(
            '<sheetViews><sheetView workbookViewId="0">'
            '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
            "</sheetView></sheetViews>"
        )
    parts.append("<sheetData>")
    for r_idx, row in enumerate(rows):
        style = STYLE_BOLD if r_idx == 0 else STYLE_NORMAL
        cells = [
            _cell(f"{col_letter(c_idx)}{r_idx + 1}", value, style)
            for c_idx, value in enumerate(row)
        ]
        parts.append(f'<row r="{r_idx + 1}">{"".join(cells)}</row>')
    parts.append("</sheetData></worksheet>")
    return "".join(parts)


def _content_types_xml(n_sheets: int) -> str:
    overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.'
        'spreadsheetml.worksheet+xml"/>'
        for i in range(1, n_sheets + 1)
    )
    return (
        f"{_XML_DECL}"
        f'<Types xmlns="{_NS_CT}">'
        '<Default Extension="rels" ContentType="application/'
        'vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/'
        'vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/'
        'vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        f"{overrides}"
        "</Types>"
    )


def _root_rels_xml() -> str:
    return (
        f"{_XML_DECL}"
        f'<Relationships xmlns="{_NS_PKG_REL}">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        "</Relationships>"
    )


def _workbook_xml(names: Sequence[str]) -> str:
    sheets = "".join(
        f'<sheet name="{_attr(name)}" sheetId="{i}" r:id="rId{i}"/>'
        for i, name in enumerate(names, start=1)
    )
    return (
        f"{_XML_DECL}"
        f'<workbook xmlns="{_NS_MAIN}" xmlns:r="{_NS_R}">'
        f"<sheets>{sheets}</sheets>"
        "</workbook>"
    )


def _workbook_rels_xml(n_sheets: int) -> str:
    rels = "".join(
        f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{i}.xml"/>'
        for i in range(1, n_sheets + 1)
    )
    rels += (
        f'<Relationship Id="rId{n_sheets + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        'relationships/styles" Target="styles.xml"/>'
    )
    return f'{_XML_DECL}<Relationships xmlns="{_NS_PKG_REL}">{rels}</Relationships>'


def _styles_xml() -> str:
    """Two cellXfs: 0 = normal, 1 = bold. The header row references ``s="1"``.

    Excel is picky here — fills[1] must be gray125 and the borders/cellStyleXfs
    entries must exist even though nothing uses them, or the file is "repaired".
    """
    return (
        f"{_XML_DECL}"
        f'<styleSheet xmlns="{_NS_MAIN}">'
        '<fonts count="2">'
        '<font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/></font>'
        "</fonts>"
        '<fills count="2">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        "</fills>"
        '<borders count="1"><border><left/><right/><top/><bottom/>'
        "<diagonal/></border></borders>"
        '<cellStyleXfs count="1">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>'
        "</cellStyleXfs>"
        '<cellXfs count="2">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
        "</cellXfs>"
        '<cellStyles count="1">'
        '<cellStyle name="Normal" xfId="0" builtinId="0"/>'
        "</cellStyles>"
        "</styleSheet>"
    )


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def _materialize(rows: Iterable[Iterable[Any]], sheet_name: str) -> list[list[Any]]:
    out: list[list[Any]] = []
    for row in rows:
        if isinstance(row, (str, bytes)):
            raise TypeError("each row must be an iterable of cells, not a string")
        out.append(list(row))
    if len(out) > MAX_ROWS:
        raise ValueError(
            f"sheet {sheet_name!r} has {len(out)} rows, exceeding MAX_ROWS "
            f"({MAX_ROWS}); export as CSV instead"
        )
    return out


def _zip(parts: Sequence[tuple[str, str]]) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in parts:
            info = zipfile.ZipInfo(name, date_time=_ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # pin, else Windows vs POSIX differ
            info.external_attr = 0o600 << 16
            zf.writestr(info, data.encode("utf-8"))
    return buf.getvalue()


def write_book(sheets: Iterable[tuple[str, Iterable[Iterable[Any]]]]) -> bytes:
    """Build a multi-sheet .xlsx workbook and return its bytes.

    ``sheets`` is an iterable of ``(sheet_name, rows)``. Row 0 of every sheet is
    treated as the header (bold, frozen pane). Names are sanitized and
    de-duplicated; rows may be ragged.
    """
    raw = list(sheets)
    if not raw:
        raw = [("Sheet1", [])]

    names = _dedupe([sanitize_sheet_name(name) for name, _ in raw])
    grids = [_materialize(rows, name) for name, (_, rows) in zip(names, raw)]

    parts: list[tuple[str, str]] = [
        ("[Content_Types].xml", _content_types_xml(len(grids))),
        ("_rels/.rels", _root_rels_xml()),
        ("xl/workbook.xml", _workbook_xml(names)),
        ("xl/_rels/workbook.xml.rels", _workbook_rels_xml(len(grids))),
        ("xl/styles.xml", _styles_xml()),
    ]
    for i, grid in enumerate(grids, start=1):
        parts.append((f"xl/worksheets/sheet{i}.xml", _sheet_xml(grid)))
    return _zip(parts)


def write_sheet(rows: Iterable[Iterable[Any]], *, sheet_name: str = "Sheet1") -> bytes:
    """Build a single-sheet .xlsx workbook and return its bytes."""
    return write_book([(sheet_name, rows)])
