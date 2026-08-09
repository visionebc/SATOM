"""Guard tests for the stdlib XLSX writer.

Every assertion goes through the real readers — ``zipfile.ZipFile`` opens the
produced bytes and ``xml.etree.ElementTree`` parses the parts. Asserting on the
byte blob would prove nothing: the whole point of this module is that Excel can
open what it emits, and "parses as XML" is the cheapest available proxy for
that.
"""
import datetime
import io
import zipfile
import xml.etree.ElementTree as ET

import pytest

from app.services import xlsx_writer

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _zf(blob):
    return zipfile.ZipFile(io.BytesIO(blob))


def _part(blob, name):
    with _zf(blob) as zf:
        return zf.read(name)


def _sheet_root(blob, n=1):
    return ET.fromstring(_part(blob, f"xl/worksheets/sheet{n}.xml"))


def _rows(blob, n=1):
    return _sheet_root(blob, n).findall(".//m:sheetData/m:row", NS)


def _cells(row):
    return row.findall("m:c", NS)


def _cell_text(cell):
    t = cell.find("m:is/m:t", NS)
    return None if t is None else (t.text or "")


# --------------------------------------------------------------------------
# package structure
# --------------------------------------------------------------------------

def test_required_parts_present_and_pk_magic():
    blob = xlsx_writer.write_sheet([["a", "b"], [1, 2]])
    assert blob[:2] == b"PK"
    with _zf(blob) as zf:
        names = set(zf.namelist())
        assert zf.testzip() is None
    for required in (
        "[Content_Types].xml",
        "_rels/.rels",
        "xl/workbook.xml",
        "xl/_rels/workbook.xml.rels",
        "xl/styles.xml",
        "xl/worksheets/sheet1.xml",
    ):
        assert required in names, f"missing part {required}"


def test_all_parts_are_wellformed_xml_and_deflated():
    blob = xlsx_writer.write_sheet([["h"], ["v"]])
    with _zf(blob) as zf:
        for info in zf.infolist():
            ET.fromstring(zf.read(info.filename))  # raises if malformed
            assert info.compress_type == zipfile.ZIP_DEFLATED


def test_styles_has_at_least_two_cellxfs_and_header_uses_style_1():
    blob = xlsx_writer.write_sheet([["head"], ["body"]])
    styles = ET.fromstring(_part(blob, "xl/styles.xml"))
    xfs = styles.findall("m:cellXfs/m:xf", NS)
    assert len(xfs) >= 2
    rows = _rows(blob)
    assert _cells(rows[0])[0].get("s") == "1"          # header bold
    assert _cells(rows[1])[0].get("s") in (None, "0")   # body normal


def test_header_pane_is_frozen():
    blob = xlsx_writer.write_sheet([["head"], ["body"]])
    pane = _sheet_root(blob).find(".//m:sheetViews/m:sheetView/m:pane", NS)
    assert pane is not None
    assert pane.get("state") == "frozen"
    assert pane.get("ySplit") == "1"


# --------------------------------------------------------------------------
# col_letter
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "index,expected",
    [
        (0, "A"),
        (25, "Z"),
        (26, "AA"),
        (27, "AB"),
        (51, "AZ"),
        (52, "BA"),
        (701, "ZZ"),
        (702, "AAA"),
    ],
)
def test_col_letter_boundaries(index, expected):
    assert xlsx_writer.col_letter(index) == expected


def test_col_letter_rejects_negative():
    with pytest.raises(ValueError):
        xlsx_writer.col_letter(-1)


def test_cell_refs_follow_col_letter():
    blob = xlsx_writer.write_sheet([["x"] * 28])
    refs = [c.get("r") for c in _cells(_rows(blob)[0])]
    assert refs[0] == "A1"
    assert refs[25] == "Z1"
    assert refs[26] == "AA1"
    assert refs[27] == "AB1"


# --------------------------------------------------------------------------
# escaping / illegal chars
# --------------------------------------------------------------------------

def test_xml_special_chars_roundtrip_exactly():
    original = "R&D <tag> \"quoted\" 'single' & more"
    blob = xlsx_writer.write_sheet([["h"], [original]])
    got = _cell_text(_cells(_rows(blob)[1])[0])
    assert got == original


def test_ampersand_is_escaped_in_the_raw_part():
    blob = xlsx_writer.write_sheet([["a&b"]])
    raw = _part(blob, "xl/worksheets/sheet1.xml").decode("utf-8")
    assert "a&amp;b" in raw
    assert "a&b" not in raw


def test_control_chars_produce_a_parseable_document():
    """The load-bearing one: a device banner with 0x00/0x1F must not poison
    the file. Excel's error for an illegal char is 'unreadable content' with no
    cell reference, so this has to be caught here."""
    dirty = "ban\x00ner\x1fend\x08!"
    blob = xlsx_writer.write_sheet([["h"], [dirty]])
    root = _sheet_root(blob)  # ET.fromstring raises on illegal chars
    text = _cell_text(_cells(root.findall(".//m:sheetData/m:row", NS)[1])[0])
    assert text == "bannerend!"
    assert "\x00" not in text and "\x1f" not in text
    # tab/newline/CR are legal XML and must survive the strip
    blob2 = xlsx_writer.write_sheet([["h"], ["a\tb\nc"]])
    ET.fromstring(_part(blob2, "xl/worksheets/sheet1.xml"))


def test_illegal_chars_never_reach_the_bytes():
    blob = xlsx_writer.write_sheet([["\x00\x01\x02x"]])
    raw = _part(blob, "xl/worksheets/sheet1.xml")
    assert b"\x00" not in raw and b"\x01" not in raw and b"\x02" not in raw


# --------------------------------------------------------------------------
# empty values
# --------------------------------------------------------------------------

def test_none_and_empty_string_emit_empty_cells_not_the_word_none():
    blob = xlsx_writer.write_sheet([["h1", "h2", "h3"], [None, "", "ok"]])
    row = _rows(blob)[1]
    cells = _cells(row)
    assert list(cells[0]) == []          # no <is>/<v> child
    assert list(cells[1]) == []
    assert _cell_text(cells[2]) == "ok"
    raw = _part(blob, "xl/worksheets/sheet1.xml").decode("utf-8")
    assert "None" not in raw


# --------------------------------------------------------------------------
# typing
# --------------------------------------------------------------------------

def test_number_bool_and_string_typing():
    blob = xlsx_writer.write_sheet(
        [["i", "f", "b", "b2", "s"], [42, 3.5, True, False, "42"]]
    )
    cells = _cells(_rows(blob)[1])
    assert cells[0].get("t") == "n"
    assert cells[0].find("m:v", NS).text == "42"
    assert cells[1].get("t") == "n"
    assert float(cells[1].find("m:v", NS).text) == 3.5
    assert cells[2].get("t") == "b" and cells[2].find("m:v", NS).text == "1"
    assert cells[3].get("t") == "b" and cells[3].find("m:v", NS).text == "0"
    assert cells[4].get("t") == "inlineStr" and _cell_text(cells[4]) == "42"


def test_float_repr_roundtrips():
    value = 0.1 + 0.2
    blob = xlsx_writer.write_sheet([["h"], [value]])
    text = _cells(_rows(blob)[1])[0].find("m:v", NS).text
    assert float(text) == value


def test_datetime_and_date_are_iso_strings_not_serials():
    dt = datetime.datetime(2026, 8, 9, 13, 45, 5)
    d = datetime.date(2026, 8, 9)
    blob = xlsx_writer.write_sheet([["dt", "d"], [dt, d]])
    cells = _cells(_rows(blob)[1])
    assert cells[0].get("t") == "inlineStr"
    assert _cell_text(cells[0]).startswith("2026-08-09")
    assert "13:45:05" in _cell_text(cells[0])
    assert cells[1].get("t") == "inlineStr"
    assert _cell_text(cells[1]) == "2026-08-09"


# --------------------------------------------------------------------------
# sheet names
# --------------------------------------------------------------------------

def test_sheet_name_sanitized_and_truncated():
    raw_name = "Fortiweb/Attack:Log*Report?Very[Long]Name-2026"
    assert len(raw_name) > 31
    blob = xlsx_writer.write_sheet([["h"]], sheet_name=raw_name)
    wb = ET.fromstring(_part(blob, "xl/workbook.xml"))
    name = wb.find(".//m:sheets/m:sheet", NS).get("name")
    assert len(name) <= 31
    for bad in "[]:*?/\\":
        assert bad not in name
    assert name.startswith("Fortiweb_Attack_Log_Report")


def test_empty_sheet_name_falls_back():
    blob = xlsx_writer.write_sheet([["h"]], sheet_name="///")
    # "///" sanitizes to "___" which is legal; a truly empty one must fall back
    blob2 = xlsx_writer.write_sheet([["h"]], sheet_name="   ")
    wb = ET.fromstring(_part(blob2, "xl/workbook.xml"))
    assert wb.find(".//m:sheets/m:sheet", NS).get("name") == "Sheet1"
    assert blob  # first call must not blow up either


def test_write_book_dedupes_identical_sheet_names():
    blob = xlsx_writer.write_book(
        [("Report", [["a"]]), ("Report", [["b"]]), ("Report", [["c"]])]
    )
    wb = ET.fromstring(_part(blob, "xl/workbook.xml"))
    names = [s.get("name") for s in wb.findall(".//m:sheets/m:sheet", NS)]
    assert len(names) == 3
    assert len(set(names)) == 3, f"duplicate sheet names: {names}"
    assert names[0] == "Report"


def test_write_book_dedupe_stays_within_31_chars():
    long_name = "A" * 31
    blob = xlsx_writer.write_book([(long_name, [["x"]]), (long_name, [["y"]])])
    wb = ET.fromstring(_part(blob, "xl/workbook.xml"))
    names = [s.get("name") for s in wb.findall(".//m:sheets/m:sheet", NS)]
    assert len(set(names)) == 2
    assert all(len(n) <= 31 for n in names)


def test_write_book_parts_and_rels_match_sheet_count():
    blob = xlsx_writer.write_book([("One", [["a"]]), ("Two", [["b"]])])
    with _zf(blob) as zf:
        names = set(zf.namelist())
    assert "xl/worksheets/sheet1.xml" in names
    assert "xl/worksheets/sheet2.xml" in names
    rels = ET.fromstring(_part(blob, "xl/_rels/workbook.xml.rels"))
    targets = [r.get("Target") for r in rels]
    assert "worksheets/sheet1.xml" in targets
    assert "worksheets/sheet2.xml" in targets
    assert "styles.xml" in targets
    assert _cell_text(_cells(_rows(blob, 2)[0])[0]) == "b"


# --------------------------------------------------------------------------
# ragged rows / limits / determinism
# --------------------------------------------------------------------------

def test_ragged_rows_produce_correct_per_row_cell_counts():
    data = [["a", "b", "c"], ["only-one"], [], [1, 2, 3, 4, 5]]
    blob = xlsx_writer.write_sheet(data)
    rows = _rows(blob)
    assert len(rows) == 4
    assert [len(_cells(r)) for r in rows] == [3, 1, 0, 5]


def test_generator_rows_are_accepted():
    blob = xlsx_writer.write_sheet([str(i)] for i in range(3))
    assert len(_rows(blob)) == 3
    assert _cell_text(_cells(_rows(blob)[2])[0]) == "2"


def test_max_rows_exceeded_raises_valueerror_naming_the_count():
    too_many = [["x"]] * (xlsx_writer.MAX_ROWS + 1)
    with pytest.raises(ValueError) as exc:
        xlsx_writer.write_sheet(too_many)
    assert str(xlsx_writer.MAX_ROWS + 1) in str(exc.value)


def test_max_rows_exactly_at_cap_is_allowed():
    ok = [["x"]] * xlsx_writer.MAX_ROWS
    blob = xlsx_writer.write_sheet(ok)
    assert blob[:2] == b"PK"


def test_output_is_deterministic():
    data = [["h1", "h2"], ["a&b", 1], [datetime.date(2026, 1, 1), None]]
    first = xlsx_writer.write_sheet(data, sheet_name="Same")
    second = xlsx_writer.write_sheet(data, sheet_name="Same")
    assert first == second
    with _zf(first) as zf:
        assert all(i.date_time == zf.infolist()[0].date_time for i in zf.infolist())


def test_empty_input_still_produces_a_valid_workbook():
    blob = xlsx_writer.write_sheet([])
    assert blob[:2] == b"PK"
    assert _rows(blob) == []
    blob2 = xlsx_writer.write_book([])
    wb = ET.fromstring(_part(blob2, "xl/workbook.xml"))
    assert len(wb.findall(".//m:sheets/m:sheet", NS)) == 1
