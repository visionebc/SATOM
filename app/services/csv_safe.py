"""CSV cells that a spreadsheet opens as text, never as a formula.

A CSV export is opened in Excel / LibreOffice / Sheets, which evaluate any cell
starting with ``=``, ``+``, ``-`` or ``@`` (and, in some versions, a leading tab
or carriage return) as a formula. Exports here carry text that operators,
devices or an unauthenticated login attempt typed (audit targets, usernames,
device object names), so such a cell is prefixed with ``'`` — the spreadsheet
convention for "this is text" (OWASP: CSV injection).
"""
from __future__ import annotations

_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")


def spreadsheet_safe(value) -> str:
    """``value`` as a CSV cell a spreadsheet will not evaluate.

    A plain number (``-5``, ``+1.5e3``) is left alone: it cannot be a formula,
    and quoting it would turn a numeric column of a query export into text.
    """
    text = "" if value is None else str(value)
    if not text.startswith(_FORMULA_LEAD):
        return text
    if text[0] in "+-":
        try:
            float(text)
            return text
        except ValueError:
            pass
    return "'" + text
