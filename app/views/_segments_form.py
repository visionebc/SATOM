"""The ONE parser of the network-segments form.

Two pages post this form -- the Administrator ``/segments`` page and the
legacy Settings console tab -- and until now each had its own copy of the
loop. Two authors of one parse is how the ``department`` column ended up
being read positionally on one page and not the other; it is also the shape
§132 was written about. Both views call :func:`parse_rows`.

**Why the row loop is positional.** Every column posts as ``seg_<field>[]``
and rows are matched by index, so a field that posts a VARIABLE number of
values per row (a ``<select multiple>``) would silently shift every column
after it. Departments therefore travel as ONE encoded string per row.
"""
from __future__ import annotations

import ipaddress
import json

from ..services import settings_store as store


def parse_departments(raw: str) -> list[str]:
    """Decode one row's departments field.

    JSON list is what the page posts -- it survives a department whose name
    contains a comma. A bare string is what a hand-built POST, an older
    browser cache of the page, or the legacy single-value ``seg_department[]``
    field sends; ``normalize_departments`` splits that on commas. Both land in
    the same normaliser, so neither encoding can drift from the other.
    """
    raw = (raw or "").strip()
    if raw.startswith("["):
        try:
            return store.normalize_departments(json.loads(raw))
        except (ValueError, TypeError):
            pass          # a literal '[' typed by hand -- treat as plain text
    return store.normalize_departments(raw)


def parse_rows(form) -> tuple[list[dict], list[str]]:
    """``(rows, bad_cidrs)`` from a posted segments form. Writes nothing."""
    names = form.getlist("seg_name[]")
    rows: list[dict] = []
    bad_cidr: list[str] = []
    for i, name in enumerate(names):
        def col(field: str) -> str:
            vals = form.getlist(f"seg_{field}[]")
            return vals[i] if i < len(vals) else ""

        cidr = (col("cidr") or "").strip()
        if not (name or "").strip() and not cidr:
            continue
        if cidr:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                bad_cidr.append(cidr)
                continue
        # 'departments' is the current field; 'department' is what a stale
        # cached copy of the page still posts. Neither is preferred over a
        # non-empty other -- the new one wins only when it carries something.
        depts = parse_departments(col("departments"))
        if not depts:
            depts = parse_departments(col("department"))
        rows.append({
            "name": name, "zone": col("zone"), "line": col("line"),
            "departments": depts, "cidr": cidr,
            "interface": col("interface") or "port1",
            "gateway": col("gateway"), "note": col("note"),
        })
    return rows, bad_cidr
