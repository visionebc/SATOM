"""The ONE parser of the network-segments form.

Two pages post this form -- the Administrator ``/segments`` page and the
legacy Settings console tab -- and until now each had its own copy of the
loop. Two authors of one parse is how the ``department`` column ended up
being read positionally on one page and not the other; it is also the shape
§132 was written about. Both views call :func:`parse_rows`.

**Why the row loop is positional.** Every column posts as ``seg_<field>[]``
and rows are matched by index, so a field that posts a VARIABLE number of
values per row (a ``<select multiple>``) would silently shift every column
after it. Departments therefore travel as ONE encoded string per row, and so
do a segment's networks (``seg_networks[]``, a JSON list of
``{cidr, gateway, interface}``) -- a segment holds as many as it needs, and
each network names its own interface (FA-0010).
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


def parse_networks(raw: str, legacy_cidr: str = "", legacy_gateway: str = "",
                   interface: str = "") -> list[dict]:
    """Decode one row's networks field.

    A JSON list is what the page posts. No field at all (a stale cached copy
    of the page, a hand-built POST) falls back to the single ``seg_cidr[]`` /
    ``seg_gateway[]`` columns -- the shape every page before FA-0002 sent.
    *interface* fills a network posted without one (see
    ``settings_store.normalize_networks``).
    """
    raw = (raw or "").strip()
    if raw.startswith("["):
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            data = None
        if isinstance(data, list):
            return store.normalize_networks({"networks": data, "interface": interface})
    return store.normalize_networks({"cidr": legacy_cidr, "gateway": legacy_gateway,
                                     "interface": interface})


def parse_rows(form) -> tuple[list[dict], list[str]]:
    """``(rows, bad_cidrs)`` from a posted segments form. Writes nothing.

    An invalid CIDR drops THAT network, not the whole segment: dropping the
    row would delete the segment (and orphan every line profile naming it)
    because one of its networks had a typo."""
    names = form.getlist("seg_name[]")
    rows: list[dict] = []
    bad_cidr: list[str] = []
    for i, name in enumerate(names):
        def col(field: str) -> str:
            vals = form.getlist(f"seg_{field}[]")
            return vals[i] if i < len(vals) else ""

        # The page no longer posts a segment interface (FA-0010): each network
        # carries its own. ``seg_interface[]`` is what a stale cached page or
        # a hand-built POST still sends; it fills the networks that name none,
        # exactly as it did when the page had that column. "port1" is the
        # default that column always had.
        interface = col("interface").strip() or "port1"
        nets = parse_networks(col("networks"), col("cidr"), col("gateway"), interface)
        if not (name or "").strip() and not nets:
            continue
        good = []
        for net in nets:
            if net["cidr"]:
                try:
                    # Validated, stored as typed: the string is the IPAM
                    # pool query, and rewriting it would change what a
                    # backend's scope matches.
                    ipaddress.ip_network(net["cidr"], strict=False)
                except ValueError:
                    bad_cidr.append(net["cidr"])
                    continue
            good.append(net)
        nets = good
        # 'departments' is the current field; 'department' is what a stale
        # cached copy of the page still posts. Neither is preferred over a
        # non-empty other -- the new one wins only when it carries something.
        depts = parse_departments(col("departments"))
        if not depts:
            depts = parse_departments(col("department"))
        rows.append({
            "name": name, "zone": col("zone"), "line": col("line"),
            "departments": depts, "networks": nets,
            "interface": interface,
            "note": col("note"),
        })
    return rows, bad_cidr
