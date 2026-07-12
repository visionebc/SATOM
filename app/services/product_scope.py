"""Product (ADOM) scoping — the ONE place that decides which product a new
record is stamped with and which records the active session may see.

Sessions carry ``session['product']`` in {'global', 'fortiweb', 'fortiadc'}
(set by ``views.product`` / the app-factory product gate). Visibility rule:

* ``fortiadc``  -> sees only records stamped ``'fortiadc'``.
* ``fortiweb``  -> sees everything EXCEPT ``'fortiadc'`` (legacy/unscoped rows
  predate stamping and are FortiWeb-era by construction).
* ``global`` / no request context (background workers) -> sees everything.

Stamping mirrors it: a record created inside a concrete ADOM carries that
product; anything created from the global ADOM or a worker thread stays ''
(unscoped). Callers may always pass an explicit product to override.
"""
from __future__ import annotations

from flask import has_request_context, session

FORTIWEB = "fortiweb"
FORTIADC = "fortiadc"
FORTIANALYZER = "fortianalyzer"
GLOBAL = "global"


def session_product() -> str:
    """The EFFECTIVE product of the active request, '' outside a request
    context. Per-tab ADOM (2026-07-07): resolution order is ``g.product``
    (stamped by the app-factory product gate: URL scope > X-ADOM header >
    session) > the raw ``X-ADOM`` header (a caller running before/without
    the gate) > the session cookie. The session is only the default for
    header-less requests — one browser tab switching ADOM no longer changes
    what another tab sees."""
    try:
        if has_request_context():
            from flask import g, request
            p = getattr(g, "product", None)
            if p in (GLOBAL, FORTIWEB, FORTIADC, FORTIANALYZER):
                return p
            h = (request.headers.get("X-ADOM") or "").strip().lower()
            if h in (GLOBAL, FORTIWEB, FORTIADC, FORTIANALYZER):
                return h
            return session.get("product") or ""
    except Exception:  # noqa: BLE001 — scoping must never break a caller
        pass
    return ""


def stamp() -> str:
    """Value to store on a record created now ('' = unscoped)."""
    p = session_product()
    return p if p in (FORTIWEB, FORTIADC, FORTIANALYZER) else ""


def visible_product(record_product: str | None) -> bool:
    """Pure visibility check for file/JSON-backed records (the job store)."""
    p = session_product()
    rp = (record_product or "").strip()
    if p == FORTIADC:
        return rp == FORTIADC
    if p == FORTIANALYZER:
        return rp == FORTIANALYZER
    if p == FORTIWEB:
        return rp not in (FORTIADC, FORTIANALYZER)
    return True


def scope_query(query, column):
    """Apply the same rule to a SQLAlchemy query. ``column`` is the model's
    ``product`` column; NULL/'' rows count as unscoped (visible to FortiWeb
    and Global, hidden from the ADC ADOM)."""
    p = session_product()
    if p == FORTIADC:
        return query.filter(column == FORTIADC)
    if p == FORTIANALYZER:
        return query.filter(column == FORTIANALYZER)
    if p == FORTIWEB:
        from sqlalchemy import and_, or_
        return query.filter(or_(
            column.is_(None),
            and_(column != FORTIADC, column != FORTIANALYZER),
        ))
    return query


def scope_appliance_query(query, kind_column):
    """Scope an Appliance query by device KIND: the ADC ADOM sees only
    ``kind == 'fortiadc'``, the FAZ ADOM only ``kind == 'fortianalyzer'``,
    the FortiWeb ADOM everything else (NULL/'' kinds are FortiWeb-era by
    construction) EXCEPT the ADC/FAZ boxes, Global/workers see all."""
    p = session_product()
    if p == FORTIADC:
        return query.filter(kind_column == FORTIADC)
    if p == FORTIANALYZER:
        return query.filter(kind_column == FORTIANALYZER)
    if p == FORTIWEB:
        from sqlalchemy import and_, or_
        return query.filter(or_(
            kind_column.is_(None),
            and_(kind_column != FORTIADC, kind_column != FORTIANALYZER),
        ))
    return query
