"""Product (ADOM) scoping — the ONE place that decides which product a new
record is stamped with and which records the active session may see.

Sessions carry ``session['product']`` (set by ``views.product`` / the
app-factory product gate). Visibility rule, as of 2026-08-05:

* a CONCRETE ADOM sees only the rows stamped with ITS OWN key;
* ``fortiweb`` additionally sees the NULL/'' rows — it is the only product
  that predates stamping, so unscoped rows are FortiWeb-era by construction;
* ``global`` / no request context (background workers) sees everything.

Stamping mirrors it: a record created inside a concrete ADOM carries that
product; anything created from the global ADOM or a worker thread stays ''
(unscoped). Callers may always pass an explicit product to override.

**Why the rule is an INCLUSION and the key set is DERIVED.** Until 2026-08-05
the FortiWeb branch was written as an exclusion (``kind NOT IN (fortiadc,
fortianalyzer)``) and the recognised keys were a hardcoded tuple. Both are
bug generators, and adding FortiAuthenticator fired both at once:

* the exclusion list never learned the new key, so ``fac01`` showed up in the
  FortiWeb ADOM;
* the hardcoded tuple did not contain ``'fortiauthenticator'``, so
  :func:`session_product` returned '' inside the FAC ADOM and every filter
  below became a no-op — that ADOM saw EVERY product's rows.

Neither failure raises. A new ADOM is a row in the registry, so the key set is
read from the registry (:func:`app.branding.all_adoms`, inactive rows
included) and each filter names the product it keeps. A product declared
tomorrow is scoped the day it is declared.
"""
from __future__ import annotations

from flask import has_request_context, session

FORTIWEB = "fortiweb"
FORTIADC = "fortiadc"
FORTIANALYZER = "fortianalyzer"
FORTIAUTHENTICATOR = "fortiauthenticator"
GLOBAL = "global"

# The one product that also owns the unscoped rows (see module docstring).
LEGACY_PRODUCT = FORTIWEB

# Offline fallback only — used when the ADOM registry cannot be read (CLI
# import outside an app context, pre-migration boot). Never the primary source.
_FALLBACK_KEYS = frozenset(
    {GLOBAL, FORTIWEB, FORTIADC, FORTIANALYZER, FORTIAUTHENTICATOR})


def product_keys() -> frozenset[str]:
    """Every ADOM key this installation has, ``global`` included.

    Read from the registry rather than declared here. INACTIVE rows count:
    deactivating an ADOM must not make its key unrecognised, because an
    unrecognised key does not fail closed — it falls through every filter
    below and shows that session everything."""
    try:
        from ..branding import all_adoms
        keys = {str(r.get("key") or "").strip().lower() for r in all_adoms()}
        keys.discard("")
        if keys:
            return frozenset(keys | {GLOBAL})
    except Exception:  # noqa: BLE001 — scoping must never break a caller
        pass
    return _FALLBACK_KEYS


def concrete_products() -> frozenset[str]:
    """The product ADOMs — every key except ``global``. A session in one of
    these is filtered; anything else (``global``, '', a worker thread) is not."""
    return product_keys() - {GLOBAL}


def session_product() -> str:
    """The EFFECTIVE product of the active request, '' outside a request
    context. Per-tab ADOM (2026-07-07): resolution order is ``g.product``
    (stamped by the app-factory product gate: URL scope > X-ADOM header >
    session) > the raw ``X-ADOM`` header (a caller running before/without
    the gate) > the session cookie. The session is only the default for
    header-less requests — one browser tab switching ADOM no longer changes
    what another tab sees.

    Every source is validated against :func:`product_keys`. The session cookie
    used to be returned unchecked, which is how a key the filters below did not
    recognise reached them."""
    try:
        if has_request_context():
            from flask import g, request
            valid = product_keys()
            p = getattr(g, "product", None)
            if p in valid:
                return p
            h = (request.headers.get("X-ADOM") or "").strip().lower()
            if h in valid:
                return h
            s = (session.get("product") or "").strip().lower()
            return s if s in valid else ""
    except Exception:  # noqa: BLE001 — scoping must never break a caller
        pass
    return ""


def stamp() -> str:
    """Value to store on a record created now ('' = unscoped)."""
    p = session_product()
    return p if p in concrete_products() else ""


def visible_product(record_product: str | None) -> bool:
    """Pure visibility check for file/JSON-backed records (the job store)."""
    p = session_product()
    if p not in concrete_products():
        return True
    rp = (record_product or "").strip().lower()
    if not rp:
        return p == LEGACY_PRODUCT
    return rp == p


def scope_query(query, column):
    """Apply the same rule to a SQLAlchemy query. ``column`` is the model's
    ``product`` column; NULL/'' rows count as unscoped (visible to FortiWeb
    and Global, hidden from every other ADOM)."""
    p = session_product()
    if p not in concrete_products():
        return query
    if p == LEGACY_PRODUCT:
        from sqlalchemy import or_
        return query.filter(or_(
            column.is_(None), column == "", column == p))
    return query.filter(column == p)


# ── device kinds (the appliance roster an ADOM may show / create) ───────────
# An appliance's ``kind`` IS an ADOM key, so the roster of kinds is the roster
# of product ADOMs. Deriving it here is the same rule the module docstring
# already argues for the key set: a hardcoded list in a form is how
# FortiAuthenticator ended up unofferable in "New appliance" for a day after it
# became a real product, with nothing raising — the option was simply absent.
_FALLBACK_DEVICE_PRODUCTS = (
    (FORTIWEB, "FortiWeb"),
    (FORTIADC, "FortiADC"),
    (FORTIAUTHENTICATOR, "FortiAuthenticator"),
    (FORTIANALYZER, "FortiAnalyzer"),
)


def device_products() -> tuple[tuple[str, str], ...]:
    """``((key, display name), ...)`` for every ACTIVE product ADOM, in
    registry order. ``global`` is excluded: it is a console, not a device."""
    try:
        from ..branding import all_adoms
        out = []
        for row in all_adoms():
            key = str(row.get("key") or "").strip().lower()
            if not key or key == GLOBAL or not row.get("active", True):
                continue
            out.append((key, str(row.get("name") or key)))
        if out:
            return tuple(out)
    except Exception:  # noqa: BLE001 — scoping must never break a caller
        pass
    return _FALLBACK_DEVICE_PRODUCTS


def creatable_kinds() -> tuple[tuple[str, str], ...]:
    """The kinds the ACTIVE session may put on an appliance.

    A concrete ADOM gets exactly ONE: its own. Offering the others there
    creates a device the creating session cannot see the moment it is saved —
    the row lands in a different ADOM and the operator reads it as a failed
    save. Global, which sees everything, gets the full roster."""
    everything = device_products()
    p = session_product()
    if p not in concrete_products():
        return everything
    mine = tuple(t for t in everything if t[0] == p)
    # An ADOM deactivated mid-session still has to be able to name itself,
    # or its console would render a form with no platform to choose.
    return mine or ((p, p),)


def may_assign_kind(kind: str | None) -> bool:
    """Server side of :func:`creatable_kinds`. The form is a hint; this is the
    rule. Without it, a posted ``kind`` field is a one-field ADOM jump."""
    k = (kind or "").strip().lower()
    return bool(k) and k in {key for key, _ in creatable_kinds()}


def scope_appliance_query(query, kind_column):
    """Scope an Appliance query by device KIND: a concrete ADOM sees only the
    boxes of its own product; the FortiWeb ADOM also sees NULL/'' kinds
    (FortiWeb-era by construction); Global/workers see all.

    A device whose ``kind`` matches no registered ADOM is therefore visible in
    the Global ADOM only. That is deliberate — no product console can manage
    it — and Global is where it stays discoverable."""
    p = session_product()
    if p not in concrete_products():
        return query
    if p == LEGACY_PRODUCT:
        from sqlalchemy import or_
        return query.filter(or_(
            kind_column.is_(None), kind_column == "", kind_column == p))
    return query.filter(kind_column == p)
