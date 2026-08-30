"""Selected-device session context (device-first navigation).

After a user picks a product they land on the Architecture map and choose ONE
device; that choice is stored in the session and becomes the implicit context
for every per-device page (Server Policy, Server Objects, Web Protection,
Exceptions, Backups, Analysis, FortiWeb Configuration). The banner Architecture
icon re-opens the map to switch device.

The selection is PER PRODUCT (ADOM): FortiWeb and FortiADC each keep their own
slot, so picking fadc in the ADC ADOM never leaks into the FortiWeb pages (the
"title says fadc while I'm in FortiWeb" bug). A device found sitting in the
wrong slot is moved to its own, not discarded.

Nothing here writes secrets; only the appliance id lives in the session.
"""
from __future__ import annotations

from flask import g, session

from ..models import Appliance

SESSION_KEY = "appliance_id"           # FortiWeb slot (legacy key, kept)
SESSION_KEY_ADC = "appliance_id_adc"   # FortiADC slot
SESSION_KEY_FAZ = "appliance_id_faz"   # FortiAnalyzer slot
_G_CACHE = "_current_appliance"

#: Slot names that predate the derivation below. Kept VERBATIM: a session
#: cookie written before 2026-08-30 still names these keys, and renaming them
#: would blank the device context of every console open at deploy time.
_LEGACY_SLOTS = {"fortiadc": SESSION_KEY_ADC, "fortianalyzer": SESSION_KEY_FAZ}

#: The slot of a request whose ADOM could not be determined. It is not a valid
#: session key, so the context resolves to None — fail closed, never onto
#: another ADOM's device.
_NO_SLOT = "\x00unresolved"


def _slot_for_product(product: str | None) -> str:
    """The session slot an ADOM keeps its device pick in — ONE PER ADOM.

    DERIVED from the ADOM registry (``product_scope.concrete_products()``),
    not typed out. Until 2026-08-30 this was a hardcoded if-chain holding
    THREE slots for FOUR device ADOMs: ``fortiauthenticator`` matched no
    branch and fell through to the FortiWeb slot. Both halves of that
    collision were silent and both were real —

    * picking a FortiWeb device overwrote the slot, so the FortiAuthenticator
      console's ENTIRE menu answered "No FortiAuthenticator is selected"
      while its own dashboard still described the live unit;
    * picking the FAC device made a FortiAuthenticator the FortiWeb ADOM's
      implicit context — ``/web/workspace/`` opened fac01's workspace.

    It is the failure :mod:`app.services.product_scope` documents for its key
    set, one module over: a new ADOM is a REGISTRY ROW, so the slot has to
    follow the row or the next ADOM lands in FortiWeb's slot too.
    """
    from .product_scope import (FORTIWEB, GLOBAL, UNRESOLVED,
                                concrete_products)
    p = (product or "").strip().lower()
    if p == UNRESOLVED:
        return _NO_SLOT
    # The legacy slot belongs to FortiWeb, to the Global console (which reads
    # FortiWeb's, as it always has) and to any kind no ADOM claims — the same
    # rule product_scope applies to the unscoped rows.
    if not p or p in (FORTIWEB, GLOBAL) or p not in concrete_products():
        return SESSION_KEY
    return _LEGACY_SLOTS.get(p, "appliance_id_" + p)


def _active_key() -> str:
    """The slot the active session product reads (global reads FortiWeb's)."""
    from .product_scope import session_product
    return _slot_for_product(session_product())


def _key_for(appl: Appliance) -> str:
    """The slot a DEVICE belongs in. Its ``kind`` IS an ADOM key."""
    return _slot_for_product(appl.kind or "fortiweb")


def _sole_device() -> "Appliance | None":
    """The ADOM's device when it has EXACTLY ONE and nothing is picked yet.

    An ADOM holding one appliance offers no choice to make. Until 2026-08-30
    only the FortiAnalyzer and FortiAuthenticator DASHBOARDS knew that, each
    through its own ``header_dev`` fallback; every other page in those ADOMs
    called :func:`current_appliance`, got None and rendered "no device
    selected". The result was a console whose front page reported a live
    unit's firmware, CPU and licence counters while its whole menu denied the
    unit existed — which is how "the FortiAuth menu does not work" was
    reported. ONE authority, so the answer cannot differ page to page.

    Read-only ON PURPOSE: it resolves the context, it does not write the
    session. A GET must not record a choice for the operator, and writing one
    would make the picker's Select button a no-op it could not undo.

    ``visible_appliances()`` is already scoped to the active ADOM's kind and
    already drops maintenance rows the user may not see, so "exactly one" is
    counted in the same terms the picker shows.
    """
    from .product_scope import concrete_products, session_product
    if session_product() not in concrete_products():
        return None            # Global / worker: "everything" is never "one"
    from ..models import visible_appliances
    rows = visible_appliances().limit(2).all()
    return rows[0] if len(rows) == 1 else None


def current_appliance() -> Appliance | None:
    """The Appliance selected for this session's active product, or None.
    Cached on g so repeated calls within one request hit the DB once."""
    if _G_CACHE in g.__dict__:
        return g.__dict__[_G_CACHE]
    key = _active_key()
    aid = session.get(key)
    appl = Appliance.query.get(int(aid)) if aid else None
    # Product gate: a device of the OTHER product must never be this ADOM's
    # implicit context. Re-home it to its own slot instead of dropping it.
    if appl is not None and _key_for(appl) != key:
        session[_key_for(appl)] = appl.id
        session.pop(key, None)
        appl = None
        aid = None
    # Maintenance-mode gate: a device the current user may not see must never
    # become the implicit per-device context (defense in depth behind the
    # pickers, which already exclude it). Treat it like a stale id.
    if appl is not None:
        from ..models import can_view_maintenance
        if appl.maintenance and not can_view_maintenance():
            appl = None
    if appl is None and aid:
        # stale id (device deleted) — forget it
        session.pop(key, None)
    if appl is None:
        appl = _sole_device()
    g.__dict__[_G_CACHE] = appl
    return appl


def set_current(appliance_id: int) -> None:
    """Remember the selection in the slot matching the DEVICE's kind (not the
    session product), so a pick made from the Global map lands correctly."""
    appl = Appliance.query.get(int(appliance_id))
    key = _key_for(appl) if appl is not None else _active_key()
    session[key] = int(appliance_id)
    g.__dict__.pop(_G_CACHE, None)


def clear_current() -> None:
    session.pop(_active_key(), None)
    g.__dict__.pop(_G_CACHE, None)
