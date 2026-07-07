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
_G_CACHE = "_current_appliance"


def _is_adc(appl: Appliance) -> bool:
    return (appl.kind or "fortiweb") == "fortiadc"


def _active_key() -> str:
    """The slot the active session product reads (global reads FortiWeb's)."""
    from .product_scope import session_product, FORTIADC
    return SESSION_KEY_ADC if session_product() == FORTIADC else SESSION_KEY


def _key_for(appl: Appliance) -> str:
    return SESSION_KEY_ADC if _is_adc(appl) else SESSION_KEY


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
