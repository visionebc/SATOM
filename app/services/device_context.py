"""Selected-device session context (device-first navigation).

After a user picks a product they land on the Architecture map and choose ONE
device; that choice is stored in the session and becomes the implicit context
for every per-device page (Server Policy, Server Objects, Web Protection,
Exceptions, Backups, Analysis, FortiWeb Configuration). The banner Architecture
icon re-opens the map to switch device.

Nothing here writes secrets; only the appliance id lives in the session.
"""
from __future__ import annotations

from flask import g, session

from ..models import Appliance

SESSION_KEY = "appliance_id"
_G_CACHE = "_current_appliance"


def current_appliance() -> Appliance | None:
    """The Appliance selected for this session, or None. Cached on g so
    repeated calls within one request hit the DB once."""
    if _G_CACHE in g.__dict__:
        return g.__dict__[_G_CACHE]
    aid = session.get(SESSION_KEY)
    appl = Appliance.query.get(int(aid)) if aid else None
    if appl is None and aid:
        # stale id (device deleted) — forget it
        session.pop(SESSION_KEY, None)
    g.__dict__[_G_CACHE] = appl
    return appl


def set_current(appliance_id: int) -> None:
    session[SESSION_KEY] = int(appliance_id)
    g.__dict__.pop(_G_CACHE, None)


def clear_current() -> None:
    session.pop(SESSION_KEY, None)
    g.__dict__.pop(_G_CACHE, None)
