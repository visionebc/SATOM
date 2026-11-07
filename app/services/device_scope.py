"""Device scope of a profile -- WHERE inside its ADOMs (2026-11-07).

A profile says WHAT (``permissions``) and in which ADOMs (``adoms``). The
device scope narrows the ADOMs to some devices and, inside a device, to some
partitions: ADOMs of a FortiWeb / FortiADC, VDOMs of a FortiGate (one
``Appliance`` row per partition, column ``vdom``). The permissions are the
same on every device of the scope: there are no per-device permissions.

Stored on the profile as ``{adom: {entry: null | [partition, ...]}}``
(``Profile.device_scope_map``):

* an ADOM absent from the map keeps every device it has;
* an entry is a CHASSIS -- :func:`entry_key`, the derived
  ``kind|host|port`` of :func:`app.models.chassis_key` (two rows that dial the
  same address are the same box), or ``id:<n>`` for a row with no chassis (an
  HA cluster container);
* ``null`` = every partition of that chassis, also the ones registered later;
  a list = only those, and then the actions that act on the WHOLE box
  (firmware, the backup vault, the console: ``require_device_scope``) are
  refused, because they would reach the partitions the profile does not.

Enforced in ONE place: :func:`app.services.product_scope.allowed_appliance_ids`
(used by the list query, the by-id loader and the multi-device records). It
only ever narrows: an entry of an ADOM the profile does not have is ignored.
"""
from __future__ import annotations

PART_SEP = "#"


def entry_key(appl) -> str:
    """The scope entry an appliance row belongs to."""
    from ..models import chassis_key
    k = chassis_key(appl)
    return k if k else "id:%s" % getattr(appl, "id", "")


def kind_of(appl) -> str:
    from .product_scope import LEGACY_PRODUCT
    return (getattr(appl, "kind", "") or "").strip().lower() or LEGACY_PRODUCT


def partition_of(appl) -> str:
    return (getattr(appl, "vdom", "") or "").strip().lower()


def reaches(appl, adoms, scope) -> bool:
    """Does a profile with ``adoms`` (None = all) and ``scope`` (None = no
    scope) reach this row? The single rule; everything else calls it."""
    k = kind_of(appl)
    if adoms is not None and k not in adoms:
        return False
    if scope is None:
        return True
    entries = scope.get(k, scope.get("*"))
    if entries is None:
        return True                                   # this ADOM is not scoped
    parts = entries.get(entry_key(appl), False)
    if parts is False:
        return False                                  # chassis not in the scope
    return parts is None or partition_of(appl) in parts


def partial(appl, scope) -> bool:
    """True when ``scope`` reaches only SOME partitions of this row's chassis
    (an explicit list): the box-wide actions must be refused."""
    if scope is None:
        return False
    entries = scope.get(kind_of(appl), scope.get("*"))
    if entries is None:
        return False
    parts = entries.get(entry_key(appl), False)
    return parts is not None          # False (not reached) or a list = partial


def choices(adom_keys) -> list[dict]:
    """The Profiles form: per device ADOM, its chassis and their partitions,
    from the whole inventory (an administrator composes a profile, not a view
    of their own session). Linux servers are added by services.wsm."""
    from ..models import Appliance
    from . import wsm
    out = []
    rows = Appliance.query.order_by(Appliance.name).all()
    wsm_adoms = wsm.module_adoms()
    for key, name in adom_keys:
        if key in wsm_adoms:
            # The Web Server Manager's ADOM: its servers, each site a partition
            # (the sites the server last listed; open its Domains & VHosts
            # page to refresh them).
            items = [{"key": wsm.SCOPE_ENTRY + c.slug, "label": c.name, "host": c.host or "",
                      "parts": sorted(wsm.known_sites(c.slug))}
                     for c in sorted(wsm.servers(), key=lambda c: (c.name or "").lower())]
            out.append({"adom": key, "name": name, "entries": items, "servers": True})
            continue
        groups = {}
        for a in rows:
            if kind_of(a) != key:
                continue
            ek = entry_key(a)
            g = groups.setdefault(ek, {"key": ek, "names": [], "host": a.host or "",
                                       "parts": []})
            g["names"].append(a.name)
            p = partition_of(a)
            if p and p not in g["parts"]:
                g["parts"].append(p)
        items = []
        for g in groups.values():
            g["label"] = " / ".join(sorted(g["names"]))
            g["parts"] = sorted(g["parts"])
            items.append(g)
        items.sort(key=lambda g: g["label"].lower())
        out.append({"adom": key, "name": name, "entries": items})
    return out


def from_form(form, adom_keys, adoms) -> dict:
    """``{adom: {entry: None | [parts]}}`` from the ticked boxes: ``dev_<adom>``
    = entry keys, ``part_<adom>`` = ``entry#partition``. An ADOM with no
    device ticked is not scoped; a device with no partition ticked = all of
    its partitions. ADOMs the profile does not have are dropped (the scope
    never widens what the ADOMs give)."""
    known = {k for k, _ in adom_keys}
    out = {}
    for adom in sorted(known):
        if adoms is not None and adom not in adoms:
            continue
        devs = [d.strip() for d in form.getlist("dev_" + adom) if d.strip()]
        if not devs:
            continue
        parts = {}
        for raw in form.getlist("part_" + adom):
            ek, sep, p = raw.rpartition(PART_SEP)
            if sep and ek in devs and p.strip():
                parts.setdefault(ek, set()).add(p.strip().lower())
        out[adom] = {d: (sorted(parts[d]) if d in parts else None) for d in devs}
    return out


def describe(scope) -> str:
    """For the audit line."""
    if scope is None:
        return "all"
    return "; ".join("%s: %s" % (adom, ", ".join(
        "%s%s" % (k, "" if v is None else "[%s]" % ",".join(sorted(v)))
        for k, v in sorted(entries.items())) or "nothing")
        for adom, entries in sorted(scope.items()))


def bell_gate(user_id: int, link: str) -> bool:
    """Notification gate (services.notifications.GATES): a notice whose link
    names ``/appliances/<id>`` is shown only to a user who reaches that device.
    A link without an id is shown."""
    import re
    from ..extensions import db
    from ..models import User
    from .product_scope import adoms_of, device_scope_of, reachable_appliance_ids
    m = re.search(r"/appliances/(\d+)", link or "")
    if not m:
        return True
    user = db.session.get(User, int(user_id))
    if user is None:
        return False
    ids = reachable_appliance_ids(adoms_of(user), device_scope_of(user))
    return ids is None or int(m.group(1)) in ids
