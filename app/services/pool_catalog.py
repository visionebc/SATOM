"""Server pools that already exist, across every appliance the ADOM may see.

The wizard's "use an existing server pool" control has to answer two different
questions, and confusing them is the whole risk:

* **Can this policy BIND it?** Only if the pool lives on the SAME appliance. A
  FortiWeb server pool is a per-device object; a policy cannot reference one
  that lives on another box. Offering a foreign pool as bindable is how an
  operator presses Apply and gets a server policy pointing at nothing.
* **What are its MEMBERS?** Useful from any appliance — that is the point of
  searching the fleet. You copy the member list, not the object.

So every row carries ``local``. The page uses it to choose between "bind this
pool" and "copy these members into a new pool here", and
``services.spo_wizard`` refuses to bind anything that is not local.

Rows come from the DEVICE CACHE and never from a box call: this list backs a
search box, and a dropdown that opens an SSL session per appliance per
keystroke is a page nobody can leave open.
"""
from __future__ import annotations

#: Standalone pools, whether or not a policy uses them.
POOL_LOGICAL = "server_pool"
#: Pools reached THROUGH a policy — the only ones whose ``pserver-list``
#: children are captured, and therefore the only ones we can name members for.
BOUND_POOL_LOGICAL = "server_policy/server_pool"

#: Capture layers, best first. ``deep`` is a fuller sweep than ``config``;
#: when both hold the same pool the deeper one wins. Reading the two as one
#: undifferentiated bag lets a stale ``config`` member list beat a fresh
#: ``deep`` one at random, which is worse than either.
LAYERS = ("deep", "config")


def _rank(layer: str) -> int:
    try:
        return LAYERS.index(layer or "")
    except ValueError:
        return len(LAYERS)


def _members_by_pool(appliance_id: int) -> dict[str, list[dict]]:
    """``{pool name: [{ip, port}]}`` for the pools this device has cached.

    Only pools bound to a policy appear — those are the only ones whose
    members were captured. A pool missing from this map is NOT an empty pool,
    and the caller must not render it as one.
    """
    from ..extensions import db
    from ..models_cache import DeviceObject

    parents = (db.session.query(DeviceObject)
               .filter_by(appliance_id=appliance_id,
                          logical_name=BOUND_POOL_LOGICAL).all())
    by_id = {p.id: p for p in parents if p.mkey}
    if not by_id:
        return {}
    kids = (db.session.query(DeviceObject)
            .filter(DeviceObject.appliance_id == appliance_id,
                    DeviceObject.parent_id.in_(list(by_id))).all())

    per: dict[tuple[str, str], list[dict]] = {}
    for k in kids:
        parent = by_id.get(k.parent_id)
        if parent is None:
            continue
        payload = k.payload or {}
        ip = str(payload.get("ip") or "").strip()
        if not ip:
            continue
        per.setdefault((parent.mkey, parent.layer or ""), []).append(
            {"ip": ip, "port": str(payload.get("port") or "80")})

    best: dict[str, tuple[int, list[dict]]] = {}
    for (name, layer), members in per.items():
        rank = _rank(layer)
        cur = best.get(name)
        if cur is None or rank < cur[0]:
            best[name] = (rank, members)
    return {name: members for name, (_r, members) in best.items()}


def pools_for(appliance, *, local_appliance_id: int = 0) -> list[dict]:
    """Every cached server pool on one appliance."""
    from ..extensions import db
    from ..models_cache import DeviceObject

    members = _members_by_pool(appliance.id)
    names = {r.mkey for r in db.session.query(DeviceObject)
             .filter_by(appliance_id=appliance.id,
                        logical_name=POOL_LOGICAL).all() if r.mkey}
    names |= set(members)

    out = []
    for name in sorted(names):
        mem = members.get(name)
        out.append({
            "appliance_id": appliance.id,
            "appliance": appliance.name,
            "pool": name,
            # The ONLY field that decides bind-vs-copy. Computed here, from
            # the ids, so no caller has to reconstruct it from names.
            "local": appliance.id == local_appliance_id,
            "members": list(mem or []),
            # ``False`` means "we do not know", NOT "it has none". A bound
            # pool with zero captured members is indistinguishable from an
            # uncaptured one, so it is reported as unknown — the direction
            # that never invents a member list.
            "members_known": bool(mem),
            "zone": getattr(appliance, "zone", "") or "",
            "line": getattr(appliance, "line", "") or "",
        })
    return out


def fleet_pools(local_appliance_id: int = 0, query: str = "",
                limit: int = 400) -> list[dict]:
    """Cached server pools across the fleet, local ones first.

    Walks ``visible_appliances()``, so the active ADOM cuts the list to what
    it may see — the same gate the rest of the device pages go through.
    """
    from flask import current_app
    from ..models import Appliance, visible_appliances

    q = (query or "").strip().lower()
    rows: list[dict] = []
    for a in visible_appliances().order_by(Appliance.name).all():
        # FortiADC has no object of this shape. Listing its pools under the
        # same English word would offer a bind that cannot exist.
        if (getattr(a, "kind", "") or "fortiweb") != "fortiweb":
            continue
        try:
            rows.extend(pools_for(a, local_appliance_id=local_appliance_id))
        except Exception as exc:  # noqa: BLE001 — one device never sinks the sweep
            current_app.logger.info("pool_catalog: %s failed: %s", a.name, exc)

    if q:
        rows = [r for r in rows if q in r["pool"].lower()
                or q in r["appliance"].lower()
                or any(q in m["ip"] for m in r["members"])]
    # Local first: the bindable rows are the ones most operators want, and a
    # fleet-sorted list buries them under whatever device sorts first.
    rows.sort(key=lambda r: (not r["local"], r["appliance"].lower(),
                             r["pool"].lower()))
    return rows[:limit]


def find_pool(appliance_id: int, pool: str) -> dict | None:
    """One cached pool row, or ``None``. Used to answer 'does it exist here'
    from the cache — never as the authority for a bind, which is checked live
    against the device by ``spo_wizard._collision_check``."""
    from ..extensions import db
    from ..models import Appliance

    appl = db.session.get(Appliance, appliance_id)
    if appl is None:
        return None
    want = (pool or "").strip()
    for row in pools_for(appl, local_appliance_id=appliance_id):
        if row["pool"] == want:
            return row
    return None
