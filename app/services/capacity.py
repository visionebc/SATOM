"""Capacity guardrails — how many of each object a FortiWeb model can hold.

Fortinet publishes a maximum per object type per (firmware major, model/SKU)
in Appendix B / the model datasheet (e.g. a FortiWeb-VM04 on 7.6 accepts N
server policies). Those ceilings are stored, per row, in ``CapacityLimit``
(``hard_max``). Because the lab fleet is unlicensed VMs that cannot self-report
a SKU, the admin ENTERS/confirms each ``hard_max`` and may set a lower
``operational_cap`` (the "espacio de sobra" buffer). Automations call
``check_headroom`` BEFORE creating an object so they never push the box past a
limit it will reject.

Pure-ish: the only side of this that touches the network is nothing — counts
come from the local device-object cache (``DeviceObject``), never a live box.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from ..extensions import db
from ..models import CapacityLimit
from ..models_cache import DeviceObject


# ---------------------------------------------------------------------------
# Object-type catalog — the stable logical tokens the caps are keyed by.
# ``count_logicals`` = the device-cache ``logical_name`` values that make up a
# live count of this type (verified against the real cache on fw6). Extend this
# dict (add vserver / server_pool / health_check …) WITHOUT a schema change.
# ---------------------------------------------------------------------------
OBJECT_TYPES: dict[str, dict] = {
    "server_policy": {
        "label": "Server Policies",
        "count_logicals": ["server_policy"],
        "order": 10,
    },
    "web_protection_profile": {
        "label": "Web Protection Profiles",
        "count_logicals": ["webprotection_profile_inline",
                           "webprotection_profile_offline"],
        "order": 20,
    },
    "certificate": {
        "label": "Local Certificates",
        "count_logicals": ["certificate"],
        "order": 30,
    },
    "sni": {
        "label": "SNI Policies",
        "count_logicals": ["certificate_sni"],
        "order": 40,
    },
}

PRODUCT_DEFAULT = "fortiweb"

# Suggested model/SKU list for the registration dropdown. FortiWeb-VM caps scale
# with the licensed vCPU/vRAM tier; hardware models carry their own datasheet
# numbers. This is only the pick-list — the NUMBERS live in CapacityLimit and
# are admin-entered (nothing here is invented as a limit).
KNOWN_MODELS: list[str] = [
    "FortiWeb-VM01", "FortiWeb-VM02", "FortiWeb-VM04",
    "FortiWeb-VM08", "FortiWeb-VM16",
    "FortiWeb 100E", "FortiWeb 400E", "FortiWeb 600E",
    "FortiWeb 1000E", "FortiWeb 2000E", "FortiWeb 3000E", "FortiWeb 4000E",
    "FortiWeb 100F", "FortiWeb 400F", "FortiWeb 600F",
    "FortiWeb 1000F", "FortiWeb 2000F", "FortiWeb 3000F", "FortiWeb 4000F",
]


def object_types_ordered() -> list[tuple[str, dict]]:
    return sorted(OBJECT_TYPES.items(), key=lambda kv: kv[1]["order"])


def firmware_major(firmware: str | None) -> str | None:
    """'7.6.8' -> '7.6', 'FortiWeb-VM 8.0.5 build...' -> '8.0'. None if unparseable."""
    if not firmware:
        return None
    import re
    m = re.search(r"(\d+)\.(\d+)", str(firmware))
    return f"{m.group(1)}.{m.group(2)}" if m else None


# ---------------------------------------------------------------------------
# Limit lookups (DB)
# ---------------------------------------------------------------------------

def get_limit(model: str | None, fw_major: str | None, object_type: str,
              product: str = PRODUCT_DEFAULT) -> CapacityLimit | None:
    if not model or not fw_major:
        return None
    return CapacityLimit.query.filter_by(
        product=product, firmware_major=fw_major, model=model,
        object_type=object_type).first()


def limit_for_appliance(appliance, object_type: str) -> CapacityLimit | None:
    return get_limit(appliance.model, firmware_major(appliance.firmware),
                     object_type, product=appliance.kind or PRODUCT_DEFAULT)


# ---------------------------------------------------------------------------
# Live counts (from the local device-object cache — no box call)
# ---------------------------------------------------------------------------

def current_count(appliance_id: int, object_type: str) -> int:
    spec = OBJECT_TYPES.get(object_type)
    if not spec:
        return 0
    logicals = spec["count_logicals"]
    from sqlalchemy import func
    return int(db.session.query(func.count()).select_from(DeviceObject).filter(
        DeviceObject.appliance_id == appliance_id,
        DeviceObject.logical_name.in_(logicals)).scalar() or 0)


@dataclass
class Headroom:
    object_type: str
    label: str
    used: int
    hard_max: int | None
    operational_cap: int | None
    effective_cap: int | None
    free: int | None          # effective_cap - used (None if no cap defined)
    ok: bool                  # would a +1 create stay within the cap?
    known: bool               # is there a cap row at all?

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def headroom(appliance, object_type: str, want: int = 0) -> Headroom:
    """Capacity picture for one object type on one appliance. ``want`` = how many
    MORE the caller intends to create (0 = just report). ``ok`` is True when the
    cap is unknown (fail-open — a missing cap must not block work) or when
    used+want stays within the effective cap."""
    spec = OBJECT_TYPES.get(object_type, {})
    label = spec.get("label", object_type)
    used = current_count(appliance.id, object_type)
    lim = limit_for_appliance(appliance, object_type)
    hard = lim.hard_max if lim else None
    opcap = lim.operational_cap if lim else None
    eff = lim.effective_cap if lim else None
    free = (eff - used) if eff is not None else None
    ok = True if eff is None else (used + max(want, 0) <= eff)
    return Headroom(object_type, label, used, hard, opcap, eff, free, ok,
                    known=lim is not None)


def fleet_headroom(appliance) -> list[Headroom]:
    return [headroom(appliance, k) for k, _ in object_types_ordered()]


def check_headroom(appliance, object_type: str, want: int = 1) -> tuple[bool, str]:
    """The guardrail automations call before creating ``want`` objects.

    Returns (allowed, message). Fail-OPEN when no cap is configured (so an
    un-provisioned model never blocks work) but the message says so. Fail-CLOSED
    only when a cap exists and would be exceeded."""
    h = headroom(appliance, object_type, want=want)
    if not h.known or h.effective_cap is None:
        return True, (f"No capacity limit set for {appliance.model or '?'} "
                      f"{firmware_major(appliance.firmware) or '?'} / {h.label}; "
                      f"allowing (used={h.used}).")
    if h.ok:
        return True, (f"OK: {h.used}+{want} <= {h.effective_cap} {h.label} "
                      f"(free {h.free}).")
    return False, (f"Capacity limit reached for {h.label} on {appliance.name}: "
                   f"used {h.used} + {want} would exceed cap {h.effective_cap} "
                   f"(hard max {h.hard_max}).")


# ---------------------------------------------------------------------------
# Admin plumbing — ensure editable rows, seed
# ---------------------------------------------------------------------------

def ensure_rows_for(model: str, fw_major: str, product: str = PRODUCT_DEFAULT,
                    commit: bool = True) -> int:
    """Create empty (hard_max=NULL) rows for every object type of a
    (model, firmware) so the admin has a full editable set. Insert-only."""
    if not model or not fw_major:
        return 0
    added = 0
    for otype in OBJECT_TYPES:
        exists = CapacityLimit.query.filter_by(
            product=product, firmware_major=fw_major, model=model,
            object_type=otype).first()
        if exists is None:
            db.session.add(CapacityLimit(
                product=product, firmware_major=fw_major, model=model,
                object_type=otype, source="admin"))
            added += 1
    if commit and added:
        db.session.commit()
    return added


def _seed_path() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "registry", "data", "capacity_seed.json")


def seed_from_json() -> int:
    """Insert-only seed of published limits from capacity_seed.json (admin edits
    always win — an existing (product,fw,model,otype) row is never touched)."""
    path = _seed_path()
    if not os.path.exists(path):
        return 0
    try:
        rows = json.load(open(path, encoding="utf-8"))
    except (ValueError, OSError):
        return 0
    added = 0
    for r in rows:
        key = dict(product=r.get("product", PRODUCT_DEFAULT),
                   firmware_major=r["firmware_major"], model=r["model"],
                   object_type=r["object_type"])
        if CapacityLimit.query.filter_by(**key).first() is not None:
            continue
        db.session.add(CapacityLimit(
            **key, hard_max=r.get("hard_max"),
            operational_cap=r.get("operational_cap"),
            source=r.get("source", "seed")))
        added += 1
    if added:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            return 0
    return added
