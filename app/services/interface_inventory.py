"""Physical-interface inventory for the Fleet Map device card.

Three sources, merged by port name into ONE row per interface:

1. **Device cache** (``device_objects``) — the hourly ``device_sync`` harvest.
   Product-specific payload shapes (FortiWeb ``interface_2``, FortiADC /
   FortiAnalyzer ``system_interface``) are normalised here into a common dict.
   This is why the card used to be empty for most devices: it only read source
   2, which is manual documentation almost nobody fills in.
2. **Manual documentation** (``appliance_interfaces``) — what the operator typed
   in the appliance editor: what the port is CABLED to, and free-text notes.
   Nothing on the box knows this, so it always wins for those two fields.
3. **MAC cache** (``appliance_nics``) — hardware addresses. NOT available over
   REST on any of the three products (verified live: the cmdb interface object
   has no MAC field), so they come from a read-only CLI probe over SSH and are
   cached here; the card never blocks on SSH.

MAC probe commands (verified live 2026-07-20, all pass ``ssh_ops.assert_readonly``):

* FortiWeb      ``diagnose hardware nic list <port>``   -> ``HWaddr <mac>``
* FortiADC      ``diagnose netlink interface list <port>`` -> ``hw_addr=<mac>``
* FortiAnalyzer ``diagnose fmnetwork interface list``   -> ``HWaddr <mac>`` (all ports at once)
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

# logical_name of the harvested interface collection, per product family.
_LOGICAL = {
    "fortiweb": "interface_2",
    "fortiadc": "system_interface",
    "fortianalyzer": "system_interface",
}

_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")

# FortiAnalyzer JSON-RPC returns enums as ints (the CLI shows the words).
_FAZ_TYPE = {0: "aggregate", 1: "physical", 2: "vlan", 3: "loopback"}
_FAZ_MODE = {0: "static", 1: "dhcp", 2: "pppoe"}
# allowaccess is a bitmask. Cross-checked live on faz01: 23 renders as
# "ping https ssh http" in `show system interface port1` -> 1|2|4|16. Bits above
# those five are unverified, so any leftover is surfaced raw rather than guessed.
_FAZ_ACCESS = [(1, "ping"), (2, "https"), (4, "ssh"), (8, "snmp"), (16, "http")]


def _faz_access(raw) -> str:
    try:
        bits = int(raw)
    except (TypeError, ValueError):
        return _s(raw)
    if not bits:
        return ""
    names = [n for b, n in _FAZ_ACCESS if bits & b]
    rest = bits & ~sum(b for b, _ in _FAZ_ACCESS)
    if rest:
        names.append(f"+{rest}")
    return " ".join(names)


def _norm_mac(raw: str | None) -> str:
    """Uppercase colon-separated MAC, or '' when *raw* holds no MAC."""
    if not raw:
        return ""
    m = _MAC_RE.search(raw)
    return m.group(0).replace("-", ":").upper() if m else ""


def _s(v: Any) -> str:
    """Payload scalar -> trimmed string ('' for None/empty containers)."""
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return " ".join(str(x) for x in v if x not in (None, "")).strip()
    return str(v).strip()


def _ip_of(payload: dict, kind: str) -> str:
    """CIDR-ish address string. FAZ ships ``["addr", "mask"]``; the others a
    ready ``a.b.c.d/nn``. A 0.0.0.0 address means *unconfigured* -> ''."""
    raw = payload.get("ip")
    if kind == "fortianalyzer" and isinstance(raw, (list, tuple)):
        addr = _s(raw[0] if raw else "")
        mask = _s(raw[1] if len(raw) > 1 else "")
        if not addr or addr.startswith("0.0.0.0"):
            return ""
        return f"{addr}/{_mask_bits(mask)}" if mask else addr
    txt = _s(raw)
    return "" if not txt or txt.startswith("0.0.0.0") else txt


def _mask_bits(mask: str) -> str:
    try:
        return str(sum(bin(int(o)).count("1") for o in mask.split(".")))
    except (ValueError, AttributeError):
        return mask


def _status_of(payload: dict, kind: str) -> str:
    raw = payload.get("status")
    if kind == "fortianalyzer":
        # 16 == enabled/up on FAZ 7.6 (cross-checked against `get system
        # interface`, which prints "status: enable" for the same ports).
        try:
            return "up" if int(raw) else "down"
        except (TypeError, ValueError):
            return _s(raw).lower()
    return _s(raw).lower()


def _type_of(payload: dict, kind: str) -> str:
    raw = payload.get("type")
    if kind == "fortianalyzer":
        try:
            return _FAZ_TYPE.get(int(raw), _s(raw))
        except (TypeError, ValueError):
            return _s(raw)
    return _s(raw)


def _mode_of(payload: dict, kind: str) -> str:
    raw = payload.get("mode")
    if kind == "fortianalyzer":
        try:
            return _FAZ_MODE.get(int(raw), _s(raw))
        except (TypeError, ValueError):
            return _s(raw)
    return _s(raw)


def _speed_of(payload: dict, kind: str) -> str:
    raw = _s(payload.get("speed"))
    if kind == "fortianalyzer" and raw in ("0", ""):
        return "auto"
    return raw


def cached_interfaces(appliance, *, session=None) -> list[dict]:
    """Normalised interface rows from the device cache (no device is touched).

    Returns [] when the appliance has never been harvested.
    """
    from ..extensions import db
    from ..models_cache import DeviceObject, DeviceSnapshot

    session = session or db.session
    kind = (appliance.kind or "").lower()
    logical = _LOGICAL.get(kind)
    if not logical:
        return []

    rows = (session.query(DeviceObject)
            .filter_by(appliance_id=appliance.id, logical_name=logical,
                       layer="config", depth=0)
            .order_by(DeviceObject.idx).all())

    out: list[dict] = []
    seen: set[str] = set()
    for r in rows:
        p = r.payload or {}
        name = _s(p.get("name")) or _s(r.mkey)
        if not name or name in seen:      # the cache can hold >1 snapshot
            continue
        seen.add(name)
        out.append({
            "name": name,
            "if_type": _type_of(p, kind),
            "ip_address": _ip_of(p, kind),
            "status": _status_of(p, kind),
            "mtu": _s(p.get("mtu")),
            "vlan": _s(p.get("vlanid")),
            "mode": _mode_of(p, kind),
            "speed": _speed_of(p, kind),
            "allowaccess": (_faz_access(p.get("allowaccess")) if kind == "fortianalyzer"
                            else _s(p.get("allowaccess"))),
            "description": _s(p.get("description")) or _s(p.get("alias")),
            "mac": "",
            "connected_to": "",
            "notes": "",
            "documented": False,
            "cached": True,
        })
    out.sort(key=_port_sort)
    return out


def _port_sort(row: dict):
    """port2 before port10 — numeric suffix first, then the raw name."""
    m = re.match(r"^(.*?)(\d+)$", row.get("name", ""))
    return (m.group(1), int(m.group(2))) if m else (row.get("name", ""), -1)


def cache_meta(appliance, *, session=None) -> dict:
    """Freshness of the harvest the rows above came from."""
    from ..extensions import db
    from ..models_cache import DeviceObject, DeviceSnapshot

    session = session or db.session
    logical = _LOGICAL.get((appliance.kind or "").lower())
    if not logical:
        return {}
    row = (session.query(DeviceObject.section)
           .filter_by(appliance_id=appliance.id, logical_name=logical, depth=0)
           .first())
    if not row:
        return {}
    snap = (session.query(DeviceSnapshot)
            .filter_by(appliance_id=appliance.id, section=row[0])
            .order_by(DeviceSnapshot.generated_at.desc()).first())
    if not snap:
        return {}
    return {"generated_at": snap.generated_at.isoformat() if snap.generated_at else None,
            "source": snap.source}


def stored_macs(appliance, *, session=None) -> dict[str, dict]:
    """``{port_name: {"mac":…, "fetched_at":…, "source":…}}`` from the cache."""
    from ..extensions import db
    from ..models import ApplianceNic

    session = session or db.session
    out = {}
    for n in session.query(ApplianceNic).filter_by(appliance_id=appliance.id).all():
        out[n.name] = {
            "mac": n.mac or "",
            "source": n.source or "",
            "fetched_at": n.fetched_at.isoformat() if n.fetched_at else None,
        }
    return out


# --- live MAC probe (read-only CLI over SSH) --------------------------------

def _probe_fortiweb(appliance, ports: list[str]) -> dict[str, str]:
    from . import ssh_ops
    macs: dict[str, str] = {}
    with ssh_ops.FortiWebReadonlySSH(appliance, timeout=20.0) as sess:
        for port in ports:
            try:
                out = sess.run_readonly(f"diagnose hardware nic list {port}")
            except Exception:  # noqa: BLE001 — one bad port must not kill the sweep
                continue
            for line in out.splitlines():
                if "hwaddr" in line.lower():
                    mac = _norm_mac(line)
                    if mac:
                        macs[port] = mac
                    break
    return macs


def _probe_fortiadc(appliance, ports: list[str]) -> dict[str, str]:
    from . import ssh_ops
    macs: dict[str, str] = {}
    with ssh_ops.FortiWebReadonlySSH(appliance, timeout=20.0) as sess:
        for port in ports:
            try:
                out = sess.run_readonly(f"diagnose netlink interface list {port}")
            except Exception:  # noqa: BLE001
                continue
            m = re.search(r"hw_addr=([0-9A-Fa-f:]{17})", out)
            if m:
                macs[port] = _norm_mac(m.group(1))
    return macs


def _probe_fortianalyzer(appliance, ports: list[str]) -> dict[str, str]:
    """One command returns every port (ifconfig-style blocks)."""
    from . import ssh_ops
    out = ssh_ops.run_command(appliance, "diagnose fmnetwork interface list", timeout=25.0)
    macs: dict[str, str] = {}
    for line in out.splitlines():
        m = re.match(r"^\s*(\S+)\s+Link encap:\S+\s+HWaddr\s+(\S+)", line)
        if m:
            mac = _norm_mac(m.group(2))
            if mac and mac != "00:00:00:00:00:00":
                macs[m.group(1)] = mac
    return macs


_PROBES = {
    "fortiweb": _probe_fortiweb,
    "fortiadc": _probe_fortiadc,
    "fortianalyzer": _probe_fortianalyzer,
}


def refresh_macs(appliance, *, session=None) -> dict:
    """Probe the box over read-only SSH and upsert ``appliance_nics``.

    Returns ``{"ok":bool, "count":int, "error":str}``. Never raises: the card
    degrades to "MACs not fetched yet" rather than 500-ing the modal.
    """
    from ..extensions import db
    from ..models import ApplianceNic

    session = session or db.session
    kind = (appliance.kind or "").lower()
    probe = _PROBES.get(kind)
    if not probe:
        return {"ok": False, "count": 0, "error": f"no MAC probe for kind {kind!r}"}

    ports = [r["name"] for r in cached_interfaces(appliance, session=session)]
    if not ports and kind != "fortianalyzer":
        return {"ok": False, "count": 0,
                "error": "no cached interfaces — run a device sync first"}

    try:
        found = probe(appliance, ports)
    except Exception as exc:  # noqa: BLE001 — SSH down / bad creds / timeout
        return {"ok": False, "count": 0, "error": str(exc)[:300]}

    now = datetime.utcnow()
    existing = {n.name: n for n in
                session.query(ApplianceNic).filter_by(appliance_id=appliance.id).all()}
    for name, mac in found.items():
        row = existing.get(name)
        if row is None:
            row = ApplianceNic(appliance_id=appliance.id, name=name[:64])
            session.add(row)
        row.mac = mac
        row.source = "cli"
        row.fetched_at = now
    try:
        session.commit()
    except Exception as exc:  # noqa: BLE001
        session.rollback()
        return {"ok": False, "count": 0, "error": str(exc)[:300]}
    return {"ok": True, "count": len(found), "error": ""}


# --- the merge the view actually calls --------------------------------------

def merged(appliance, *, session=None) -> dict:
    """``{"interfaces":[…], "cache":{…}, "mac_fetched_at":…}`` for the card."""
    from ..extensions import db

    session = session or db.session
    rows = cached_interfaces(appliance, session=session)
    by_name = {r["name"]: r for r in rows}

    # manual documentation wins for connected_to / notes, and fills a port the
    # harvest never saw (e.g. a mgmt port on a box that has never synced).
    for doc in sorted(appliance.interfaces,
                      key=lambda x: (x.sort_order or 0, x.id or 0)):
        name = (doc.name or "").strip()
        if not name:
            continue
        row = by_name.get(name)
        if row is None:
            row = {"name": name, "if_type": "", "ip_address": "", "status": "",
                   "mtu": "", "vlan": "", "mode": "", "speed": "",
                   "allowaccess": "", "description": "", "mac": "",
                   "connected_to": "", "notes": "", "documented": False,
                   "cached": False}
            by_name[name] = row
            rows.append(row)
        row["documented"] = True
        row["connected_to"] = (doc.connected_to or "").strip()
        row["notes"] = (doc.notes or "").strip()
        if doc.if_type and not row["if_type"]:
            row["if_type"] = doc.if_type.strip()
        if doc.ip_address and not row["ip_address"]:
            row["ip_address"] = doc.ip_address.strip()

    macs = stored_macs(appliance, session=session)
    fetched = ""
    for name, info in macs.items():
        row = by_name.get(name)
        if row is not None:
            row["mac"] = info["mac"]
        fetched = fetched or (info.get("fetched_at") or "")

    rows.sort(key=_port_sort)
    return {"interfaces": rows, "cache": cache_meta(appliance, session=session),
            "mac_fetched_at": fetched}
