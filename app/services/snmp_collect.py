"""SNMP polling — the collector that reads an appliance beyond its own API.

Every other collector in :mod:`metrics_collect` asks the appliance's REST or
CLI. This one asks the standard management plane instead: SNMP v2c, which
every Fortinet product serves and which a customer's monitoring already
speaks. It is **opt-in per appliance** — a community string is a credential,
and a device nobody configured must not be polled with ``public`` on the
off-chance it answers.

What one poll reads (one GET + one bounded table walk):

* ``sysUpTime`` -> ``satom_snmp_sysuptime_seconds``;
* the interface table (``ifDescr`` / ``ifOperStatus`` / the 64-bit octet
  counters, falling back to the 32-bit ones on a build that lacks ``ifX``)
  -> ``satom_snmp_if_oper_up``, ``satom_snmp_if_in_octets_total``,
  ``satom_snmp_if_out_octets_total`` labelled ``iface`` + ``ifindex``;
* CPU and memory from the vendor's enterprise MIB (:data:`VENDOR_OIDS`, each
  marked verified or not) with HOST-RESOURCES as the fallback ->
  ``satom_snmp_cpu_pct`` / ``satom_snmp_mem_pct``.

The contract it shares with every collector: a poll that fails writes
``satom_scrape_up{collector="snmp"} 0`` (``run_target`` does that for every
runner), never nothing; a reading the agent does not have is skipped, never
written as 0; and the community string is never part of any message, label,
log line or page.
"""
from __future__ import annotations

from . import snmp_client as sc
from . import vm_store

COLLECTOR = "snmp"
DEFAULT_PORT = 161
TIMEOUT_S = 3.0
RETRIES = 1
MAX_IFACES = 256

OID_SYSUPTIME = "1.3.6.1.2.1.1.3.0"
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_OPER = "1.3.6.1.2.1.2.2.1.8"
OID_IF_IN = "1.3.6.1.2.1.2.2.1.10"
OID_IF_OUT = "1.3.6.1.2.1.2.2.1.16"
OID_IFX_IN = "1.3.6.1.2.1.31.1.1.1.6"
OID_IFX_OUT = "1.3.6.1.2.1.31.1.1.1.10"
# HOST-RESOURCES: per-processor load (%) and the storage table for memory.
OID_HR_CPU = "1.3.6.1.2.1.25.3.3.1.2"
OID_HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"
OID_HR_STORAGE_UNITS = "1.3.6.1.2.1.25.2.3.1.4"
OID_HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
OID_HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"
HR_STORAGE_RAM = "1.3.6.1.2.1.25.2.1.2"

#: Fortinet enterprise OIDs for CPU and memory utilisation (percent), per
#: product. ``verified`` says whether a lab appliance of that product answered
#: them while this was built; an unverified OID is still tried, and when the
#: agent lacks it the reading simply falls back to HOST-RESOURCES.
VENDOR_OIDS: dict[str, dict] = {
    # FORTINET-FORTIGATE-MIB fgSysCpuUsage / fgSysMemUsage / fgSysDiskUsage
    "fortigate": {"cpu": "1.3.6.1.4.1.12356.101.4.1.3.0",
                  "mem": "1.3.6.1.4.1.12356.101.4.1.4.0",
                  "disk": "1.3.6.1.4.1.12356.101.4.1.6.0", "verified": False},
    # FORTINET-FORTIWEB-MIB fwSysCpuUsage (.5) / fwSysMemUsage (.7) /
    # fwSysLogDiskUsage (.9). VERIFIED on fortiweb17 (FortiWeb-KVM 7.6.8,
    # 2026-10-21): SNMP 5 / 79 / 3 against REST system_resource 5 / 80 / 3.
    "fortiweb": {"cpu": "1.3.6.1.4.1.12356.107.2.1.5.0",
                 "mem": "1.3.6.1.4.1.12356.107.2.1.7.0",
                 "disk": "1.3.6.1.4.1.12356.107.2.1.9.0", "verified": True},
    # FORTINET-FORTIADC-MIB fadcSysCpuUsage / fadcSysMemUsage
    "fortiadc": {"cpu": "1.3.6.1.4.1.12356.112.1.4.1.0",
                 "mem": "1.3.6.1.4.1.12356.112.1.4.2.0", "verified": False},
    # FORTINET-FORTIANALYZER-MIB fazSysCpuUsage / fazSysMemUsage
    "fortianalyzer": {"cpu": "1.3.6.1.4.1.12356.103.2.1.1.0",
                      "mem": "1.3.6.1.4.1.12356.103.2.1.2.0", "verified": False},
    # FORTINET-FORTIAUTHENTICATOR-MIB facSysCpuUsage / facSysMemUsage
    "fortiauthenticator": {"cpu": "1.3.6.1.4.1.12356.113.1.4.1.0",
                           "mem": "1.3.6.1.4.1.12356.113.1.4.2.0", "verified": False},
}


def _pct(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if 0 <= f <= 100 else None


def client_for(appliance) -> sc.SnmpClient:
    """The client for ``appliance`` — refuses a row with SNMP switched off or
    no community, with a reason that names neither."""
    if not getattr(appliance, "snmp_enabled", False):
        raise RuntimeError("SNMP is not enabled on this appliance")
    if not getattr(appliance, "has_snmp_community", False):
        raise RuntimeError("SNMP is enabled but no community string is stored")
    host = (getattr(appliance, "display_host", None) or appliance.host or "").strip()
    if not host:
        raise RuntimeError("no host configured")
    return sc.SnmpClient(host, appliance.snmp_community,
                         int(getattr(appliance, "snmp_port", None) or DEFAULT_PORT),
                         timeout=TIMEOUT_S, retries=RETRIES)


def _rows(binds, column) -> dict[str, object]:
    return {sc.table_index(b.oid, column): b.value for b in binds
            if b.value is not None and sc.table_index(b.oid, column)}


def read(client: sc.SnmpClient, kind: str, *, max_ifaces: int = MAX_IFACES) -> dict:
    """One poll, as a plain dict (no store I/O): uptime, interfaces, cpu, mem,
    and ``source`` saying where cpu/mem came from (``vendor`` / ``host`` / '').
    """
    vendor = VENDOR_OIDS.get(kind) or {}
    want = [OID_SYSUPTIME] + [o for o in (vendor.get("cpu"), vendor.get("mem"),
                                          vendor.get("disk")) if o]
    got = client.get_values(want)
    out: dict = {"uptime_s": None, "cpu_pct": None, "mem_pct": None, "disk_pct": None,
                 "source": "", "ifaces": []}
    ticks = got.get(OID_SYSUPTIME)
    if ticks is not None:
        out["uptime_s"] = int(ticks) / 100.0
    cpu = _pct(got.get(vendor.get("cpu"))) if vendor else None
    mem = _pct(got.get(vendor.get("mem"))) if vendor else None
    out["disk_pct"] = _pct(got.get(vendor.get("disk"))) if vendor.get("disk") else None
    if cpu is not None or mem is not None:
        out["source"] = "vendor"
    if cpu is None:
        loads = [_pct(b.value) for b in client.walk(OID_HR_CPU, max_rows=256)]
        loads = [l for l in loads if l is not None]
        if loads:
            cpu = sum(loads) / len(loads)
            out["source"] = out["source"] or "host"
    if mem is None:
        mem = _hr_memory(client)
        if mem is not None:
            out["source"] = out["source"] or "host"
    out["cpu_pct"], out["mem_pct"] = cpu, mem
    descr = _rows(client.walk(OID_IF_DESCR, max_rows=max_ifaces), OID_IF_DESCR)
    if descr:
        oper = _rows(client.walk(OID_IF_OPER, max_rows=max_ifaces), OID_IF_OPER)
        ins = _rows(client.walk(OID_IFX_IN, max_rows=max_ifaces), OID_IFX_IN)
        outs = _rows(client.walk(OID_IFX_OUT, max_rows=max_ifaces), OID_IFX_OUT)
        if not ins:   # no ifXTable on this build: the 32-bit counters
            ins = _rows(client.walk(OID_IF_IN, max_rows=max_ifaces), OID_IF_IN)
            outs = _rows(client.walk(OID_IF_OUT, max_rows=max_ifaces), OID_IF_OUT)
        for idx, name in descr.items():
            out["ifaces"].append({
                "ifindex": idx, "name": str(name),
                "oper_up": (1 if oper.get(idx) == 1 else 0) if idx in oper else None,
                "in_octets": ins.get(idx), "out_octets": outs.get(idx)})
    return out


def _hr_memory(client: sc.SnmpClient):
    types = _rows(client.walk(OID_HR_STORAGE_TYPE, max_rows=64), OID_HR_STORAGE_TYPE)
    ram = [i for i, t in types.items() if t == HR_STORAGE_RAM]
    if not ram:
        return None
    idx = ram[0]
    vals = client.get_values(["%s.%s" % (OID_HR_STORAGE_SIZE, idx),
                              "%s.%s" % (OID_HR_STORAGE_USED, idx)])
    size = vals.get("%s.%s" % (OID_HR_STORAGE_SIZE, idx))
    used = vals.get("%s.%s" % (OID_HR_STORAGE_USED, idx))
    if not size or used is None:
        return None
    return _pct(100.0 * float(used) / float(size))


def lines_for(appliance, reading: dict, ts) -> list:
    """Exposition lines for one reading. Pure."""
    L = {"device": appliance.name, "kind": appliance.kind}
    out = [vm_store.line("satom_snmp_sysuptime_seconds", L, reading.get("uptime_s"), ts),
           vm_store.line("satom_snmp_cpu_pct", L, reading.get("cpu_pct"), ts),
           vm_store.line("satom_snmp_mem_pct", L, reading.get("mem_pct"), ts),
           vm_store.line("satom_snmp_disk_pct", L, reading.get("disk_pct"), ts),
           vm_store.line("satom_snmp_ifaces", L, len(reading.get("ifaces") or []), ts)]
    for i in reading.get("ifaces") or []:
        IL = dict(L, iface=i.get("name") or i.get("ifindex"), ifindex=i.get("ifindex"))
        out.append(vm_store.line("satom_snmp_if_oper_up", IL, i.get("oper_up"), ts))
        out.append(vm_store.line("satom_snmp_if_in_octets_total", IL, i.get("in_octets"), ts))
        out.append(vm_store.line("satom_snmp_if_out_octets_total", IL, i.get("out_octets"), ts))
    return [l for l in out if l]


def collect(appliance, params, ts) -> list:
    """The runner ``metrics_collect`` dispatches to for collector ``snmp``."""
    client = client_for(appliance)
    try:
        reading = read(client, appliance.kind,
                       max_ifaces=int((params or {}).get("max_ifaces") or MAX_IFACES))
    except sc.SnmpError as exc:
        # The codec's messages never carry the community; the class name says
        # what kind of failure it was.
        raise RuntimeError("SNMP %s: %s" % (exc.__class__.__name__, str(exc)[:160])) from None
    if reading.get("uptime_s") is None and not reading.get("ifaces"):
        raise RuntimeError("the agent answered but carried neither sysUpTime nor an interface table")
    return lines_for(appliance, reading, ts)


def sync_target(appliance) -> str:
    """Make the ``snmp`` scrape target follow the appliance's switch.

    Called after the appliance form is saved. Enabling creates the target (via
    the same provisioning seam every collector uses) or re-enables a disabled
    one; disabling disables the target instead of leaving a row that goes red
    on every sweep. Returns ``created`` / ``enabled`` / ``disabled`` / ``kept``
    / ``none``.
    """
    from ..extensions import db
    from ..models_metrics import ScrapeTarget
    from . import metrics_collect as mc

    row = ScrapeTarget.query.filter_by(appliance_id=appliance.id,
                                       collector=COLLECTOR).first()
    if getattr(appliance, "snmp_enabled", False):
        if row is None:
            if mc.ensure_targets(appliance):
                return "created"
            return "none"
        if not row.enabled:
            row.enabled = True
            db.session.commit()
            return "enabled"
        return "kept"
    if row is not None and row.enabled:
        row.enabled = False
        db.session.commit()
        return "disabled"
    return "none" if row is None else "kept"
