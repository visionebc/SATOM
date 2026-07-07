"""Device HARDWARE inventory over SSH (vCPU / RAM / disks).

The lab fleet's REST API is license-locked (HTTP 423 -20010) but the CLI stays
alive, so hardware facts are captured with the same read-only SSH channel the
diagnostics use (services.ssh_ops) and cached in the ``device_hardware`` table
(one row per appliance, upserted). Consumed by the Monitoring dashboard and the
Architecture map — pages never probe live; a scan is an explicit background job.
"""
from __future__ import annotations

import json
import re

from ..models import db, Appliance, DeviceHardware
from . import ssh_ops

HW_COMMANDS = [
    "get system status",
    "diagnose hardware cpu list",
    "diagnose hardware mem list",
    "diagnose hardware harddisk list",
    "diagnose hardware logdisk info",
]


# ---------------------------------------------------------------------------
# Pure parsers (tolerant — raw output is stored anyway)
# ---------------------------------------------------------------------------

def parse_cpu(text: str) -> tuple[int | None, str | None]:
    """Count 'processor : N' stanzas (/proc/cpuinfo style) + first model name."""
    if not text:
        return None, None
    procs = re.findall(r"^processor\s*:\s*\d+", text, re.M | re.I)
    model = None
    m = re.search(r"^model name\s*:\s*(.+)$", text, re.M | re.I)
    if m:
        model = m.group(1).strip()[:120]
    return (len(procs) or None), model


def parse_mem(text: str) -> int | None:
    """MemTotal from /proc/meminfo-style output -> MB."""
    if not text:
        return None
    m = re.search(r"MemTotal\s*:?\s*([\d,]+)\s*(kB|KB|MB|GB)?", text, re.I)
    if not m:
        return None
    val = float(m.group(1).replace(",", ""))
    unit = (m.group(2) or "kB").lower()
    if unit == "mb":
        return int(val)
    if unit == "gb":
        return int(val * 1024)
    return int(val / 1024)  # kB default


_DISK_ROW_RE = re.compile(
    r"^(?:disk\s+)?(?P<name>[A-Za-z0-9_\-/]+)\b.*?(?P<size>[\d][\d.,]*)\s*(?P<unit>TB|GB|MB|MiB|GiB)\b",
    re.I)
_SIZE_RE = re.compile(r"size[^0-9]*([\d][\d.,]*)\s*(TB|GB|MB)", re.I)


def _to_gb(size: float, unit: str) -> float:
    u = unit.lower()
    if u.startswith("t"):
        return size * 1024
    if u.startswith("m"):
        return size / 1024
    return size


def parse_disks(text: str) -> list[dict]:
    """Best-effort disk rows out of `diagnose hardware harddisk list` /
    `logdisk info` — any line carrying a name + a sized quantity."""
    disks: list[dict] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("diagnose", "name ", "---", "=")):
            continue
        m = _DISK_ROW_RE.search(line)
        if m and m.group("name").lower() not in ("size", "total", "free", "used"):
            name = m.group("name")[:32]
            if name in seen:
                continue
            seen.add(name)
            gb = _to_gb(float(m.group("size").replace(",", "")), m.group("unit"))
            disks.append({"name": name, "size_gb": round(gb, 1)})
            continue
        m2 = _SIZE_RE.search(line)
        if m2 and not disks:
            gb = _to_gb(float(m2.group(1).replace(",", "")), m2.group(2))
            disks.append({"name": "disk", "size_gb": round(gb, 1)})
    return disks


# ---------------------------------------------------------------------------
# Probe + store
# ---------------------------------------------------------------------------

def probe_hardware(appliance) -> dict:
    """SSH into the box and run the read-only hardware battery."""
    with ssh_ops.FortiWebReadonlySSH(appliance) as ssh:
        raw = ssh.run_battery(HW_COMMANDS)
    cpu_count, cpu_model = parse_cpu(raw.get("diagnose hardware cpu list", ""))
    mem_mb = parse_mem(raw.get("diagnose hardware mem list", ""))
    disks = parse_disks(raw.get("diagnose hardware harddisk list", ""))
    extra = parse_disks(raw.get("diagnose hardware logdisk info", ""))
    names = {d["name"] for d in disks}
    disks += [d for d in extra if d["name"] not in names]
    return {"cpu_count": cpu_count, "cpu_model": cpu_model,
            "mem_total_mb": mem_mb, "disks": disks, "raw": raw}


def store_hardware(appliance_id: int, info: dict) -> DeviceHardware:
    row = DeviceHardware.query.filter_by(appliance_id=appliance_id).first()
    if row is None:
        row = DeviceHardware(appliance_id=appliance_id)
        db.session.add(row)
    row.cpu_count = info.get("cpu_count")
    row.cpu_model = info.get("cpu_model")
    row.mem_total_mb = info.get("mem_total_mb")
    row.disks_json = json.dumps(info.get("disks") or [])
    row.raw_json = json.dumps(info.get("raw") or {})[:200_000]
    row.source = "ssh"
    db.session.commit()
    return row


def scan_appliance(appliance) -> DeviceHardware:
    return store_hardware(appliance.id, probe_hardware(appliance))


def hardware_map(ids: list[int] | None = None) -> dict[int, dict]:
    """appliance_id -> hardware dict for every scanned device (cache only)."""
    q = DeviceHardware.query
    if ids:
        q = q.filter(DeviceHardware.appliance_id.in_(ids))
    return {r.appliance_id: r.to_dict() for r in q.all()}
