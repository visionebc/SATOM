"""Live firmware / model read for ONE appliance -- the inventory primitive.

**Why this module exists.** ``Appliance.firmware`` is documentation, and until
now nothing kept it current. ``device_sync`` never writes it (it says so in its
own comment) and ``rediscovery.apply_inventory`` only fills it as a side effect
of a status poll that happens to meet a *fresh* snapshot. Measured on the live
node 2026-08-13: 5 of the 10 registered appliances carried an EMPTY firmware
string while every online one answered a status call fine. A CMDB whose version
column is empty on half the estate is a list of IP addresses.

**What it does.** Exactly one status call per appliance -- the same call
``Appliance.probe_status`` already makes -- and nothing else: no config read, no
SoT version, no Change Request. That is what makes it safe to expose on
``/api/v1``, where firmware *upgrade* stays hard-blocked.

**Why it is per-kind.** The four vendors put the version in four different
places. Every shape below was read off the live devices on 2026-08-13 except
FortiAnalyzer, whose only registered box is retired -- that branch is written
from the documented ``/sys/status`` shape, reads a candidate list rather than
one key, and is marked UNVERIFIED so nobody mistakes it for measured.

===================  ==================================  ====================
kind                 status call                         version key
===================  ==================================  ====================
fortiweb             status.systemstatus                 firmwareVersion
fortiadc             /api/platform/version               version + build
fortiauthenticator   GET /api/v1/systeminfo/             firmware
fortianalyzer        get /sys/status (JSON-RPC)          Version (UNVERIFIED)
===================  ==================================  ====================

**An empty answer is a failure, not an observation.** If the status call
succeeds but carries no version string, :func:`read` returns ``ok=False`` and
:func:`refresh` persists NOTHING -- in particular it does not stamp
``firmware_checked_at``. A row that claims it was checked at 14:02 while showing
a stale version is worse than one that admits it was never checked: that
timestamp is the only thing a consumer (VEYRS) can use to decide whether the
version is worth correlating against a CVE feed.
"""
from __future__ import annotations

from datetime import datetime

# Substrings that mark a virtual appliance in a model / firmware / serial blob.
_VM_HINTS = ("VM", "KVM", "HV", "AWS", "AZURE", "GCP", "OCI", "XEN")


def _first(d: dict, keys) -> str:
    """First non-empty value among *keys*, as a stripped string ('' if none)."""
    if not isinstance(d, dict):
        return ""
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return str(v).strip()
    return ""


def _hw_from(blob: str) -> str | None:
    """'vm' / 'hardware' / None (unknown) from a model+firmware+serial blob."""
    up = (blob or "").upper()
    if not up.strip():
        return None
    return "vm" if any(h in up for h in _VM_HINTS) else "hardware"


def _unwrap(raw):
    """FortiWeb answers ``{'results': {...}}``; the others answer flat."""
    if isinstance(raw, dict) and isinstance(raw.get("results"), dict):
        return raw["results"]
    return raw if isinstance(raw, dict) else {}


def _ok(firmware: str, model: str | None, hw: str | None) -> dict:
    return {"ok": True, "firmware": firmware, "model": model or None,
            "hw_type": hw, "error": "", "detail": ""}


def _fail(code: str, detail: str = "") -> dict:
    return {"ok": False, "firmware": "", "model": None, "hw_type": None,
            "error": code, "detail": str(detail)[:300]}


# --------------------------------------------------------------------------- #
#  Per-kind readers                                                            #
# --------------------------------------------------------------------------- #

def _read_fortiweb(appliance) -> dict:
    d = _unwrap(appliance.build_client(timeout=15.0).status_check())
    fw = _first(d, ("firmwareVersion", "firmware_version", "version"))
    if not fw:
        # FortiWeb answers a REFUSAL with HTTP 200 and an {errcode, message}
        # envelope, so the client raises nothing. Live on fortiweb08
        # (192.0.2.13) 2026-08-13: errcode -20010, "The license of peer VM
        # FortiWeb is not valid." Reporting that as a generic parse miss would
        # send an operator to read this parser instead of the licence.
        errcode = _first(d, ("errcode", "error_code"))
        if errcode:
            return _fail("device_refused",
                         f"errcode {errcode}: {_first(d, ('message', 'msg'))}")
        return _fail("no_version_in_status", f"keys={sorted(d)[:12]}")
    platform = _first(d, ("platformName", "platform"))
    serial = _first(d, ("serialNumber", "serial"))
    # "FortiWeb-KVM 7.6.8,build1128(GA.M),260602" -> model "FortiWeb-KVM 7.6.8"
    model = fw.split(",")[0].strip() or platform or None
    return _ok(fw, model, _hw_from(f"{platform} {fw} {serial}"))


def _read_fortiadc(appliance) -> dict:
    # Through adc_ops, never ``clients.fortiadc`` directly: this module is
    # fleet-wide and tests/test_product_separation.py keeps ADC client
    # construction inside ADC modules.
    from . import adc_ops

    p = adc_ops.platform_payload(appliance)
    model, hw, fw = adc_ops.model_inventory_from(p)
    if not fw:
        return _fail("no_version_in_status", f"keys={sorted(p)[:12]}")
    return _ok(fw, model, hw)


def _read_fortiauthenticator(appliance) -> dict:
    d = appliance.build_client(timeout=15.0).status_check()
    d = d if isinstance(d, dict) else {}
    # Live 2026-08-13: {"firmware": "FACVMKVM v8.0.3, build0099 (GA)", "sn": ...}
    fw = _first(d, ("firmware", "version", "firmware_version"))
    if not fw:
        return _fail("no_version_in_status", f"keys={sorted(d)[:12]}")
    serial = _first(d, ("sn", "serial", "serial_number"))
    # The head token is the platform: "FACVMKVM v8.0.3, ..." -> "FACVMKVM".
    parts = fw.split()
    head = parts[0].strip() if parts else ""
    model = f"FortiAuthenticator-{head}" if head else None
    return _ok(fw, model, _hw_from(f"{head} {fw} {serial}"))


def _read_fortianalyzer(appliance) -> dict:
    # UNVERIFIED against a live box (the only FAZ row is retired). Candidate
    # keys, not one assumed key, so a shape surprise degrades to a clean
    # "no_version_in_status" instead of a confidently wrong version.
    d = appliance.build_client(timeout=15.0).status_check()
    d = d if isinstance(d, dict) else {}
    fw = _first(d, ("Version", "version", "firmware", "Firmware Version"))
    if not fw:
        return _fail("no_version_in_status", f"keys={sorted(d)[:12]}")
    platform = _first(d, ("Platform Full Name", "Platform Type", "platform"))
    serial = _first(d, ("Serial Number", "serial"))
    model = f"FortiAnalyzer-{platform}" if platform else None
    return _ok(fw, model, _hw_from(f"{platform} {fw} {serial}"))


_READERS = {
    "fortiweb": _read_fortiweb,
    "fortiadc": _read_fortiadc,
    "fortianalyzer": _read_fortianalyzer,
    "fortiauthenticator": _read_fortiauthenticator,
}


# --------------------------------------------------------------------------- #
#  Public API                                                                  #
# --------------------------------------------------------------------------- #

def read(appliance) -> dict:
    """Read the running firmware off the device. NEVER raises.

    Returns ``{ok, firmware, model, hw_type, error, detail}``. ``ok`` is True
    only when a NON-EMPTY version string came back.
    """
    reader = _READERS.get(getattr(appliance, "kind", "") or "")
    if reader is None:
        return _fail("unsupported_kind", str(getattr(appliance, "kind", "")))
    try:
        return reader(appliance)
    except Exception as exc:  # noqa: BLE001 -- a probe must never 500 its caller
        return _fail("unreachable", f"{type(exc).__name__}: {exc}")


def refresh(appliance) -> dict:
    """:func:`read` + persist. On failure NOTHING is written -- not even the
    timestamp (see the module docstring on attestation).

    Adds ``changed`` (did the version actually move), ``previous`` and
    ``checked_at`` (ISO, only on success).
    """
    from ..extensions import db

    res = read(appliance)
    if not res.get("ok"):
        res["changed"] = False
        res["checked_at"] = None
        return res

    previous = appliance.firmware or ""
    res["changed"] = (previous != res["firmware"])
    res["previous"] = previous or None
    appliance.firmware = res["firmware"]
    # model / hw_type are refreshed only when the device actually told us; an
    # unknown must never erase an operator-entered value.
    if res.get("model"):
        appliance.model = res["model"]
    if res.get("hw_type"):
        appliance.hw_type = res["hw_type"]
    now = datetime.utcnow()
    appliance.firmware_checked_at = now
    db.session.commit()
    res["checked_at"] = now.isoformat()
    return res
