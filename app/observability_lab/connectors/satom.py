"""``fortinet_source = satom``: how each SATOM appliance is read.

Operator 2026-11-05: "the data must be direct — it is SATOM in the end".
Observability is part of SATOM, so FortiWeb and FortiGate are read DIRECTLY
from the device, as SATOM: with the credential SATOM holds for the appliance
(decrypted by SATOM, in memory only), GET only (:mod:`..http_ro` refuses any
other method), every read a visible job step. When a device read of a
configuration table fails (unreachable, licence refused), that table comes
from SATOM's cache instead and the step says so with the snapshot time.

FortiADC, FortiAuthenticator and FortiAnalyzer have no direct reader here yet:
they come from SATOM's cache and SATOM's own collectors
(:mod:`.satom_cache`). Everything read is stored in Observability's own tables.
"""
from __future__ import annotations

import time

from .. import satom_bridge
from . import EndpointResult, FactRow
from .fortigate import FortiGateConnector
from .fortiweb import FortiWebConnector
from .satom_cache import SatomFortiADC, SatomFortiAnalyzer, SatomFortiAuthenticator


class _DirectAsSatom:
    #: REST path -> SATOM logical name: the fallback when the device read fails.
    CACHE: dict = {}
    #: True when the parser takes the whole body (FortiGate), False for rows.
    BODY = False

    def __init__(self, source, *, secret: str = "", transport=None):
        aid = int((source.config or {}).get("appliance_id") or 0)
        _user, pw = satom_bridge.credentials(aid)
        super().__init__(source, secret=pw, transport=transport)
        self.appliance_id = aid

    def _read(self, client, endpoint, path, layers, parse):
        res = super()._read(client, endpoint, path, layers, parse)
        key = path.split("?")[0]
        # SATOM caches ONE VDOM per appliance: a per-VDOM read has no fallback.
        if res.ok or res.absent or key not in self.CACHE or "vdom=" in path:
            return res
        rows, at = satom_bridge.cache_rows(self.appliance_id, self.CACHE[key], "config")
        if at is None:
            return res
        started = time.monotonic()
        fb = EndpointResult(endpoint=endpoint, path="SATOM cache · %s" % self.CACHE[key], layers=layers)
        fb.rows = len(rows)
        try:
            parse({"results": rows, "status": "success",
                   "vdom": (self.source.config or {}).get("vdom") or "root"} if self.BODY else rows, fb)
        except Exception as exc:  # noqa: BLE001 — unexpected shape = error, not empty
            fb.ok, fb.error = False, "device read failed (%s); unexpected cached shape: %s" % (res.error[:120], exc)
            fb.facts, fb.metrics = [], []
        else:
            fb.error = "device read failed (%s) — from SATOM's snapshot %s UTC" % (
                res.error[:160], at.strftime("%Y-%m-%d %H:%M"))
        fb.elapsed_ms = res.elapsed_ms + int((time.monotonic() - started) * 1000)
        return fb

    def collect(self):
        out = super().collect()
        mode = EndpointResult(endpoint="read mode", path="SATOM · appliance", layers=("device",))
        mode.facts.append(FactRow("device", "device", "read_mode", "direct, as SATOM"))
        return out + [mode]


class SatomFortiWeb(_DirectAsSatom, FortiWebConnector):
    kind = "fortiweb"
    label = "FortiWeb (direct, as SATOM)"
    CACHE = {
        "/api/v2.0/cmdb/system/interface": "interface_2",
        "/api/v2.0/cmdb/router/static": "route",
        "/api/v2.0/cmdb/system/vip": "vip",
        "/api/v2.0/cmdb/server-policy/policy": "server_policy",
        "/api/v2.0/cmdb/server-policy/server-pool": "server_pool",
    }


class SatomFortiGate(_DirectAsSatom, FortiGateConnector):
    kind = "fortigate"
    label = "FortiGate (direct, as SATOM)"
    BODY = True
    CACHE = {
        "/api/v2/cmdb/system/interface": "system_interface",
        "/api/v2/cmdb/firewall/address": "firewall_address",
        "/api/v2/cmdb/firewall/addrgrp": "firewall_addrgrp",
        "/api/v2/cmdb/firewall.service/custom": "firewall_service_custom",
        "/api/v2/cmdb/firewall.service/group": "firewall_service_group",
        "/api/v2/cmdb/firewall/policy": "firewall_policy",
        "/api/v2/cmdb/system/sdwan": "system_sdwan",
    }


#: Source.kind stays the product (what the overview, insights and graph key on).
BY_PRODUCT = {"fortiweb": SatomFortiWeb, "fortigate": SatomFortiGate, "fortiadc": SatomFortiADC,
              "fortiauthenticator": SatomFortiAuthenticator, "fortianalyzer": SatomFortiAnalyzer}
