"""``fortinet_source = satom``: the same FortiWeb / FortiGate connectors, with
the configuration read from SATOM's device cache instead of the device.

What SATOM caches (cmdb tables) is served from ``device_objects`` through the
SAME parsers the direct connectors use — the cache holds the REST rows, so the
facts are identical. What SATOM does not hold (live interface state and
counters, policy status and sessions, back-end health, licence, routing table,
firewall-policy counters, detected devices) is read from the device exactly as
the direct connector does: GET only, with the credential SATOM holds for that
appliance, decrypted by SATOM in memory and never stored here.

Each cache read is a visible job step ("SATOM cache · …") with the age of the
snapshot it came from.
"""
from __future__ import annotations

import time

from .. import satom_bridge
from . import EndpointResult
from .fortigate import FortiGateConnector
from .fortiweb import FortiWebConnector


class _FromSatom:
    #: REST path -> (SATOM logical name, layer)
    CACHE: dict = {}
    #: True when the parser takes the whole body (FortiGate), False for rows.
    BODY = False

    def __init__(self, source, *, secret: str = "", transport=None):
        aid = int((source.config or {}).get("appliance_id") or 0)
        user, pw = satom_bridge.credentials(aid)
        super().__init__(source, secret=pw, transport=transport)
        self.appliance_id = aid
        self.satom_user = user

    def _read(self, client, endpoint, path, layers, parse):
        key = path.split("?")[0]
        # SATOM caches ONE VDOM per appliance: a per-VDOM read goes to the device.
        if key in self.CACHE and "vdom=" not in path:
            logical, layer = self.CACHE[key]
            started = time.monotonic()
            rows, at = satom_bridge.cache_rows(self.appliance_id, logical, layer)
            if at is not None:
                res = EndpointResult(endpoint=endpoint, path="SATOM cache · %s" % logical, layers=layers)
                res.rows = len(rows)
                try:
                    parse({"results": rows, "status": "success",
                           "vdom": (self.source.config or {}).get("vdom") or "root"} if self.BODY else rows, res)
                except Exception as exc:  # noqa: BLE001 — unexpected shape = error, not empty
                    res.ok, res.error = False, "unexpected cached shape: %s" % exc
                    res.facts, res.metrics = [], []
                else:
                    res.error = "SATOM snapshot %s UTC" % at.strftime("%Y-%m-%d %H:%M")
                res.elapsed_ms = int((time.monotonic() - started) * 1000)
                return res
            # SATOM never captured this table: read it from the device.
        return super()._read(client, endpoint, path, layers, parse)


class SatomFortiWeb(_FromSatom, FortiWebConnector):
    kind = "satom-fortiweb"
    label = "FortiWeb (from SATOM)"
    CACHE = {
        "/api/v2.0/cmdb/system/interface": ("interface_2", "config"),
        "/api/v2.0/cmdb/router/static": ("route", "config"),
        "/api/v2.0/cmdb/system/vip": ("vip", "config"),
        "/api/v2.0/cmdb/server-policy/policy": ("server_policy", "config"),
        "/api/v2.0/cmdb/server-policy/server-pool": ("server_pool", "config"),
    }


class SatomFortiGate(_FromSatom, FortiGateConnector):
    kind = "satom-fortigate"
    label = "FortiGate (from SATOM)"
    BODY = True
    CACHE = {
        "/api/v2/cmdb/system/interface": ("system_interface", "config"),
        "/api/v2/cmdb/firewall/address": ("firewall_address", "config"),
        "/api/v2/cmdb/firewall/policy": ("firewall_policy", "config"),
        "/api/v2/cmdb/system/sdwan": ("system_sdwan", "config"),
        "/api/v2/cmdb/firewall/addrgrp": ("firewall_addrgrp", "config"),
        "/api/v2/cmdb/firewall.service/custom": ("firewall_service_custom", "config"),
        "/api/v2/cmdb/firewall.service/group": ("firewall_service_group", "config"),
    }


#: Source.kind stays the product (fortiweb/fortigate: what the overview,
#: insights and graph key on); the class is chosen by ``fortinet_source``.
from .satom_cache import SatomFortiADC, SatomFortiAnalyzer, SatomFortiAuthenticator  # noqa: E402

BY_PRODUCT = {"fortiweb": SatomFortiWeb, "fortigate": SatomFortiGate, "fortiadc": SatomFortiADC,
              "fortiauthenticator": SatomFortiAuthenticator, "fortianalyzer": SatomFortiAnalyzer}
