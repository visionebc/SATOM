"""FortiGate, read directly from the appliance (``fortinet_source = direct``).

Transport and auth are SATOM's (``app/clients/fortigate.py``): FortiOS REST
``/api/v2/{monitor,cmdb}/...`` with a REST API administrator token as
``Authorization: Bearer`` — GET only, so the read-only transport holds without
exceptions. The token belongs to an ``api-user`` with a read-only profile and
this server as its only trusted host.

Every parser reads only fields measured on fgt02 (FortiGate-VM64-KVM v8.0.2
build0251, 2026-11-05, token ``observability`` / profile ``satom-ro``); the
answers are the fixtures in ``tests/fixtures/fortigate-8.0.2``. Other builds:
"unverified on this build" until measured. Not read yet because fgt02 has none
to measure: IPsec tunnels, SD-WAN health checks, HA peers, VIPs.
"""
from __future__ import annotations

import ipaddress
import json
import time

from .. import http_ro
from . import Connector, EndpointResult, FactRow, register

VERIFIED_BUILDS = ("v8.0.2",)
#: Usage counters the device reports as "current" (cpu/mem/disk in %).
USAGE_KEYS = {"cpu": "cpu_pct", "mem": "mem_pct", "disk": "disk_pct",
              "session": "sessions", "setuprate": "session_setup_rate"}


def device_error(status: int, body) -> tuple[str, bool]:
    """(error, absent). HTTP 200 is not success: the envelope is read.
    404 = the build does not serve the path (measured on 8.0.x)."""
    if status == 404:
        return "", True
    if status == 401:
        return "HTTP 401: token rejected (wrong key, or this server is not a trusted host)", False
    if status == 403:
        return "HTTP 403: the token's profile cannot read this", False
    if status >= 400:
        return "HTTP %s" % status, False
    if not isinstance(body, dict):
        return "HTTP %s: not JSON" % status, False
    if body.get("status") not in (None, "success"):
        return "device error: %s (HTTP %s)" % (body.get("error") or body.get("status"), body.get("http_status", status)), False
    return "", False


def _cidr(ip_mask: str) -> str:
    """'192.0.2.14 255.255.255.0' -> '192.0.2.14/24'; '' for 0.0.0.0."""
    parts = (ip_mask or "").split()
    if len(parts) != 2 or parts[0] == "0.0.0.0":
        return ""
    try:
        return str(ipaddress.ip_interface("%s/%s" % tuple(parts)))
    except ValueError:
        return ip_mask


def _names(v) -> list:
    return [x.get("name") for x in v if isinstance(x, dict)] if isinstance(v, list) else []


@register
class FortiGateConnector(Connector):
    kind = "fortigate"
    label = "FortiGate (direct)"
    secret_label = "API key"
    secret_help = ("Key of a REST API administrator (System › Administrators › REST API Admin) with a "
                   "read-only profile and this server as its only trusted host.")
    uses_username = False
    uses_vdom = False  # VDOMs are off on fgt02; multi-VDOM is unmeasured

    def _client(self):
        cfg = self.source.config or {}
        return http_ro.make_client(verify=self.source.tls_verify, ca_pem=self.source.ca_pem or "",
                                   timeout=float(cfg.get("timeout_s", 30)), transport=self.transport)

    def _url(self, path: str) -> str:
        return "https://%s:%s%s" % (self.source.host, self.source.port or 443, path)

    def _read(self, client, endpoint, path, layers, parse) -> EndpointResult:
        res = EndpointResult(endpoint=endpoint, path=path.split("?")[0], layers=layers)
        started = time.monotonic()
        try:
            status, _h, raw = http_ro.get(
                client, self._url(path),
                headers={"Authorization": "Bearer " + self.secret, "Accept": "application/json"},
                deadline=float((self.source.config or {}).get("deadline_s", 60)))
        except Exception as exc:  # noqa: BLE001 — an unreachable box is a result
            res.ok, res.error = False, "%s: %s" % (type(exc).__name__, exc)
            return res
        finally:
            res.elapsed_ms = int((time.monotonic() - started) * 1000)
        try:
            body = json.loads(raw.decode("utf-8", "replace")) if raw else None
        except ValueError:
            body = None
        err, absent = device_error(status, body)
        if absent:
            res.absent = True
            return res
        if err:
            res.ok, res.error = False, err
            return res
        results = body.get("results")
        res.rows = len(results) if isinstance(results, (list, dict)) else 0
        try:
            parse(body, res)
        except Exception as exc:  # noqa: BLE001 — unexpected shape = error, not empty
            res.ok, res.error = False, "unexpected response shape: %s" % exc
            res.facts, res.metrics = [], []
        return res

    PLAN = [
        ("system status", "/api/v2/monitor/system/status", ("device",), "_p_status"),
        ("licence", "/api/v2/monitor/license/status", ("device",), "_p_licence"),
        ("resource usage", "/api/v2/monitor/system/resource/usage?interval=1-min", ("device",), "_p_usage"),
        ("interface state", "/api/v2/monitor/system/interface?include_vlan=true", ("L1", "L3"), "_p_ifmon"),
        ("interfaces", "/api/v2/cmdb/system/interface", ("L2", "L3"), "_p_ifcfg"),
        ("routing table", "/api/v2/monitor/router/ipv4", ("L3",), "_p_routes"),
        ("addresses", "/api/v2/cmdb/firewall/address", ("L3",), "_p_address"),
        ("detected devices", "/api/v2/monitor/user/device/query", ("L2", "L3"), "_p_devices"),
        ("firewall policies", "/api/v2/cmdb/firewall/policy", ("L4",), "_p_polcfg"),
        ("policy counters", "/api/v2/monitor/firewall/policy", ("L4",), "_p_polmon"),
    ]

    def test(self) -> dict:
        with self._client() as c:
            r = self._read(c, "system status", self.PLAN[0][1], ("device",), self._p_status)
        if not r.ok:
            return {"ok": False, "detail": r.error, "build": ""}
        f = {x.key: x.value for x in r.facts}
        build = f.get("firmware", "")
        note = "" if any(v in build for v in VERIFIED_BUILDS) else " · unverified on this build"
        return {"ok": True, "build": build, "detail": "%s · %s%s" % (f.get("hostname", "?"), build, note)}

    def capabilities(self) -> dict:
        return {
            "device": ["hostname", "firmware", "serial", "model", "licence_status", "licence_valid",
                       "cpu_pct", "mem_pct", "disk_pct", "sessions", "session_setup_rate"],
            "L1": ["link", "speed", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors"],
            "L2": ["type", "admin_status", "vlanid", "parent", "role", "alias", "mac"],
            "L3": ["address", "configured_address", "routes", "subnet"],
            "L4": ["name", "action", "srcintf", "dstintf", "srcaddr", "dstaddr", "service", "nat",
                   "hit_count", "bytes", "active_sessions", "last_used"],
        }

    def collect(self) -> list[EndpointResult]:
        with self._client() as c:
            out = [self._read(c, name, path, layers, getattr(self, parser))
                   for name, path, layers, parser in self.PLAN]
        lbl = {"source": self.source.name}
        for r in out:
            r.metrics.append(("obs_endpoint_up", dict(lbl, endpoint=r.endpoint), 1 if r.ok else 0))
        return out

    # ---- parsers ----------------------------------------------------------
    @staticmethod
    def _p_status(body, res):
        r = body.get("results") or {}
        if not r.get("hostname"):
            raise ValueError("no hostname in system status")
        model = "%s-%s" % (r.get("model_name", ""), r.get("model_number", ""))
        res.facts += [FactRow("device", "device", "hostname", r["hostname"]),
                      FactRow("device", "device", "model", model),
                      FactRow("device", "device", "firmware", "%s %s,build%04d" % (
                          model, body.get("version", ""), int(body.get("build") or 0))),
                      FactRow("device", "device", "serial", body.get("serial", ""))]

    @staticmethod
    def _p_licence(body, res):
        vm = (body.get("results") or {}).get("vm")
        if isinstance(vm, dict):  # VM platform licence; hardware has none here
            res.facts += [FactRow("device", "device", "licence_status", vm.get("status", "")),
                          FactRow("device", "device", "licence_valid", bool(vm.get("valid")))]
            res.metrics.append(("obs_dev_licence_valid", {}, 1 if vm.get("valid") else 0))

    @staticmethod
    def _p_usage(body, res):
        r = body.get("results") or {}
        for src, key in USAGE_KEYS.items():
            cur = (r.get(src) or [{}])[0].get("current")
            if isinstance(cur, (int, float)):
                res.facts.append(FactRow("device", "device", key, cur))
                res.metrics.append(("obs_dev_%s" % key, {}, cur))

    @staticmethod
    def _p_ifmon(body, res):
        rows = body.get("results")
        if not isinstance(rows, dict):
            raise ValueError("interface state is not a map")
        for name, i in rows.items():
            ref = "if:%s" % name
            link = "up" if i.get("link") else "down"
            res.facts += [FactRow(ref, "L1", "link", link)]
            if i.get("speed"):
                res.facts.append(FactRow(ref, "L1", "speed", "%d Mbps%s" % (i["speed"], " full duplex" if i.get("duplex") == 1 else "")))
            for k in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors"):
                if isinstance(i.get(k), (int, float)):
                    res.facts.append(FactRow(ref, "L1", k, i[k]))
                    res.metrics.append(("obs_if_%s" % k, {"interface": name}, i[k]))
            res.metrics.append(("obs_if_link_up", {"interface": name}, 1 if i.get("link") else 0))
            if i.get("ip") and i.get("ip") != "0.0.0.0":
                res.facts.append(FactRow(ref, "L3", "address", "%s/%s" % (i["ip"], i.get("mask", ""))))
            if i.get("mac"):
                res.facts.append(FactRow(ref, "L2", "mac", i["mac"]))

    @staticmethod
    def _p_ifcfg(body, res):
        for i in body.get("results") or []:
            ref = "if:%s" % i.get("name")
            res.facts += [FactRow(ref, "L2", "type", i.get("type", "")),
                          FactRow(ref, "L2", "admin_status", i.get("status", ""))]
            for k in ("role", "alias"):
                if i.get(k) and i.get(k) != "undefined":
                    res.facts.append(FactRow(ref, "L2", k, i[k]))
            if i.get("vlanid"):
                res.facts.append(FactRow(ref, "L2", "vlanid", i["vlanid"]))
            if i.get("interface"):
                res.facts.append(FactRow(ref, "L2", "parent", i["interface"]))
            cidr = _cidr(i.get("ip", ""))
            if cidr:
                res.facts.append(FactRow(ref, "L3", "configured_address", cidr))
            if i.get("allowaccess"):
                res.facts.append(FactRow(ref, "L4", "management_access", i["allowaccess"]))

    @staticmethod
    def _p_routes(body, res):
        routes = [{"dst": r.get("ip_mask"), "gateway": r.get("gateway"), "device": r.get("interface"),
                   "type": r.get("type"), "distance": r.get("distance")} for r in body.get("results") or []]
        res.facts.append(FactRow("device", "L3", "routes", routes))
        for r in routes:
            if r["device"]:
                res.facts.append(FactRow("if:%s" % r["device"], "L3", "route:%s" % r["dst"],
                                         "%s via %s" % (r["type"], r["gateway"])))

    @staticmethod
    def _p_address(body, res):
        for a in body.get("results") or []:
            ref = "address:%s" % a.get("name")
            sub = _cidr(a.get("subnet", ""))
            value = sub or a.get("fqdn") or ("%s-%s" % (a["start-ip"], a["end-ip"]) if a.get("start-ip") else "")
            if value:
                res.facts.append(FactRow(ref, "L3", "subnet", value))
            if a.get("associated-interface"):
                res.facts.append(FactRow(ref, "L3", "interface", a["associated-interface"]))

    @staticmethod
    def _p_devices(body, res):
        for d in body.get("results") or []:
            if not d.get("mac"):
                continue
            ref = "endpoint:%s" % d["mac"]
            res.facts += [FactRow(ref, "L2", "interface", d.get("detected_interface", "")),
                          FactRow(ref, "L2", "online", bool(d.get("is_online")))]
            if d.get("ipv4_address"):
                res.facts.append(FactRow(ref, "L3", "address", d["ipv4_address"]))
            for k in ("hostname", "os_name", "hardware_vendor"):
                if d.get(k) and d.get(k) != "Unknown":
                    res.facts.append(FactRow(ref, "L2", k, d[k]))

    @staticmethod
    def _p_polcfg(body, res):
        for p in body.get("results") or []:
            ref = "fwpolicy:%s" % p.get("policyid")
            res.facts += [FactRow(ref, "L4", "name", p.get("name", "")),
                          FactRow(ref, "L4", "status", p.get("status", "")),
                          FactRow(ref, "L4", "action", p.get("action", "")),
                          FactRow(ref, "L4", "nat", p.get("nat", ""))]
            for k in ("srcintf", "dstintf", "srcaddr", "dstaddr", "service"):
                res.facts.append(FactRow(ref, "L4", k, _names(p.get(k))))

    @staticmethod
    def _p_polmon(body, res):
        for p in body.get("results") or []:
            pid = p.get("policyid")
            ref = "fwpolicy:%s" % pid
            for k in ("hit_count", "bytes", "packets", "active_sessions"):
                if isinstance(p.get(k), (int, float)):
                    res.facts.append(FactRow(ref, "L4", k, p[k]))
                    res.metrics.append(("obs_fwpolicy_%s" % k, {"policy": str(pid)}, p[k]))
            if p.get("last_used"):
                res.facts.append(FactRow(ref, "L4", "last_used",
                                         time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(p["last_used"]))))
