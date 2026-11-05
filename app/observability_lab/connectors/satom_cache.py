"""FortiADC, FortiAuthenticator and FortiAnalyzer: read from SATOM's device
cache only (operator request 2026-11-05: "why are the devices SATOM has not
here").

These connectors never talk to the device: what they know is SATOM's last
configuration snapshot (``device_objects``), and every fact says so — the
snapshot time is a fact (``config_snapshot_at``) and an old snapshot is an
alert, because a FortiADC whose licence is invalid cannot be read by SATOM
either (fortiadc10 / fortiadc11 since 2026-10-25/26). Live state (link,
counters, back-end health) is NOT invented: interfaces carry no link state and
back-ends say ``not read``.

Shapes measured on the lab caches 2026-11-05: FortiADC 7.6.7 / 8.0.4
(``system_interface`` ``ip`` = "a.b.c.d/len", ``router_static`` ``dest``/``gw``,
``load_balance_virtual_server`` → ``load_balance_content_routing`` /
``load_balance_pool`` (child ``pool_member.real_server_id``) →
``load_balance_real_server.address``); FortiAuthenticator 8.0.3 (CLI rows,
``ip`` = "a.b.c.d/mask"); FortiAnalyzer 7.6.7 (``ip`` = [addr, mask],
``system_route`` ``dst`` = [addr, mask]).
"""
from __future__ import annotations

import ipaddress
import time
from datetime import datetime, timezone

from .. import satom_bridge
from . import Connector, EndpointResult, FactRow, register

#: A configuration snapshot older than this is reported (it is all we know).
STALE_SNAPSHOT_H = 48


def _cidr(ip, mask=None) -> str:
    """'a/len', 'a/dotted', ['a', 'dotted'] or ('a', 'dotted') -> 'a/len' ('' if none)."""
    if isinstance(ip, (list, tuple)):
        ip, mask = (list(ip) + [None])[:2]
    ip = str(ip or "").strip()
    if mask is None and " " in ip:
        ip, mask = ip.split(None, 1)
    if mask is None and "/" in ip:
        ip, mask = ip.split("/", 1)
    try:
        itf = ipaddress.ip_interface("%s/%s" % (ip, str(mask or "32").strip()))
    except ValueError:
        return ""
    return "" if itf.ip.is_unspecified else "%s/%d" % (itf.ip, itf.network.prefixlen)


def _net(dst, mask=None) -> str:
    """'a/len', 'a dotted', ['a', 'dotted'] -> 'net/len' ('' if not a network)."""
    if isinstance(dst, (list, tuple)):
        dst, mask = (list(dst) + [None])[:2]
    text_ = str(dst or "").strip()
    if mask is None and " " in text_:
        text_, mask = text_.split(None, 1)
    try:
        return str(ipaddress.ip_network(text_ if mask is None else "%s/%s" % (text_, str(mask).strip()), strict=False))
    except ValueError:
        return ""


class SatomCacheConnector(Connector):
    """Base of every source inside SATOM: NOTHING here talks to a device.

    * configuration: SATOM's cache (``config`` layer; ``deep`` for nested
      tables), one visible step per table;
    * live state: the series SATOM's own collectors write (``satom_*`` in
      SATOM's VictoriaMetrics), one step per SATOM collector with its state;
    * what SATOM does not collect for this product is a step marked
      "not collected by SATOM", never a device read and never a guess.
    The facts are stored in Observability's own tables (schema
    ``observability``) and the numbers are kept as ``obs_*`` series."""
    available = True
    uses_username = False
    uses_vdom = False
    secret_label = "Password"
    secret_help = "Not used: everything is read from SATOM."
    #: (endpoint name, SATOM logical name, layers, parser method) — config layer
    TABLES: list = []
    #: same, from SATOM's nightly ``deep`` snapshot, children nested
    DEEP: list = []
    #: (endpoint name, layers, what SATOM does not collect for this product)
    NOT_COLLECTED: list = []

    def __init__(self, source, *, secret: str = "", transport=None):
        super().__init__(source, secret="", transport=transport)
        self.appliance_id = int((source.config or {}).get("appliance_id") or 0)
        self.vdom = (source.config or {}).get("vdom") or "root"

    def _snapshot(self):
        return satom_bridge.cache_rows(self.appliance_id, "__none__", "config")[1]

    def test(self) -> dict:
        if not self.appliance_id:
            return {"ok": False, "detail": "only available for SATOM appliances", "build": ""}
        at = self._snapshot()
        if at is None:
            return {"ok": False, "detail": "SATOM holds no configuration snapshot of this device", "build": ""}
        try:
            live = satom_bridge.satom_live(self.source.name)
            col = ", ".join("%s %s" % (c, "ok" if v == 1 else "FAILING") for c, v in sorted(live["collectors"].items()))
        except satom_bridge.SatomLiveError as exc:
            col = "metrics store: %s" % exc
        return {"ok": True, "build": self.source.build or "",
                "detail": "from SATOM only — configuration snapshot %s UTC; SATOM collectors: %s; the device "
                          "itself is never contacted" % (at.strftime("%Y-%m-%d %H:%M"), col or "none")}

    def _table(self, name, logical, layers, parser, layer, cache, out):
        started = time.monotonic()
        res = EndpointResult(endpoint=name, path="SATOM %s · %s" % ("cache" if layer == "config" else layer + " snapshot", logical),
                             layers=layers)
        rows, at = (satom_bridge.cache_rows if layer == "config" else satom_bridge.cache_tree)(
            self.appliance_id, logical, layer)
        if at is None:
            if layer == "config":
                res.ok, res.error = False, "SATOM holds no configuration snapshot of this device"
            else:
                res.absent, res.error = True, "SATOM holds no %s snapshot of this device" % layer
        else:
            cache[logical if layer == "config" else layer + ":" + logical] = rows
            res.rows = len(rows)
            try:
                getattr(self, parser)(rows, res, cache)
            except Exception as exc:  # noqa: BLE001 — unexpected shape = error, not empty
                res.ok, res.error = False, "unexpected cached shape: %s" % exc
                res.facts = []
            else:
                res.error = "SATOM %s snapshot %s UTC" % (layer, at.strftime("%Y-%m-%d %H:%M"))
        res.elapsed_ms = int((time.monotonic() - started) * 1000)
        out.append(res)

    def collect(self) -> list[EndpointResult]:
        if not self.appliance_id:
            return [EndpointResult(endpoint="SATOM cache", path="SATOM cache", layers=("device",), ok=False,
                                   error="only available for SATOM appliances")]
        out, cache = [], {}
        for name, logical, layers, parser in self.TABLES:
            self._table(name, logical, layers, parser, "config", cache, out)
        for name, logical, layers, parser in self.DEEP:
            self._table(name, logical, layers, parser, "deep", cache, out)
        at = self._snapshot()
        ident = satom_bridge.appliance_identity(self.appliance_id)
        dev = EndpointResult(endpoint="identity", path="SATOM · appliance", layers=("device",))
        dev.facts += [FactRow("device", "device", "hostname", ident.get("hostname") or self.source.name),
                      FactRow("device", "device", "firmware", ident.get("firmware") or self.source.build or ""),
                      FactRow("device", "device", "read_mode", "from SATOM")]
        for k in ("serial", "model", "ha"):
            if ident.get(k):
                dev.facts.append(FactRow("device", "device", k, ident[k]))
        if at is not None:
            dev.facts.append(FactRow("device", "device", "config_snapshot_at", at.strftime("%Y-%m-%d %H:%M:%S")))
            age_h = (datetime.now(timezone.utc).replace(tzinfo=None) - at).total_seconds() / 3600
            dev.metrics.append(("obs_config_snapshot_age_hours", {}, round(age_h, 2)))
        out.insert(0, dev)
        out.extend(self._live())
        for name, layers, what in self.NOT_COLLECTED:
            out.append(EndpointResult(endpoint=name, path="not collected by SATOM", layers=layers, absent=True,
                                      error="not collected by SATOM: %s" % what))
        for r in out:
            r.metrics.append(("obs_endpoint_up", {"endpoint": r.endpoint}, 0 if not r.ok else 1))
        return out

    # ---- live state: SATOM's own collectors -------------------------------
    #: satom_* family -> (fact layer, fact key, obs metric) ; ref built per family
    BOX = {"satom_box_cpu_pct": "cpu_pct", "satom_box_mem_pct": "mem_pct", "satom_box_disk_pct": "disk_pct",
           "satom_box_sessions": "sessions"}
    IFACE = {"satom_iface_rx_bytes_total": "rx_bytes", "satom_iface_tx_bytes_total": "tx_bytes",
             "satom_iface_rx_packets_total": "rx_packets", "satom_iface_tx_packets_total": "tx_packets"}
    POLICY = {"satom_policy_sessions": "sessions", "satom_policy_conn_per_sec": "conn_per_s",
              "satom_policy_app_response_ms": "app_response_time", "satom_policy_client_rtt_ms": "client_rtt",
              "satom_policy_server_rtt_ms": "server_rtt"}

    def _live(self) -> list:
        started = time.monotonic()
        res = EndpointResult(endpoint="SATOM live metrics", path="SATOM metrics · %s" % self.source.name,
                             layers=("device", "L1", "L7"))
        try:
            live = satom_bridge.satom_live(self.source.name)
        except satom_bridge.SatomLiveError as exc:
            res.ok, res.error = False, "SATOM metrics store: %s" % exc
            return [res]
        steps = []
        for coll, v in sorted(live["collectors"].items()):
            steps.append(EndpointResult(endpoint="SATOM collector · %s" % coll, path="SATOM collector · %s" % coll,
                                        layers=("device",), ok=v == 1,
                                        error="" if v == 1 else "SATOM's collector %s is failing for this device "
                                                                "(satom_scrape_up = 0) — see SATOM › Monitoring › Collection" % coll))
        for name, labels, value in live["series"]:
            if name in self.BOX:
                res.facts.append(FactRow("device", "device", self.BOX[name], value))
                res.metrics.append(("obs_dev_%s" % self.BOX[name], {}, value))
            elif name == "satom_iface_up" and labels.get("iface"):
                res.facts.append(FactRow("if:%s" % labels["iface"], "L1", "link", "up" if value == 1 else "down"))
                res.metrics.append(("obs_if_link_up", {"interface": labels["iface"]}, value))
            elif name in self.IFACE and labels.get("iface"):
                res.facts.append(FactRow("if:%s" % labels["iface"], "L1", self.IFACE[name], value))
                res.metrics.append(("obs_if_%s" % self.IFACE[name], {"interface": labels["iface"]}, value))
            elif name in self.POLICY and labels.get("policy"):
                res.facts.append(FactRow("policy:%s" % labels["policy"], "L7", self.POLICY[name], value))
                res.metrics.append(("obs_policy_%s" % self.POLICY[name], {"policy": labels["policy"]}, value))
            elif name == "satom_policy_up" and labels.get("policy"):
                res.facts.append(FactRow("policy:%s" % labels["policy"], "L7", "live_up", value == 1))
        res.rows = len(live["series"])
        if not live["series"] and not live["collectors"]:
            res.absent, res.error = True, "SATOM runs no live collector for this device"
        else:
            res.error = "%d series from SATOM's collectors (last value within %s)" % (len(live["series"]), live["window"])
        res.elapsed_ms = int((time.monotonic() - started) * 1000)
        return [res] + steps

    def _routes_source(self, res, cache, what="configured static routes"):
        res.facts.append(FactRow("device", "device", "routes_source", "%s (SATOM cache)" % what))

    # ---- shared parsers ---------------------------------------------------
    def _if_row(self, res, name, cidr, *, admin="", itype="", vdom=None, mgmt=""):
        ref = "if:%s" % name
        if itype:
            res.facts.append(FactRow(ref, "L2", "type", itype))
        if admin:
            res.facts.append(FactRow(ref, "L2", "admin_status", admin))
        res.facts.append(FactRow(ref, "L2", "vdom", vdom or self.vdom))
        if cidr:
            res.facts += [FactRow(ref, "L3", "configured_address", cidr), FactRow(ref, "L3", "address", cidr)]
        if mgmt:
            res.facts.append(FactRow(ref, "L4", "management_access", mgmt))

    def _routes(self, res, routes):
        self._routes_source(res, None)
        for r in routes:
            r.setdefault("vdom", self.vdom)
        res.facts.append(FactRow("device", "L3", "routes", routes))
        for r in routes:
            if r.get("device"):
                res.facts.append(FactRow("if:%s" % r["device"], "L3", "route:%s" % r["dst"],
                                         "%s via %s" % (r["type"], r["gateway"])))


@register
class SatomFortiADC(SatomCacheConnector):
    kind = "fortiadc"
    label = "FortiADC (from SATOM)"
    TABLES = [
        ("interfaces", "system_interface", ("L2", "L3"), "_p_if"),
        ("static routes", "router_static", ("L3",), "_p_routes"),
        ("real servers", "load_balance_real_server", ("L7",), "_p_noop"),
        ("pools", "load_balance_pool", ("L7",), "_p_pools"),
        ("content routing", "load_balance_content_routing", ("L7",), "_p_noop"),
        ("virtual servers", "load_balance_virtual_server", ("L4", "L7"), "_p_vs"),
    ]
    NOT_COLLECTED = [("real-server health", ("L7",), "health of each real server: back-ends come from the "
                                                       "configuration, their state is not known")]

    def _p_noop(self, rows, res, cache):
        pass

    def _p_if(self, rows, res, cache):
        for i in rows:
            self._if_row(res, i.get("mkey"), _cidr(i.get("ip")), admin=str(i.get("status") or "").strip(),
                         itype=i.get("type") or "", vdom=i.get("vdom") or self.vdom,
                         mgmt=str(i.get("allowaccess") or "").strip())

    def _p_routes(self, rows, res, cache):
        self._routes(res, [{"dst": _net(r.get("dest")), "gateway": r.get("gw") or "", "device": "",
                            "type": "static", "distance": r.get("distance")} for r in rows if _net(r.get("dest"))])

    def _members(self, cache):
        rs = {r.get("mkey"): r for r in cache.get("load_balance_real_server", [])}
        out = {}
        for p in cache.get("load_balance_pool", []):
            bks = []
            for m in p.get("pool_member") or []:
                r = rs.get(m.get("real_server_id")) or {}
                bks.append({"pool": p.get("mkey"), "address": r.get("address") or "", "port": int(m["port"]) if str(m.get("port", "")).isdigit() else m.get("port"),
                            "real_server": m.get("real_server_id"), "health": "not read",
                            "backup": m.get("backup") == "enable",
                            "enabled": m.get("status") == "enable" and r.get("status", "enable") == "enable"})
            out[p.get("mkey")] = bks
        return out

    def _p_pools(self, rows, res, cache):
        for p in rows:
            ref = "pool:%s" % p.get("mkey")
            res.facts += [FactRow(ref, "L7", "members", len(p.get("pool_member") or [])),
                          FactRow(ref, "L7", "health_check", (p.get("health_check_list") or "").strip()
                                  if p.get("health_check") == "enable" else "none")]

    def _p_vs(self, rows, res, cache):
        members = self._members(cache)
        cr = {c.get("mkey"): c.get("pool") for c in cache.get("load_balance_content_routing", [])}
        for v in rows:
            name = v.get("mkey")
            pools = [v.get("pool")] if v.get("pool") else []
            if v.get("content-routing") == "enable":
                pools += [cr.get(c) for c in (v.get("content-routing-list") or "").split() if cr.get(c)]
            pools = list(dict.fromkeys(p for p in pools if p))
            bks = [b for p in pools for b in members.get(p, [])]
            listen = "%s:%s" % (v.get("address") or "", str(v.get("port") or "").strip())
            ref = "policy:%s" % name
            res.facts += [FactRow(ref, "L7", "status", v.get("status") or ""),
                          FactRow(ref, "L4", "listen", listen),
                          FactRow(ref, "L4", "protocol", v.get("type") or ""),
                          FactRow(ref, "L7", "server_pool", ", ".join(pools)),
                          FactRow(ref, "L7", "vserver", name),
                          FactRow(ref, "L7", "object_kind", "virtual server"),
                          FactRow(ref, "L7", "backends", bks)]
            if v.get("address"):
                res.facts += [FactRow("vip:%s" % name, "L4", "vip", "%s/32" % v["address"]),
                              FactRow("vip:%s" % name, "L4", "vip_interface", v.get("interface") or "")]


@register
class SatomFortiAuthenticator(SatomCacheConnector):
    kind = "fortiauthenticator"
    label = "FortiAuthenticator (from SATOM)"
    NOT_COLLECTED = [("interface state", ("L1",), "link state and counters of the interfaces")]
    TABLES = [("interfaces", "cli:system/interface", ("L2", "L3"), "_p_if"),
              ("static routes", "cli:router/static", ("L3",), "_p_routes")]

    def _p_if(self, rows, res, cache):
        for i in rows:
            self._if_row(res, i.get("_edit"), _cidr(i.get("ip")), mgmt=i.get("allowaccess") or "")

    def _p_routes(self, rows, res, cache):
        self._routes(res, [{"dst": _net(r.get("dst")), "gateway": r.get("gateway") or "", "device": r.get("device") or "",
                            "type": "static", "distance": None} for r in rows if _net(r.get("dst"))])


@register
class SatomFortiAnalyzer(SatomCacheConnector):
    kind = "fortianalyzer"
    label = "FortiAnalyzer (from SATOM)"
    NOT_COLLECTED = [("interface state", ("L1",), "link state and counters of the interfaces")]
    TABLES = [("interfaces", "system_interface", ("L2", "L3"), "_p_if"),
              ("static routes", "system_route", ("L3",), "_p_routes")]

    def _p_if(self, rows, res, cache):
        for i in rows:
            self._if_row(res, i.get("name"), _cidr(i.get("ip")))

    def _p_routes(self, rows, res, cache):
        self._routes(res, [{"dst": _net(r.get("dst")), "gateway": r.get("gateway") or "", "device": r.get("device") or "",
                            "type": "static", "distance": None} for r in rows if _net(r.get("dst"))])


def _strip_port(v):
    v = str(v or "").strip().split()[0] if str(v or "").strip() else ""
    return int(v) if v.isdigit() else None


class SatomFortiWeb(SatomCacheConnector):
    """FortiWeb inside SATOM: configuration from SATOM's cache, back-ends and
    listeners from its nightly ``deep`` snapshot, live policy and interface
    numbers from SATOM's ``policies``/``interfaces``/``box`` collectors."""
    kind = "fortiweb"
    label = "FortiWeb (from SATOM)"
    TABLES = [
        ("interfaces", "interface_2", ("L2", "L3"), "_fw_if"),
        ("static routes", "route", ("L3",), "_fw_routes"),
        ("virtual IPs", "vip", ("L4",), "_fw_vip"),
        ("services", "services_custom", ("L4",), "_noop"),
        ("predefined services", "services_predefined", ("L4",), "_noop"),
        ("server policies", "server_policy", ("L4", "L7"), "_fw_policy"),
        ("server pools", "server_pool", ("L7",), "_fw_pool"),
    ]
    DEEP = [("listeners and back-ends", "server_policy", ("L4", "L7"), "_fw_deep")]
    NOT_COLLECTED = [
        ("back-end health", ("L7",), "health of each back-end server (FortiWeb policystatus.detail): back-ends "
                                     "come from the configuration, their state is not known"),
        ("licence", ("device",), "VM licence state (system status vmLicense)"),
        ("v-zones", ("L2",), "v-zone membership (not in SATOM's cache)"),
        ("policy routes", ("L3",), "policy routes (not in SATOM's cache)"),
    ]

    def _noop(self, rows, res, cache):
        pass

    def _fw_if(self, rows, res, cache):
        from .fortiweb import FortiWebConnector
        FortiWebConnector._p_interface(rows, res)

    def _fw_routes(self, rows, res, cache):
        from .fortiweb import FortiWebConnector
        FortiWebConnector._p_routes(rows, res)
        self._routes_source(res, cache)

    def _fw_vip(self, rows, res, cache):
        from .fortiweb import FortiWebConnector
        FortiWebConnector._p_vip(rows, res)

    def _fw_policy(self, rows, res, cache):
        from .fortiweb import FortiWebConnector
        FortiWebConnector._p_policy(rows, res)
        for p in rows:
            ref = "policy:%s" % p.get("name")
            res.facts += [FactRow(ref, "L7", "status", p.get("status", "")),
                          FactRow(ref, "L4", "protocol", p.get("protocol", ""))]

    def _fw_pool(self, rows, res, cache):
        from .fortiweb import FortiWebConnector
        FortiWebConnector._p_pool(rows, res)

    def _fw_deep(self, rows, res, cache):
        ports = {s.get("name"): _strip_port(s.get("port"))
                 for s in cache.get("services_custom", []) + cache.get("services_predefined", [])}
        vips = {v.get("name"): str(v.get("vip") or "").split("/")[0] for v in cache.get("vip", [])}
        ifip = {i.get("name"): str(i.get("ip") or "").split("/")[0] for i in cache.get("interface_2", [])}
        cfg = {c.get("name"): c for c in cache.get("server_policy", [])}  # fresher than the nightly deep
        for p in rows:
            ref = "policy:%s" % p.get("name")
            c = cfg.get(p.get("name")) or p
            port = ports.get(c.get("service")) or ports.get(c.get("https-service"))
            addrs = []
            for vs in p.get("vserver") or []:
                for e in vs.get("vip-list") or []:
                    if e.get("use-interface-ip") == "enable":
                        addrs.append(ifip.get(e.get("interface")) or "")
                    else:
                        nested = (e.get("vip") if isinstance(e.get("vip"), list) else None) or []
                        addrs.append(str(nested[0].get("vip") or "").split("/")[0] if nested else
                                     vips.get(e.get("vip"), ""))
            addrs = [a for a in addrs if a and not a.startswith("0.0.0.0")]
            if addrs:
                res.facts.append(FactRow(ref, "L4", "listen", "%s:%s" % (addrs[0], port if port else "")))
            backends = []
            for pool in p.get("server_pool") or []:
                for ps in pool.get("pserver-list") or []:
                    backends.append({"pool": pool.get("name"), "address": ps.get("ip") or ps.get("domain") or "",
                                     "port": ps.get("port"), "health": "not read",
                                     "backup": ps.get("backup-server") == "enable",
                                     "enabled": ps.get("status") == "enable"})
            if p.get("server_pool"):
                res.facts.append(FactRow(ref, "L7", "backends", backends))


class SatomFortiGate(SatomCacheConnector):
    """FortiGate inside SATOM: configuration (interfaces, addresses, groups,
    services, policies in sequence order, SD-WAN, static routes) from SATOM's
    cache; CPU/memory/sessions from SATOM's ``box`` collector."""
    kind = "fortigate"
    label = "FortiGate (from SATOM)"
    TABLES = [
        ("interfaces", "system_interface", ("L2", "L3"), "_fg_ifcfg"),
        ("static routes", "router_static", ("L3",), "_fg_static"),
        ("addresses", "firewall_address", ("L3",), "_fg_address"),
        ("address groups", "firewall_addrgrp", ("L3",), "_fg_addrgrp"),
        ("services", "firewall_service_custom", ("L4",), "_fg_service"),
        ("service groups", "firewall_service_group", ("L4",), "_fg_svcgrp"),
        ("firewall policies", "firewall_policy", ("L4",), "_fg_polcfg"),
        ("sd-wan", "system_sdwan", ("L3",), "_fg_sdwan"),
    ]
    NOT_COLLECTED = [
        ("routing table", ("L3",), "live routing table — only the configured static routes are known, "
                                   "dynamic (BGP/OSPF) and SD-WAN-installed routes are not"),
        ("interface state", ("L1",), "link state and counters of the interfaces (SATOM runs no interfaces "
                                     "collector for FortiGate)"),
        ("policy counters", ("L4",), "hits, bytes and active sessions per firewall policy"),
        ("detected devices", ("L2", "L3"), "hosts the FortiGate has seen"),
        ("licence", ("device",), "licence status"),
        ("policy routes", ("L3",), "policy routes (not in SATOM's cache)"),
    ]

    def _body(self, fn, rows, res):
        from .fortigate import FortiGateConnector
        getattr(FortiGateConnector, fn)({"results": rows, "status": "success", "vdom": self.vdom}, res)

    def _fg_ifcfg(self, rows, res, cache):
        self._body("_p_ifcfg", rows, res)

    def _fg_address(self, rows, res, cache):
        self._body("_p_address", rows, res)

    def _fg_addrgrp(self, rows, res, cache):
        self._body("_p_addrgrp", rows, res)

    def _fg_service(self, rows, res, cache):
        self._body("_p_service", rows, res)

    def _fg_svcgrp(self, rows, res, cache):
        self._body("_p_svcgrp", rows, res)

    def _fg_polcfg(self, rows, res, cache):
        self._body("_p_polcfg", rows, res)

    def _fg_sdwan(self, rows, res, cache):
        self._body("_p_sdwan", rows, res)

    def _fg_static(self, rows, res, cache):
        routes = []
        for r in rows:
            if str(r.get("status") or "enable") != "enable" or str(r.get("blackhole") or "") == "enable":
                continue
            dst = _net(r.get("dst"))
            if dst:
                routes.append({"dst": dst, "gateway": r.get("gateway") or "", "device": r.get("device") or "",
                               "type": "static", "distance": r.get("distance"), "vdom": self.vdom})
        self._routes(res, routes)
