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
    """Base: one EndpointResult per cached table, a visible job step each."""
    available = True
    uses_username = False
    uses_vdom = False
    secret_label = "Password"
    secret_help = "Not used: this product is read from SATOM's cache only."
    #: (endpoint name, SATOM logical name, layers, parser method)
    TABLES: list = []

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
        return {"ok": True, "build": self.source.build or "",
                "detail": "read from SATOM's cache (snapshot %s UTC); the device itself is not contacted"
                          % at.strftime("%Y-%m-%d %H:%M")}

    def collect(self) -> list[EndpointResult]:
        if not self.appliance_id:
            return [EndpointResult(endpoint="SATOM cache", path="SATOM cache", layers=("device",), ok=False,
                                   error="only available for SATOM appliances")]
        out, cache = [], {}
        for name, logical, layers, parser in self.TABLES:
            started = time.monotonic()
            res = EndpointResult(endpoint=name, path="SATOM cache · %s" % logical, layers=layers)
            rows, at = satom_bridge.cache_rows(self.appliance_id, logical, "config")
            if at is None:
                res.ok, res.error = False, "SATOM holds no configuration snapshot of this device"
            else:
                cache[logical] = rows
                res.rows = len(rows)
                try:
                    getattr(self, parser)(rows, res, cache)
                except Exception as exc:  # noqa: BLE001 — unexpected shape = error, not empty
                    res.ok, res.error = False, "unexpected cached shape: %s" % exc
                    res.facts = []
                else:
                    res.error = "SATOM snapshot %s UTC" % at.strftime("%Y-%m-%d %H:%M")
            res.elapsed_ms = int((time.monotonic() - started) * 1000)
            out.append(res)
        at = self._snapshot()
        dev = EndpointResult(endpoint="identity", path="SATOM cache · appliance", layers=("device",))
        dev.facts += [FactRow("device", "device", "hostname", self.source.name),
                      FactRow("device", "device", "firmware", self.source.build or ""),
                      FactRow("device", "device", "read_mode", "SATOM cache only")]
        if at is not None:
            dev.facts.append(FactRow("device", "device", "config_snapshot_at", at.strftime("%Y-%m-%d %H:%M:%S")))
            age_h = (datetime.now(timezone.utc).replace(tzinfo=None) - at).total_seconds() / 3600
            dev.metrics.append(("obs_config_snapshot_age_hours", {}, round(age_h, 2)))
        out.insert(0, dev)
        for r in out:
            r.metrics.append(("obs_endpoint_up", {"source": self.source.name, "endpoint": r.endpoint}, 1 if r.ok else 0))
        return out

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
    label = "FortiADC (from SATOM cache)"
    TABLES = [
        ("interfaces", "system_interface", ("L2", "L3"), "_p_if"),
        ("static routes", "router_static", ("L3",), "_p_routes"),
        ("real servers", "load_balance_real_server", ("L7",), "_p_noop"),
        ("pools", "load_balance_pool", ("L7",), "_p_pools"),
        ("content routing", "load_balance_content_routing", ("L7",), "_p_noop"),
        ("virtual servers", "load_balance_virtual_server", ("L4", "L7"), "_p_vs"),
    ]

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
    label = "FortiAuthenticator (from SATOM cache)"
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
    label = "FortiAnalyzer (from SATOM cache)"
    TABLES = [("interfaces", "system_interface", ("L2", "L3"), "_p_if"),
              ("static routes", "system_route", ("L3",), "_p_routes")]

    def _p_if(self, rows, res, cache):
        for i in rows:
            self._if_row(res, i.get("name"), _cidr(i.get("ip")))

    def _p_routes(self, rows, res, cache):
        self._routes(res, [{"dst": _net(r.get("dst")), "gateway": r.get("gateway") or "", "device": r.get("device") or "",
                            "type": "static", "distance": None} for r in rows if _net(r.get("dst"))])
