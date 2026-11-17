"""FortiWeb, read directly from the appliance (``fortinet_source = direct``).

Endpoints and response shapes were taken from SATOM's API library for
FortiWeb 7.6.8 and verified live against fortiweb19 (7.6.8 build1128,
2026-11-05); the captured answers are the test fixtures in
``tests/fixtures/fortiweb-7.6.8``. Other builds: "unverified on this build"
until measured.

Auth is SATOM's: a base64 JSON ``{"username","password"[,"vdom"]}`` in the
Authorization header of every GET — no login POST, so the GET-only transport
holds for this product without exceptions.
"""
from __future__ import annotations

import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from .. import http_ro
from . import Connector, EndpointResult, FactRow, register

VERIFIED_BUILDS = ("7.6.8",)
#: errcodes that mean "this build does not serve that path" / "not found":
#: benign, the endpoint is reported as absent, not as an error.
BENIGN = {"-20001", "-3"}
DEFAULT_MAX_DETAIL = 60


def _rows(body):
    res = body.get("results") if isinstance(body, dict) else None
    if isinstance(res, list):
        return res
    if isinstance(res, dict):
        return [res]
    return []


def device_error(status: int, body) -> tuple[str, bool]:
    """(error, absent). HTTP 200 is not success: the body is read.

    FortiWeb answers failures as an HTTP error status (423 licence lock, 401
    auth), an errcode envelope (top level or under ``results``), or both.
    """
    if not isinstance(body, dict):
        return ("HTTP %s: not JSON" % status if status >= 400 or body is None else ""), False
    env = body
    res = body.get("results")
    if isinstance(res, dict) and res.get("errcode") not in (None, 0, "0"):
        env = res
    code = env.get("errcode")
    if code not in (None, 0, "0"):
        if str(code) in BENIGN:
            return "", True
        msg = env.get("message") or ""
        return ("device error %s%s (HTTP %s)" % (code, ": " + msg if msg else "", status)), False
    if status == 401:
        return "HTTP 401: credentials rejected (account, trusted hosts or lockout)", False
    if status >= 400:
        return "HTTP %s" % status, False
    payload = body.get("payload")
    if isinstance(payload, str) and "licen" in payload.lower():
        return "licence: %s" % payload, False
    return "", False


def _num(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        try:
            return float(str(v).strip())
        except (TypeError, ValueError):
            return None


@register
class FortiWebConnector(Connector):
    kind = "fortiweb"
    label = "FortiWeb (direct)"

    # ---- transport -------------------------------------------------------
    def _auth(self) -> str:
        payload = {"username": self.source.username, "password": self.secret}
        vdom = (self.source.config or {}).get("vdom")
        if vdom:
            payload["vdom"] = vdom
        raw = json.dumps(payload, separators=(",", ":")) + "\n"
        return base64.b64encode(raw.encode()).decode()

    def _client(self):
        return http_ro.make_client(verify=self.source.tls_verify, ca_pem=self.source.ca_pem or "",
                                   timeout=float((self.source.config or {}).get("timeout_s", 30)),
                                   transport=self.transport)

    def _base(self) -> str:
        return "https://%s:%s" % (self.source.host, self.source.port or 443)

    def _get(self, client, path):
        """(status, body, elapsed_ms); a transport failure raises."""
        started = time.monotonic()
        status, _h, raw = http_ro.get(
            client, self._base() + path, headers={"Authorization": self._auth(),
                                                  "Accept": "application/json"},
            deadline=float((self.source.config or {}).get("deadline_s", 60)))
        try:
            body = json.loads(raw.decode("utf-8", "replace")) if raw else None
        except ValueError:
            body = None
        return status, body, int((time.monotonic() - started) * 1000)

    def _read(self, client, endpoint, path, layers, parse) -> EndpointResult:
        res = EndpointResult(endpoint=endpoint, path=path.split("?")[0], layers=layers)
        try:
            status, body, res.elapsed_ms = self._get(client, path)
        except Exception as exc:  # noqa: BLE001 — an unreachable box is a result
            res.ok, res.error = False, "%s: %s" % (type(exc).__name__, exc)
            return res
        err, absent = device_error(status, body)
        if absent:
            res.absent = True
            return res
        if err:
            res.ok, res.error = False, err
            return res
        rows = _rows(body)
        res.rows = len(rows)
        try:
            parse(rows, res)
        except Exception as exc:  # noqa: BLE001 — unexpected shape = error, not empty
            res.ok, res.error = False, "unexpected response shape: %s" % exc
            res.facts, res.metrics = [], []
        return res

    # ---- contract --------------------------------------------------------
    def test(self) -> dict:
        with self._client() as c:
            r = self._read(c, "system status", "/api/v2.0/system/status.systemstatus",
                           ("device",), self._p_status)
        if not r.ok:
            return {"ok": False, "detail": r.error, "build": ""}
        facts = {f.key: f.value for f in r.facts}
        build = facts.get("firmware", "")
        notes = []
        if not any(v in build for v in VERIFIED_BUILDS):
            notes.append("unverified on this build")
        if str(facts.get("vm_licence", "")).lower() == "invalid":
            notes.append("VM licence invalid: some features (signatures) are inactive")
        return {"ok": True, "build": build,
                "detail": "%s · %s%s" % (facts.get("hostname", "?"), build,
                                         (" · " + "; ".join(notes)) if notes else "")}

    def capabilities(self) -> dict:
        return {
            "device": ["hostname", "firmware", "serial", "vm_licence", "ha", "mode"],
            "L1": ["link", "speed_duplex", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets"],
            "L2": ["type", "vlanid", "parent", "mtu", "admin_status", "v_zone_members"],
            "L3": ["address", "routes", "policy_routes"],
            "L4": ["vip", "vip_interface", "service", "listen", "protocol"],
            "L7": ["vserver", "server_pool", "wpp", "status", "sessions", "client_rtt",
                   "server_rtt", "app_response_time", "lb_algo", "health_check",
                   "backends"],
        }

    def collect(self) -> list[EndpointResult]:
        out = []
        cfg = self.source.config or {}
        with self._client() as c:
            plan = [
                ("system status", "/api/v2.0/system/status.systemstatus", ("device",), self._p_status),
                ("interface state", "/api/v2.0/system/status.systemoperation", ("L1", "L3"), self._p_operation),
                ("interfaces", "/api/v2.0/cmdb/system/interface", ("L2", "L3"), self._p_interface),
                ("v-zones", "/api/v2.0/cmdb/system/v-zone", ("L2",), self._p_vzone),
                ("static routes", "/api/v2.0/cmdb/router/static", ("L3",), self._p_routes),
                ("policy routes", "/api/v2.0/cmdb/router/policy", ("L3",), self._p_proutes),
                ("virtual IPs", "/api/v2.0/cmdb/system/vip", ("L4",), self._p_vip),
                ("server policies", "/api/v2.0/cmdb/server-policy/policy", ("L4", "L7"), self._p_policy),
                ("server pools", "/api/v2.0/cmdb/server-policy/server-pool", ("L7",), self._p_pool),
                ("policy status", "/api/v2.0/policy/policystatus", ("L4", "L7"), self._p_pstatus),
            ]
            for name, path, layers, parse in plan:
                out.append(self._read(c, name, path, layers, parse))

            pstat = next(r for r in out if r.endpoint == "policy status")
            names = [f.object_ref.split(":", 1)[1] for f in pstat.facts
                     if f.key == "status" and f.value == "enable"]
            limit = int(cfg.get("max_policy_detail", DEFAULT_MAX_DETAIL))
            skipped = max(0, len(names) - limit)
            names = names[:limit]

            def one(pname):
                return self._read(c, "backend health · %s" % pname,
                                  "/api/v2.0/policy/policystatus.detail?policy_name=%s" % quote(pname, safe=""),
                                  ("L7",), lambda rows, res, p=pname: self._p_detail(p, rows, res))
            with ThreadPoolExecutor(max_workers=4) as pool:
                out.extend(pool.map(one, names))
            if skipped:
                out.append(EndpointResult(endpoint="backend health (capped)", path="",
                                          layers=("L7",), ok=True,
                                          error="%d enabled policies not read (max_policy_detail=%d)"
                                          % (skipped, limit)))
        lbl = {"source": self.source.name}
        for r in out:
            r.metrics.append(("obs_endpoint_up", dict(lbl, endpoint=r.endpoint), 0 if not r.ok else 1))
        return out

    # ---- parsers (one per endpoint; facts only from fields we measured) ---
    @staticmethod
    def _p_status(rows, res):
        s = rows[0] if rows else {}
        if not s:
            raise ValueError("empty system status")
        dev = "device"
        for key, field in (("hostname", "hostName"), ("firmware", "firmwareVersion"),
                           ("serial", "serialNumber"), ("vm_licence", "vmLicense"),
                           ("ha", "haStatus"), ("mode", "operationMode"),
                           ("adom", "administrativeDomain")):
            if field in s:
                res.facts.append(FactRow(dev, "device", key, s[field]))

    @staticmethod
    def _p_operation(rows, res):
        net = (rows[0] or {}).get("network") if rows else None
        if not isinstance(net, list):
            raise ValueError("no 'network' list in system operation")
        for i in net:
            ref = "if:%s" % i.get("name")
            link = str(i.get("link", ""))
            res.facts += [FactRow(ref, "L1", "link", link),
                          FactRow(ref, "L1", "speed_duplex", i.get("speedDuplex", ""))]
            for k, f in (("rx_bytes", "rx_bytes"), ("tx_bytes", "tx_bytes"),
                         ("rx_packets", "rx"), ("tx_packets", "tx")):
                v = _num(i.get(f))
                if v is not None:
                    res.facts.append(FactRow(ref, "L1", k, v))
                    res.metrics.append(("obs_if_%s" % k, {"interface": i.get("name")}, v))
            res.metrics.append(("obs_if_link_up", {"interface": i.get("name")}, 1 if link.lower() == "up" else 0))
            ip = i.get("ip_netmask", "")
            if ip and not ip.startswith("0.0.0.0"):
                res.facts.append(FactRow(ref, "L3", "address", ip))

    @staticmethod
    def _p_interface(rows, res):
        for i in rows:
            ref = "if:%s" % i.get("name")
            res.facts += [FactRow(ref, "L2", "type", i.get("type", "")),
                          FactRow(ref, "L2", "admin_status", i.get("status", ""))]
            if i.get("mtu") is not None:
                res.facts.append(FactRow(ref, "L2", "mtu", i.get("mtu")))
            if i.get("vlanid"):
                res.facts.append(FactRow(ref, "L2", "vlanid", i.get("vlanid")))
            if i.get("interface"):
                res.facts.append(FactRow(ref, "L2", "parent", i.get("interface")))
            ip = (i.get("ip") or "").strip()
            if ip and not ip.startswith("0.0.0.0"):
                res.facts.append(FactRow(ref, "L3", "configured_address", ip))
            if i.get("allowaccess"):
                res.facts.append(FactRow(ref, "L4", "management_access", i.get("allowaccess")))

    @staticmethod
    def _p_vzone(rows, res):
        for z in rows:
            res.facts.append(FactRow("vzone:%s" % z.get("name"), "L2", "v_zone_members",
                                     z.get("interfaces") or z.get("member") or ""))

    @staticmethod
    def _p_routes(rows, res):
        routes = [{"id": r.get("id"), "dst": r.get("dst"), "gateway": r.get("gateway"),
                   "device": r.get("device")} for r in rows]
        res.facts.append(FactRow("device", "L3", "routes", routes))
        for r in routes:
            if r["device"]:
                res.facts.append(FactRow("if:%s" % r["device"], "L3", "route:%s" % r["id"],
                                         "%s via %s" % (r["dst"], r["gateway"])))

    @staticmethod
    def _p_proutes(rows, res):
        res.facts.append(FactRow("device", "L3", "policy_routes", [
            {k: r.get(k) for k in ("id", "iif", "src", "dst", "gateway", "oif") if k in r}
            for r in rows]))

    @staticmethod
    def _p_vip(rows, res):
        for v in rows:
            ref = "vip:%s" % v.get("name")
            res.facts += [FactRow(ref, "L4", "vip", v.get("vip", "")),
                          FactRow(ref, "L4", "vip_interface", v.get("interface", ""))]
            if v.get("q_ref_string"):
                res.facts.append(FactRow(ref, "L4", "used_by", v["q_ref_string"].strip()))

    @staticmethod
    def _p_policy(rows, res):
        for p in rows:
            ref = "policy:%s" % p.get("name")
            res.facts += [FactRow(ref, "L7", "vserver", p.get("vserver", "")),
                          FactRow(ref, "L7", "server_pool", p.get("server-pool", "")),
                          FactRow(ref, "L7", "wpp", p.get("web-protection-profile", "")),
                          FactRow(ref, "L7", "deployment_mode", p.get("deployment-mode", "")),
                          FactRow(ref, "L4", "service", p.get("service", "")),
                          FactRow(ref, "L4", "https_service", p.get("https-service", "")),
                          FactRow(ref, "L4", "ssl", p.get("ssl", ""))]

    @staticmethod
    def _p_pool(rows, res):
        for p in rows:
            ref = "pool:%s" % p.get("name")
            res.facts += [FactRow(ref, "L7", "lb_algo", p.get("lb-algo", "")),
                          FactRow(ref, "L7", "health_check", p.get("health", "")),
                          FactRow(ref, "L7", "protocol", p.get("protocol", "")),
                          FactRow(ref, "L7", "members", p.get("sz_pserver-list", 0))]

    @staticmethod
    def _p_pstatus(rows, res):
        for p in rows:
            name = p.get("name")
            ref = "policy:%s" % name
            res.facts += [FactRow(ref, "L7", "status", p.get("status", "")),
                          FactRow(ref, "L4", "listen", "%s:%s" % ((p.get("vserver") or "").strip().split("/")[0],
                                                                  p.get("httpPort", ""))),
                          FactRow(ref, "L4", "protocol", p.get("protocol", ""))]
            for k in ("sessionCount", "connCntPerSec", "client_rtt", "server_rtt", "app_response_time"):
                v = _num(p.get(k))
                if v is not None:
                    key = {"sessionCount": "sessions", "connCntPerSec": "conn_per_s"}.get(k, k)
                    res.facts.append(FactRow(ref, "L7", key, v))
                    res.metrics.append(("obs_policy_%s" % key, {"policy": name}, v))

    @staticmethod
    def _p_detail(pname, rows, res):
        backends = []
        for b in rows:
            hc = str(b.get("healthCheckStatus", ""))
            backends.append({"pool": b.get("pool"), "address": b.get("ipDomainName"),
                             "port": b.get("port"),
                             # fortiweb19 7.6.8 answers "N/A" live; the capture had "N-A".
                             "health": {"enable": "up", "disable": "down"}.get(hc, "no health check" if hc in ("N-A", "N/A", "") else hc),
                             # the device's own word, kept as evidence ("disable" = check failing)
                             "health_raw": hc,
                             "sessions": b.get("sessionCount"), "backup": bool(b.get("backupServer"))})
        res.facts.append(FactRow("policy:%s" % pname, "L7", "backends", backends))
