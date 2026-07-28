import base64
import json
from urllib.parse import quote
from .base import BaseClient


class FortiWebClient(BaseClient):
    def __init__(self, appliance, timeout: float = 30.0):
        """
        appliance: Appliance model instance with attributes:
            host, port, verify_ssl, username, password (decrypted), vdom
        """
        super().__init__(appliance.host, appliance.port, appliance.verify_ssl, timeout)
        self._username = appliance.username
        self._password = appliance.password
        self._vdom = getattr(appliance, 'vdom', None)

    def _auth_token(self) -> str:
        payload = {"username": self._username, "password": self._password}
        if self._vdom:
            payload["vdom"] = self._vdom
        raw = json.dumps(payload, separators=(",", ":")) + "\n"
        return base64.b64encode(raw.encode("utf-8")).decode("ascii")

    def _headers(self):
        return {
            "Authorization": self._auth_token(),
            "Content-Type": "application/json",
        }

    def get(self, path):
        return self._request('GET', path, headers=self._headers())

    def post(self, path, data=None):
        return self._request('POST', path, headers=self._headers(), json=data)

    def put(self, path, data=None):
        return self._request('PUT', path, headers=self._headers(), json=data)

    def delete(self, path):
        return self._request('DELETE', path, headers=self._headers())

    def status_check(self):
        return self.get('/api/v2.0/system/status.systemstatus').json()

    def ha_status(self):
        """Best-effort live HA member/role info as a flat dict.

        Tries the HA monitor endpoint then falls back to system status / the HA
        cmdb object; returns {} on any failure so the resolver degrades to
        'standalone'/'unknown'. The exact 7.x monitor path is verified live and
        may be pinned here once an HA cluster confirms it."""
        for path in (
            '/api/v2.0/system/ha-status.member',
            '/api/v2.0/system/status.systemstatus',
            '/api/v2.0/cmdb/system/ha',
        ):
            try:
                data = self._results_one(self.get(path).json())
                if data:
                    return data
            except Exception:
                continue
        return {}

    def list_server_policies(self):
        return self.get('/api/v2.0/cmdb/server-policy/policy').json()

    # --- response-envelope helpers (FortiWeb wraps cmdb reads in {"results": ...}) ---
    @staticmethod
    def _results_one(raw):
        """A single cmdb object out of a (possibly mkey-scoped) response."""
        if isinstance(raw, dict):
            res = raw.get('results', raw.get('data'))
            if isinstance(res, dict) and res.get('errcode') not in (None, 0):
                return {}  # error envelope (e.g. errcode -3 "not found") -> empty
            if isinstance(res, list):
                return res[0] if res else {}
            if isinstance(res, dict):
                return res
            return raw if 'name' in raw else {}
        return {}

    @staticmethod
    def _results_list(raw):
        if isinstance(raw, dict):
            res = raw.get('results', raw.get('data'))
            if isinstance(res, dict) and res.get('errcode') not in (None, 0):
                return []  # error envelope -> no rows
            if isinstance(res, list):
                return res
            if isinstance(res, dict):
                return [res]
        return raw if isinstance(raw, list) else []

    def _safe_one(self, path: str):
        try:
            return self._results_one(self.get(path).json())
        except Exception:
            return {}

    def _safe_list(self, path: str):
        try:
            return self._results_list(self.get(path).json())
        except Exception:
            return []

    # --- error-surfacing reads (Configuration browser) -----------------------
    _BENIGN_ERRCODES = {'-20001', '-3'}  # absent on this firmware / not found

    @staticmethod
    def _device_error(resp):
        """A human-readable device refusal for a cmdb read, else None.

        FortiWeb signals failures two ways: an HTTP error status (423 license
        lock, 401 auth) and/or an errcode envelope — sometimes top-level
        ({"errcode": "-20010", ...}), sometimes nested under "results". Both are
        surfaced; errcode -20001/-3 (object absent on this firmware / not
        found) stays benign because the registry is a cross-firmware superset.
        """
        try:
            j = resp.json()
        except Exception:  # noqa: BLE001 - non-JSON body
            return ('HTTP %s' % resp.status_code) if resp.status_code >= 400 else None
        body = j if isinstance(j, dict) else {}
        res = body.get('results')
        if isinstance(res, dict) and res.get('errcode') not in (None, 0, '0'):
            body = res
        code = body.get('errcode')
        if code in (None, 0, '0'):
            return ('HTTP %s' % resp.status_code) if resp.status_code >= 400 else None
        if str(code) in FortiWebClient._BENIGN_ERRCODES:
            return None
        msg = body.get('message') or ''
        return ('device error %s: %s' % (code, msg)) if msg else ('device error %s' % code)

    def list_with_error(self, path: str):
        """(rows, error) — like _safe_list, but a device refusal (license lock,
        auth failure, unreachable host) is RETURNED instead of reading as []."""
        try:
            resp = self.get(path)
        except Exception as exc:  # noqa: BLE001 - transport-level failure
            return [], str(exc)
        err = self._device_error(resp)
        if err:
            return [], err
        try:
            return self._results_list(resp.json()), None
        except Exception as exc:  # noqa: BLE001
            return [], str(exc)

    def get_server_policy(self, name: str):
        """The full server-policy object, unwrapped from the results envelope."""
        return self._results_one(
            self.get('/api/v2.0/cmdb/server-policy/policy?mkey=%s' % quote(name, safe='')).json())

    def policy_full(self, name: str) -> dict:
        """A server policy plus its linked objects — mirrors the desktop app's
        ``operations.policy_full`` composite read: virtual server (+ VIPs), server
        pool (+ back-end servers), health check and web-protection profile.

        By-parent sub-tables (vip-list, pserver-list) are read through the logical
        ``?mkey=<parent>`` form; the path-style ``/<parent>/<sub-list>`` form leaks
        the whole parent collection when the sub-table is empty (FortiWeb quirk)."""
        q = lambda v: quote(v, safe='')
        policy = self.get_server_policy(name)
        out = {'policy': policy}
        vs = policy.get('vserver')
        sp = policy.get('server-pool')
        wpp = policy.get('web-protection-profile')
        if vs:
            out['vserver'] = self._safe_one('/api/v2.0/cmdb/server-policy/vserver?mkey=%s' % q(vs))
            out['vips'] = self._resolve_vip_ips(
                self._safe_list('/api/v2.0/cmdb/server-policy/vserver/vip-list?mkey=%s' % q(vs)))
        if sp:
            pool = self._safe_one('/api/v2.0/cmdb/server-policy/server-pool?mkey=%s' % q(sp))
            out['pool'] = pool
            out['backends'] = self._safe_list(
                '/api/v2.0/cmdb/server-policy/server-pool/pserver-list?mkey=%s' % q(sp))
            health = pool.get('health') if isinstance(pool, dict) else None
            if health:
                out['health'] = self._safe_one('/api/v2.0/cmdb/server-policy/health?mkey=%s' % q(health))
        if wpp:
            out['wpp'] = self._safe_one(
                '/api/v2.0/cmdb/waf/web-protection-profile.inline-protection?mkey=%s' % q(wpp))
        return out

    def list_virtual_servers(self):
        return self.get('/api/v2.0/cmdb/server-policy/vserver').json()

    def list_pools(self):
        return self.get('/api/v2.0/cmdb/server-policy/server-pool').json()

    def list_wpp(self):
        return self.get('/api/v2.0/cmdb/waf/web-protection-profile.inline-protection').json()

    # --- reference-option + interface helpers (for the editable workspace) ----
    def cmdb_names(self, endpoint: str):
        """Object names from one or more cmdb collections ('a|b' = merged),
        for populating a reference <select>. Never raises (returns [])."""
        seen, out = set(), []
        for ep in (endpoint or '').split('|'):
            ep = ep.strip()
            if not ep:
                continue
            path = ep if ep.startswith('/api/') else '/api/v2.0/cmdb/' + ep.lstrip('/')
            for o in self._safe_list(path):
                n = o.get('name') if isinstance(o, dict) else None
                if n and n not in seen:
                    seen.add(n)
                    out.append(n)
        return out

    def interface_ip(self, name: str):
        """Resolve a system interface's configured IP (CIDR), cached per client.
        Returns '' for unset (0.0.0.0/0) or unknown interfaces."""
        if not name:
            return ''
        cache = getattr(self, '_iface_ip_cache', None)
        if cache is None:
            cache = self._iface_ip_cache = {}
        if name in cache:
            return cache[name]
        obj = self._safe_one('/api/v2.0/cmdb/system/interface?mkey=%s' % quote(name, safe=''))
        ip = (obj.get('ip') or '').strip() if isinstance(obj, dict) else ''
        if ip.startswith('0.0.0.0'):
            ip = ''
        cache[name] = ip
        return ip

    def _resolve_vip_ips(self, vips):
        """Annotate each VIP row with the IP it actually answers on — the
        interface IP when use-interface-ip=enable (otherwise the explicit vip).
        Fixes the 'VIP shows no IP' case where the address comes from the port."""
        for v in vips or []:
            use_if = str(v.get('use-interface-ip', '')).lower() in ('enable', 'enabled', '1', 'true')
            if use_if and v.get('interface'):
                v['effective_ip'] = self.interface_ip(v['interface'])
                v['ip_source'] = 'interface (%s)' % v['interface']
            elif v.get('vip'):
                v['effective_ip'] = v['vip']
                v['ip_source'] = 'static'
            else:
                v['effective_ip'] = ''
                v['ip_source'] = ''
        return vips

    # --- runtime backend health (policy status monitor, NOT cmdb) -----------
    def policy_health(self, name: str):
        """Live per-backend health for one server policy.

        Reads the RUNTIME monitor endpoint policy/policystatus.detail
        (?policy_name=<name> query param, not a cmdb read) -> one row per
        pool member carrying healthCheckStatus (enable=UP / disable=DOWN /
        N-A=no health check). Returns (members, error) so a device refusal
        (license lock, auth failure, unreachable host) is surfaced rather than
        read as an empty list. Verified live on fw6 7.6.8.
        """
        path = ('/api/v2.0/policy/policystatus.detail?policy_name=%s'
                % quote(name, safe=''))
        return self.list_with_error(path)

    # --- live monitor endpoints (runtime telemetry, NOT cmdb) ---------------
    #
    # FortiWeb 7.6 has no ``/api/v2.0/monitor/<resource>`` tree: that prefix
    # answers ONLY ``monitor/permission-check``. Runtime telemetry lives at
    # ``/api/v2.0/<family>/<object>.<view>``. Every path below was enumerated
    # out of the appliance's own GUI bundle (``/ng/app/dashboard/*.js``) and
    # then verified live against fortiweb08 7.6.8 build1128 (2026-07-28) —
    # guessing at plausible URLs produced nothing but ``-20001 invalid URL``.
    #
    # All of these return (value, error) so a licence lock (HTTP 423
    # ``-20010``) is surfaced as an error instead of being read as "no traffic".

    def system_resource(self):
        """Box gauges: cpu, mem, logDisk, dbStatus, diskUsage, sessionCount,
        connCntPerSec. Source of the GUI's System Resources widget."""
        return self._monitor_one('/api/v2.0/system/status.systemresource')

    def system_operation(self):
        """Per-interface live counters: ip_netmask, speedDuplex, link, tx/rx
        packets and tx_bytes/rx_bytes (cumulative since boot).

        This is the LIVE interface state — unlike the harvest cache, it can
        tell "no data" apart from "no change".
        """
        return self._monitor_one('/api/v2.0/system/status.systemoperation')

    def policy_status(self):
        """One row per server policy with sessionCount, connCntPerSec,
        client_rtt, server_rtt, app_response_time and the runtime ``policy``
        handle. Source of the GUI's Policy Sessions widget."""
        return self.list_with_error('/api/v2.0/policy/policystatus')

    def policy_traffic(self, name: str):
        """Throughput series for one policy, or for the aggregate pseudo-policy
        ``Total HTTP Throughput`` (``Total FTP/ADFS Throughput`` also exist, and
        in VDOM mode the names become ``Administrative Domain <X> Traffic``).

        Returns 60 samples, one per second, oldest first. **Values are BYTES per
        second as strings** — the GUI multiplies by 8 and divides by 1024 to
        render Kb/s. A bare list means no web-cache; a dict carries
        ``throughput`` plus ``cache_enabled``/``cache_tp``.
        """
        path = ('/api/v2.0/policy/policytraffic?policy_name=%s'
                % quote(name, safe=''))
        return self._monitor_one(path)

    def http_transactions(self, name: str, hours: int = 1):
        """Bucketed HTTP transaction counts for ONE policy over ``hours``.

        ``time`` is a number of hours and drives the bucket width the appliance
        picks (1h -> 5 min buckets, 24h -> 2h buckets). The aggregate
        pseudo-policies are NOT accepted here: a bad name yields an empty
        ``errcode 0`` envelope rather than an error, so callers must pass a real
        policy name.
        """
        path = ('/api/v2.0/system/status.httptransactions?time=%d&policy=%s'
                % (int(hours), quote(name, safe='')))
        return self.list_with_error(path)

    def _monitor_one(self, path: str):
        """GET a monitor path returning (results, error).

        ``results`` may legitimately be a dict OR a list depending on the
        widget, so this does not force either shape the way ``_results_one``
        does.
        """
        try:
            resp = self.get(path)
        except Exception as exc:  # noqa: BLE001 — an unreachable box is a result
            return None, str(exc)
        err = self._device_error(resp)
        if err:
            return None, err
        try:
            raw = resp.json()
        except Exception as exc:  # noqa: BLE001
            return None, 'unparseable response: %s' % exc
        if isinstance(raw, dict) and 'results' in raw:
            return raw['results'], None
        return raw, None

    def api_call(self, method: str, path: str, data=None):
        return self._request(method, path, headers=self._headers(), json=data)

    def upload(self, path, files, data=None, timeout: float | None = None):
        """Multipart POST (e.g. firmware ``imageFile`` upload).

        Only the Authorization header is sent — httpx sets the multipart
        ``Content-Type`` + boundary itself, so we must NOT pin
        ``application/json`` here as the JSON helpers do.
        """
        kwargs = {"headers": {"Authorization": self._auth_token()}, "files": files}
        if data is not None:
            kwargs["data"] = data
        if timeout is not None:
            kwargs["timeout"] = timeout
        return self._request('POST', path, **kwargs)

    def download_backup(self, name: str) -> bytes:
        return self._request('GET', f'/System/Maintenance/Backup/{name}', headers=self._headers()).content
