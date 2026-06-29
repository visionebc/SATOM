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
