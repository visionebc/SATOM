"""FortiAnalyzer JSON-RPC client (session auth).

Conventions (FortiAnalyzer 7.6 JSON-RPC — every call VERIFIED LIVE against
faz01 v7.6.7-build3737 on 2026-07-12; single endpoint ``POST /jsonrpc``):

* login: ``exec /sys/login/user`` ``{user, passwd}`` → top-level ``session``
  token; every later call carries ``"session": <token>`` in the body.
* TWO request dialects share that session, selected by the URL family:
  - **legacy** (``/sys``, ``/cli``, ``/dvmdb``, ``/task``, ``/um``, ``/pm``):
    ``{"method", "params": [{"url": …, "data": …}], "id", "session"}`` —
    response ``{"result": [{"status": {"code", "message"}, "data": …}]}``.
  - **v3** (``/logview``, ``/eventmgmt``, ``/incidentmgmt``, ``/report``,
    ``/fortiview``, ``/fazsys``, ``/ueba``, ``/soarmgmt``): the SAME shape
    PLUS ``"jsonrpc": "2.0"`` at the top and ``"apiver": 3`` inside the
    param — without both the device answers ``-32600 Missing param
    "jsonrpc"`` / ``-32013 Missing param 'uri'``. Response is JSON-RPC 2.0:
    ``{"result": {"data": …, "status": …}}`` or a top-level ``{"error"}``.
* JSON-RPC verbs are lowercase: ``get`` / ``exec`` / ``add`` / ``set`` /
  ``update`` / ``delete`` (NOT HTTP verbs).
* paths are registry-resolved (``registry.loader.resolve_faz``) — callers
  never hardcode URLs. ADOM-scoped URIs keep working with ``adom/root`` even
  when Admin Domains are disabled on the unit (verified).
"""
from __future__ import annotations

from .base import BaseClient

# URL families that require the JSON-RPC 2.0 / apiver-3 envelope.
_V3_PREFIXES = ('/logview', '/eventmgmt', '/incidentmgmt', '/report',
                '/fortiview', '/fazsys', '/ueba', '/soarmgmt')


class FortiAnalyzerError(RuntimeError):
    """A device-level refusal (non-zero status code / JSON-RPC error)."""


class FortiAnalyzerClient(BaseClient):
    def __init__(self, appliance, timeout: float = 30.0):
        """
        appliance: Appliance model instance with attributes:
            host, port, verify_ssl, username, password (decrypted)
        """
        super().__init__(appliance.host, appliance.port, appliance.verify_ssl, timeout)
        self._username = appliance.username
        self._password = appliance.password
        self._session = None

    # -- transport ------------------------------------------------------------

    def _post(self, body: dict) -> dict:
        resp = self._request('POST', '/jsonrpc', json=body)
        resp.raise_for_status()
        return resp.json()

    def login(self):
        out = self._post({
            'method': 'exec', 'id': 1,
            'params': [{'url': '/sys/login/user',
                        'data': {'user': self._username, 'passwd': self._password}}],
        })
        code = ((out.get('result') or [{}])[0].get('status') or {}).get('code')
        self._session = out.get('session')
        if code != 0 or not self._session:
            raise FortiAnalyzerError(f'login refused (code {code})')

    def logout(self):
        if self._session:
            try:
                self._post({'method': 'exec', 'id': 99, 'session': self._session,
                            'params': [{'url': '/sys/logout'}]})
            except Exception:  # noqa: BLE001 — session dies with the client anyway
                pass
            self._session = None

    @staticmethod
    def _is_v3(url: str) -> bool:
        return url.startswith(_V3_PREFIXES)

    def rpc(self, method: str, url: str, data=None, **params) -> dict:
        """One JSON-RPC call, dialect picked from the URL. Returns the raw
        decoded response body (envelope included) — see :meth:`call` for the
        (data, error) convenience wrapper."""
        if not self._session:
            self.login()
        p: dict = {'url': url}
        if data is not None:
            p['data'] = data
        if params:
            p.update(params)
        body: dict = {'method': method, 'params': [p], 'id': 1,
                      'session': self._session}
        if self._is_v3(url):
            body['jsonrpc'] = '2.0'
            p['apiver'] = 3
        return self._post(body)

    # -- envelope -------------------------------------------------------------

    @staticmethod
    def _unwrap(raw: dict):
        """(data, error) from either dialect's envelope."""
        if not isinstance(raw, dict):
            return None, 'unparseable response body'
        if 'error' in raw:  # v3 JSON-RPC 2.0 error object
            e = raw['error'] or {}
            return None, f"code {e.get('code')}: {e.get('message')}"
        res = raw.get('result')
        if isinstance(res, list):          # legacy: result = [ {status, data} ]
            res = res[0] if res else {}
        if not isinstance(res, dict):
            return None, 'unexpected result shape'
        st = res.get('status') or {}
        code = st.get('code', 0)
        # v3 returns code 0 "no data." for empty sets — that's not an error.
        if code not in (0, None):
            return None, f"device code {code}: {st.get('message')}"
        return res.get('data'), None

    def call(self, method: str, url: str, data=None, **params):
        """(data, error) — transport failures surface as ``error`` too."""
        try:
            raw = self.rpc(method, url, data, **params)
        except Exception as exc:  # noqa: BLE001 — transport
            return None, f'{type(exc).__name__}: {exc}'
        return self._unwrap(raw)

    # -- generic, registry-resolved reads --------------------------------------

    def _resolve(self, logical: str) -> str:
        from ..registry import loader
        return loader.resolve_faz(logical)

    def list_with_error(self, logical: str, **params):
        """(rows, error) for a registry endpoint — device refusals surface as
        ``error`` instead of masquerading as an empty list (the FortiWeb
        license-lock lesson, applied here from day one)."""
        try:
            url = self._resolve(logical)
        except KeyError as exc:
            return [], str(exc)
        data, err = self.call('get', url, **params)
        if err:
            return [], err
        if isinstance(data, dict):
            data = [data]
        return (data if isinstance(data, list) else []), None

    # -- platform inventory -----------------------------------------------------

    def sys_status(self) -> dict:
        """``get /sys/status`` → flat dict (Platform Type, Version, Serial …)."""
        data, err = self.call('get', '/sys/status')
        if err:
            raise FortiAnalyzerError(err)
        return data if isinstance(data, dict) else {}

    def status_check(self):
        return self.sys_status()

    def ha_status(self):
        """Best-effort live HA status as a flat dict. ``{}`` on failure so the
        resolver degrades to 'standalone'/'unknown'."""
        data, _err = self.call('get', '/sys/ha/status')
        return data if isinstance(data, dict) else {}

    def api_call(self, method: str, path: str, data=None, **params) -> dict:
        """Raw explorer entry point: JSON-RPC verb + URL (or already-resolved
        path) + optional data/params → the raw response envelope."""
        return self.rpc(method, path, data, **params)
