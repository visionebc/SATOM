"""FortiGate (FortiOS) REST client — read-only base.

Transport: ``https://<host>:<port>/api/v2/{cmdb,monitor}/...`` with a REST API
administrator token sent as ``Authorization: Bearer``. The token travels in the
appliance's encrypted ``password`` column (same envelope as the FortiAuthenticator
API key); ``username`` is informational only (the api-user name).

What FortiOS does that shapes this module (measured on fgt02, FortiOS 8.0.1
build0245, 2026-10-07):

* Every answer — success or error — carries ``version``/``build``/``serial``,
  so the build of the box is known from any call, not just the status one.
* An unknown cmdb path answers **400** (``status: error``), not 200 with the
  parent's rows the way FortiWeb does. A 200 here really means "served".
* An UNLICENSED VM answers 401 to everything except ``license/status``. The
  error text says so, because "wrong token" and "no licence" look identical.
* A read-only ``accprofile`` reads cmdb and monitor per table, but the global
  schema index (``/api/v2/cmdb/?action=schema`` with no table) is 403.

Every read returns ``(payload, error)``; a refusal is never an empty result.
"""
from __future__ import annotations

from .base import BaseClient, DeviceAuthError, response_summary


class FortiGateError(RuntimeError):
    """A device-level refusal (HTTP error, unparseable body)."""


def cmdb_url(path: str) -> str:
    """``firewall.service/custom`` → ``/api/v2/cmdb/firewall.service/custom``."""
    return '/api/v2/cmdb/' + path.strip('/')


class FortiGateClient(BaseClient):
    def __init__(self, appliance, timeout: float = 30.0):
        super().__init__(appliance.host, appliance.port or 443,
                         appliance.verify_ssl, timeout)
        self._token = appliance.password or ''
        self._vdom = (getattr(appliance, 'vdom', None) or '').strip()

    # -- transport ------------------------------------------------------------

    def _headers(self) -> dict:
        return {'Authorization': f'Bearer {self._token}',
                'Accept': 'application/json'}

    def _call(self, method: str, path: str, params=None):
        """(payload, error) for one request. ``payload`` is the whole JSON
        envelope (``results`` plus version/build/serial)."""
        q = dict(params or {})
        if self._vdom and 'vdom' not in q:
            q['vdom'] = self._vdom
        try:
            resp = self._request(method, path, headers=self._headers(),
                                 params=q or None)
        except Exception as exc:  # noqa: BLE001 — transport
            return None, f'{type(exc).__name__}: {exc}'
        if resp.status_code == 401:
            return None, ('401 unauthorized — the API token was refused, or '
                          'the FortiGate-VM has no valid licence (an '
                          'unlicensed VM answers 401 to every REST call '
                          'except license/status). '
                          + response_summary(resp))
        if resp.status_code == 403:
            return None, ('403 forbidden — the token authenticated but its '
                          'admin profile does not grant this resource, or '
                          'the source address is not a trusted host.')
        if resp.status_code == 404:
            return None, f'404 — no such resource on this firmware: {path}'
        if resp.status_code >= 400:
            return None, f'HTTP {resp.status_code}: {response_summary(resp)}'
        try:
            return resp.json(), None
        except Exception:  # noqa: BLE001 — non-JSON body
            return None, f'unparseable response body: {response_summary(resp)}'

    # -- reads ----------------------------------------------------------------

    def cmdb(self, path: str, **params):
        """(results, error) for one cmdb path. ``results`` is a list for a
        table and a dict for a single-instance setting, exactly as served."""
        payload, err = self._call('GET', cmdb_url(path), params)
        if err:
            return None, err
        if not isinstance(payload, dict) or 'results' not in payload:
            return None, 'response has no "results" member'
        return payload.get('results'), None

    def sys_status(self) -> dict:
        """``GET /api/v2/monitor/system/status`` flattened: version, build,
        serial plus the model/hostname block."""
        payload, err = self._call('GET', '/api/v2/monitor/system/status')
        if err:
            if err.startswith('401'):
                raise DeviceAuthError(err)
            raise FortiGateError(err)
        out = dict(payload.get('results') or {}) if isinstance(payload, dict) else {}
        for k in ('version', 'build', 'serial'):
            if isinstance(payload, dict) and k in payload:
                out[k] = payload[k]
        return out

    def status_check(self):
        return self.sys_status()

    def ha_status(self) -> dict:
        """Not wired in the base ADOM: an empty dict means "unknown", which
        ``services.ha_inventory`` never reads as standalone."""
        return {}

    def api_call(self, method: str, path: str, data=None, **params):
        """Raw explorer entry point. GET only in the base ADOM — a write verb
        is refused here, not sent."""
        if method.upper() != 'GET':
            return None, 'FortiGate base ADOM is read-only: only GET is sent.'
        return self._call('GET', path, params)
