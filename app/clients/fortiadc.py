"""FortiADC REST client (token auth).

Conventions (FortiADC 8.0 REST API — cross-checked against the official
Ansible httpapi plugin ``fadcos`` and the ``terraform-provider-fortiadc``
SDK; re-verify live once a lab device exists — see docs/fortiadc.md):

* login: ``POST /api/user/login`` ``{username, password}`` → ``{"token": …}``;
  later calls carry ``Authorization: Bearer <token>`` AND the login cookies
  (the official httpapi plugin sends both).
* object paths mirror the CLI tree with separators flattened to underscores:
  ``config load-balance virtual-server`` → ``/api/load_balance_virtual_server``.
  Paths are registry-resolved (``registry.loader.resolve_adc``) — callers
  never hardcode URLs.
* responses wrap data in ``{"payload": …}`` — an array for collection GETs,
  an object/1-element array for single reads, a NUMBER for write results
  (negative = device error code).
* single object: ``?mkey=<name>``; child tables ride dedicated
  ``<parent>_child_<table>`` endpoints scoped by ``?pkey=<parent>`` (child
  row keyed by ``&mkey=``).
* multi-tenant boxes take ``?vdom=<name>`` (``global`` = omit).
"""
from __future__ import annotations

from .base import BaseClient


class FortiADCError(RuntimeError):
    """A device-level refusal (negative payload / error body / HTTP >= 400)."""


class FortiADCClient(BaseClient):
    def __init__(self, appliance, timeout: float = 30.0):
        """
        appliance: Appliance model instance with attributes:
            host, port, verify_ssl, username, password (decrypted)
        """
        super().__init__(appliance.host, appliance.port, appliance.verify_ssl, timeout)
        self._username = appliance.username
        self._password = appliance.password
        self._token = None
        self._cookies = None

    def login(self):
        resp = self._request(
            'POST',
            '/api/user/login',
            json={"username": self._username, "password": self._password},
        )
        resp.raise_for_status()
        self._token = resp.json().get('token', '')
        # BaseClient opens a fresh httpx.Client per request, so the login
        # session cookie must be carried explicitly alongside the Bearer token.
        self._cookies = dict(resp.cookies) or None

    def _headers(self):
        if not self._token:
            self.login()
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _api(self, method: str, path: str, **kwargs):
        return self._request(method, path, headers=self._headers(),
                             cookies=self._cookies, **kwargs)

    # -- payload envelope ---------------------------------------------------

    @staticmethod
    def _device_error(resp) -> str | None:
        """A human-readable device error, or None when the response is usable."""
        if resp.status_code >= 400:
            detail = ''
            try:
                j = resp.json()
                detail = str(j.get('errcode') or j.get('error')
                             or j.get('payload') or '')[:200]
            except Exception:  # noqa: BLE001
                pass
            return f"HTTP {resp.status_code}" + (f" — {detail}" if detail else "")
        try:
            j = resp.json()
        except Exception:  # noqa: BLE001
            return "unparseable response body"
        if isinstance(j, dict):
            p = j.get('payload')
            # FortiADC signals refusals as a negative integer payload.
            if isinstance(p, int) and p < 0:
                return f"device errcode {p}"
        return None

    @staticmethod
    def _payload(resp):
        j = resp.json()
        if isinstance(j, dict):
            return j.get('payload', j.get('data', j))
        return j

    # -- generic, registry-resolved CRUD ------------------------------------

    def _resolve(self, logical: str) -> str:
        from ..registry import loader
        return loader.resolve_adc(logical)

    def list_with_error(self, logical: str, **params):
        """(rows, error) for a collection endpoint — device refusals surface
        as ``error`` instead of masquerading as an empty list (the FortiWeb
        license-lock lesson, applied here from day one)."""
        try:
            resp = self._api('GET', self._resolve(logical), params=params or None)
        except KeyError as exc:
            return [], str(exc)
        except Exception as exc:  # noqa: BLE001 — transport
            return [], f"{type(exc).__name__}: {exc}"
        err = self._device_error(resp)
        if err:
            return [], err
        rows = self._payload(resp)
        if isinstance(rows, dict):
            rows = [rows]
        return (rows if isinstance(rows, list) else []), None

    def get_object(self, logical: str, mkey: str, **params):
        resp = self._api('GET', self._resolve(logical),
                         params={'mkey': mkey, **params})
        err = self._device_error(resp)
        if err:
            raise FortiADCError(err)
        data = self._payload(resp)
        # a ?mkey= read may still return a 1-element array
        if isinstance(data, list):
            data = data[0] if data else {}
        return data

    def create(self, logical: str, data: dict, **params):
        resp = self._api('POST', self._resolve(logical), json=data,
                         params=params or None)
        err = self._device_error(resp)
        if err:
            raise FortiADCError(err)
        return self._payload(resp)

    def update(self, logical: str, mkey: str, data: dict, **params):
        resp = self._api('PUT', self._resolve(logical), json=data,
                         params={'mkey': mkey, **params})
        err = self._device_error(resp)
        if err:
            raise FortiADCError(err)
        return self._payload(resp)

    def delete(self, logical: str, mkey: str, **params):
        resp = self._api('DELETE', self._resolve(logical),
                         params={'mkey': mkey, **params})
        err = self._device_error(resp)
        if err:
            raise FortiADCError(err)
        return self._payload(resp)

    # -- legacy convenience (kept for existing callers) ----------------------

    def list_virtual_servers(self):
        return self._api('GET', '/api/load_balance_virtual_server').json()

    def list_pools(self):
        return self._api('GET', '/api/load_balance_pool').json()

    def platform_version(self) -> dict:
        """``/api/platform/version`` → ``{build, hostname, model, version}``.
        VERIFIED LIVE on FortiADC-KVM 8.0.3 — the old ``/api/system/status``
        does NOT exist on FortiADC (404), so the connectivity check and the
        firmware/model inventory both key off this endpoint."""
        resp = self._api('GET', '/api/platform/version')
        err = self._device_error(resp)
        if err:
            raise FortiADCError(err)
        data = self._payload(resp)
        return data if isinstance(data, dict) else {}

    def status_check(self):
        return self.platform_version()

    def ha_status(self):
        """Best-effort live HA status as a flat dict (FortiADC). Returns {} on
        failure so the resolver degrades to 'standalone'/'unknown'."""
        for path in ('/api/system_ha_status', '/api/system_ha'):
            try:
                raw = self._api('GET', path).json()
            except Exception:
                continue
            if isinstance(raw, dict):
                data = raw.get('payload', raw)
                if isinstance(data, dict) and data:
                    return data
        return {}

    # -- runtime telemetry --------------------------------------------------
    #
    # FortiADC has no ``monitor/`` namespace. Guessing names returns a flat 404
    # for every candidate (probed live, 2026-08-06), so these were censused out
    # of the GUI's own bundle (``/ui/js/all.min.js``): the console builds its
    # calls as ``/api/<entity>/<_method>``, which is a different shape from the
    # ``/api/<object>`` cmdb surface the registry drives.
    #
    # NOT usable, and the reason matters:
    #   ``/api/platform/resources`` returns "1 CPU/1 allowed", " 3831 MB RAM" —
    #   installed hardware, not utilisation. Parsing it as a percentage would
    #   publish a fabricated series. CPU and memory therefore keep coming from
    #   ``get system performance`` over the read-only CLI.

    def _runtime(self, path: str, **params):
        """GET a runtime endpoint, returning its ``payload`` (or None)."""
        resp = self._api('GET', path, params=params or None)
        if self._device_error(resp) or resp.status_code != 200:
            return None
        try:
            body = resp.json()
        except ValueError:
            return None
        return body.get('payload') if isinstance(body, dict) else None

    def vs_status(self, vdom: str = 'root', vsname: str | None = None):
        """Aggregate (or per-virtual-server) runtime counters.

        This is FortiADC's analogue of FortiWeb's ``policystatus``: ONE call
        carries sessions, RTT, byte and request/error counters for the whole
        vdom, so a device with 500 virtual servers costs one round trip rather
        than 500. VERIFIED LIVE on 8.0.3 — keys: current_sessions,
        total_sessions, limit_sessions, in_bytes, out_bytes, requests,
        request_errors, response_errors, client_rtt, server_rtt, app_response.
        """
        params = {'vdom': vdom}
        if vsname:
            params['vsname'] = vsname
        return self._runtime('/api/status_history/vs_status', **params)

    def vs_list(self, vdom: str = 'root'):
        """Virtual servers with their runtime state (list; [] when none)."""
        rows = self._runtime('/api/all_vs_info/vs_list', vdom=vdom)
        return rows if isinstance(rows, list) else []

    def pool_member_list(self, vdom: str = 'root'):
        """Pool members with health-check state (list; [] when none)."""
        rows = self._runtime('/api/all_vs_info/pool_member_list', vdom=vdom)
        return rows if isinstance(rows, list) else []

    def interface_info(self, vdom: str = 'root'):
        """Interface runtime (link, addressing, counters); [] when none."""
        rows = self._runtime('/api/system_interface/interface_info', vdom=vdom)
        return rows if isinstance(rows, list) else []

    def ha_peer_status(self, vdom: str = 'root'):
        """``system_ha/peerstatus`` — mode, local_state, peers. {} on failure."""
        data = self._runtime('/api/system_ha/peerstatus', vdom=vdom)
        return data if isinstance(data, dict) else {}

    def api_call(self, method: str, path: str, data=None):
        return self._api(method, path, json=data)

    # -- certificate deployment (REST) --------------------------------------

    def upload_local_certificate(self, name: str, cert_pem: str, key_pem: str):
        """Upload a Local certificate (cert + private key PEM) over REST.

        The FortiADC GUI posts this as a multipart form to
        ``/api/upload/certificate_local`` with ``type=CertKey`` and the PEMs as
        file parts ``cert``/``key`` (found in the GUI JS bundle; VERIFIED LIVE on
        FortiADC-KVM 8.0.3 — a wildcard cert+key imported and bound cleanly).
        The manager only UPLOADS material a CA/third party generated; REST cmdb
        cannot carry a PEM, exactly like the FortiWeb SSH path.
        """
        if not self._token:
            self.login()
        headers = {"Authorization": f"Bearer {self._token}"}  # no JSON CT — multipart
        files = {
            "cert": (f"{name}.crt", cert_pem, "application/x-pem-file"),
            "key": (f"{name}.key", key_pem, "application/x-pem-file"),
        }
        resp = self._request(
            "POST", "/api/upload/certificate_local",
            headers=headers, cookies=self._cookies, files=files,
            data={"mkey": name, "type": "CertKey"},
        )
        err = self._device_error(resp)
        if err:
            raise FortiADCError(err)
        return self._payload(resp)

    def bind_https_admin_cert(self, name: str):
        """Point the admin GUI HTTPS server cert at *name* (``system_global``
        ``https-server-cert``). VERIFIED LIVE on FortiADC-KVM 8.0.3."""
        return self.update('system_global', '', {'https-server-cert': name})
