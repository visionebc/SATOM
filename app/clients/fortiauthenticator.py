"""FortiAuthenticator REST client (Django/Tastypie, HTTP Basic + API key).

Conventions (FortiAuthenticator 8.0 REST API — every behaviour below was
VERIFIED LIVE against fac01 ``FACVMKVM v8.0.3, build0099 (GA)`` on 2026-08-05).
This product does NOT speak the Fortinet CMDB dialect the other three do:

* **One path per resource**: ``GET /api/v1/<resource>/``. There is no
  ``/cmdb/`` tree and no JSON-RPC transport. ``GET /api/v1/`` returns the
  directory of all 58 resources — *without authentication*, which is why the
  registry could be censused before a key existed.
* **Auth is HTTP Basic with a per-user API key**, NOT the login password.
  Posting the admin password yields 401 even though the very same credential
  logs into the GUI. The key is issued by ticking *Web service access* on an
  Administrator account. :class:`FortiAuthenticatorError` says so explicitly on
  401, because "unauthorized" alone sends the operator to rotate the wrong
  secret.
* **Two payload shapes share one namespace.** Collections answer
  ``{"meta": {...}, "objects": [...]}``; singletons (system_info,
  system_log_settings, policy_user_lockout, …) answer a *bare object*. The
  shape is detected at RUNTIME rather than from a hand-maintained list of
  singleton names — a second list would rot out of sync with
  ``endpoints_fortiauthenticator.yaml`` the first time the vendor moves a
  resource between shapes.
* **Pagination is mandatory, and ``limit=0`` does NOT mean "all".** The default
  page is 20 rows and ``limit=0`` is clamped by the server to ``MAX_LIMIT``
  (1000, measured). A caller that trusts either one harvests a prefix of the
  fleet's users and reports success. :meth:`list_with_error` therefore walks
  ``meta.next`` to exhaustion and refuses to return a short read silently.
* Secrets are **write-only**: a canary round-trip confirmed the device omits
  ``radiusclients.secret`` and ``localusers.password`` from GET payloads
  entirely, so a snapshot cannot leak them. Re-verify after a firmware bump.
* ``POST /api/v1/localusers/`` is a **bulk** endpoint: HTTP 207 with a list
  body, no ``Location`` header, and a per-item status key the vendor spells
  ``statue``. :meth:`api_call` returns the decoded body untouched so the
  explorer shows that reality instead of a normalised fiction.

Paths are registry-resolved (``registry.loader.resolve_fac``) — callers never
hardcode a URL, so a firmware upgrade that moves a resource is a row edit on
the Registry page, not a deploy.
"""
from __future__ import annotations

import base64

from .base import BaseClient

# Server-side clamp on ``limit`` (measured: ``?limit=0`` came back as
# ``meta.limit == 1000``). Ask for exactly this much per page so a full
# collection costs the fewest possible round trips without ever relying on
# ``limit=0`` meaning "everything" — it does not.
_PAGE_SIZE = 1000

# Runaway guard for the pagination walk. 500 pages x 1000 rows = 500k objects,
# far past any real FortiAuthenticator, so hitting it means the device is
# looping us (``next`` that never advances) rather than that we have more data.
_MAX_PAGES = 500


class FortiAuthenticatorError(RuntimeError):
    """A device-level refusal (HTTP error, auth failure, unparseable body)."""


class FortiAuthenticatorClient(BaseClient):
    def __init__(self, appliance, timeout: float = 30.0):
        """
        appliance: Appliance model instance with attributes:
            host, port, verify_ssl, username, password (decrypted API key)

        ``password`` carries the **API key**, not the login password — see the
        module docstring. Storing it in the existing encrypted column keeps it
        out of the config tree and reuses the Fernet envelope every other
        product already relies on.
        """
        super().__init__(appliance.host, appliance.port, appliance.verify_ssl, timeout)
        self._username = appliance.username or ''
        self._api_key = appliance.password or ''

    # -- transport ------------------------------------------------------------

    def _headers(self) -> dict:
        raw = f'{self._username}:{self._api_key}'.encode()
        return {
            'Authorization': 'Basic ' + base64.b64encode(raw).decode(),
            'Accept': 'application/json',
        }

    def _call(self, method: str, path: str, json_body=None, params=None):
        """(payload, error). Transport failures and HTTP errors both surface as
        ``error`` — never as an empty payload, so a refusal can't be mistaken
        for "this appliance has nothing configured" (the FortiWeb license-lock
        lesson, applied here from day one)."""
        kwargs: dict = {'headers': self._headers()}
        if params:
            kwargs['params'] = params
        if json_body is not None:
            kwargs['json'] = json_body
            kwargs['headers']['Content-Type'] = 'application/json'
        try:
            resp = self._request(method, path, **kwargs)
        except Exception as exc:  # noqa: BLE001 — transport
            return None, f'{type(exc).__name__}: {exc}'

        if resp.status_code == 401:
            return None, ('401 unauthorized — FortiAuthenticator requires a '
                          'per-user API key, not the login password. Tick '
                          '"Web service access" on the Administrator account '
                          'and store the emitted key as this appliance\'s '
                          'password.')
        if resp.status_code == 403:
            return None, (f'403 forbidden — the API key authenticated but this '
                          f'resource is not permitted for {self._username!r}.')
        if resp.status_code == 405:
            return None, ('405 method not allowed — this resource does not '
                          'serve that verb (several FortiAuthenticator '
                          'resources are POST-only actions, not readable '
                          'config).')
        if resp.status_code >= 400:
            body = (resp.text or '')[:200]
            return None, f'HTTP {resp.status_code}: {body}'

        text = resp.text or ''
        if not text.strip():
            return None, None  # e.g. 204 No Content on DELETE
        try:
            return resp.json(), None
        except Exception:  # noqa: BLE001 — device returned non-JSON
            return None, f'unparseable response body: {text[:200]!r}'

    # -- shape handling -------------------------------------------------------

    @staticmethod
    def _is_collection(payload) -> bool:
        """A Tastypie collection is ``{"meta": ..., "objects": [...]}``.

        Detected from the payload rather than from a list of singleton names:
        the registry YAML is already the single place that enumerates
        resources, and a parallel list of "which ones are singletons" is a copy
        that silently rots when the vendor changes a shape.
        """
        return (isinstance(payload, dict)
                and isinstance(payload.get('objects'), list)
                and isinstance(payload.get('meta'), dict))

    # -- generic, registry-resolved reads --------------------------------------

    def _resolve(self, logical: str) -> str:
        from ..registry import loader
        return loader.resolve_fac(logical)

    def list_with_error(self, logical: str, **params):
        """(rows, error) for a registry endpoint, fully paginated.

        Singletons are normalised to a one-element list so every caller —
        harvest, menu, explorer — handles exactly one shape. Device refusals
        surface as ``error`` instead of masquerading as an empty list.
        """
        try:
            path = self._resolve(logical)
        except KeyError as exc:
            return [], str(exc)
        return self.list_path_with_error(path, **params)

    def list_path_with_error(self, path: str, **params):
        """Same contract as :meth:`list_with_error` for an already-resolved
        path (the explorer hands us raw paths)."""
        first, err = self._call('GET', path, params={'limit': _PAGE_SIZE, **params})
        if err:
            return [], err
        if first is None:
            return [], None
        if not self._is_collection(first):
            return [first], None  # singleton resource

        rows = list(first.get('objects') or [])
        meta = first.get('meta') or {}
        total = meta.get('total_count')
        seen_offsets = {int(meta.get('offset') or 0)}
        nxt = meta.get('next')

        pages = 1
        while nxt and pages < _MAX_PAGES:
            page, err = self._call('GET', nxt)
            if err:
                # A short read is NOT a successful read. Report what we have
                # AND why it stopped, so a truncated harvest can never be
                # mistaken for a complete one.
                return rows, (f'pagination stopped after {len(rows)} of '
                              f'{total if total is not None else "?"} rows: {err}')
            if not self._is_collection(page):
                break
            meta = page.get('meta') or {}
            off = int(meta.get('offset') or 0)
            if off in seen_offsets:
                break  # device is looping us — stop rather than spin
            seen_offsets.add(off)
            rows.extend(page.get('objects') or [])
            nxt = meta.get('next')
            pages += 1

        if total is not None and len(rows) < total and not nxt:
            return rows, (f'short read: device reported {total} rows but only '
                          f'{len(rows)} were returned')
        return rows, None

    # -- platform inventory -----------------------------------------------------

    def sys_status(self) -> dict:
        """``GET /api/v1/systeminfo/`` → flat dict (firmware, sn, cpu, memory,
        disk and the per-feature licence counters)."""
        payload, err = self._call('GET', '/api/v1/systeminfo/')
        if err:
            raise FortiAuthenticatorError(err)
        return payload if isinstance(payload, dict) else {}

    def status_check(self):
        return self.sys_status()

    def ha_status(self) -> dict:
        """Best-effort live HA status as a flat dict.

        FortiAuthenticator exposes **no HA resource** in ``/api/v1/`` (censused:
        58 resources, none of them HA). The only signal the device gives is
        ``systeminfo.ha_sn`` — the serial of the peer, empty when there is
        none. We surface that raw value and nothing else; deciding
        clustered/standalone/unknown belongs to ``services.ha_inventory``, which
        already refuses to call an un-harvested box "standalone".
        """
        try:
            info = self.sys_status()
        except FortiAuthenticatorError:
            return {}
        return {'ha_sn': info.get('ha_sn') or '',
                'sn': info.get('sn') or ''}

    def api_call(self, method: str, path: str, data=None, **params):
        """Raw explorer entry point: HTTP verb + path + optional body/params →
        ``(payload, error)`` with the body exactly as the device sent it.

        Deliberately un-normalised: ``POST /api/v1/localusers/`` answers 207
        with a list and a misspelled ``statue`` key, and an operator debugging
        that needs to see it, not a tidied-up version of it.
        """
        return self._call(method.upper(), path, json_body=data,
                          params=params or None)
