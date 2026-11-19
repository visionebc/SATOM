"""The only HTTP path to devices and inventories: GET/HEAD only.

Read-only is enforced in the transport, below every connector: a POST, PUT,
PATCH or DELETE raises :class:`WriteBlocked` before the request is sent, so a
connector bug or an over-privileged account still cannot write.

Every request also has a TOTAL deadline. A socket timeout alone bounds each
read, not the request: a device that trickles bytes (seen on FortiWeb in
SATOM, >100 s with a 30 s timeout) would otherwise hold a collection forever.
"""
from __future__ import annotations

import ssl
import time

import httpx

ALLOWED_METHODS = frozenset({"GET", "HEAD"})
MAX_BODY = 32 * 1024 * 1024
_MAX_CONNECT_S = 10.0


class WriteBlocked(RuntimeError):
    """A connector tried to send something other than GET/HEAD."""


class DeadlineExceeded(RuntimeError):
    """The whole request took longer than its deadline."""


class _ReadOnlyTransport(httpx.BaseTransport):
    def __init__(self, inner: httpx.BaseTransport, tls_name: str | None = None):
        self._inner = inner
        self._tls_name = (tls_name or "").strip() or None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.method.upper() not in ALLOWED_METHODS:
            raise WriteBlocked("%s %s refused: SATOM Observability is read-only"
                               % (request.method, request.url.copy_with(query=None)))
        if self._tls_name:
            # The certificate is checked against this name, sent as SNI: an HA
            # member presents the cluster's synced certificate (SA-0015).
            request.extensions.setdefault("sni_hostname", self._tls_name)
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


def _store_context() -> ssl.SSLContext:
    """The public roots plus SATOM's trust store (Settings › Trust store), the
    CAs every other outbound connection of SATOM trusts (SA-0003). A store that
    cannot be read leaves the public roots, never no verification."""
    try:
        from ..services import trust_store
        return trust_store.ssl_context(True)
    except Exception:  # noqa: BLE001
        return ssl.create_default_context()


def ssl_context(verify: bool, ca_pem: str = "") -> ssl.SSLContext | bool:
    """``False`` only when the operator turned verification off for this source.
    Otherwise the public roots, SATOM's trust store and the source's own CA,
    if given."""
    if not verify:
        return False
    ctx = _store_context()
    if ca_pem.strip():
        ctx.load_verify_locations(cadata=ca_pem)
    return ctx


def make_client(*, verify: bool = True, ca_pem: str = "", timeout: float = 30.0,
                transport: httpx.BaseTransport | None = None,
                tls_name: str | None = None) -> httpx.Client:
    inner = transport or httpx.HTTPTransport(verify=ssl_context(verify, ca_pem), retries=0)
    return httpx.Client(transport=_ReadOnlyTransport(inner, tls_name if verify else None),
                        timeout=httpx.Timeout(timeout, connect=min(_MAX_CONNECT_S, timeout)),
                        follow_redirects=False)


def get(client: httpx.Client, url: str, *, headers=None, params=None,
        deadline: float = 60.0) -> tuple[int, dict, bytes]:
    """GET with a total deadline and a body cap. Returns (status, headers, body)."""
    started = time.monotonic()
    chunks, size = [], 0
    with client.stream("GET", url, headers=headers, params=params) as resp:
        for chunk in resp.iter_bytes():
            size += len(chunk)
            if size > MAX_BODY:
                raise RuntimeError("response larger than %d bytes" % MAX_BODY)
            chunks.append(chunk)
            if time.monotonic() - started > deadline:
                raise DeadlineExceeded("no complete answer within %.0f s" % deadline)
        return resp.status_code, dict(resp.headers), b"".join(chunks)
