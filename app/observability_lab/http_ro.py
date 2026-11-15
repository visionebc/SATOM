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
    def __init__(self, inner: httpx.BaseTransport):
        self._inner = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.method.upper() not in ALLOWED_METHODS:
            raise WriteBlocked("%s %s refused: SATOM Observability is read-only"
                               % (request.method, request.url.copy_with(query=None)))
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


def ssl_context(verify: bool, ca_pem: str = "") -> ssl.SSLContext | bool:
    """``False`` only when the operator turned verification off for this source.
    Otherwise the system trust store plus the source's own CA, if given."""
    if not verify:
        return False
    ctx = ssl.create_default_context()
    if ca_pem.strip():
        ctx.load_verify_locations(cadata=ca_pem)
    return ctx


def make_client(*, verify: bool = True, ca_pem: str = "", timeout: float = 30.0,
                transport: httpx.BaseTransport | None = None) -> httpx.Client:
    inner = transport or httpx.HTTPTransport(verify=ssl_context(verify, ca_pem), retries=0)
    return httpx.Client(transport=_ReadOnlyTransport(inner),
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
