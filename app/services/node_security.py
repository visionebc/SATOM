"""Inter-node security: the shared identity key, the request signature built
from it, and the encrypted + verified transport used for node-to-node HTTP.

Two concerns, kept together because they secure the same channel:

* **Confidentiality + peer identity at the TLS layer** — peer requests
  (``/healthz*``, ``/settings/peer/*``, ``/monitoring/collection/peer/*``) ride
  HTTPS on **:8443** (nginx node cert) ONLY. There is no plain-HTTP fallback.
  The peer certificate MUST verify against the system trust store (the public
  fleet wildcard issued over ACME) or the node's internal CA bundle (an
  internal-CA-minted leaf); ``check_hostname`` is off because peers are
  IP-addressed. An untrusted cert is REFUSED (fail-closed) with a clear error
  log and a per-host reason (:func:`tls_refusal`). A break-glass environment
  override (``SATOM_PEER_TLS_ALLOW_UNVERIFIED=1``) restores the old
  encrypted-but-unverified retry for an emergency; it is off by default.

* **Authenticity** — a shared **identity key** proves "who is who" when the two
  nodes talk. It is generated once on the PRIMARY, stored Fernet-encrypted in
  ``app_settings`` (key ``security.node_identity_key``) and therefore replicates
  to the standby over the same streaming replication (both nodes share
  ``FERNET_KEY``, so the standby can decrypt it). The key itself NEVER crosses
  the wire: every peer request carries an HMAC-SHA256 signature over
  ``(method, path+query, timestamp, sha256(body))`` keyed with it
  (``X-SATOM-Node-Ts`` + ``X-SATOM-Node-Sig``). The receiver recomputes it,
  compares in constant time and rejects a timestamp more than
  :data:`MAX_SKEW_S` seconds away from its own clock, so a captured request
  can neither be altered nor replayed outside that short window.

``/healthz`` stays answerable without a signature (LB probe); the signature
only unlocks the detail, and the ``/healthz/<x>`` + peer endpoints refuse an
unsigned caller.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import encryption as enc
from . import settings_store as ss

log = logging.getLogger(__name__)

# Request-signature headers. The legacy static ``X-FM-Node-Key`` header (the
# raw key on the wire) is gone and is NOT accepted any more.
TS_HEADER = "X-SATOM-Node-Ts"
SIG_HEADER = "X-SATOM-Node-Sig"
SIG_SCHEME = "v1"
# Largest accepted |receiver clock - signed timestamp|, seconds. Both nodes run
# NTP; this bounds the replay window of a captured request.
MAX_SKEW_S = 120
# The receiver hashes the whole body to check the signature; refuse to buffer
# anything bigger than this (the largest legitimate peer body — a metrics
# ingest batch — is capped at 4 MiB by its own endpoint).
MAX_SIGNED_BODY = 8 * 1024 * 1024

_KEY_SETTING = "security.node_identity_key"  # Fernet token in app_settings
HTTPS_PORT = 8443
# Retained ONLY as a constant other modules may read for diagnostics. The
# transport below NEVER connects to it: node-to-node requests are HTTPS-only.
HTTP_PORT = 8000

# Break-glass: set to 1/true in the service environment to let a peer whose
# certificate does not verify be reached encrypted-but-unverified (the
# pre-hardening behaviour). Off by default — an untrusted cert is refused.
ALLOW_UNVERIFIED_ENV = "SATOM_PEER_TLS_ALLOW_UNVERIFIED"

# Internal CA trust bundle. The source of truth for this path is
# ``cert_service`` (PKI = Path("/opt/satom/pki"); CA_DIR = PKI / "internal-ca";
# the cert is ``ca.crt``). It is duplicated here on purpose so this low-level
# transport stays import-light — cert_service pulls in ``cryptography`` and
# ``self_update`` — and cannot form an import cycle when a peer probe runs.
CA_BUNDLE = Path("/opt/satom/pki/internal-ca/ca.crt")


# ---------------------------------------------------------------------------
# Identity key
# ---------------------------------------------------------------------------
def get_identity_key() -> str | None:
    """The shared identity key (plaintext) if configured, else None. Read-only —
    works on the standby (reads the replicated, encrypted app_setting)."""
    tok = ss.get_str(_KEY_SETTING, None)
    if not tok:
        return None
    try:
        return enc.decrypt(tok)
    except Exception:
        return None


def ensure_identity_key(by: str = "system") -> str | None:
    """Create + store the identity key if missing (PRIMARY only — the standby's
    DB is read-only). Returns the plaintext key, or None if it could not be
    stored (e.g. called on a standby with no key yet)."""
    k = get_identity_key()
    if k:
        return k
    k = secrets.token_urlsafe(48)
    try:
        ss.set_str(_KEY_SETTING, enc.encrypt(k))
    except Exception:
        return None
    return k


def rotate_identity_key(by: str = "system") -> str | None:
    """Force a new identity key (PRIMARY only). Both nodes pick it up via
    replication + their next probe."""
    k = secrets.token_urlsafe(48)
    try:
        ss.set_str(_KEY_SETTING, enc.encrypt(k))
    except Exception:
        return None
    return k


def configured() -> bool:
    return get_identity_key() is not None


# ---------------------------------------------------------------------------
# Request signature (HMAC-SHA256)
# ---------------------------------------------------------------------------
def _canonical_target(path: str) -> str:
    """``path[?query]`` exactly as the receiving Flask app will reconstruct it:
    the path percent-DECODED (WSGI ``PATH_INFO`` is decoded before Flask sees
    it), the query string RAW (``request.query_string`` is not decoded)."""
    p, _sep, q = (path or "/").partition("?")
    p = urllib.parse.unquote(p) or "/"
    return p + ("?" + q if q else "")


def _mac(key: str, method: str, target: str, ts: int, body: bytes) -> str:
    """``v1=<hex>``: HMAC-SHA256 keyed with the identity key over the newline-
    joined (scheme, METHOD, target, ts, sha256(body))."""
    msg = "\n".join((SIG_SCHEME, (method or "GET").upper(), target, str(int(ts)),
                     hashlib.sha256(body or b"").hexdigest())).encode("utf-8")
    return SIG_SCHEME + "=" + hmac.new(str(key).encode("utf-8"), msg,
                                       hashlib.sha256).hexdigest()


def sign_headers(method: str, path: str, body: bytes | None = b"", *,
                 key: str | None = None, ts: int | None = None) -> dict:
    """The two signature headers for one request, or ``{}`` when no identity key
    is configured. The raw key is never part of the result."""
    k = get_identity_key() if key is None else key
    if not k:
        return {}
    t = int(time.time()) if ts is None else int(ts)
    return {TS_HEADER: str(t),
            SIG_HEADER: _mac(k, method, _canonical_target(path), t, body or b"")}


def verify_request(req=None, *, now: float | None = None) -> bool | None:
    """Check that ``req`` (a Flask/werkzeug request; defaults to the current
    one) carries a valid, fresh signature.

    Returns None when no key is configured (feature off — callers treat that
    as "not authenticated" / fail closed), else True/False. False for: missing
    headers, a malformed or stale (|now - ts| > MAX_SKEW_S) timestamp, an
    oversized body, or any mismatch of method / path / query / body / key. A
    bare headers mapping (no method/path/body) can never verify.
    """
    k = get_identity_key()
    if not k:
        return None
    if req is None:
        from flask import request as req  # noqa: PLW0127 — current request
    headers = getattr(req, "headers", None)
    method = getattr(req, "method", None)
    if headers is None or not method or not hasattr(req, "get_data"):
        return False
    ts_raw = headers.get(TS_HEADER)
    sig = headers.get(SIG_HEADER)
    if not ts_raw or not sig:
        return False
    ts_raw = str(ts_raw).strip()
    if not ts_raw.isdigit() or len(ts_raw) > 12:
        return False
    ts = int(ts_raw)
    if abs((time.time() if now is None else now) - ts) > MAX_SKEW_S:
        return False
    cl = getattr(req, "content_length", None)
    if cl and cl > MAX_SIGNED_BODY:
        return False
    try:
        body = req.get_data(cache=True) or b""  # cached: the view still reads it
    except Exception:  # noqa: BLE001
        return False
    if len(body) > MAX_SIGNED_BODY:
        return False
    target = (getattr(req, "script_root", "") or "") + (req.path or "/")
    qs = getattr(req, "query_string", b"") or b""
    if qs:
        target += "?" + (qs.decode("latin-1") if isinstance(qs, bytes) else str(qs))
    want = _mac(k, method, target, ts, body)
    return hmac.compare_digest(str(sig).encode("utf-8"), want.encode("utf-8"))


# ---------------------------------------------------------------------------
# Encrypted + verified peer transport
# ---------------------------------------------------------------------------
def _verified_ctx() -> ssl.SSLContext | None:
    """HTTPS context that VERIFIES the peer cert against BOTH trust stores.

    A node serves one of two certs: the PUBLIC fleet wildcard (issued by a real
    CA over ACME — chains to the SYSTEM trust store) or an internal-CA-minted
    leaf (chains to ``CA_BUNDLE``). We trust both so a correctly-configured pair
    verifies either way. ``check_hostname`` is False because peers are
    addressed by IP while the cert CN/SAN is a hostname; ``verify_mode`` stays
    CERT_REQUIRED so the chain must still validate against one of the stores.

    Returns ``None`` only when no trust store is usable at all.
    """
    try:
        ctx = ssl.create_default_context()  # loads the system trust store
    except Exception:
        return None
    if CA_BUNDLE.is_file():
        try:
            ctx.load_verify_locations(cafile=str(CA_BUNDLE))  # + internal CA
        except Exception:
            # A malformed internal bundle must NOT discard system-store trust.
            pass
    ctx.check_hostname = False           # IP-addressed peer, hostname CN
    ctx.verify_mode = ssl.CERT_REQUIRED  # chain to EITHER store required
    return ctx


def _unverified_ctx() -> ssl.SSLContext:
    """Encrypted-but-unauthenticated-at-TLS context. Used ONLY under the
    :data:`ALLOW_UNVERIFIED_ENV` break-glass override."""
    return ssl._create_unverified_context()


def peer_ssl_context() -> ssl.SSLContext | None:
    """The verifying TLS context for node-to-node requests, or None when no
    trust store is usable (the transport then refuses unless the break-glass
    override is set)."""
    return _verified_ctx()


def allow_unverified() -> bool:
    return (os.environ.get(ALLOW_UNVERIFIED_ENV, "") or "").strip().lower() in (
        "1", "true", "yes", "on")


# host -> last TLS refusal reason (cleared on the next good answer); and the
# per-host time of the last ERROR log so a dashboard polling every few seconds
# does not flood the journal.
_tls_refusals: dict[str, str] = {}
_last_refusal_log: dict[str, float] = {}
_REFUSAL_LOG_EVERY_S = 300.0


def tls_refusal(host: str) -> str | None:
    """Why the last request to ``host`` was refused at the TLS layer, if it was
    (this worker process only). None after any successful answer."""
    return _tls_refusals.get(host)


def unreachable_detail(host: str) -> str:
    """Operator-facing reason for a ``status is None`` answer from
    :func:`peer_get` / :func:`peer_post`."""
    return tls_refusal(host) or ("no answer on :%d" % HTTPS_PORT)


def _refuse(host: str, reason: str) -> None:
    _tls_refusals[host] = reason
    now = time.monotonic()
    last = _last_refusal_log.get(host)
    if last is None or now - last >= _REFUSAL_LOG_EVERY_S:
        _last_refusal_log[host] = now
        log.error("peer TLS refused for %s: %s", host, reason)


def _peer_request(host: str, path: str, *, data: bytes | None, method: str,
                  headers: dict, timeout: float):
    """Carry one request to a peer over HTTPS :8443 ONLY and return
    ``(status, body_bytes, secure)``. Shared body of :func:`peer_get` /
    :func:`peer_post`.

    Fail-closed: the peer certificate must verify (system roots or internal
    CA). A verification failure, or no usable trust store, returns
    ``(None, b"", False)`` and records the reason (:func:`tls_refusal`) —
    unless the :data:`ALLOW_UNVERIFIED_ENV` break-glass override is set, in
    which case it retries ONCE encrypted-but-unverified with a warning.

    ``status`` is None when the peer did not answer (unreachable, refused,
    timed out, or TLS-refused). An HTTP error status IS a valid answer and is
    returned as-is so callers can tell "refused" from "unreachable".
    """
    url = "https://%s:%d%s" % (host, HTTPS_PORT, path)

    def _attempt(ctx):
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.getcode(), r.read(), True

    verified = _verified_ctx()
    if verified is None:
        if not allow_unverified():
            _refuse(host, "no usable TLS trust store on this node (system roots "
                    "and internal CA bundle %s both unavailable); refusing to "
                    "send an unverified peer request" % CA_BUNDLE)
            return None, b"", False
        log.warning("peer TLS unverified (%s=1): no usable trust store; "
                    "encrypting to %s without peer-cert verification",
                    ALLOW_UNVERIFIED_ENV, host)
        ctx, verifying = _unverified_ctx(), False
    else:
        ctx, verifying = verified, True

    while True:
        try:
            out = _attempt(ctx)
            _tls_refusals.pop(host, None)
            return out
        except urllib.error.HTTPError as e:  # reachable, non-2xx — valid answer
            _tls_refusals.pop(host, None)
            try:
                body = e.read()
            except Exception:
                body = b""
            return e.code, body, True
        except (urllib.error.URLError, ssl.SSLError) as e:
            reason = getattr(e, "reason", e)
            is_tls = isinstance(e, ssl.SSLError) or isinstance(reason, ssl.SSLError)
            if verifying and is_tls:
                if allow_unverified():
                    log.warning(
                        "peer TLS cert for %s did not verify (%s); retrying "
                        "encrypted-but-unverified because %s=1", host, reason,
                        ALLOW_UNVERIFIED_ENV)
                    ctx, verifying = _unverified_ctx(), False
                    continue
                _refuse(host, "peer TLS certificate did not verify against the "
                        "system trust store or the internal CA (%s) — request "
                        "refused. Install a trusted node certificate (Settings > "
                        "Node TLS) on the peer; %s=1 is a temporary override"
                        % (reason, ALLOW_UNVERIFIED_ENV))
                return None, b"", False
            return None, b"", False
        except Exception:
            return None, b"", False  # never let a probe raise into a dashboard


def peer_get(host: str, path: str, timeout: float = 2.0):
    """Signed GET of ``path`` from a peer over verified HTTPS :8443. Returns
    ``(status, body_bytes, secure)``; ``status`` is None when the peer did not
    answer (see :func:`unreachable_detail`)."""
    return _peer_request(host, path, data=None, method="GET",
                         headers=sign_headers("GET", path, b""), timeout=timeout)


def peer_post(host: str, path: str, data: bytes, timeout: float = 2.0):
    """Signed POST of ``data`` (JSON bytes) to a peer — the write twin of
    :func:`peer_get`: same transport, same signature (over the exact body
    bytes sent), same return shape. The RECEIVER re-validates whatever it is
    asked to do; this function only carries bytes."""
    body = data or b""
    hdrs = sign_headers("POST", path, body)
    hdrs["Content-Type"] = "application/json"
    return _peer_request(host, path, data=body, method="POST",
                         headers=hdrs, timeout=timeout)
