"""Inter-node security: the shared identity key + the encrypted transport used
for node-to-node HTTP probes.

Two concerns, kept together because they secure the same channel:

* **Confidentiality** — peer probes (``/healthz*``) now ride HTTPS on **:8443**
  (nginx node cert) instead of plain HTTP on :8000. ``peer_get()`` prefers
  :8443 and falls back to :8000 only if TLS is unreachable, so the transport is
  encrypted whenever the peer's TLS front is up.

* **Authenticity** — a shared **identity key** proves "who is who" when the two
  nodes talk. It is generated once on the PRIMARY, stored Fernet-encrypted in
  ``app_settings`` (key ``security.node_identity_key``) and therefore replicates
  to the standby over the same streaming replication (both nodes share
  ``FERNET_KEY``, so the standby can decrypt it). Every peer probe carries it in
  the ``X-FM-Node-Key`` header; ``/healthz`` echoes ``peer_authenticated`` so the
  caller — and the Monitoring encryption card — can see the peer accepted it.

The key does NOT gate ``/healthz`` (that must stay answerable for the LB probe);
it is an *attestation*, surfaced not enforced, matching the current trust model
(LAN-only, nftables-scoped). A future pairing handshake can promote it to a hard
gate once both nodes provably hold it.
"""
from __future__ import annotations

import hmac
import secrets
import ssl
import urllib.error
import urllib.request

from . import encryption as enc
from . import settings_store as ss

HEADER = "X-FM-Node-Key"
_KEY_SETTING = "security.node_identity_key"  # Fernet token in app_settings
HTTPS_PORT = 8443
HTTP_PORT = 8000


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


def verify_request(headers) -> bool | None:
    """Constant-time check that a request carries the correct identity key.
    Returns None when no key is configured (feature off), else True/False."""
    k = get_identity_key()
    if not k:
        return None
    got = headers.get(HEADER) if headers else None
    if not got:
        return False
    return hmac.compare_digest(str(got), str(k))


# ---------------------------------------------------------------------------
# Encrypted peer transport
# ---------------------------------------------------------------------------
def peer_ssl_context() -> ssl.SSLContext:
    """TLS context for node-to-node probes. Certificate verification is OFF here
    on purpose: node_reports() addresses peers by IP, and the node cert's CN is
    the hostname, so hostname verification cannot pass. Confidentiality comes
    from TLS; AUTHENTICITY comes from the identity-key header, not the cert. The
    node-cert's own trust is validated separately by the encryption card."""
    return ssl._create_unverified_context()


def auth_headers() -> dict:
    k = get_identity_key()
    return {HEADER: k} if k else {}


def peer_get(host: str, path: str, timeout: float = 2.0):
    """GET ``path`` from a peer, preferring HTTPS :8443 and falling back to plain
    HTTP :8000 only if TLS is unreachable. Returns ``(status, body_bytes,
    secure)`` where ``secure`` is True when the answer came over TLS; ``status``
    is None when the peer is unreachable on both. An HTTP error status (e.g. 503
    from /healthz/primary on a standby) is a valid answer and is returned as-is.
    """
    ctx = peer_ssl_context()
    hdrs = auth_headers()
    for scheme, port, secure in (("https", HTTPS_PORT, True), ("http", HTTP_PORT, False)):
        url = "%s://%s:%d%s" % (scheme, host, port, path)
        try:
            req = urllib.request.Request(url, headers=hdrs)
            kw = {"timeout": timeout}
            if secure:
                kw["context"] = ctx
            with urllib.request.urlopen(req, **kw) as r:
                return r.getcode(), r.read(), secure
        except urllib.error.HTTPError as e:  # reachable, non-2xx — valid answer
            try:
                body = e.read()
            except Exception:
                body = b""
            return e.code, body, secure
        except Exception:
            continue  # TLS unreachable → try plain HTTP; then give up
    return None, b"", False
