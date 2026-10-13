"""Inter-node security: the shared identity key + the encrypted transport used
for node-to-node HTTP probes.

Two concerns, kept together because they secure the same channel:

* **Confidentiality** — peer probes (``/healthz*``) ride HTTPS on **:8443**
  (nginx node cert) ONLY. There is no plain-HTTP fallback, so the identity key
  below can NEVER cross the wire in cleartext. The peer certificate is verified
  against BOTH the system trust store (the public fleet wildcard issued over
  ACME) AND the node's internal CA bundle (an internal-CA-minted leaf), so a
  correctly-configured pair is fully verified either way; only a genuinely
  untrusted / self-signed cert (or a node with no usable trust store) degrades
  to encrypted-but-unverified. See :func:`_peer_request` for the full ladder.

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
import logging
import secrets
import ssl
import urllib.error
import urllib.request
from pathlib import Path

from . import encryption as enc
from . import settings_store as ss

log = logging.getLogger(__name__)

HEADER = "X-FM-Node-Key"
_KEY_SETTING = "security.node_identity_key"  # Fernet token in app_settings
HTTPS_PORT = 8443
# Retained ONLY as a constant other modules read for their "no answer on :%d or
# :%d" diagnostics (ha_link, self_update, service_control). The transport below
# NEVER connects to it: node-to-node probes are HTTPS-only now.
HTTP_PORT = 8000

# Internal CA trust bundle. The source of truth for this path is
# ``cert_service`` (cert_service.py:58-60 -> PKI = Path("/opt/satom/pki");
# CA_DIR = PKI / "internal-ca"; the cert is ``ca.crt``). It is duplicated here
# on purpose so this low-level transport stays import-light — cert_service pulls
# in ``cryptography`` and ``self_update`` — and cannot form an import cycle when
# a peer probe runs. BOTH nodes are meant to hold ``ca.crt`` (the issuer also
# holds ``ca.key``); a node that only ever imported the fleet wildcard may have
# neither, which the degrade ladder in _peer_request() handles.
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
def _verified_ctx() -> ssl.SSLContext | None:
    """HTTPS context that VERIFIES the peer cert against BOTH trust stores.

    A node serves one of two certs: the PUBLIC fleet wildcard (issued by a real
    CA over ACME — chains to the SYSTEM trust store) or an internal-CA-minted
    leaf (chains to ``CA_BUNDLE``). We trust both so a correctly-configured pair
    verifies either way:

    * start from :func:`ssl.create_default_context`, which loads the system
      default CAs (``load_default_certs``) — this validates the wildcard case;
    * if the internal CA bundle is present, also ``load_verify_locations`` it —
      this validates the internal-CA case.

    ``check_hostname`` is False because peers are addressed by IP while the cert
    CN/SAN is a hostname, so hostname matching cannot pass; ``verify_mode`` stays
    CERT_REQUIRED so the chain must still validate against one of the two stores.
    Only a genuinely untrusted / self-signed cert fails here and drops to the
    retry-once-unverified rung of the ladder.

    Returns ``None`` (not a hard error) only when BOTH stores are unavailable
    (e.g. ``create_default_context`` itself fails and the bundle is absent), so
    the caller degrades to an encrypted-but-unverified context rather than
    breaking every peer view.
    """
    try:
        ctx = ssl.create_default_context()  # loads the system trust store
    except Exception:
        # No usable system trust store at all: treat as "cannot verify".
        return None
    if CA_BUNDLE.is_file():
        try:
            ctx.load_verify_locations(cafile=str(CA_BUNDLE))  # + internal CA
        except Exception:
            # A malformed internal bundle must NOT discard system-store trust;
            # keep verifying against the system roots (the wildcard case).
            pass
    ctx.check_hostname = False           # IP-addressed peer, hostname CN
    ctx.verify_mode = ssl.CERT_REQUIRED  # chain to EITHER store required
    return ctx


def _unverified_ctx() -> ssl.SSLContext:
    """Encrypted-but-unauthenticated-at-TLS context. Authenticity still comes
    from the ``X-FM-Node-Key`` header; this is the confidentiality-only rung of
    the ladder for a peer whose cert chains to NEITHER the system roots nor the
    internal CA (genuinely self-signed / untrusted), or when no trust store is
    usable at all."""
    return ssl._create_unverified_context()


def peer_ssl_context() -> ssl.SSLContext:
    """Best-available TLS context for node-to-node probes: the verifying one
    (system roots + internal CA) when a trust store is usable, else the
    unverified-but-encrypted one. Kept as a public helper for callers/tests
    that want a single context;
    the live request path uses the full degrade ladder in :func:`_peer_request`
    (which can RETRY unverified after a verify failure — something a single
    context cannot express)."""
    return _verified_ctx() or _unverified_ctx()


def auth_headers() -> dict:
    # The identity key is sent as a STATIC header, deliberately unchanged on the
    # wire. Promoting it to an HMAC-over-(method, path, body, timestamp) scheme
    # would defeat replay, but it requires BOTH nodes to run the new verifier at
    # the same instant — impossible during a rolling deploy — so it is out of
    # scope here. TODO(hardening): HMAC-with-timestamp once a pairing handshake
    # can confirm both nodes speak the new scheme before either enforces it.
    k = get_identity_key()
    return {HEADER: k} if k else {}


def _peer_request(host: str, path: str, *, data: bytes | None, method: str | None,
                  headers: dict, timeout: float):
    """Carry one request to a peer over HTTPS :8443 ONLY and return
    ``(status, body_bytes, secure)``. Shared body of :func:`peer_get` /
    :func:`peer_post`.

    There is NO ``http://`` branch anywhere in this function — that is the whole
    point of fix #1: the identity-key header must be impossible to send in
    cleartext, even under a misconfiguration (the installer does not expose the
    plain-HTTP port at all).

    Degrade ladder — goal: "encrypted ALWAYS, verified WHEN POSSIBLE", and NEVER
    let a best-effort peer view break just because a cert could not be verified:

      1. A trust store is available -> connect with the verifying context, which
         trusts BOTH the system roots AND the internal CA (``check_hostname=False``
         + ``CERT_REQUIRED``; see :func:`_verified_ctx`). This is the common case
         and it SUCCEEDS silently whether the peer serves the public fleet
         wildcard (validates via system roots) or an internal-CA leaf (validates
         via the internal CA), defeating a passive/active attacker on the LAN.
      2. That TLS verification FAILS -> retry the request ONCE over the SAME
         HTTPS port with the unverified context, and log ONE warning. This is
         now only the genuinely untrusted / self-signed case; still encrypted,
         authenticity still comes from the identity-key header, and the peer
         view must not go down.
      3. NO usable trust store at all (``_verified_ctx`` returned None) -> there
         is nothing to verify against, so skip straight to the unverified
         context and log ONE warning.

    ``status`` is None only when the peer answered on neither attempt (genuinely
    unreachable / refused / timed out). An HTTP error status (e.g. 503 from
    ``/healthz/primary`` on a standby) IS a valid answer and is returned as-is
    so callers can tell "refused" from "unreachable". ``secure`` is always True
    on a successful answer because the only transport is TLS.
    """
    url = "https://%s:%d%s" % (host, HTTPS_PORT, path)

    def _attempt(ctx):
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.getcode(), r.read(), True

    verified = _verified_ctx()
    if verified is None:
        # Rung 3: no usable trust store at all -> encrypt without verification.
        log.warning(
            "peer TLS unverified: no usable trust store (system roots + internal "
            "CA bundle %s both unavailable); encrypting to %s without peer-cert "
            "verification", CA_BUNDLE, host)
        ctx, verifying = _unverified_ctx(), False
    else:
        ctx, verifying = verified, True  # rung 1

    while True:
        try:
            return _attempt(ctx)
        except urllib.error.HTTPError as e:  # reachable, non-2xx — valid answer
            try:
                body = e.read()
            except Exception:
                body = b""
            return e.code, body, True
        except (urllib.error.URLError, ssl.SSLError) as e:
            # A cert-verification failure surfaces as ssl.SSLError, usually
            # wrapped as URLError(reason=SSLCertVerificationError). Only that
            # case earns the one unverified retry (rung 2); a refused/timed-out
            # peer (reason is ConnectionRefused/timeout, not SSL) is just down.
            reason = getattr(e, "reason", e)
            is_tls = isinstance(e, ssl.SSLError) or isinstance(reason, ssl.SSLError)
            if verifying and is_tls:
                log.warning(
                    "peer TLS cert for %s did not verify against the system "
                    "roots or the internal CA (%s); retrying encrypted-but-"
                    "unverified — the served cert appears untrusted/self-signed",
                    host, reason)
                ctx, verifying = _unverified_ctx(), False
                continue
            return None, b"", False
        except Exception:
            return None, b"", False  # never let a probe raise into a dashboard


def peer_get(host: str, path: str, timeout: float = 2.0):
    """GET ``path`` from a peer over HTTPS :8443 (see :func:`_peer_request` for
    the transport and the verify/degrade ladder). Returns ``(status, body_bytes,
    secure)``; ``status`` is None when the peer is unreachable."""
    return _peer_request(host, path, data=None, method=None,
                         headers=auth_headers(), timeout=timeout)


def peer_post(host: str, path: str, data: bytes, timeout: float = 2.0):
    """POST ``data`` (JSON bytes) to a peer — the write twin of :func:`peer_get`,
    same HTTPS-only transport, same ``X-FM-Node-Key`` identity header (there is
    exactly ONE inter-node auth scheme and this is it), same return shape.

    Authenticity comes from the header, not the certificate — see
    :func:`_peer_request`. The RECEIVER re-validates whatever it is asked to do;
    this function only carries bytes."""
    hdrs = dict(auth_headers())
    hdrs["Content-Type"] = "application/json"
    return _peer_request(host, path, data=data or b"", method="POST",
                         headers=hdrs, timeout=timeout)
