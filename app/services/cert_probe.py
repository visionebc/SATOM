# app/services/cert_probe.py
"""Certificate detail + live TLS-handshake probe.

FortiWeb's REST API exposes NO certificate material (the cmdb GET returns only
name/type/status/comment, ``can_view=0``, and there is no monitor endpoint for
validity). So X.509 detail for an on-device cert can only be recovered by a live
TLS handshake against wherever the cert is actually served (a server policy's
VIP:port, or the admin GUI :443). Manager-signed certs skip the probe — their
signed PEM is stored locally.

Pure helpers (``detail_from_pem``) + one network op (``probe_leaf_pem``) that is
best-effort with a short timeout, so a dead box never hangs a page. No Flask/DB.
"""
from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime

logger = logging.getLogger(__name__)

_EMPTY = {
    "cn": "", "issuer_cn": "", "serial": "", "sans": [],
    "not_before": None, "not_after": None, "days_left": None,
    "fingerprint_sha256": "", "key_type": "", "sig_algo": "",
}


def _first_cn(name) -> str:
    from cryptography.x509.oid import NameOID
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""
    except Exception:  # noqa: BLE001
        return ""


def detail_from_pem(pem: str) -> dict:
    """Parse a PEM certificate into a display detail dict. Never raises; unknown
    fields come back empty so the caller can render partial detail."""
    from cryptography import x509
    out = dict(_EMPTY)
    out["sans"] = []
    try:
        cert = x509.load_pem_x509_certificate((pem or "").encode())
    except Exception:  # noqa: BLE001
        return out
    try:
        out["cn"] = _first_cn(cert.subject)
        out["issuer_cn"] = _first_cn(cert.issuer)
    except Exception:  # noqa: BLE001
        pass
    try:
        out["serial"] = format(cert.serial_number, "x")
    except Exception:  # noqa: BLE001
        pass
    try:
        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        out["not_before"] = nb.replace(tzinfo=None)
        out["not_after"] = na.replace(tzinfo=None)
        out["days_left"] = (out["not_after"] - datetime.utcnow()).days
    except Exception:  # noqa: BLE001
        pass
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        out["sans"] = [str(g.value) for g in ext.value]
    except Exception:  # noqa: BLE001
        pass
    try:
        out["fingerprint_sha256"] = cert.fingerprint(_sha256()).hex()
    except Exception:  # noqa: BLE001
        pass
    try:
        out["sig_algo"] = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
    except Exception:  # noqa: BLE001
        pass
    try:
        pk = cert.public_key()
        out["key_type"] = type(pk).__name__.replace("_", "").replace("PublicKey", "")
    except Exception:  # noqa: BLE001
        pass
    return out


def _sha256():
    from cryptography.hazmat.primitives import hashes
    return hashes.SHA256()


def probe_leaf_pem(host: str, port: int, *, server_name: str | None = None,
                   timeout: float = 4.0) -> tuple[str, str]:
    """Open a TLS connection and return ``(leaf_pem, error)``. Certificate
    validation is DISABLED (we only want the presented leaf, and FortiWeb serves
    self/CA-signed certs) — this is a read-only inspection, never a trust decision.
    Empty ``leaf_pem`` + a populated ``error`` means the probe could not run."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sni = server_name or host
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                der = tls.getpeercert(binary_form=True)
        if not der:
            return "", "no certificate presented"
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        cert = x509.load_der_x509_certificate(der)
        return cert.public_bytes(serialization.Encoding.PEM).decode(), ""
    except Exception as exc:  # noqa: BLE001 — any failure is a non-fatal miss
        return "", f"{type(exc).__name__}: {exc}"[:200]


__all__ = ["detail_from_pem", "probe_leaf_pem"]
