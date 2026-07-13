"""The service's OWN TLS certificate — the leaf nginx serves on :8443 (the
node-facing / soon-to-be-public listener).

Two ways to put a cert here, exactly as the operator asked:

* **Import** — upload a PEM cert (+ key, + optional chain) issued anywhere else.
  We validate that the key matches the cert, install it, track its expiry and
  warn before it lapses. Import is *import-only*: we did not issue it, so we do
  NOT pretend to auto-renew it — the dashboard just alerts and the operator
  re-imports.
* **Issue via the internal cert-manager** — mint a leaf from the node's internal
  CA (``pki/internal-ca``, primary holds the key) for the node hostname. Because
  we issued it, we CAN and DO auto-renew it before expiry (``fm-cert-renew``
  timer → ``flask cert-renew``).

Installing = write ``pki/public/server.{crt,key}``, ``nginx -t`` (roll back on a
bad config), then reload nginx. The web process runs as root on this node, so it
performs the install + reload directly; there is no separate privileged runner
hop for cert changes. Node-local by design — each node serves its OWN hostname's
cert, so this is NEVER replicated (pki/ is outside ``data/``).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import self_update as su
from . import settings_store as ss

PKI = Path("/opt/fortinet-manager/pki")
PUB = PKI / "public"
CA_DIR = PKI / "internal-ca"
CRT = PUB / "server.crt"
KEY = PUB / "server.key"
META = PUB / "meta.json"
RENEW_THRESHOLD_DAYS = 30
ISSUE_DAYS = 825


# ---------------------------------------------------------------------------
def node_hostname() -> str:
    """Public hostname this node serves TLS for. Operator-overridable; defaults
    from the HA node name."""
    h = ss.get_str("security.node_cert.hostname", None)
    if h:
        return h
    name = su.this_node_name() or "fortinet-manager"
    return name if "." in name else name + ".example.net"


def _meta() -> dict:
    try:
        return json.loads(META.read_text())
    except Exception:
        return {}


def _write_meta(**kw) -> None:
    m = _meta()
    m.update(kw)
    META.write_text(json.dumps(m, indent=2))


def can_issue_internal() -> bool:
    """Only the CA-key holder (primary) can mint from the internal CA."""
    return (CA_DIR / "ca.key").exists() and (CA_DIR / "ca.crt").exists()


# ---------------------------------------------------------------------------
# Inspect
# ---------------------------------------------------------------------------
def current() -> dict:
    from . import encryption_health as eh
    info = eh.node_cert()
    m = _meta()
    info["source"] = m.get("source", ss.get_str("security.node_cert.source", "bootstrap"))
    info["installed_at"] = m.get("installed_at")
    info["hostname"] = node_hostname()
    info["can_issue_internal"] = can_issue_internal()
    info["renew_threshold_days"] = RENEW_THRESHOLD_DAYS
    return info


# ---------------------------------------------------------------------------
# Validate + install
# ---------------------------------------------------------------------------
def validate_pem(cert_pem: bytes, key_pem: bytes, chain_pem: bytes | None = None) -> dict:
    """Parse + sanity-check an imported cert/key. Raises ValueError on any
    problem (bad PEM, key/cert mismatch)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec

    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception as e:
        raise ValueError("certificate is not valid PEM: %s" % e)
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except Exception as e:
        raise ValueError("private key is not valid PEM (or is passphrase-protected): %s" % e)

    # key must match the cert's public key
    cpub = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    kpub = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if cpub != kpub:
        raise ValueError("private key does not match the certificate")

    if chain_pem:
        try:
            x509.load_pem_x509_certificates(chain_pem)
        except Exception as e:
            raise ValueError("chain is not valid PEM: %s" % e)

    na = cert.not_valid_after_utc
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_after": na.isoformat(),
        "days_left": int((na - datetime.now(timezone.utc)).total_seconds() // 86400),
        "self_signed": cert.subject == cert.issuer,
    }


def _reload_nginx() -> None:
    """Validate config then reload. Raises RuntimeError with nginx's message on a
    bad config (the caller has already restored the previous cert on failure)."""
    t = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if t.returncode != 0:
        raise RuntimeError("nginx -t failed: " + (t.stderr or t.stdout)[-400:])
    r = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("nginx reload failed: " + (r.stderr or r.stdout)[-400:])


def _install(cert_pem: bytes, key_pem: bytes, chain_pem: bytes | None,
             source: str, by: str) -> dict:
    """Write the cert (+chain) and key, test nginx, reload — rolling the files
    back if nginx rejects them."""
    PUB.mkdir(parents=True, exist_ok=True)
    bak = PUB / ".rollback"
    bak.mkdir(exist_ok=True)
    for f in (CRT, KEY):
        if f.exists():
            shutil.copy2(f, bak / f.name)
    full = cert_pem if not chain_pem else (cert_pem.rstrip() + b"\n" + chain_pem.lstrip())
    try:
        CRT.write_bytes(full)
        KEY.write_bytes(key_pem)
        KEY.chmod(0o600)
        _reload_nginx()
    except Exception:
        # roll back to the previous cert/key so :8443 keeps serving
        for f in (CRT, KEY):
            b = bak / f.name
            if b.exists():
                shutil.copy2(b, f)
        try:
            subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True)
        except Exception:
            pass
        raise
    # meta.json (node-local file) is the source of record for the cert origin —
    # it works even on a standby whose Postgres is read-only.
    _write_meta(source=source, installed_at=datetime.now(timezone.utc).isoformat(),
                installed_by=by, hostname=node_hostname())
    # Mirror into app_settings when writable (primary); best-effort on a standby
    # (read-only replica) where the UPDATE would raise — the cert is already live.
    try:
        ss.set_str("security.node_cert.source", source)
    except Exception:
        try:
            from ..models import db
            db.session.rollback()
        except Exception:
            pass
    return current()


def import_pem(cert_pem: bytes, key_pem: bytes, chain_pem: bytes | None, by: str) -> dict:
    """Validate + install an externally-issued cert. Import-only (no auto-renew)."""
    validate_pem(cert_pem, key_pem, chain_pem)
    return _install(cert_pem, key_pem, chain_pem, source="imported", by=by)


# ---------------------------------------------------------------------------
# Issue from the internal CA (+ auto-renew)
# ---------------------------------------------------------------------------
def _mint_leaf(hostname: str, days: int = ISSUE_DAYS) -> tuple[bytes, bytes]:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    ca_cert = x509.load_pem_x509_certificate((CA_DIR / "ca.crt").read_bytes())
    ca_key = serialization.load_pem_private_key((CA_DIR / "ca.key").read_bytes(), password=None)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    crt_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
    return crt_pem, key_pem


def issue_internal(by: str, hostname: str | None = None) -> dict:
    """Mint + install a leaf from the internal CA (primary only). Auto-renewable."""
    if not can_issue_internal():
        raise RuntimeError("internal CA key not present on this node — this node "
                           "cannot issue (only the CA holder / primary can). Import a cert instead.")
    hostname = hostname or node_hostname()
    crt_pem, key_pem = _mint_leaf(hostname)
    ca_pem = (CA_DIR / "ca.crt").read_bytes()  # ship the internal CA as the chain
    return _install(crt_pem, key_pem, ca_pem, source="issued", by=by)


def renew_if_needed(by: str = "auto-renew", force: bool = False) -> dict:
    """Re-issue an *issued* cert when it is within the renewal threshold. No-op
    for imported / bootstrap certs (we cannot renew what we did not issue)."""
    cur = current()
    if cur.get("source") != "issued":
        return {"renewed": False, "reason": "source is %r — only CA-issued certs auto-renew"
                % cur.get("source"), "days_left": cur.get("days_left")}
    if not can_issue_internal():
        return {"renewed": False, "reason": "no CA key on this node", "days_left": cur.get("days_left")}
    days = cur.get("days_left")
    if not force and days is not None and days > RENEW_THRESHOLD_DAYS:
        return {"renewed": False, "reason": "not due (%s d left, threshold %s)"
                % (days, RENEW_THRESHOLD_DAYS), "days_left": days}
    new = issue_internal(by=by)
    return {"renewed": True, "days_left": new.get("days_left"), "not_after": new.get("not_after")}
