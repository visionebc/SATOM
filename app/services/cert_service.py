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
  we issued it, we CAN and DO auto-renew it before expiry (``satom-cert-renew``
  timer → ``flask cert-renew``).

Installing = write ``pki/public/server.{crt,key}``, ``nginx -t`` (roll back on a
bad config), then reload nginx. The web process runs as root on this node, so it
performs the install + reload directly; there is no separate privileged runner
hop for cert changes. Node-local by design — each node serves its OWN hostname's
cert, so this is NEVER replicated (pki/ is outside ``data/``).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import self_update as su
from . import settings_store as ss

PKI = Path("/opt/satom/pki")
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
    name = su.this_node_name() or "satom"
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


def _priv(argv: list[str]) -> list[str]:
    """Prefix a command with non-interactive sudo unless we are already root.

    The web worker runs as the unprivileged SATOM service account (see
    docs/privilege-model.md). Exactly two commands are allowlisted in
    /etc/sudoers.d/satom -- `nginx -t` and `systemctl reload nginx` -- and both
    live in this module, because activating a TLS certificate is the only thing
    the worker does that genuinely needs root.

    Kept conditional so a node that has not run deploy/migrate-deprivilege.sh
    yet (app still User=root) behaves identically instead of hard-failing on a
    missing sudoers file.
    """
    return argv if os.geteuid() == 0 else ["sudo", "-n", *argv]


def _reload_nginx() -> None:
    """Validate config then reload. Raises RuntimeError with nginx's message on a
    bad config (the caller has already restored the previous cert on failure)."""
    t = subprocess.run(_priv(["nginx", "-t"]), capture_output=True, text=True)
    if t.returncode != 0:
        raise RuntimeError("nginx -t failed: " + (t.stderr or t.stdout)[-400:])
    r = subprocess.run(_priv(["systemctl", "reload", "nginx"]),
                       capture_output=True, text=True)
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
            subprocess.run(_priv(["systemctl", "reload", "nginx"]),
                           capture_output=True, text=True)
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


def import_pem(cert_pem: bytes, key_pem: bytes, chain_pem: bytes | None, by: str,
               *, _log: bool = True) -> dict:
    """Validate + install an externally-issued cert. Import-only (no auto-renew).

    _log=False when the caller already journals the attempt (autopull), so a
    single renewal does not produce two rows on the Renewals page."""
    from . import cert_renew_log as jrn
    try:
        validate_pem(cert_pem, key_pem, chain_pem)
        info = _install(cert_pem, key_pem, chain_pem, source="imported", by=by)
    except Exception as exc:  # noqa: BLE001 — _install already rolled nginx back
        if _log:
            jrn.record(jrn.CH_IMPORT, jrn.OK_ERROR, "import rejected — cert NOT installed",
                       error="%s: %s" % (type(exc).__name__, exc), by=by)
        raise
    if _log:
        jrn.record(jrn.CH_IMPORT, jrn.OK_RENEWED, "imported PEM installed", by=by,
                   days_left=info.get("days_left"), not_after=info.get("not_after"))
    return info


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


def issue_internal(by: str, hostname: str | None = None, *, _log: bool = True) -> dict:
    """Mint + install a leaf from the internal CA (primary only). Auto-renewable.

    _log=False when renew_if_needed already journals the attempt."""
    from . import cert_renew_log as jrn
    if not can_issue_internal():
        raise RuntimeError("internal CA key not present on this node — this node "
                           "cannot issue (only the CA holder / primary can). Import a cert instead.")
    hostname = hostname or node_hostname()
    try:
        crt_pem, key_pem = _mint_leaf(hostname)
        ca_pem = (CA_DIR / "ca.crt").read_bytes()  # ship the internal CA as the chain
        info = _install(crt_pem, key_pem, ca_pem, source="issued", by=by)
    except Exception as exc:  # noqa: BLE001
        if _log:
            jrn.record(jrn.CH_ISSUE, jrn.OK_ERROR, "minting from the internal CA failed",
                       error="%s: %s" % (type(exc).__name__, exc), by=by)
        raise
    if _log:
        jrn.record(jrn.CH_ISSUE, jrn.OK_RENEWED, "minted from the internal CA (%s)" % hostname,
                   by=by, days_left=info.get("days_left"), not_after=info.get("not_after"))
    return info


def renew_if_needed(by: str = "auto-renew", force: bool = False) -> dict:
    """Re-issue an *issued* cert when it is within the renewal threshold. No-op
    for imported / bootstrap certs (we cannot renew what we did not issue).

    Every outcome — renewed, skipped, failed — goes to the renewal journal
    (app.services.cert_renew_log) so the Renewals page can show WHY a
    night produced no new certificate. Before this existed the only trace was
    the timer's stdout in journald."""
    from . import cert_renew_log as jrn
    cur = current()
    days = cur.get("days_left")
    na = cur.get("not_after")
    if cur.get("source") != "issued":
        res = {"renewed": False, "reason": "source is %r — only CA-issued certs auto-renew"
               % cur.get("source"), "days_left": days}
        jrn.record(jrn.CH_INTERNAL, jrn.OK_SKIPPED, res["reason"], by=by,
                   days_left=days, not_after=na)
        return res
    if not can_issue_internal():
        res = {"renewed": False, "reason": "no CA key on this node", "days_left": days}
        jrn.record(jrn.CH_INTERNAL, jrn.OK_SKIPPED, res["reason"], by=by,
                   days_left=days, not_after=na)
        return res
    if not force and days is not None and days > RENEW_THRESHOLD_DAYS:
        res = {"renewed": False, "reason": "not due (%s d left, threshold %s)"
               % (days, RENEW_THRESHOLD_DAYS), "days_left": days}
        jrn.record(jrn.CH_INTERNAL, jrn.OK_SKIPPED, res["reason"], by=by,
                   days_left=days, not_after=na)
        return res
    try:
        new = issue_internal(by=by, _log=False)
    except Exception as exc:  # noqa: BLE001 — journal it, then let the caller see it
        jrn.record(jrn.CH_INTERNAL, jrn.OK_ERROR, "re-mint from the internal CA failed",
                   error="%s: %s" % (type(exc).__name__, exc), by=by, days_left=days)
        raise
    jrn.record(jrn.CH_INTERNAL, jrn.OK_RENEWED, "re-minted from the internal CA", by=by,
               days_left=new.get("days_left"), not_after=new.get("not_after"))
    return {"renewed": True, "days_left": new.get("days_left"), "not_after": new.get("not_after")}


# ---------------------------------------------------------------------------
# Renewal strategy for IMPORTED certs — the operator's choice of two ways
# ---------------------------------------------------------------------------
# A CA-*issued* cert auto-renews above. An *imported* cert (e.g. the fleet
# wildcard copied from the edge) can't be re-minted here, so the operator picks:
#
#   * ``alert``    (default) — do nothing automatic; the alert engine warns at
#                  T-N days (services.alerts cert check) and the operator re-
#                  imports by hand. Zero extra trust, zero key movement.
#   * ``autopull`` — the node fetches the renewed cert+key from a source over
#                  SSH/SFTP (typically the edge that runs certbot) and installs
#                  it through the same validated import path (nginx -t + auto-
#                  rollback). Convenient, but it means a private key is copied to
#                  the node and an SSH trust to the source exists — the operator
#                  opts into that explicitly.
#
# Both run from the SAME nightly ``satom-cert-renew`` timer. The mode + autopull
# connection live in app_settings (JSON, SSH password Fernet-encrypted at rest).
K_RENEW_MODE = "cert.renew_mode"          # "alert" | "autopull"
K_AUTOPULL = "cert.autopull"              # JSON dict
_AUTOPULL_DEFAULTS = {
    "ssh_host": "", "ssh_port": 22, "ssh_user": "root",
    "ssh_auth": "key",                    # "key" | "password"
    "ssh_key_path": "", "ssh_password_enc": "",
    "remote_cert": "", "remote_key": "", "remote_chain": "",
}


def renew_mode() -> str:
    m = (ss.get_str(K_RENEW_MODE, "alert") or "alert").strip().lower()
    return m if m in ("alert", "autopull") else "alert"


def autopull_config(reveal_secret: bool = False) -> dict:
    raw = ss.get_json(K_AUTOPULL, {}) or {}
    cfg = dict(_AUTOPULL_DEFAULTS)
    if isinstance(raw, dict):
        cfg.update({k: raw.get(k, v) for k, v in _AUTOPULL_DEFAULTS.items()})
    try:
        cfg["ssh_port"] = int(cfg.get("ssh_port") or 22)
    except (TypeError, ValueError):
        cfg["ssh_port"] = 22
    if reveal_secret:
        from . import encryption
        tok = cfg.get("ssh_password_enc") or ""
        try:
            cfg["ssh_password"] = encryption.decrypt(tok) if tok else ""
        except Exception:
            cfg["ssh_password"] = ""
    cfg["configured"] = bool(cfg.get("ssh_host") and cfg.get("remote_cert")
                             and cfg.get("remote_key"))
    return cfg


def save_autopull_config(form: dict, mode: str | None = None) -> None:
    from . import encryption
    cur = ss.get_json(K_AUTOPULL, {}) or {}
    out = dict(_AUTOPULL_DEFAULTS)
    if isinstance(cur, dict):
        out.update({k: cur.get(k, v) for k, v in _AUTOPULL_DEFAULTS.items()})
    for k in ("ssh_host", "ssh_user", "ssh_auth", "ssh_key_path",
              "remote_cert", "remote_key", "remote_chain"):
        if k in form:
            out[k] = (form.get(k) or "").strip()
    if "ssh_port" in form:
        try:
            out["ssh_port"] = int(form.get("ssh_port") or 22)
        except (TypeError, ValueError):
            out["ssh_port"] = 22
    new_pw = form.get("ssh_password", "")
    if new_pw:
        out["ssh_password_enc"] = encryption.encrypt(new_pw)
    ss.set_json(K_AUTOPULL, out)
    if mode is not None:
        ss.set_str(K_RENEW_MODE, mode if mode in ("alert", "autopull") else "alert")


def autopull(by: str = "autopull-timer", force: bool = False) -> dict:
    """Journaling wrapper around _autopull — classifies the outcome into
    renewed / skipped / error and writes it to the renewal journal so a silent
    nightly failure (bad SSH host, stale remote path, key mismatch) becomes a
    visible row with its error text instead of a line in journald."""
    from . import cert_renew_log as jrn
    try:
        res = _autopull(by=by, force=force)
    except Exception as exc:  # noqa: BLE001 — _autopull is documented never to raise
        jrn.record(jrn.CH_AUTOPULL, jrn.OK_ERROR, "autopull crashed",
                   error="%s: %s" % (type(exc).__name__, exc), by=by)
        raise
    reason = res.get("reason") or ""
    if res.get("pulled"):
        jrn.record(jrn.CH_AUTOPULL, jrn.OK_RENEWED, "fetched + installed the renewed cert",
                   by=by, days_left=res.get("days_left"), not_after=res.get("not_after"))
    elif reason.startswith(("fetch failed", "install rejected", "paramiko unavailable")):
        jrn.record(jrn.CH_AUTOPULL, jrn.OK_ERROR, "autopull failed", error=reason, by=by)
    else:
        jrn.record(jrn.CH_AUTOPULL, jrn.OK_SKIPPED, reason, by=by,
                   days_left=res.get("days_left"))
    return res


def _autopull(by: str = "autopull-timer", force: bool = False) -> dict:
    """Fetch the renewed cert/key (+optional chain) from the configured source
    over SFTP and install it through the validated import path. No-op unless the
    renewal mode is ``autopull`` and the connection is configured. Never raises —
    connection/validation failures are reported in the return dict (install has
    its own nginx-test + rollback)."""
    if not force and renew_mode() != "autopull":
        return {"pulled": False, "reason": "renew_mode is not 'autopull'"}
    cfg = autopull_config(reveal_secret=True)
    if not cfg.get("configured"):
        return {"pulled": False, "reason": "autopull source not configured"}
    try:
        import paramiko
    except Exception as exc:  # noqa: BLE001
        return {"pulled": False, "reason": f"paramiko unavailable: {exc}"}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kw = {"hostname": cfg["ssh_host"], "port": cfg["ssh_port"],
                  "username": cfg["ssh_user"], "timeout": 15, "allow_agent": False,
                  "look_for_keys": False}
    if cfg.get("ssh_auth") == "password":
        connect_kw["password"] = cfg.get("ssh_password") or ""
    else:
        if cfg.get("ssh_key_path"):
            connect_kw["key_filename"] = cfg["ssh_key_path"]
        connect_kw["look_for_keys"] = True
    try:
        client.connect(**connect_kw)
        sftp = client.open_sftp()
        try:
            with sftp.open(cfg["remote_cert"], "rb") as fh:
                cert_pem = fh.read()
            with sftp.open(cfg["remote_key"], "rb") as fh:
                key_pem = fh.read()
            chain_pem = None
            if cfg.get("remote_chain"):
                with sftp.open(cfg["remote_chain"], "rb") as fh:
                    chain_pem = fh.read()
        finally:
            sftp.close()
    except Exception as exc:  # noqa: BLE001
        return {"pulled": False, "reason": f"fetch failed: {type(exc).__name__}: {exc}"}
    finally:
        try:
            client.close()
        except Exception:
            pass

    # Skip a redundant reinstall when the fetched cert already matches what we
    # serve (same bytes) — avoids a needless nginx reload every night.
    try:
        full = cert_pem if not chain_pem else cert_pem.rstrip() + b"\n" + chain_pem.lstrip()
        if CRT.exists() and CRT.read_bytes().strip() == full.strip():
            return {"pulled": False, "reason": "already up to date (identical cert)",
                    "days_left": current().get("days_left")}
    except Exception:  # noqa: BLE001
        pass
    try:
        info = import_pem(cert_pem, key_pem, chain_pem, by=by, _log=False)
        return {"pulled": True, "days_left": info.get("days_left"),
                "not_after": info.get("not_after")}
    except Exception as exc:  # noqa: BLE001 — import_pem already rolled nginx back
        return {"pulled": False, "reason": f"install rejected: {exc}"}
