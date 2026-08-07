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
hop for cert changes.

``pki/`` itself is node-local (outside ``data/``, gitignored), but the three
things under it do NOT share one rule — see ``docs/encryption-and-node-tls.md``:

* ``internal-ca/`` — BOTH nodes are meant to hold it; the installer places
  ``ca.key`` on a joining node from the cluster join key. ``ca_custody()``
  reports whether THIS node can actually issue, because a node with ``ca.crt``
  and no ``ca.key`` cannot self-renew and cannot take over issuance after a
  promote. Nothing here moves ``ca.key`` between hosts: the join key is the
  sanctioned transport and it is operator-driven.
* ``node/leaf.*`` — per node, forever. It names this node in its SAN and is also
  the Postgres replication CLIENT cert, so a copy breaks ``clientcert=verify-ca``
  on the peer. This module never reads or writes it.
* ``public/server.*`` — the served cert. Shareable via ``data/pki-shared/``
  (``publish_shared_cert`` / ``install_shared_cert``), because ``data/`` is what
  the HA datasync replicates. Only an **imported** cert may be shared — a
  CA-issued leaf carries one node's name and sharing it is the leaf bug again —
  and a shared cert is installed only on a node whose served names it covers.
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

# The one slot both nodes can see. data/ is what satom-ha-datasync replicates
# (and what the backup bundles carry); pki/ is not, which is why the served
# cert used to be copied between nodes BY HAND. Gitignored like the rest of
# data/, so no private key reaches the repository.
SHARED_DIR = Path(__file__).resolve().parents[2] / "data" / "pki-shared"
SHARED_SOURCE = "imported"   # the ONLY origin that may be shared — see below
CH_SHARED = "shared"         # renewal-journal channel for the shared slot


# ---------------------------------------------------------------------------
def node_hostname() -> str:
    """Public hostname this node serves TLS for. Operator-overridable; defaults
    from the HA node name."""
    h = ss.get_str("security.node_cert.hostname", None)
    if h:
        return h
    name = su.this_node_name() or "satom"
    if "." in name:
        return name
    # Only the SUFFIX is deployment-specific, and it is read per node rather
    # than stored as a full name: on an HA pair the standby replicates the
    # primary's settings row, so a stored FQDN would make the standby issue a
    # certificate naming the primary. Empty by default — appending a domain
    # the installation does not own produces a certificate for somebody
    # else's namespace, and an internal CA is content with a short name.
    domain = (ss.get_str("security.node_cert.domain", None) or "").strip(". ")
    return "%s.%s" % (name, domain) if domain else name


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
    """A node can mint from the internal CA only if it holds the CA KEY."""
    return (CA_DIR / "ca.key").exists() and (CA_DIR / "ca.crt").exists()


# --- CA custody ------------------------------------------------------------
# The installer's node-join step writes ca.key onto a joining node from the
# cluster join key, so BOTH nodes are supposed to be issuers. A node that ended
# up with ca.crt only (older install path) still looks fine everywhere else:
# TLS verifies, the trust bundle is complete, the Monitoring cards are green.
# What it cannot do is issue — so it cannot auto-renew its own leaf and cannot
# take over issuance after a promote. That is a state with a remedy, not a
# healthy state, and the remedy is operator-driven: re-run the join step. No
# code path here copies ca.key over the network.
CUSTODY_ISSUER = "issuer"            # ca.crt + ca.key — can issue and renew
CUSTODY_TRUST_ONLY = "trust-only"    # ca.crt only — verifies, cannot issue
CUSTODY_KEY_ONLY = "key-without-cert"  # ca.key only — unusable, half a CA
CUSTODY_ABSENT = "absent"            # no internal CA on this node at all

_CUSTODY_REMEDY = {
    CUSTODY_TRUST_ONLY:
        "This node holds the internal CA certificate but NOT its private key, so "
        "it cannot mint or renew a leaf and cannot take over issuance after a "
        "promote. Re-run the installer's node-join step with the cluster join key "
        "(the sanctioned transport for ca.key) on this node. Do not copy the key "
        "by hand, and do not let a service copy it for you.",
    CUSTODY_KEY_ONLY:
        "This node holds an internal CA private key with no matching certificate — "
        "issuing is impossible and the trust bundle is incomplete. Re-run the "
        "installer's node-join step to place a consistent CA pair.",
    CUSTODY_ABSENT:
        "No internal CA on this node. Bootstrap it on the first node with the "
        "installer, then join this node with the cluster join key so it receives "
        "the CA and can issue and renew on its own.",
}


def ca_custody() -> dict:
    """Who holds what of the internal CA on THIS node, and can it issue?

    Reportable state — a node that cannot issue is never reported healthy."""
    has_crt = (CA_DIR / "ca.crt").exists()
    has_key = (CA_DIR / "ca.key").exists()
    if has_crt and has_key:
        state = CUSTODY_ISSUER
    elif has_crt:
        state = CUSTODY_TRUST_ONLY
    elif has_key:
        state = CUSTODY_KEY_ONLY
    else:
        state = CUSTODY_ABSENT
    can_issue = can_issue_internal()
    return {
        "state": state,
        "has_ca_cert": has_crt,
        "has_ca_key": has_key,
        "can_issue": can_issue,
        "healthy": state == CUSTODY_ISSUER,
        "summary": {
            CUSTODY_ISSUER: "internal CA present — this node can issue and auto-renew",
            CUSTODY_TRUST_ONLY: "internal CA certificate only — this node CANNOT issue",
            CUSTODY_KEY_ONLY: "internal CA key without its certificate — unusable",
            CUSTODY_ABSENT: "no internal CA on this node",
        }[state],
        "remedy": _CUSTODY_REMEDY.get(state, ""),
    }


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

    # This connection carries the node's TLS certificate AND PRIVATE KEY back
    # over SFTP. It had no host-key store at all: AutoAdd with nothing to
    # compare against accepts whatever key answers, every time, and never
    # notices when the answer changes.
    from . import ssh_pinning
    known = Path(__file__).resolve().parents[2] / "data" / "known_hosts"

    class _PinError(RuntimeError):
        pass

    client = paramiko.SSHClient()
    try:
        ssh_pinning.load_pins(client, known, _PinError)
    except _PinError as exc:
        return {"pulled": False, "reason": str(exc)}
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
        ssh_pinning.persist(client, known, _PinError)
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


# ---------------------------------------------------------------------------
# The SHARED served certificate — data/pki-shared/
#
# The served cert is the ONE piece of pki/ that legitimately wants to be the
# same on both nodes: `satom{,-2}` are two names under one wildcard, and the
# operator was copying it across by hand. It goes through data/ because that is
# the tree satom-ha-datasync replicates (primary -> standby, rsync --delete) and
# the tree the backup bundles carry.
#
# Two hard gates, both enforced below rather than promised in prose:
#
#   1. source must be `imported`. A CA-ISSUED leaf is per-node BY CONSTRUCTION —
#      its SAN is that node's hostname — so sharing it repeats exactly the bug
#      that makes pki/node/leaf.* non-shareable. `bootstrap` (the self-signed
#      cert minted for this node at install) is per-node for the same reason.
#   2. the cert must cover THIS node's served names. Installing one that does
#      not is worse than doing nothing: the node then serves a certificate the
#      browser rejects, and the product reports it as freshly installed.
#
# Install reuses the ordinary _install() path — key/cert match check, nginx -t,
# automatic rollback — so there is exactly one implementation of "activate a
# certificate safely" in this module.
# ---------------------------------------------------------------------------
def _shared_paths() -> tuple[Path, Path, Path]:
    return (SHARED_DIR / "server.crt", SHARED_DIR / "server.key",
            SHARED_DIR / "meta.json")


def _write_private(path: Path, data: bytes) -> None:
    """Create/replace a private key file that is never briefly world-readable."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(path, 0o600)


def cert_dns_names(cert_pem: bytes) -> list[str]:
    """DNS names a certificate presents (SAN, falling back to CN)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    cert = x509.load_pem_x509_certificate(cert_pem)
    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = list(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        names = []
    if not names:
        names = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    return [str(n).strip().rstrip(".").lower() for n in names if n]


def _name_matches(presented: str, wanted: str) -> bool:
    """RFC 6125 host matching: a wildcard covers exactly ONE leftmost label."""
    presented = (presented or "").strip().rstrip(".").lower()
    wanted = (wanted or "").strip().rstrip(".").lower()
    if not presented or not wanted:
        return False
    if not presented.startswith("*."):
        return presented == wanted
    head, _, rest = wanted.partition(".")
    return bool(head) and rest == presented[2:]


def served_names() -> list[str]:
    """The names this node must be able to answer for on :443/:8443."""
    return [n for n in (node_hostname(),) if n]


def cert_covers_served_names(cert_pem: bytes) -> tuple[bool, list[str], list[str]]:
    """(covers?, names NOT covered, names the cert presents)."""
    presented = cert_dns_names(cert_pem)
    missing = [w for w in served_names()
               if not any(_name_matches(p, w) for p in presented)]
    return (not missing), missing, presented


def shared_cert_status() -> dict:
    """What is in the shared slot and whether THIS node could take it."""
    crt_p, key_p, meta_p = _shared_paths()
    out = {"present": False, "source": None, "names": [], "not_after": None,
           "covers_this_node": None, "missing_names": [], "differs": None,
           "shareable": None, "error": None}
    if not (crt_p.exists() and key_p.exists()):
        return out
    out["present"] = True
    try:
        smeta = json.loads(meta_p.read_text())
    except Exception:  # noqa: BLE001 — an unreadable meta is a refusal, not a crash
        smeta = {}
    out["source"] = smeta.get("source")
    out["published_at"] = smeta.get("published_at")
    out["published_by"] = smeta.get("published_by")
    out["shareable"] = (out["source"] or "").strip().lower() == SHARED_SOURCE
    try:
        cert_pem = crt_p.read_bytes()
        covers, missing, names = cert_covers_served_names(cert_pem)
        out["names"] = names
        out["covers_this_node"] = covers
        out["missing_names"] = missing
        out["not_after"] = validate_pem(cert_pem, key_p.read_bytes())["not_after"]
        out["differs"] = not (CRT.exists()
                              and CRT.read_bytes().strip() == cert_pem.strip())
    except Exception as exc:  # noqa: BLE001
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    return out


def publish_shared_cert(by: str = "publish") -> dict:
    """Copy the cert this node SERVES into data/pki-shared/ so the peer gets it.

    Refuses anything the peer must not receive. Never raises."""
    from . import cert_renew_log as jrn

    def _refuse(reason: str) -> dict:
        jrn.record(CH_SHARED, jrn.OK_SKIPPED, "publish refused: " + reason, by=by)
        return {"published": False, "reason": reason}

    if not (CRT.exists() and KEY.exists()):
        return _refuse("no certificate is served on this node yet")
    src = (_meta().get("source") or "").strip().lower()
    if src != SHARED_SOURCE:
        return _refuse(
            "the served certificate's source is %r, and only an %r certificate may "
            "be shared: a %s certificate names THIS node in its SAN, so the peer "
            "would serve a certificate for somebody else's hostname"
            % (src or "unknown", SHARED_SOURCE, src or "node-local"))
    cert_pem, key_pem = CRT.read_bytes(), KEY.read_bytes()
    try:
        info = validate_pem(cert_pem, key_pem)
    except ValueError as exc:
        return _refuse("the served cert/key pair does not validate: %s" % exc)

    crt_p, key_p, meta_p = _shared_paths()
    try:
        SHARED_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(SHARED_DIR, 0o700)
        except OSError:
            pass
        crt_p.write_bytes(cert_pem)
        _write_private(key_p, key_pem)
        names = cert_dns_names(cert_pem)
        meta_p.write_text(json.dumps({
            "source": SHARED_SOURCE,
            "subject": info["subject"],
            "not_after": info["not_after"],
            "names": names,
            "published_at": datetime.now(timezone.utc).isoformat(),
            "published_by": by,
            "published_from": node_hostname(),
            "note": "Served certificate shared with the peer node via the HA data "
                    "sync. Only imported certs land here; the internal CA key and "
                    "the per-node leaf never do.",
        }, indent=2))
    except Exception as exc:  # noqa: BLE001
        return _refuse("could not write the shared slot: %s: %s"
                       % (type(exc).__name__, exc))
    jrn.record(CH_SHARED, jrn.OK_RENEWED, "published the served certificate to the "
               "shared slot", by=by, days_left=info.get("days_left"),
               not_after=info.get("not_after"))
    return {"published": True, "reason": "", "names": names,
            "not_after": info["not_after"], "days_left": info["days_left"]}


def install_shared_cert(by: str = "ha-shared") -> dict:
    """Adopt the shared certificate on THIS node, if it is one we may serve.

    Idempotent and safe to run on either node: a slot holding what we already
    serve is a no-op (no nginx reload), and anything we must not serve is
    refused with the reason. Never raises."""
    from . import cert_renew_log as jrn

    def _refuse(reason: str) -> dict:
        jrn.record(CH_SHARED, jrn.OK_ERROR, "shared certificate refused",
                   error=reason, by=by)
        return {"installed": False, "reason": reason}

    crt_p, key_p, meta_p = _shared_paths()
    if not (crt_p.exists() and key_p.exists()):
        # Steady state on a pair that never published — not journalled, or the
        # nightly timer would write one row per node per night forever.
        return {"installed": False, "reason": "no shared certificate published"}
    try:
        smeta = json.loads(meta_p.read_text())
    except Exception:  # noqa: BLE001
        smeta = {}
    src = (smeta.get("source") or "").strip().lower()
    if src != SHARED_SOURCE:
        return _refuse(
            "the shared certificate declares source %r; only an %r certificate may "
            "be shared between nodes (a CA-issued or bootstrap cert is minted for "
            "ONE node's name)" % (src or "unknown", SHARED_SOURCE))

    cert_pem, key_pem = crt_p.read_bytes(), key_p.read_bytes()
    if CRT.exists() and CRT.read_bytes().strip() == cert_pem.strip():
        return {"installed": False, "reason": "already up to date (identical cert)",
                "days_left": current().get("days_left")}
    try:
        validate_pem(cert_pem, key_pem)
    except ValueError as exc:
        return _refuse("the shared cert/key pair does not validate: %s" % exc)
    covers, missing, presented = cert_covers_served_names(cert_pem)
    if not covers:
        return _refuse(
            "the shared certificate does not cover this node's served name(s) %s — "
            "it presents %s. Installing it would serve a certificate every browser "
            "rejects, so it is NOT installed."
            % (", ".join(missing), ", ".join(presented) or "no DNS name"))
    try:
        # Same install path as import/issue: nginx -t, automatic rollback.
        info = _install(cert_pem, key_pem, None, source=SHARED_SOURCE, by=by)
    except Exception as exc:  # noqa: BLE001 — _install already rolled nginx back
        return _refuse("install rejected: %s: %s" % (type(exc).__name__, exc))
    jrn.record(CH_SHARED, jrn.OK_RENEWED, "installed the shared certificate", by=by,
               days_left=info.get("days_left"), not_after=info.get("not_after"))
    return {"installed": True, "reason": "", "names": presented,
            "days_left": info.get("days_left"), "not_after": info.get("not_after")}
