"""Certificate Manager — the generate → sign → store → deploy → swap → revoke cycle.

The lifecycle service behind Automation → Certificate Manager. NOTHING about the
CA is hardcoded: the admin configures the ADCS connection and, per certificate
class (server / clientserver / client), a signing COMMAND TEMPLATE with
placeholders (Settings, :mod:`app.services.settings_store`). This module only
*consumes* those parameters.

Pipeline (same for the three classes; the class chooses the template + EKUs):

1. **generate** — a CSR + private key are built locally with ``cryptography``
   (no openssl subprocess). The key never leaves the box in plaintext; it is
   stored Fernet-encrypted on the :class:`ManagedCertificate` row.
2. **sign** — the class's ``submit_cmd`` is interpolated ({csr}/{out}/{ca}/…) and
   run as a subprocess. This is the Linux equivalent of the operator's
   ``certreq -submit`` — it hands the CA the CSR and gets back the signed cert.
3. **store** — serial / issue+expiry / SANs are parsed from the signed cert.
4. **deploy** — the cert + key are uploaded to the FortiWeb under a NEW name
   (naming carries {date} so the old and new coexist) over the cert-only SSH path
   (:mod:`app.services.cert_ssh`). REST cannot carry key material.
5. **swap** (separate, opt-in) — point a server policy at the new cert. Default is
   NOT to touch the binding: the new cert is left "ready for swap in a window".
6. **revoke** — run the class ``revoke_cmd`` at the CA; deleting the cert off the
   box is refused while it is still bound to a server policy.

Every step writes a :class:`ManagedCertificateEvent` (the per-cert timeline) and
an audit row; a real box write goes through :class:`FortiWebOps`. Email
notifications are best-effort (:mod:`app.services.email_service`).
"""
from __future__ import annotations

import logging
import os
import re
import shlex
import subprocess
import tempfile
from datetime import datetime
from urllib.parse import quote as _url_quote

from ..models import (DeviceCertificate, ManagedCertificate,
                      ManagedCertificateEvent, db)
from . import cert_adc, cert_ssh, naming
from . import settings_store as store
from .audit import log_action
from .fortiweb_ops import FortiWebOps

logger = logging.getLogger(__name__)

SERVER_POLICY_EP = "/api/v2.0/cmdb/server-policy/policy"
# The policy fields that can bind a Local certificate (checked for "in use").
_CERT_BIND_FIELDS = ("certificate", "sni-certificate", "ssl-client-verify")

# Cross-binder cert-usage endpoints: SNI members carry per-domain local-certs,
# and system/global carries the GUI / management HTTPS certificate.
SNI_EP = "/api/v2.0/cmdb/system/certificate.sni"
GLOBAL_EP = "/api/v2.0/cmdb/system/global"
GUI_CERT_FIELD = "https-certificate"

_SIGN_TIMEOUT = 180  # seconds for the external signer


class CertManagerError(Exception):
    """A lifecycle step failed (generation / signing / deploy)."""


# --------------------------------------------------------------------------- #
#  Timeline + audit                                                             #
# --------------------------------------------------------------------------- #
def _event(cert: ManagedCertificate, kind: str, ok: bool, detail: str = "",
           by: str = "") -> None:
    try:
        db.session.add(ManagedCertificateEvent(
            cert_id=cert.id, kind=kind, ok=ok,
            by=by or _actor(), detail=(detail or "")[:4000],
            ts=datetime.utcnow()))
        db.session.commit()
    except Exception:  # noqa: BLE001 — the timeline is best-effort
        db.session.rollback()
    log_action(f"certmgr.{kind}", target=cert.name,
               appliance_id=cert.appliance_id, detail=f"ok={ok} {detail}"[:400])


def _actor() -> str:
    try:
        from flask_login import current_user
        if current_user and current_user.is_authenticated:
            return current_user.username
    except Exception:  # noqa: BLE001
        pass
    return "system"


# --------------------------------------------------------------------------- #
#  1) CSR + key generation (pure cryptography, no openssl subprocess)          #
# --------------------------------------------------------------------------- #
_EKU_BY_CLASS = {
    "server": ("server_auth",),
    "client": ("client_auth",),
    "clientserver": ("server_auth", "client_auth"),
}

_DN_OID = {}  # lazily filled to avoid an import at module load


def _dn_oid_map():
    global _DN_OID
    if not _DN_OID:
        from cryptography.x509.oid import NameOID
        _DN_OID = {
            "CN": NameOID.COMMON_NAME, "O": NameOID.ORGANIZATION_NAME,
            "OU": NameOID.ORGANIZATIONAL_UNIT_NAME, "C": NameOID.COUNTRY_NAME,
            "L": NameOID.LOCALITY_NAME, "ST": NameOID.STATE_OR_PROVINCE_NAME,
            "EMAILADDRESS": NameOID.EMAIL_ADDRESS, "EMAIL": NameOID.EMAIL_ADDRESS,
        }
    return _DN_OID


def _parse_dn(dn: str):
    from cryptography import x509
    attrs = []
    oids = _dn_oid_map()
    for part in (dn or "").split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        oid = oids.get(k.strip().upper())
        if oid and v.strip():
            attrs.append(x509.NameAttribute(oid, v.strip()))
    if not attrs:  # never build an empty subject
        attrs.append(x509.NameAttribute(_dn_oid_map()["CN"], "unnamed"))
    return x509.Name(attrs)


def _parse_sans(san_spec: str):
    """``"DNS:a.com,DNS:b.com,IP:192.0.2.1"`` → list of x509 GeneralName. A bare
    token with no ``DNS:``/``IP:`` prefix is treated as a DNS name."""
    import ipaddress

    from cryptography import x509
    out = []
    for tok in re.split(r"[,\s]+", (san_spec or "").strip()):
        if not tok:
            continue
        low = tok.lower()
        if low.startswith("dns:"):
            out.append(x509.DNSName(tok[4:]))
        elif low.startswith("ip:"):
            try:
                out.append(x509.IPAddress(ipaddress.ip_address(tok[3:])))
            except ValueError:
                continue
        elif low.startswith("email:"):
            out.append(x509.RFC822Name(tok[6:]))
        else:
            out.append(x509.DNSName(tok))
    return out


def generate_csr(subject: str, sans: str, cert_class: str,
                 key_type: str = "rsa", key_size: str = "2048"):
    """Return ``(csr_pem, key_pem)``. Adds the EKUs for the class so the CA
    template's key-usage matches the requested purpose."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID

    if (key_type or "rsa").lower() == "ec":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        try:
            bits = int(key_size or 2048)
        except (TypeError, ValueError):
            bits = 2048
        key = rsa.generate_private_key(public_exponent=65537, key_size=max(2048, bits))

    builder = x509.CertificateSigningRequestBuilder().subject_name(_parse_dn(subject))
    san_list = _parse_sans(sans)
    if san_list:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)
    eku_map = {"server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
               "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH}
    ekus = [eku_map[e] for e in _EKU_BY_CLASS.get(cert_class, ("server_auth",))]
    if ekus:
        builder = builder.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)

    csr = builder.sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return csr_pem, key_pem


# --------------------------------------------------------------------------- #
#  2) Sign the CSR via the admin-configured external command                   #
# --------------------------------------------------------------------------- #
def _interpolate(template: str, mapping: dict) -> str:
    out = template or ""
    for tok, val in mapping.items():
        out = out.replace("{" + tok + "}", str(val))
    return out


def _argv_from_template(cmd_tmpl: str, mapping: dict) -> list[str]:
    """Build the argv SAFELY: the admin's template is shlex-parsed FIRST and the
    tokens are substituted inside each argument afterwards. A value carrying
    spaces / quotes (a password, a DN, an URL) therefore stays ONE argument and
    can never break parsing or inject extra arguments into the CA command."""
    try:
        parts = shlex.split(cmd_tmpl or "")
    except ValueError as exc:
        raise CertManagerError(f"command template is not parseable: {exc}") from exc
    argv = [_interpolate(p, mapping) for p in parts]
    if not argv:
        raise CertManagerError("command template is empty")
    return argv


def _redact(text: str, secret: str) -> str:
    return text.replace(secret, "********") if secret else text


# --------------------------------------------------------------------------- #
#  Protocol dispatch — the CA backend is CHOSEN in the admin console            #
#  (Settings → Certificate Manager): "adcs" = enterprise-CA command template,   #
#  "acme" = an ACME client (certbot/acme.sh/lego) driven through the same       #
#  template contract. Adding a protocol = a settings_store entry + a context    #
#  builder here; the pipeline (generate/sign/deploy/swap/revoke) is shared.     #
# --------------------------------------------------------------------------- #
def _signing_context(cert_class: str) -> tuple[str, str, dict, str]:
    """(protocol, submit command template, base token mapping, secret) for the
    ACTIVE issuance protocol. ``{csr}``/``{out}`` are added at run time."""
    protocol = store.cert_manager_protocol()
    ccfg = store.cert_class_config(cert_class)
    if protocol == "acme":
        acme = store.cert_manager_acme(reveal_secret=True)
        secret = acme.get("eab_hmac", "")
        mapping = {
            "bin": acme.get("bin", "certbot"),
            "directory": acme.get("directory_url", ""),
            "email": acme.get("account_email", ""),
            "eab_kid": acme.get("eab_kid", ""),
            "eab_hmac": secret,
            "challenge": acme.get("challenge", "http-01"),
            "template": ccfg.get("template", ""),
        }
        return "acme", (acme.get("submit_cmd") or "").strip(), mapping, secret
    adcs = store.cert_manager_adcs(reveal_secret=True)
    secret = adcs.get("secret", "")
    mapping = {
        "bin": adcs.get("bin", "certipy"),
        "user": adcs.get("user", ""),
        "domain": adcs.get("domain", ""),
        "password": secret,
        "ca": adcs.get("ca", ""),
        "ca_name": adcs.get("ca_name", ""),
        "template": ccfg.get("template", ""),
    }
    return "adcs", (ccfg.get("submit_cmd") or "").strip(), mapping, secret


def _revoke_context(cert: ManagedCertificate) -> tuple[str, str, dict, str]:
    """(protocol, revoke command template, base token mapping, secret). The ACME
    revoke references the CERTIFICATE itself ({cert}, written to a temp file at
    run time); the ADCS revoke references {serial}/{request_id}."""
    protocol = store.cert_manager_protocol()
    if protocol == "acme":
        acme = store.cert_manager_acme(reveal_secret=True)
        secret = acme.get("eab_hmac", "")
        mapping = {
            "bin": acme.get("bin", "certbot"),
            "directory": acme.get("directory_url", ""),
            "email": acme.get("account_email", ""),
            "eab_kid": acme.get("eab_kid", ""),
            "eab_hmac": secret,
            "challenge": acme.get("challenge", "http-01"),
            "serial": cert.serial or "",
        }
        return "acme", (acme.get("revoke_cmd") or "").strip(), mapping, secret
    ccfg = store.cert_class_config(cert.cert_class)
    adcs = store.cert_manager_adcs(reveal_secret=True)
    secret = adcs.get("secret", "")
    mapping = {
        "bin": adcs.get("bin", "certipy"), "user": adcs.get("user", ""),
        "domain": adcs.get("domain", ""), "password": secret,
        "ca": adcs.get("ca", ""), "ca_name": adcs.get("ca_name", ""),
        "serial": cert.serial or "", "request_id": cert.ca_request_id or "",
    }
    return "adcs", (ccfg.get("revoke_cmd") or "").strip(), mapping, secret


def _extract_cert_pem(out_path: str, stdout: str, stderr: str) -> str:
    """Find the signed certificate: prefer the ``{out}`` file, else scan stdout.
    Accepts PEM or DER (converted to PEM)."""
    data = b""
    if out_path and os.path.exists(out_path):
        with open(out_path, "rb") as fh:
            data = fh.read()
    text = data.decode("utf-8", "replace") if data else ""
    for blob in (text, stdout or ""):
        m = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
                      blob, re.S)
        if m:
            return m.group(0) + "\n"
    if data and b"-----BEGIN" not in data:  # maybe DER
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            cert = x509.load_der_x509_certificate(data)
            return cert.public_bytes(serialization.Encoding.PEM).decode()
        except Exception:  # noqa: BLE001
            pass
    return ""


def sign_csr(cert_class: str, csr_pem: str) -> tuple[str, str]:
    """Run the ACTIVE protocol's signing command against the CSR. Returns
    ``(cert_pem, log)``.

    The command template ({csr}/{out}/… — ADCS or ACME tokens) is fully
    admin-defined — this is the "the user specifies the command parameters"
    contract. Raises :class:`CertManagerError` on failure."""
    protocol, cmd_tmpl, mapping, secret = _signing_context(cert_class)
    if not cmd_tmpl:
        raise CertManagerError(
            f"no signing command configured for protocol {protocol!r} / "
            f"class {cert_class!r}")

    with tempfile.TemporaryDirectory(prefix="certmgr-") as d:
        csr_path = os.path.join(d, "request.csr")
        out_path = os.path.join(d, "signed.cer")
        with open(csr_path, "w") as fh:
            fh.write(csr_pem)
        mapping = dict(mapping, csr=csr_path, out=out_path)
        argv = _argv_from_template(cmd_tmpl, mapping)

        safe_cmd = _redact(" ".join(shlex.quote(a) for a in argv), secret)
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=_SIGN_TIMEOUT, cwd=d)
        except FileNotFoundError as exc:
            raise CertManagerError(
                f"signing binary not found: {argv[0]!r} — install it or set {{bin}} "
                f"(cmd: {safe_cmd})") from exc
        except subprocess.TimeoutExpired as exc:
            raise CertManagerError(f"signing command timed out after {_SIGN_TIMEOUT}s") from exc

        stdout = _redact(proc.stdout or "", secret)
        stderr = _redact(proc.stderr or "", secret)
        log = (f"$ {safe_cmd}\n[rc={proc.returncode}]\n{stdout}\n{stderr}").strip()
        cert_pem = _extract_cert_pem(out_path, proc.stdout or "", proc.stderr or "")
        if not cert_pem:
            raise CertManagerError(
                f"signer produced no certificate (rc={proc.returncode}). "
                f"Check the command template + CA config.\n{log[:1500]}")
        return cert_pem, log


# --------------------------------------------------------------------------- #
#  3) Parse the signed certificate                                             #
# --------------------------------------------------------------------------- #
def parse_certificate(cert_pem: str) -> dict:
    """serial / issued_at / expires_at / SAN dns+ip from a PEM cert (best-effort)."""
    from cryptography import x509
    info = {"serial": "", "issued_at": None, "expires_at": None, "sans": []}
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception:  # noqa: BLE001
        return info
    try:
        info["serial"] = format(cert.serial_number, "x")
    except Exception:  # noqa: BLE001
        pass
    try:  # cryptography >=42 exposes *_utc; fall back to the naive property
        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        info["issued_at"] = nb.replace(tzinfo=None)
        info["expires_at"] = na.replace(tzinfo=None)
    except Exception:  # noqa: BLE001
        pass
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info["sans"] = [str(g.value) for g in ext.value]
    except Exception:  # noqa: BLE001
        pass
    return info


# --------------------------------------------------------------------------- #
#  Naming                                                                       #
# --------------------------------------------------------------------------- #
def cert_name_for(cn: str, cert_class: str, serial: str = "") -> str:
    adcs = store.cert_manager_adcs()
    pattern = naming.effective_scheme(
        store.naming_overrides("fortiweb"), "fortiweb").get(
        "managed_certificate", "cert-{class}-{cn}-{date}")
    date_str = datetime.utcnow().strftime(adcs.get("date_format") or "%Y%m%d")
    return naming.render_cert_name(pattern, cls=cert_class, cn=cn,
                                   date_str=date_str, serial=(serial or "")[:8])


def _cn_of(cert: ManagedCertificate) -> str:
    m = re.search(r"CN=([^,]+)", cert.subject or "")
    if m:
        return m.group(1).strip()
    return cert.sans[0] if cert.sans else cert.name


# --------------------------------------------------------------------------- #
#  Orchestration: create / renew                                               #
# --------------------------------------------------------------------------- #
def create_certificate(appliance, cn: str, cert_class: str, *, extra_sans=None,
                       deploy: bool = True, supersedes: int | None = None,
                       actor: str = "") -> dict:
    """Full cycle for one certificate. Returns ``{ok, cert_id, name, error}``.

    Never raises — every failure is captured on the row's timeline and returned.
    """
    cn = (cn or "").strip()
    if cn == "":
        return {"ok": False, "error": "a certificate CN/hostname is required.", "cert_id": None}
    if cert_class not in store.CERT_CLASSES:
        return {"ok": False, "error": f"unknown certificate class {cert_class!r}.", "cert_id": None}

    ccfg = store.cert_class_config(cert_class)
    if not ccfg.get("template"):
        return {"ok": False,
                "error": f"class {cert_class!r} has no ADCS template configured "
                         "(Settings → Certificate Manager).", "cert_id": None}

    subject = _interpolate(ccfg.get("subject_format", "CN={cn}"), {"cn": cn})
    san_spec = _interpolate(ccfg.get("san_format", "DNS:{cn}"), {"cn": cn})
    if extra_sans:
        san_spec = (san_spec + "," + ",".join(
            s if ":" in s else "DNS:" + s for s in extra_sans)).strip(",")

    # --- generate CSR + key; open a 'pending' row (key encrypted) ---------
    try:
        csr_pem, key_pem = generate_csr(
            subject, san_spec, cert_class,
            key_type=ccfg.get("key_type", "rsa"),
            key_size=ccfg.get("key_size", "2048"))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"CSR generation failed: {exc}", "cert_id": None}

    name = cert_name_for(cn, cert_class)
    row = ManagedCertificate(
        name=name, appliance_id=getattr(appliance, "id", None),
        cert_class=cert_class, subject=subject, status="pending",
        created_by=actor or _actor(), supersedes_id=supersedes)
    row.sans = [s.split(":", 1)[-1] for s in re.split(r"[,\s]+", san_spec) if s]
    row.csr_pem = csr_pem
    row.private_key = key_pem
    db.session.add(row)
    db.session.commit()
    _event(row, "generate", True, f"CSR generated for {subject}", by=actor)

    # --- sign ------------------------------------------------------------
    try:
        cert_pem, sign_log = sign_csr(cert_class, csr_pem)
    except CertManagerError as exc:
        _event(row, "error", False, f"sign failed: {exc}", by=actor)
        return {"ok": False, "error": str(exc), "cert_id": row.id, "name": name}

    meta = parse_certificate(cert_pem)
    row.cert_pem = cert_pem
    row.serial = meta["serial"]
    row.issued_at = meta["issued_at"]
    row.expires_at = meta["expires_at"]
    if meta["sans"]:
        row.sans = meta["sans"]
    db.session.commit()
    _event(row, "sign", True,
           f"signed serial={row.serial} expires={row.expires_at}", by=actor)

    # --- deploy (cert + key over the cert-only SSH write path) -----------
    if deploy:
        if getattr(appliance, "id", None) is None:
            _event(row, "deploy", False, "no target appliance for deploy", by=actor)
            return {"ok": False, "error": "signed but not deployed (no appliance).",
                    "cert_id": row.id, "name": name}
        try:
            # FortiADC takes key material over a REST multipart upload; FortiWeb
            # over the SSH CLI. Same call shape, dispatched on the device kind.
            deployer = (cert_adc if getattr(appliance, "kind", "fortiweb") == "fortiadc"
                        else cert_ssh)
            out = deployer.deploy_certificate(
                appliance, name, cert_pem, row.private_key,
                secret=appliance.password)
            _event(row, "deploy", True, f"uploaded to {appliance.name}", by=actor)
            row.status = "pending"
            db.session.commit()
        except Exception as exc:  # noqa: BLE001
            _event(row, "deploy", False, f"upload to {appliance.name} failed: {exc}",
                   by=actor)
            return {"ok": False, "error": f"signed but deploy failed: {exc}",
                    "cert_id": row.id, "name": name}

    _notify(row, subject="Certificate ready",
            body=(f"Certificate {name} ({cert_class}) for {cn} is signed and "
                  f"{'deployed to ' + appliance.name if deploy and appliance else 'stored'}. "
                  f"Expires {row.expires_at}. It is NOT yet bound to a policy — "
                  "swap it in during a maintenance window."))
    return {"ok": True, "cert_id": row.id, "name": name, "error": ""}


def renew_certificate(cert: ManagedCertificate, *, deploy: bool = True,
                      actor: str = "") -> dict:
    """Generate a fresh certificate for the same CN/class/device, with a new
    {date}-stamped name so it coexists with the current one. Does NOT swap the
    binding (decision: leave it ready for a maintenance-window swap)."""
    appliance = None
    if cert.appliance_id:
        from ..models import Appliance
        appliance = db.session.get(Appliance, cert.appliance_id)
    res = create_certificate(appliance, _cn_of(cert), cert.cert_class,
                             extra_sans=None, deploy=deploy,
                             supersedes=cert.id, actor=actor)
    if res.get("ok"):
        _event(cert, "renew", True,
               f"renewed → {res.get('name')} (cert #{res.get('cert_id')})", by=actor)
    return res


# --------------------------------------------------------------------------- #
#  Bindings / swap                                                              #
# --------------------------------------------------------------------------- #
def read_bindings(appliance, cert_name: str) -> list[str]:
    """Server policies on *appliance* that reference *cert_name* (any cert field).
    Read-only; returns [] on any error (so callers never crash on a dead box)."""
    try:
        resp = appliance.build_client().api_call("GET", SERVER_POLICY_EP)
        body = resp.json() if resp is not None else {}
    except Exception:  # noqa: BLE001
        return []
    rows = body.get("results") if isinstance(body, dict) else None
    if not isinstance(rows, list):
        return []
    out = []
    for p in rows:
        if not isinstance(p, dict):
            continue
        if any(str(p.get(f, "")).strip() == cert_name for f in _CERT_BIND_FIELDS):
            out.append(str(p.get("name", "")))
    return sorted({n for n in out if n})


def _get_results(client, ep):
    """GET *ep* (a canonical ``/api/v2.0/cmdb/...`` path) and return its ``results``
    (a list for object collections, a dict for singletons like system/global), or
    ``None`` on any error. Read-only, best-effort."""
    try:
        resp = client.api_call("GET", ep)
        body = resp.json() if resp is not None else {}
    except Exception:  # noqa: BLE001
        return None
    return body.get("results") if isinstance(body, dict) else None


def _enumerate_usage(client, appliance, cert_name):
    """Walk the three cert binders and return ``(complete, rows)``.

    *rows* is the same list of ``{kind, target, field, sub_mkey, label, probe}``
    dicts :func:`cert_usage` builds. *complete* is ``True`` only if every binder
    read succeeded: if ANY ``_get_results`` returns ``None`` (a device read
    error) that binder could not be verified and *complete* becomes ``False``.
    The removal safety guard must refuse unless *complete* is ``True``.
    """
    complete = True
    out = []

    rows = _get_results(client, SERVER_POLICY_EP)
    if rows is None:
        complete = False
    for p in (rows or []):
        if not isinstance(p, dict):
            continue
        pname = str(p.get("name", ""))
        for f in _CERT_BIND_FIELDS:
            if str(p.get(f, "")).strip() == cert_name:
                out.append({
                    "kind": "server-policy", "target": pname, "field": f,
                    "sub_mkey": None,
                    "label": f"Server policy {pname}" + ("" if f == "certificate" else f" ({f})"),
                    "probe": _policy_probe(client, p),
                })

    sni_rows = _get_results(client, SNI_EP)
    if sni_rows is None:
        complete = False
    for s in (sni_rows or []):
        if not isinstance(s, dict):
            continue
        sname = str(s.get("name", ""))
        for m in (s.get("members") or []):
            if isinstance(m, dict) and str(m.get("local-cert", "")).strip() == cert_name:
                out.append({
                    "kind": "sni", "target": sname, "field": "local-cert",
                    "sub_mkey": str(m.get("id", "")),
                    "label": f"SNI {sname} \u2014 {m.get('domain', '')}".strip(" \u2014"),
                    "probe": None,
                })

    g = _get_results(client, GLOBAL_EP)
    if g is None:
        complete = False
    if isinstance(g, dict) and str(g.get(GUI_CERT_FIELD, "")).strip() == cert_name:
        out.append({
            "kind": "gui", "target": "", "field": GUI_CERT_FIELD, "sub_mkey": None,
            "label": "GUI / admin access (HTTPS management cert)",
            "probe": {"host": getattr(appliance, "host", ""), "port": _admin_sport(g)},
        })
    return complete, out


def cert_usage(appliance, cert_name):
    """Every place *cert_name* is bound on *appliance* (best-effort; [] on failure).

    Keeps its lenient contract for display callers. For the *safety* decision in
    remove_device_certificate, use _enumerate_usage which reports completeness.
    Dispatches on ``appliance.kind`` (FortiADC walks the cert-group → SSL-profile
    → virtual-server chain instead of server-policy / SNI / GUI).
    """
    try:
        client = appliance.build_client(timeout=6.0)
    except Exception:  # noqa: BLE001
        return []
    if getattr(appliance, "kind", "fortiweb") == "fortiadc":
        from . import cert_adc
        _complete, rows = cert_adc.enumerate_usage(client, cert_name)
        return rows
    _complete, rows = _enumerate_usage(client, appliance, cert_name)
    return rows


def _policy_probe(client, policy):
    """Best-effort ``{host, port}`` to TLS-probe a server policy's live leaf.

    Resolves: policy.vserver → vserver.vip-list → effective VIP IP (handles
    both static VIPs and interface-IP VIPs via ``_resolve_vip_ips``).
    Returns ``None`` when no reachable IP can be determined.
    """
    vserver = str(policy.get("vserver") or "").strip()
    if not vserver:
        return None
    vip_rows = client._safe_list(
        "/api/v2.0/cmdb/server-policy/vserver/vip-list?mkey=%s" % _url_quote(vserver, safe="")
    )
    for v in client._resolve_vip_ips(vip_rows or []):
        ip = str(v.get("effective_ip") or "").strip()
        if ip and not ip.startswith("0.0.0.0"):
            return {"host": ip, "port": 443}
    return None


# Certificate stores whose X.509 detail can be read over the CLI. FortiWeb prints
# the fully-decoded cert with ``get system certificate <cli> <name>`` — the only
# source of validity/issuer/SANs for a cert that is on the box but bound nowhere
# (so it can never be TLS-probed). Verified for the Local store on fw 7.6/8.0.
_CERT_STORE_CLI = {"Local": "local"}


def device_cert_detail_via_ssh(appliance, store_label, cert_name, *,
                               timeout: float = 20.0):
    """Best-effort X.509 detail for an on-device cert, read over SSH.

    Runs the read-only ``get system certificate <cli> <name>`` and parses the
    decoded output (:func:`cert_probe.detail_from_fortiweb_cli`). Returns the same
    detail dict the TLS probe / stored PEM produce, or ``None`` on any failure or
    for a store with no CLI reader. Never raises."""
    cli = _CERT_STORE_CLI.get(store_label)
    if not cli:
        return None
    try:
        cert_ssh.assert_cert_name(cert_name)  # reuse the injection-safe name guard
    except Exception:  # noqa: BLE001
        return None
    try:
        from .ssh_ops import FortiWebReadonlySSH
        from . import cert_probe
        with FortiWebReadonlySSH(appliance, timeout=timeout) as ssh:
            out = ssh.run_readonly(f"get system certificate {cli} {cert_name}")
        return cert_probe.detail_from_fortiweb_cli(out)
    except Exception:  # noqa: BLE001 — SSH unreachable / parse miss → no detail
        logger.debug("SSH cert detail read failed for %s", cert_name, exc_info=True)
        return None


def _admin_sport(global_obj):
    v = global_obj.get("admin-sport")
    try:
        return int(v)
    except (TypeError, ValueError):
        return 443


def swap_binding(appliance, policy: str, cert_name: str, *,
                 dry_run: bool = True, actor: str = "") -> dict:
    """Point *policy*'s certificate at *cert_name* via FortiWebOps (snapshot +
    audit + change-history). dry_run previews without touching the box."""
    ops = FortiWebOps(appliance)
    result = ops.update(SERVER_POLICY_EP, policy, {"certificate": cert_name},
                        dry_run=dry_run)
    ok = bool(result.get("ok"))
    return {"ok": ok, "error": result.get("error", ""),
            "request": result.get("request"), "dry_run": dry_run}


def swap_server_policy_cert(appliance, policy, field, cert_name, *, dry_run=True):
    """Point *policy*.*field* at *cert_name* (field must be a cert binding field)."""
    if field not in _CERT_BIND_FIELDS:
        return {"ok": False, "error": f"field {field!r} is not a cert binding field"}
    r = FortiWebOps(appliance).update(SERVER_POLICY_EP, policy, {field: cert_name},
                                      dry_run=dry_run)
    return _op_result(r, dry_run)


def swap_sni_member(appliance, sni_name, member_id, cert_name, *, dry_run=True):
    """Repoint one SNI member row's local-cert (by-parent sub-table update)."""
    r = FortiWebOps(appliance).update(SNI_EP + "/members", sni_name,
                                      {"local-cert": cert_name},
                                      dry_run=dry_run, sub_mkey=str(member_id))
    return _op_result(r, dry_run)


def swap_gui_cert(appliance, cert_name, *, dry_run=True):
    """Set the GUI/admin HTTPS server certificate. FortiWeb: system/global
    singleton PUT via FortiWebOps. FortiADC: ``system_global.https-server-cert``
    over REST (the live-verified bind path)."""
    if getattr(appliance, "kind", "fortiweb") == "fortiadc":
        req = {"method": "PUT", "path": "system_global",
               "body": {"https-server-cert": cert_name}}
        if dry_run:
            return {"ok": True, "error": "", "request": req, "dry_run": True}
        try:
            appliance.build_client(timeout=8.0).bind_https_admin_cert(cert_name)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc), "request": req, "dry_run": False}
        log_action("certmgr.swap_gui", target=cert_name,
                   appliance_id=getattr(appliance, "id", None))
        return {"ok": True, "error": "", "request": req, "dry_run": False}
    r = FortiWebOps(appliance).update(GLOBAL_EP, None, {GUI_CERT_FIELD: cert_name},
                                      dry_run=dry_run)
    return _op_result(r, dry_run)


def _op_result(r, dry_run):
    """Normalise an OpResult/dict from FortiWebOps into the view's dict shape."""
    get = (r.get if isinstance(r, dict) else (lambda k, d=None: getattr(r, k, d)))
    return {"ok": bool(get("ok")), "error": get("error", "") or "",
            "request": get("request"), "dry_run": dry_run}


def _audit_remove(appliance, cert_name, *, ok, detail):
    """Best-effort audit for a device-cert removal decision. Never raises —
    a failed audit must not sink a safety refusal."""
    try:
        log_action("certmgr.device_remove", target=cert_name,
                   appliance_id=getattr(appliance, "id", None),
                   detail=f"ok={ok} {detail}"[:400])
    except Exception:  # noqa: BLE001 — auditing must never break the op
        pass


def remove_device_certificate(appliance, store_label, cert_name, *,
                              dry_run=True, actor=""):
    """Delete an on-device certificate — REFUSED unless we can positively CONFIRM
    it is bound NOWHERE (server-policy / SNI / GUI). Fails CLOSED: if the client
    cannot be built, or ANY binder read fails, removal is refused. ``Local`` store
    deletes over SSH (only path for key-material stores); other stores delete over
    cmdb REST. FortiADC deletes over REST after the same fail-closed check
    (usage = cert-group / SSL-profile / virtual-server / admin-GUI chain).
    dry_run reports what WOULD happen without touching the box."""
    try:
        client = appliance.build_client(timeout=6.0)
    except Exception as exc:  # noqa: BLE001
        _audit_remove(appliance, cert_name, ok=False,
                      detail=f"refused: cannot verify bindings (client): {exc}")
        return {"ok": False, "removed": False, "bindings": [],
                "error": f"cannot verify bindings on {getattr(appliance,'name','device')}: {exc}"}

    is_adc = getattr(appliance, "kind", "fortiweb") == "fortiadc"
    if is_adc:
        from . import cert_adc
        complete, usage = cert_adc.enumerate_usage(client, cert_name)
    else:
        complete, usage = _enumerate_usage(client, appliance, cert_name)
    if not complete:
        _audit_remove(appliance, cert_name, ok=False,
                      detail="refused: binding check incomplete (device read failed)")
        return {"ok": False, "removed": False, "bindings": usage,
                "error": "could not fully verify bindings (a device read failed); "
                         "refusing to remove"}
    if usage:
        _audit_remove(appliance, cert_name, ok=False,
                      detail="refused: still bound to " + ", ".join(u["label"] for u in usage))
        return {"ok": False, "removed": False, "bindings": usage,
                "error": "still bound to: " + ", ".join(u["label"] for u in usage)}

    if dry_run:
        how = ("REST delete" if is_adc else
               "SSH config-delete" if store_label == "Local" else "cmdb REST delete")
        return {"ok": True, "removed": False, "dry_run": True, "bindings": [],
                "error": "", "summary": f"[dry-run] would remove {cert_name} via {how}"}

    if is_adc:
        from . import cert_adc
        logical = next((lg for _k, lbl, lg in cert_adc.ADC_CERT_STORES
                        if lbl == store_label), "")
        if not logical:
            _audit_remove(appliance, cert_name, ok=False,
                          detail=f"refused: unknown ADC store {store_label!r}")
            return {"ok": False, "removed": False, "bindings": [],
                    "error": f"don't know how to delete a {store_label!r} certificate"}
        try:
            client.delete(logical, cert_name)
        except Exception as exc:  # noqa: BLE001
            _audit_remove(appliance, cert_name, ok=False, detail=str(exc))
            return {"ok": False, "removed": False, "bindings": [], "error": str(exc)}
        _audit_remove(appliance, cert_name, ok=True,
                      detail=f"removed store={store_label} by={actor or _actor()} (REST)")
        return {"ok": True, "removed": True, "error": "", "bindings": []}

    try:
        if store_label == "Local":
            cert_ssh.remove_certificate(appliance, cert_name, secret=appliance.password)
        else:
            ep = _store_ep(store_label)
            if not ep:
                _audit_remove(appliance, cert_name, ok=False,
                              detail=f"refused: unknown store {store_label!r}")
                return {"ok": False, "removed": False, "bindings": [],
                        "error": f"don't know how to delete a {store_label!r} certificate"}
            res = FortiWebOps(appliance).delete(ep, cert_name, dry_run=False)
            r = _op_result(res, False)
            if not r["ok"]:
                _audit_remove(appliance, cert_name, ok=False,
                              detail=f"REST delete failed: {r['error']}")
                return {"ok": False, "removed": False, "bindings": [],
                        "error": r["error"]}
    except Exception as exc:  # noqa: BLE001
        _audit_remove(appliance, cert_name, ok=False, detail=str(exc))
        return {"ok": False, "removed": False, "bindings": [], "error": str(exc)}

    _audit_remove(appliance, cert_name, ok=True,
                  detail=f"removed store={store_label} by={actor or _actor()}")
    return {"ok": True, "removed": True, "error": "", "bindings": []}


def _store_ep(store_label):
    for _key, label, ep in _DEVICE_CERT_STORES:
        if label == store_label:
            return ep
    return ""


def confirm_swap(cert: ManagedCertificate, policy: str, *, actor: str = "") -> dict:
    """Real swap of *policy* onto *cert*, then reconcile inventory state: the new
    cert becomes active/bound, the one it supersedes becomes 'superseded'."""
    from ..models import Appliance
    appliance = db.session.get(Appliance, cert.appliance_id) if cert.appliance_id else None
    if appliance is None:
        return {"ok": False, "error": "certificate has no target appliance."}
    res = swap_binding(appliance, policy, cert.name, dry_run=False, actor=actor)
    if res.get("ok"):
        bound = set(cert.bound_policies)
        bound.add(policy)
        cert.bound_policies = sorted(bound)
        cert.status = "active"
        db.session.commit()
        _event(cert, "swap", True, f"policy {policy} → {cert.name}", by=actor)
        if cert.supersedes_id:
            old = db.session.get(ManagedCertificate, cert.supersedes_id)
            if old and old.status not in ("revoked",):
                old.status = "superseded"
                old.superseded_at = old.superseded_at or datetime.utcnow()
                db.session.commit()
                _event(old, "swap", True,
                       f"superseded by {cert.name} on policy {policy}", by=actor)
    else:
        _event(cert, "error", False, f"swap onto {policy} failed: {res.get('error')}",
               by=actor)
    return res


# --------------------------------------------------------------------------- #
#  Revoke                                                                        #
# --------------------------------------------------------------------------- #
def revoke_certificate(cert: ManagedCertificate, *, delete_from_box: bool = False,
                       dry_run: bool = False, actor: str = "") -> dict:
    """Revoke at the CA (via the ACTIVE protocol's ``revoke_cmd``) and mark the
    row revoked. Deleting the cert off the FortiWeb is refused while it is bound
    to any server policy."""
    protocol, cmd_tmpl, mapping, secret = _revoke_context(cert)

    if dry_run:
        preview = _redact(_interpolate(cmd_tmpl, dict(mapping, cert="<cert.pem>")),
                          secret)
        return {"ok": True, "dry_run": True,
                "summary": f"[dry-run] revoke ({protocol}): {preview}",
                "bindings": read_bindings_for(cert)}

    # 1) CA revoke (best-effort but reported).
    ca_ok, ca_log = True, ""
    if cmd_tmpl:
        with tempfile.TemporaryDirectory(prefix="certmgr-rev-") as d:
            cert_path = os.path.join(d, "cert.pem")
            with open(cert_path, "w") as fh:
                fh.write(cert.cert_pem or "")
            try:
                argv = _argv_from_template(cmd_tmpl, dict(mapping, cert=cert_path))
                proc = subprocess.run(argv, capture_output=True,
                                      text=True, timeout=_SIGN_TIMEOUT, cwd=d)
                ca_ok = proc.returncode == 0
                ca_log = _redact(f"[{protocol}] [rc={proc.returncode}] "
                                 f"{proc.stdout}\n{proc.stderr}", secret)[:2000]
            except Exception as exc:  # noqa: BLE001
                ca_ok, ca_log = False, f"revoke command error: {exc}"
    else:
        ca_log = (f"no revoke_cmd configured for protocol {protocol!r} — "
                  "marked revoked locally only.")

    cert.status = "revoked"
    cert.revoked_at = cert.revoked_at or datetime.utcnow()
    db.session.commit()
    _event(cert, "revoke", ca_ok, ca_log, by=actor)

    # 2) Optionally remove from the box — ONLY if not bound anywhere.
    box_detail = ""
    if delete_from_box and cert.appliance_id:
        from ..models import Appliance
        appliance = db.session.get(Appliance, cert.appliance_id)
        # Fail-closed: delegate to the strict remover, which verifies ALL THREE
        # binders (server-policy / SNI / GUI) via _enumerate_usage and refuses on
        # any unverifiable read. Managed certs live in the Local store (key
        # material -> SSH config-delete), matching revoke's previous SSH delete.
        res = remove_device_certificate(appliance, "Local", cert.name,
                                        dry_run=False, actor=actor)
        if res.get("removed"):
            box_detail = f"deleted {cert.name} from {appliance.name}"
            _event(cert, "revoke", True, box_detail, by=actor)
        else:
            box_detail = res.get("error") or "device delete refused"
            _event(cert, "revoke", False, box_detail, by=actor)
            return {"ok": ca_ok, "revoked": True, "deleted": False,
                    "bindings": res.get("bindings", []), "error": box_detail,
                    "log": ca_log}

    _notify(cert, subject="Certificate revoked",
            body=f"Certificate {cert.name} ({cert.cert_class}) was revoked. {box_detail}")
    return {"ok": ca_ok, "revoked": True, "deleted": delete_from_box,
            "bindings": [], "error": "" if ca_ok else "CA revoke reported an error",
            "log": ca_log}


def read_bindings_for(cert: ManagedCertificate) -> list[str]:
    """Bindings for a stored cert (resolves its appliance). [] if none/unknown."""
    if not cert.appliance_id:
        return []
    from ..models import Appliance
    appliance = db.session.get(Appliance, cert.appliance_id)
    if appliance is None:
        return []
    return read_bindings(appliance, cert.name)


# --------------------------------------------------------------------------- #
#  Expiry sweep (consumed by the automation actions)                            #
# --------------------------------------------------------------------------- #
def expiring_certificates(appliance_id: int | None, cert_class: str,
                          within_days: int) -> list[ManagedCertificate]:
    """Active/managed certs of *cert_class* on *appliance_id* (or fleet-wide if
    None) whose expiry is within *within_days* and that have not been superseded
    or revoked — the renewal candidates."""
    q = ManagedCertificate.query.filter(
        ManagedCertificate.cert_class == cert_class,
        ManagedCertificate.status.in_(("active", "pending", "expiring")))
    if appliance_id is not None:
        q = q.filter(ManagedCertificate.appliance_id == appliance_id)
    out = []
    for c in q.all():
        d = c.days_left
        if d is not None and d <= within_days:
            out.append(c)
    return out


# --------------------------------------------------------------------------- #
#  Lifecycle policy — WHEN a cert gets revoked at the CA and WHEN its material  #
#  leaves the devices. Driven ENTIRELY by the admin-console policy              #
#  (Settings → Certificate Manager → Lifecycle policy); consumed by the         #
#  ``cert_lifecycle`` scheduled action and the manual sweep button.             #
# --------------------------------------------------------------------------- #
def _days_since(ts) -> int | None:
    if not ts:
        return None
    return (datetime.utcnow() - ts).days


def lifecycle_candidates(appliance_id: int | None = None) -> dict:
    """What the lifecycle policy says is DUE right now.

    * ``revoke_due`` — superseded certs past the revoke grace window
      (``revoke_on_supersede``). Revocation happens at the CA; the material
      stays on the box until the delete rule below picks it up.
    * ``delete_due`` — certs whose material must leave the FortiWeb:
      revoked certs (``delete_revoked_from_device``), superseded certs past
      the retention window (when revocation-on-supersede is off), and expired
      certs past the expiry retention window.

    Candidates carrying bound policies in the DB are listed as ``blocked``
    instead — and the apply path re-verifies bindings LIVE and fail-closed
    (:func:`remove_device_certificate`), so a bound cert can never be removed."""
    pol = store.cert_lifecycle_policy()
    q = ManagedCertificate.query
    if appliance_id is not None:
        q = q.filter(ManagedCertificate.appliance_id == appliance_id)
    revoke_due, delete_due, blocked = [], [], []
    for c in q.all():
        sup_days = _days_since(c.superseded_at or
                               (c.updated_at if c.status == "superseded" else None))
        if (pol["revoke_on_supersede"] and c.status == "superseded"
                and sup_days is not None and sup_days >= pol["revoke_grace_days"]):
            item = {"cert": c, "action": "revoke",
                    "reason": (f"superseded {sup_days}d ago "
                               f"(grace {pol['revoke_grace_days']}d)")}
            (blocked if c.is_bound else revoke_due).append(item)

        if not c.appliance_id:
            continue
        reason = ""
        if c.status == "revoked" and pol["delete_revoked_from_device"]:
            reason = "revoked — material must leave the device"
        elif (c.status == "superseded" and not pol["revoke_on_supersede"]
                and sup_days is not None
                and sup_days >= pol["delete_superseded_after_days"]):
            reason = (f"superseded {sup_days}d ago (retention "
                      f"{pol['delete_superseded_after_days']}d)")
        else:
            exp_days = _days_since(c.expires_at)
            if (exp_days is not None and exp_days >= pol["delete_expired_after_days"]
                    and c.status != "revoked" and c.expires_at):
                reason = (f"expired {exp_days}d ago (retention "
                          f"{pol['delete_expired_after_days']}d)")
        if reason:
            item = {"cert": c, "action": "delete", "reason": reason}
            (blocked if c.is_bound else delete_due).append(item)
    return {"revoke_due": revoke_due, "delete_due": delete_due,
            "blocked": blocked, "policy": pol}


def run_lifecycle_sweep(*, dry_run: bool = True, appliance_id: int | None = None,
                        actor: str = "") -> dict:
    """Apply the lifecycle policy: revoke what is due, then delete due material
    off the devices. Every destructive step re-verifies bindings LIVE and
    fail-closed — an unverifiable or bound cert is skipped and reported, never
    forced. ``dry_run=True`` only reports what WOULD happen."""
    from ..models import Appliance
    cand = lifecycle_candidates(appliance_id)
    out = {"dry_run": dry_run, "revoked": [], "deleted": [], "skipped": [],
           "policy": cand["policy"]}
    for item in cand["blocked"]:
        out["skipped"].append(f"{item['cert'].name}: {item['action']} due "
                              f"({item['reason']}) but still bound in DB — skipped")

    for item in cand["revoke_due"]:
        c = item["cert"]
        # Live, fail-closed binding check: a cert we cannot PROVE unbound is skipped.
        try:
            bindings = read_bindings_for(c)
        except Exception as exc:  # noqa: BLE001
            out["skipped"].append(f"{c.name}: revoke due but bindings unreadable "
                                  f"({exc}) — skipped (fail-closed)")
            continue
        if bindings:
            out["skipped"].append(f"{c.name}: revoke due but LIVE-bound to "
                                  f"{', '.join(bindings)} — skipped")
            continue
        if dry_run:
            out["revoked"].append(f"[dry-run] would revoke {c.name} — {item['reason']}")
            continue
        res = revoke_certificate(c, delete_from_box=False, actor=actor or "lifecycle")
        if res.get("revoked"):
            _event(c, "lifecycle", True, f"auto-revoked: {item['reason']}", by=actor)
            out["revoked"].append(f"revoked {c.name} — {item['reason']}")
        else:
            out["skipped"].append(f"{c.name}: revoke failed — {res.get('error')}")

    for item in cand["delete_due"]:
        c = item["cert"]
        appliance = db.session.get(Appliance, c.appliance_id)
        if appliance is None:
            out["skipped"].append(f"{c.name}: target appliance missing — skipped")
            continue
        if dry_run:
            out["deleted"].append(f"[dry-run] would delete {c.name} from "
                                  f"{appliance.name} — {item['reason']}")
            continue
        # remove_device_certificate re-verifies ALL binders live, fail-closed.
        res = remove_device_certificate(appliance, "Local", c.name,
                                        dry_run=False, actor=actor or "lifecycle")
        if res.get("removed"):
            _event(c, "lifecycle", True,
                   f"deleted from {appliance.name}: {item['reason']}", by=actor)
            out["deleted"].append(f"deleted {c.name} from {appliance.name} — "
                                  f"{item['reason']}")
        else:
            out["skipped"].append(f"{c.name}: device delete refused — "
                                  f"{res.get('error')}")

    if not dry_run and (out["revoked"] or out["deleted"]):
        to = store.cert_manager_adcs().get("notify_to", "")
        if to:
            try:
                from . import email_service
                body = "\n".join(["Lifecycle sweep results:"] + out["revoked"]
                                 + out["deleted"] + out["skipped"])
                email_service.send_email(to, "[Cert Manager] Lifecycle sweep", body)
            except Exception:  # noqa: BLE001
                logger.debug("lifecycle email skipped", exc_info=True)
    log_action("certmgr.lifecycle_sweep",
               detail=(f"dry_run={dry_run} revoked={len(out['revoked'])} "
                       f"deleted={len(out['deleted'])} skipped={len(out['skipped'])}"))
    return out


# --------------------------------------------------------------------------- #
#  Email                                                                         #
# --------------------------------------------------------------------------- #
def _notify(cert: ManagedCertificate, *, subject: str, body: str) -> None:
    to = store.cert_manager_adcs().get("notify_to", "")
    if not to:
        return
    try:
        from . import email_service
        email_service.send_email(to, f"[Cert Manager] {subject}", body)
    except Exception:  # noqa: BLE001 — email is best-effort
        logger.debug("cert manager email notification skipped", exc_info=True)


# --------------------------------------------------------------------------- #
#  Read-only inventory of certificates that already live on the FortiWebs.      #
#  Independent of ADCS config — a plain cmdb GET per certificate store, so the  #
#  operator can always SEE what is on each box even before signing is set up.   #
# --------------------------------------------------------------------------- #
# (store key, friendly label, cmdb endpoint). The cmdb GET carries name/type/
# status/comment — NOT validity/issuer (FortiWeb exposes no monitor endpoint for
# that on 7.6/8.0; a box absent of a store just yields an empty list).
_DEVICE_CERT_STORES = (
    ("local", "Local", "/api/v2.0/cmdb/system/certificate.local"),
    ("sni", "SNI", "/api/v2.0/cmdb/system/certificate.sni"),
    ("ca", "CA", "/api/v2.0/cmdb/system/certificate.ca"),
    ("letsencrypt", "Let's Encrypt", "/api/v2.0/cmdb/system/certificate.letsencrypt"),
)


def list_device_certificates(appliances, *, timeout: float = 6.0) -> list[dict]:
    """Live, read-only sweep of every appliance's certificate stores.

    Returns one entry per appliance: ``{appliance, online, error, certs[]}``.
    Dispatches on ``appliance.kind`` — FortiWeb reads the four cmdb stores,
    FortiADC reads its REST stores (:func:`cert_adc.sweep_certificates`, same
    entry shape). Best-effort — an unreachable box is marked ``online=False``
    (its first store GET failed) and the sweep moves on; a store missing on a
    given firmware just contributes nothing. No SSH, no ADCS, never raises.
    """
    from . import cert_adc
    out: list[dict] = []
    for a in appliances:
        if getattr(a, "kind", "fortiweb") == "fortiadc":
            entry = cert_adc.sweep_certificates(a, timeout=timeout)
            for c in entry["certs"]:
                c.pop("detail", None)  # summary shape parity with FortiWeb
            out.append(entry)
            continue
        entry = {"appliance": a, "online": True, "error": None, "certs": []}
        try:
            client = a.build_client(timeout=timeout)
        except Exception as exc:  # noqa: BLE001 — client build failed → offline
            entry["online"] = False
            entry["error"] = type(exc).__name__
            out.append(entry)
            continue
        for idx, (_key, label, ep) in enumerate(_DEVICE_CERT_STORES):
            try:
                resp = client.api_call("GET", ep)
                body = resp.json() if resp is not None else {}
                rows = body.get("results") if isinstance(body, dict) else []
                if isinstance(rows, dict):  # single-mkey shape
                    rows = [rows]
                for row in (rows or []):
                    if not isinstance(row, dict):
                        continue
                    name = row.get("name")
                    if not name:
                        continue
                    entry["certs"].append({
                        "name": str(name),
                        "store": label,
                        "type": str(row.get("type") or ""),
                        "status": str(row.get("status") or ""),
                        "comment": str(row.get("comment") or ""),
                    })
            except Exception as exc:  # noqa: BLE001
                if idx == 0:
                    # First (Local) store failed → treat the box as unreachable
                    # and skip the remaining stores instead of timing out on each.
                    entry["online"] = False
                    entry["error"] = type(exc).__name__
                    break
                continue
        entry["certs"].sort(key=lambda c: (c["store"], c["name"].lower()))
        out.append(entry)
    return out


def consolidate_device_certificates(device_certs) -> dict:
    """Collapse the per-appliance sweep into ONE row per unique certificate.

    The SAME certificate (same store + same name) deployed on several FortiWebs is
    one logical cert — so it becomes a single row listing every device it lives on,
    instead of one line per box (which reads as duplicate certificates). Pure.

    Returns ``{"rows": [...], "offline": [...], "unique": int, "deployments": int}``
    where each row is ``{name, store, type, comment, status, devices[], device_count}``
    and ``devices`` is ``[{id, name}]``.
    """
    by_key: dict[tuple, dict] = {}
    offline: list[dict] = []
    deployments = 0
    for entry in device_certs:
        a = entry["appliance"]
        if not entry.get("online"):
            offline.append({"name": a.name, "host": getattr(a, "host", ""),
                            "error": entry.get("error") or "offline"})
            continue
        for c in entry["certs"]:
            key = (c["store"], c["name"])
            deployments += 1
            row = by_key.get(key)
            if row is None:
                row = by_key[key] = {
                    "name": c["name"], "store": c["store"],
                    "type": c["type"], "comment": c["comment"],
                    "statuses": set(), "devices": [],
                }
            row["statuses"].add(c["status"] or "")
            if not row["type"] and c["type"]:
                row["type"] = c["type"]
            if not row["comment"] and c["comment"]:
                row["comment"] = c["comment"]
            row["devices"].append({"id": a.id, "name": a.name})
    rows: list[dict] = []
    for row in by_key.values():
        present = {s for s in row["statuses"] if s}
        if not present:
            status = ""
        elif present == {"ok"}:
            status = "ok"
        else:  # surface the worst (any non-ok) so a mixed fleet is visible
            status = sorted(present - {"ok"})[0]
        row["devices"].sort(key=lambda d: d["name"].lower())
        rows.append({
            "name": row["name"], "store": row["store"], "type": row["type"],
            "comment": row["comment"], "status": status,
            "devices": row["devices"], "device_count": len(row["devices"]),
        })
    rows.sort(key=lambda r: (r["store"], r["name"].lower()))
    return {"rows": rows, "offline": offline,
            "unique": len(rows), "deployments": deployments}


# --------------------------------------------------------------------------- #
#  Device-certificate SCAN + persistent cache                                  #
# --------------------------------------------------------------------------- #
def _bindings_index(client):
    """One-pass ``cert_name -> [binding labels]`` map for a box: read the server
    policies + SNI members ONCE and tally which cert each references. Cheap
    (2 REST GETs), read-only, best-effort ({} on failure)."""
    idx: dict[str, set] = {}
    pols = _get_results(client, SERVER_POLICY_EP) or []
    for p in pols:
        if not isinstance(p, dict):
            continue
        pname = str(p.get("name", "")).strip()
        for f in _CERT_BIND_FIELDS:
            cert = str(p.get(f, "")).strip()
            if cert and pname:
                idx.setdefault(cert, set()).add(pname)
    sni_rows = _get_results(client, SNI_EP) or []
    for s in sni_rows:
        if not isinstance(s, dict):
            continue
        sname = str(s.get("name", "")).strip()
        for m in (s.get("members") or []):
            if isinstance(m, dict):
                cert = str(m.get("local-cert", "")).strip()
                if cert:
                    idx.setdefault(cert, set()).add(f"SNI {sname}".strip())
    return idx


def _scan_adc_certificates(appliance, *, with_bindings: bool = True,
                           timeout: float = 8.0) -> dict:
    """FortiADC leg of :func:`scan_device_certificates` — pure REST.

    The ADC list payload already carries the decoded X.509 detail, so one sweep
    yields summary + detail in a single pass (no SSH). Bindings walk the ADC
    chain cert → local-cert-group → client-SSL-profile → virtual server, plus
    the admin GUI cert. Upsert/prune/commit semantics identical to FortiWeb.
    """
    from . import cert_adc
    res = {"ok": False, "online": False, "appliance": appliance.name,
           "scanned": 0, "detailed": 0, "error": None}
    entry = cert_adc.sweep_certificates(appliance, timeout=timeout)
    if not entry.get("online"):
        res["error"] = entry.get("error") or "offline"
        return res
    res["online"] = True

    bindings_idx = {}
    if with_bindings:
        try:
            bindings_idx = cert_adc.bindings_index(
                appliance.build_client(timeout=timeout))
        except Exception:  # noqa: BLE001 — bindings are best-effort
            bindings_idx = {}

    now = datetime.utcnow()
    existing = {(r.store, r.name): r for r in
                DeviceCertificate.query.filter_by(appliance_id=appliance.id).all()}
    seen_keys = set()
    for c in entry["certs"]:
        key = (c["store"], c["name"])
        seen_keys.add(key)
        row = existing.get(key)
        if row is None:
            row = DeviceCertificate(appliance_id=appliance.id,
                                    store=c["store"], name=c["name"])
            db.session.add(row)
        row.cert_type = c.get("type") or ""
        row.status = c.get("status") or ""
        row.comment = (c.get("comment") or "")[:512]
        det = c.get("detail") or {}
        if det:
            row.apply_detail(det, source="rest")
            res["detailed"] += 1
        if with_bindings:
            row.bindings = sorted(bindings_idx.get(c["name"], set()))
        row.scanned_at = now
        res["scanned"] += 1
    for key, row in existing.items():
        if key not in seen_keys:
            db.session.delete(row)
    db.session.commit()
    res["ok"] = True
    return res


def scan_device_certificates(appliance, *, with_bindings: bool = True,
                             timeout: float = 8.0) -> dict:
    """Scan ONE appliance and UPSERT its certificate inventory into the DB.

    Dispatches on ``appliance.kind`` (FortiADC → :func:`_scan_adc_certificates`,
    pure REST). FortiWeb: reads every store's cmdb rows (name/type/status/
    comment), then over ONE SSH session reads the decoded X.509 detail of each
    Local cert (:func:`cert_probe.detail_from_fortiweb_cli`), and (optionally)
    computes each cert's server-policy / SNI bindings from a single REST pass.
    Rows no longer present on the box are pruned. Commits. Never raises.

    Returns ``{ok, online, appliance, scanned, detailed, error}``.
    """
    if getattr(appliance, "kind", "fortiweb") == "fortiadc":
        return _scan_adc_certificates(appliance, with_bindings=with_bindings,
                                      timeout=timeout)

    res = {"ok": False, "online": False, "appliance": appliance.name,
           "scanned": 0, "detailed": 0, "error": None}

    swept = list_device_certificates([appliance], timeout=timeout)
    entry = swept[0] if swept else {"online": False, "certs": [], "error": "no-sweep"}
    if not entry.get("online"):
        res["error"] = entry.get("error") or "offline"
        return res
    res["online"] = True
    certs = entry.get("certs") or []

    # Bindings — one REST pass reused for every cert on this box.
    bindings_idx = {}
    if with_bindings:
        try:
            bindings_idx = _bindings_index(appliance.build_client(timeout=timeout))
        except Exception:  # noqa: BLE001 — bindings are best-effort
            bindings_idx = {}

    # Decoded detail for Local-store certs — one SSH session, many reads.
    detail_by_name: dict[str, dict] = {}
    local_names = [c["name"] for c in certs if c.get("store") == "Local"]
    if local_names:
        try:
            from .ssh_ops import FortiWebReadonlySSH
            from . import cert_probe
            with FortiWebReadonlySSH(appliance, timeout=max(timeout, 20.0)) as ssh:
                for cname in local_names:
                    try:
                        cert_ssh.assert_cert_name(cname)
                    except Exception:  # noqa: BLE001 — skip odd names
                        continue
                    try:
                        out = ssh.run_readonly(
                            f"get system certificate local {cname}")
                        det = cert_probe.detail_from_fortiweb_cli(out)
                    except Exception:  # noqa: BLE001
                        det = None
                    if det:
                        detail_by_name[cname] = det
        except Exception:  # noqa: BLE001 — SSH unreachable → cmdb-only rows
            logger.debug("SSH cert scan session failed for %s", appliance.name,
                         exc_info=True)

    # A managed cert with a stored PEM lends detail for non-Local (SNI/CA/LE) rows.
    from . import cert_probe as _cp
    now = datetime.utcnow()
    existing = {(r.store, r.name): r for r in
                DeviceCertificate.query.filter_by(appliance_id=appliance.id).all()}
    seen_keys = set()
    for c in certs:
        store_label = c["store"]
        name = c["name"]
        key = (store_label, name)
        seen_keys.add(key)
        row = existing.get(key)
        if row is None:
            row = DeviceCertificate(appliance_id=appliance.id,
                                    store=store_label, name=name)
            db.session.add(row)
        row.cert_type = c.get("type") or ""
        row.status = c.get("status") or ""
        row.comment = (c.get("comment") or "")[:512]
        det = detail_by_name.get(name)
        if det:
            row.apply_detail(det, source="ssh")
            res["detailed"] += 1
        elif not row.has_detail:
            mc = ManagedCertificate.query.filter_by(name=name).first()
            if mc and mc.cert_pem:
                pem_det = _cp.detail_from_pem(mc.cert_pem)
                if pem_det:
                    row.apply_detail(pem_det, source="pem")
                    res["detailed"] += 1
        if with_bindings:
            row.bindings = sorted(bindings_idx.get(name, set()))
        row.scanned_at = now
        res["scanned"] += 1

    # Prune rows for certs no longer on the box.
    for key, row in existing.items():
        if key not in seen_keys:
            db.session.delete(row)

    db.session.commit()
    res["ok"] = True
    return res


def scan_fleet_certificates(appliances, *, with_bindings: bool = True,
                            timeout: float = 8.0) -> dict:
    """Run :func:`scan_device_certificates` across many boxes. Best-effort per
    device; returns ``{ok, scanned, detailed, online, offline[], results[]}``."""
    results, offline = [], []
    scanned = detailed = online = 0
    for a in appliances:
        try:
            r = scan_device_certificates(a, with_bindings=with_bindings,
                                         timeout=timeout)
        except Exception as exc:  # noqa: BLE001 — never let one box sink the run
            db.session.rollback()
            r = {"ok": False, "online": False, "appliance": a.name,
                 "scanned": 0, "detailed": 0, "error": type(exc).__name__}
        results.append(r)
        scanned += r["scanned"]
        detailed += r["detailed"]
        if r["online"]:
            online += 1
        else:
            offline.append({"name": a.name, "error": r.get("error") or "offline"})
    return {"ok": True, "scanned": scanned, "detailed": detailed,
            "online": online, "offline": offline, "results": results}


def stored_device_certificates(appliances) -> dict:
    """Read the CACHED on-device inventory from the DB and consolidate it into ONE
    row per unique (store, name) — the same shape
    :func:`consolidate_device_certificates` yields, plus detail
    (sans/expires_at/days_left/issuer/bindings) and ``last_scanned``. No box call.
    """
    ids = [a.id for a in appliances]
    by_id = {a.id: a for a in appliances}
    if not ids:
        return {"rows": [], "unique": 0, "deployments": 0, "last_scanned": None}
    rows_db = (DeviceCertificate.query
               .filter(DeviceCertificate.appliance_id.in_(ids))
               .all())
    by_key: dict[tuple, dict] = {}
    deployments = 0
    last_scanned = None
    for dc in rows_db:
        a = by_id.get(dc.appliance_id)
        if a is None:
            continue
        deployments += 1
        if dc.scanned_at and (last_scanned is None or dc.scanned_at > last_scanned):
            last_scanned = dc.scanned_at
        key = (dc.store, dc.name)
        row = by_key.get(key)
        if row is None:
            row = by_key[key] = {
                "name": dc.name, "store": dc.store, "type": dc.cert_type or "",
                "comment": dc.comment or "", "statuses": set(), "devices": [],
                "sans": [], "expires_at": None, "not_before": None,
                "days_left": None, "issuer_cn": "", "serial": "",
                "fingerprint": "", "bindings": set(), "detail_source": "",
            }
        row["statuses"].add(dc.status or "")
        if not row["type"] and dc.cert_type:
            row["type"] = dc.cert_type
        if not row["comment"] and dc.comment:
            row["comment"] = dc.comment
        # Detail: take the richest available across the box copies.
        if dc.not_after and row["expires_at"] is None:
            row["expires_at"] = dc.not_after
            row["days_left"] = dc.days_left
        if dc.sans and not row["sans"]:
            row["sans"] = dc.sans
        if dc.issuer_cn and not row["issuer_cn"]:
            row["issuer_cn"] = dc.issuer_cn
        if dc.serial and not row["serial"]:
            row["serial"] = dc.serial
        if dc.fingerprint_sha256 and not row["fingerprint"]:
            row["fingerprint"] = dc.fingerprint_sha256
        if dc.detail_source and not row["detail_source"]:
            row["detail_source"] = dc.detail_source
        row["bindings"].update(dc.bindings)
        row["devices"].append({"id": a.id, "name": a.name})
    rows: list[dict] = []
    for row in by_key.values():
        present = {s for s in row["statuses"] if s}
        status = "" if not present else ("ok" if present == {"ok"}
                                         else sorted(present - {"ok"})[0])
        row["devices"].sort(key=lambda d: d["name"].lower())
        rows.append({
            "name": row["name"], "store": row["store"], "type": row["type"],
            "comment": row["comment"], "status": status,
            "sans": row["sans"], "expires_at": row["expires_at"],
            "days_left": row["days_left"], "issuer_cn": row["issuer_cn"],
            "serial": row["serial"], "fingerprint": row["fingerprint"],
            "detail_source": row["detail_source"],
            "bindings": sorted(row["bindings"]),
            "devices": row["devices"], "device_count": len(row["devices"]),
        })
    rows.sort(key=lambda r: (r["store"], r["name"].lower()))
    return {"rows": rows, "unique": len(rows), "deployments": deployments,
            "last_scanned": last_scanned}


__all__ = [
    "CertManagerError", "generate_csr", "sign_csr", "parse_certificate",
    "cert_name_for", "create_certificate", "renew_certificate",
    "read_bindings", "read_bindings_for", "swap_binding", "confirm_swap",
    "cert_usage", "device_cert_detail_via_ssh",
    "swap_server_policy_cert", "swap_sni_member", "swap_gui_cert",
    "remove_device_certificate",
    "revoke_certificate", "expiring_certificates", "list_device_certificates",
    "consolidate_device_certificates",
    "scan_device_certificates", "scan_fleet_certificates",
    "stored_device_certificates",
]
