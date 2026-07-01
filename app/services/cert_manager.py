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

from ..models import ManagedCertificate, ManagedCertificateEvent, db
from . import cert_ssh, naming
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


def _redact(text: str, secret: str) -> str:
    return text.replace(secret, "********") if secret else text


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
    """Run the class's signing command against the CSR. Returns ``(cert_pem, log)``.

    The command template ({csr}/{out}/{ca}/{ca_name}/{template}/{user}/{domain}/
    {password}/{bin}) is fully admin-defined — this is the "el usuario indica los
    parámetros del comando" contract. Raises :class:`CertManagerError` on failure.
    """
    adcs = store.cert_manager_adcs(reveal_secret=True)
    ccfg = store.cert_class_config(cert_class)
    cmd_tmpl = (ccfg.get("submit_cmd") or "").strip()
    if not cmd_tmpl:
        raise CertManagerError(f"no signing command configured for class {cert_class!r}")

    secret = adcs.get("secret", "")
    with tempfile.TemporaryDirectory(prefix="certmgr-") as d:
        csr_path = os.path.join(d, "request.csr")
        out_path = os.path.join(d, "signed.cer")
        with open(csr_path, "w") as fh:
            fh.write(csr_pem)
        mapping = {
            "bin": adcs.get("bin", "certipy"),
            "user": adcs.get("user", ""),
            "domain": adcs.get("domain", ""),
            "password": secret,
            "ca": adcs.get("ca", ""),
            "ca_name": adcs.get("ca_name", ""),
            "template": ccfg.get("template", ""),
            "csr": csr_path,
            "out": out_path,
        }
        cmd_str = _interpolate(cmd_tmpl, mapping)
        try:
            argv = shlex.split(cmd_str)
        except ValueError as exc:
            raise CertManagerError(f"signing command is not parseable: {exc}") from exc
        if not argv:
            raise CertManagerError("signing command is empty after interpolation")

        safe_cmd = _redact(cmd_str, secret)
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
            out = cert_ssh.deploy_certificate(
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
    """GET *ep* and return its ``results`` (list or dict), or ``None`` on error.

    Tries the endpoint first WITHOUT and then WITH the ``/api/v2.0/`` REST prefix.
    The live FortiWeb needs the prefixed path (see :data:`SERVER_POLICY_EP`), but
    this order lets a caller pass the short ``cmdb/...`` form too: the short probe
    just yields nothing on a real box and the prefixed retry answers.
    """
    core = ep.lstrip("/")
    if core.startswith("api/v2.0/"):
        core = core[len("api/v2.0/"):]
    for path in (core, "/api/v2.0/" + core):
        try:
            resp = client.api_call("GET", path)
            body = resp.json() if resp is not None else {}
        except Exception:  # noqa: BLE001
            continue
        res = body.get("results") if isinstance(body, dict) else None
        if res is not None:
            return res
    return None


def cert_usage(appliance, cert_name):
    """Every place *cert_name* is bound on *appliance*, across the three binders.

    Returns list of {kind, target, field, sub_mkey, label, probe}; kind in
    {server-policy, sni, gui}. Read-only, best-effort — a dead box yields [].
    """
    try:
        client = appliance.build_client(timeout=6.0)
    except Exception:  # noqa: BLE001
        return []
    out = []

    rows = _get_results(client, SERVER_POLICY_EP)
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
                    "probe": _policy_probe(p),
                })

    sni_rows = _get_results(client, SNI_EP)
    for s in (sni_rows or []):
        if not isinstance(s, dict):
            continue
        sname = str(s.get("name", ""))
        for m in (s.get("members") or []):
            if isinstance(m, dict) and str(m.get("local-cert", "")).strip() == cert_name:
                out.append({
                    "kind": "sni", "target": sname, "field": "local-cert",
                    "sub_mkey": str(m.get("id", "")),
                    "label": f"SNI {sname} — {m.get('domain', '')}".strip(" —"),
                    "probe": None,
                })

    g = _get_results(client, GLOBAL_EP)
    if isinstance(g, dict) and str(g.get(GUI_CERT_FIELD, "")).strip() == cert_name:
        out.append({
            "kind": "gui", "target": "", "field": GUI_CERT_FIELD, "sub_mkey": None,
            "label": "GUI / admin access (HTTPS management cert)",
            "probe": {"host": getattr(appliance, "host", ""), "port": _admin_sport(g)},
        })
    return out


def _policy_probe(policy):
    """Best-effort (host, port) for a server policy's published listener, to TLS-probe
    the live leaf. Port from HTTPS service if numeric else 443; host from explicit VIP.
    Returns None when nothing usable is found."""
    host = str(policy.get("vip") or "").strip()
    port = None
    for pf in ("https-service", "service"):
        v = str(policy.get(pf, "")).strip()
        if v.isdigit():
            port = int(v)
            break
    if not host:
        return None
    return {"host": host, "port": port or 443}


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
    """Revoke at the CA (class ``revoke_cmd``) and mark the row revoked. Deleting
    the cert off the FortiWeb is refused while it is bound to any server policy."""
    ccfg = store.cert_class_config(cert.cert_class)
    adcs = store.cert_manager_adcs(reveal_secret=True)
    cmd_tmpl = (ccfg.get("revoke_cmd") or "").strip()
    secret = adcs.get("secret", "")

    if dry_run:
        preview = _redact(_interpolate(cmd_tmpl, {
            "bin": adcs.get("bin", ""), "user": adcs.get("user", ""),
            "domain": adcs.get("domain", ""), "password": secret,
            "ca": adcs.get("ca", ""), "ca_name": adcs.get("ca_name", ""),
            "serial": cert.serial or "", "request_id": cert.ca_request_id or "",
        }), secret)
        return {"ok": True, "dry_run": True, "summary": f"[dry-run] revoke: {preview}",
                "bindings": read_bindings_for(cert)}

    # 1) CA revoke (best-effort but reported).
    ca_ok, ca_log = True, ""
    if cmd_tmpl:
        mapping = {
            "bin": adcs.get("bin", "certipy"), "user": adcs.get("user", ""),
            "domain": adcs.get("domain", ""), "password": secret,
            "ca": adcs.get("ca", ""), "ca_name": adcs.get("ca_name", ""),
            "serial": cert.serial or "", "request_id": cert.ca_request_id or "",
        }
        cmd_str = _interpolate(cmd_tmpl, mapping)
        try:
            proc = subprocess.run(shlex.split(cmd_str), capture_output=True,
                                  text=True, timeout=_SIGN_TIMEOUT)
            ca_ok = proc.returncode == 0
            ca_log = _redact(f"[rc={proc.returncode}] {proc.stdout}\n{proc.stderr}", secret)[:2000]
        except Exception as exc:  # noqa: BLE001
            ca_ok, ca_log = False, f"revoke command error: {exc}"
    else:
        ca_log = "no revoke_cmd configured — marked revoked locally only."

    cert.status = "revoked"
    db.session.commit()
    _event(cert, "revoke", ca_ok, ca_log, by=actor)

    # 2) Optionally remove from the box — ONLY if not bound anywhere.
    box_detail = ""
    if delete_from_box and cert.appliance_id:
        bindings = read_bindings_for(cert)
        if bindings:
            box_detail = ("NOT deleted from device — still bound to: "
                          + ", ".join(bindings))
            _event(cert, "revoke", False, box_detail, by=actor)
            return {"ok": ca_ok, "revoked": True, "deleted": False,
                    "bindings": bindings, "error": box_detail, "log": ca_log}
        from ..models import Appliance
        appliance = db.session.get(Appliance, cert.appliance_id)
        try:
            cert_ssh.remove_certificate(appliance, cert.name, secret=appliance.password)
            box_detail = f"deleted {cert.name} from {appliance.name}"
            _event(cert, "revoke", True, box_detail, by=actor)
        except Exception as exc:  # noqa: BLE001
            box_detail = f"device delete failed: {exc}"
            _event(cert, "revoke", False, box_detail, by=actor)

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
    """Live, read-only sweep of every FortiWeb's certificate stores.

    Returns one entry per appliance: ``{appliance, online, error, certs[]}``.
    Best-effort — an unreachable box is marked ``online=False`` (its first store
    GET failed) and the sweep moves on; a store missing on a given firmware just
    contributes nothing. No SSH, no ADCS, never raises.
    """
    out: list[dict] = []
    for a in appliances:
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


__all__ = [
    "CertManagerError", "generate_csr", "sign_csr", "parse_certificate",
    "cert_name_for", "create_certificate", "renew_certificate",
    "read_bindings", "read_bindings_for", "swap_binding", "confirm_swap",
    "cert_usage",
    "revoke_certificate", "expiring_certificates", "list_device_certificates",
    "consolidate_device_certificates",
]
