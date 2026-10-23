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
from datetime import datetime, timedelta
from urllib.parse import quote as _url_quote

from ..models import (DeviceCertificate, ManagedCertificate,
                      ManagedCertificateEvent, db)
from . import cert_adc, cert_ssh, naming
from . import settings_store as store
from .audit import log_action
from .fortiweb_ops import FortiWebOps

logger = logging.getLogger(__name__)

#: Device kinds whose certificate stores SATOM reads and deploys to: FortiWeb
#: (REST cmdb + SSH X.509 detail) and FortiADC (REST, services/cert_adc.py).
#: Every per-kind dispatcher below sends anything that is not FortiADC down the
#: FortiWeb path, so a FortiGate reached that path with FortiWeb calls and was
#: reported "Unreachable". The device lists, the scans and the sidebar
#: (services/adom_menu.py) all read this one tuple.
CERT_KINDS = ("fortiweb", "fortiadc")


def supports_kind(appliance) -> bool:
    """Whether SATOM manages certificates on *appliance*'s kind (None = FortiWeb)."""
    return (getattr(appliance, "kind", None) or "fortiweb") in CERT_KINDS


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


def _redact_all(text: str, secrets) -> str:
    """Mask EVERY secret handed to the child process.

    ADCS had exactly one (the enrolment password). ACME can have many: the EAB
    HMAC plus one credential per DNS-provider field. Longest first, so a secret
    that contains another one still masks cleanly."""
    out = text or ""
    for s in sorted({str(x) for x in (secrets or []) if str(x).strip()},
                    key=len, reverse=True):
        out = out.replace(s, "********")
    return out


# The ONLY variables inherited from the web process. The app runs as root and
# its environment carries FERNET_KEY / SQLALCHEMY_DATABASE_URI — an external
# signer (or a DNS hook script) must never see them. Everything the child needs
# is passed EXPLICITLY by the protocol context.
_ENV_PASSTHROUGH = ("PATH", "LANG", "LC_ALL", "TZ",
                    "SSL_CERT_FILE", "SSL_CERT_DIR",
                    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                    "http_proxy", "https_proxy", "no_proxy")
_ENV_DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _build_env(extra: dict | None = None, *, home: str = "") -> dict[str, str]:
    """A MINIMAL environment for the signer: a curated passthrough + whatever
    the protocol context supplies (DNS-provider credentials, mostly).

    This is the channel that makes a provider catalog possible at all: every
    ACME client takes provider credentials from the environment, never from
    argv — which also keeps them out of the command line, /proc and the logs."""
    env = {k: os.environ[k] for k in _ENV_PASSTHROUGH if os.environ.get(k)}
    env.setdefault("PATH", _ENV_DEFAULT_PATH)
    # Never a shared, world-writable directory: a signer keeps state under
    # $HOME (account keys, tickets, config) with the app's privileges. Callers
    # pass the ACME account dir, or their own private per-call temp dir.
    env["HOME"] = home or env.get("HOME") or os.path.expanduser("~")
    for k, v in (extra or {}).items():
        if k and v is not None:
            env[str(k)] = str(v)
    return env


# --------------------------------------------------------------------------- #
#  Protocol dispatch — the CA backend is CHOSEN in the admin console            #
#  (Settings → Certificate Manager): "adcs" = enterprise-CA command template,   #
#  "acme" = an ACME client (certbot/acme.sh/lego) driven through the same       #
#  template contract. Adding a protocol = a settings_store entry + a context    #
#  builder here; the pipeline (generate/sign/deploy/swap/revoke) is shared.     #
# --------------------------------------------------------------------------- #
def _acme_common() -> tuple[dict, dict, dict, list[str]]:
    """(acme cfg, token mapping, child environment, secrets to redact).

    Shared by the submit and revoke contexts. The DNS-provider credentials come
    from the catalog (:mod:`app.services.acme_providers`) and travel ONLY in the
    environment — never in argv."""
    from . import acme_providers  # local: acme_providers imports settings_store

    acme = store.cert_manager_acme(reveal_secret=True)
    eab = acme.get("eab_hmac", "")
    acme_path = acme.get("account_key_dir") or "/opt/satom/data/acme"
    mapping = {
        "bin": acme.get("bin", "lego"),
        "helper": acme.get("helper", ""),
        "directory": acme.get("directory_url", ""),
        "email": acme.get("account_email", ""),
        "eab_kid": acme.get("eab_kid", ""),
        "eab_hmac": eab,
        "challenge": acme.get("challenge", "http-01"),
        "key_type": acme.get("key_type", "EC256"),
        "acme_path": acme_path,
        "webroot": acme.get("webroot_path", ""),
        "http_port": acme.get("http_port", "80"),
        "dns_resolvers": acme.get("dns_resolvers", ""),
        "dns_propagation_wait": acme.get("dns_propagation_wait", ""),
        "dns_flag": "",
    }
    env, secrets = {}, [eab] if eab else []
    if acme.get("challenge") == "dns-01" and acme.get("dns_provider"):
        prov = acme_providers.get(acme["dns_provider"])
        if prov is None:
            raise CertManagerError(
                f"DNS provider {acme['dns_provider']!r} is not in the catalog — "
                "pick one in Settings → Certificate Manager.")
        missing = acme_providers.missing_required(prov.slug)
        if missing:
            raise CertManagerError(
                f"DNS provider {prov.label!r} is missing required credentials: "
                f"{', '.join(missing)}")
        mapping["dns_flag"] = prov.flag
        env, psecrets = acme_providers.env_for(prov.slug)
        secrets += psecrets
    # The account key MUST survive across issuances (rate limits + revocation).
    try:
        os.makedirs(acme_path, mode=0o700, exist_ok=True)
    except OSError as exc:  # noqa: BLE001 — surfaced as a clean config error
        raise CertManagerError(
            f"ACME account directory {acme_path!r} is not creatable: {exc}") from exc
    return acme, mapping, env, secrets


# The CA secret is ALSO exported to the signer as $SATOM_CA_SECRET, so a
# command template can drop {password} and keep the secret out of argv (and so
# out of /proc/<pid>/cmdline). {password} keeps working for signers that only
# take it on the command line (certipy).
CA_SECRET_ENV = "SATOM_CA_SECRET"


def _ca_secret_env(secret: str) -> dict:
    return {CA_SECRET_ENV: secret} if secret else {}


def _signing_context(cert_class: str, provider: str = "") -> tuple[str, str, dict, dict, list[str]]:
    """(protocol, submit template, token mapping, child env, secrets) for the
    issuance protocol of ``provider`` (``""`` = the configured one, see
    :mod:`cert_providers`). ``{csr}``/``{out}`` are added at run time."""
    from . import cert_providers
    protocol = cert_providers.protocol_of(provider)
    ccfg = store.cert_class_config(cert_class)
    if protocol == "acme":
        acme, mapping, env, secrets = _acme_common()
        mapping["template"] = ccfg.get("template", "")
        return ("acme", (acme.get("submit_cmd") or "").strip(),
                mapping, env, secrets)
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
    return ("adcs", (ccfg.get("submit_cmd") or "").strip(), mapping,
            _ca_secret_env(secret), [secret] if secret else [])


def _revoke_context(cert: ManagedCertificate) -> tuple[str, str, dict, dict, list[str]]:
    """(protocol, revoke template, token mapping, child env, secrets). The ACME
    revoke references the CERTIFICATE ({cert}, a temp file) and its {cn}; the
    ADCS revoke references {serial}/{request_id}. The protocol is the one of
    the provider that ISSUED it."""
    from . import cert_providers
    protocol = cert_providers.protocol_of(getattr(cert, "provider", "") or "")
    if protocol == "acme":
        acme, mapping, env, secrets = _acme_common()
        mapping["serial"] = cert.serial or ""
        mapping["cn"] = _cn_of(cert)
        return ("acme", (acme.get("revoke_cmd") or "").strip(),
                mapping, env, secrets)
    ccfg = store.cert_class_config(cert.cert_class)
    adcs = store.cert_manager_adcs(reveal_secret=True)
    secret = adcs.get("secret", "")
    mapping = {
        "bin": adcs.get("bin", "certipy"), "user": adcs.get("user", ""),
        "domain": adcs.get("domain", ""), "password": secret,
        "ca": adcs.get("ca", ""), "ca_name": adcs.get("ca_name", ""),
        "serial": cert.serial or "", "request_id": cert.ca_request_id or "",
    }
    return ("adcs", (ccfg.get("revoke_cmd") or "").strip(), mapping,
            _ca_secret_env(secret), [secret] if secret else [])


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


_REQUEST_ID_RE = re.compile(r"request\s*id(?:\s+is)?\s*[:=]?\s*\"?(\d{1,18})", re.IGNORECASE)


def ca_request_id_from_log(log: str) -> str:
    """The CA request id a signer printed, or "" when it printed none."""
    m = _REQUEST_ID_RE.search(log or "")
    return m.group(1) if m else ""


def sign_csr(cert_class: str, csr_pem: str, provider: str = "") -> tuple[str, str]:
    """Run the ACTIVE protocol's signing command against the CSR. Returns
    ``(cert_pem, log)``.

    The command template ({csr}/{out}/… — ADCS or ACME tokens) is fully
    admin-defined — this is the "the user specifies the command parameters"
    contract. Raises :class:`CertManagerError` on failure."""
    protocol, cmd_tmpl, mapping, env, secrets = _signing_context(cert_class, provider)
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

        safe_cmd = _redact_all(" ".join(shlex.quote(a) for a in argv), secrets)
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=_SIGN_TIMEOUT, cwd=d,
                                  env=_build_env(env, home=mapping.get("acme_path") or d))
        except FileNotFoundError as exc:
            raise CertManagerError(
                f"signing binary not found: {argv[0]!r} — install it or set {{bin}} "
                f"(cmd: {safe_cmd})") from exc
        except subprocess.TimeoutExpired as exc:
            raise CertManagerError(f"signing command timed out after {_SIGN_TIMEOUT}s") from exc

        stdout = _redact_all(proc.stdout or "", secrets)
        stderr = _redact_all(proc.stderr or "", secrets)
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
#  Per-certificate policy: the windows a certificate rotates by                 #
# --------------------------------------------------------------------------- #
#: Windows a certificate can override (NULL column = class / policy default).
WINDOW_FIELDS = ("renew_before_days", "swap_after_days", "remove_after_days",
                 "retain_days")


def _int_or(value, default: int) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def default_policy(cert_class: str = "server") -> dict:
    """The windows a certificate WITHOUT overrides follows."""
    pol = store.cert_lifecycle_policy()
    ccfg = store.cert_class_config(cert_class)
    return {
        "renew_before_days": _int_or(ccfg.get("renew_before_days"), 30) or 30,
        "swap_after_days": pol["swap_after_days"],
        "remove_after_days": pol["delete_superseded_after_days"],
        "retain_days": pol["retain_after_removal_days"],
        "revoke_superseded": bool(pol["revoke_on_supersede"]),
    }


def cert_policy(cert: ManagedCertificate) -> dict:
    """The EFFECTIVE windows of *cert*: its own value where set, else the
    default. ``source`` says which, so the page can show "default"."""
    base = default_policy(cert.cert_class)
    out = dict(base, auto_renew=bool(cert.auto_renew), source={})
    for k in WINDOW_FIELDS:
        v = getattr(cert, k, None)
        if v is not None:
            out[k] = max(0, int(v))
        out["source"][k] = "cert" if v is not None else "default"
    if cert.revoke_superseded is not None:
        out["revoke_superseded"] = bool(cert.revoke_superseded)
    out["source"]["revoke_superseded"] = (
        "cert" if cert.revoke_superseded is not None else "default")
    return out


def window_error(renew_before: int, swap_after: int) -> str:
    """Why a (renew, swap) pair cannot work, or "". The swap has to land
    before the certificate it replaces expires."""
    if renew_before <= 0:
        return "renew-before must be at least 1 day."
    if swap_after >= renew_before:
        return (f"the swap ({swap_after} d after the renewal) would land on or "
                f"after the expiry (the renewal runs {renew_before} d before it) "
                "— make the swap delay shorter than the renew window.")
    return ""


def apply_windows(cert: ManagedCertificate, values: dict) -> str:
    """Store per-cert overrides from a form-ish dict. Blank = default.
    Returns an error string (nothing saved) or ""."""
    parsed = {}
    for k in WINDOW_FIELDS:
        raw = values.get(k)
        if raw is None or str(raw).strip() == "":
            parsed[k] = None
            continue
        try:
            n = int(str(raw).strip())
        except ValueError:
            return f"{k.replace('_', ' ')} must be a whole number of days."
        if n < 0 or n > 3650:
            return f"{k.replace('_', ' ')} must be between 0 and 3650."
        parsed[k] = n
    base = default_policy(cert.cert_class)
    renew = parsed["renew_before_days"] if parsed["renew_before_days"] is not None \
        else base["renew_before_days"]
    swap = parsed["swap_after_days"] if parsed["swap_after_days"] is not None \
        else base["swap_after_days"]
    err = window_error(renew, swap)
    if err:
        return err
    rv = str(values.get("revoke_superseded") or "").strip().lower()
    for k, v in parsed.items():
        setattr(cert, k, v)
    cert.revoke_superseded = (True if rv in ("1", "yes", "on", "true") else
                              False if rv in ("0", "no", "off", "false") else None)
    if "auto_renew" in values:
        cert.auto_renew = str(values.get("auto_renew") or "").strip().lower() in (
            "1", "yes", "on", "true")
    return ""


def _copy_windows(src: ManagedCertificate, dst: ManagedCertificate) -> None:
    """A renewal keeps the rotation settings of the certificate it replaces."""
    for k in WINDOW_FIELDS + ("revoke_superseded", "auto_renew"):
        setattr(dst, k, getattr(src, k))


def successor_of(cert: ManagedCertificate):
    """The live renewal of *cert* (staged / awaiting signature / active), or None."""
    return (ManagedCertificate.query
            .filter(ManagedCertificate.supersedes_id == cert.id,
                    ManagedCertificate.archived_at.is_(None),
                    ManagedCertificate.status != "revoked")
            .order_by(ManagedCertificate.id.desc()).first())


def predecessor_of(cert: ManagedCertificate):
    return (db.session.get(ManagedCertificate, cert.supersedes_id)
            if cert.supersedes_id else None)


def _unique_name(base: str) -> str:
    """A device name no other managed certificate uses. Two issuances on the
    same day share the {date} stamp, and a renewal deployed under its
    predecessor's name would overwrite the certificate it is meant to replace."""
    taken = {n for (n,) in db.session.query(ManagedCertificate.name).all()}
    if base not in taken:
        return base
    for i in range(2, 1000):
        sfx = f"-{i}"
        cand = base[:naming.MAX_NAME_LEN - len(sfx)] + sfx
        if cand not in taken:
            return cand
    raise CertManagerError(f"no free certificate name derived from {base!r}")


def next_step(cert: ManagedCertificate) -> dict:
    """What happens to *cert* next and when — ``{label, at}`` for the table."""
    now = datetime.utcnow()
    pol = cert_policy(cert)
    if cert.archived_at:
        return {"label": "archived", "at": cert.archived_at}
    if cert.status == "awaiting_signature":
        return {"label": "waiting for the CA's signature", "at": None}
    if cert.status == "staged":
        return {"label": "swap", "at": cert.swap_due_at}
    if cert.status in ("superseded", "revoked"):
        if cert.removed_at or not cert.appliance_id:
            since = cert.removed_at or cert.superseded_at or cert.revoked_at or now
            return {"label": "leaves SATOM",
                    "at": since + timedelta(days=pol["retain_days"])}
        if cert.status == "superseded":
            since = cert.superseded_at or cert.updated_at or now
            return {"label": "leaves the device",
                    "at": since + timedelta(days=pol["remove_after_days"])}
        return {"label": "leaves the device (once unbound)", "at": None}
    succ = successor_of(cert)
    if succ is not None:
        return {"label": f"replaced by {succ.name}", "at": succ.swap_due_at}
    if cert.expires_at:
        if cert.origin == "imported":
            return {"label": "renew outside SATOM, then import",
                    "at": cert.expires_at - timedelta(days=pol["renew_before_days"])}
        if not cert.auto_renew:
            return {"label": "auto-renew off", "at": None}
        return {"label": "renewal" if cert.origin == "signer" else "new CSR",
                "at": cert.expires_at - timedelta(days=pol["renew_before_days"])}
    return {"label": "", "at": None}


# --------------------------------------------------------------------------- #
#  Orchestration: create / renew                                               #
# --------------------------------------------------------------------------- #
def _subject_and_sans(cn: str, cert_class: str, extra_sans=None):
    ccfg = store.cert_class_config(cert_class)
    subject = _interpolate(ccfg.get("subject_format", "CN={cn}"), {"cn": cn})
    san_spec = _interpolate(ccfg.get("san_format", "DNS:{cn}"), {"cn": cn})
    if extra_sans:
        san_spec = (san_spec + "," + ",".join(
            s if ":" in s else "DNS:" + s for s in extra_sans)).strip(",")
    return ccfg, subject, san_spec


def _open_row(appliance, cn: str, cert_class: str, *, extra_sans=None,
              supersedes: int | None = None, origin: str = "signer",
              actor: str = "") -> ManagedCertificate:
    """Generate CSR + key and store a row for them (key encrypted). Raises
    :class:`CertManagerError`."""
    ccfg, subject, san_spec = _subject_and_sans(cn, cert_class, extra_sans)
    try:
        csr_pem, key_pem = generate_csr(
            subject, san_spec, cert_class,
            key_type=ccfg.get("key_type", "rsa"),
            key_size=ccfg.get("key_size", "2048"))
    except Exception as exc:  # noqa: BLE001
        raise CertManagerError(f"CSR generation failed: {exc}") from exc
    name = _unique_name(cert_name_for(cn, cert_class))
    row = ManagedCertificate(
        name=name, appliance_id=getattr(appliance, "id", None),
        cert_class=cert_class, subject=subject,
        status="awaiting_signature" if origin == "external" else "pending",
        origin=origin, key_origin="satom",
        created_by=actor or _actor(), supersedes_id=supersedes)
    row.sans = [s.split(":", 1)[-1] for s in re.split(r"[,\s]+", san_spec) if s]
    row.csr_pem = csr_pem
    row.private_key = key_pem
    old = db.session.get(ManagedCertificate, supersedes) if supersedes else None
    if old is not None:
        _copy_windows(old, row)
    db.session.add(row)
    db.session.commit()
    _event(row, "generate", True, f"CSR generated for {subject}", by=actor)
    return row


def _store_signed(row: ManagedCertificate, cert_pem: str) -> None:
    meta = parse_certificate(cert_pem)
    row.cert_pem = cert_pem
    row.serial = meta["serial"]
    row.issued_at = meta["issued_at"]
    row.expires_at = meta["expires_at"]
    if meta["sans"]:
        row.sans = meta["sans"]
    db.session.commit()


def _appliance_of(cert: ManagedCertificate):
    if not cert.appliance_id:
        return None
    from ..models import Appliance
    return db.session.get(Appliance, cert.appliance_id)


def _deploy(row: ManagedCertificate, appliance, *, actor: str = "") -> str:
    """Upload cert + key to the device. Returns "" or the error text."""
    if appliance is None:
        _event(row, "deploy", False, "no target appliance for deploy", by=actor)
        return "signed but not deployed (no appliance)."
    try:
        # FortiADC takes key material over a REST multipart upload; FortiWeb
        # over the SSH CLI. Same call shape, dispatched on the device kind.
        deployer = (cert_adc if getattr(appliance, "kind", "fortiweb") == "fortiadc"
                    else cert_ssh)
        deployer.deploy_certificate(appliance, row.name, row.cert_pem,
                                    row.private_key, secret=appliance.ssh_secret)
    except Exception as exc:  # noqa: BLE001
        _event(row, "deploy", False, f"upload to {appliance.name} failed: {exc}",
               by=actor)
        return f"deploy failed: {exc}"
    _event(row, "deploy", True, f"uploaded to {appliance.name}", by=actor)
    return ""


def deploy_existing(row: ManagedCertificate, appliance, *, actor: str = "") -> str:
    """Upload a certificate the Certificate Manager already holds to
    ``appliance`` (Plugin Studio's certificate step, mode "existing").
    Returns "" or the error text. A certificate without its key, revoked,
    or whose key left SATOM cannot be deployed, and says so."""
    if row.revoked_at or row.status == "revoked":
        return f"certificate {row.name} is revoked"
    if row.archived_at or not row.has_private_key:
        return f"certificate {row.name} has no private key in SATOM any more"
    if not (row.cert_pem or "").strip():
        return f"certificate {row.name} is not signed yet ({row.status})"
    return _deploy(row, appliance, actor=actor)


def _schedule_swap(new: ManagedCertificate, old: ManagedCertificate | None) -> None:
    """A deployed renewal waits for its swap date: N days after it was issued,
    but never later than the day before the certificate it replaces expires."""
    now = datetime.utcnow()
    if old is None or old.status in ("revoked", "superseded") or old.archived_at:
        new.status = "pending"
        new.swap_due_at = None
        db.session.commit()
        return
    due = now + timedelta(days=cert_policy(new)["swap_after_days"])
    if old.expires_at:
        latest = old.expires_at - timedelta(days=1)
        if due > latest:
            due = max(now, latest)
    new.status = "staged"
    new.swap_due_at = due
    db.session.commit()
    _event(new, "schedule", True,
           f"swap onto the bindings of {old.name} scheduled for "
           f"{due:%Y-%m-%d %H:%M} UTC")


def _after_issue(row: ManagedCertificate, appliance, *, deploy: bool,
                 actor: str = "") -> dict:
    """Deploy a freshly signed/imported row and, if it is a renewal, schedule
    its swap. Returns the create_* result dict."""
    if deploy:
        err = _deploy(row, appliance, actor=actor)
        if err:
            return {"ok": False, "error": err, "cert_id": row.id, "name": row.name}
        _schedule_swap(row, predecessor_of(row))
    else:
        row.status = "pending"
        db.session.commit()
    where = (f"deployed to {appliance.name}" if deploy and appliance else "stored")
    tail = (f"It replaces {predecessor_of(row).name} on "
            f"{row.swap_due_at:%Y-%m-%d %H:%M} UTC." if row.status == "staged" else
            "It is NOT yet bound to a policy — swap it in during a maintenance window.")
    _notify(row, subject="Certificate ready",
            body=(f"Certificate {row.name} ({row.cert_class}) for {_cn_of(row)} is "
                  f"{where}. Expires {row.expires_at}. {tail}"))
    return {"ok": True, "cert_id": row.id, "name": row.name, "error": ""}


def create_certificate(appliance, cn: str, cert_class: str, *, extra_sans=None,
                       deploy: bool = True, supersedes: int | None = None,
                       actor: str = "", provider: str = "") -> dict:
    """Full cycle for one certificate signed by ``provider``'s CA (``""`` =
    the first provider, see :mod:`cert_providers`). Returns
    ``{ok, cert_id, name, error}``.

    Never raises — every failure is captured on the row's timeline and returned.
    """
    cn = (cn or "").strip()
    if cn == "":
        return {"ok": False, "error": "a certificate CN/hostname is required.", "cert_id": None}
    if cert_class not in store.CERT_CLASSES:
        return {"ok": False, "error": f"unknown certificate class {cert_class!r}.", "cert_id": None}

    from . import cert_providers
    try:
        prov = cert_providers.require(provider)
    except cert_providers.ProviderError as exc:
        return {"ok": False, "error": str(exc), "cert_id": None}
    ccfg = store.cert_class_config(cert_class)
    # The class template is an ADCS concept; an ACME issuer has none to need.
    if cert_providers.protocol_of(prov["key"]) != "acme" and not ccfg.get("template"):
        return {"ok": False,
                "error": f"class {cert_class!r} has no ADCS template configured "
                         "(Settings → Certificate Manager).", "cert_id": None}
    try:
        row = _open_row(appliance, cn, cert_class, extra_sans=extra_sans,
                        supersedes=supersedes, origin="signer", actor=actor)
    except CertManagerError as exc:
        return {"ok": False, "error": str(exc), "cert_id": None}

    row.provider = prov["key"]
    db.session.commit()
    try:
        cert_pem, sign_log = sign_csr(cert_class, row.csr_pem, prov["key"])
    except CertManagerError as exc:
        _event(row, "error", False, f"sign failed: {exc}", by=actor)
        return {"ok": False, "error": str(exc), "cert_id": row.id, "name": row.name}
    _store_signed(row, cert_pem)
    # The ADCS request id, for a revoke command that references {request_id}.
    rid = ca_request_id_from_log(sign_log)
    if rid:
        row.ca_request_id = rid
        db.session.commit()
    _event(row, "sign", True,
           f"signed serial={row.serial} expires={row.expires_at}", by=actor)
    return _after_issue(row, appliance, deploy=deploy, actor=actor)


def create_external_csr(appliance, cn: str, cert_class: str, *, extra_sans=None,
                        supersedes: int | None = None, actor: str = "") -> dict:
    """CSR for ANOTHER CA: the key is generated and kept (encrypted) here; the
    CSR is downloaded, signed elsewhere, and the result imported with
    :func:`import_signed`. Returns ``{ok, cert_id, name, error}``."""
    cn = (cn or "").strip()
    if cn == "":
        return {"ok": False, "error": "a certificate CN/hostname is required.", "cert_id": None}
    if cert_class not in store.CERT_CLASSES:
        return {"ok": False, "error": f"unknown certificate class {cert_class!r}.", "cert_id": None}
    try:
        row = _open_row(appliance, cn, cert_class, extra_sans=extra_sans,
                        supersedes=supersedes, origin="external", actor=actor)
    except CertManagerError as exc:
        return {"ok": False, "error": str(exc), "cert_id": None}
    _notify(row, subject="CSR ready for signature",
            body=(f"A CSR for {cn} ({cert_class}) is ready: {row.name}. Download it "
                  "from the Certificate Manager, have your CA sign it, and import "
                  "the signed certificate on the same row."))
    return {"ok": True, "cert_id": row.id, "name": row.name, "error": ""}


def renew_certificate(cert: ManagedCertificate, *, deploy: bool = True,
                      actor: str = "") -> dict:
    """Start the replacement of *cert*: signed by the configured CA → staged
    for its swap date; external origin → a new CSR awaiting signature;
    imported → refused (SATOM cannot reissue a certificate it never held the
    request for). The current certificate keeps serving until the swap."""
    if cert.origin == "imported":
        return {"ok": False, "cert_id": None,
                "error": "imported certificates are renewed outside SATOM — "
                         "import the replacement with Replace."}
    succ = successor_of(cert)
    if succ is not None:
        return {"ok": False, "cert_id": succ.id, "name": succ.name,
                "error": f"a replacement is already in progress ({succ.name}, "
                         f"{succ.status})."}
    appliance = _appliance_of(cert)
    if cert.origin == "external":
        res = create_external_csr(appliance, _cn_of(cert), cert.cert_class,
                                  supersedes=cert.id, actor=actor)
        kind = "new CSR"
    else:
        res = create_certificate(appliance, _cn_of(cert), cert.cert_class,
                                 extra_sans=None, deploy=deploy,
                                 supersedes=cert.id, actor=actor,
                                 provider=getattr(cert, "provider", "") or "")
        kind = "renewed"
    if res.get("ok"):
        _event(cert, "renew", True,
               f"{kind} → {res.get('name')} (cert #{res.get('cert_id')})", by=actor)
    return res


# --------------------------------------------------------------------------- #
#  Import: a signed certificate for OUR CSR, or a certificate + key from outside #
# --------------------------------------------------------------------------- #
_PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)
_PEM_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----.+?"
    r"-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----", re.S)


def _spki(public_key) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(serialization.Encoding.DER,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)


def _certs_from_pem(text: str) -> list:
    from cryptography import x509
    out = []
    for blob in _PEM_CERT_RE.findall(text or ""):
        try:
            out.append(x509.load_pem_x509_certificate(blob.encode()))
        except Exception:  # noqa: BLE001 — a broken block is skipped, not fatal
            continue
    return out


def _pem_of(cert) -> str:
    from cryptography.hazmat.primitives import serialization
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key) -> str:
    from cryptography.hazmat.primitives import serialization
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def _leaf_for_key(certs: list, key_spki: bytes):
    return next((c for c in certs if _spki(c.public_key()) == key_spki), None)


def _sans_of(cert) -> set[str]:
    from cryptography import x509
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return {str(g.value).lower() for g in ext.value}
    except Exception:  # noqa: BLE001
        return set()


def _not_after(cert):
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    return na.replace(tzinfo=None)


def import_signed(cert: ManagedCertificate, pem_text: str, *, deploy: bool = True,
                  actor: str = "") -> dict:
    """Attach the certificate another CA signed for the CSR SATOM generated.

    Only a PEM certificate (a chain is fine: the leaf is the one whose public
    key is the stored key). Never a key: the key of this request was made here
    and never left, which is the whole point of the CSR path — so a PKCS#12
    or a key is refused for an ``awaiting_signature`` row. Rejected unless the
    public key matches the stored key, every requested SAN is present and the
    certificate has not expired."""
    from cryptography.hazmat.primitives import serialization
    if cert.status != "awaiting_signature":
        return {"ok": False, "cert_id": cert.id,
                "error": f"{cert.name} is not waiting for a signature ({cert.status})."}
    if _PEM_KEY_RE.search(pem_text or ""):
        return {"ok": False, "cert_id": cert.id,
                "error": "a private key was pasted: the key of this request was "
                         "generated in SATOM and never leaves it — paste only the "
                         "signed certificate (and its chain)."}
    certs = _certs_from_pem(pem_text)
    if not certs:
        return {"ok": False, "cert_id": cert.id,
                "error": "no PEM certificate found in what was pasted."}
    try:
        key = serialization.load_pem_private_key(cert.private_key.encode(), None)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "cert_id": cert.id,
                "error": f"the stored key of this request is unreadable: {exc}"}
    leaf = _leaf_for_key(certs, _spki(key.public_key()))
    if leaf is None:
        _event(cert, "import", False, "rejected: no certificate matches the stored key",
               by=actor)
        return {"ok": False, "cert_id": cert.id,
                "error": "none of the certificates matches the key of this CSR — "
                         "it was signed for a different request."}
    wanted = {s.lower() for s in cert.sans}
    missing = sorted(wanted - _sans_of(leaf))
    if missing:
        _event(cert, "import", False, f"rejected: SANs missing {missing}", by=actor)
        return {"ok": False, "cert_id": cert.id,
                "error": "the signed certificate lacks requested SANs: "
                         + ", ".join(missing)}
    if _not_after(leaf) <= datetime.utcnow():
        return {"ok": False, "cert_id": cert.id,
                "error": f"the signed certificate already expired ({_not_after(leaf)})."}
    _store_signed(cert, _pem_of(leaf))
    _event(cert, "import", True,
           f"signed certificate imported: serial={cert.serial} expires={cert.expires_at}",
           by=actor)
    return _after_issue(cert, _appliance_of(cert), deploy=deploy, actor=actor)


def _load_external(data: bytes, key_pem: str, password: str):
    """``(leaf, key, chain_count)`` from a PKCS#12 blob or PEM cert(s) + key.
    Raises :class:`CertManagerError` with an operator-facing reason."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    pw = password.encode() if password else None
    text = ""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if "-----BEGIN" not in text:
        try:
            key, leaf, extra = pkcs12.load_key_and_certificates(data, pw)
        except Exception as exc:  # noqa: BLE001
            raise CertManagerError(
                f"not a readable PKCS#12 file (wrong password?): {exc}") from exc
        if key is None or leaf is None:
            raise CertManagerError("the PKCS#12 file holds no key or no certificate.")
        return leaf, key, len(extra or [])
    certs = _certs_from_pem(text)
    if not certs:
        raise CertManagerError("no PEM certificate found.")
    key_text = key_pem or ""
    if not _PEM_KEY_RE.search(key_text):
        m = _PEM_KEY_RE.search(text)
        key_text = m.group(0) if m else ""
    if not key_text:
        raise CertManagerError("the private key is missing (paste it or use a PKCS#12).")
    try:
        key = serialization.load_pem_private_key(key_text.encode(), pw)
    except TypeError as exc:
        raise CertManagerError("the private key is encrypted: enter its password.") from exc
    except Exception as exc:  # noqa: BLE001
        raise CertManagerError(f"the private key is unreadable: {exc}") from exc
    leaf = _leaf_for_key(certs, _spki(key.public_key()))
    if leaf is None:
        raise CertManagerError("the private key does not belong to any of the certificates.")
    return leaf, key, len(certs) - 1


def import_certificate(appliance, cert_class: str, data: bytes, *, key_pem: str = "",
                       password: str = "", supersedes: int | None = None,
                       deploy: bool = True, actor: str = "") -> dict:
    """Bring in a certificate AND key made outside SATOM (PEM pair or
    PKCS#12). The key is stored encrypted and marked ``key_origin=external``:
    SATOM did not generate it and cannot vouch for where else it lives.
    With *supersedes* it is the replacement of that certificate and follows
    the same staged swap as a renewal."""
    if cert_class not in store.CERT_CLASSES:
        return {"ok": False, "error": f"unknown certificate class {cert_class!r}.",
                "cert_id": None}
    old = db.session.get(ManagedCertificate, supersedes) if supersedes else None
    if old is not None and old.status == "awaiting_signature":
        return {"ok": False, "cert_id": old.id,
                "error": "that row is a CSR generated in SATOM — import only its "
                         "signed certificate there (a key from outside would "
                         "replace the key of the request)."}
    try:
        leaf, key, _chain = _load_external(data, key_pem, password)
    except CertManagerError as exc:
        return {"ok": False, "error": str(exc), "cert_id": None}
    if _not_after(leaf) <= datetime.utcnow():
        return {"ok": False, "cert_id": None,
                "error": f"the certificate already expired ({_not_after(leaf)})."}
    from cryptography.x509.oid import NameOID
    try:
        cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, ValueError):
        cn = next(iter(sorted(_sans_of(leaf))), "imported")
    row = ManagedCertificate(
        name=_unique_name(cert_name_for(cn, cert_class)),
        appliance_id=getattr(appliance, "id", None) or (old.appliance_id if old else None),
        cert_class=cert_class, subject=leaf.subject.rfc4514_string(),
        status="pending", origin="imported", key_origin="external",
        created_by=actor or _actor(), supersedes_id=supersedes)
    if old is not None:
        _copy_windows(old, row)
    row.private_key = _key_pem(key)
    db.session.add(row)
    db.session.commit()
    _store_signed(row, _pem_of(leaf))
    _event(row, "import", True,
           f"certificate + key imported (key generated outside SATOM): "
           f"serial={row.serial} expires={row.expires_at}", by=actor)
    if old is not None:
        _event(old, "renew", True, f"replacement imported → {row.name}", by=actor)
    return _after_issue(row, appliance if appliance is not None else _appliance_of(row),
                        deploy=deploy, actor=actor)


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
            client = appliance.build_client(timeout=8.0)
            client.bind_https_admin_cert(cert_name)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc), "request": req, "dry_run": False}
        # The settings singleton re-read: the admin GUI must now serve THIS
        # certificate, or the swap did not happen whatever the PUT answered.
        from . import device_verify
        v = device_verify.adc_after_write(appliance, client, "update",
                                          logical="system_global", mkey="",
                                          sent=req["body"])
        log_action("certmgr.swap_gui", target=cert_name,
                   appliance_id=getattr(appliance, "id", None),
                   detail=device_verify.label(v))
        if device_verify.failed(v):
            return {"ok": False, "error": device_verify.label(v), "request": req,
                    "dry_run": False, "verify": v}
        return {"ok": True, "error": "", "request": req, "dry_run": False, "verify": v}
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
        # Verified by absence: an accepted delete of a certificate the box
        # still holds (a binding the usage walk could not see) is a failure,
        # not "removed".
        from . import device_verify
        v = device_verify.adc_after_write(appliance, client, "delete",
                                          logical=logical, mkey=cert_name)
        if device_verify.failed(v):
            _audit_remove(appliance, cert_name, ok=False, detail=device_verify.label(v))
            return {"ok": False, "removed": False, "bindings": [],
                    "error": device_verify.label(v), "verify": v}
        _audit_remove(appliance, cert_name, ok=True,
                      detail=f"removed store={store_label} by={actor or _actor()} (REST; "
                             f"{device_verify.label(v)})")
        return {"ok": True, "removed": True, "error": "", "bindings": [], "verify": v}

    try:
        if store_label == "Local":
            cert_ssh.remove_certificate(appliance, cert_name, secret=appliance.ssh_secret)
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
    """Real swap of ONE server *policy* onto *cert*, then reconcile inventory
    state: the new cert becomes active/bound, the one it supersedes becomes
    'superseded'. (The rotation moves EVERY binding: :func:`perform_swap`.)"""
    appliance = _appliance_of(cert)
    if appliance is None:
        return {"ok": False, "error": "certificate has no target appliance."}
    res = swap_binding(appliance, policy, cert.name, dry_run=False, actor=actor)
    if res.get("ok"):
        bound = set(cert.bound_policies)
        bound.add(policy)
        cert.bound_policies = sorted(bound)
        cert.status = "active"
        cert.swap_due_at = None
        cert.swapped_at = cert.swapped_at or datetime.utcnow()
        db.session.commit()
        _event(cert, "swap", True, f"policy {policy} → {cert.name}", by=actor)
        old = predecessor_of(cert)
        if old and old.status not in ("revoked",):
            old.status = "superseded"
            old.superseded_at = old.superseded_at or datetime.utcnow()
            old.bound_policies = [p for p in old.bound_policies if p != policy]
            db.session.commit()
            _event(old, "swap", True,
                   f"superseded by {cert.name} on policy {policy}", by=actor)
    else:
        _event(cert, "error", False, f"swap onto {policy} failed: {res.get('error')}",
               by=actor)
    return res


# --------------------------------------------------------------------------- #
#  Swap EVERY reference of one certificate onto another (rotation + rollback)  #
# --------------------------------------------------------------------------- #
def _swap_fortiweb_refs(appliance, old_name: str, new_name: str) -> dict:
    """FortiWeb: server-policy cert fields, SNI members, the GUI cert."""
    out = {"complete": True, "done": [], "failed": []}
    try:
        client = appliance.build_client(timeout=8.0)
    except Exception as exc:  # noqa: BLE001
        return {"complete": False, "done": [], "failed": [("device", str(exc))]}
    complete, usage = _enumerate_usage(client, appliance, old_name)
    out["complete"] = complete
    if not complete:
        out["failed"].append(("bindings", "a binding read failed — nothing swapped"))
        return out
    for u in usage:
        if u["kind"] == "server-policy":
            r = swap_server_policy_cert(appliance, u["target"], u["field"], new_name,
                                        dry_run=False)
        elif u["kind"] == "sni":
            r = swap_sni_member(appliance, u["target"], u["sub_mkey"], new_name,
                                dry_run=False)
        elif u["kind"] == "gui":
            r = swap_gui_cert(appliance, new_name, dry_run=False)
        else:
            r = {"ok": False, "error": f"unknown binding kind {u['kind']!r}"}
        if r.get("ok"):
            out["done"].append(u["label"])
        else:
            out["failed"].append((u["label"], r.get("error") or "write refused"))
    return out


def swap_references(appliance, old_name: str, new_name: str) -> dict:
    """Move every binding of *old_name* on *appliance* onto *new_name*.
    ``{complete, done, failed}`` — see the per-kind helpers."""
    if getattr(appliance, "kind", "fortiweb") == "fortiadc":
        try:
            return cert_adc.swap_references(appliance, old_name, new_name)
        except Exception as exc:  # noqa: BLE001
            return {"complete": False, "done": [], "failed": [("device", str(exc))]}
    return _swap_fortiweb_refs(appliance, old_name, new_name)


def perform_swap(new: ManagedCertificate, *, actor: str = "",
                 dry_run: bool = False) -> dict:
    """The swap day of a renewal: every binding of the certificate it replaces
    moves onto *new*. The old one stays ON the device (that is what makes
    :func:`rollback` a single click) until its removal window passes.

    Fail-closed: if the bindings cannot all be READ, nothing is written and
    the swap is retried on the next run. A partial swap is reported as an
    error and the old certificate keeps the bindings that did not move — it
    can then never be removed while they remain."""
    old = predecessor_of(new)
    appliance = _appliance_of(new)
    if appliance is None:
        return {"ok": False, "error": f"{new.name} has no target appliance."}
    if old is None or old.status in ("revoked",) or old.archived_at:
        if not dry_run:
            new.status = "pending"
            new.swap_due_at = None
            db.session.commit()
            _event(new, "swap", True, "nothing to take over — left unbound", by=actor)
        return {"ok": True, "done": [], "failed": [], "note": "no predecessor"}
    if dry_run:
        return {"ok": True, "dry_run": True, "done": [], "failed": [],
                "note": f"would move every binding of {old.name} onto {new.name}"}
    res = swap_references(appliance, old.name, new.name)
    now = datetime.utcnow()
    if not res["complete"] and not res["done"]:
        detail = "; ".join(f"{l}: {e}" for l, e in res["failed"])
        _event(new, "swap", False, f"swap postponed (fail-closed): {detail}", by=actor)
        return {"ok": False, "error": detail, "done": [], "failed": res["failed"]}
    if res["failed"] and not res["done"]:
        detail = "; ".join(f"{l}: {e}" for l, e in res["failed"])
        _event(new, "swap", False, f"swap failed: {detail}", by=actor)
        return {"ok": False, "error": detail, "done": [], "failed": res["failed"]}
    new.status = "active" if res["done"] else "pending"
    new.swap_due_at = None
    new.swapped_at = now
    new.bound_policies = res["done"]
    old.status = "superseded"
    old.superseded_at = now
    old.bound_policies = [l for l, _e in res["failed"]]
    db.session.commit()
    moved = ", ".join(res["done"]) or "nothing (it was bound nowhere)"
    _event(new, "swap", not res["failed"],
           f"took over from {old.name}: {moved}"
           + ("" if not res["failed"] else " — NOT moved: "
              + "; ".join(f"{l}: {e}" for l, e in res["failed"])), by=actor)
    _event(old, "swap", True, f"superseded by {new.name} ({moved})", by=actor)
    _notify(new, subject="Certificate swapped",
            body=(f"{new.name} replaced {old.name} on {appliance.name}: {moved}. "
                  f"{old.name} stays on the device until "
                  f"{(now + timedelta(days=cert_policy(old)['remove_after_days'])):%Y-%m-%d}"
                  " — Roll back is available until then."))
    return {"ok": not res["failed"], "done": res["done"], "failed": res["failed"],
            "error": "" if not res["failed"] else "partial swap"}


def can_rollback(new: ManagedCertificate) -> str:
    """"" when *new* can hand its bindings back to the certificate it
    replaced, else why not."""
    old = predecessor_of(new)
    if new.status != "active" or old is None:
        return "only an active renewal can be rolled back."
    if old.status != "superseded":
        return f"{old.name} is {old.status}."
    if old.removed_at or old.archived_at:
        return f"{old.name} is no longer on the device."
    if old.expires_at and old.expires_at <= datetime.utcnow():
        return f"{old.name} has expired."
    return ""


def rollback(new: ManagedCertificate, *, actor: str = "") -> dict:
    """Give every binding of *new* back to the certificate it replaced. The
    renewal stays on the device as ``pending`` (no new swap is scheduled —
    swap it again by hand once the problem is understood)."""
    why = can_rollback(new)
    if why:
        return {"ok": False, "error": why}
    old = predecessor_of(new)
    appliance = _appliance_of(new)
    res = swap_references(appliance, new.name, old.name)
    if not res["done"]:
        detail = "; ".join(f"{l}: {e}" for l, e in res["failed"]) or "nothing to move"
        _event(new, "rollback", False, f"rollback failed: {detail}", by=actor)
        return {"ok": False, "error": detail}
    old.status = "active"
    old.superseded_at = None
    old.bound_policies = res["done"]
    new.status = "pending"
    new.bound_policies = [l for l, _e in res["failed"]]
    db.session.commit()
    _event(old, "rollback", True, f"bindings returned from {new.name}: "
           + ", ".join(res["done"]), by=actor)
    _event(new, "rollback", not res["failed"],
           f"rolled back to {old.name}"
           + ("" if not res["failed"] else " — NOT moved: "
              + "; ".join(f"{l}: {e}" for l, e in res["failed"])), by=actor)
    return {"ok": not res["failed"], "done": res["done"], "failed": res["failed"],
            "error": "" if not res["failed"] else "partial rollback"}


# --------------------------------------------------------------------------- #
#  Bindings, fail-closed, for one managed certificate                           #
# --------------------------------------------------------------------------- #
def binding_check(cert: ManagedCertificate) -> tuple[bool, list[str]]:
    """``(complete, labels)`` — where *cert* is in use right now.

    A certificate that is not on a device (no appliance, already removed, or
    a CSR still waiting for its signature) is bound nowhere by construction.
    Otherwise the device is read; ``complete=False`` means it could not be
    read fully and the caller must refuse anything that needs "unbound"."""
    if (not cert.appliance_id or cert.removed_at or cert.archived_at
            or cert.status == "awaiting_signature"):
        return True, list(cert.bound_policies)
    appliance = _appliance_of(cert)
    if appliance is None:
        return True, list(cert.bound_policies)
    try:
        client = appliance.build_client(timeout=6.0)
    except Exception:  # noqa: BLE001
        return False, list(cert.bound_policies)
    if getattr(appliance, "kind", "fortiweb") == "fortiadc":
        complete, usage = cert_adc.enumerate_usage(client, cert.name)
    else:
        complete, usage = _enumerate_usage(client, appliance, cert.name)
    return complete, [u["label"] for u in usage]


# --------------------------------------------------------------------------- #
#  Revoke — generic: whatever CA is configured, plus the revocation register    #
# --------------------------------------------------------------------------- #
def ca_label(provider: str = "") -> str:
    """Which CA SATOM would ask — for the register, not for logic."""
    from . import cert_providers
    who = (cert_providers.label(provider) + ": ") if provider else ""
    if cert_providers.protocol_of(provider) == "acme":
        a = store.cert_manager_acme()
        return f"{who}acme {a.get('directory_url') or '?'}"
    a = store.cert_manager_adcs()
    return f"{who}adcs {a.get('ca') or '?'} / {a.get('ca_name') or '?'}"


def revoke_route(cert: ManagedCertificate) -> tuple[str, str]:
    """``("ca", "")`` when the configured CA's revoke command will be run;
    ``("manual", why)`` when somebody has to revoke it at the CA by hand."""
    if cert.origin != "signer":
        return ("manual", "it was not signed by the CA configured in SATOM — "
                          "revoke it at the CA that signed it")
    _proto, cmd_tmpl, _m, _e, _s = _revoke_context(cert)
    if not cmd_tmpl:
        return ("manual", "the configured CA has no revoke command "
                          "(Settings → Certificate Manager)")
    return ("ca", "")


def _fingerprint(cert: ManagedCertificate) -> str:
    if not cert.cert_pem:
        return ""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        c = x509.load_pem_x509_certificate(cert.cert_pem.encode())
        return c.fingerprint(hashes.SHA256()).hex()
    except Exception:  # noqa: BLE001
        return ""


def _issuer(cert: ManagedCertificate) -> str:
    if not cert.cert_pem:
        return ""
    try:
        from cryptography import x509
        return x509.load_pem_x509_certificate(cert.cert_pem.encode()).issuer.rfc4514_string()
    except Exception:  # noqa: BLE001
        return ""


def register_revocation(cert: ManagedCertificate, *, reason: str, result: str,
                        detail: str = "", by: str = "", ca: str = ""):
    from ..models import CertRevocation
    row = CertRevocation(
        cert_id=cert.id, cert_name=cert.name, serial=cert.serial or "",
        fingerprint_sha256=_fingerprint(cert), subject=cert.subject or "",
        issuer=_issuer(cert), ca_label=(ca or "")[:256], reason=reason,
        result=result, detail=(detail or "")[:4000], requested_by=by or _actor(),
        requested_at=datetime.utcnow())
    db.session.add(row)
    db.session.commit()
    return row


def confirm_manual_revocation(rev, *, actor: str = "") -> dict:
    """An operator states the certificate WAS revoked at its CA."""
    if rev.result != "manual_pending":
        return {"ok": False, "error": f"this entry is {rev.result}, not pending."}
    rev.result = "manual_done"
    rev.confirmed_by = actor or _actor()
    rev.confirmed_at = datetime.utcnow()
    db.session.commit()
    log_action("certmgr.revoke_confirmed", target=rev.cert_name,
               detail=f"serial={rev.serial} reason={rev.reason}")
    return {"ok": True}


def revoke_certificate(cert: ManagedCertificate, *, reason: str = "unspecified",
                       delete_from_box: bool = False, dry_run: bool = False,
                       allow_bound: bool = False, actor: str = "") -> dict:
    """Revoke *cert* — at the configured CA when SATOM can (its ``revoke_cmd``,
    with ``{serial}``/``{request_id}``/``{cert}``/``{reason}``/``{fingerprint}``),
    otherwise as a ``manual_pending`` entry of the register. Either way the
    register gets a row and the certificate is marked revoked.

    A certificate still IN USE is refused unless *allow_bound* (the operator
    confirmed it — a compromised key cannot wait for a maintenance window);
    bindings that cannot be read count as in use. Deleting it off the device
    stays refused while bound, whatever *allow_bound* says."""
    from ..models import CertRevocation
    reason = reason if reason in CertRevocation.REASONS else "unspecified"
    if cert.status == "awaiting_signature":
        return {"ok": False, "revoked": False, "bindings": [],
                "error": "a CSR that was never signed has nothing to revoke — "
                         "delete the record instead."}
    if cert.status == "revoked":
        return {"ok": False, "revoked": True, "bindings": [],
                "error": f"{cert.name} is already revoked."}
    route, why = revoke_route(cert)
    protocol, cmd_tmpl, mapping, env, secrets = _revoke_context(cert)
    complete, bound = binding_check(cert)

    if dry_run:
        preview = (_redact_all(_interpolate(cmd_tmpl, dict(
            mapping, cert="<cert.pem>", reason=reason,
            fingerprint=_fingerprint(cert))), secrets)
            if route == "ca" else f"manual: {why}")
        return {"ok": True, "dry_run": True, "route": route,
                "summary": f"[dry-run] revoke ({protocol}): {preview}",
                "bindings": bound, "complete": complete}

    if (bound or not complete) and not allow_bound:
        return {"ok": False, "revoked": False, "bindings": bound, "in_use": True,
                "error": ("still in use: " + ", ".join(bound)) if bound else
                         "its bindings could not be read — treated as in use"}

    ca_ok, ca_log, result = True, "", "manual_pending"
    if route == "ca":
        with tempfile.TemporaryDirectory(prefix="certmgr-rev-") as d:
            cert_path = os.path.join(d, "cert.pem")
            with open(cert_path, "w") as fh:
                fh.write(cert.cert_pem or "")
            try:
                argv = _argv_from_template(cmd_tmpl, dict(
                    mapping, cert=cert_path, reason=reason,
                    fingerprint=_fingerprint(cert)))
                proc = subprocess.run(argv, capture_output=True,
                                      text=True, timeout=_SIGN_TIMEOUT, cwd=d,
                                      env=_build_env(env, home=mapping.get("acme_path") or d))
                ca_ok = proc.returncode == 0
                ca_log = _redact_all(f"[{protocol}] [rc={proc.returncode}] "
                                     f"{proc.stdout}\n{proc.stderr}", secrets)[:2000]
            except Exception as exc:  # noqa: BLE001
                ca_ok, ca_log = False, _redact_all(f"revoke command error: {exc}", secrets)
        result = "revoked" if ca_ok else "failed"
    else:
        ca_log = f"not revoked at a CA by SATOM: {why}. Marked revoked here; " \
                 "confirm in the revocation register once the CA has done it."

    if result == "failed":
        # The CA said no: the certificate is NOT revoked. Register the attempt,
        # leave the status alone so it can be retried.
        register_revocation(cert, reason=reason, result="failed", detail=ca_log,
                            by=actor, ca=ca_label(getattr(cert, "provider", "") or ""))
        _event(cert, "revoke", False, ca_log, by=actor)
        return {"ok": False, "revoked": False, "bindings": bound,
                "error": "the CA's revoke command failed", "log": ca_log}

    cert.status = "revoked"
    cert.revoked_at = cert.revoked_at or datetime.utcnow()
    cert.swap_due_at = None
    db.session.commit()
    register_revocation(cert, reason=reason, result=result, detail=ca_log,
                        by=actor, ca=ca_label(getattr(cert, "provider", "") or "") if route == "ca" else why)
    _event(cert, "revoke", True,
           f"reason={reason} ({'at the CA' if route == 'ca' else 'manual at the CA'})"
           f"{' WHILE IN USE: ' + ', '.join(bound) if bound else ''}\n{ca_log}", by=actor)

    box_detail = ""
    if delete_from_box and cert.appliance_id and not cert.removed_at:
        res = remove_from_device(cert, actor=actor)
        if not res.get("removed"):
            box_detail = res.get("error") or "device delete refused"
            _notify(cert, subject="Certificate revoked",
                    body=f"Certificate {cert.name} was revoked ({reason}). "
                         f"NOT removed from the device: {box_detail}")
            return {"ok": True, "revoked": True, "deleted": False, "route": route,
                    "bindings": res.get("bindings", []), "error": box_detail,
                    "log": ca_log}
        box_detail = "removed from the device"
    _notify(cert, subject="Certificate revoked",
            body=f"Certificate {cert.name} ({cert.cert_class}) was revoked ({reason}, "
                 f"{'at the CA' if route == 'ca' else 'pending at the CA: ' + why}). "
                 f"{box_detail}")
    return {"ok": True, "revoked": True, "deleted": bool(box_detail), "route": route,
            "bindings": bound, "error": "", "log": ca_log,
            "manual": route != "ca", "manual_reason": why}


def remove_from_device(cert: ManagedCertificate, *, actor: str = "") -> dict:
    """Take a managed certificate off its device (fail-closed on bindings, via
    :func:`remove_device_certificate`) and record WHEN."""
    appliance = _appliance_of(cert)
    if appliance is None:
        return {"ok": False, "removed": False, "bindings": [],
                "error": "certificate has no target appliance."}
    res = remove_device_certificate(appliance, "Local", cert.name, dry_run=False,
                                    actor=actor)
    if res.get("removed"):
        cert.removed_at = datetime.utcnow()
        cert.bound_policies = []
        db.session.commit()
        _event(cert, "remove", True, f"removed from {appliance.name}", by=actor)
    else:
        _event(cert, "remove", False, res.get("error") or "device delete refused",
               by=actor)
    return res


def delete_record(cert: ManagedCertificate, *, revoke_first: bool = False,
                  reason: str = "cessationOfOperation",
                  remove_from_box: bool = False, actor: str = "") -> dict:
    """Delete a certificate RECORD. Refused while the certificate is in use
    (or its bindings cannot be read): SATOM must not forget a certificate a
    device is serving. Optionally revoke first and/or take it off the device
    first; either failing aborts the delete. The revocation register keeps
    its rows (``cert_id`` → NULL)."""
    from ..models import CertRevocation
    complete, bound = binding_check(cert)
    if bound or not complete:
        return {"ok": False, "bindings": bound,
                "error": ("in use: " + ", ".join(bound) + " — swap it out first")
                         if bound else "its bindings could not be read — "
                                       "refusing to forget it"}
    if revoke_first and cert.status not in ("revoked", "awaiting_signature"):
        r = revoke_certificate(cert, reason=reason, actor=actor)
        if not r.get("revoked"):
            return {"ok": False, "bindings": [], "error": f"revoke failed: {r.get('error')}"}
    if remove_from_box and cert.appliance_id and not cert.removed_at \
            and cert.status != "awaiting_signature":
        r = remove_from_device(cert, actor=actor)
        if not r.get("removed"):
            return {"ok": False, "bindings": r.get("bindings", []),
                    "error": f"not removed from the device: {r.get('error')}"}
    name, cid = cert.name, cert.id
    # On the device only if a deploy of it succeeded and it was not taken off
    # since: a CSR, or a certificate stored without deploying, has no copy there.
    on_device = bool(cert.appliance_id and not cert.removed_at
                     and any(e.kind == "deploy" and e.ok for e in cert.events))
    CertRevocation.query.filter_by(cert_id=cid).update({"cert_id": None})
    ManagedCertificate.query.filter_by(supersedes_id=cid).update({"supersedes_id": None})
    ManagedCertificateEvent.query.filter_by(cert_id=cid).delete()
    db.session.delete(cert)
    db.session.commit()
    log_action("certmgr.delete", target=name,
               detail=f"revoke_first={revoke_first} remove_from_box={remove_from_box}")
    return {"ok": True, "name": name, "left_on_device": on_device}


def read_bindings_for(cert: ManagedCertificate) -> list[str]:
    """Bindings for a stored cert (resolves its appliance). [] if none/unknown."""
    appliance = _appliance_of(cert)
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
        ManagedCertificate.archived_at.is_(None),
        ManagedCertificate.status.in_(("active", "pending")))
    if appliance_id is not None:
        q = q.filter(ManagedCertificate.appliance_id == appliance_id)
    out = []
    for c in q.all():
        d = c.days_left
        if d is not None and d <= within_days:
            out.append(c)
    return out


# --------------------------------------------------------------------------- #
#  Rotation — renew → staged → swap → off the device → out of SATOM            #
# --------------------------------------------------------------------------- #
def _scope(appliance_id, cert_class):
    q = ManagedCertificate.query.filter(ManagedCertificate.archived_at.is_(None))
    if appliance_id is not None:
        q = q.filter(ManagedCertificate.appliance_id == appliance_id)
    if cert_class:
        q = q.filter(ManagedCertificate.cert_class == cert_class)
    return q.order_by(ManagedCertificate.id).all()


def rotation_plan(appliance_id: int | None = None, cert_class: str = "") -> dict:
    """What the rotation would do RIGHT NOW, per stage. Pure read.

    * ``renew`` — auto-renew on, inside its renew window, no replacement yet;
    * ``notice`` — inside the window but SATOM cannot start the replacement
      (imported, or auto-renew off): someone has to act;
    * ``swap`` — staged renewals whose swap date has come;
    * ``remove`` — superseded certificates past their removal window;
    * ``archive`` — certificates off the device past their retention window.
    """
    now = datetime.utcnow()
    plan = {"renew": [], "notice": [], "swap": [], "remove": [], "archive": []}
    for c in _scope(appliance_id, cert_class):
        pol = cert_policy(c)
        if c.status in ("active", "pending") and c.days_left is not None \
                and c.days_left <= pol["renew_before_days"] \
                and successor_of(c) is None:
            if c.origin != "imported" and c.auto_renew:
                plan["renew"].append(c)
            else:
                plan["notice"].append(c)
        elif c.status == "staged" and c.swap_due_at and c.swap_due_at <= now:
            plan["swap"].append(c)
        elif c.status == "superseded" and c.appliance_id and not c.removed_at:
            since = c.superseded_at or c.updated_at or now
            if since + timedelta(days=pol["remove_after_days"]) <= now:
                plan["remove"].append(c)
        if c.status in ("superseded", "revoked") and not c.archived_at:
            gone = c.removed_at or (None if c.appliance_id else
                                    (c.superseded_at or c.revoked_at))
            if gone and gone + timedelta(days=pol["retain_days"]) <= now:
                plan["archive"].append(c)
    return plan


def archive_certificate(cert: ManagedCertificate, *, actor: str = "") -> None:
    """The key leaves SATOM: private key and CSR are purged, the row is
    hidden from the inventory. Serial, dates, PEM and the timeline stay —
    that is the record."""
    cert.private_key_enc = ""
    cert.csr_pem = ""
    cert.archived_at = datetime.utcnow()
    db.session.commit()
    _event(cert, "archive", True, "private key purged; kept as a record only", by=actor)


def run_rotation(*, dry_run: bool = False, appliance_id: int | None = None,
                 cert_class: str = "", actor: str = "") -> dict:
    """Apply :func:`rotation_plan`. Every destructive step is fail-closed (a
    certificate that cannot be PROVEN unbound is never removed); every step
    writes the certificate's timeline. Never raises."""
    who = actor or "rotation"
    plan = rotation_plan(appliance_id, cert_class)
    out = {"dry_run": dry_run, "renewed": [], "swapped": [], "removed": [],
           "revoked": [], "archived": [], "notices": [], "skipped": []}
    for c in plan["notice"]:
        why = ("imported — renew it outside SATOM and import the replacement"
               if c.origin == "imported" else "auto-renew is off")
        out["notices"].append(f"{c.name}: {c.days_left} d left, {why}")
    for c in plan["renew"]:
        if dry_run:
            out["renewed"].append(f"[dry-run] would {'renew' if c.origin == 'signer' else 'generate a CSR for'} {c.name}")
            continue
        try:
            res = renew_certificate(c, deploy=True, actor=who)
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            res = {"ok": False, "error": str(exc)}
        if res.get("ok"):
            out["renewed"].append(f"{c.name} → {res.get('name')}")
        else:
            out["skipped"].append(f"{c.name}: renewal failed — {res.get('error')}")
    for c in plan["swap"]:
        if dry_run:
            out["swapped"].append(f"[dry-run] would swap {c.name} in")
            continue
        try:
            res = perform_swap(c, actor=who)
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            res = {"ok": False, "error": str(exc)}
        (out["swapped"] if res.get("ok") else out["skipped"]).append(
            f"{c.name}: " + (", ".join(res.get("done") or []) or res.get("note") or "")
            if res.get("ok") else f"{c.name}: swap — {res.get('error')}")
    for c in plan["remove"]:
        if dry_run:
            out["removed"].append(f"[dry-run] would remove {c.name} from its device")
            if cert_policy(c)["revoke_superseded"] and c.status != "revoked":
                out["revoked"].append(f"[dry-run] would revoke {c.name} (superseded) "
                                      "as it leaves the device")
            continue
        res = remove_from_device(c, actor=who)
        if not res.get("removed"):
            out["skipped"].append(f"{c.name}: device removal refused — {res.get('error')}")
            continue
        out["removed"].append(f"{c.name}: off the device")
        if cert_policy(c)["revoke_superseded"] and c.status != "revoked":
            r = revoke_certificate(c, reason="superseded", actor=who)
            if r.get("revoked"):
                out["revoked"].append(
                    f"{c.name}: {'revoked at the CA' if r.get('route') == 'ca' else 'revocation pending at the CA'}")
            else:
                out["skipped"].append(f"{c.name}: revoke failed — {r.get('error')}")
    for c in plan["archive"]:
        if dry_run:
            out["archived"].append(f"[dry-run] would purge the key of {c.name}")
            continue
        archive_certificate(c, actor=who)
        out["archived"].append(f"{c.name}: key purged, kept as a record")
    return out


# --------------------------------------------------------------------------- #
#  Lifecycle policy — material that must leave the devices regardless of a     #
#  rotation: revoked certificates and expired ones. Driven by Settings →        #
#  Certificate Manager → Lifecycle policy; the superseded side is the rotation. #
# --------------------------------------------------------------------------- #
def _days_since(ts) -> int | None:
    if not ts:
        return None
    return (datetime.utcnow() - ts).days


def lifecycle_candidates(appliance_id: int | None = None) -> dict:
    """What is DUE right now, for the page and the sweep.

    * ``revoke_due`` — superseded certificates whose removal window passed and
      whose policy revokes them (they are revoked as they leave the device);
    * ``delete_due`` — material that must leave the device: superseded past
      the removal window, revoked (``delete_revoked_from_device``), expired
      past the expiry retention window.

    Candidates bound in the DB are listed as ``blocked`` instead — and the
    apply path re-verifies bindings LIVE and fail-closed, so a bound
    certificate can never be removed."""
    pol = store.cert_lifecycle_policy()
    revoke_due, delete_due, blocked = [], [], []
    plan = rotation_plan(appliance_id)
    for c in plan["remove"]:
        item = {"cert": c, "action": "delete",
                "reason": (f"superseded {_days_since(c.superseded_at or c.updated_at)}d ago "
                           f"(removal after {cert_policy(c)['remove_after_days']}d)")}
        (blocked if c.is_bound else delete_due).append(item)
        if cert_policy(c)["revoke_superseded"]:
            ritem = {"cert": c, "action": "revoke",
                     "reason": "superseded — revoked as it leaves the device"}
            (blocked if c.is_bound else revoke_due).append(ritem)
    q = ManagedCertificate.query.filter(ManagedCertificate.archived_at.is_(None),
                                        ManagedCertificate.removed_at.is_(None))
    if appliance_id is not None:
        q = q.filter(ManagedCertificate.appliance_id == appliance_id)
    for c in q.all():
        if not c.appliance_id or c.status in ("superseded", "awaiting_signature"):
            continue
        reason = ""
        if c.status == "revoked" and pol["delete_revoked_from_device"]:
            reason = "revoked — material must leave the device"
        elif c.status != "revoked" and c.expires_at:
            exp_days = _days_since(c.expires_at)
            if exp_days is not None and exp_days >= pol["delete_expired_after_days"]:
                reason = (f"expired {exp_days}d ago (retention "
                          f"{pol['delete_expired_after_days']}d)")
        if reason:
            item = {"cert": c, "action": "delete", "reason": reason}
            (blocked if c.is_bound else delete_due).append(item)
    return {"revoke_due": revoke_due, "delete_due": delete_due,
            "blocked": blocked, "policy": pol}


def run_lifecycle_sweep(*, dry_run: bool = True, appliance_id: int | None = None,
                        actor: str = "") -> dict:
    """The rotation (renew / swap / remove / revoke / archive) plus the policy
    deletes (revoked and expired material). Every destructive step re-verifies
    bindings LIVE and fail-closed — an unverifiable or bound cert is skipped
    and reported, never forced. ``dry_run=True`` only reports."""
    rot = run_rotation(dry_run=dry_run, appliance_id=appliance_id,
                       actor=actor or "lifecycle")
    out = {"dry_run": dry_run, "revoked": list(rot["revoked"]),
           "deleted": list(rot["removed"]), "skipped": list(rot["skipped"]),
           "renewed": rot["renewed"], "swapped": rot["swapped"],
           "archived": rot["archived"], "notices": rot["notices"],
           "policy": store.cert_lifecycle_policy()}
    cand = lifecycle_candidates(appliance_id)
    for item in cand["delete_due"]:
        c = item["cert"]
        if c.status == "superseded":
            continue  # the rotation above owns superseded certificates
        if dry_run:
            out["deleted"].append(f"[dry-run] would delete {c.name} — {item['reason']}")
            continue
        res = remove_from_device(c, actor=actor or "lifecycle")
        if res.get("removed"):
            out["deleted"].append(f"deleted {c.name} — {item['reason']}")
        else:
            out["skipped"].append(f"{c.name}: device delete refused — {res.get('error')}")
    for item in cand["blocked"]:
        if item["cert"].status != "superseded":
            out["skipped"].append(f"{item['cert'].name}: {item['action']} due "
                                  f"({item['reason']}) but still bound in DB — skipped")

    changed = [x for k in ("renewed", "swapped", "revoked", "deleted", "archived")
               for x in out[k]]
    if not dry_run and changed:
        to = store.cert_manager_adcs().get("notify_to", "")
        if to:
            try:
                from . import email_service
                body = "\n".join(["Lifecycle sweep results:"] + changed
                                 + out["notices"] + out["skipped"])
                email_service.send_email(to, "[Cert Manager] Lifecycle sweep", body)
            except Exception:  # noqa: BLE001
                logger.debug("lifecycle email skipped", exc_info=True)
    log_action("certmgr.lifecycle_sweep",
               detail=(f"dry_run={dry_run} renewed={len(out['renewed'])} "
                       f"swapped={len(out['swapped'])} revoked={len(out['revoked'])} "
                       f"deleted={len(out['deleted'])} archived={len(out['archived'])} "
                       f"skipped={len(out['skipped'])}"))
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


def _store_refusal(resp, body) -> str:
    """``""`` when a cmdb GET answered with data; else why it did not
    (``HTTP 423: The license of peer VM FortiWeb is not valid.``)."""
    if resp is None:
        return "no answer"
    status = getattr(resp, "status_code", 200) or 200
    err = body.get("errcode") if isinstance(body, dict) else None
    try:
        negative = err is not None and int(err) < 0
    except (TypeError, ValueError):
        negative = False
    if status < 400 and not negative:
        return ""
    msg = str(body.get("message") or "") if isinstance(body, dict) else ""
    return ("HTTP %s%s" % (status, (": " + msg) if msg else (" errcode %s" % err if err else "")))[:160]


def list_device_certificates(appliances, *, timeout: float = 6.0) -> list[dict]:
    """Live, read-only sweep of every appliance's certificate stores.

    Returns one entry per appliance: ``{appliance, online, error, certs[]}``.
    Dispatches on ``appliance.kind`` — FortiWeb reads the four cmdb stores,
    FortiADC reads its REST stores (:func:`cert_adc.sweep_certificates`, same
    entry shape). Best-effort — an unreachable box is marked ``online=False``
    (its first store GET failed) and the sweep moves on; a store missing on a
    given firmware just contributes nothing. No SSH, no ADCS, never raises.
    Kinds outside :data:`CERT_KINDS` are skipped, not swept with FortiWeb calls.
    """
    from . import cert_adc
    out: list[dict] = []
    for a in appliances:
        if not supports_kind(a):
            continue
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
                refused = _store_refusal(resp, body)
                if refused:
                    # A 4xx / negative errcode is NOT an empty store: a box whose
                    # REST is license-locked (423, -20010) answered "0 certs" here
                    # while it holds them (2026-10-23).
                    if idx == 0:
                        entry["online"] = False
                        entry["error"] = refused
                        break
                    continue
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
    if not supports_kind(appliance):
        return {"ok": False, "online": False, "appliance": appliance.name,
                "scanned": 0, "detailed": 0,
                "error": (f"certificate management is not available for "
                          f"{appliance.kind} (FortiWeb and FortiADC only)")}
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
    "CERT_KINDS", "supports_kind",
    "CertManagerError","generate_csr", "sign_csr", "parse_certificate",
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
