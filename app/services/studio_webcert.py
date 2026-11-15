"""Plugin Studio > Apps -- signing a web server's certificate request.

The private key of a managed web server's certificate is made ON that server
(``satom-webctl cert.csr``) and never leaves it. What travels is the request
(CSR) and, back, the certificate -- both public. This step is the middle:

* ``cert_sign`` -- the request is signed by a provider of the Certificate
  Manager (Certificate Manager > Providers): the internal CA (ADCS-style
  command, e.g. the OPNsense CA signer) or ACME (lego, DNS-01 through the
  catalogued DNS provider). It is :func:`cert_manager.sign_csr`, the same
  call the Certificate Manager's own issuance makes; nothing about the
  protocol is decided here a second time.

The step checks the request before anything is signed (a valid signature,
at least one name, no more than :data:`MAX_NAMES`) and the answer before it
is returned (the certificate must be for the request's key). It asks the
user who RUNS it for the permission the Certificate Manager's issue page
asks (``user_manage``): an app never widens who may issue certificates. A run
without a user (a schedule, an event) is refused. Each signature leaves an
audit line (``webhost.cert.sign``).
"""
from __future__ import annotations

import datetime

from . import studio_flow as F

GROUP = "satom"
KIND_KEYS = ("cert_sign",)
WRITE_KINDS = ("cert_sign",)
DEVICE_KINDS: tuple = ()
DEFAULT_SAVE_AS = {"cert_sign": "signed"}
PERMISSION = "user_manage"
CLASSES = ("server", "clientserver")
MAX_NAMES = 100
MAX_CSR = 16 * 1024


def kinds() -> list:
    P, K = F.Param, F.Kind
    return [
        K("cert_sign", "Sign a certificate request", GROUP,
          "Sign a server's certificate request (CSR) with a Certificate Manager provider -- "
          "the internal CA or ACME -- and return the certificate. The private key stays on "
          "the server that made the request (satom-webctl cert.csr); the next step installs "
          "the certificate there (cert.install). Needs the user_manage permission, like "
          "the Certificate Manager.",
          [P("csr", "Certificate request (PEM)", "textarea", True,
             help="e.g. {{ req.csr }} -- the answer of a cert.csr step"),
           P("provider", "Provider",
             help="A provider key (Certificate Manager > Providers), e.g. "
                  "{{ form.provider }}. Empty = the first provider."),
           P("cert_class", "Certificate class", "select", choices=CLASSES, default="server"),
           F._save_as("signed")], writes=True),
    ]


def need(ctx) -> None:
    u = ctx.user_obj
    if u is None:
        raise F.FlowError("signing a certificate answers for the person who runs the app; "
                          "a run without a user (a schedule or an event) cannot use it")
    if not (getattr(u, "can", None) and u.can(PERMISSION)):
        raise F.FlowError("this step needs the %s permission (the Certificate Manager asks "
                          "the same); the user running the app does not hold it" % PERMISSION)


def check_csr(pem: str):
    """The parsed request, or FlowError: a valid signature and 1..MAX_NAMES names."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    pem = (pem or "").strip()
    if not pem:
        raise F.FlowError("no certificate request: run cert.csr first")
    if len(pem) > MAX_CSR:
        raise F.FlowError("the certificate request is larger than %d bytes" % MAX_CSR)
    if "PRIVATE KEY" in pem:
        raise F.FlowError("that is a private key, not a request: a key never leaves its server")
    try:
        csr = x509.load_pem_x509_csr(pem.encode())
    except ValueError:
        raise F.FlowError("the certificate request is not a PEM CSR") from None
    if not csr.is_signature_valid:
        raise F.FlowError("the certificate request's signature is not valid")
    return csr, names_of(csr, NameOID)


def names_of(csr, NameOID=None) -> list[str]:
    from cryptography import x509
    if NameOID is None:
        from cryptography.x509.oid import NameOID
    names = [a.value for a in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names += [str(v) for v in san.get_values_for_type(x509.DNSName)]
        names += [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    out = []
    for n in names:
        if n not in out:
            out.append(str(n))
    if not out:
        raise F.FlowError("the certificate request names no host")
    if len(out) > MAX_NAMES:
        raise F.FlowError("the certificate request names more than %d hosts" % MAX_NAMES)
    return out


def _spki(key) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def describe(cert_pem: str, csr) -> dict:
    """What the signed certificate says; FlowError when it is not for the
    request's key (a CA that answered with another certificate)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    try:
        certs = x509.load_pem_x509_certificates(cert_pem.encode())
    except ValueError:
        raise F.FlowError("the provider answered with no PEM certificate") from None
    leaf = next((c for c in certs if _spki(c.public_key()) == _spki(csr.public_key())), None)
    if leaf is None:
        raise F.FlowError("the provider's certificate is not for this request's key")
    na = getattr(leaf, "not_valid_after_utc", None) or leaf.not_valid_after.replace(
        tzinfo=datetime.timezone.utc)
    cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer = (leaf.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
              or leaf.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME))
    # the leaf first, then the rest of what the provider sent (its chain)
    from cryptography.hazmat.primitives import serialization
    ordered = [leaf] + [c for c in certs if c is not leaf]
    pem = "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in ordered)
    return {"certificate": pem, "subject": cn[0].value if cn else "",
            "issuer": issuer[0].value if issuer else "",
            "serial": format(leaf.serial_number, "x"),
            "sha256": leaf.fingerprint(hashes.SHA256()).hex(),
            "not_after": na.strftime("%Y-%m-%d %H:%M UTC"),
            "days_left": int((na - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
                             // 86400),
            "chain_length": len(ordered)}


def _provider(node, ctx) -> str:
    from . import cert_providers as CP
    key = str(F.render(F._p(node, "provider", ""), ctx.scope()) or "").strip()
    known = [p["key"] for p in CP.providers()]
    if key and key not in known:
        raise F.FlowError("provider %r is not in the Certificate Manager (%s)"
                          % (key, ", ".join(known)))
    return key or (known[0] if known else "")


def _cert_class(node) -> str:
    c = F._p(node, "cert_class", "server") or "server"
    if c not in CLASSES:
        raise F.FlowError("certificate class: %s" % ", ".join(CLASSES))
    return c


def rehearse(node: dict, ctx) -> tuple:
    csr, names = check_csr(str(F.render(F._p(node, "csr", ""), ctx.scope()) or ""))
    provider = _provider(node, ctx)
    return "ok", {"certificate": "", "subject": names[0], "issuer": "<the provider's CA>",
                  "serial": "", "sha256": "", "not_after": "", "days_left": 0,
                  "chain_length": 0, "provider": provider, "names": names,
                  "rehearsal": True}, \
        "rehearsal: would sign the request for %s with %s" % (", ".join(names[:5]), provider)


def run(node: dict, ctx) -> tuple:
    need(ctx)
    from . import cert_manager as CM
    from .audit import log_action
    csr, names = check_csr(str(F.render(F._p(node, "csr", ""), ctx.scope()) or ""))
    provider, cls = _provider(node, ctx), _cert_class(node)
    from cryptography.hazmat.primitives import serialization
    pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    try:
        cert_pem, _log = CM.sign_csr(cls, pem, provider)
    except CM.CertManagerError as exc:
        log_action("webhost.cert.sign", target=names[0],
                   extra={"provider": provider, "names": names[:20], "ok": False,
                          "error": str(exc)[:300], "by": ctx.user, "run": ctx.run_id})
        raise F.FlowError("the provider did not sign: %s" % str(exc)[:600]) from None
    d = describe(cert_pem, csr)
    d.update({"provider": provider, "names": names})
    log_action("webhost.cert.sign", target=names[0],
               extra={"provider": provider, "names": names[:20], "serial": d["serial"],
                      "not_after": d["not_after"], "class": cls, "ok": True, "by": ctx.user,
                      "run": ctx.run_id})
    return "ok", d, "signed by %s (%s), %d day(s) left" % (d["issuer"] or provider, provider,
                                                           d["days_left"])
