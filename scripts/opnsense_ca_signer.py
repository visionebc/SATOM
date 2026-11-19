#!/usr/bin/env python3
"""Sign a CSR with a CA held in an OPNsense firewall (System > Trust).

A signer for the Certificate Manager's command-template contract
(Settings > Certificate Manager, "Enterprise CA (command template)"):

    sign:   {bin} sign --url {ca} --ca-ref {ca_name} --key {user}
                  --cert-type {template} --csr {csr} --out {out}
                  --pin-sha256 <base64 SPKI hash>

where {bin} is ``/opt/satom/venv/bin/python /opt/satom/scripts/opnsense_ca_signer.py``.

* The API secret is read ONLY from ``$SATOM_CA_SECRET`` (the Certificate
  Manager exports the stored CA secret there); a secret on the command line is
  refused, so it never shows up in ``/proc/<pid>/cmdline`` or a job log.
* The private key never leaves SATOM: OPNsense's ``sign_csr`` action receives
  the CSR only.
* OPNsense's ``sign_csr`` does NOT copy the CSR's subjectAltName extension, so
  the SANs are read from the CSR and sent as ``altnames_*`` fields. Without
  them browsers and curl reject the certificate.
* The signed certificate stays in the firewall's Trust store on purpose: it is
  the CA's issuance record, and a later revocation (CRL) references it.
* TLS: ``--pin-sha256`` pins the firewall's public key (checked BEFORE any
  credential is sent), ``--cafile`` verifies against a bundle; the default is
  the system trust store. A pin survives a certificate renewal that keeps the
  key, and an expired GUI certificate.

Uses the Python standard library plus ``cryptography`` (already in SATOM's venv).

Exit codes: 0 ok, 2 usage/configuration, 3 TLS identity mismatch, 4 API error.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import socket
import ssl
import sys
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization

SECRET_ENV = "SATOM_CA_SECRET"
TIMEOUT = 30


class SignerError(Exception):
    def __init__(self, msg: str, code: int = 4):
        super().__init__(msg)
        self.code = code


def spki_sha256(der_cert: bytes) -> str:
    """base64(sha256(SubjectPublicKeyInfo)) — the curl ``--pinnedpubkey`` form."""
    cert = x509.load_der_x509_certificate(der_cert)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()


class Api:
    def __init__(self, url: str, key: str, secret: str, *, pin: str = "",
                 cafile: str = ""):
        parts = urlsplit(url if "://" in url else "https://" + url)
        if parts.scheme != "https" or not parts.hostname:
            raise SignerError(f"--url must be an https URL, got {url!r}", 2)
        self.host, self.port = parts.hostname, parts.port or 443
        self.prefix = parts.path.rstrip("/")
        self.pin = pin.strip().removeprefix("sha256//")
        if self.pin:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # identity = the pin, checked below
        else:
            ctx = ssl.create_default_context(cafile=cafile or None)
        self.ctx = ctx
        token = base64.b64encode(f"{key}:{secret}".encode()).decode()
        self.headers = {"Authorization": "Basic " + token,
                        "Accept": "application/json"}

    def _connect(self) -> http.client.HTTPSConnection:
        conn = http.client.HTTPSConnection(self.host, self.port,
                                           context=self.ctx, timeout=TIMEOUT)
        try:
            conn.connect()
        except (OSError, ssl.SSLError, socket.timeout) as exc:
            raise SignerError(f"cannot reach {self.host}:{self.port}: {exc}") from exc
        if self.pin:
            got = spki_sha256(conn.sock.getpeercert(binary_form=True))
            if got != self.pin:
                conn.close()
                raise SignerError(
                    f"TLS public key of {self.host}:{self.port} does not match the "
                    f"pin (got sha256//{got}); no credentials were sent", 3)
        return conn

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        conn = self._connect()
        try:
            payload = json.dumps(body).encode() if body is not None else None
            headers = dict(self.headers)
            if payload is not None:
                headers["Content-Type"] = "application/json"
            conn.request(method, self.prefix + path, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", "replace")
        finally:
            conn.close()
        if resp.status in (401, 403):
            raise SignerError(f"{method} {path}: HTTP {resp.status} — the API key "
                              "needs the System: Certificate Manager privilege", 2)
        if resp.status >= 400:
            raise SignerError(f"{method} {path}: HTTP {resp.status}: {raw[:300]}")
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise SignerError(f"{method} {path}: not JSON: {raw[:200]}") from exc


def csr_altnames(csr: x509.CertificateSigningRequest) -> dict[str, str]:
    """The CSR's SANs as OPNsense ``altnames_*`` fields — one value per LINE
    (a comma-separated list is rejected: "X509 V3 routines::missing value")."""
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return {}
    out = {
        "altnames_dns": san.get_values_for_type(x509.DNSName),
        "altnames_ip": [str(ip) for ip in san.get_values_for_type(x509.IPAddress)],
        "altnames_email": san.get_values_for_type(x509.RFC822Name),
        "altnames_uri": san.get_values_for_type(x509.UniformResourceIdentifier),
    }
    return {k: "\n".join(v) for k, v in out.items() if v}


def cn_of(csr: x509.CertificateSigningRequest) -> str:
    attrs = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else ""


def cmd_sign(args, api: Api) -> int:
    with open(args.csr, "rb") as fh:
        csr_pem = fh.read()
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
    except ValueError as exc:
        raise SignerError(f"{args.csr} is not a PEM CSR: {exc}", 2) from exc
    if not csr.is_signature_valid:
        raise SignerError("the CSR signature does not verify", 2)
    fields = {
        "action": "sign_csr",
        "caref": args.ca_ref,
        "csr_payload": csr_pem.decode(),
        "cert_type": args.cert_type,
        "lifetime": str(args.lifetime),
        "digest": args.digest,
        "private_key_location": "local",
        "descr": f"SATOM: {cn_of(csr) or 'certificate'}",
        **csr_altnames(csr),
    }
    res = api.call("POST", "/api/trust/cert/add", {"cert": fields})
    uuid = res.get("uuid")
    if res.get("result") != "saved" or not uuid:
        raise SignerError(f"sign_csr refused: {json.dumps(res)[:400]}")
    cert = api.call("GET", f"/api/trust/cert/get/{uuid}").get("cert", {})
    pem = (cert.get("crt_payload") or "").strip()
    if "BEGIN CERTIFICATE" not in pem:
        raise SignerError(f"OPNsense stored the request ({uuid}) but returned no certificate")
    leaf = x509.load_pem_x509_certificate(pem.encode())
    with open(args.out, "w") as fh:
        fh.write(pem + "\n")
    print(f"signed by OPNsense CA {args.ca_ref}: serial {leaf.serial_number:x}, "
          f"not after {leaf.not_valid_after_utc:%Y-%m-%d}, "
          f"trust store refid {cert.get('refid', '?')} (uuid {uuid})")
    return 0


def cmd_pin(args, _api) -> int:
    """Print the server's SPKI pin (TOFU helper: compare it out of band)."""
    parts = urlsplit(args.url if "://" in args.url else "https://" + args.url)
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((parts.hostname, parts.port or 443), TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=parts.hostname) as tls:
            print("sha256//" + spki_sha256(tls.getpeercert(binary_form=True)))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, *, creds=True):
        sp.add_argument("--url", required=True, help="https://<firewall>[:port]")
        if creds:
            sp.add_argument("--key", required=True, help="OPNsense API key (not the secret)")
            sp.add_argument("--pin-sha256", default="", help="base64 SPKI pin of the firewall")
            sp.add_argument("--cafile", default="", help="CA bundle to verify the firewall")

    s = sub.add_parser("sign", help="sign a CSR")
    common(s)
    s.add_argument("--ca-ref", required=True, help="refid of the issuing CA (System > Trust > Authorities)")
    s.add_argument("--csr", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--cert-type", default="server_cert",
                   choices=("server_cert", "usr_cert", "combined_server_client"))
    s.add_argument("--lifetime", type=int, default=397, help="days")
    s.add_argument("--digest", default="sha256", choices=("sha256", "sha384", "sha512"))
    s.set_defaults(func=cmd_sign)

    pn = sub.add_parser("pin", help="print the firewall's SPKI pin")
    common(pn, creds=False)
    pn.set_defaults(func=cmd_pin)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if any(a == "--secret" or a.startswith("--secret=") for a in argv):
        print(f"error: pass the API secret in ${SECRET_ENV}, never on the command line",
              file=sys.stderr)
        return 2
    args = build_parser().parse_args(argv)
    try:
        api = None
        if args.cmd != "pin":
            secret = os.environ.get(SECRET_ENV, "")
            if not secret:
                raise SignerError(f"${SECRET_ENV} is empty — store the API secret in "
                                  "Settings > Certificate Manager", 2)
            api = Api(args.url, args.key, secret, pin=args.pin_sha256, cafile=args.cafile)
        return args.func(args, api)
    except SignerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.code
    except (OSError, ipaddress.AddressValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
