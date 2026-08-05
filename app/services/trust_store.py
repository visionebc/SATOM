"""TLS trust store — build the CA bundle this node verifies devices against.

Companion to :mod:`app.models_trust`. Three jobs:

1. **Import** a pasted/uploaded PEM (a root, an intermediate, or a whole chain
   in one blob) into ``trusted_cas``, parsed and classified.
2. **Materialise** the enabled rows into an on-disk bundle OpenSSL can read,
   and hand its path to :mod:`app.clients.base` as httpx's ``verify=``.
3. **Diagnose** a device's TLS in terms an operator can act on — which of
   *unknown issuer* / *hostname mismatch* / *expired* actually happened.

Three rules hold this together:

* **The bundle CONTAINS the public roots, it does not replace them.** httpx's
  ``verify=True`` means certifi; handing it a path replaces that list wholesale.
  A fleet is mixed — some appliances present the company CA, some present the
  public wildcard the edge renews (fortiweb09/10 do, since 2026-08-03). Shipping
  only the private CAs would break verification for exactly the devices that
  were already verifiable, which reads as "the trust store broke my fleet".
* **A bundle that cannot be built NEVER downgrades to no verification.** The
  fallback is ``True`` (public roots only) — a visible failure. Falling back to
  ``False`` would turn a transient DB hiccup into silent, fleet-wide, unverified
  TLS, and nothing would ever print that it happened.
* **Only CA certificates are accepted.** OpenSSL will not anchor a chain on a
  ``basicConstraints CA:FALSE`` certificate: importing a device's self-signed
  *leaf* would appear to work and then fail every handshake with an unhelpful
  error. Rejecting it at import, with the reason, is the honest answer — a
  self-signed leaf has no CA to trust, and that device stays on
  ``verify_ssl=False`` until it is re-issued from a real CA.
"""
from __future__ import annotations

import hashlib
import os
import socket
import ssl
import threading
from datetime import datetime, timezone
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ..models_trust import ROLE_INTERMEDIATE, ROLE_ROOT, TrustedCa
from ..extensions import db

#: Where the derived bundle is written. Node-local by design: it is a cache of
#: the DB rows, and every node rebuilds its own. Overridable so the test suite
#: never writes into a live installation (the lesson of the job ledger, which
#: pytest quietly filled with 36 ghost records on 2026-07-28).
_DEFAULT_DIR = Path(__file__).resolve().parents[2] / "pki" / "trust"
BUNDLE_NAME = "ca-bundle.pem"

_lock = threading.Lock()
_cached_digest: str | None = None

#: ``verify_param`` is consulted on EVERY device request (a full sync is
#: hundreds), so the resolved answer is held briefly rather than re-querying the
#: table each time. Short enough that enabling a CA takes effect on its own.
_RESOLVE_TTL_S = 30.0
_resolved: tuple[float, object] | None = None


def trust_dir() -> Path:
    return Path(os.environ.get("SATOM_TRUST_DIR") or _DEFAULT_DIR)


def bundle_file() -> Path:
    return trust_dir() / BUNDLE_NAME


# ---------------------------------------------------------------------------
# parsing / import
# ---------------------------------------------------------------------------

def _dn(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:  # noqa: BLE001
        return str(name)


def _naive_utc(dt: datetime) -> datetime:
    """Store naive UTC — the rest of this schema does, and mixing the two makes
    every comparison raise."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _describe(cert: x509.Certificate) -> dict:
    der = cert.public_bytes(Encoding.DER)
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = bool(bc.ca)
    except x509.ExtensionNotFound:
        # No basicConstraints at all. Ancient roots omit it; treat as NOT a CA
        # rather than guessing — a wrong "yes" here produces a bundle that
        # fails at handshake time instead of at import time.
        is_ca = False
    subject, issuer = _dn(cert.subject), _dn(cert.issuer)
    return {
        "cert": cert,
        "pem": cert.public_bytes(Encoding.PEM).decode("ascii"),
        "fingerprint": hashlib.sha256(der).hexdigest(),
        "subject": subject,
        "issuer": issuer,
        "serial": format(cert.serial_number, "x"),
        "is_ca": is_ca,
        "self_signed": subject == issuer,
        "role": ROLE_ROOT if subject == issuer else ROLE_INTERMEDIATE,
        "not_before": _naive_utc(cert.not_valid_before_utc),
        "not_after": _naive_utc(cert.not_valid_after_utc),
        "common_name": _common_name(cert),
    }


def _common_name(cert: x509.Certificate) -> str:
    try:
        vals = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if vals:
            return str(vals[0].value)
    except Exception:  # noqa: BLE001
        pass
    return _dn(cert.subject)[:120]


def parse_pem(blob: str | bytes) -> list[dict]:
    """Every certificate in ``blob``, described. Accepts a single PEM, a
    concatenated chain (root + intermediate pasted together — the common case
    for this feature) or DER.

    Raises ValueError with a readable message when nothing parses; the UI shows
    it verbatim, so it must say what to do, not just that it failed."""
    if isinstance(blob, str):
        raw = blob.encode()
    else:
        raw = blob
    raw = raw.strip()
    if not raw:
        raise ValueError("Nothing to import — paste or upload a PEM certificate.")
    certs: list[x509.Certificate] = []
    if b"-----BEGIN" in raw:
        try:
            certs = x509.load_pem_x509_certificates(raw)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"Could not parse the PEM: {exc}") from exc
    else:
        try:
            certs = [x509.load_der_x509_certificate(raw)]
        except Exception as exc:  # noqa: BLE001
            raise ValueError(
                "Not a certificate. Expected PEM text starting with "
                "'-----BEGIN CERTIFICATE-----', or a DER file."
            ) from exc
    if not certs:
        raise ValueError("The file parsed but contained no certificate.")
    return [_describe(c) for c in certs]


def import_pem(blob: str | bytes, actor: str = "", note: str = "",
               name_hint: str = "") -> dict:
    """Import every CA in ``blob``. Idempotent: re-importing refreshes the row
    that already holds that fingerprint instead of stacking a duplicate.

    Returns ``{"imported": [...], "updated": [...], "rejected": [{name, reason}]}``.
    Partial success is a real outcome — pasting a full chain where the leaf came
    along is normal, and the two CAs in it should still land."""
    parsed = parse_pem(blob)
    out: dict[str, list] = {"imported": [], "updated": [], "rejected": []}
    for info in parsed:
        label = info["common_name"] or info["subject"]
        if not info["is_ca"]:
            out["rejected"].append({
                "name": label,
                "reason": "not a CA certificate (basicConstraints CA:FALSE or "
                          "absent) — OpenSSL cannot anchor a chain on it. If "
                          "this is a device's own self-signed certificate, "
                          "there is no CA to trust and that appliance has to "
                          "keep TLS verification off until it is re-issued.",
            })
            continue
        row = TrustedCa.query.filter_by(fingerprint=info["fingerprint"]).first()
        if row is not None:
            row.pem = info["pem"]
            row.subject, row.issuer = info["subject"], info["issuer"]
            row.serial, row.role = info["serial"], info["role"]
            row.not_before, row.not_after = info["not_before"], info["not_after"]
            if note:
                row.note = note
            out["updated"].append(row.name)
            continue
        name = (name_hint or label or info["fingerprint"][:16]).strip()[:200]
        if len(parsed) > 1 and name_hint:
            # One hint, several certs — keep the names distinct or the unique
            # constraint turns a valid chain import into an opaque DB error.
            name = f"{name_hint} ({info['role']})"[:200]
        base, n = name, 2
        while TrustedCa.query.filter_by(name=name).first() is not None:
            name = f"{base} #{n}"[:200]
            n += 1
        db.session.add(TrustedCa(
            name=name, pem=info["pem"], fingerprint=info["fingerprint"],
            subject=info["subject"], issuer=info["issuer"],
            serial=info["serial"], role=info["role"],
            not_before=info["not_before"], not_after=info["not_after"],
            enabled=True, note=note, added_by=actor or "",
        ))
        out["imported"].append(name)
    db.session.commit()
    invalidate()
    return out


def invalidate() -> None:
    """Force the next :func:`verify_param` to rebuild the on-disk bundle."""
    global _cached_digest, _resolved
    with _lock:
        _cached_digest = None
        _resolved = None


# ---------------------------------------------------------------------------
# bundle materialisation
# ---------------------------------------------------------------------------

def enabled_cas() -> list[TrustedCa]:
    return (TrustedCa.query.filter_by(enabled=True)
            .order_by(TrustedCa.role.desc(), TrustedCa.name).all())


def _digest(rows) -> str:
    h = hashlib.sha256()
    for r in rows:
        h.update(r.fingerprint.encode())
    return h.hexdigest()


def build_bundle() -> Path | None:
    """Write ``<trust_dir>/ca-bundle.pem`` = public roots + enabled private CAs.

    Returns the path, or ``None`` when there is nothing private to add (the
    caller then uses the stock public list — writing a copy of certifi would
    just be a second file to keep fresh)."""
    rows = enabled_cas()
    if not rows:
        return None
    global _cached_digest
    want = _digest(rows)
    path = bundle_file()
    with _lock:
        if _cached_digest == want and path.exists():
            return path
        path.parent.mkdir(parents=True, exist_ok=True)
        body = [Path(certifi.where()).read_text(encoding="utf-8")]
        for r in rows:
            body.append(f"\n# SATOM trust store: {r.name} ({r.role})\n"
                        f"# subject: {r.subject}\n# sha256: {r.fingerprint}\n")
            body.append(r.pem if r.pem.endswith("\n") else r.pem + "\n")
        tmp = path.with_suffix(".tmp")
        tmp.write_text("".join(body), encoding="utf-8")
        os.replace(tmp, path)          # atomic — a reader never sees a half file
        try:
            path.chmod(0o644)
        except OSError:
            pass
        _cached_digest = want
        return path


def verify_param():
    """What to hand httpx / ssl as ``verify=``.

    ``True`` (public roots) when there is no private CA or when the bundle
    cannot be built. **Never ``False``** — see the module docstring."""
    global _resolved
    import time
    now = time.monotonic()
    cached = _resolved
    if cached is not None and (now - cached[0]) < _RESOLVE_TTL_S:
        return cached[1]
    try:
        p = build_bundle()
        val: object = str(p) if p else True
    except Exception:  # noqa: BLE001 — a broken store must not disable TLS
        return True     # not cached: a transient failure must not stick
    _resolved = (now, val)
    return val


def chain_gaps() -> list[dict]:
    """Enabled intermediates whose issuer is in neither the store nor certifi.

    A chain that stops short still imports cleanly and then fails every
    handshake with "unable to get issuer certificate" — a message that points
    at the device, not at the missing root. Surfacing it on the page is the
    difference between a five-minute fix and an afternoon."""
    rows = enabled_cas()
    subjects = {r.subject for r in rows}
    gaps = []
    for r in rows:
        if r.role == ROLE_ROOT or r.issuer in subjects:
            continue
        gaps.append({"name": r.name, "issuer": r.issuer})
    return gaps


# ---------------------------------------------------------------------------
# per-device diagnosis
# ---------------------------------------------------------------------------

def _leaf_of(host: str, port: int, timeout: float) -> dict:
    """The certificate the device presents, read WITHOUT validating it.

    ``getpeercert()`` returns an EMPTY dict under ``CERT_NONE`` — CPython only
    fills the parsed fields when it validated the chain. The DER always comes
    back, so parse that (same trap as the deep-monitor TLS probe, 2026-07-28)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            proto, cipher = tls.version(), (tls.cipher() or ("", "", 0))[0]
    cert = x509.load_der_x509_certificate(der)
    info = _describe(cert)
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
        names = [str(n.value) for n in san]
    except x509.ExtensionNotFound:
        names = []
    return {
        "subject": info["subject"], "issuer": info["issuer"],
        "self_signed": info["self_signed"], "sans": names,
        "not_after": info["not_after"], "not_before": info["not_before"],
        "fingerprint": info["fingerprint"],
        "protocol": proto, "cipher": cipher,
        "common_name": info["common_name"],
    }


def _try_verify(host: str, port: int, timeout: float, cafile,
                check_hostname: bool) -> tuple[bool, str]:
    ctx = ssl.create_default_context(
        cafile=cafile if isinstance(cafile, str) else None)
    ctx.check_hostname = check_hostname
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True, ""
    except ssl.SSLCertVerificationError as exc:
        return False, (getattr(exc, "verify_message", "") or str(exc))
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def probe(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Diagnose one device's TLS against the CURRENT trust store.

    The point is the ``reason``: "verification failed" is useless, because the
    three causes need three different fixes — import a CA, change the appliance
    host to a name the certificate covers, or re-issue an expired cert. So the
    chain is tested with hostname checking OFF as well as ON, and the two
    results together name the cause."""
    res: dict = {"host": host, "port": int(port), "reachable": False,
                 "leaf": None, "chain_ok": False, "hostname_ok": False,
                 "verified": False, "reason": "", "advice": ""}
    try:
        res["leaf"] = _leaf_of(host, int(port), timeout)
        res["reachable"] = True
    except Exception as exc:  # noqa: BLE001
        res["reason"] = f"could not open a TLS connection: {exc}"
        res["advice"] = ("The device did not complete a TLS handshake. This is "
                         "reachability, not trust — check the host, the port "
                         "and that the box is up.")
        return res

    cafile = verify_param()
    ca = cafile if isinstance(cafile, str) else certifi.where()
    chain_ok, chain_err = _try_verify(host, int(port), timeout, ca, False)
    res["chain_ok"] = chain_ok
    if chain_ok:
        name_ok, name_err = _try_verify(host, int(port), timeout, ca, True)
        res["hostname_ok"] = name_ok
        res["verified"] = name_ok
        if name_ok:
            res["reason"] = "certificate chain and hostname both verify"
            res["advice"] = ("This appliance can run with TLS verification ON. "
                             "Tick 'Verify TLS' on its Appliance record.")
        else:
            names = ", ".join(res["leaf"]["sans"]) or res["leaf"]["common_name"]
            res["reason"] = f"chain is trusted but the hostname does not match: {name_err}"
            res["advice"] = (
                f"The CA is trusted — only the name is wrong. The certificate "
                f"covers: {names}. Set the appliance's Host to one of those "
                f"(SATOM is connecting to '{host}'), or re-issue the "
                f"certificate with that name in its SAN.")
        return res

    leaf = res["leaf"]
    if leaf["not_after"] and leaf["not_after"] < datetime.utcnow():
        res["reason"] = f"the device certificate expired on {leaf['not_after']:%Y-%m-%d}"
        res["advice"] = ("Re-issue the appliance certificate. Trusting a CA "
                         "cannot rescue an expired leaf.")
    elif leaf["self_signed"]:
        res["reason"] = "the device presents a SELF-SIGNED certificate — there is no CA to trust"
        res["advice"] = (
            "Nothing to import: a self-signed leaf is its own issuer and "
            "OpenSSL will not anchor on it. Either re-issue this device's "
            "certificate from your company CA (then import that CA here), or "
            "leave TLS verification off for this appliance.")
    else:
        res["reason"] = f"issuer is not trusted: {chain_err or 'unable to get issuer certificate'}"
        res["advice"] = (
            f"Import the CA that signed it. The certificate says its issuer is: "
            f"{leaf['issuer']}. Add that CA (and any intermediate above it) to "
            f"the trust store, then probe again.")
    return res
