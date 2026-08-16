# app/services/cert_inspect.py
"""Certificate & chain inspector — the tool that answers "is this chain complete".

Why this exists, from this project's own scar tissue: CT 346 served a wildcard
whose chain was one certificate short. The symptom was ``curl`` reporting
``unable to get local issuer certificate``, and the fix was knowing that the
correct fullchain carries THREE certificates. Nothing in SATOM could say that,
so it was discovered by hand, twice.

What this module refuses to do:

* **It never reports "incomplete" when it simply could not read the chain.**
  A leaf-only read (no ``openssl`` binary available, so the TLS stack hands back
  only the peer certificate) sets ``chain_source='leaf'`` and completeness
  ``unknown``. Those are different answers and they send the operator to
  different places; collapsing them into "incomplete" would manufacture an
  incident. This is the same discipline as the metric panels: a failed query is
  painted as an ERROR, never as an empty graph.
* **It never asserts a link it did not verify.** Adjacent chain links are
  checked by actually verifying the child's signature with the parent's public
  key. The anchor above the last presented certificate is checked by NAME
  against this host's trust store, and is reported as a name match — because
  that is all it is.

Pure computation plus one outbound socket (:func:`fetch_chain`). Certificate
field extraction is NOT re-implemented here: :mod:`app.services.cert_probe`
already owns it and a second copy is the copy that rots.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from datetime import datetime

from . import cert_probe

logger = logging.getLogger(__name__)

#: Certificates expiring inside this many days are flagged.
EXPIRY_WARN_DAYS = 30
#: …and inside this many days are flagged as critical.
EXPIRY_CRIT_DAYS = 7
#: RSA keys below this are flagged. 2048 is the CA/Browser Forum floor.
MIN_RSA_BITS = 2048
#: Signature hashes that are broken for certificate use.
WEAK_HASHES = ("md5", "sha1")

#: Max certificates accepted in one pasted bundle (a chain is 2-4; a paste of
#: a whole trust store is a mistake, and parsing 150 certs to say so is waste).
MAX_BUNDLE = 12

_PEM_RX = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL)

_TRUST_PATHS = (
    "/etc/ssl/certs/ca-certificates.crt",       # Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",         # RHEL/Fedora
    "/etc/ssl/ca-bundle.pem",                   # openSUSE
    "/etc/ssl/cert.pem",                        # Alpine/macOS ports
)


# --------------------------------------------------------------------------- #
#  Parsing                                                                     #
# --------------------------------------------------------------------------- #
def split_pem(text: str) -> list[str]:
    """Every PEM certificate block in a blob, in the order it appears.

    Operators paste fullchains, ``openssl s_client`` transcripts (which carry
    ``s:``/``i:`` annotation lines between blocks) and files with CRLF endings.
    All three are the same list of certificates, so all three are accepted.
    """
    raw = (text or "").replace("\r\n", "\n")
    return [m.group(0) for m in _PEM_RX.finditer(raw)][:MAX_BUNDLE]


def _dn(name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:  # noqa: BLE001
        return ""


def cert_info(pem: str) -> dict:
    """One certificate's detail: :func:`cert_probe.detail_from_pem` plus the
    chain-relevant fields (full DNs, CA flag, key size, self-signedness)."""
    from cryptography import x509

    out = dict(cert_probe.detail_from_pem(pem))
    out.update({"subject_dn": "", "issuer_dn": "", "is_ca": False,
                "self_signed": False, "key_bits": 0, "pem": pem or "",
                "parse_error": ""})
    try:
        cert = x509.load_pem_x509_certificate((pem or "").encode())
    except Exception as exc:  # noqa: BLE001
        out["parse_error"] = "%s: %s" % (type(exc).__name__, exc)
        return out
    out["subject_dn"] = _dn(cert.subject)
    out["issuer_dn"] = _dn(cert.issuer)
    out["self_signed"] = bool(out["subject_dn"]) and out["subject_dn"] == out["issuer_dn"]
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        out["is_ca"] = bool(bc.value.ca)
    except Exception:  # noqa: BLE001 — no BasicConstraints means not a CA
        pass
    try:
        pk = cert.public_key()
        out["key_bits"] = int(getattr(pk, "key_size", 0) or 0)
    except Exception:  # noqa: BLE001
        pass
    return out


# --------------------------------------------------------------------------- #
#  Link verification — real signature checks, not name matching                #
# --------------------------------------------------------------------------- #
def verify_signed_by(child_pem: str, parent_pem: str):
    """``True`` / ``False`` / ``None`` — did *parent* actually sign *child*?

    ``None`` means the signature algorithm is one this build cannot verify, and
    is reported as such. Returning ``False`` for "I don't know" would tell the
    operator their chain is broken on the strength of a missing code path.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding

    try:
        child = x509.load_pem_x509_certificate((child_pem or "").encode())
        parent = x509.load_pem_x509_certificate((parent_pem or "").encode())
    except Exception:  # noqa: BLE001
        return None
    pub = parent.public_key()
    try:
        if isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub.verify(child.signature, child.tbs_certificate_bytes)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       ec.ECDSA(child.signature_hash_algorithm))
        elif hasattr(pub, "verify"):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       padding.PKCS1v15(), child.signature_hash_algorithm)
        else:
            return None
    except Exception as exc:  # noqa: BLE001
        # A genuine signature mismatch is InvalidSignature; anything else means
        # we could not perform the check, and those must not read the same.
        if type(exc).__name__ == "InvalidSignature":
            return False
        return None
    return True


def key_matches_cert(cert_pem: str, key_pem: str, passphrase: str = "") -> dict:
    """Does this private key belong to this certificate?

    The failure this catches is the one that already happened here: a cert and a
    key copied into place from two different issuances. nginx starts, serves,
    and every client fails the handshake — with an error that names neither file.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    out = {"checked": False, "match": None, "error": ""}
    if not (key_pem or "").strip():
        return out
    try:
        cert = x509.load_pem_x509_certificate((cert_pem or "").encode())
    except Exception:  # noqa: BLE001
        out["error"] = "the certificate could not be parsed"
        return out
    try:
        key = serialization.load_pem_private_key(
            key_pem.encode(),
            password=(passphrase.encode() if passphrase else None))
    except TypeError:
        out["error"] = "this private key is encrypted — supply its passphrase"
        return out
    except Exception as exc:  # noqa: BLE001
        out["error"] = "the private key could not be parsed (%s)" % type(exc).__name__
        return out
    out["checked"] = True
    try:
        a = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        b = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        out["match"] = (a == b)
    except Exception as exc:  # noqa: BLE001
        out["checked"] = False
        out["error"] = "could not compare the keys (%s)" % type(exc).__name__
    return out


# --------------------------------------------------------------------------- #
#  Chain assembly                                                              #
# --------------------------------------------------------------------------- #
#: Parsed-trust-store cache. The bundle is ~140 certificates and it is read on
#: every analysis that reaches an unknown anchor; re-parsing it per request
#: turned a 3 ms answer into a 400 ms one for no new information.
_TRUST_CACHE: dict[str, set[str]] = {}


def _trust_subjects() -> set[str]:
    """Subject DNs present in this host's CA trust store.

    A NAME index, deliberately: it answers "is the certificate above the last
    presented one a public root this machine already trusts", which is the
    question that separates *the server forgot the intermediate* from *the
    server is correct and only the root is absent, as it should be*. It is not a
    signature check and every caller labels it as a name match.
    """
    subjects: set[str] = set()
    path = ""
    for p in _TRUST_PATHS:
        if os.path.exists(p):
            path = p
            break
    if not path:
        try:
            import certifi
            path = certifi.where()
        except Exception:  # noqa: BLE001
            return subjects
    cached = _TRUST_CACHE.get(path)
    if cached is not None:
        return cached
    try:
        with open(path, "rb") as fh:
            blob = fh.read().decode("utf-8", "replace")
    except OSError:
        return subjects
    import warnings

    from cryptography import x509
    with warnings.catch_warnings():
        # A public trust store legitimately carries certificates whose serial
        # RFC 5280 dislikes. That is a fact about the world, not about the
        # operator's input, and surfacing it in the app log on every analysis
        # trains people to ignore the log.
        warnings.simplefilter("ignore")
        for block in _PEM_RX.finditer(blob):
            try:
                subjects.add(_dn(x509.load_pem_x509_certificate(
                    block.group(0).encode()).subject))
            except Exception:  # noqa: BLE001
                continue
    _TRUST_CACHE[path] = subjects
    return subjects


def order_chain(infos: list[dict]) -> dict:
    """Order a bag of certificates leaf-first and say what is missing.

    Returns ``{'chain': [...], 'extras': [...], 'presented_order_ok': bool}``.
    ``extras`` are certificates that belong to no position in the chain — a
    bundle carrying an unrelated certificate is a real and common mistake, and
    silently dropping it is how it survives.
    """
    usable = [i for i in infos if not i.get("parse_error")]
    if not usable:
        return {"chain": [], "extras": list(infos), "presented_order_ok": True}

    issuers = {i["subject_dn"] for i in usable if i["subject_dn"]}
    # The leaf is the certificate nobody else in the bag was issued BY.
    signed_subjects = {i["issuer_dn"] for i in usable if i["issuer_dn"]}
    leaves = [i for i in usable
              if i["subject_dn"] not in signed_subjects or i["self_signed"] and len(usable) == 1]
    non_ca = [i for i in leaves if not i["is_ca"]]
    leaf = (non_ca or leaves or usable)[0]

    chain = [leaf]
    used = {id(leaf)}
    cur = leaf
    while not cur["self_signed"]:
        nxt = next((i for i in usable
                    if id(i) not in used and i["subject_dn"] == cur["issuer_dn"]), None)
        if nxt is None:
            break
        chain.append(nxt)
        used.add(id(nxt))
        cur = nxt
    extras = [i for i in infos if id(i) not in used]
    presented_order_ok = [id(i) for i in usable[:len(chain)]] == [id(i) for i in chain]
    del issuers
    return {"chain": chain, "extras": extras,
            "presented_order_ok": presented_order_ok}


# --------------------------------------------------------------------------- #
#  Hostname matching (RFC 6125, the parts that matter)                         #
# --------------------------------------------------------------------------- #
def name_matches(pattern: str, host: str) -> bool:
    """Does one SAN/CN *pattern* cover *host*?

    Wildcards match ONE label and only in the leftmost position — ``*.a.com``
    covers ``x.a.com`` and does NOT cover ``a.com`` or ``x.y.a.com``. Operators
    reliably believe otherwise, and that belief is exactly what produces a
    certificate that works in testing and fails on the apex.
    """
    p = str(pattern or "").strip().lower().rstrip(".")
    h = str(host or "").strip().lower().rstrip(".")
    if not p or not h:
        return False
    if p == h:
        return True
    if not p.startswith("*."):
        return False
    suffix = p[1:]                       # ".a.com"
    if not h.endswith(suffix):
        return False
    label = h[: -len(suffix)]
    return bool(label) and "." not in label


def _is_ip_literal(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(str(host or "").strip().strip("[]"))
    except ValueError:
        return False
    return True


def hostname_report(info: dict, host: str) -> dict:
    """Which presented name (if any) covers *host*."""
    out = {"checked": False, "match": None, "matched_name": "",
           "names": [], "source": ""}
    if not host:
        return out
    names = list(info.get("sans") or [])
    source = "SAN"
    if not names and info.get("cn"):
        names = [info["cn"]]
        source = "CN (no SAN present)"
    out.update(checked=True, names=names, source=source)
    for n in names:
        if name_matches(n, host):
            out.update(match=True, matched_name=n)
            return out
    out["match"] = False
    return out


# --------------------------------------------------------------------------- #
#  Live fetch                                                                  #
# --------------------------------------------------------------------------- #
def openssl_available() -> bool:
    return bool(shutil.which("openssl"))


def fetch_chain(ip: str, port: int, *, server_name: str,
                timeout: float = 6.0) -> dict:
    """Pull the certificates a server presents, as a chain when possible.

    Python 3.11's ``ssl`` exposes only the PEER certificate
    (``get_unverified_chain`` landed in 3.13), so the full chain comes from
    ``openssl s_client -showcerts``. When that binary is absent the leaf is
    still read through :func:`cert_probe.probe_leaf_pem` and ``source`` says
    ``leaf`` — the caller MUST NOT report chain completeness from a leaf-only
    read, and :func:`analyse` does not.

    Connects to *ip* and sends *server_name* as SNI: the address was authorised
    by :mod:`app.services.net_guard` and re-resolving the name here would dial
    something the guard never saw.
    """
    out = {"pems": [], "source": "", "error": "", "verify_line": "",
           "protocol": "", "cipher": ""}
    if openssl_available():
        cmd = ["openssl", "s_client", "-showcerts", "-connect",
               "%s:%d" % (_bracket(ip), int(port)), "-servername", server_name]
        try:
            proc = subprocess.run(cmd, input=b"", capture_output=True,
                                  timeout=timeout)
            text = (proc.stdout or b"").decode("utf-8", "replace") + \
                   (proc.stderr or b"").decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            out["error"] = "timed out after %gs" % timeout
            return out
        except Exception as exc:  # noqa: BLE001
            out["error"] = "%s: %s" % (type(exc).__name__, exc)
            return out
        pems = split_pem(text)
        if pems:
            out["pems"] = pems
            out["source"] = "chain"
            m = re.search(r"^\s*Verify return code:.*$", text, re.MULTILINE)
            if m:
                out["verify_line"] = m.group(0).strip()
            # OpenSSL 3.0 with a closed stdin does NOT print the ``SSL-Session``
            # block, so the ``Protocol :``/``Cipher :`` lines everyone greps for
            # are simply absent — measured against 3.0.20, not assumed. The
            # ``New, TLSv1.3, Cipher is …`` summary line is always there, so it
            # is read first and the session block is only the fallback.
            m = re.search(r"^New,\s*([^,]+),\s*Cipher is\s*(\S+)", text, re.MULTILINE)
            if m and m.group(1).strip() != "(NONE)":
                out["protocol"] = m.group(1).strip()
                out["cipher"] = m.group(2).strip()
            else:
                m = re.search(r"^\s*Protocol\s*:\s*(\S+)", text, re.MULTILINE)
                if m:
                    out["protocol"] = m.group(1)
                m = re.search(r"^\s*Cipher\s*:\s*(\S+)", text, re.MULTILINE)
                if m and m.group(1) not in ("0000", "(NONE)"):
                    out["cipher"] = m.group(1)
            return out
        out["error"] = _first_error_line(text) or "no certificate in the handshake"
        return out
    # Fallback: leaf only, and it says so.
    pem, err = cert_probe.probe_leaf_pem(ip, int(port), server_name=server_name,
                                         timeout=timeout)
    if pem:
        out["pems"] = [pem]
        out["source"] = "leaf"
    else:
        out["error"] = err or "no certificate presented"
    return out


def _bracket(ip: str) -> str:
    return "[%s]" % ip if ":" in str(ip) else str(ip)


def _first_error_line(text: str) -> str:
    for ln in (text or "").splitlines():
        s = ln.strip()
        if s.startswith("connect:") or "errno" in s.lower() or "alert" in s.lower():
            return s[:200]
    return ""


# --------------------------------------------------------------------------- #
#  Findings                                                                    #
# --------------------------------------------------------------------------- #
def _f(sev: str, code: str, title: str, detail: str, fix: str = "") -> dict:
    return {"severity": sev, "code": code, "title": title, "detail": detail,
            "fix": fix}


def analyse(pems: list[str], *, hostname: str = "", source: str = "paste",
            key_pem: str = "", key_passphrase: str = "",
            verify_line: str = "") -> dict:
    """Everything this tool has to say about a set of certificates."""
    infos = [cert_info(p) for p in (pems or [])]
    bad = [i for i in infos if i.get("parse_error")]
    ordered = order_chain(infos)
    chain = ordered["chain"]
    findings: list[dict] = []

    for i in bad:
        findings.append(_f("crit", "unparseable", "A block is not a certificate",
                           i["parse_error"],
                           "Check the paste for a truncated or re-wrapped block."))

    # --- links -------------------------------------------------------------
    links = []
    for a, b in zip(chain, chain[1:]):
        ok = verify_signed_by(a["pem"], b["pem"])
        links.append({"child": a["cn"] or a["subject_dn"],
                      "parent": b["cn"] or b["subject_dn"], "verified": ok})
        if ok is False:
            findings.append(_f(
                "crit", "bad_signature", "A chain link does not verify",
                "%s claims to be issued by %s, but that certificate's key does "
                "not verify the signature." % (a["cn"] or a["subject_dn"],
                                               b["cn"] or b["subject_dn"]),
                "One of the two certificates is from a different issuance. "
                "Re-export the fullchain from the CA."))
        elif ok is None:
            findings.append(_f(
                "info", "link_unverified", "A chain link could not be verified",
                "The signature algorithm on %s is one this build cannot check. "
                "The link is neither confirmed nor denied."
                % (a["cn"] or a["subject_dn"]), ""))

    # --- completeness ------------------------------------------------------
    complete = None
    anchor = ""
    if source == "leaf":
        findings.append(_f(
            "info", "chain_unknown", "Chain completeness was not measured",
            "Only the leaf certificate could be read on this host (the "
            "'openssl' binary is not available), so whether the server sends "
            "its intermediates is UNKNOWN — not 'incomplete'.",
            "Install openssl on the SATOM node, or paste the server's "
            "fullchain file into the Paste tab."))
    elif chain:
        top = chain[-1]
        if top["self_signed"]:
            complete = True
            anchor = "self-signed root present in the bundle"
        else:
            trusted = _trust_subjects()
            if top["issuer_dn"] and top["issuer_dn"] in trusted:
                complete = True
                anchor = ("issuer %s found in this host's trust store (name "
                          "match, not a signature check)" % top["issuer_dn"])
            else:
                complete = False
                anchor = "issuer %s is neither presented nor in this host's " \
                         "trust store" % (top["issuer_dn"] or "(unknown)")
                findings.append(_f(
                    "crit", "incomplete_chain", "The chain is incomplete",
                    "The last certificate presented (%s) was issued by %s, and "
                    "that certificate is neither in this bundle nor in this "
                    "host's trust store. Clients that do not already hold it "
                    "will fail with 'unable to get local issuer certificate'."
                    % (top["cn"] or top["subject_dn"], top["issuer_dn"] or "?"),
                    "Serve the FULLCHAIN file (leaf + every intermediate), not "
                    "the leaf certificate alone."))
    if verify_line and "Verify return code: 0" not in verify_line:
        findings.append(_f("info", "openssl_verify", "OpenSSL's own verdict",
                           verify_line,
                           "This is what a default-configured client sees."))

    # --- per-certificate ---------------------------------------------------
    now = datetime.utcnow()
    for idx, i in enumerate(chain):
        who = i["cn"] or i["subject_dn"] or "certificate %d" % (idx + 1)
        na, nb = i.get("not_after"), i.get("not_before")
        if na is not None:
            days = (na - now).days
            if days < 0:
                findings.append(_f("crit", "expired", "%s has EXPIRED" % who,
                                   "Valid until %s — %d days ago."
                                   % (na.strftime("%Y-%m-%d"), -days),
                                   "Renew and redeploy; clients are already failing."))
            elif days <= EXPIRY_CRIT_DAYS:
                findings.append(_f("crit", "expiring", "%s expires in %d days"
                                   % (who, days), "Valid until %s."
                                   % na.strftime("%Y-%m-%d"), "Renew now."))
            elif days <= EXPIRY_WARN_DAYS:
                findings.append(_f("warn", "expiring", "%s expires in %d days"
                                   % (who, days), "Valid until %s."
                                   % na.strftime("%Y-%m-%d"), "Schedule the renewal."))
        if nb is not None and nb > now:
            findings.append(_f("crit", "not_yet_valid", "%s is not valid yet" % who,
                               "Not valid before %s." % nb.strftime("%Y-%m-%d %H:%M"),
                               "Check the clock on the issuing system."))
        if i["key_bits"] and i["key_type"].upper().startswith("RSA") \
                and i["key_bits"] < MIN_RSA_BITS:
            findings.append(_f("warn", "weak_key", "%s has a %d-bit RSA key"
                               % (who, i["key_bits"]),
                               "Below the %d-bit floor browsers enforce."
                               % MIN_RSA_BITS, "Reissue with a 2048-bit or "
                               "larger key, or an EC key."))
        if (i["sig_algo"] or "").lower() in WEAK_HASHES:
            findings.append(_f("warn", "weak_signature",
                               "%s is signed with %s" % (who, i["sig_algo"]),
                               "This hash is not accepted for certificate "
                               "signatures by current clients.", "Reissue."))

    leaf = chain[0] if chain else None
    if leaf is not None and leaf["self_signed"] and len(chain) == 1:
        findings.append(_f(
            "warn", "self_signed", "The leaf is self-signed",
            "Nothing vouches for %s but itself. Browsers and API clients reject "
            "it unless the certificate is installed as a trust anchor."
            % (leaf["cn"] or leaf["subject_dn"]),
            "Expected on an appliance's factory GUI certificate; NOT expected "
            "on a published service."))
    if leaf is not None and leaf["is_ca"]:
        findings.append(_f("info", "leaf_is_ca", "The leaf carries the CA flag",
                           "basicConstraints says CA:TRUE on the end-entity "
                           "certificate.", ""))

    if chain and chain[-1]["self_signed"] and len(chain) > 1:
        findings.append(_f(
            "info", "root_included", "The root is included in the bundle",
            "Harmless, but it is bytes sent on every handshake that no client "
            "needs — a client that does not already trust the root will not "
            "start trusting it because the server sent it.",
            "Serving leaf + intermediates only is the usual choice."))

    if ordered["extras"]:
        findings.append(_f(
            "warn", "extra_certificates",
            "%d certificate(s) belong to no position in this chain"
            % len(ordered["extras"]),
            "Present in the bundle, not reachable from the leaf: %s"
            % ", ".join(x["cn"] or x["subject_dn"] or "?"
                        for x in ordered["extras"]),
            "Remove them, or check whether the wrong leaf was pasted."))
    if chain and not ordered["presented_order_ok"]:
        findings.append(_f(
            "warn", "out_of_order",
            "The certificates are not in leaf-first order",
            "TLS requires the end-entity certificate first, each following "
            "certificate certifying the one before it. Some clients tolerate "
            "any order; others do not, which is how this reproduces on one "
            "client and not another.",
            "Reorder the file leaf → intermediate(s) → (root)."))

    host_rep = hostname_report(leaf, hostname) if leaf else \
        {"checked": False, "match": None, "matched_name": "", "names": [],
         "source": ""}
    if host_rep.get("checked") and host_rep.get("match") is False:
        if _is_ip_literal(hostname):
            # Probing an appliance BY ADDRESS is the normal inventory path, and
            # management certificates carry names, not IP SANs. Reporting that
            # as critical would paint every device in the fleet red on arrival —
            # and an alarm that is always on is not an alarm any more.
            findings.append(_f(
                "info", "hostname_is_ip",
                "Probed by address, so no name could match",
                "The certificate presents %s. A client that connects to %s "
                "rather than to one of those names fails hostname verification; "
                "for a management GUI reached by address that is expected."
                % (", ".join(host_rep["names"]) or "(no names)", hostname),
                "To check the name a real client uses, re-probe with that "
                "hostname as the SNI."))
        else:
            findings.append(_f(
                "crit", "hostname_mismatch", "No presented name covers %s" % hostname,
                "The certificate presents: %s" % (", ".join(host_rep["names"]) or "(none)"),
                "Reissue with %s in the SAN list. Remember a wildcard covers one "
                "label and not the apex." % hostname))

    key_rep = key_matches_cert(leaf["pem"], key_pem, key_passphrase) if \
        (leaf and key_pem) else {"checked": False, "match": None, "error": ""}
    if key_rep.get("checked") and key_rep.get("match") is False:
        findings.append(_f(
            "crit", "key_mismatch", "The private key does not match this certificate",
            "The key's public half differs from the certificate's. A server "
            "configured with this pair starts normally and fails EVERY "
            "handshake.",
            "The two files are from different issuances — take both from the "
            "same one."))
    elif key_rep.get("error"):
        findings.append(_f("info", "key_unchecked", "The private key was not checked",
                           key_rep["error"], ""))

    order = {"crit": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 3))
    return {
        "certificates": [_public(i) for i in chain],
        "extras": [_public(i) for i in ordered["extras"]],
        "links": links,
        "chain_source": source,
        "chain_complete": complete,
        "chain_anchor": anchor,
        "hostname": host_rep,
        "private_key": key_rep,
        "findings": findings,
        "verdict": ("crit" if any(f["severity"] == "crit" for f in findings)
                    else "warn" if any(f["severity"] == "warn" for f in findings)
                    else "ok"),
        "count": len(chain),
    }


def _public(i: dict) -> dict:
    """Certificate detail as the browser sees it — WITHOUT the PEM body.

    The PEM is input, not output. Echoing it back grows every response by a few
    kB per certificate for a value the caller already has, and for a probe it
    would hand the browser material it never asked for."""
    out = {k: v for k, v in i.items() if k != "pem"}
    for k in ("not_before", "not_after"):
        if isinstance(out.get(k), datetime):
            out[k] = out[k].strftime("%Y-%m-%d %H:%M:%S")
    return out


__all__ = [
    "EXPIRY_WARN_DAYS", "EXPIRY_CRIT_DAYS", "MIN_RSA_BITS", "MAX_BUNDLE",
    "split_pem", "cert_info", "verify_signed_by", "key_matches_cert",
    "order_chain", "name_matches", "hostname_report", "openssl_available",
    "fetch_chain", "analyse",
]
