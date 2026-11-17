"""Service probes: does the SERVICE behind a port really work?

A port can be open while the service behind it is dead: a web server that
answers 502, an SSL VPN portal whose daemon crashed behind a listening
socket, an IKE port held by a hung process. Every probe here therefore speaks
the service's own protocol and judges the ANSWER, never just the connect.

This module is the pure protocol layer. It stores nothing, schedules nothing
and imports nothing from the Flask app. The caller hands it a kind and a
target dict and gets one :class:`ProbeResult` back.

STATUS VOCABULARY (the same for every kind)
    up        the service answered correctly
    degraded  it answered, but a soft condition fails (a certificate that
              expires within ``cert_warn_days``, or one that does not verify
              while the target says ``verify_tls: False``)
    down      no answer, refused, timed out, the wrong protocol answered, or
              an expectation failed (HTTP status, keyword, expired
              certificate, verification failure with ``verify_tls: True``)
    error     OUR side: an invalid target, or the destination guard refused

THE DESTINATION GUARD
    ``guard(host, port)`` is called before EVERY socket this module opens,
    including every HTTP redirect hop and every certificate-verification
    re-connect. A guard that raises turns the result into ``error`` with the
    guard's message, and nothing is dialled.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import os
import re
import socket
import ssl
import struct
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

__all__ = [
    "CERT_KINDS",
    "KINDS",
    "KIND_LABEL",
    "ProbeResult",
    "run",
    "validate_target",
    "wireguard_keypair",
]


# --------------------------------------------------------------------------- #
#  Public surface                                                              #
# --------------------------------------------------------------------------- #

@dataclass
class ProbeResult:
    """What one probe found. ``detail`` and ``cert`` are JSON-serialisable."""

    status: str            # "up" | "degraded" | "down" | "error"
    latency_ms: float | None
    summary: str
    detail: dict = field(default_factory=dict)
    cert: dict | None = None

    def as_dict(self) -> dict:
        return asdict(self)


KINDS: tuple[str, ...] = ("http", "https", "tls", "tcp", "dns", "ssh", "smtp",
                          "sslvpn", "openvpn", "ipsec", "wireguard")

KIND_LABEL: dict[str, str] = {
    "http": "HTTP website",
    "https": "HTTPS website + certificate",
    "tls": "TLS handshake + certificate",
    "tcp": "TCP port",
    "dns": "DNS query",
    "ssh": "SSH server",
    "smtp": "SMTP server (+ STARTTLS)",
    "sslvpn": "SSL VPN portal",
    "openvpn": "OpenVPN server",
    "ipsec": "IPsec (IKE responder)",
    "wireguard": "WireGuard handshake",
}

CERT_KINDS: frozenset[str] = frozenset({"https", "tls", "smtp", "sslvpn", "openvpn"})

_STATUS_RANK = {"up": 0, "degraded": 1, "down": 2, "error": 3}
_USER_AGENT = "SATOM-service-probe/1.0"
_MAX_REDIRECTS = 5
_BODY_LIMIT = 1024 * 1024          # keyword search window (1 MiB)
_BANNER_LIMIT = 512                # tcp expect_banner window
_BANNER_WINDOW_S = 2.0
_TIMEOUT_MAX_S = 120.0


# --------------------------------------------------------------------------- #
#  Internal control flow                                                       #
# --------------------------------------------------------------------------- #

class _Refused(Exception):
    """The destination guard refused a (host, port). Never an OSError, so the
    network-error handlers can never swallow it into a 'down'."""


class _Down(Exception):
    """Short-circuit to a ``down`` result with an operator-readable reason."""

    def __init__(self, summary: str, detail: dict | None = None,
                 cert: dict | None = None, latency_ms: float | None = None):
        super().__init__(summary)
        self.summary = summary
        self.detail = detail or {}
        self.cert = cert
        self.latency_ms = latency_ms


class _Deadline:
    """One overall time budget shared by every step of a probe."""

    def __init__(self, seconds: float):
        self.seconds = seconds
        self.end = time.monotonic() + seconds

    def left(self) -> float:
        return max(0.0, self.end - time.monotonic())

    def remaining(self) -> float:
        """Seconds left; raises ``TimeoutError`` once the budget is spent."""
        left = self.end - time.monotonic()
        if left <= 0:
            raise TimeoutError("timed out")
        return left


def _ms(seconds: float) -> float:
    return round(seconds * 1000.0, 1)


def _worst(*statuses: str) -> str:
    return max(statuses, key=lambda s: _STATUS_RANK.get(s, 3))


def _guarded(guard, host: str, port: int) -> None:
    if guard is None:
        return
    try:
        guard(host, port)
    except Exception as exc:  # noqa: BLE001 -- any refusal, whatever its type
        raise _Refused(str(exc) or exc.__class__.__name__) from exc


def _open_tcp(host: str, port: int, deadline: _Deadline, guard) -> socket.socket:
    _guarded(guard, host, port)
    sock = socket.create_connection((host, port), timeout=deadline.remaining())
    sock.settimeout(deadline.remaining())
    return sock


def _open_udp(host: str, port: int, deadline: _Deadline, guard) -> socket.socket:
    _guarded(guard, host, port)
    family, stype, proto, _, addr = socket.getaddrinfo(
        host, port, 0, socket.SOCK_DGRAM)[0]
    sock = socket.socket(family, stype, proto)
    try:
        sock.settimeout(deadline.remaining())
        # A CONNECTED UDP socket turns an ICMP port-unreachable into
        # ConnectionRefusedError on recv(): "nothing listens" becomes a fast,
        # explicit answer instead of a full timeout.
        sock.connect(addr)
    except BaseException:
        sock.close()
        raise
    return sock


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _sni(name: str | None) -> str | None:
    """SNI carries host NAMES only (RFC 6066 §3): an IP literal is not sent."""
    if not name or _is_ip(name):
        return None
    return name


def _printable(data: bytes, limit: int = 512) -> str:
    text = data[:limit].decode("latin-1")
    return "".join(ch if 32 <= ord(ch) < 127 or ch in "\r\n\t" else "\\x%02x" % ord(ch)
                   for ch in text)


# --------------------------------------------------------------------------- #
#  Target validation                                                           #
# --------------------------------------------------------------------------- #

_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")
_RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
_SSLVPN_PATHS = {
    "fortinet": "/remote/login",
    "cisco": "/+CSCOE+/logon.html",
    "paloalto": "/global-protect/login.esp",
    "pulse": "/dana-na/auth/url_default/welcome.cgi",
    "generic": "/",
}
_OVPN_DIGESTS = {"MD5": "md5", "SHA1": "sha1", "SHA224": "sha224", "SHA256": "sha256",
                 "SHA384": "sha384", "SHA512": "sha512"}
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off", ""}


def _valid_hostname(name: str) -> bool:
    name = name[:-1] if name.endswith(".") else name
    if not name or len(name) > 253:
        return False
    return all(_LABEL_RE.match(label) for label in name.split("."))


def _v_host(value, field_name: str = "host") -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is required (a hostname or an IP address)")
    host = value.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if _is_ip(host):
        return host
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = ""
    if not _valid_hostname(ascii_host):
        raise ValueError(f"{field_name} {value!r} is not a valid hostname or IP address")
    return ascii_host


def _v_port(value, default: int | None, field_name: str = "port") -> int:
    if value is None or value == "":
        if default is None:
            raise ValueError(f"{field_name} is required (1-65535)")
        return default
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a number between 1 and 65535")
    try:
        port = int(str(value).strip())
    except ValueError:
        raise ValueError(f"{field_name} must be a number between 1 and 65535") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"{field_name} must be between 1 and 65535, got {port}")
    return port


def _v_bool(value, default: bool, field_name: str) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ValueError(f"{field_name} must be true or false")


def _v_timeout(value) -> float | None:
    if value is None or value == "":
        return None
    try:
        secs = float(value)
    except (TypeError, ValueError):
        raise ValueError("timeout must be a number of seconds") from None
    if not 0 < secs <= _TIMEOUT_MAX_S:
        raise ValueError(f"timeout must be between 0 and {_TIMEOUT_MAX_S:g} seconds")
    return secs


def _parse_expect_status(spec: str) -> list[tuple[int, int]]:
    """``"200-399"``, ``"200,301"`` or a mix (``"200-299,301"``)."""
    ranges = []
    for part in str(spec).replace(" ", "").split(","):
        if not part:
            continue
        match = re.fullmatch(r"(\d{3})(?:-(\d{3}))?", part)
        if not match:
            raise ValueError(f"expect_status {spec!r}: use a range like 200-399 "
                             "or a list like 200,301")
        low = int(match.group(1))
        high = int(match.group(2) or low)
        if not (100 <= low <= 599 and 100 <= high <= 599 and low <= high):
            raise ValueError(f"expect_status {spec!r}: codes must be 100-599, low to high")
        ranges.append((low, high))
    if not ranges:
        raise ValueError("expect_status is empty")
    return ranges


def _status_expected(code: int, spec: str) -> bool:
    return any(low <= code <= high for low, high in _parse_expect_status(spec))


def _parse_static_key(text: str, field_name: str) -> bytes:
    """An OpenVPN ``Static key V1`` file: 2048 bits as 16 lines of hex."""
    if not isinstance(text, str):
        raise ValueError(f"{field_name} must be the text of an OpenVPN static key file")
    match = re.search(r"-----BEGIN OpenVPN Static key V1-----(.*?)"
                      r"-----END OpenVPN Static key V1-----", text, re.S)
    body = match.group(1) if match else text
    hexdigits = "".join(line.strip() for line in body.splitlines()
                        if line.strip() and not line.strip().startswith("#"))
    try:
        key = binascii.unhexlify(hexdigits)
    except (binascii.Error, ValueError):
        raise ValueError(f"{field_name} is not a valid OpenVPN static key "
                         "(expected the hex block of an 'OpenVPN Static key V1' file)") from None
    if len(key) != 256:
        raise ValueError(f"{field_name} must hold 2048 bits (256 bytes), got {len(key)} bytes")
    return key


def _parse_b64_key(value, field_name: str) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is required (base64, 32 bytes)")
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"{field_name} is not valid base64") from None
    if len(raw) != 32:
        raise ValueError(f"{field_name} must decode to 32 bytes, got {len(raw)}")
    return raw


def _v_dns_name(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("name (the DNS name to query) is required")
    name = value.strip()
    try:
        ascii_name = name.encode("idna").decode("ascii") if name != "." else "."
    except UnicodeError:
        raise ValueError(f"name {value!r} is not a valid DNS name") from None
    if ascii_name != "." and not _valid_hostname(ascii_name):
        raise ValueError(f"name {value!r} is not a valid DNS name")
    return ascii_name


def validate_target(kind: str, target: dict) -> dict:
    """Return a normalised copy of ``target`` for ``kind``.

    Raises ``ValueError`` with an English message on bad input. Keys this
    module does not know are dropped from the copy.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown probe kind {kind!r}; expected one of: {', '.join(KINDS)}")
    if not isinstance(target, dict):
        raise ValueError("target must be a JSON object")
    t = target
    out: dict = {}
    timeout = _v_timeout(t.get("timeout"))
    if timeout is not None:
        out["timeout"] = timeout

    if kind in ("http", "https"):
        url = t.get("url")
        if not isinstance(url, str) or not url.strip():
            raise ValueError("url is required")
        url = url.strip()
        if "://" not in url:
            url = f"{kind}://{url}"
        parts = urlsplit(url)
        if parts.scheme.lower() != kind:
            raise ValueError(f"a {parts.scheme}:// URL needs probe kind {parts.scheme!r}, "
                             f"not {kind!r}")
        if not parts.hostname:
            raise ValueError(f"url {url!r} has no host")
        _v_host(parts.hostname)
        try:
            parts.port
        except ValueError:
            raise ValueError(f"url {url!r} has an invalid port") from None
        method = str(t.get("method") or "GET").strip().upper()
        if method not in ("GET", "HEAD"):
            raise ValueError("method must be GET or HEAD")
        expect = str(t.get("expect_status") or "200-399").strip()
        _parse_expect_status(expect)
        out.update(url=url, method=method, expect_status=expect,
                   verify_tls=_v_bool(t.get("verify_tls"), True, "verify_tls"))
        keyword = t.get("keyword")
        if keyword not in (None, ""):
            if not isinstance(keyword, str) or len(keyword) > 1024:
                raise ValueError("keyword must be text of at most 1024 characters")
            if method == "HEAD":
                raise ValueError("keyword needs method GET (HEAD returns no body)")
            out["keyword"] = keyword
        return out

    out["host"] = _v_host(t.get("host"))

    if kind == "tls":
        out["port"] = _v_port(t.get("port"), 443)
        sni = t.get("sni")
        if sni not in (None, ""):
            out["sni"] = _v_host(sni, "sni")
        out["verify_tls"] = _v_bool(t.get("verify_tls"), True, "verify_tls")
    elif kind == "tcp":
        out["port"] = _v_port(t.get("port"), None)
        banner = t.get("expect_banner")
        if banner not in (None, ""):
            if not isinstance(banner, str) or len(banner) > 512:
                raise ValueError("expect_banner must be a regular expression of at most 512 characters")
            try:
                re.compile(banner)
            except re.error as exc:
                raise ValueError(f"expect_banner is not a valid regular expression: {exc}") from None
            out["expect_banner"] = banner
    elif kind == "dns":
        out["port"] = _v_port(t.get("port"), 53)
        out["name"] = _v_dns_name(t.get("name"))
        rtype = str(t.get("rtype") or "A").strip().upper()
        if rtype not in _RTYPES:
            raise ValueError(f"rtype must be one of {', '.join(_RTYPES)}")
        out["rtype"] = rtype
        expect = t.get("expect")
        if expect not in (None, ""):
            out["expect"] = str(expect)
    elif kind == "ssh":
        out["port"] = _v_port(t.get("port"), 22)
    elif kind == "smtp":
        out["port"] = _v_port(t.get("port"), 25)
        out["starttls"] = _v_bool(t.get("starttls"), True, "starttls")
        out["verify_tls"] = _v_bool(t.get("verify_tls"), True, "verify_tls")
    elif kind == "sslvpn":
        out["port"] = _v_port(t.get("port"), 443)
        vendor = str(t.get("vendor") or "fortinet").strip().lower()
        if vendor not in _SSLVPN_PATHS:
            raise ValueError(f"vendor must be one of {', '.join(_SSLVPN_PATHS)}")
        out["vendor"] = vendor
        out["verify_tls"] = _v_bool(t.get("verify_tls"), True, "verify_tls")
    elif kind == "openvpn":
        out["port"] = _v_port(t.get("port"), 1194)
        proto = str(t.get("proto") or "udp").strip().lower()
        if proto not in ("udp", "tcp"):
            raise ValueError("proto must be udp or tcp")
        out["proto"] = proto
        auth_key = t.get("tls_auth_key")
        crypt_key = t.get("tls_crypt_key")
        if auth_key and crypt_key:
            raise ValueError("give tls_auth_key OR tls_crypt_key, not both "
                             "(an OpenVPN server uses one or the other)")
        if auth_key:
            _parse_static_key(auth_key, "tls_auth_key")
            out["tls_auth_key"] = auth_key
        if crypt_key:
            _parse_static_key(crypt_key, "tls_crypt_key")
            out["tls_crypt_key"] = crypt_key
        direction = t.get("key_direction")
        if direction in (None, "", "none", "None", "bidirectional"):
            out["key_direction"] = None
        else:
            try:
                direction = int(str(direction).strip())
            except ValueError:
                raise ValueError("key_direction must be 0, 1 or empty") from None
            if direction not in (0, 1):
                raise ValueError("key_direction must be 0, 1 or empty")
            out["key_direction"] = direction
        digest = str(t.get("auth_digest") or "SHA1").strip().upper().replace("-", "")
        if digest not in _OVPN_DIGESTS:
            raise ValueError(f"auth_digest must be one of {', '.join(_OVPN_DIGESTS)}")
        out["auth_digest"] = digest
        out["verify_tls"] = _v_bool(t.get("verify_tls"), False, "verify_tls")
    elif kind == "ipsec":
        nat_t = _v_bool(t.get("nat_t"), False, "nat_t")
        out["nat_t"] = nat_t
        out["port"] = _v_port(t.get("port"), 4500 if nat_t else 500)
        version = t.get("ike_version")
        try:
            version = 2 if version in (None, "") else int(str(version).strip())
        except ValueError:
            raise ValueError("ike_version must be 1 or 2") from None
        if version not in (1, 2):
            raise ValueError("ike_version must be 1 or 2")
        out["ike_version"] = version
    elif kind == "wireguard":
        out["port"] = _v_port(t.get("port"), 51820)
        _parse_b64_key(t.get("server_public_key"), "server_public_key")
        _parse_b64_key(t.get("client_private_key"), "client_private_key")
        out["server_public_key"] = t["server_public_key"].strip()
        out["client_private_key"] = t["client_private_key"].strip()
        psk = t.get("preshared_key")
        if psk not in (None, ""):
            _parse_b64_key(psk, "preshared_key")
            out["preshared_key"] = psk.strip()
    return out


# --------------------------------------------------------------------------- #
#  Certificates                                                                #
# --------------------------------------------------------------------------- #

def _empty_cert(error: str) -> dict:
    return {"subject": None, "issuer": None, "not_before": None, "not_after": None,
            "days_left": None, "sans": [], "sha256": None, "self_signed": None,
            "chain_ok": None, "hostname_ok": None, "error": error}


def _dns_name_matches(pattern: str, name: str) -> bool:
    """RFC 6125 §6.4.3, as OpenSSL applies it with NO_PARTIAL_WILDCARDS:
    a wildcard is the whole LEFT-MOST label and never spans a dot."""
    pattern = pattern.lower().rstrip(".")
    name = name.lower().rstrip(".")
    if "*" not in pattern:
        return pattern == name
    p_labels = pattern.split(".")
    n_labels = name.split(".")
    if p_labels[0] != "*" or "*" in ".".join(p_labels[1:]) or len(p_labels) < 3:
        return False
    return len(n_labels) == len(p_labels) and bool(n_labels[0]) and \
        n_labels[1:] == p_labels[1:]


def _hostname_ok(cert: x509.Certificate, name: str | None) -> bool | None:
    if not name:
        return None
    dns_names: list[str] = []
    ip_names: list = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = san.get_values_for_type(x509.DNSName)
        ip_names = san.get_values_for_type(x509.IPAddress)
    except x509.ExtensionNotFound:
        pass
    if _is_ip(name):
        return ipaddress.ip_address(name) in ip_names
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    if not dns_names:
        # Legacy fallback OpenSSL still honours: CN only when no DNS SAN exists.
        dns_names = [attr.value for attr in
                     cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                     if isinstance(attr.value, str)]
    return any(_dns_name_matches(pattern, name) for pattern in dns_names)


def _cert_facts(der: bytes, match_name: str | None) -> dict:
    """Facts from a DER certificate, read WITHOUT trusting it."""
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        return _empty_cert(f"certificate could not be parsed: {exc}")
    now = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    sans: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = [str(v) for v in san.get_values_for_type(x509.DNSName)]
        sans += [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    except ValueError:
        pass
    self_signed = cert.subject == cert.issuer
    if self_signed:
        try:
            cert.verify_directly_issued_by(cert)
        except (ValueError, TypeError, InvalidSignature):
            self_signed = False
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        # Whole days, floored: a certificate expiring in 10 hours has 0 days
        # left and one that expired an hour ago has -1.
        "days_left": (not_after - now).days,
        "sans": sans,
        "sha256": hashlib.sha256(der).hexdigest(),
        "self_signed": self_signed,
        "chain_ok": None,
        "hostname_ok": _hostname_ok(cert, match_name),
        "error": None,
    }


def _judge_cert(cert: dict | None, verify_tls: bool, warn_days: int,
                unreadable_counts: bool = True) -> tuple[str, list[str]]:
    """Apply the status rules to a certificate. Returns (status, reasons)."""
    if cert is None:
        return "up", []
    if cert.get("not_after") is None:
        if not unreadable_counts:
            return "up", []
        return ("down" if verify_tls else "degraded"), [
            f"certificate unreadable: {cert.get('error') or 'unknown error'}"]
    now = datetime.now(timezone.utc)
    if datetime.fromisoformat(cert["not_after"]) <= now:
        return "down", [f"certificate EXPIRED on {cert['not_after'][:10]}"]
    if datetime.fromisoformat(cert["not_before"]) > now:
        return "down", [f"certificate not valid before {cert['not_before'][:10]}"]
    status, reasons = "up", []
    problems = []
    if cert.get("chain_ok") is False:
        problems.append("certificate chain does not verify"
                        + (f" ({cert['error']})" if cert.get("error") else ""))
    if cert.get("hostname_ok") is False:
        problems.append("certificate does not match the host name")
    if problems:
        status = "down" if verify_tls else "degraded"
        reasons += problems
    if cert["days_left"] <= warn_days:
        status = _worst(status, "degraded")
        reasons.append(f"certificate expires in {cert['days_left']} days")
    return status, reasons


def _lenient_context(max_tls12: bool = False) -> ssl.SSLContext:
    """A context that reads the facts from ANY server, even a broken or legacy
    one: no verification, old protocol versions and weak ciphers allowed.
    Trust is judged separately by :func:`_verification_context`."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (ValueError, ssl.SSLError):
        pass
    if max_tls12:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers("ALL:!aNULL:!eNULL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


def _verification_context() -> ssl.SSLContext:
    """The trust judgement: the platform's default CA store and policy.

    Hostname checking is OFF here on purpose and done by :func:`_hostname_ok`
    against the parsed SANs (RFC 6125 §6.4). OpenSSL stops at the FIRST
    failure, so a combined check cannot tell "untrusted chain" from "wrong
    name", and the operator needs both facts to fix the right thing.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    return ctx


def _tls_verify(open_plain, server_name: str | None) -> tuple[bool | None, str | None]:
    """A SEPARATE handshake with the verifying context. (chain_ok, error)."""
    try:
        sock = open_plain()
    except (OSError, _Down) as exc:
        return None, f"verification attempt could not connect: {exc}"
    try:
        with _verification_context().wrap_socket(sock, server_hostname=_sni(server_name)):
            return True, None
    except ssl.SSLCertVerificationError as exc:
        return False, exc.verify_message or str(exc)
    except (OSError, ValueError) as exc:
        return None, f"verification handshake failed: {exc}"
    finally:
        sock.close()


def _tls_read(sock: socket.socket, server_name: str | None):
    """Handshake with the lenient context. Returns (ssl_socket, der, version, cipher)."""
    tls = _lenient_context().wrap_socket(sock, server_hostname=_sni(server_name))
    der = tls.getpeercert(binary_form=True)
    return tls, der, tls.version(), tls.cipher()


def _cert_for(der: bytes | None, match_name: str | None, chain: tuple) -> dict:
    if not der:
        return _empty_cert("the server presented no certificate")
    cert = _cert_facts(der, match_name)
    chain_ok, error = chain
    cert["chain_ok"] = chain_ok
    if error and cert.get("error") is None:
        cert["error"] = error
    return cert


def _tls_with_cert(host: str, port: int, server_name: str | None, deadline: _Deadline,
                   guard, pre=None) -> dict:
    """Read the certificate (lenient), then verify it in a second handshake.

    ``pre(sock, deadline)`` runs a cleartext dialogue first (SMTP STARTTLS).
    Returns a dict with cert, tls_version, cipher, handshake_ms, pre_info.
    """
    sock = _open_tcp(host, port, deadline, guard)
    started = time.monotonic()
    try:
        pre_info = pre(sock, deadline) if pre else None
        sock.settimeout(deadline.remaining())
        try:
            tls, der, version, cipher = _tls_read(sock, server_name)
        except ssl.SSLError as exc:
            raise _Down(f"TLS handshake failed: {exc.reason or exc}",
                        {"pre": pre_info} if pre_info else None) from exc
        handshake_ms = _ms(time.monotonic() - started)
        tls.close()
    finally:
        sock.close()

    def open_plain():
        plain = _open_tcp(host, port, deadline, guard)
        if pre:
            try:
                pre(plain, deadline)
            except BaseException:
                plain.close()
                raise
        plain.settimeout(deadline.remaining())
        return plain

    chain = _tls_verify(open_plain, server_name)
    return {
        "cert": _cert_for(der, server_name or host, chain),
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
        "cipher_bits": cipher[2] if cipher else None,
        "handshake_ms": handshake_ms,
        "pre": pre_info,
    }


# --------------------------------------------------------------------------- #
#  HTTP / HTTPS                                                                #
# --------------------------------------------------------------------------- #

def _http_fetch(url: str, method: str, deadline: _Deadline, guard,
                read_body: bool = True) -> dict:
    """GET/HEAD ``url`` following at most five redirects BY HAND, guarding
    every hop before its socket exists. Certificates are NOT checked here
    (verify=False): the certificate is judged by its own handshake, so a bad
    certificate is reported as a certificate problem, not as "site down"."""
    redirects: list[dict] = []
    started = time.monotonic()
    with httpx.Client(verify=False, follow_redirects=False, trust_env=False,
                      headers={"User-Agent": _USER_AGENT}) as client:
        for _hop in range(_MAX_REDIRECTS + 1):
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise _Down(f"redirect to unsupported URL {url!r}",
                            {"redirects": redirects})
            port = parts.port or (443 if parts.scheme == "https" else 80)
            _guarded(guard, parts.hostname, port)
            try:
                with client.stream(method, url,
                                   timeout=httpx.Timeout(deadline.remaining())) as resp:
                    location = resp.headers.get("location")
                    if resp.status_code in (301, 302, 303, 307, 308) and location:
                        nxt = urljoin(url, location)
                        redirects.append({"status": resp.status_code, "location": nxt})
                        # RFC 9110 §15.4.4: a 303 answer is fetched with GET.
                        if resp.status_code == 303 and method != "HEAD":
                            method = "GET"
                        url = nxt
                        continue
                    body = b""
                    complete = True
                    if read_body and method != "HEAD":
                        chunks = []
                        size = 0
                        for chunk in resp.iter_bytes():
                            chunks.append(chunk)
                            size += len(chunk)
                            if size >= _BODY_LIMIT:
                                complete = False
                                break
                        body = b"".join(chunks)[:_BODY_LIMIT]
                    return {
                        "status": resp.status_code,
                        "reason": resp.reason_phrase,
                        "final_url": url,
                        "redirects": redirects,
                        "headers": resp.headers,
                        "body": body,
                        "body_complete": complete,
                        "encoding": resp.encoding,
                        "elapsed_ms": _ms(time.monotonic() - started),
                    }
            except httpx.TimeoutException:
                raise _Down(f"no HTTP answer from {parts.hostname}:{port} within "
                            f"{deadline.seconds:g} s", {"redirects": redirects}) from None
            except httpx.ConnectError as exc:
                raise _Down(f"cannot connect to {parts.hostname}:{port}: {exc}",
                            {"redirects": redirects}) from None
            except httpx.HTTPError as exc:
                raise _Down(f"HTTP exchange with {parts.hostname}:{port} failed: {exc}",
                            {"redirects": redirects}) from None
    raise _Down(f"too many redirects (more than {_MAX_REDIRECTS})",
                {"redirects": redirects, "final_url": url})


def _body_text(fetched: dict) -> str:
    encoding = fetched.get("encoding") or "utf-8"
    try:
        return fetched["body"].decode(encoding, errors="replace")
    except LookupError:
        return fetched["body"].decode("utf-8", errors="replace")


def _probe_http(kind: str, t: dict, deadline: _Deadline, guard, warn_days: int) -> ProbeResult:
    fetched = _http_fetch(t["url"], t["method"], deadline, guard,
                          read_body="keyword" in t)
    headers = fetched["headers"]
    clen = headers.get("content-length")
    detail = {
        "http_status": fetched["status"],
        "final_url": fetched["final_url"],
        "redirects": fetched["redirects"],
        "latency_ms": fetched["elapsed_ms"],
        "server": headers.get("server"),
        "content_length": int(clen) if clen and clen.isdigit() else None,
        "method": t["method"],
        "expect_status": t["expect_status"],
    }
    status, reasons = "up", []
    code = fetched["status"]
    if not _status_expected(code, t["expect_status"]):
        status = "down"
        reasons.append(f"HTTP {code} is not in the expected {t['expect_status']}")
    if "keyword" in t:
        found = t["keyword"] in _body_text(fetched)
        detail["keyword_found"] = found
        if not found:
            status = "down"
            reasons.append(f"keyword {t['keyword']!r} not found in the first "
                           f"{_BODY_LIMIT // 1024} KiB of the body")

    cert = None
    if kind == "https":
        final = urlsplit(fetched["final_url"])
        if final.scheme == "https":
            host = final.hostname
            port = final.port or 443
            tls = _tls_with_cert(host, port, host, deadline, guard)
            cert = tls["cert"]
            detail["tls_version"] = tls["tls_version"]
            detail["cipher"] = tls["cipher"]
            cert_status, cert_reasons = _judge_cert(cert, t["verify_tls"], warn_days)
            status = _worst(status, cert_status)
            reasons += cert_reasons
        else:
            detail["cert_note"] = "the final URL is plain http, so there is no certificate"
            status = _worst(status, "degraded")
            reasons.append("HTTPS redirected to plain http")

    hops = len(fetched["redirects"])
    head = f"HTTP {code} {fetched['reason'] or ''}".rstrip()
    head += f" in {fetched['elapsed_ms']:g} ms"
    if hops:
        head += f" after {hops} redirect{'s' if hops != 1 else ''}"
    summary = head + (": " + "; ".join(reasons) if reasons else "")
    return ProbeResult(status, fetched["elapsed_ms"], summary, detail, cert)


# --------------------------------------------------------------------------- #
#  TLS / TCP / SSH                                                             #
# --------------------------------------------------------------------------- #

def _probe_tls(t: dict, deadline: _Deadline, guard, warn_days: int) -> ProbeResult:
    name = t.get("sni") or t["host"]
    tls = _tls_with_cert(t["host"], t["port"], name, deadline, guard)
    cert = tls["cert"]
    status, reasons = _judge_cert(cert, t["verify_tls"], warn_days)
    detail = {"tls_version": tls["tls_version"], "cipher": tls["cipher"],
              "cipher_bits": tls["cipher_bits"], "sni": _sni(name)}
    summary = (f"TLS handshake OK ({tls['tls_version']}, {tls['cipher']}) in "
               f"{tls['handshake_ms']:g} ms")
    if cert.get("days_left") is not None:
        summary += f", certificate valid {cert['days_left']} more days"
    if reasons:
        summary += ": " + "; ".join(reasons)
    return ProbeResult(status, tls["handshake_ms"], summary, detail, cert)


def _read_some(sock: socket.socket, window: float, limit: int,
               done=lambda data: False) -> bytes:
    """Read up to ``limit`` bytes within ``window`` seconds, stopping early on
    EOF or when ``done(data)`` is satisfied."""
    data = b""
    end = time.monotonic() + window
    while len(data) < limit:
        left = end - time.monotonic()
        if left <= 0:
            break
        sock.settimeout(left)
        try:
            chunk = sock.recv(limit - len(data))
        except (TimeoutError, socket.timeout):
            break
        if not chunk:
            break
        data += chunk
        if done(data):
            break
    return data


def _probe_tcp(t: dict, deadline: _Deadline, guard, warn_days: int) -> ProbeResult:
    started = time.monotonic()
    sock = _open_tcp(t["host"], t["port"], deadline, guard)
    latency = _ms(time.monotonic() - started)
    try:
        pattern = t.get("expect_banner")
        if not pattern:
            return ProbeResult(
                "up", latency,
                f"TCP connect to {t['host']}:{t['port']} succeeded in {latency:g} ms "
                "(connect test only: the service itself was not checked)",
                {"connect_only": True}, None)
        rx = re.compile(pattern)
        # latin-1 maps every byte to one character, so the regex sees the
        # banner byte-for-byte whatever its encoding.
        data = _read_some(sock, min(_BANNER_WINDOW_S, deadline.left()), _BANNER_LIMIT,
                          lambda d: rx.search(d.decode("latin-1")) is not None)
    finally:
        sock.close()
    banner = _printable(data, _BANNER_LIMIT)
    detail = {"connect_only": False, "banner": banner, "expect_banner": pattern}
    if not data:
        raise _Down(f"port open but no banner within {_BANNER_WINDOW_S:g} s "
                    f"(expected /{pattern}/)", detail, latency_ms=latency)
    if not rx.search(data.decode("latin-1")):
        raise _Down(f"banner does not match /{pattern}/: {banner[:80]!r}", detail,
                    latency_ms=latency)
    return ProbeResult("up", latency, f"banner matches /{pattern}/: {banner.strip()[:80]!r}",
                       detail, None)


def _probe_ssh(t: dict, deadline: _Deadline, guard, warn_days: int) -> ProbeResult:
    started = time.monotonic()
    sock = _open_tcp(t["host"], t["port"], deadline, guard)
    try:
        # RFC 4253 §4.2: the server MAY send other lines before the
        # identification string; the version line itself is at most 255 bytes.
        data = _read_some(sock, deadline.left(), 8192,
                          lambda d: re.search(rb"(^|\n)SSH-[^\n]*\n", d) is not None)
    finally:
        sock.close()
    latency = _ms(time.monotonic() - started)
    ident = None
    for line in data.split(b"\n"):
        if line.startswith(b"SSH-"):
            ident = line.rstrip(b"\r")[:255].decode("utf-8", errors="replace")
            break
    if ident is None:
        if not data:
            raise _Down("port open but the server sent no SSH identification line",
                        latency_ms=latency)
        raise _Down(f"not an SSH server: it sent {_printable(data, 80)!r}",
                    {"banner": _printable(data)}, latency_ms=latency)
    proto, _, rest = ident[4:].partition("-")
    software, _, comments = rest.partition(" ")
    detail = {"identification": ident, "proto_version": proto,
              "software": software, "comments": comments or None}
    if proto in ("2.0", "1.99"):
        return ProbeResult("up", latency, f"SSH server answered: {ident}", detail, None)
    return ProbeResult("degraded", latency,
                       f"SSH server speaks only protocol {proto} (obsolete): {ident}",
                       detail, None)


# --------------------------------------------------------------------------- #
#  SMTP                                                                        #
# --------------------------------------------------------------------------- #

class _LineReader:
    def __init__(self, sock: socket.socket, deadline: _Deadline):
        self.sock = sock
        self.deadline = deadline
        self.buf = b""

    def line(self) -> bytes:
        while b"\n" not in self.buf:
            if len(self.buf) > 8192:
                raise _Down("server sent an over-long line")
            self.sock.settimeout(self.deadline.remaining())
            chunk = self.sock.recv(4096)
            if not chunk:
                raise _Down("server closed the connection")
            self.buf += chunk
        line, _, self.buf = self.buf.partition(b"\n")
        return line.rstrip(b"\r")


def _smtp_reply(reader: _LineReader) -> tuple[int, list[str]]:
    """One (possibly multi-line) reply, RFC 5321 §4.2.1."""
    lines = []
    while True:
        raw = reader.line()
        text = raw.decode("utf-8", errors="replace")
        if len(text) < 3 or not text[:3].isdigit():
            raise _Down(f"not an SMTP reply: {text[:80]!r}")
        lines.append(text[4:])
        if len(text) == 3 or text[3] != "-":
            return int(text[:3]), lines


def _ehlo_name(sock: socket.socket) -> str:
    """An address literal of our own end (RFC 5321 §4.1.3): no DNS lookup of
    our own name, and always syntactically valid."""
    local = sock.getsockname()[0]
    if ":" in local:
        return f"[IPv6:{local}]"
    return f"[{local}]"


def _smtp_dialogue(starttls: bool):
    def dialogue(sock: socket.socket, deadline: _Deadline) -> dict:
        reader = _LineReader(sock, deadline)
        code, lines = _smtp_reply(reader)
        info: dict = {"banner": lines[0] if lines else ""}
        if code != 220:
            raise _Down(f"server refused service: {code} {' '.join(lines)[:120]}", info)
        sock.sendall(f"EHLO {_ehlo_name(sock)}\r\n".encode())
        code, lines = _smtp_reply(reader)
        if code != 250:
            raise _Down(f"EHLO rejected: {code} {' '.join(lines)[:120]}", info)
        info["ehlo_extensions"] = [ln.split(" ")[0].upper() for ln in lines[1:]]
        if starttls:
            if "STARTTLS" not in info["ehlo_extensions"]:
                raise _Down("server does not offer STARTTLS", info)
            sock.sendall(b"STARTTLS\r\n")
            code, lines = _smtp_reply(reader)
            if code != 220:
                raise _Down(f"STARTTLS refused: {code} {' '.join(lines)[:120]}", info)
            if reader.buf:
                # RFC 3207 §6 / CVE-2011-0411: bytes pipelined after the 220 would be
                # read as if they came over TLS. A server that sends them is broken.
                raise _Down("server sent data after its STARTTLS reply (injection risk)", info)
        return info
    return dialogue


def _probe_smtp(t: dict, deadline: _Deadline, guard, warn_days: int) -> ProbeResult:
    started = time.monotonic()
    if not t["starttls"]:
        sock = _open_tcp(t["host"], t["port"], deadline, guard)
        try:
            info = _smtp_dialogue(False)(sock, deadline)
            try:
                sock.sendall(b"QUIT\r\n")
            except OSError:
                pass
        finally:
            sock.close()
        latency = _ms(time.monotonic() - started)
        return ProbeResult("up", latency,
                           f"SMTP server answered 220 and accepted EHLO: {info['banner'][:80]}",
                           dict(info, starttls=False), None)

    tls = _tls_with_cert(t["host"], t["port"], t["host"], deadline, guard,
                         pre=_smtp_dialogue(True))
    latency = _ms(time.monotonic() - started)
    cert = tls["cert"]
    status, reasons = _judge_cert(cert, t["verify_tls"], warn_days)
    detail = dict(tls["pre"] or {}, starttls=True, tls_version=tls["tls_version"],
                  cipher=tls["cipher"])
    summary = (f"SMTP 220, EHLO and STARTTLS OK ({tls['tls_version']})"
               + (": " + "; ".join(reasons) if reasons else ""))
    return ProbeResult(status, latency, summary, detail, cert)


# --------------------------------------------------------------------------- #
#  DNS (RFC 1035)                                                              #
# --------------------------------------------------------------------------- #

_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
_RTYPE_NAMES = {v: k for k, v in _RTYPES.items()}


def _dns_query(name: str, rtype: str) -> tuple[int, bytes]:
    qid = int.from_bytes(os.urandom(2), "big")
    # Header §4.1.1: ID, flags with RD=1 (recursion desired), QDCOUNT=1.
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode("ascii")
                     for label in name.rstrip(".").split(".") if label) + b"\x00"
    return qid, header + qname + struct.pack(">HH", _RTYPES[rtype], 1)


def _dns_name(msg: bytes, off: int) -> tuple[str, int]:
    """Decode a possibly compressed name (§4.1.4). Returns (name, next offset)."""
    labels = []
    jumps = 0
    end = None
    while True:
        if off >= len(msg):
            raise ValueError("name runs past the message")
        length = msg[off]
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise ValueError("truncated compression pointer")
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | msg[off + 1]
            jumps += 1
            if jumps > 64:
                raise ValueError("compression loop")
            continue
        if length == 0:
            off += 1
            break
        labels.append(msg[off + 1:off + 1 + length].decode("ascii", errors="replace"))
        off += 1 + length
    return (".".join(labels) or "."), (end if end is not None else off)


def _dns_parse(msg: bytes, qid: int) -> dict:
    if len(msg) < 12:
        raise ValueError("reply shorter than a DNS header")
    rid, flags, qd, an, _ns, _ar = struct.unpack_from(">HHHHHH", msg, 0)
    if rid != qid or not flags & 0x8000:
        raise ValueError("not a reply to our query")
    off = 12
    for _ in range(qd):
        _, off = _dns_name(msg, off)
        off += 4
    answers = []
    for _ in range(an):
        rname, off = _dns_name(msg, off)
        rtype, _cls, ttl, rdlen = struct.unpack_from(">HHIH", msg, off)
        off += 10
        rdata = msg[off:off + rdlen]
        if len(rdata) != rdlen:
            raise ValueError("record data runs past the message")
        if rtype == 1 and rdlen == 4:
            value = str(ipaddress.IPv4Address(rdata))
        elif rtype == 28 and rdlen == 16:
            value = str(ipaddress.IPv6Address(rdata))
        elif rtype in (2, 5):
            value = _dns_name(msg, off)[0]
        elif rtype == 15:
            value = f"{struct.unpack_from('>H', msg, off)[0]} {_dns_name(msg, off + 2)[0]}"
        elif rtype == 16:
            parts, pos = [], 0
            while pos < rdlen:
                ln = rdata[pos]
                parts.append(rdata[pos + 1:pos + 1 + ln].decode("utf-8", errors="replace"))
                pos += 1 + ln
            value = "".join(parts)
        else:
            value = rdata.hex()
        answers.append({"name": rname, "type": _RTYPE_NAMES.get(rtype, str(rtype)),
                        "ttl": ttl, "value": value})
        off += rdlen
    return {"rcode": _RCODES.get(flags & 0xF, str(flags & 0xF)),
            "truncated": bool(flags & 0x0200), "authoritative": bool(flags & 0x0400),
            "recursion_available": bool(flags & 0x0080), "answers": answers}


def _recv_exact(sock: socket.socket, n: int, deadline: _Deadline) -> bytes:
    data = b""
    while len(data) < n:
        sock.settimeout(deadline.remaining())
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise _Down("server closed the connection mid-message")
        data += chunk
    return data


def _probe_dns(t: dict, deadline: _Deadline, guard, warn_days: int) -> ProbeResult:
    host, port = t["host"], t["port"]
    qid, query = _dns_query(t["name"], t["rtype"])
    started = time.monotonic()
    sock = _open_udp(host, port, deadline, guard)
    parsed = None
    try:
        sock.send(query)
        while parsed is None:
            sock.settimeout(deadline.remaining())
            try:
                reply = sock.recv(65535)
            except ConnectionRefusedError:
                raise _Down(f"nothing answers DNS on {host}:{port}/udp (port unreachable)") from None
            try:
                parsed = _dns_parse(reply, qid)
            except (ValueError, struct.error):
                continue   # a stray datagram: keep waiting for OUR answer
    finally:
        sock.close()
    transport = "udp"
    if parsed["truncated"]:
        # RFC 1035 §4.2.2 / RFC 7766: a truncated UDP answer is retried over
        # TCP, where each message carries a two-byte length prefix.
        transport = "tcp"
        tsock = _open_tcp(host, port, deadline, guard)
        try:
            tsock.sendall(struct.pack(">H", len(query)) + query)
            length = struct.unpack(">H", _recv_exact(tsock, 2, deadline))[0]
            try:
                parsed = _dns_parse(_recv_exact(tsock, length, deadline), qid)
            except (ValueError, struct.error) as exc:
                raise _Down(f"malformed DNS answer over TCP: {exc}") from None
        finally:
            tsock.close()
    latency = _ms(time.monotonic() - started)
    detail = dict(parsed, transport=transport, name=t["name"], rtype=t["rtype"])
    if parsed["rcode"] != "NOERROR":
        raise _Down(f"DNS answered {parsed['rcode']} for {t['name']} {t['rtype']}",
                    detail, latency_ms=latency)
    values = [a["value"] for a in parsed["answers"] if a["type"] == t["rtype"]]
    if not values:
        raise _Down(f"DNS answered but holds no {t['rtype']} record for {t['name']}",
                    detail, latency_ms=latency)
    expect = t.get("expect")
    if expect and not any(expect.lower() in v.lower() for v in values):
        raise _Down(f"no {t['rtype']} answer contains {expect!r} (got {', '.join(values)[:120]})",
                    detail, latency_ms=latency)
    return ProbeResult("up", latency,
                       f"DNS answered {t['rtype']} {', '.join(values)[:120]} in {latency:g} ms",
                       detail, None)


# --------------------------------------------------------------------------- #
#  SSL VPN portals                                                             #
# --------------------------------------------------------------------------- #

_SSLVPN_MARKERS = {
    "fortinet": re.compile(r"sslvpn|fortinet|/remote/", re.I),
    "cisco": re.compile(r"webvpn|\+CSCOE\+|anyconnect", re.I),
    "paloalto": re.compile(r"globalprotect|global-protect", re.I),
    "pulse": re.compile(r"dana-na|pulse secure|ivanti|welcome\.cgi", re.I),
}


def _probe_sslvpn(t: dict, deadline: _Deadline, guard, warn_days: int) -> ProbeResult:
    host, port, vendor = t["host"], t["port"], t["vendor"]
    tls = _tls_with_cert(host, port, host, deadline, guard)
    cert = tls["cert"]
    hostpart = f"[{host}]" if ":" in host else host
    url = f"https://{hostpart}:{port}{_SSLVPN_PATHS[vendor]}"
    detail = {"vendor": vendor, "portal_url": url, "tls_version": tls["tls_version"],
              "cipher": tls["cipher"]}
    try:
        fetched = _http_fetch(url, "GET", deadline, guard)
    except _Down as exc:
        exc.detail = dict(detail, **exc.detail)
        exc.cert = cert
        raise
    detail.update(http_status=fetched["status"], final_url=fetched["final_url"],
                  redirects=fetched["redirects"], server=fetched["headers"].get("server"))
    code = fetched["status"]
    if vendor == "generic":
        ok = code < 500
        why = f"HTTP {code}" if ok else f"portal answered HTTP {code}"
    else:
        match = _SSLVPN_MARKERS[vendor].search(_body_text(fetched)) if code == 200 else None
        ok = match is not None
        detail["marker"] = match.group(0) if match else None
        if code != 200:
            why = f"portal path answered HTTP {code}, not 200"
        elif not ok:
            why = f"HTTP 200 but the page carries no {vendor} SSL VPN marker"
        else:
            why = f"{vendor} portal found (marker {match.group(0)!r})"
    if not ok:
        raise _Down(f"SSL VPN portal not working: {why}", detail, cert, fetched["elapsed_ms"])
    status, reasons = _judge_cert(cert, t["verify_tls"], warn_days)
    summary = f"SSL VPN portal answers: {why}" + ("; " + "; ".join(reasons) if reasons else "")
    return ProbeResult(status, fetched["elapsed_ms"], summary, detail, cert)


# --------------------------------------------------------------------------- #
#  OpenVPN                                                                     #
# --------------------------------------------------------------------------- #
#
# Wire format (OpenVPN 2.x, ssl_pkt.h / reliable.c): every control packet is
#   opcode<<3 | key_id      1 byte
#   session_id              8 bytes
#   [tls-auth: HMAC | replay packet_id (4) | net_time (4)]
#   ack count               1 byte, then that many 4-byte packet ids
#   remote session_id       8 bytes, only when ack count > 0
#   message packet_id       4 bytes, absent in P_ACK_V1
#   TLS payload
# Over TCP every packet is prefixed with a 2-byte big-endian length.

_OP_CONTROL_V1 = 4
_OP_ACK_V1 = 5
_OP_HARD_RESET_CLIENT_V2 = 7
_OP_HARD_RESET_SERVER_V2 = 8
_OVPN_CHUNK = 1000          # control payload per packet, under the default tls-mtu
_OVPN_MAX_ACKS = 8          # RELIABLE_ACK_SIZE


class _OvpnWrap:
    """The control-channel wrapping: none, tls-auth or tls-crypt (v1)."""

    def __init__(self, mode: str, key: bytes | None = None,
                 key_direction: int | None = None, digest: str = "sha1"):
        self.mode = mode
        self.pid = 0
        if key is None:
            return
        slots = [(key[0:64], key[64:128]), (key[128:192], key[192:256])]
        if mode == "tls-crypt":
            # tls-crypt fixes the direction: the client is KEY_DIRECTION_INVERSE,
            # it sends with slot 1 and receives with slot 0 (tls_crypt.c).
            key_direction = 1
        # key_direction_state_init(): bidirectional uses slot 0 both ways;
        # 0 ("normal", the server's usual setting) sends 0/receives 1;
        # 1 ("inverse", the client's) sends 1/receives 0.
        out_slot, in_slot = {None: (0, 0), 0: (0, 1), 1: (1, 0)}[key_direction]
        if mode == "tls-auth":
            self.digest = digest
            size = hashlib.new(digest).digest_size
            self.hmac_out = slots[out_slot][1][:size]
            self.hmac_in = slots[in_slot][1][:size]
            self.hmac_len = size
        else:
            # tls-crypt v1: AES-256-CTR + HMAC-SHA256, 256-bit keys from each slot.
            self.enc_out, self.auth_out = slots[out_slot][0][:32], slots[out_slot][1][:32]
            self.enc_in, self.auth_in = slots[in_slot][0][:32], slots[in_slot][1][:32]

    def _replay_id(self) -> bytes:
        # Long-form packet_id: 32-bit counter + 32-bit Unix time (packet_id.h).
        self.pid += 1
        return struct.pack(">II", self.pid, int(time.time()) & 0xFFFFFFFF)

    def wrap(self, op: int, sid: bytes, rest: bytes) -> bytes:
        opb = bytes([op])
        if self.mode == "none":
            return opb + sid + rest
        if self.mode == "tls-auth":
            replay = self._replay_id()
            # The HMAC covers the packet with the HMAC field removed and the
            # replay id moved to the front: pid|time|op|sid|rest (swap_hmac()).
            mac = hmac.new(self.hmac_out, replay + opb + sid + rest, self.digest).digest()
            return opb + sid + mac + replay + rest
        header = opb + sid + self._replay_id()
        # tls_crypt_wrap(): tag = HMAC-SHA256(Ka, header|plaintext); the first
        # 128 bits of the tag are the AES-256-CTR IV for the plaintext.
        tag = hmac.new(self.auth_out, header + rest, hashlib.sha256).digest()
        enc = Cipher(algorithms.AES(self.enc_out), modes.CTR(tag[:16])).encryptor()
        return header + tag + enc.update(rest) + enc.finalize()

    def unwrap(self, pkt: bytes) -> tuple[int, bytes, bytes, bool | None]:
        """(op, session_id, rest, verified). ``verified`` is None without a key."""
        if len(pkt) < 9:
            raise ValueError("packet too short")
        op, sid = pkt[0], pkt[1:9]
        if self.mode == "none":
            return op, sid, pkt[9:], None
        if self.mode == "tls-auth":
            mac = pkt[9:9 + self.hmac_len]
            replay = pkt[9 + self.hmac_len:17 + self.hmac_len]
            rest = pkt[17 + self.hmac_len:]
            if len(replay) != 8:
                raise ValueError("packet too short for tls-auth")
            expected = hmac.new(self.hmac_in, replay + bytes([op]) + sid + rest,
                                self.digest).digest()
            return op, sid, rest, hmac.compare_digest(mac, expected)
        header, tag, body = pkt[:17], pkt[17:49], pkt[49:]
        if len(tag) != 32:
            raise ValueError("packet too short for tls-crypt")
        dec = Cipher(algorithms.AES(self.enc_in), modes.CTR(tag[:16])).decryptor()
        rest = dec.update(body) + dec.finalize()
        expected = hmac.new(self.auth_in, header + rest, hashlib.sha256).digest()
        return op, sid, rest, hmac.compare_digest(tag, expected)


def _ovpn_rest(acks: list[int], remote_sid: bytes | None, msg_pid: int | None,
               payload: bytes = b"") -> bytes:
    out = bytes([len(acks)]) + b"".join(struct.pack(">I", a) for a in acks)
    if acks:
        out += remote_sid
    if msg_pid is not None:
        out += struct.pack(">I", msg_pid)
    return out + payload


def _ovpn_parse_rest(op: int, rest: bytes) -> tuple[list[int], bytes | None, int | None, bytes]:
    n = rest[0]
    off = 1 + 4 * n
    acks = list(struct.unpack_from(f">{n}I", rest, 1)) if n else []
    remote = None
    if n:
        remote = rest[off:off + 8]
        off += 8
    if op >> 3 == _OP_ACK_V1:
        return acks, remote, None, b""
    if len(rest) < off + 4:
        raise ValueError("control packet too short")
    msg_pid = struct.unpack_from(">I", rest, off)[0]
    return acks, remote, msg_pid, rest[off + 4:]


class _OvpnTransport:
    def __init__(self, sock: socket.socket, proto: str):
        self.sock = sock
        self.proto = proto
        self.buf = b""

    def send(self, pkt: bytes) -> None:
        if self.proto == "tcp":
            self.sock.sendall(struct.pack(">H", len(pkt)) + pkt)
        else:
            self.sock.send(pkt)

    def recv(self, wait: float) -> bytes | None:
        """One packet, or None after ``wait`` seconds of silence."""
        end = time.monotonic() + max(0.01, wait)
        if self.proto == "udp":
            self.sock.settimeout(max(0.01, wait))
            try:
                return self.sock.recv(65535)
            except (TimeoutError, socket.timeout):
                return None
        while True:
            if len(self.buf) >= 2:
                size = struct.unpack(">H", self.buf[:2])[0]
                if len(self.buf) >= 2 + size:
                    pkt, self.buf = self.buf[2:2 + size], self.buf[2 + size:]
                    return pkt
            left = end - time.monotonic()
            if left <= 0:
                return None
            self.sock.settimeout(left)
            try:
                chunk = self.sock.recv(65535)
            except (TimeoutError, socket.timeout):
                return None
            if not chunk:
                raise _Down("the server closed the TCP connection")
            self.buf += chunk


class _TlsSniffer:
    """Reads plaintext TLS 1.2 handshake records (RFC 5246 §6.2, §7.4) to
    pull out the server's Certificate message, independent of OpenSSL."""

    def __init__(self):
        self.records = b""
        self.handshake = b""
        self.certs: list[bytes] = []
        self.server_version: str | None = None
        self.hello_done = False
        self.alert: tuple[int, int] | None = None
        self.encrypted = False

    def feed(self, data: bytes) -> None:
        self.records += data
        while len(self.records) >= 5 and not self.encrypted:
            ctype, _ver, length = struct.unpack(">BHH", self.records[:5])
            if len(self.records) < 5 + length:
                return
            frag, self.records = self.records[5:5 + length], self.records[5 + length:]
            if ctype == 21 and len(frag) >= 2 and self.alert is None:
                self.alert = (frag[0], frag[1])
            elif ctype == 20:
                self.encrypted = True     # after ChangeCipherSpec nothing is readable
            elif ctype == 22:
                self.handshake += frag
                self._messages()

    def _messages(self) -> None:
        while len(self.handshake) >= 4:
            mtype = self.handshake[0]
            mlen = int.from_bytes(self.handshake[1:4], "big")
            if len(self.handshake) < 4 + mlen:
                return
            body, self.handshake = self.handshake[4:4 + mlen], self.handshake[4 + mlen:]
            if mtype == 2 and len(body) >= 2:          # ServerHello
                self.server_version = {0x0301: "TLSv1", 0x0302: "TLSv1.1",
                                       0x0303: "TLSv1.2"}.get(
                    int.from_bytes(body[:2], "big"), hex(int.from_bytes(body[:2], "big")))
            elif mtype == 11 and len(body) >= 3:       # Certificate
                total = int.from_bytes(body[:3], "big")
                pos = 3
                while pos + 3 <= min(len(body), 3 + total):
                    clen = int.from_bytes(body[pos:pos + 3], "big")
                    self.certs.append(body[pos + 3:pos + 3 + clen])
                    pos += 3 + clen
            elif mtype == 14:                          # ServerHelloDone
                self.hello_done = True


_TLS_ALERTS = {40: "handshake_failure", 42: "bad_certificate", 47: "illegal_parameter",
               48: "unknown_ca", 70: "protocol_version", 71: "insufficient_security",
               80: "internal_error", 86: "inappropriate_fallback", 109: "missing_extension",
               112: "unrecognized_name", 116: "certificate_required"}


_TLS13_HINT = (" (the server probably insists on TLS 1.3, where the certificate is "
               "encrypted and cannot be read without completing the handshake)")


def _ovpn_fetch_cert(transport: _OvpnTransport, wrap: _OvpnWrap, sid: bytes,
                     server_sid: bytes, server_reset_pid: int, budget: float,
                     verify_tls: bool) -> dict:
    """Run TLS (capped at 1.2) over P_CONTROL_V1 until the server's Certificate
    is seen. In TLS 1.2 that message travels in PLAINTEXT, so it can be read
    off the wire without completing the handshake (or holding a client cert).
    Returns {"der", "tls_version", "chain_ok", "error"}."""
    end = time.monotonic() + budget
    ctx = _lenient_context(max_tls12=True)
    if verify_tls:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()
    inc, outg = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(inc, outg, server_side=False)
    sniffer = _TlsSniffer()
    pending_acks = [server_reset_pid]
    unacked: dict[int, bytes] = {}
    next_out = 1           # our reset used message packet_id 0
    next_in = server_reset_pid + 1
    held: dict[int, bytes] = {}
    chain_ok = None
    ssl_error = None
    dropped = False

    def send_control(payload: bytes) -> None:
        nonlocal next_out, pending_acks
        acks, pending_acks = pending_acks[:_OVPN_MAX_ACKS], pending_acks[_OVPN_MAX_ACKS:]
        rest = _ovpn_rest(acks, server_sid, next_out, payload)
        transport.send(wrap.wrap(_OP_CONTROL_V1 << 3, sid, rest))
        unacked[next_out] = payload
        next_out += 1

    def flush_acks() -> None:
        nonlocal pending_acks
        while pending_acks:
            acks, pending_acks = pending_acks[:_OVPN_MAX_ACKS], pending_acks[_OVPN_MAX_ACKS:]
            transport.send(wrap.wrap(_OP_ACK_V1 << 3, sid, _ovpn_rest(acks, server_sid, None)))

    def step_tls() -> None:
        nonlocal chain_ok, ssl_error
        if ssl_error is not None:
            return
        try:
            tls.do_handshake()
            chain_ok = True if verify_tls else None
        except ssl.SSLWantReadError:
            if verify_tls and sniffer.hello_done:
                # OpenSSL verifies the chain as soon as it parses Certificate;
                # still wanting to read past ServerHelloDone means it passed.
                chain_ok = True
        except ssl.SSLCertVerificationError as exc:
            chain_ok = False
            ssl_error = exc.verify_message or str(exc)
        except ssl.SSLError as exc:
            ssl_error = exc.reason or str(exc)
        data = outg.read()
        for pos in range(0, len(data), _OVPN_CHUNK):
            send_control(data[pos:pos + _OVPN_CHUNK])

    step_tls()             # emits the ClientHello
    flush_acks()
    while True:
        if sniffer.certs and (not verify_tls or chain_ok is not None or ssl_error):
            break
        if sniffer.alert or (ssl_error and not sniffer.certs):
            break
        left = end - time.monotonic()
        if left <= 0:
            break
        try:
            pkt = transport.recv(min(left, 1.0))
        except (ConnectionRefusedError, _Down):
            # OpenVPN answers a TLS failure by tearing the session down without
            # an alert (2.6 logs "TLS handshake failed" and restarts/drops it).
            dropped = True
            break
        if pkt is None:
            # Reliability layer: retransmit what the server has not ACKed.
            if transport.proto == "udp":
                for pid in sorted(unacked):
                    rest = _ovpn_rest([], None, pid, unacked[pid])
                    transport.send(wrap.wrap(_OP_CONTROL_V1 << 3, sid, rest))
            continue
        try:
            op, psid, rest, verified = wrap.unwrap(pkt)
            if psid != server_sid or verified is False:
                continue
            acks, _remote, msg_pid, payload = _ovpn_parse_rest(op, rest)
        except (ValueError, struct.error, IndexError):
            continue
        for ack in acks:
            unacked.pop(ack, None)
        if op >> 3 != _OP_CONTROL_V1 or msg_pid is None:
            continue
        pending_acks.append(msg_pid)
        if msg_pid >= next_in:
            held.setdefault(msg_pid, payload)
        while next_in in held:
            data = held.pop(next_in)
            next_in += 1
            sniffer.feed(data)
            inc.write(data)
        step_tls()
        flush_acks()

    result = {"der": sniffer.certs[0] if sniffer.certs else None,
              "tls_version": sniffer.server_version, "chain_ok": chain_ok, "error": None}
    if not sniffer.certs:
        if sniffer.alert:
            name = _TLS_ALERTS.get(sniffer.alert[1], str(sniffer.alert[1]))
            hint = _TLS13_HINT if sniffer.alert[1] == 70 else ""
            result["error"] = f"server ended the TLS handshake with alert {name}{hint}"
        elif ssl_error:
            result["error"] = f"TLS handshake failed before the certificate: {ssl_error}"
        elif dropped:
            result["error"] = ("the server dropped the session after our TLS 1.2 ClientHello"
                               + _TLS13_HINT)
        elif not sniffer.records and not sniffer.server_version:
            result["error"] = ("TLS handshake stalled: no answer to our TLS 1.2 ClientHello"
                               + _TLS13_HINT)
        else:
            result["error"] = "TLS handshake stalled before the server certificate arrived"
    elif chain_ok is False:
        result["error"] = ssl_error
    return result


def _probe_openvpn(t: dict, deadline: _Deadline, guard, warn_days: int) -> ProbeResult:
    if t.get("tls_crypt_key"):
        wrap = _OvpnWrap("tls-crypt", _parse_static_key(t["tls_crypt_key"], "tls_crypt_key"))
    elif t.get("tls_auth_key"):
        wrap = _OvpnWrap("tls-auth", _parse_static_key(t["tls_auth_key"], "tls_auth_key"),
                         t.get("key_direction"), _OVPN_DIGESTS[t["auth_digest"]])
    else:
        wrap = _OvpnWrap("none")
    host, port, proto = t["host"], t["port"], t["proto"]
    detail: dict = {"proto": proto, "wrapping": wrap.mode}
    if wrap.mode == "tls-auth":
        detail.update(key_direction=t.get("key_direction"), auth_digest=t["auth_digest"])
    no_key_hint = ("the server may require tls-auth/tls-crypt: supply its static key "
                   "(tls_auth_key or tls_crypt_key) to probe it")
    key_hint = (f"a server using {wrap.mode} silently drops packets whose authentication "
                "fails: check the key, key_direction and auth_digest")
    started = time.monotonic()
    try:
        sock = (_open_udp if proto == "udp" else _open_tcp)(host, port, deadline, guard)
    except ConnectionRefusedError:
        raise _Down(f"connection to {host}:{port}/tcp refused", detail) from None
    transport = _OvpnTransport(sock, proto)
    sid = os.urandom(8)
    try:
        reset = None
        resend_every = max(1.0, deadline.seconds / 4)
        try:
            while reset is None:
                # P_CONTROL_HARD_RESET_CLIENT_V2 with message packet_id 0 and
                # no payload (the TLS ClientHello follows in P_CONTROL_V1).
                transport.send(wrap.wrap(_OP_HARD_RESET_CLIENT_V2 << 3, sid,
                                         _ovpn_rest([], None, 0)))
                window_end = time.monotonic() + resend_every
                while reset is None:
                    wait = min(window_end - time.monotonic(), deadline.left())
                    if deadline.left() <= 0:
                        raise TimeoutError
                    if wait <= 0:
                        break
                    pkt = transport.recv(wait)
                    if pkt is None:
                        continue
                    try:
                        op, server_sid, rest, verified = wrap.unwrap(pkt)
                    except ValueError:
                        continue
                    if op >> 3 != _OP_HARD_RESET_SERVER_V2:
                        continue
                    if verified is False:
                        reset = (op, server_sid, None, verified)
                        break
                    try:
                        acks, remote, msg_pid, _payload = _ovpn_parse_rest(op, rest)
                    except (ValueError, struct.error, IndexError):
                        continue
                    if acks and remote != sid:
                        continue        # an answer to somebody else's session
                    reset = (op, server_sid, msg_pid, verified)
        except TimeoutError:
            raise _Down(f"no OpenVPN reply within {deadline.seconds:g} s: "
                        + (key_hint if wrap.mode != "none" else no_key_hint), detail) from None
        except ConnectionRefusedError:
            raise _Down(f"nothing listens on {host}:{port}/{proto} (port unreachable)",
                        detail) from None
        latency = _ms(time.monotonic() - started)
        _op, server_sid, server_pid, verified = reset
        detail.update(server_session_id=server_sid.hex(), client_session_id=sid.hex(),
                      hmac_verified=verified)
        if verified is False:
            return ProbeResult(
                "degraded", latency,
                f"OpenVPN server answered, but its reply failed {wrap.mode} authentication "
                "(check key_direction and auth_digest)", detail, None)

        budget = min(deadline.left(), max(3.0, deadline.seconds / 2))
        cert = None
        try:
            got = _ovpn_fetch_cert(transport, wrap, sid, server_sid, server_pid or 0,
                                   budget, t["verify_tls"])
        except (OSError, _Down) as exc:
            got = {"der": None, "tls_version": None, "chain_ok": None,
                   "error": f"certificate step failed: {exc}"}
        if got["der"]:
            cert = _cert_facts(got["der"], None)
            cert["chain_ok"] = got["chain_ok"]
            if got["error"]:
                cert["error"] = got["error"]
        else:
            cert = _empty_cert(got["error"] or "no certificate received")
        detail["tls_version"] = got["tls_version"]
    finally:
        sock.close()

    status, reasons = _judge_cert(cert, t["verify_tls"], warn_days, unreadable_counts=False)
    auth = {"none": "", "tls-auth": ", tls-auth HMAC verified",
            "tls-crypt": ", tls-crypt verified"}[wrap.mode]
    summary = f"OpenVPN server answered P_CONTROL_HARD_RESET_SERVER_V2{auth}"
    if cert.get("error") and not cert.get("subject"):
        summary += f" (certificate not read: {cert['error']})"
    if reasons:
        summary += ": " + "; ".join(reasons)
    return ProbeResult(status, latency, summary, detail, cert)


# --------------------------------------------------------------------------- #
#  IPsec: IKEv2 (RFC 7296) and IKEv1 (RFC 2408/2409)                           #
# --------------------------------------------------------------------------- #

# RFC 3526 §3 (group 14) and RFC 2409 §6.2 / RFC 3526 §2 (groups 2, 5), g = 2.
_MODP_PRIMES = {
    2: int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16),
    5: int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16),
    14: int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16),
}
_KE_GROUPS = (14, 19, 5, 2)   # what we can build a KE payload for

_IKE2_ENCR = {3: "3DES", 12: "AES_CBC", 13: "AES_CTR", 14: "AES_CCM_8", 16: "AES_CCM_16",
              18: "AES_GCM_8", 19: "AES_GCM_12", 20: "AES_GCM_16", 28: "CHACHA20_POLY1305"}
_IKE2_PRF = {1: "PRF_HMAC_MD5", 2: "PRF_HMAC_SHA1", 4: "PRF_AES128_XCBC",
             5: "PRF_HMAC_SHA2_256", 6: "PRF_HMAC_SHA2_384", 7: "PRF_HMAC_SHA2_512"}
_IKE2_INTEG = {1: "HMAC_MD5_96", 2: "HMAC_SHA1_96", 5: "AES_XCBC_96",
               12: "HMAC_SHA2_256_128", 13: "HMAC_SHA2_384_192", 14: "HMAC_SHA2_512_256"}
_IKE2_DH = {1: "MODP_768", 2: "MODP_1024", 5: "MODP_1536", 14: "MODP_2048", 15: "MODP_3072",
            16: "MODP_4096", 19: "ECP_256", 20: "ECP_384", 21: "ECP_521", 31: "CURVE25519",
            32: "CURVE448"}
_IKE2_NOTIFY = {1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI",
                5: "INVALID_MAJOR_VERSION", 7: "INVALID_SYNTAX", 9: "INVALID_MESSAGE_ID",
                11: "INVALID_SPI", 14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD",
                24: "AUTHENTICATION_FAILED", 34: "SINGLE_PAIR_REQUIRED",
                35: "NO_ADDITIONAL_SAS", 36: "INTERNAL_ADDRESS_FAILURE",
                37: "FAILED_CP_REQUIRED", 38: "TS_UNACCEPTABLE", 39: "INVALID_SELECTORS",
                43: "TEMPORARY_FAILURE", 44: "CHILD_SA_NOT_FOUND", 16384: "INITIAL_CONTACT",
                16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP",
                16390: "COOKIE", 16404: "MULTIPLE_AUTH_SUPPORTED",
                16406: "REDIRECT_SUPPORTED", 16407: "REDIRECT",
                16418: "CHILDLESS_IKEV2_SUPPORTED", 16430: "IKEV2_FRAGMENTATION_SUPPORTED",
                16431: "SIGNATURE_HASH_ALGORITHMS", 16435: "USE_PPK"}
_N_INVALID_KE = 17
_N_COOKIE = 16390

# Vendor IDs by prefix. Hashes from the vendors' own sources / ike-scan's list.
_VENDOR_IDS = (
    (bytes.fromhex("882fe56d6fd20dbc2251613b2ebe5beb"), "strongSwan"),
    (bytes.fromhex("1d6e178f6c2c0be284985465450fe9d4"), "Fortinet FortiGate"),
    (bytes.fromhex("8299031757a36082c6a621de"), "Fortinet (endpoint control)"),
    (bytes.fromhex("4048b7d56ebce88525e7de7f00d6c2d3"), "IKE fragmentation (Cisco/Fortinet)"),
    (bytes.fromhex("12f5f28c457168a9702d9fe274cc0100"), "Cisco Unity"),
    (b"CISCO", "Cisco"),
    (b"FLEXVPN-SUPPORTED", "Cisco FlexVPN"),
    (b"OE", "Openswan/libreswan"),
    (bytes.fromhex("afcad71368a1f1c96b8696fc77570100"), "Dead Peer Detection (RFC 3706)"),
    (bytes.fromhex("4a131c81070358455c5728f20e95452f"), "NAT-Traversal (RFC 3947)"),
    (bytes.fromhex("1e2b516905991c7d7c96fcbfb587e461"), "Microsoft Windows"),
    (bytes.fromhex("09002689dfd6b712"), "XAUTH"),
    (b"HeartBeat_Notify", "Juniper/NetScreen"),
)

_IKE_CERT_NOTE = ("IKE sends certificates only inside the encrypted IKE_AUTH exchange, "
                  "which needs credentials; no certificate can be read from IKE_SA_INIT")
_NON_ESP_MARKER = b"\x00\x00\x00\x00"   # RFC 3948 §2.2, IKE on UDP 4500


def _vendor_ids(vids: list[bytes]) -> list[dict]:
    out = []
    for vid in vids:
        name = next((label for prefix, label in _VENDOR_IDS if vid.startswith(prefix)), None)
        out.append({"hex": vid.hex(), "name": name})
    return out


def _ike_ke_value(group: int) -> bytes:
    """A genuine DH public value for ``group`` (RFC 7296 §3.4)."""
    if group in _MODP_PRIMES:
        prime = _MODP_PRIMES[group]
        exponent = int.from_bytes(os.urandom(32), "big") | (1 << 255)
        return pow(2, exponent, prime).to_bytes((prime.bit_length() + 7) // 8, "big")
    if group == 19:
        # RFC 5903 §7: ECP public value = x | y, without the 0x04 point prefix.
        point = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return point[1:]
    raise ValueError(f"no KE implementation for DH group {group}")


def _ike2_transform(ttype: int, tid: int, keylen: int | None = None, last: bool = False) -> bytes:
    attrs = struct.pack(">HH", 0x800E, keylen) if keylen else b""   # TV Key Length
    return struct.pack(">BBHBBH", 0 if last else 3, 0, 8 + len(attrs), ttype, 0, tid) + attrs


def _ike2_proposal(num: int, transforms: list[tuple], last: bool) -> bytes:
    body = b"".join(_ike2_transform(*tr, last=(i == len(transforms) - 1))
                    for i, tr in enumerate(transforms))
    # Protocol 1 = IKE, SPI size 0 in IKE_SA_INIT (RFC 7296 §3.3.1).
    return struct.pack(">BBHBBBB", 0 if last else 2, 0, 8 + len(body), num, 1, 0,
                       len(transforms)) + body


# Transform types: 1 ENCR, 2 PRF, 3 INTEG, 4 DH (RFC 7296 §3.3.2).
_IKE2_PROPOSALS = (
    [(1, 12, 256), (1, 12, 128), (2, 5), (2, 2), (3, 12), (3, 2),
     (4, 14), (4, 19), (4, 5), (4, 2)],
    [(1, 20, 256), (2, 5), (4, 19), (4, 14)],
)
_IKE2_OFFERED_GROUPS = {tid for prop in _IKE2_PROPOSALS for (ttype, tid, *_k) in prop
                        if ttype == 4}


def _ike_payloads(payloads: list[tuple[int, bytes]]) -> bytes:
    """Chain generic payload headers (RFC 7296 §3.2): each names the NEXT type."""
    out = b""
    for i, (_ptype, body) in enumerate(payloads):
        nxt = payloads[i + 1][0] if i + 1 < len(payloads) else 0
        out += struct.pack(">BBH", nxt, 0, 4 + len(body)) + body
    return out


def _nat_hash(spi_i: bytes, addr: tuple) -> bytes:
    # RFC 7296 §2.23: SHA-1(SPIi | SPIr | IP | Port), SPIr all zero in the request.
    ip = ipaddress.ip_address(addr[0]).packed
    return hashlib.sha1(spi_i + b"\x00" * 8 + ip + struct.pack(">H", addr[1])).digest()


def _ike2_sa_init(spi_i: bytes, group: int, nonce: bytes, cookie: bytes | None,
                  local: tuple, remote: tuple) -> bytes:
    sa = b"".join(_ike2_proposal(i + 1, prop, i == len(_IKE2_PROPOSALS) - 1)
                  for i, prop in enumerate(_IKE2_PROPOSALS))
    ke = struct.pack(">HH", group, 0) + _ike_ke_value(group)
    payloads = []
    if cookie is not None:
        # RFC 7296 §2.6: the retry carries the COOKIE notify as FIRST payload.
        payloads.append((41, struct.pack(">BBH", 0, 0, _N_COOKIE) + cookie))
    payloads += [
        (33, sa), (34, ke), (40, nonce),
        (41, struct.pack(">BBH", 0, 0, 16388) + _nat_hash(spi_i, local)),
        (41, struct.pack(">BBH", 0, 0, 16389) + _nat_hash(spi_i, remote)),
    ]
    body = _ike_payloads(payloads)
    # Header: SPIi, SPIr=0, next payload, version 2.0, IKE_SA_INIT (34),
    # flags = Initiator (0x08), message id 0, total length.
    header = spi_i + b"\x00" * 8 + struct.pack(">BBBBII", payloads[0][0], 0x20, 34, 0x08,
                                               0, 28 + len(body))
    return header + body


def _ike2_parse_sa(body: bytes) -> dict:
    """The responder's chosen proposal: exactly one (RFC 7296 §3.3)."""
    _last, _r, _plen, pnum, _proto, spisize, ntrans = struct.unpack_from(">BBHBBBB", body, 0)
    off = 8 + spisize
    chosen: dict = {"proposal": pnum}
    for _ in range(ntrans):
        _tl, _r, tlen, ttype, _r2, tid = struct.unpack_from(">BBHBBH", body, off)
        keylen = None
        aoff = off + 8
        while aoff + 4 <= off + tlen:
            atype, aval = struct.unpack_from(">HH", body, aoff)
            if atype & 0x8000:
                if atype & 0x7FFF == 14:
                    keylen = aval
                aoff += 4
            else:
                aoff += 4 + aval
        names = {1: _IKE2_ENCR, 2: _IKE2_PRF, 3: _IKE2_INTEG, 4: _IKE2_DH}.get(ttype, {})
        label = names.get(tid, f"{ttype}:{tid}")
        if keylen:
            label = f"{label}-{keylen}"
        key = {1: "encr", 2: "prf", 3: "integ", 4: "dh"}.get(ttype, f"type{ttype}")
        chosen[key] = label
        off += tlen
    return chosen


def _ike2_parse(msg: bytes, spi_i: bytes) -> dict:
    if len(msg) < 28 or msg[:8] != spi_i:
        raise ValueError("not a reply to our IKE_SA_INIT")
    spi_r = msg[8:16]
    nxt, version, exch, flags, _mid, length = struct.unpack_from(">BBBBII", msg, 16)
    parsed = {"responder_spi": spi_r.hex(), "version": f"{version >> 4}.{version & 0xF}",
              "exchange": exch, "response": bool(flags & 0x20), "notifies": [],
              "vendor_ids": [], "sa": None, "ke_group": None}
    if version >> 4 != 2:
        return parsed
    off = 28
    end = min(len(msg), length)
    while nxt and off + 4 <= end:
        ptype = nxt
        nxt, _crit, plen = struct.unpack_from(">BBH", msg, off)
        if plen < 4 or off + plen > end:
            raise ValueError("malformed payload length")
        body = msg[off + 4:off + plen]
        if ptype == 33:
            parsed["sa"] = _ike2_parse_sa(body)
        elif ptype == 34 and len(body) >= 2:
            parsed["ke_group"] = struct.unpack_from(">H", body)[0]
        elif ptype == 41 and len(body) >= 4:
            _proto, spisize, ntype = struct.unpack_from(">BBH", body)
            parsed["notifies"].append((ntype, body[4 + spisize:]))
        elif ptype == 43:
            parsed["vendor_ids"].append(body)
        off += plen
    return parsed


def _udp_exchange(sock: socket.socket, payload: bytes, accept, deadline: _Deadline,
                  sends: int = 3) -> tuple[bytes, float]:
    """Send ``payload``, retransmitting up to ``sends`` times across the
    deadline, until a datagram that ``accept`` likes arrives."""
    interval = max(0.5, deadline.left() / sends)
    started = time.monotonic()
    for _ in range(sends):
        sock.send(payload)
        window_end = min(time.monotonic() + interval, deadline.end)
        while True:
            left = window_end - time.monotonic()
            if left <= 0:
                break
            sock.settimeout(left)
            try:
                data = sock.recv(65535)
            except (TimeoutError, socket.timeout):
                break
            if accept(data):
                return data, _ms(time.monotonic() - started)
        if deadline.left() <= 0:
            break
    raise TimeoutError("no reply")


def _probe_ipsec(t: dict, deadline: _Deadline, guard, warn_days: int) -> ProbeResult:
    host, port, nat_t = t["host"], t["port"], t["nat_t"]
    prefix = _NON_ESP_MARKER if nat_t else b""
    detail: dict = {"ike_version": t["ike_version"], "nat_t": nat_t, "cert_note": _IKE_CERT_NOTE}
    sock = _open_udp(host, port, deadline, guard)
    try:
        if t["ike_version"] == 1:
            return _ike1(sock, prefix, detail, deadline, host, port)
        local = sock.getsockname()[:2]
        remote = sock.getpeername()[:2]
        spi_i = os.urandom(8)
        nonce = os.urandom(32)
        # The KE payload carries the FIRST group of the first proposal
        # (MODP-2048); a responder preferring another answers INVALID_KE_PAYLOAD.
        group, cookie = 14, None
        exchanges: list[str] = []
        latency = None
        parsed = None

        def accept(data: bytes) -> bool:
            if prefix and data.startswith(prefix):
                data = data[len(prefix):]
            return len(data) >= 28 and data[:8] == spi_i

        for _attempt in range(3):
            msg = prefix + _ike2_sa_init(spi_i, group, nonce, cookie, local, remote)
            try:
                reply, rtt = _udp_exchange(sock, msg, accept, deadline)
            except TimeoutError:
                if parsed is not None:
                    break       # we already know a responder is alive
                raise _Down(f"no IKE response from {host}:{port}/udp within "
                            f"{deadline.seconds:g} s", detail) from None
            except ConnectionRefusedError:
                raise _Down(f"nothing listens on {host}:{port}/udp (port unreachable): "
                            "no IKE daemon", detail) from None
            latency = latency if latency is not None else rtt
            if prefix and reply.startswith(prefix):
                reply = reply[len(prefix):]
            try:
                parsed = _ike2_parse(reply, spi_i)
            except (ValueError, struct.error) as exc:
                raise _Down(f"malformed IKE reply: {exc}", detail, latency_ms=latency) from None
            types = {ntype: data for ntype, data in parsed["notifies"]}
            if _N_COOKIE in types and cookie is None:
                cookie = types[_N_COOKIE]
                exchanges.append("COOKIE")
                continue
            if _N_INVALID_KE in types and "INVALID_KE_PAYLOAD" not in exchanges:
                data = types[_N_INVALID_KE]
                wanted = struct.unpack(">H", data[:2])[0] if len(data) >= 2 else None
                exchanges.append("INVALID_KE_PAYLOAD")
                detail["requested_group"] = _IKE2_DH.get(wanted, str(wanted))
                if wanted in _KE_GROUPS and wanted in _IKE2_OFFERED_GROUPS and wanted != group:
                    group = wanted
                    continue
            break
    finally:
        sock.close()

    notify_names = [_IKE2_NOTIFY.get(n, str(n)) for n, _ in parsed["notifies"]]
    detail.update(responder_spi=parsed["responder_spi"], exchanges=exchanges + ["final"],
                  attempts=len(exchanges) + 1, notifies=notify_names, ke_group=_IKE2_DH.get(group),
                  vendor_ids=_vendor_ids(parsed["vendor_ids"]),
                  chosen_proposal=parsed["sa"], responder_version=parsed["version"])
    if parsed["version"].split(".")[0] != "2":
        summary = f"IKE responder answered with IKE version {parsed['version']}"
    elif parsed["sa"]:
        chosen = parsed["sa"]
        parts = [chosen.get(k) for k in ("encr", "integ", "prf", "dh") if chosen.get(k)]
        summary = f"IKEv2 responder accepted proposal {'/'.join(parts)}"
    else:
        errors = [name for (n, _), name in zip(parsed["notifies"], notify_names) if n < 16384]
        summary = f"IKEv2 responder answered ({', '.join(errors or notify_names) or 'empty reply'})"
    names = [v["name"] for v in detail["vendor_ids"] if v["name"]]
    if names:
        summary += f"; vendor: {', '.join(names)}"
    return ProbeResult("up", latency, summary, detail, None)


_IKE1_NOTIFY = {1: "INVALID-PAYLOAD-TYPE", 2: "DOI-NOT-SUPPORTED", 3: "SITUATION-NOT-SUPPORTED",
                4: "INVALID-COOKIE", 5: "INVALID-MAJOR-VERSION", 6: "INVALID-MINOR-VERSION",
                7: "INVALID-EXCHANGE-TYPE", 8: "INVALID-FLAGS", 9: "INVALID-MESSAGE-ID",
                10: "INVALID-PROTOCOL-ID", 11: "INVALID-SPI", 12: "INVALID-TRANSFORM-ID",
                13: "ATTRIBUTES-NOT-SUPPORTED", 14: "NO-PROPOSAL-CHOSEN",
                15: "BAD-PROPOSAL-SYNTAX", 16: "PAYLOAD-MALFORMED",
                17: "INVALID-KEY-INFORMATION", 18: "INVALID-ID-INFORMATION",
                24: "AUTHENTICATION-FAILED"}
_IKE1_ENC = {1: "DES", 5: "3DES", 7: "AES"}
_IKE1_HASH = {1: "MD5", 2: "SHA1", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512"}
_IKE1_AUTH = {1: "PSK", 3: "RSA-SIG", 65001: "XAUTH-PSK"}
_IKE1_GROUP = {1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048", 19: "ECP-256"}
# (encryption, key length, hash, auth method, group): RFC 2409 Appendix A values.
_IKE1_TRANSFORMS = ((7, 256, 4, 1, 14), (7, 256, 2, 1, 14), (7, 128, 2, 1, 2),
                    (5, None, 2, 1, 2), (7, 256, 4, 3, 14))


def _ike1_main_mode(icookie: bytes) -> bytes:
    transforms = b""
    for i, (enc, keylen, hsh, auth, grp) in enumerate(_IKE1_TRANSFORMS):
        attrs = struct.pack(">HH", 0x8001, enc)
        if keylen:
            attrs += struct.pack(">HH", 0x800E, keylen)
        attrs += struct.pack(">HHHHHHHHHH", 0x8002, hsh, 0x8003, auth, 0x8004, grp,
                             0x800B, 1, 0x800C, 28800)   # life type seconds, 8 h
        last = i == len(_IKE1_TRANSFORMS) - 1
        # Transform payload (RFC 2408 §3.6): transform id 1 = KEY_IKE.
        transforms += struct.pack(">BBHBBH", 0 if last else 3, 0, 8 + len(attrs), i + 1, 1,
                                  0) + attrs
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0,
                           len(_IKE1_TRANSFORMS)) + transforms
    # SA payload (RFC 2408 §3.4): DOI 1 (IPsec), situation SIT_IDENTITY_ONLY,
    # then the Proposal payload, which carries its OWN generic header. A second
    # generic header here made strongSwan answer PAYLOAD-MALFORMED ("payload
    # type SECURITY_ASSOCIATION_V1 could not be parsed", verified 2026-11-17
    # against charon 5.9) — and a stricter peer drops the packet silently,
    # which would read as "no IKE daemon".
    sa_body = struct.pack(">II", 1, 1) + proposal
    vids = [bytes.fromhex("4a131c81070358455c5728f20e95452f"),   # RFC 3947 NAT-T
            bytes.fromhex("afcad71368a1f1c96b8696fc77570100")]   # RFC 3706 DPD
    payloads = [(1, sa_body)] + [(13, v) for v in vids]
    body = _ike_payloads(payloads)
    # Header: version 1.0, exchange 2 = Identity Protection (Main Mode).
    return icookie + b"\x00" * 8 + struct.pack(">BBBBII", 1, 0x10, 2, 0, 0, 28 + len(body)) + body


def _ike1(sock, prefix, detail, deadline, host, port) -> ProbeResult:
    icookie = os.urandom(8)

    def accept(data: bytes) -> bool:
        if prefix and data.startswith(prefix):
            data = data[len(prefix):]
        return len(data) >= 28 and data[:8] == icookie

    try:
        reply, latency = _udp_exchange(sock, prefix + _ike1_main_mode(icookie), accept, deadline)
    except TimeoutError:
        raise _Down(f"no ISAKMP response from {host}:{port}/udp within "
                    f"{deadline.seconds:g} s", detail) from None
    except ConnectionRefusedError:
        raise _Down(f"nothing listens on {host}:{port}/udp (port unreachable): no IKE daemon",
                    detail) from None
    if prefix and reply.startswith(prefix):
        reply = reply[len(prefix):]
    nxt, version, exch, _flags, _mid, length = struct.unpack_from(">BBBBII", reply, 16)
    notifies, vids, chosen = [], [], None
    off, end = 28, min(len(reply), length)
    while nxt and off + 4 <= end:
        ptype = nxt
        nxt, _r, plen = struct.unpack_from(">BBH", reply, off)
        if plen < 4 or off + plen > end:
            break
        body = reply[off + 4:off + plen]
        if ptype == 11 and len(body) >= 8:
            notifies.append(_IKE1_NOTIFY.get(struct.unpack_from(">H", body, 6)[0],
                                             str(struct.unpack_from(">H", body, 6)[0])))
        elif ptype == 13:
            vids.append(body)
        elif ptype == 1 and len(body) >= 8 + 8 + 8:
            attrs = {}
            toff = 8 + 8 + 8         # DOI+situation, proposal header, transform header
            tlen = struct.unpack_from(">H", body, 8 + 8 + 2)[0]
            while toff + 4 <= 8 + 8 + tlen and toff + 4 <= len(body):
                atype, aval = struct.unpack_from(">HH", body, toff)
                if atype & 0x8000:
                    attrs[atype & 0x7FFF] = aval
                    toff += 4
                else:
                    toff += 4 + aval
            enc = _IKE1_ENC.get(attrs.get(1), str(attrs.get(1)))
            if attrs.get(14):
                enc += f"-{attrs[14]}"
            chosen = "/".join([enc, _IKE1_HASH.get(attrs.get(2), str(attrs.get(2))),
                               _IKE1_AUTH.get(attrs.get(3), str(attrs.get(3))),
                               _IKE1_GROUP.get(attrs.get(4), str(attrs.get(4)))])
        off += plen
    detail.update(responder_cookie=reply[8:16].hex(), exchange=exch,
                  responder_version=f"{version >> 4}.{version & 0xF}",
                  notifies=notifies, chosen_transform=chosen, vendor_ids=_vendor_ids(vids))
    if chosen:
        summary = f"IKEv1 responder answered Main Mode with transform {chosen}"
    else:
        summary = f"IKEv1 responder answered ({', '.join(notifies) or f'exchange {exch}'})"
    names = [v["name"] for v in detail["vendor_ids"] if v["name"]]
    if names:
        summary += f"; vendor: {', '.join(names)}"
    return ProbeResult("up", latency, summary, detail, None)


# --------------------------------------------------------------------------- #
#  WireGuard (whitepaper §5.4, "Noise_IKpsk2")                                 #
# --------------------------------------------------------------------------- #

_WG_CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
_WG_IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
_WG_LABEL_MAC1 = b"mac1----"
_WG_SILENT = ("no handshake response — WireGuard stays silent to keys it does not know: "
              "check that the monitoring peer's public key is configured on the server")
_WG_CERT_NOTE = "WireGuard has no certificates: peers authenticate with static keys"


def _wg_hash(*parts: bytes) -> bytes:
    h = hashlib.blake2s()
    for part in parts:
        h.update(part)
    return h.digest()


def _wg_hmac(key: bytes, data: bytes) -> bytes:
    # §5.4: HMAC over BLAKE2s (RFC 2104 construction, 64-byte block).
    return hmac.new(key, data, hashlib.blake2s).digest()


def _wg_kdf(key: bytes, data: bytes, n: int) -> list[bytes]:
    """HKDF as defined in §5.4: τ0 = HMAC(key, input), τi = HMAC(τ0, τi-1 || i)."""
    t0 = _wg_hmac(key, data)
    out, prev = [], b""
    for i in range(1, n + 1):
        prev = _wg_hmac(t0, prev + bytes([i]))
        out.append(prev)
    return out


def _wg_mac(key: bytes, data: bytes) -> bytes:
    # MAC(key, input) = Keyed-Blake2s(key, input, 16).
    return hashlib.blake2s(data, digest_size=16, key=key).digest()


def _wg_aead(key: bytes, counter: int, plain: bytes, ad: bytes) -> bytes:
    # 96-bit nonce: 32 zero bits then the 64-bit little-endian counter.
    return ChaCha20Poly1305(key).encrypt(b"\x00" * 4 + struct.pack("<Q", counter), plain, ad)


def _wg_open(key: bytes, counter: int, sealed: bytes, ad: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(b"\x00" * 4 + struct.pack("<Q", counter), sealed, ad)


def _wg_dh(private: X25519PrivateKey, public: bytes) -> bytes:
    return private.exchange(X25519PublicKey.from_public_bytes(public))


def _wg_tai64n() -> bytes:
    # TAI64N: 2^62 + 10 + Unix seconds (TAI offset as the reference
    # implementations apply it), then nanoseconds, both big-endian.
    now = time.time_ns()
    return struct.pack(">QI", 0x400000000000000A + now // 1_000_000_000, now % 1_000_000_000)


def _raw_public(private: X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)


def _wg_initiation(s_priv: X25519PrivateKey, s_pub_r: bytes) -> tuple[bytes, dict]:
    """Handshake initiation, message type 1 (§5.4.2). Returns (packet, state)."""
    s_pub_i = _raw_public(s_priv)
    c = _wg_hash(_WG_CONSTRUCTION)
    h = _wg_hash(c, _WG_IDENTIFIER)
    h = _wg_hash(h, s_pub_r)
    e_priv = X25519PrivateKey.generate()
    e_pub = _raw_public(e_priv)
    c = _wg_kdf(c, e_pub, 1)[0]
    h = _wg_hash(h, e_pub)
    c, k = _wg_kdf(c, _wg_dh(e_priv, s_pub_r), 2)
    enc_static = _wg_aead(k, 0, s_pub_i, h)
    h = _wg_hash(h, enc_static)
    c, k = _wg_kdf(c, _wg_dh(s_priv, s_pub_r), 2)
    enc_time = _wg_aead(k, 0, _wg_tai64n(), h)
    h = _wg_hash(h, enc_time)
    sender = os.urandom(4)
    msg = b"\x01\x00\x00\x00" + sender + e_pub + enc_static + enc_time
    # §5.4.4: mac1 keyed with HASH(LABEL_MAC1 || responder's static public key);
    # mac2 stays zero because we hold no cookie.
    mac1 = _wg_mac(_wg_hash(_WG_LABEL_MAC1, s_pub_r), msg)
    return msg + mac1 + b"\x00" * 16, {"c": c, "h": h, "e_priv": e_priv, "sender": sender}


def _wg_check_response(pkt: bytes, state: dict, s_priv: X25519PrivateKey,
                       psk: bytes) -> tuple[bool, str]:
    """Consume a type-2 response (§5.4.3) with the initiator's state."""
    if len(pkt) != 92 or pkt[0] != 2 or pkt[1:4] != b"\x00\x00\x00":
        return False, "not a handshake response"
    if pkt[8:12] != state["sender"]:
        return False, "response for another handshake"
    s_pub_i = _raw_public(s_priv)
    if not hmac.compare_digest(pkt[60:76], _wg_mac(_wg_hash(_WG_LABEL_MAC1, s_pub_i), pkt[:60])):
        return False, "mac1 of the response does not verify"
    e_pub_r = pkt[12:44]
    c, h = state["c"], state["h"]
    c = _wg_kdf(c, e_pub_r, 1)[0]
    h = _wg_hash(h, e_pub_r)
    try:
        c = _wg_kdf(c, _wg_dh(state["e_priv"], e_pub_r), 1)[0]
        c = _wg_kdf(c, _wg_dh(s_priv, e_pub_r), 1)[0]
    except ValueError:
        return False, "the responder's ephemeral key is invalid"
    c, tau, k = _wg_kdf(c, psk, 3)
    h = _wg_hash(h, tau)
    try:
        _wg_open(k, 0, pkt[44:60], h)
    except InvalidTag:
        return False, ("the response does not authenticate (wrong server key or "
                       "preshared key)")
    return True, "ok"


def wireguard_keypair() -> tuple[str, str]:
    """A fresh X25519 key pair as (private_b64, public_b64), WireGuard style."""
    private = X25519PrivateKey.generate()
    raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
    return base64.b64encode(raw).decode(), base64.b64encode(_raw_public(private)).decode()


def _probe_wireguard(t: dict, deadline: _Deadline, guard, warn_days: int) -> ProbeResult:
    s_pub_r = _parse_b64_key(t["server_public_key"], "server_public_key")
    s_priv = X25519PrivateKey.from_private_bytes(
        _parse_b64_key(t["client_private_key"], "client_private_key"))
    psk = _parse_b64_key(t["preshared_key"], "preshared_key") if t.get("preshared_key") \
        else b"\x00" * 32
    detail = {"client_public_key": base64.b64encode(_raw_public(s_priv)).decode(),
              "server_public_key": t["server_public_key"],
              "preshared_key_used": bool(t.get("preshared_key")),
              "cert_note": _WG_CERT_NOTE}
    host, port = t["host"], t["port"]
    sock = _open_udp(host, port, deadline, guard)
    states: dict[bytes, dict] = {}
    started = time.monotonic()
    failure = None
    try:
        interval = max(0.5, deadline.left() / 2)
        for _ in range(2):
            # Each retry is a FRESH initiation: the responder rejects a replayed
            # TAI64N timestamp (§5.1), so resending the same bytes is useless.
            msg, state = _wg_initiation(s_priv, s_pub_r)
            states[state["sender"]] = state
            sock.send(msg)
            window_end = min(time.monotonic() + interval, deadline.end)
            while time.monotonic() < window_end:
                sock.settimeout(max(0.01, window_end - time.monotonic()))
                try:
                    pkt = sock.recv(2048)
                except (TimeoutError, socket.timeout):
                    break
                except ConnectionRefusedError:
                    raise _Down(f"nothing listens on {host}:{port}/udp (port unreachable)",
                                detail) from None
                latency = _ms(time.monotonic() - started)
                if len(pkt) == 64 and pkt[0] == 3:
                    # A cookie reply (§5.4.7) proves the server knows its key and
                    # is alive but under load; it says nothing about our peer.
                    return ProbeResult("degraded", latency,
                                       "WireGuard answered with a cookie reply (server "
                                       "under load); handshake not completed", detail, None)
                state = states.get(pkt[8:12]) if len(pkt) >= 12 else None
                if state is None:
                    continue
                ok, why = _wg_check_response(pkt, state, s_priv, psk)
                if ok:
                    detail.update(sender_index=state["sender"].hex(),
                                  receiver_index=pkt[4:8].hex())
                    return ProbeResult("up", latency,
                                       f"WireGuard handshake completed in {latency:g} ms "
                                       "(response authenticated with the expected keys)",
                                       detail, None)
                failure = why
            if deadline.left() <= 0:
                break
    finally:
        sock.close()
    if failure:
        raise _Down(f"WireGuard answered but {failure}", detail)
    raise _Down(_WG_SILENT, detail)


# --------------------------------------------------------------------------- #
#  Dispatcher                                                                  #
# --------------------------------------------------------------------------- #

def _probe_https(t, deadline, guard, warn_days):
    return _probe_http("https", t, deadline, guard, warn_days)


def _probe_plain_http(t, deadline, guard, warn_days):
    return _probe_http("http", t, deadline, guard, warn_days)


_PROBES = {
    "http": _probe_plain_http,
    "https": _probe_https,
    "tls": _probe_tls,
    "tcp": _probe_tcp,
    "dns": _probe_dns,
    "ssh": _probe_ssh,
    "smtp": _probe_smtp,
    "sslvpn": _probe_sslvpn,
    "openvpn": _probe_openvpn,
    "ipsec": _probe_ipsec,
    "wireguard": _probe_wireguard,
}


def run(kind: str, target: dict, *, timeout: float = 10.0,
        guard=None, cert_warn_days: int = 21) -> ProbeResult:
    """Probe one service. Never raises: every failure is a :class:`ProbeResult`."""
    try:
        t = validate_target(kind, target)
    except ValueError as exc:
        return ProbeResult("error", None, f"invalid target: {exc}", {"kind": kind}, None)
    seconds = t.get("timeout") or timeout
    try:
        seconds = float(seconds)
        if not seconds > 0:
            raise ValueError
    except (TypeError, ValueError):
        return ProbeResult("error", None, "invalid timeout", {"kind": kind}, None)
    deadline = _Deadline(seconds)
    where = {"kind": kind, "host": t.get("host") or urlsplit(t.get("url", "")).hostname,
             "port": t.get("port")}
    try:
        result = _PROBES[kind](t, deadline, guard, cert_warn_days)
    except _Refused as exc:
        return ProbeResult("error", None, f"destination refused by guard: {exc}", where, None)
    except _Down as exc:
        result = ProbeResult("down", exc.latency_ms, exc.summary, exc.detail, exc.cert)
    except (TimeoutError, socket.timeout):
        result = ProbeResult("down", None, f"no answer within {seconds:g} s (timed out)", {}, None)
    except ConnectionRefusedError:
        result = ProbeResult("down", None, "connection refused: nothing listens on that port",
                             {}, None)
    except socket.gaierror as exc:
        result = ProbeResult("down", None, f"cannot resolve host: {exc.strerror or exc}",
                             {}, None)
    except ssl.SSLError as exc:
        result = ProbeResult("down", None, f"TLS error: {exc.reason or exc}", {}, None)
    except OSError as exc:
        result = ProbeResult("down", None, f"network error: {exc.strerror or exc}", {}, None)
    except Exception as exc:  # noqa: BLE001 -- a probe bug must not crash the scheduler
        return ProbeResult("error", None,
                           f"probe failed internally: {exc.__class__.__name__}: {exc}",
                           where, None)
    for key, value in where.items():
        result.detail.setdefault(key, value)
    return result
