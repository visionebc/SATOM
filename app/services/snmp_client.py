"""SNMP v2c client — GET, GETNEXT, GETBULK and a bounded walk — on the standard
library alone.

Why hand-rolled: the venv carries no SNMP library and the offline bundles ship
exactly the wheels ``requirements.txt`` pins. Adding one for four PDU types
would put a new dependency into every installer, image and update package for
a codec that fits in a page. So this module encodes and decodes the subset of
BER that SNMPv2c uses (RFC 3416 / RFC 3417) and nothing more.

What it is NOT:

* **Not SNMPv3.** v3 needs the User Security Model (RFC 3414: HMAC
  authentication, DES/AES privacy, engine-id discovery and time windows). That
  is a separate piece of work; it arrives when a customer needs it, and the
  user guide says so.
* **Not a trap receiver.** Polling only: SATOM asks, the appliance answers.

Rules the collector relies on:

* The community string is never part of an exception message, a log line or a
  ``repr``: a failed poll must be reportable on a page without leaking the one
  secret the protocol has.
* Every decode step checks lengths before it indexes: a malformed or truncated
  datagram raises :class:`SnmpDecodeError`, it never raises ``IndexError`` or
  returns a half-parsed answer.
* A response is accepted only when its request-id matches: a late answer to an
  earlier, timed-out request is dropped, not mistaken for the current one.
* ``noSuchObject`` / ``noSuchInstance`` / ``endOfMibView`` decode to ``None``
  with the exception tag kept on the var-bind, so "the box does not have that
  OID" is distinguishable from "the box answered 0".
"""
from __future__ import annotations

import secrets
import socket
import time
from dataclasses import dataclass
from typing import Any

# ── BER tags ────────────────────────────────────────────────────────────────
T_INTEGER = 0x02
T_OCTET_STRING = 0x04
T_NULL = 0x05
T_OID = 0x06
T_SEQUENCE = 0x30
T_IPADDRESS = 0x40
T_COUNTER32 = 0x41
T_GAUGE32 = 0x42
T_TIMETICKS = 0x43
T_OPAQUE = 0x44
T_COUNTER64 = 0x46
T_NO_SUCH_OBJECT = 0x80
T_NO_SUCH_INSTANCE = 0x81
T_END_OF_MIB_VIEW = 0x82

PDU_GET = 0xA0
PDU_GETNEXT = 0xA1
PDU_RESPONSE = 0xA2
PDU_GETBULK = 0xA5

EXCEPTION_TAGS = {T_NO_SUCH_OBJECT: "noSuchObject",
                  T_NO_SUCH_INSTANCE: "noSuchInstance",
                  T_END_OF_MIB_VIEW: "endOfMibView"}
UNSIGNED_TAGS = (T_COUNTER32, T_GAUGE32, T_TIMETICKS, T_COUNTER64)

VERSION_2C = 1
MAX_DATAGRAM = 65535
#: Longest OID / string this codec will accept; anything bigger is a datagram
#: we did not ask for.
MAX_OCTETS = 4096

ERROR_STATUS = {0: "noError", 1: "tooBig", 2: "noSuchName", 3: "badValue",
                4: "readOnly", 5: "genErr", 6: "noAccess", 7: "wrongType",
                8: "wrongLength", 9: "wrongEncoding", 10: "wrongValue",
                11: "noCreation", 12: "inconsistentValue",
                13: "resourceUnavailable", 14: "commitFailed",
                15: "undoFailed", 16: "authorizationError",
                17: "notWritable", 18: "inconsistentName"}


class SnmpError(Exception):
    """Base class. Messages never carry the community string."""


class SnmpTimeout(SnmpError):
    """No answer within the timeout, after every retry."""


class SnmpDecodeError(SnmpError):
    """The datagram is not the BER we expected (truncated, wrong tag, oversize)."""


class SnmpResponseError(SnmpError):
    """The agent answered with a non-zero error-status."""

    def __init__(self, status: int, index: int):
        self.status, self.index = status, index
        super().__init__("agent error %s (index %d)"
                         % (ERROR_STATUS.get(status, str(status)), index))


@dataclass
class VarBind:
    oid: str
    tag: int
    value: Any

    @property
    def exception(self) -> str:
        """``noSuchObject`` / ``noSuchInstance`` / ``endOfMibView`` or ''."""
        return EXCEPTION_TAGS.get(self.tag, "")


# ── encoding ────────────────────────────────────────────────────────────────

def encode_length(n: int) -> bytes:
    if n < 0:
        raise SnmpDecodeError("negative length")
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(body)) + body


def encode_integer(value: int) -> bytes:
    """Two's-complement INTEGER, minimal length (BER)."""
    value = int(value)
    if value == 0:
        return tlv(T_INTEGER, b"\x00")
    n = (value.bit_length() + 8) // 8   # one extra bit for the sign
    return tlv(T_INTEGER, value.to_bytes(n, "big", signed=True))


def encode_unsigned(tag: int, value: int) -> bytes:
    value = int(value)
    if value < 0:
        raise SnmpDecodeError("unsigned value below zero")
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body   # keep the sign bit clear
    return tlv(tag, body)


def encode_octets(value) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return tlv(T_OCTET_STRING, bytes(value))


def encode_oid(oid: str) -> bytes:
    parts = [p for p in str(oid).strip().strip(".").split(".") if p != ""]
    try:
        ids = [int(p) for p in parts]
    except ValueError:
        raise SnmpDecodeError("OID %r is not dotted-decimal" % oid) from None
    if len(ids) < 2 or ids[0] > 2 or ids[1] > 39 or any(i < 0 for i in ids):
        raise SnmpDecodeError("OID %r is not a valid object identifier" % oid)
    out = bytearray([40 * ids[0] + ids[1]])
    for sub in ids[2:]:
        if sub < 0x80:
            out.append(sub)
            continue
        chunk = [sub & 0x7F]
        sub >>= 7
        while sub:
            chunk.append(0x80 | (sub & 0x7F))
            sub >>= 7
        out.extend(reversed(chunk))
    return tlv(T_OID, bytes(out))


def encode_null() -> bytes:
    return tlv(T_NULL, b"")


def _pdu(pdu_tag: int, request_id: int, a: int, b: int, oids) -> bytes:
    vbs = b"".join(tlv(T_SEQUENCE, encode_oid(o) + encode_null()) for o in oids)
    body = (encode_integer(request_id) + encode_integer(a) + encode_integer(b)
            + tlv(T_SEQUENCE, vbs))
    return tlv(pdu_tag, body)


def build_message(community: str, pdu: bytes) -> bytes:
    return tlv(T_SEQUENCE, encode_integer(VERSION_2C) + encode_octets(community) + pdu)


def build_get(community: str, oids, request_id: int, *, next_: bool = False) -> bytes:
    """A GetRequest (or GetNextRequest with ``next_``) for ``oids``."""
    return build_message(community, _pdu(PDU_GETNEXT if next_ else PDU_GET,
                                         request_id, 0, 0, oids))


def build_getbulk(community: str, oids, request_id: int, *,
                  non_repeaters: int = 0, max_repetitions: int = 25) -> bytes:
    return build_message(community, _pdu(PDU_GETBULK, request_id,
                                         non_repeaters, max_repetitions, oids))


# ── decoding ────────────────────────────────────────────────────────────────

def decode_tlv(buf: bytes, pos: int = 0) -> tuple[int, bytes, int]:
    """``(tag, body, next_pos)`` of the element at ``pos``; every byte checked."""
    if pos + 2 > len(buf):
        raise SnmpDecodeError("truncated element at %d" % pos)
    tag = buf[pos]
    first = buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4:
            raise SnmpDecodeError("unsupported length encoding at %d" % pos)
        if pos + n > len(buf):
            raise SnmpDecodeError("truncated length at %d" % pos)
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    if length > MAX_DATAGRAM or pos + length > len(buf):
        raise SnmpDecodeError("element at %d claims %d bytes, %d remain"
                              % (pos, length, len(buf) - pos))
    return tag, buf[pos:pos + length], pos + length


def decode_integer(body: bytes) -> int:
    if not body or len(body) > 9:
        raise SnmpDecodeError("INTEGER of %d bytes" % len(body))
    return int.from_bytes(body, "big", signed=True)


def decode_unsigned(body: bytes) -> int:
    if not body or len(body) > 9:
        raise SnmpDecodeError("unsigned of %d bytes" % len(body))
    return int.from_bytes(body, "big", signed=False)


def decode_oid(body: bytes) -> str:
    if not body:
        raise SnmpDecodeError("empty OID")
    if len(body) > MAX_OCTETS:
        raise SnmpDecodeError("OID of %d bytes" % len(body))
    first = body[0]
    ids = [first // 40, first % 40] if first < 80 else [2, first - 80]
    cur = 0
    pending = False
    for b in body[1:]:
        cur = (cur << 7) | (b & 0x7F)
        pending = True
        if cur > 0xFFFFFFFF:
            raise SnmpDecodeError("sub-identifier overflow")
        if not b & 0x80:
            ids.append(cur)
            cur, pending = 0, False
    if pending:
        raise SnmpDecodeError("OID ends inside a sub-identifier")
    return ".".join(str(i) for i in ids)


def decode_value(tag: int, body: bytes) -> Any:
    if tag == T_INTEGER:
        return decode_integer(body)
    if tag in UNSIGNED_TAGS:
        return decode_unsigned(body)
    if tag in (T_OCTET_STRING, T_OPAQUE):
        if len(body) > MAX_OCTETS:
            raise SnmpDecodeError("string of %d bytes" % len(body))
        return body.decode("utf-8", "replace")
    if tag == T_OID:
        return decode_oid(body)
    if tag == T_IPADDRESS:
        if len(body) != 4:
            raise SnmpDecodeError("IpAddress of %d bytes" % len(body))
        return ".".join(str(b) for b in body)
    if tag == T_NULL or tag in EXCEPTION_TAGS:
        return None
    raise SnmpDecodeError("unknown value tag 0x%02x" % tag)


def _children(body: bytes) -> list[tuple[int, bytes]]:
    out, pos = [], 0
    while pos < len(body):
        tag, child, pos = decode_tlv(body, pos)
        out.append((tag, child))
    return out


def parse_response(data: bytes) -> tuple[int, int, int, list[VarBind]]:
    """``(request_id, error_status, error_index, var_binds)`` of a v2c Response.

    Raises :class:`SnmpDecodeError` for anything that is not one.
    """
    if len(data) > MAX_DATAGRAM:
        raise SnmpDecodeError("datagram of %d bytes" % len(data))
    tag, msg, end = decode_tlv(data, 0)
    if tag != T_SEQUENCE:
        raise SnmpDecodeError("message is not a SEQUENCE")
    parts = _children(msg)
    if len(parts) != 3:
        raise SnmpDecodeError("message has %d parts, expected 3" % len(parts))
    (vtag, vbody), (ctag, _community), (ptag, pbody) = parts
    if vtag != T_INTEGER or decode_integer(vbody) != VERSION_2C:
        raise SnmpDecodeError("not an SNMPv2c message")
    if ctag != T_OCTET_STRING:
        raise SnmpDecodeError("community is not an OCTET STRING")
    if ptag != PDU_RESPONSE:
        raise SnmpDecodeError("PDU tag 0x%02x is not a Response" % ptag)
    fields = _children(pbody)
    if len(fields) != 4:
        raise SnmpDecodeError("PDU has %d fields, expected 4" % len(fields))
    (rtag, rbody), (stag, sbody), (itag, ibody), (btag, bbody) = fields
    if rtag != T_INTEGER or stag != T_INTEGER or itag != T_INTEGER:
        raise SnmpDecodeError("PDU header fields are not INTEGERs")
    if btag != T_SEQUENCE:
        raise SnmpDecodeError("var-bind list is not a SEQUENCE")
    binds: list[VarBind] = []
    for btag2, bb in _children(bbody):
        if btag2 != T_SEQUENCE:
            raise SnmpDecodeError("var-bind is not a SEQUENCE")
        pair = _children(bb)
        if len(pair) != 2 or pair[0][0] != T_OID:
            raise SnmpDecodeError("var-bind is not (OID, value)")
        oid = decode_oid(pair[0][1])
        vtag2, vbody2 = pair[1]
        binds.append(VarBind(oid, vtag2, decode_value(vtag2, vbody2)))
    return (decode_integer(rbody), decode_integer(sbody), decode_integer(ibody), binds)


def oid_in_subtree(oid: str, base: str) -> bool:
    return oid == base or oid.startswith(base.rstrip(".") + ".")


# ── client ──────────────────────────────────────────────────────────────────

class SnmpClient:
    """One agent: ``host:port`` + community. Every call opens its own socket."""

    def __init__(self, host: str, community: str, port: int = 161, *,
                 timeout: float = 2.0, retries: int = 1):
        self.host = str(host)
        self.port = int(port or 161)
        self._community = str(community or "")
        self.timeout = float(timeout)
        self.retries = max(0, int(retries))

    def __repr__(self) -> str:   # the community is deliberately absent
        return "<SnmpClient %s:%d>" % (self.host, self.port)

    # -- transport --------------------------------------------------------
    def _exchange(self, payload: bytes, request_id: int):
        """Send, wait, decode; retry on timeout; ignore answers to other ids."""
        last_exc: Exception | None = None
        for _attempt in range(self.retries + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(self.timeout)
                sock.sendto(payload, (self.host, self.port))
                deadline = time.monotonic() + self.timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise socket.timeout()
                    sock.settimeout(remaining)
                    data, _peer = sock.recvfrom(MAX_DATAGRAM)
                    rid, status, index, binds = parse_response(data)
                    if rid != request_id:
                        continue   # a stale answer to an earlier request
                    if status:
                        raise SnmpResponseError(status, index)
                    return binds
            except socket.timeout:
                last_exc = SnmpTimeout("no answer from %s:%d within %.1f s"
                                       % (self.host, self.port, self.timeout))
            except OSError as exc:
                raise SnmpError("socket error towards %s:%d: %s"
                                % (self.host, self.port, exc.__class__.__name__)) from None
            finally:
                sock.close()
        raise last_exc or SnmpTimeout("no answer")

    @staticmethod
    def _rid() -> int:
        return secrets.randbelow(0x7FFFFFFE) + 1

    # -- operations -------------------------------------------------------
    def get(self, oids) -> list[VarBind]:
        oids = list(oids)
        if not oids:
            return []
        rid = self._rid()
        return self._exchange(build_get(self._community, oids, rid), rid)

    def get_values(self, oids) -> dict[str, Any]:
        """``{oid: value}``; an OID the agent lacks maps to ``None``."""
        return {vb.oid: vb.value for vb in self.get(oids)}

    def get_next(self, oids) -> list[VarBind]:
        rid = self._rid()
        return self._exchange(build_get(self._community, list(oids), rid, next_=True), rid)

    def get_bulk(self, oids, *, max_repetitions: int = 25,
                 non_repeaters: int = 0) -> list[VarBind]:
        rid = self._rid()
        return self._exchange(build_getbulk(self._community, list(oids), rid,
                                            non_repeaters=non_repeaters,
                                            max_repetitions=max_repetitions), rid)

    def walk(self, base: str, *, max_rows: int = 512,
             max_repetitions: int = 25) -> list[VarBind]:
        """Every var-bind under ``base`` (GETBULK, bounded by ``max_rows``).

        Stops at the first OID outside the subtree, at ``endOfMibView``, when
        the agent stops advancing, or at the row bound — whichever first.
        """
        base = str(base).strip(".")
        out: list[VarBind] = []
        cursor = base
        while len(out) < max_rows:
            binds = self.get_bulk([cursor], max_repetitions=max_repetitions)
            if not binds:
                break
            advanced = False
            for vb in binds:
                if vb.exception == "endOfMibView" or not oid_in_subtree(vb.oid, base):
                    return out
                if vb.oid == cursor:
                    continue   # the agent did not advance: stop, do not loop
                out.append(vb)
                cursor, advanced = vb.oid, True
                if len(out) >= max_rows:
                    break
            if not advanced:
                break
        return out


def table_index(oid: str, column: str) -> str:
    """The row index of ``oid`` under table column ``column`` ('' if not under it)."""
    column = column.strip(".")
    if not oid.startswith(column + "."):
        return ""
    return oid[len(column) + 1:]
