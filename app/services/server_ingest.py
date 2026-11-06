"""The one gate every byte from a monitored server passes before SATOM uses it.

A server SATOM watches (the Servers ADOM: Linux and Windows hosts, with or
without ``satom-agent``) is not a Fortinet appliance with a vendor-signed
firmware. It is a machine whose administrator -- or whoever compromised it --
writes every byte SATOM reads back: process names, mount points, unit names,
query results. The connection only ever goes SATOM -> host, but the ANSWER
travels the other way, and the answer is the attack surface. This module is
where that answer stops being "bytes from a host" and becomes data.

What the gate does, in this order, and why:

1. **Size before parse.** A body over the collector's cap is refused before a
   single byte is decoded -- a 2 GB answer must not become a 2 GB string.
2. **Strict JSON, stdlib only.** UTF-8 that does not decode, the non-standard
   ``NaN`` / ``Infinity`` tokens, a key that appears twice in one object (two
   parsers disagree on which one wins), nesting deeper than
   :data:`MAX_DEPTH`, and integers longer than Python's digit limit are all
   refused. Never pickle, YAML or XML: nothing a host sends is ever a type.
3. **A closed schema per collector.** Every field has a type, a range or a
   length and, for names, a character set. ``True`` is not an integer and
   ``1`` is not a boolean (Python says otherwise; the gate does not). Text may
   not carry control characters or the Unicode bidi overrides that make a
   string read differently from what it is. Keys the schema does not name are
   dropped -- a newer agent may send more, SATOM keeps only what it knows.
4. **All or nothing.** One violation rejects the WHOLE payload. Nothing is
   "repaired": a repair is where a crafted value gets through, and a half
   accepted answer is a set of numbers nobody can vouch for.

What it deliberately does NOT do: decide that ``<script>`` is not a process
name. It can be one. The gate settles structure, type, range and character
set; the CONTEXT a value is printed into settles the encoding -- Jinja
autoescape for pages, :func:`plugin_frame.json_island` for script islands,
:func:`vm_store.escape_label` for the metrics store, ``csv_safe`` for exports.
No value that passed this gate is ever interpolated into a shell command, an
SQL statement or a filesystem path; actions come from SATOM's own catalog with
typed parameters.

And the limit nobody can lift: validation catches what is malformed or
hostile, not what is FALSE. A host that reports its disk at 10 % while it is
at 99 % passes every check here. Data from a server is therefore labelled as
reported by that server, never as measured by SATOM.

The verdict never raises and never echoes the payload. A rejection carries the
schema path and the rule broken (both written by SATOM) plus a short digest of
the raw body, so an operator can match it to the host's own log -- never the
offending value itself, which may be a secret or a payload aimed at whoever
reads the log.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any

#: Default cap on one answer, in bytes. A collector may lower it; nothing here
#: needs more than this (2 048 units of ~200 bytes each is ~400 KB).
MAX_PAYLOAD_BYTES = 1024 * 1024
#: Deepest nesting any schema needs is 4; anything past 8 is not a reading.
MAX_DEPTH = 8
#: Integers above this are not a byte count, a pid or a counter of anything.
MAX_INT = 2 ** 62

# C0 controls and DEL. Tab is a control too: no field here holds one.
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
# The same, minus tab, newline and carriage return: the controls a text FILE
# (a virtual host configuration) legitimately holds.
_CTRL_TEXT_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Bidi embeddings/overrides/isolates (the "Trojan Source" set) and the
# zero-width marks that make two identical-looking names different.
_BIDI_RE = re.compile("[​-‏‪-‮⁦-⁩﻿]")


class Rejected(Exception):
    """Internal: one rule broken at one path. Never leaves :func:`ingest`."""

    def __init__(self, path: str, rule: str):
        super().__init__("%s: %s" % (path or "$", rule))
        self.path = path or "$"
        self.rule = rule


@dataclass(frozen=True)
class Verdict:
    """What the gate decided. ``data`` is set only when ``ok``."""
    ok: bool
    data: Any = None
    reason: str = ""
    digest: str = ""
    dropped_keys: int = 0


# ── schema primitives ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Int:
    min: int = 0
    max: int = MAX_INT
    required: bool = True

    def check(self, v, path, ctx):
        if isinstance(v, bool) or not isinstance(v, int):
            raise Rejected(path, "expected an integer")
        if v < self.min or v > self.max:
            raise Rejected(path, "out of range [%d, %d]" % (self.min, self.max))
        return v


@dataclass(frozen=True)
class Num:
    min: float = 0.0
    max: float = float(MAX_INT)
    required: bool = True

    def check(self, v, path, ctx):
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise Rejected(path, "expected a number")
        if not math.isfinite(float(v)):
            raise Rejected(path, "not a finite number")
        if v < self.min or v > self.max:
            raise Rejected(path, "out of range [%g, %g]" % (self.min, self.max))
        return float(v)


@dataclass(frozen=True)
class Bool:
    required: bool = True

    def check(self, v, path, ctx):
        if not isinstance(v, bool):
            raise Rejected(path, "expected true or false")
        return v


@dataclass(frozen=True)
class Str:
    max_len: int = 256
    pattern: "str | None" = None
    choices: "tuple | None" = None
    min_len: int = 0
    required: bool = True
    #: A text file's content: tab, newline and carriage return are allowed;
    #: every other control character and the bidi marks still are not.
    multiline: bool = False

    def check(self, v, path, ctx):
        if not isinstance(v, str):
            raise Rejected(path, "expected a string")
        if len(v) > self.max_len or len(v) < self.min_len:
            raise Rejected(path, "length outside [%d, %d]" % (self.min_len, self.max_len))
        if (_CTRL_TEXT_RE if self.multiline else _CTRL_RE).search(v):
            raise Rejected(path, "control character")
        if _BIDI_RE.search(v):
            raise Rejected(path, "bidi or zero-width character")
        if self.choices is not None and v not in self.choices:
            raise Rejected(path, "not one of the allowed values")
        if self.pattern is not None and not re.fullmatch(self.pattern, v):
            raise Rejected(path, "characters outside the allowed set")
        return v


@dataclass(frozen=True)
class List:
    item: Any
    max_items: int = 256
    required: bool = True

    def check(self, v, path, ctx):
        if not isinstance(v, list):
            raise Rejected(path, "expected a list")
        if len(v) > self.max_items:
            raise Rejected(path, "more than %d items" % self.max_items)
        return [self.item.check(x, "%s[%d]" % (path, i), ctx) for i, x in enumerate(v)]


@dataclass(frozen=True)
class Obj:
    fields: dict
    #: ``(rule text, predicate)`` pairs over the validated object -- e.g.
    #: "used <= size". A predicate that raises counts as broken.
    checks: tuple = ()
    required: bool = True

    def check(self, v, path, ctx):
        if not isinstance(v, dict):
            raise Rejected(path, "expected an object")
        out = {}
        for name, spec in self.fields.items():
            sub = "%s.%s" % (path, name) if path else name
            if name not in v or v[name] is None:
                if spec.required:
                    raise Rejected(sub, "missing")
                continue
            out[name] = spec.check(v[name], sub, ctx)
        ctx["dropped"] += sum(1 for k in v if k not in self.fields)
        for rule, pred in self.checks:
            try:
                good = bool(pred(out))
            except Exception:  # noqa: BLE001 -- a crafted shape is a violation
                good = False
            if not good:
                raise Rejected(path, rule)
        return out


# ── parsing ───────────────────────────────────────────────────────────────────

def _no_constants(token):
    raise Rejected("", "non-standard JSON constant")


def _no_duplicates(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise Rejected("", "duplicate key")
        seen[k] = v
    return seen


def _depth(obj) -> int:
    """Nesting depth, iteratively (a recursive walk is itself the DoS)."""
    deepest, stack = 0, [(obj, 1)]
    while stack:
        cur, d = stack.pop()
        deepest = max(deepest, d)
        if deepest > MAX_DEPTH:
            return deepest
        if isinstance(cur, dict):
            stack.extend((x, d + 1) for x in cur.values())
        elif isinstance(cur, list):
            stack.extend((x, d + 1) for x in cur)
    return deepest


def digest(raw) -> str:
    """Short, stable id of a raw body for logs: never the body itself."""
    b = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode("utf-8", "replace")
    return hashlib.sha256(b).hexdigest()[:16]


def parse(raw, *, max_bytes: int = MAX_PAYLOAD_BYTES):
    """Bytes (or str) -> a JSON value, or :class:`Rejected`."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogatepass")
    if not isinstance(raw, (bytes, bytearray)):
        raise Rejected("", "not a byte body")
    if len(raw) > max_bytes:
        raise Rejected("", "body over %d bytes" % max_bytes)
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        raise Rejected("", "not valid UTF-8") from None
    try:
        obj = json.loads(text, parse_constant=_no_constants,
                         object_pairs_hook=_no_duplicates)
    except Rejected:
        raise
    except RecursionError:
        raise Rejected("", "nested deeper than %d" % MAX_DEPTH) from None
    except ValueError:
        # JSONDecodeError, and int() over Python's digit limit.
        raise Rejected("", "not valid JSON") from None
    if _depth(obj) > MAX_DEPTH:
        raise Rejected("", "nested deeper than %d" % MAX_DEPTH)
    return obj


def ingest(raw, schema, *, max_bytes: int = MAX_PAYLOAD_BYTES) -> Verdict:
    """The gate: parse, validate against ``schema``, all or nothing.

    Never raises. On rejection ``reason`` is ``"<path>: <rule>"`` -- both
    written by SATOM, never by the host."""
    dg = digest(raw if isinstance(raw, (bytes, bytearray, str)) else b"")
    ctx = {"dropped": 0}
    try:
        obj = parse(raw, max_bytes=max_bytes)
        data = schema.check(obj, "", ctx)
    except Rejected as exc:
        return Verdict(False, None, "%s: %s" % (exc.path, exc.rule), dg)
    except Exception:  # noqa: BLE001 -- the gate itself must not be a crash
        return Verdict(False, None, "$: unreadable answer", dg)
    return Verdict(True, data, "", dg, ctx["dropped"])


# ── the schemas of the Servers collectors ─────────────────────────────────────
# One per reading. The agent's API reference and the agentless parser both
# produce exactly these shapes; a field added on one side and not here is
# dropped, never trusted.

_BYTES = Int(0, MAX_INT)
_OPT_BYTES = Int(0, MAX_INT, required=False)
#: An absolute path as Linux prints a mount point: anything printable but
#: control characters (the Str rule) -- spaces are legal in a mount point.
_MOUNT = Str(max_len=512, min_len=1, pattern=r"/[^\x00]*")
_FSTYPE = Str(max_len=32, min_len=1, pattern=r"[a-z0-9][a-z0-9._+-]*")
#: POSIX portable user names plus the ``DOMAIN\\user`` and ``user@realm``
#: forms an SSSD/AD-joined host prints.
_USER = Str(max_len=64, min_len=1, pattern=r"[A-Za-z0-9_.@\\$-]+")
#: Linux ``comm`` is at most 15 bytes; Windows image names are longer. Any
#: printable text is a legal process name -- including ``<script>``.
_PNAME = Str(max_len=128, min_len=1)
_UNIT = Str(max_len=256, min_len=3,
            pattern=r"[A-Za-z0-9:_.@\\-]+\.(service|socket|timer|mount|path|target)")

MEMORY = Obj(
    {"total_bytes": Int(1, MAX_INT),
     "available_bytes": _BYTES,
     "swap_total_bytes": _OPT_BYTES,
     "swap_used_bytes": _OPT_BYTES},
    checks=(("available_bytes exceeds total_bytes",
             lambda d: d["available_bytes"] <= d["total_bytes"]),
            ("swap_used_bytes exceeds swap_total_bytes",
             lambda d: d.get("swap_used_bytes", 0) <= d.get("swap_total_bytes", 0)
             or "swap_total_bytes" not in d)),
)

FILESYSTEM = Obj(
    {"mount": _MOUNT, "fstype": _FSTYPE,
     "size_bytes": _BYTES, "used_bytes": _BYTES,
     "inodes_total": _OPT_BYTES, "inodes_used": _OPT_BYTES},
    checks=(("used_bytes exceeds size_bytes",
             lambda d: d["used_bytes"] <= d["size_bytes"]),
            ("inodes_used exceeds inodes_total",
             lambda d: d.get("inodes_used", 0) <= d.get("inodes_total", 0)
             or "inodes_total" not in d)),
)
FILESYSTEMS = Obj({"filesystems": List(FILESYSTEM, max_items=64)})

PROCESS = Obj(
    {"pid": Int(1, 2 ** 32), "user": _USER, "name": _PNAME,
     "state": Str(max_len=1, min_len=1, choices=tuple("RSDZTtIWXPK")),
     # One CPU is 100 %; a 4 096-thread host is the ceiling we accept.
     "cpu_pct": Num(0.0, 409600.0),
     "rss_bytes": _BYTES,
     # Off unless the operator switched it on for this host (passwords live in
     # command lines). Capped, and still subject to the control-char rule.
     "cmdline": Str(max_len=4096, required=False)},
)
PROCESSES = Obj(
    {"counts": Obj({"total": Int(0, 2 ** 32), "running": Int(0, 2 ** 32),
                    "sleeping": Int(0, 2 ** 32), "zombie": Int(0, 2 ** 32)},
                   checks=(("state counts exceed total",
                            lambda d: d["running"] + d["sleeping"] + d["zombie"]
                            <= d["total"]),)),
     "top": List(PROCESS, max_items=50)},
)

SERVICE = Obj(
    {"unit": _UNIT,
     "active": Str(max_len=16, choices=("active", "inactive", "failed", "activating",
                                        "deactivating", "reloading", "maintenance",
                                        "refreshing")),
     "sub": Str(max_len=32, min_len=1, pattern=r"[a-z][a-z-]*"),
     "enabled": Str(max_len=24, required=False,
                    choices=("enabled", "disabled", "static", "masked", "indirect",
                             "generated", "transient", "alias", "linked",
                             "enabled-runtime", "linked-runtime", "masked-runtime",
                             "bad"))},
)
SERVICES = Obj({"services": List(SERVICE, max_items=2048)})

#: Collector name -> schema. The only shapes a server answer can take.
SCHEMAS: "dict[str, Obj]" = {
    "memory": MEMORY,
    "filesystems": FILESYSTEMS,
    "processes": PROCESSES,
    "services": SERVICES,
}


# ── satom-webctl answers (Plugin Studio "server" connections) ────────────────
# One schema per operation of hostctl/satom-webctl.py, wrapped in the envelope
# {"ok", "result" | "error", "detail"}. satom-webctl leaves out of a listing
# any name the gate would refuse (control or bidi characters), so one hostile
# file name cannot make a folder impossible to browse.

#: The biggest file satom-webctl sends (its max_file_bytes cap, 4 MiB by
#: default) as base64, inside its envelope.
WEBCTL_MAX_ANSWER = 8 * 1024 * 1024
_HEX64 = Str(max_len=64, min_len=64, pattern=r"[0-9a-f]{64}")
_ABS = Str(max_len=1024, min_len=1, pattern=r"/[^\x00]*")
_REL = Str(max_len=1024, pattern=r"[^\x00]*")
_WEBSERVER = Str(max_len=8, choices=("nginx", "apache"))
_VHNAME = Str(max_len=100, min_len=1, pattern=r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
_HOSTNAME = Str(max_len=255, min_len=1, pattern=r"(\*\.)?[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}|_")
_BACKUP = Str(max_len=120, pattern=r"([0-9T]{15,30}-[a-z-]{4,20}-[0-9a-f]{8}\.tar\.gz)?",
              required=False)
_OUTPUT = Str(max_len=4000, multiline=True, required=False)
_OPT_BOOL = Bool(required=False)

_SERVER_INFO = Obj({"layout": Str(max_len=8, choices=("debian", "confd")),
                    "available": _ABS, "enabled": _REL}, required=False)
WEBCTL_INFO = Obj({
    "version": Str(max_len=32, min_len=1, pattern=r"[0-9][0-9.]{0,30}"),
    "servers": Obj({"nginx": _SERVER_INFO, "apache": _SERVER_INFO}),
    "roots": List(_ABS, max_items=32),
    "read_only": Bool(),
    "max_file_bytes": Int(0, 64 * 1024 * 1024),
    # satom-webctl 1.1.0+: where certificates live and whether they can be managed
    "cert_dir": Str(max_len=1024, pattern=r"(/[^\x00]*)?", required=False),
    "certs_ready": Bool(required=False),
    "openssl": Str(max_len=120, required=False),
})
WEBCTL_VHOST = Obj({
    "server": _WEBSERVER, "name": _VHNAME, "enabled": Bool(),
    "server_names": List(_HOSTNAME, max_items=50),
    "docroots": List(_ABS, max_items=20),
    "listen": List(Str(max_len=128), max_items=20),
    "ssl": Bool(), "bytes": Int(0, MAX_INT), "mtime": Int(0, MAX_INT),
    "managed_root": Bool(),
})
WEBCTL_VHOSTS = Obj({"vhosts": List(WEBCTL_VHOST, max_items=2000)})
WEBCTL_VHOST_GET = Obj({
    "server": _WEBSERVER, "name": _VHNAME, "enabled": Bool(),
    "content": Str(max_len=4 * 1024 * 1024, multiline=True), "sha256": _HEX64,
})
#: Every configuration write answers with a subset of these.
WEBCTL_APPLY = Obj({
    "applied": _OPT_BOOL, "restored": _OPT_BOOL, "restored_config_valid": _OPT_BOOL,
    "changed": _OPT_BOOL, "enabled": _OPT_BOOL, "deleted": _OPT_BOOL, "created": _OPT_BOOL,
    "docroot_created": _OPT_BOOL, "test_output": _OUTPUT, "reload_output": _OUTPUT,
    "backup": _BACKUP, "sha256": Str(max_len=64, pattern=r"[0-9a-f]{64}", required=False),
    "name": Str(max_len=100, pattern=r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", required=False),
    "docroot": Str(max_len=1024, pattern=r"/[^\x00]*", required=False),
})
WEBCTL_FILES = Obj({
    "docroot": _ABS, "path": _REL,
    "entries": List(Obj({"name": Str(max_len=255, min_len=1),
                         "type": Str(max_len=4, choices=("file", "dir", "link")),
                         "size": Int(0, MAX_INT), "mtime": Int(-2 ** 31, MAX_INT),
                         "mode": Str(max_len=4, min_len=1, pattern=r"[0-7]{1,4}")}),
                    max_items=5000),
    "truncated": Bool(), "skipped": Int(0, 2 ** 31, required=False),
})
WEBCTL_FILE = Obj({
    "path": _REL, "size": Int(0, 64 * 1024 * 1024), "sha256": _HEX64,
    "content_b64": Str(max_len=6 * 1024 * 1024, pattern=r"[A-Za-z0-9+/]*={0,2}",
                       required=False),
    # files.read with "text": true -- the file as text when it is text.
    "content": Str(max_len=4 * 1024 * 1024, multiline=True, required=False),
    "binary": Bool(required=False),
}, checks=(("a file answer carries content or content_b64, not both",
            lambda d: ("content" in d) != ("content_b64" in d)),))
WEBCTL_WRITTEN = Obj({"path": _REL, "size": Int(0, 64 * 1024 * 1024), "sha256": _HEX64,
                      "backup": _BACKUP})
WEBCTL_PATH = Obj({"path": _REL, "backup": _BACKUP})

# ── certificates (satom-webctl 1.1.0+). A private key never appears in any of
# these: the PEM fields admit certificates and requests, nothing else. ──
_CERTNAME = Str(max_len=64, min_len=1, pattern=r"[a-z0-9][a-z0-9._-]{0,63}")
_SAN = Str(max_len=253, min_len=1,
           pattern=r"(\*\.)?[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}|[0-9a-fA-F.:]{2,45}")
_CERT_TEXT = Str(max_len=200)
_PEM_CERTS = Str(max_len=96 * 1024, multiline=True,
                 pattern=r"(-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+"
                         r"-----END CERTIFICATE-----\n?)*")
_PEM_CSR = Str(max_len=16 * 1024, multiline=True,
               pattern=r"(-----BEGIN CERTIFICATE REQUEST-----\n[A-Za-z0-9+/=\n]+"
                       r"-----END CERTIFICATE REQUEST-----\n?)?")
CERT_STATUSES = ("valid", "expiring", "expired", "requested", "missing", "unreadable")
_CERT_FIELDS = {
    "name": Str(max_len=64, pattern=r"([a-z0-9][a-z0-9._-]{0,63})?"),  # "" = not managed
    "managed": Bool(), "path": _ABS, "key_path": _REL,
    "status": Str(max_len=12, choices=CERT_STATUSES),
    "subject": _CERT_TEXT, "issuer": _CERT_TEXT, "sans": List(_SAN, max_items=100),
    "not_before": Int(0, MAX_INT), "not_after": Int(0, MAX_INT),
    "days_left": Int(-10 ** 6, 10 ** 6),
    "serial": Str(max_len=64, pattern=r"[0-9a-f]*"),
    "sha256": Str(max_len=64, pattern=r"([0-9a-f]{64})?"),
    "self_signed": Bool(), "chain_length": Int(0, 64),
    "key_matches": Bool(required=False), "pending": Bool(),
    "used_by": List(Obj({"server": _WEBSERVER, "vhost": _VHNAME, "enabled": Bool()}),
                    max_items=100),
}
WEBCTL_CERT = Obj(_CERT_FIELDS)
WEBCTL_CERTS = Obj({"cert_dir": _ABS, "expiring_days": Int(0, 3650),
                    "certs": List(WEBCTL_CERT, max_items=500)})
WEBCTL_CERT_GET = Obj(dict(_CERT_FIELDS, certificate=_PEM_CERTS, csr=_PEM_CSR))
WEBCTL_CERT_CSR = Obj({
    "name": _CERTNAME, "csr": Str(max_len=16 * 1024, min_len=1, multiline=True,
                                  pattern=_PEM_CSR.pattern),
    "common_name": _HOSTNAME, "sans": List(_SAN, max_items=51),
    "key_type": Str(max_len=8, choices=("ec256", "ec384", "rsa2048", "rsa4096")),
    "renewal": Bool(), "backup": _BACKUP})
WEBCTL_CERT_INSTALL = Obj({
    "applied": _OPT_BOOL, "restored": _OPT_BOOL, "restored_config_valid": _OPT_BOOL,
    "test_output": _OUTPUT, "reload_output": _OUTPUT,
    "reloaded": List(_WEBSERVER, max_items=2), "name": _CERTNAME, "installed": Bool(),
    "renewal": Bool(), "not_after": Int(0, MAX_INT), "days_left": Int(-10 ** 6, 10 ** 6),
    "subject": _CERT_TEXT, "backup": _BACKUP})
WEBCTL_CERT_ASSIGN = Obj(dict(WEBCTL_APPLY.fields, cert=Str(
    max_len=64, pattern=r"[a-z0-9][a-z0-9._-]{0,63}", required=False)))
WEBCTL_CERT_DELETE = Obj({"name": _CERTNAME, "deleted": Bool(), "backup": _BACKUP})

#: satom-webctl operation -> (writes, schema of its result).
WEBCTL_OPS: "dict[str, tuple]" = {
    "info": (False, WEBCTL_INFO),
    "vhosts.list": (False, WEBCTL_VHOSTS),
    "vhost.get": (False, WEBCTL_VHOST_GET),
    "vhost.put": (True, WEBCTL_APPLY),
    "vhost.create": (True, WEBCTL_APPLY),
    "vhost.enable": (True, WEBCTL_APPLY),
    "vhost.disable": (True, WEBCTL_APPLY),
    "vhost.delete": (True, WEBCTL_APPLY),
    "files.list": (False, WEBCTL_FILES),
    "files.read": (False, WEBCTL_FILE),
    "files.write": (True, WEBCTL_WRITTEN),
    "files.mkdir": (True, WEBCTL_PATH),
    "files.rename": (True, WEBCTL_PATH),
    "files.delete": (True, WEBCTL_PATH),
    "certs.list": (False, WEBCTL_CERTS),
    "cert.get": (False, WEBCTL_CERT_GET),
    "cert.csr": (True, WEBCTL_CERT_CSR),
    "cert.install": (True, WEBCTL_CERT_INSTALL),
    "cert.assign": (True, WEBCTL_CERT_ASSIGN),
    "cert.delete": (True, WEBCTL_CERT_DELETE),
}


def webctl_envelope(op: str) -> Obj:
    """The whole answer of one satom-webctl call for ``op``."""
    return Obj({"ok": Bool(),
                "result": Obj(WEBCTL_OPS[op][1].fields, WEBCTL_OPS[op][1].checks,
                              required=False),
                "error": Str(max_len=32, pattern=r"[a-z_]{1,32}", required=False),
                "detail": Str(max_len=600, required=False)},
               checks=(("an answer is a result or an error",
                        lambda d: ("result" in d) == bool(d["ok"])
                        and (d["ok"] or "error" in d)),))



# ── Web Server Manager (satom-wsm, the session helper) ───────────────────────
# The helper answers ~80 operations; the ones it shares with satom-webctl keep
# their closed schemas above, the rest pass a strict GENERIC shape: objects
# with plain keys, lists, bounded text without control characters (tab,
# newline and carriage return allowed: logs and files are text) or bidi marks,
# bounded integers, finite numbers, booleans. Nothing a server sends becomes a
# type, and every value is printed through autoescape like any other.

_TREE_KEY_RE = re.compile(r"[A-Za-z0-9_.:@/+-]{1,80}")


@dataclass(frozen=True)
class Tree:
    max_str: int = 8 * 1024 * 1024
    max_items: int = 50000
    max_keys: int = 2000
    required: bool = True

    def check(self, v, path, ctx):
        if v is None:
            return None
        if isinstance(v, bool):
            return v
        if isinstance(v, int):
            if abs(v) > MAX_INT:
                raise Rejected(path, "integer out of range")
            return v
        if isinstance(v, float):
            if not math.isfinite(v):
                raise Rejected(path, "not a finite number")
            return v
        if isinstance(v, str):
            if len(v) > self.max_str:
                raise Rejected(path, "text longer than %d" % self.max_str)
            if _CTRL_TEXT_RE.search(v):
                raise Rejected(path, "control character")
            if _BIDI_RE.search(v):
                raise Rejected(path, "bidi or zero-width character")
            return v
        if isinstance(v, list):
            if len(v) > self.max_items:
                raise Rejected(path, "more than %d items" % self.max_items)
            return [self.check(x, "%s[%d]" % (path, i), ctx) for i, x in enumerate(v)]
        if isinstance(v, dict):
            if len(v) > self.max_keys:
                raise Rejected(path, "more than %d keys" % self.max_keys)
            out = {}
            for k, x in v.items():
                if not isinstance(k, str) or not _TREE_KEY_RE.fullmatch(k):
                    raise Rejected(path, "a key outside the allowed set")
                out[k] = self.check(x, "%s.%s" % (path, k) if path else k, ctx)
            return out
        raise Rejected(path, "unexpected type")


WSM_WHO = Obj({"user": Str(max_len=64), "uid": Int(0, 2 ** 32)}, required=False)
#: satom-webctl operations whose session answers have the agent's shape.
WSM_CLOSED = {op for op in WEBCTL_OPS if op not in ("vhost.create", "files.list", "files.read")}


def wsm_envelope(op: str) -> Obj:
    """The whole answer of one satom-wsm call for ``op``."""
    if op in WSM_CLOSED:
        result = Obj(WEBCTL_OPS[op][1].fields, WEBCTL_OPS[op][1].checks, required=False)
    else:
        result = Tree(required=False)
    return Obj({"ok": Bool(), "result": result,
                "error": Str(max_len=32, pattern=r"[a-z_]{1,32}", required=False),
                "detail": Str(max_len=600, multiline=True, required=False),
                "who": WSM_WHO},
               checks=(("an answer is a result or an error",
                        lambda d: ("result" in d) == bool(d["ok"])
                        and (d["ok"] or "error" in d)),))
