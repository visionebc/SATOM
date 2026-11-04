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

    def check(self, v, path, ctx):
        if not isinstance(v, str):
            raise Rejected(path, "expected a string")
        if len(v) > self.max_len or len(v) < self.min_len:
            raise Rejected(path, "length outside [%d, %d]" % (self.min_len, self.max_len))
        if _CTRL_RE.search(v):
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
