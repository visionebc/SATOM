"""Write the fields only the CLI serves, over SSH, and prove they landed.

SATOM writes configuration through REST. Some settings exist only in the CLI
on some builds (the API library classifies them ``cli_only`` or ``hidden`` per
EXACT build — :func:`api_library.channels_at`). This module is the path for
those fields and ONLY those fields:

* :func:`split_payload` is the gate every flow calls first. A field goes to
  the CLI only when the library classifies it ``cli_only``/``hidden`` on the
  appliance's exact build; ``both``/``rest_only`` go to REST (the existing
  clients); anything the build does not know, or nobody measured, is refused
  with the reason. Measured on FortiWeb 7.6.8 and 8.0.6 there are no
  CLI-only fields at all, so on those builds everything routes to REST — that
  is the correct answer, not a gap.
* :class:`CliWriter` renders and runs ONE object's change as a CLI
  transaction (``config`` / ``edit`` / ``set`` / ``unset`` / ``next`` /
  ``end``), stops at the first error the box prints and discards the pending
  change with ``abort`` instead of committing it, then reads the object back
  in a FRESH session with ``show full-configuration`` (parsed by
  :func:`cli_schema.parse_show_full_values`). Every written field must read
  back equal or the result is failed with the diff. When the object also has
  a REST path that serves, REST is read back too.

THIS IS NOT A WIDENING OF THE READ-ONLY CONSOLE. ``ssh_ops.assert_readonly``
is untouched; the write session here is :class:`ssh_console.FortiWriteSSH`
(the one write-capable SSH class, with its own deny-list gate, which every
line still passes) and the readback uses the read-only session with a plain
``show``.

Measured on fortiweb18 (FortiWeb-KVM 8.0.6 build0116, 2026-10-07), recorded in
/srv/satom-kb/lab/phase6/:

* ``abort`` inside an ``edit`` discards that row and leaves its table: in a
  nested row it returns to the parent row, at a top-level row to the root.
  Inside a singleton ``config`` it discards and returns to the root.
* ``abort`` at a TABLE level with no open row is a parse error; ``end`` there
  closes the table. A sub-table closed with ``end`` and then the parent row
  aborted leaves nothing behind: the change is committed only by the
  top-level ``next``/``end``.
* A row that fails validation fails on ``next`` (``Command fail. Invalid IP
  address.``) and the CLI has already left the row — the prompt is the only
  reliable position, so the writer resyncs on it after every line.
* ``edit 0`` in a sub-table creates the next free id; the prompt names it.
* ``show full-configuration`` in the SAME session after writes sometimes
  prints the block with no ``set`` lines at all (seen twice, not reproducible
  on demand). The readback therefore runs in a NEW session and treats a row
  with no lines as unreadable (retried), never as "every field is empty".
* Escaping in output: ``"`` -> ``\\"``, ``'`` -> ``\\'``, ``\\`` -> ``\\\\``.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from . import cli_schema, job_progress
from .ssh_console import (ConsoleViolation, FortiWriteSSH, REDACTED, TIER_SAFE,
                          assert_console_command, classify_command, classify_output,
                          redact)
from .ssh_ops import FortiSSHError, FortiWebReadonlySSH, _ANSI

# --------------------------------------------------------------------------- #
#  Dialects                                                                    #
# --------------------------------------------------------------------------- #
#: Per product: does ``abort`` discard a pending edit, may ``?`` be typed
#: inside a quoted value, and on what build was that verified. A product not
#: listed here has no CLI writer at all.
DIALECTS: dict[str, dict] = {
    "fortiweb": {"abort": True, "question_mark": True,
                 "verified": "FortiWeb-KVM 8.0.6 build0116 (lab fortiweb18, 2026-10-07)"},
    # FortiOS-family CLIs document ``abort`` the same way; NOT verified on a
    # box by this writer yet, and ``?`` there opens context help even inside
    # quotes, so it is refused.
    "fortigate": {"abort": True, "question_mark": False, "verified": ""},
    "fortiauthenticator": {"abort": True, "question_mark": False, "verified": ""},
    "fortiadc": {"abort": True, "question_mark": False, "verified": ""},
}

#: Channels a field may be written by CLI on.
CLI_CHANNELS = frozenset({"cli_only", "hidden"})
REST_CHANNELS = frozenset({"both", "rest_only"})

#: Prefix every object created or changed under the lab bypass must carry.
LAB_PREFIX = "lab-"


class CliWriteRefused(Exception):
    """The write was refused before anything was sent."""


class CliValueError(CliWriteRefused):
    """A value cannot be typed into the CLI safely."""


# --------------------------------------------------------------------------- #
#  Reading the box's answer                                                    #
# --------------------------------------------------------------------------- #
#: Specific error patterns, first match wins. The ids are what the result and
#: the audit row carry (the raw line can hold the rejected value, which may be
#: a secret). ``Return code`` only when NEGATIVE (FortiOS prints 0 on success).
ERROR_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("node_check_object_fail", re.compile(r"node_check_object fail", re.I)),
    ("value_parse_error", re.compile(r"value parse error", re.I)),
    ("parse_error", re.compile(r"Parsing error at|command parse error", re.I)),
    ("entry_not_found", re.compile(r"entry '[^'\n]*' (?:is )?not found|entry (?:is )?not found|"
                                   r"Entry '[^'\n]*' is not found", re.I)),
    ("out_of_range", re.compile(r"out of range|value check fail", re.I)),
    ("must_be_set", re.compile(r"MUST be set|must be set", re.I)),
    ("return_code", re.compile(r"(?:Return|error) code\s*:?\s*(-\d+)", re.I)),
    ("unknown_action", re.compile(r"Unknown action", re.I)),
    ("permission_denied", re.compile(r"permission denied", re.I)),
    ("in_use", re.compile(r"The (?:object|entry) is (?:in use|used)", re.I)),
    ("invalid_value", re.compile(r"\bInvalid\b|is invalid\b", re.I)),
    ("command_fail", re.compile(r"Command fail", re.I)),
)
_RC = re.compile(r"(?:Return|error) code\s*:?\s*(-\d+)", re.I)


def detect_error(output: str) -> dict | None:
    """``{"pattern", "line", "code"}`` for the first CLI error in ``output``.

    Falls back to :func:`ssh_console.classify_output` (the console's own
    markers), so a marker either module knows is an error here.
    """
    text = _ANSI.sub("", output or "").replace("\r", "")
    for pid, pat in ERROR_PATTERNS:
        m = pat.search(text)
        if m:
            line = next((ln.strip() for ln in text.splitlines() if pat.search(ln)), "")
            rc = _RC.search(text)
            return {"pattern": pid, "line": line[:300], "code": rc.group(1) if rc else ""}
    status, detail = classify_output(text)
    if status == "error":
        return {"pattern": detail.replace(" ", "_") or "error", "line": text.strip()[:300],
                "code": ""}
    return None


# --------------------------------------------------------------------------- #
#  Quoting                                                                     #
# --------------------------------------------------------------------------- #
_NEEDS_QUOTES = re.compile(r"""[\s"'\\#;|&?<>(){}]""")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def cli_token(value: Any, *, product: str = "fortiweb") -> str:
    """One value as ONE CLI token: bare when safe, else double-quoted with
    ``\\`` and ``"`` escaped. Refuses what cannot be typed into an
    interactive shell: control characters (a newline would be a second
    command, a tab a completion) and, where the dialect reads it as help,
    ``?``."""
    if isinstance(value, bool):
        value = "enable" if value else "disable"
    s = "" if value is None else str(value)
    if _CONTROL.search(s):
        raise CliValueError("a value holds a control character (newline/tab); the CLI "
                            "would read it as another command — refused")
    if "?" in s and not DIALECTS.get(product, {}).get("question_mark"):
        raise CliValueError("a value holds '?', which the %s CLI reads as a help request "
                            "even inside quotes — refused" % product)
    if s and not _NEEDS_QUOTES.search(s):
        return s
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def cli_value(value: Any, *, product: str = "fortiweb") -> str:
    """A field value: a list/tuple is a multi-value field (one token each)."""
    if isinstance(value, (list, tuple)):
        if not value:
            raise CliValueError("an empty list is not a value; use unset")
        return " ".join(cli_token(v, product=product) for v in value)
    return cli_token(value, product=product)


def _unescape(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s)


def _tokens(raw: str) -> list:
    """Split a raw CLI value (as printed) into tokens, honouring quotes."""
    out, cur, q, esc, have = [], [], False, False, False
    for ch in raw or "":
        if esc:
            cur.append(ch)
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            q = not q
            have = True
            continue
        if ch.isspace() and not q:
            if cur or have:
                out.append("".join(cur))
            cur, have = [], False
            continue
        cur.append(ch)
    if cur or have:
        out.append("".join(cur))
    return out


_SECRET_NAME = re.compile(r"(pass|secret|psk|private|token|key$|-key\b|credential)", re.I)


def is_secret(name: str, attrs: dict | None = None) -> bool:
    cli_type = str((attrs or {}).get("cli_type") or "")
    return "passwd" in cli_type or bool(_SECRET_NAME.search(name or ""))


# --------------------------------------------------------------------------- #
#  The plan                                                                    #
# --------------------------------------------------------------------------- #
@dataclass
class CliLevel:
    """One ``config`` (+ ``edit``) step on the way to the object.

    ``words`` are relative to the previous level (the first level carries the
    namespaces: ``server-policy server-pool``). ``mkey`` is None for a
    singleton; ``"0"`` in a sub-table asks the box for the next free id."""
    words: str
    mkey: str | None = None
    kind: str = cli_schema.KIND_TABLE


@dataclass
class CliChild:
    """A row of a sub-table changed in the same transaction as its parent."""
    words: str
    mkey: str
    set: dict = field(default_factory=dict)
    unset: list = field(default_factory=list)
    delete: bool = False


@dataclass
class CliPlan:
    product: str
    levels: list
    set: dict = field(default_factory=dict)
    unset: list = field(default_factory=list)
    children: list = field(default_factory=list)
    delete: bool = False              # delete the innermost object (table row)
    endpoint: str = ""                # REST key (``server-policy/server-pool``)
    secret_fields: frozenset = frozenset()
    gated: bool = False               # every field was approved by split_payload
    lab_bypass: bool = False          # the channel gate was skipped (lab only)
    allow_disruptive: bool = False    # passed to the console gate
    rest_readback: bool = True        # the endpoint's REST path serves (library verdict ok)

    @property
    def cli_path(self) -> str:
        return " ".join(lv.words for lv in self.levels)

    @property
    def target(self) -> CliLevel:
        return self.levels[-1]

    def field_names(self) -> list:
        names = list(self.set) + list(self.unset)
        for ch in self.children:
            names += ["%s[%s].%s" % (ch.words, ch.mkey, n) for n in list(ch.set) + list(ch.unset)]
        return names


def _check_plan(plan: CliPlan) -> None:
    if plan.product not in DIALECTS:
        raise CliWriteRefused("no CLI writer for %s" % (plan.product or "this product"))
    if not plan.levels or not plan.levels[0].words.strip():
        raise CliWriteRefused("the plan names no CLI object")
    if not (plan.set or plan.unset or plan.children or plan.delete):
        raise CliWriteRefused("nothing to write")
    if plan.delete and (plan.set or plan.unset or plan.children):
        raise CliWriteRefused("a delete carries no fields")
    if plan.delete and plan.target.mkey in (None, ""):
        raise CliWriteRefused("only a table row can be deleted")
    for i, lv in enumerate(plan.levels):
        if lv.kind == cli_schema.KIND_TABLE and lv.mkey in (None, ""):
            raise CliWriteRefused("table %r needs a row key" % lv.words)
    names = list(plan.set) + list(plan.unset)
    for ch in plan.children:
        names += list(ch.set) + list(ch.unset)
    for n in names:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.\-]*", str(n)):
            raise CliWriteRefused("%r is not a CLI field name" % (n,))
    if plan.lab_bypass:
        for lv in plan.levels[:1]:
            if lv.kind == cli_schema.KIND_TABLE and not str(lv.mkey).startswith(LAB_PREFIX):
                raise CliWriteRefused("the lab bypass writes only %s* objects; refused %r"
                                      % (LAB_PREFIX, lv.mkey))
    elif not plan.gated:
        raise CliWriteRefused("this plan was not approved by split_payload (the channel "
                              "gate); only CLI-only/hidden fields of this build go by CLI")


def render_script(plan: CliPlan, *, mask_secrets: bool = True) -> list:
    """The CLI lines of ``plan``, indented for reading. With ``mask_secrets``
    the value of every secret field is replaced (preview/transcript form)."""
    p = plan.product

    def _val(name, value):
        if mask_secrets and name in plan.secret_fields:
            return REDACTED
        return cli_value(value, product=p)

    out: list = []
    depth = 0

    def emit(line):
        out.append("  " * depth + line)

    last = len(plan.levels) - 1
    for i, lv in enumerate(plan.levels):
        if plan.delete and i == last:
            emit("config " + lv.words)
            depth += 1
            emit("delete " + cli_token(lv.mkey, product=p))
            depth -= 1
            emit("end")
            break
        emit("config " + lv.words)
        depth += 1
        if lv.mkey is not None:
            emit("edit " + cli_token(lv.mkey, product=p))
            depth += 1
    if not plan.delete:
        for name, value in plan.set.items():
            emit("set %s %s" % (name, _val(name, value)))
        for name in plan.unset:
            emit("unset %s" % name)
        for ch in plan.children:
            emit("config " + ch.words)
            depth += 1
            if ch.delete:
                emit("delete " + cli_token(ch.mkey, product=p))
            else:
                emit("edit " + cli_token(ch.mkey, product=p))
                depth += 1
                for name, value in ch.set.items():
                    emit("set %s %s" % (name, _val(name, value)))
                for name in ch.unset:
                    emit("unset %s" % name)
                depth -= 1
                emit("next")
            depth -= 1
            emit("end")
    # close the levels opened above (the delete branch closed its own)
    opened = plan.levels[:-1] if plan.delete else plan.levels
    for lv in reversed(opened):
        if lv.mkey is not None:
            depth -= 1
            emit("next")
        depth -= 1
        emit("end")
    return out


# --------------------------------------------------------------------------- #
#  The session                                                                 #
# --------------------------------------------------------------------------- #
# A prompt at the end of the buffer: ``host # `` or ``host (context) # ``. The
# context may hold spaces (``edit "lab x"`` prompts ``(lab x)``).
_PROMPT = re.compile(r"(?:^|\n)(?P<host>[\w.\-]+) (?:\((?P<ctx>[^\n]*)\) )?# ?$")


def prompt_context(buf: str):
    """``(seen, context)`` of the prompt ending ``buf``; context None = root."""
    text = _ANSI.sub("", buf or "").replace("\r", "").rstrip(" ")
    m = _PROMPT.search(text)
    if not m:
        return False, None
    return True, m.group("ctx")


class CliWriteSession(FortiWriteSSH):
    """The write session: :class:`ssh_console.FortiWriteSSH` (connection,
    host-key pinning, pager, the console's deny-list gate) plus a read that
    ends on the PROMPT, so every line's answer and position are known."""

    def send_line(self, command: str, *, allow_disruptive: bool = False,
                  maxt: float = 30.0) -> tuple:
        """Send one line; ``(output, prompt_seen, context)``."""
        command = assert_console_command(command, allow_disruptive=allow_disruptive)
        if not self._shell:
            raise FortiSSHError("SSH session is not connected")
        self._shell.send(command + "\n")
        buf = ""
        start = time.time()
        sh = self._shell
        while time.time() - start < maxt:
            if sh.recv_ready():
                buf += sh.recv(16384).decode("utf-8", "replace")
                seen, _ = prompt_context(buf)
                if seen:
                    time.sleep(0.15)
                    if not sh.recv_ready():
                        break
            else:
                time.sleep(0.05)
        seen, ctx = prompt_context(buf)
        lines = strip_echo(_ANSI.sub("", buf).replace("\r", ""), command).split("\n")
        if seen and lines:
            lines = lines[:-1]
        return "\n".join(lines).strip(), seen, ctx


def strip_echo(text: str, command: str) -> str:
    """``text`` without the echo of ``command``.

    The terminal wraps a long echoed line (the shell is 220 columns), so the
    echo is matched character by character across line breaks. Leaving it in
    would let a value that merely says "Invalid" or "Command fail" read as
    the box refusing the line."""
    want = command.strip()
    i = 0
    while i < len(text) and text[i] in " \n":
        i += 1
    j = 0
    while i < len(text) and j < len(want):
        if text[i] == want[j]:
            i += 1
            j += 1
        elif text[i] == "\n" or (text[i] == " " and want[j] != " "):
            i += 1                      # a wrap the terminal inserted
        else:
            break
    if j == len(want):
        return text[i:].lstrip(" ").lstrip("\n")
    first, _, rest = text.partition("\n")
    return rest if first.strip() == want else text


@dataclass
class _Frame:
    kind: str          # "config" | "edit"
    label: str
    singleton: bool = False


def _label_of(words: str) -> str:
    return words.split()[-1] if words.split() else ""


# --------------------------------------------------------------------------- #
#  Readback                                                                    #
# --------------------------------------------------------------------------- #
_EDIT = re.compile(r"^\s*edit\s+(?P<k>.+?)\s*$")
_CONFIG = re.compile(r"^\s*config\s+(?P<w>.+?)\s*$")
_UNSET = re.compile(r"^\s*unset\s+(?P<n>\S+)")
_SETRAW = re.compile(r"^\s*set\s+(?P<n>\S+)(?:\s+(?P<v>.*))?$")


_odd_quotes = cli_schema._odd_quotes


def _unquote_key(k: str) -> str:
    k = k.strip()
    if len(k) >= 2 and k[0] == '"' and k[-1] == '"':
        k = k[1:-1]
    return _unescape(k)


def show_rows(text: str) -> dict:
    """``show full-configuration`` -> ``{chain: [lines]}`` per row/object.

    ``chain`` = tuple of ``(config words, edit key or None)`` from the root,
    e.g. ``(("server-policy server-pool", "p1"), ("pserver-list", "1"))``. A
    row is recorded even when it prints no lines (that is what the
    same-session quirk looks like)."""
    rows: dict = {}
    stack: list = []          # [config words, current edit key or None]
    pending_quote = False
    cur_key = None
    for raw in (text or "").replace("\r", "").splitlines():
        if pending_quote:
            if cur_key is not None:
                rows[cur_key].append(raw)
            if _odd_quotes(raw):
                pending_quote = False
            continue
        line = raw.strip()
        m = _CONFIG.match(raw)
        if m and line.startswith("config "):
            stack.append([" ".join(m.group("w").split()), None])
            cur_key = tuple((w, k) for w, k in stack)
            rows.setdefault(cur_key, [])
            continue
        if line == "end":
            if stack:
                stack.pop()
            cur_key = tuple((w, k) for w, k in stack) if stack else None
            continue
        if line == "next":
            if stack:
                stack[-1][1] = None
            cur_key = tuple((w, k) for w, k in stack) if stack else None
            continue
        m = _EDIT.match(raw)
        if m and stack:
            stack[-1][1] = _unquote_key(m.group("k"))
            cur_key = tuple((w, k) for w, k in stack)
            rows.setdefault(cur_key, [])
            continue
        if cur_key is not None and (line.startswith("set ") or line.startswith("unset ")):
            rows[cur_key].append(raw)
            if line.startswith("set ") and _odd_quotes(line):
                pending_quote = True
    return rows


def row_values(lines: list, cli_path: str) -> dict:
    """``{"values": {name: str|None}, "raw": {name: raw}, "unset": set}`` of
    one row's lines, values through :func:`cli_schema.parse_show_full_values`."""
    synth = "config %s\n%s\nend\n" % (cli_path, "\n".join(lines))
    parsed = cli_schema.parse_show_full_values(synth).get(cli_path, {})
    raw: dict = {}
    unset: set = set()
    for ln in lines:
        m = _SETRAW.match(ln)
        if m:
            raw.setdefault(m.group("n"), m.group("v") or "")
            continue
        m = _UNSET.match(ln)
        if m:
            unset.add(m.group("n"))
    values = {k: (None if v is None else _unescape(v)) for k, v in parsed.items()}
    return {"values": values, "raw": raw, "unset": unset}


def _norm_scalar(v) -> str:
    s = "" if v is None else str(v).strip()
    if isinstance(v, bool):
        s = "enable" if v else "disable"
    if re.fullmatch(r"-?\d+", s):
        return str(int(s))
    return s


def value_matches(expected, raw_printed: str | None, parsed: str | None) -> bool:
    """Does what the CLI printed equal what was written?

    A list is compared token by token (order-insensitive: FortiOS-family
    CLIs re-order some multi-value fields); a scalar against the unquoted,
    unescaped value."""
    if isinstance(expected, (list, tuple)):
        got = _tokens(raw_printed or "")
        return sorted(_norm_scalar(x) for x in expected) == sorted(_norm_scalar(x) for x in got)
    if parsed is None:
        return False
    return _norm_scalar(expected) == _norm_scalar(parsed)


def rest_value_matches(expected, got) -> bool:
    if isinstance(expected, (list, tuple)):
        items = got if isinstance(got, list) else str(got or "").split()
        return sorted(_norm_scalar(x) for x in expected) == sorted(_norm_scalar(x) for x in items)
    return _norm_scalar(expected) == _norm_scalar(got)


# --------------------------------------------------------------------------- #
#  The writer                                                                  #
# --------------------------------------------------------------------------- #
@dataclass
class CliWriteResult:
    ok: bool = False
    dry_run: bool = True
    product: str = ""
    endpoint: str = ""
    cli_path: str = ""
    mkey: str = ""
    script: list = field(default_factory=list)           # masked
    steps: list = field(default_factory=list)            # {command, output, status, context}
    error: dict | None = None                            # {pattern, line, code, command, field}
    aborted: bool = False
    recovery: list = field(default_factory=list)
    assigned_ids: dict = field(default_factory=dict)     # child words -> id the box gave
    before: dict | None = None                           # {exists, lines}
    readback: dict = field(default_factory=dict)         # cli / rest verdicts
    diff: list = field(default_factory=list)             # [{field, expected, got, channel}]
    nothing_applied: bool | None = None                  # after a failure: before == after
    notes: list = field(default_factory=list)
    dialect_verified: str = ""

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def _rest_reader_for(appliance) -> Callable | None:
    """``read(path) -> (status, json)`` through the app's REST client."""
    if getattr(appliance, "kind", "fortiweb") not in ("fortiweb", "", None):
        return None
    from ..clients.fortiweb import FortiWebClient
    client = FortiWebClient(appliance)

    def read(path):
        resp = client.get(path)
        try:
            return resp.status_code, resp.json()
        except Exception:  # noqa: BLE001
            return resp.status_code, None
    return read


def _audit(appliance, plan: CliPlan, res: CliWriteResult) -> None:
    """One audit row per apply: object path, field NAMES, outcome. Never a
    value — the error is recorded as its pattern id, not the line (which can
    echo the rejected value)."""
    err = res.error or {}
    detail = ("cli_path=%s mkey=%s fields=%s delete=%s ok=%s lab_bypass=%s"
              % (plan.cli_path, plan.target.mkey or "", ",".join(plan.field_names()),
                 plan.delete, res.ok, plan.lab_bypass))
    if err:
        detail += " error=%s%s" % (err.get("pattern", ""),
                                   (" field=%s" % err["field"]) if err.get("field") else "")
    if res.diff:
        detail += " readback_mismatch=%s" % ",".join(d["field"] for d in res.diff)
    try:
        from .audit import log_action
        log_action("config.cli_write", target=plan.endpoint or plan.cli_path,
                   appliance_id=getattr(appliance, "id", None), detail=detail)
    except Exception:  # noqa: BLE001 — audit is best-effort; outside an app context
        res.notes.append("audit row not written (no application context)")


class CliWriter:
    """Run one :class:`CliPlan` against one appliance.

    ``session_factory`` / ``reader_factory`` / ``rest_reader`` exist for the
    tests (recorded transcripts) and the lab driver; the defaults are the
    app's own SSH sessions and REST client.
    """

    READBACK_TRIES = 3
    READBACK_PAUSE_S = 2.0

    def __init__(self, appliance, *, session_factory: Callable | None = None,
                 reader_factory: Callable | None = None,
                 rest_reader: Callable | None = None, audit: bool = True,
                 sleep: Callable[[float], None] = time.sleep):
        self.appliance = appliance
        self.product = getattr(appliance, "kind", "") or "fortiweb"
        self._session_factory = session_factory or (lambda: CliWriteSession(appliance))
        self._reader_factory = reader_factory or (lambda: FortiWebReadonlySSH(appliance))
        self._rest_reader = rest_reader
        self._audit = audit
        self._sleep = sleep

    # -- preview -----------------------------------------------------------
    def render(self, plan: CliPlan) -> CliWriteResult:
        _check_plan(plan)
        res = self._new_result(plan)
        res.ok = True
        return res

    def _new_result(self, plan: CliPlan) -> CliWriteResult:
        script = render_script(plan, mask_secrets=True)
        for line in render_script(plan, mask_secrets=False):
            tier, why = classify_command(line.strip())
            if tier != TIER_SAFE and not (plan.allow_disruptive and tier == "disruptive"):
                raise CliWriteRefused("the console gate refuses a line of this script: %s"
                                      % why)
        return CliWriteResult(dry_run=True, product=plan.product, endpoint=plan.endpoint,
                              cli_path=plan.cli_path, mkey=str(plan.target.mkey or ""),
                              script=script,
                              dialect_verified=DIALECTS[plan.product]["verified"])

    # -- readback ------------------------------------------------------------
    def _show_command(self, plan: CliPlan) -> tuple:
        """``(command, chain of the target)``. The show names the TOP object;
        deeper levels are isolated from its text."""
        top = plan.levels[0]
        cmd = "show full-configuration " + top.words
        if top.mkey is not None:
            cmd += " " + cli_token(top.mkey, product=plan.product)
        chain = []
        for lv in plan.levels:
            chain.append((" ".join(lv.words.split()), None if lv.mkey is None else str(lv.mkey)))
        return cmd, tuple(chain)

    def _read_object(self, plan: CliPlan) -> dict:
        """One fresh read-only session: ``{"text", "rows", "not_found"}``."""
        cmd, _ = self._show_command(plan)
        sess = self._reader_factory()
        try:
            sess.connect()
            text = sess.run_readonly(cmd)
        finally:
            try:
                sess.close()
            except Exception:  # noqa: BLE001
                pass
        nf = bool(re.search(r"is not found|not found!|entry not found", text or "", re.I))
        return {"text": text or "", "rows": {} if nf else show_rows(text), "not_found": nf}

    def _snapshot(self, plan: CliPlan, read: dict, chain: tuple) -> dict:
        rows = read["rows"]
        if read["not_found"] or chain not in rows:
            return {"exists": False, "lines": [], "children": {}}
        kids = {}
        for ch in plan.children:
            key = chain + ((" ".join(ch.words.split()), None),)
            kids[ch.words] = sorted(k[-1][1] for k in rows
                                    if len(k) == len(key) and k[:-1] == chain
                                    and k[-1][0] == key[-1][0] and k[-1][1] is not None)
        return {"exists": True, "lines": list(rows[chain]), "children": kids}

    def _read_until_readable(self, plan: CliPlan, chain: tuple, want_lines: bool) -> dict:
        read = None
        for i in range(self.READBACK_TRIES):
            read = self._read_object(plan)
            rows = read["rows"]
            # a row that exists but prints no line at all is the same-session
            # quirk, not a row whose every field is empty: read again
            if not want_lines or read["not_found"] or (chain in rows and rows[chain]):
                return read
            if chain not in rows:
                return read
            if i + 1 < self.READBACK_TRIES:
                self._sleep(self.READBACK_PAUSE_S)
        read["unreadable"] = True
        return read

    def _verify_cli(self, plan: CliPlan, res: CliWriteResult, read: dict, chain: tuple) -> None:
        rows = read["rows"]
        out = {"command": self._show_command(plan)[0], "fields": {}, "exists": None}
        if plan.delete:
            exists = (not read["not_found"]) and chain in rows
            out["exists"] = exists
            if exists:
                res.diff.append({"field": "(object)", "expected": "deleted",
                                 "got": "still present", "channel": "cli"})
            res.readback["cli"] = out
            return
        if read["not_found"] or chain not in rows:
            out["exists"] = False
            res.diff.append({"field": "(object)", "expected": "present", "got": "not found",
                             "channel": "cli"})
            res.readback["cli"] = out
            return
        out["exists"] = True
        if read.get("unreadable"):
            out["unreadable"] = True
            res.diff.append({"field": "(object)", "expected": "readable",
                             "got": "the row printed no lines in %d sessions" % self.READBACK_TRIES,
                             "channel": "cli"})
        targets = [(chain, plan.cli_path, plan.set, plan.unset, "")]
        for ch in plan.children:
            cid = res.assigned_ids.get(ch.words, ch.mkey)
            key = chain + ((" ".join(ch.words.split()), str(cid)),)
            if ch.delete:
                gone = key not in rows
                out["fields"]["%s[%s]" % (ch.words, cid)] = "deleted" if gone else "still present"
                if not gone:
                    res.diff.append({"field": "%s[%s]" % (ch.words, cid), "expected": "deleted",
                                     "got": "still present", "channel": "cli"})
                continue
            if key not in rows:
                res.diff.append({"field": "%s[%s]" % (ch.words, cid), "expected": "present",
                                 "got": "not found", "channel": "cli"})
                continue
            targets.append((key, plan.cli_path + " " + ch.words, ch.set, ch.unset,
                            "%s[%s]." % (ch.words, cid)))
        for key, path, sets, unsets, prefix in targets:
            vals = row_values(rows.get(key, []), path)
            for name, want in sets.items():
                label = prefix + name
                secret = name in plan.secret_fields
                if name not in vals["values"] and name not in vals["raw"]:
                    out["fields"][label] = "missing"
                    res.diff.append({"field": label, "expected": "(set)" if secret else want,
                                     "got": "not printed", "channel": "cli"})
                    continue
                if secret:
                    # printed encrypted (``ENC ...``): presence is all a readback can prove
                    out["fields"][label] = "present (secret, not compared)"
                    continue
                if value_matches(want, vals["raw"].get(name), vals["values"].get(name)):
                    out["fields"][label] = "ok"
                else:
                    out["fields"][label] = "mismatch"
                    res.diff.append({"field": label, "expected": want,
                                     "got": vals["values"].get(name), "channel": "cli"})
            for name in unsets:
                label = prefix + name
                got = vals["values"].get(name)
                if name in vals["unset"] or (name not in vals["raw"] and got is None):
                    out["fields"][label] = "ok (unset)"
                elif got in ("", None):
                    out["fields"][label] = "ok (empty)"
                else:
                    out["fields"][label] = "mismatch"
                    res.diff.append({"field": label, "expected": "(unset)", "got": got,
                                     "channel": "cli"})
        res.readback["cli"] = out

    def _verify_rest(self, plan: CliPlan, res: CliWriteResult) -> None:
        if not plan.endpoint:
            res.readback["rest"] = {"skipped": "the object has no REST path"}
            return
        if not plan.rest_readback:
            # FortiWeb answers a path it does not serve with the PARENT's
            # rows: reading it would compare this object against another one
            res.readback["rest"] = {"skipped": "REST does not serve %s on this build"
                                    % plan.endpoint}
            return
        reader = self._rest_reader
        if reader is None:
            try:
                reader = _rest_reader_for(self.appliance)
            except Exception as exc:  # noqa: BLE001
                res.readback["rest"] = {"skipped": "no REST client: %s" % exc}
                return
        if reader is None:
            res.readback["rest"] = {"skipped": "no REST readback for %s" % plan.product}
            return
        from urllib.parse import quote
        urn = cli_schema.urn_for(plan.product, plan.endpoint)
        mkey = plan.target.mkey
        out = {"path": urn, "fields": {}}
        try:
            if plan.delete:
                if mkey is None:
                    out["skipped"] = "nothing to read"
                else:
                    status, body = reader("%s?mkey=%s" % (urn, quote(str(mkey), safe="")))
                    row = (body or {}).get("results") if isinstance(body, dict) else None
                    gone = not (status < 400 and isinstance(row, dict)
                                and str(row.get("name", row.get("id", ""))) == str(mkey))
                    out["exists"] = not gone
                    if not gone:
                        res.diff.append({"field": "(object)", "expected": "deleted",
                                         "got": "still present", "channel": "rest"})
                res.readback["rest"] = out
                return
            path = urn if mkey is None else "%s?mkey=%s" % (urn, quote(str(mkey), safe=""))
            status, body = reader(path)
            row = (body or {}).get("results") if isinstance(body, dict) else None
            if isinstance(row, list):
                row = row[0] if len(row) == 1 else None
            if not isinstance(row, dict) or status >= 400:
                out["skipped"] = "REST did not return the object (HTTP %s)" % status
                res.readback["rest"] = out
                return
            if mkey is not None and "name" in row and str(row["name"]) != str(mkey):
                out["skipped"] = "REST returned another object (%r)" % (row["name"],)
                res.readback["rest"] = out
                return
            self._compare_rest(plan, res, out, row, plan.set, plan.unset, "")
            for ch in plan.children:
                cid = res.assigned_ids.get(ch.words, ch.mkey)
                sub = "%s/%s" % (urn, ".".join(ch.words.split()))
                status, body = reader("%s?mkey=%s&sub_mkey=%s" % (
                    sub, quote(str(mkey), safe=""), quote(str(cid), safe="")))
                rows = (body or {}).get("results") if isinstance(body, dict) else None
                rows = rows if isinstance(rows, list) else [rows] if isinstance(rows, dict) else []
                crow = next((r for r in rows if isinstance(r, dict)
                             and str(r.get("id", r.get("_id", ""))) == str(cid)), None)
                label = "%s[%s]" % (ch.words, cid)
                if ch.delete:
                    out["fields"][label] = "deleted" if crow is None else "still present"
                    if crow is not None:
                        res.diff.append({"field": label, "expected": "deleted",
                                         "got": "still present", "channel": "rest"})
                    continue
                if crow is None:
                    # FortiWeb answers an unknown nested path with the PARENT's
                    # rows: only a row carrying this id is this row.
                    out["fields"][label] = "row not returned"
                    continue
                self._compare_rest(plan, res, out, crow, ch.set, ch.unset, label + ".")
        except Exception as exc:  # noqa: BLE001
            out["skipped"] = "REST readback failed: %s" % exc
        res.readback["rest"] = out

    @staticmethod
    def _compare_rest(plan, res, out, row, sets, unsets, prefix):
        for name, want in sets.items():
            label = prefix + name
            if name not in row:
                out["fields"][label] = "not served by REST"
                continue
            if name in plan.secret_fields:
                out["fields"][label] = "present (secret, not compared)"
                continue
            if rest_value_matches(want, row.get(name)):
                out["fields"][label] = "ok"
            else:
                out["fields"][label] = "mismatch"
                res.diff.append({"field": label, "expected": want, "got": row.get(name),
                                 "channel": "rest"})
        for name in unsets:
            label = prefix + name
            if name not in row:
                out["fields"][label] = "not served by REST"
            elif row.get(name) in ("", None, 0, "0"):
                out["fields"][label] = "ok (unset)"
            else:
                out["fields"][label] = "value after unset: %r" % (row.get(name),)

    # -- apply ---------------------------------------------------------------
    def apply(self, plan: CliPlan) -> CliWriteResult:
        _check_plan(plan)
        res = self._new_result(plan)
        res.dry_run = False
        sink = job_progress.current()
        if sink is not None:
            # The SAME per-device lock a REST write takes: the key is the REST
            # base URL (clients/base.py), so a CLI write and a REST write to one
            # box queue behind each other. A CLI write always locks.
            sink.exclusive = True
            sink.before_call("https://%s:%s" % (self.appliance.host,
                                                int(getattr(self.appliance, "port", 443) or 443)))
            sink.add_step("CLI write · %s %s" % (plan.cli_path, plan.target.mkey or ""))
        _, chain = self._show_command(plan)
        try:
            before_read = self._read_object(plan)
        except Exception as exc:  # noqa: BLE001
            res.error = {"pattern": "readback_unavailable", "line": str(exc)[:300],
                         "code": "", "command": res.script[0].strip() if res.script else ""}
            res.notes.append("nothing was sent: the object could not be read before the write")
            self._finish(plan, res)
            return res
        res.before = self._snapshot(plan, before_read, chain)
        if plan.delete and not res.before["exists"]:
            res.error = {"pattern": "entry_not_found", "line": "the object does not exist",
                         "code": "", "command": ""}
            res.nothing_applied = True
            self._finish(plan, res)
            return res

        lines = [ln.strip() for ln in render_script(plan, mask_secrets=False)]
        shown = [ln.strip() for ln in res.script]
        self._run(plan, res, lines, shown, sink)

        # readback in a NEW session (never the write session: see the module doc)
        try:
            after = self._read_until_readable(plan, chain, want_lines=not plan.delete)
        except Exception as exc:  # noqa: BLE001
            res.readback["cli"] = {"error": str(exc)[:300]}
            res.diff.append({"field": "(object)", "expected": "readback", "got": str(exc)[:200],
                             "channel": "cli"})
            self._finish(plan, res)
            return res
        if res.error:
            snap = self._snapshot(plan, after, chain)
            res.nothing_applied = (snap["exists"] == res.before["exists"]
                                   and snap["lines"] == res.before["lines"]
                                   and snap["children"] == res.before["children"])
            res.readback["cli"] = {"command": self._show_command(plan)[0],
                                   "unchanged": res.nothing_applied}
            if not res.nothing_applied:
                res.notes.append("the object differs from its state before the write: "
                                 "part of the change may have been applied")
        else:
            self._verify_cli(plan, res, after, chain)
            self._verify_rest(plan, res)
        self._finish(plan, res)
        return res

    def _finish(self, plan: CliPlan, res: CliWriteResult) -> None:
        res.ok = res.error is None and not res.diff
        if self._audit:
            _audit(self.appliance, plan, res)

    def _run(self, plan: CliPlan, res: CliWriteResult, lines: list, shown: list, sink) -> None:
        """Send the script line by line; on the first error, discard."""
        try:
            sess = self._session_factory()
            sess.connect()
        except Exception as exc:  # noqa: BLE001
            res.error = {"pattern": "session", "line": str(exc)[:300], "code": "",
                         "command": ""}
            res.nothing_applied = True
            return
        stack: list = []
        levels = list(plan.levels)
        child_words = None
        try:
            for i, (line, show) in enumerate(zip(lines, shown)):
                started = time.monotonic()
                try:
                    out, seen, ctx = sess.send_line(line, allow_disruptive=plan.allow_disruptive)
                except (ConsoleViolation, FortiSSHError) as exc:
                    out, seen, ctx = str(exc), False, None
                    err = {"pattern": "session", "line": str(exc)[:300], "code": ""}
                else:
                    err = detect_error(out)
                    if err is None and not seen:
                        err = {"pattern": "no_prompt", "line": "the prompt did not come back",
                               "code": ""}
                if sink is not None:
                    sink.after_call("SSH", show[:80], "error" if err else "ok", started)
                res.steps.append({"command": show, "output": redact(_mask(out, plan)),
                                  "status": "error" if err else "ok", "context": ctx})
                verb = line.split(" ", 1)[0]
                if err is not None:
                    err["command"] = show
                    m = re.match(r"(?:un)?set\s+(\S+)", line)
                    if m:
                        err["field"] = m.group(1)
                    err["line"] = redact(_mask(err["line"], plan))
                    res.error = err
                    if res.assigned_ids:
                        # ids the box handed out inside a transaction that is
                        # about to be discarded name rows that will not exist
                        res.notes.append("discarded row ids: %s" % res.assigned_ids)
                        res.assigned_ids = {}
                    _resync(stack, seen, ctx)
                    self._recover(plan, res, sess, stack)
                    return
                # successful line: track where the CLI is
                if verb == "config":
                    words = line[7:].strip()
                    singleton = False
                    if levels and " ".join(levels[0].words.split()) == words:
                        singleton = levels[0].mkey is None
                        levels.pop(0)
                    else:
                        child_words = words
                    stack.append(_Frame("config", _label_of(words), singleton))
                elif verb == "edit":
                    stack.append(_Frame("edit", ctx or ""))
                    if child_words is not None and line.split(" ", 1)[1].strip('"') == "0":
                        res.assigned_ids[child_words] = ctx or ""
                elif verb == "next":
                    if stack and stack[-1].kind == "edit":
                        stack.pop()
                elif verb == "end":
                    if stack and stack[-1].kind == "config":
                        stack.pop()
                    if child_words is not None and not any(
                            f.kind == "config" and f.label == _label_of(child_words) for f in stack):
                        child_words = None
                _resync(stack, seen, ctx)
        finally:
            try:
                sess.close()
            except Exception:  # noqa: BLE001
                pass

    def _recover(self, plan: CliPlan, res: CliWriteResult, sess, stack: list) -> None:
        """Leave the CLI at the root WITHOUT committing anything pending.

        ``abort`` in a row (or a singleton) discards it; a table level with
        no open row is left with ``end`` (nothing is pending there: a failed
        ``next`` has already discarded its row, and a sub-table's rows only
        reach the box through the parent row, which is aborted next)."""
        dialect = DIALECTS[plan.product]
        if not dialect.get("abort"):
            res.recovery.append("dialect has no abort: session closed without end")
            return
        for _ in range(12):
            if not stack:
                break
            top = stack[-1]
            cmd = "abort" if (top.kind == "edit" or top.singleton) else "end"
            try:
                out, seen, ctx = sess.send_line(cmd)
            except Exception as exc:  # noqa: BLE001
                res.recovery.append("%s -> %s" % (cmd, exc))
                break
            res.recovery.append("%s -> %s" % (cmd, ("(%s)" % ctx) if ctx else "root"))
            res.steps.append({"command": cmd, "output": redact(_mask(out, plan)),
                              "status": "recovery", "context": ctx})
            if cmd == "abort":
                res.aborted = True
            if not seen:
                break
            before = len(stack)
            if cmd == "abort" and top.kind == "edit":
                stack.pop()                       # the row ...
                if stack and stack[-1].kind == "config":
                    stack.pop()                   # ... and its table
            else:
                stack.pop()
            _resync(stack, seen, ctx)
            if len(stack) >= before:
                break
        if stack:
            res.recovery.append("the CLI did not return to the root; the session was "
                                "closed without committing")


def _mask(text: str, plan: CliPlan) -> str:
    out = text or ""
    for name in plan.secret_fields:
        for src in (plan.set, *[c.set for c in plan.children]):
            if name in src and src[name] not in (None, ""):
                for form in {str(src[name]), cli_value(src[name], product=plan.product)}:
                    if form:
                        out = out.replace(form, REDACTED)
    return out


def _resync(stack: list, seen: bool, ctx) -> None:
    """Make ``stack`` agree with the prompt the box printed."""
    if not seen:
        return
    if ctx is None:
        stack.clear()
        return
    for i in range(len(stack) - 1, -1, -1):
        if stack[i].label == ctx:
            del stack[i + 1:]
            return


# --------------------------------------------------------------------------- #
#  The gate: which channel may carry which field on THIS build                 #
# --------------------------------------------------------------------------- #
_CACHE: dict = {}
_CACHE_TTL_S = 120.0


def _cache_clear() -> None:
    _CACHE.clear()


def _channels(product: str, version: str, key: str) -> dict:
    from . import api_library as lib
    ck = (product, version, key)
    hit = _CACHE.get(ck)
    now = time.monotonic()
    if hit and now - hit[0] < _CACHE_TTL_S:
        return hit[1]
    view = lib.channels_at(product, version, endpoint=key or None)
    _CACHE[ck] = (now, view)
    return view


def split_payload(appliance, endpoint: str, fields: dict) -> dict:
    """Route each field of a write to the channel this build serves it on.

    ``{"rest": {...}, "cli": {...}, "refused": {name: reason}, "endpoint",
    "product", "version", "build_known", "object": {cli_path, kind, mkey,
    parent} | None, "secret_fields": [...]}``.

    * ``cli`` — the library classifies the field ``cli_only`` or ``hidden``
      on the appliance's EXACT build;
    * ``rest`` — ``both`` or ``rest_only``;
    * ``refused`` — ``unknown`` (no source measured it on this build), a field
      the build does not have, an endpoint the build's library does not know,
      or a build SATOM cannot name.
    """
    from . import api_library as lib
    fields = dict(fields or {})
    info = lib.resolve_appliance(appliance)
    product, version = info.get("product") or "", info.get("version") or ""
    out = {"rest": {}, "cli": {}, "refused": {}, "endpoint": "", "product": product,
           "version": version, "build_known": False, "object": None, "secret_fields": [],
           "rest_served": False}
    if not version:
        for k in fields:
            out["refused"][k] = ("the running build of this appliance is unknown; "
                                 "run a firmware check first")
        return out
    key = lib.urn_key(endpoint) if "/" in (endpoint or "") else (endpoint or "")
    view = _channels(product, version, key)
    eps = view.get("endpoints") or {}
    ep = eps.get(key) or (next(iter(eps.values())) if len(eps) == 1 else None)
    out["build_known"] = bool(view.get("build"))
    if ep is None:
        for k in fields:
            out["refused"][k] = ("%s is not known on %s %s (no evidence for this endpoint "
                                 "on this build)" % (endpoint, product, version))
        return out
    out["endpoint"] = ep.get("endpoint") or key
    out["rest_served"] = ep.get("rest_verdict") == "ok"
    attrs = ep.get("attrs") or {}
    if attrs.get("cli_path"):
        out["object"] = {k: attrs.get(k) for k in ("cli_path", "kind", "mkey", "parent")}
    efields = ep.get("fields") or {}
    for name, value in fields.items():
        spec = efields.get(name)
        if spec is None:
            out["refused"][name] = "field does not exist on %s %s" % (product, version)
            continue
        ch = spec.get("channel")
        if ch in CLI_CHANNELS:
            out["cli"][name] = value
            if is_secret(name, spec.get("attrs")):
                out["secret_fields"].append(name)
        elif ch in REST_CHANNELS:
            out["rest"][name] = value
        else:
            out["refused"][name] = ("no source measured this field on %s %s (channel "
                                    "unknown)" % (product, version))
    return out


def plan_for(appliance, split: dict, mkey: str | None, *, parent_mkeys=(),
             unset=()) -> CliPlan:
    """A gated :class:`CliPlan` for the ``cli`` half of a :func:`split_payload`.

    ``parent_mkeys`` names the row of every TABLE ancestor, outermost first,
    for an object nested in a table (``server-policy/server-pool/pserver-list``
    needs the pool's name)."""
    obj = split.get("object")
    if not obj or not obj.get("cli_path"):
        raise CliWriteRefused("the library does not name the CLI path of %s on this build"
                              % (split.get("endpoint") or "this endpoint"))
    product, version = split["product"], split["version"]
    chain = []
    cur = obj
    key = split["endpoint"]
    for _ in range(8):
        chain.append(cur)
        parent = cur.get("parent") or ""
        if not parent:
            break
        pv = _channels(product, version, parent).get("endpoints", {}).get(parent) or {}
        pattrs = pv.get("attrs") or {}
        if not pattrs.get("cli_path"):
            raise CliWriteRefused("the CLI path of the parent %s is unknown" % parent)
        cur = {k: pattrs.get(k) for k in ("cli_path", "kind", "mkey", "parent")}
    chain.reverse()
    pm = list(parent_mkeys)
    levels = []
    prev_words: list = []
    for i, o in enumerate(chain):
        words = (o["cli_path"] or "").split()
        rel = words[len(prev_words):] if words[:len(prev_words)] == prev_words else words
        is_target = i == len(chain) - 1
        kind = o.get("kind") or cli_schema.KIND_TABLE
        if kind == cli_schema.KIND_SINGLETON:
            row = None
        elif is_target:
            row = mkey
        else:
            if not pm:
                raise CliWriteRefused("%s is nested in the table %s: name its row"
                                      % (key, o["cli_path"]))
            row = pm.pop(0)
        levels.append(CliLevel(" ".join(rel), None if row is None else str(row), kind))
        prev_words = words
    return CliPlan(product=product, levels=levels, set=dict(split.get("cli") or {}),
                   unset=list(unset), endpoint=split["endpoint"],
                   secret_fields=frozenset(split.get("secret_fields") or ()), gated=True,
                   rest_readback=bool(split.get("rest_served")))


def write_fields(appliance, endpoint: str, mkey: str | None, fields: dict, *,
                 dry_run: bool = True, parent_mkeys=(), writer: CliWriter | None = None) -> dict:
    """Gate, render, and (unless ``dry_run``) apply the CLI half of a write.

    Returns ``{"split": ..., "result": CliWriteResult.as_dict() | None,
    "refused": {...}}``. Fields that belong to REST are NOT written here: the
    caller sends ``split["rest"]`` through its REST client."""
    split = split_payload(appliance, endpoint, fields)
    if not split["cli"]:
        return {"split": split, "result": None}
    plan = plan_for(appliance, split, mkey, parent_mkeys=parent_mkeys)
    w = writer or CliWriter(appliance)
    res = w.render(plan) if dry_run else w.apply(plan)
    return {"split": split, "result": res.as_dict()}


def lab_plan(product: str, levels: list, *, set=None, unset=(), children=(),
             delete: bool = False, endpoint: str = "", secret_fields=(),
             bypass_channel_gate_for_lab_test: bool = False) -> CliPlan:
    """TEST/LAB ONLY: a plan that skips :func:`split_payload`.

    Exists because the lab builds (FortiWeb 7.6.8 / 8.0.6) have no CLI-only
    field to exercise the writer with. The flag must be passed by name, and
    :func:`_check_plan` still refuses any top-level table row that is not a
    ``lab-`` object."""
    if not bypass_channel_gate_for_lab_test:
        raise CliWriteRefused("lab_plan needs bypass_channel_gate_for_lab_test=True")
    return CliPlan(product=product, levels=list(levels), set=dict(set or {}),
                   unset=list(unset), children=list(children), delete=delete,
                   endpoint=endpoint, secret_fields=frozenset(secret_fields),
                   gated=False, lab_bypass=True)


__all__ = [
    "DIALECTS", "ERROR_PATTERNS", "CliWriteRefused", "CliValueError", "CliLevel", "CliChild",
    "CliPlan", "CliWriter", "CliWriteResult", "CliWriteSession", "detect_error", "cli_token",
    "cli_value", "render_script", "strip_echo", "show_rows", "row_values", "value_matches",
    "split_payload", "plan_for", "write_fields", "lab_plan", "prompt_context",
]
