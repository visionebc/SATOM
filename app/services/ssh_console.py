"""Write-capable FortiOS console — the ONE place in SATOM that may mutate a device over SSH.

WHY THIS IS A NEW MODULE AND NOT A FLAG ON ``ssh_ops``
------------------------------------------------------
:mod:`app.services.ssh_ops` documents, in its own docstring, that the web
console "is locked to read commands" and that "a console user can never mutate
or reboot the box from here". Six other services import it on that promise
(``cert_manager``, ``backup``, ``backend_probe``, ``reach_batch``,
``logcollect``, ``interface_inventory``). Adding a ``write=True`` argument
there would make that sentence false for all of them at once, and the next
reader auditing *any* of those six would have to re-derive which call sites can
now write.

So ``assert_readonly`` is untouched and every existing caller keeps the
guarantee it was written against. The write path lives HERE, is reachable from
exactly one blueprint (``app.views.console``) and one future caller (the
Process engine), and carries its own gate.

THE GATE IS A DENYLIST, AND THAT IS DELIBERATE
----------------------------------------------
An allowlist is the right shape for ``ssh_ops`` because the question there is
closed: "is this a pure read?". Here the question is open — an operator
recovering a box at 3 a.m. needs whatever FortiOS spells today, and a
capability the allowlist authors did not foresee reads to them as a broken
tool, which is how people end up SSHing in from a laptop with no audit trail at
all. What is closed is the set of commands that destroy an appliance or lose
SATOM its access, so THAT is what is enumerated.

Three tiers:

``TIER_FORBIDDEN``
    Refused unconditionally. No flag, no checkbox, no UI path. These do not
    fail a change — they end an appliance (``execute factoryreset``,
    ``execute formatlogdisk``).
``TIER_DISRUPTIVE``
    Refused unless the caller passes ``allow_disruptive=True``, which the view
    only sets when the operator ticked the acknowledgement AND typed the
    appliance name. These succeed exactly as asked and that is the problem:
    a reboot, a config restore, an HA failover, an admin password change.
``TIER_SAFE``
    Everything else, behind ``config_write``.

WHAT THIS DELIBERATELY DOES NOT PROTECT
---------------------------------------
``delete_guard`` — the service that refuses to delete a FortiWeb object still
referenced by another — sits in front of the REST path. It does NOT see this
console, and cannot: a CLI ``delete`` inside a ``config`` block is not an
object reference the guard can resolve without re-implementing the whole
reference graph against CLI syntax. **A console user can delete a shared object
that the web UI would have refused to delete.** That is the cost of the tier the
operator asked for; it is written down here, in the page, and in every audit
row rather than discovered later.

SECRETS NEVER LEAVE IN A TRANSCRIPT
-----------------------------------
:func:`redact` runs over every transcript before it is stored, audited, or put
into a TAC bundle. A bundle is a file that gets attached to a support ticket
and leaves the building; a transcript containing ``set password`` and the
password is the single worst thing this module could produce.
"""
from __future__ import annotations

import json
import re
import tarfile
import time
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterable

from . import ssh_ops
from .ssh_ops import FortiSSHError, FortiWebReadonlySSH, clean_output

TIER_SAFE = "safe"
TIER_DISRUPTIVE = "disruptive"
TIER_FORBIDDEN = "forbidden"


class ConsoleViolation(Exception):
    """A command was refused by the console gate before being sent."""


# --------------------------------------------------------------------------- #
#  The gate                                                                    #
# --------------------------------------------------------------------------- #
#
# BOTH tiers are searched ANYWHERE in the unquoted part of a line — never
# anchored to its start.
#
# Anchoring was the first design and it was wrong. The case it defended against
# is a value that merely mentions a dangerous command, and FortiOS requires
# quotes around any value containing whitespace, so every such value is already
# blanked by :func:`_unquoted` before the scan. What anchoring DID do was let
# ``FortiWeb # execute reboot`` — a line pasted straight out of a session log,
# which is exactly how an operator retypes a sequence — classify as safe and
# skip the acknowledgement. A guard whose only observable effect is a bypass is
# not a guard.
#
# Quoted spans are removed first so ``set comment "never run execute
# factoryreset"`` is a comment and not a refusal.
_FORBIDDEN: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\bexecute\s+factoryreset", re.I),
     "factory reset — erases the entire configuration and every certificate on the appliance"),
    (re.compile(r"\bexecute\s+formatlogdisk", re.I),
     "formats the log disk — destroys the local log history this console exists to collect"),
    (re.compile(r"\bexecute\s+erase-disk", re.I),
     "erases a disk"),
    (re.compile(r"\bexecute\s+(usb-disk\s+|disk\s+)?format\b", re.I),
     "formats storage"),
)

_DISRUPTIVE: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\bexecute\s+reboot\b", re.I),
     "reboots the appliance — every policy it serves goes down until it comes back"),
    (re.compile(r"\bexecute\s+shutdown\b", re.I),
     "powers the appliance off — SATOM has no way to power it back on"),
    (re.compile(r"\bexecute\s+restore\b", re.I),
     "replaces the running configuration or firmware image"),
    (re.compile(r"\bexecute\s+ha\b", re.I),
     "changes HA state — this can force a failover"),
    (re.compile(r"\bexecute\s+(backup|migrate)\s+.*\b(tftp|ftp)\b", re.I),
     "sends configuration off the appliance in the clear"),
    (re.compile(r"\bset\s+(password|passwd)\b", re.I),
     "changes a stored password — if this is the admin SATOM uses, SATOM loses "
     "the appliance until the credential is updated in Appliances"),
)

_QUOTED = re.compile(r"""(["'])(?:\\.|(?!\1).)*\1""")


def _unquoted(line: str) -> str:
    """``line`` with quoted spans blanked out, so values are not read as verbs."""
    return _QUOTED.sub(" ", line)


def parse_script(text: str) -> list[str]:
    """Split pasted console input into commands: one per line, comments dropped.

    ``#`` comments are dropped only when the line STARTS with one. A ``#``
    inside a FortiOS value (a URL fragment, a password) is data, and stripping
    from the first ``#`` anywhere would silently truncate the command that was
    typed — the operator would watch a different command run than the one on
    screen.
    """
    out: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def classify_command(command: str) -> tuple[str, str]:
    """``(tier, reason)`` for one command line. ``reason`` is "" when safe."""
    line = (command or "").strip()
    if not line:
        return TIER_FORBIDDEN, "empty command"
    bare = _unquoted(line)
    for pat, why in _FORBIDDEN:
        if pat.search(bare):
            return TIER_FORBIDDEN, why
    for pat, why in _DISRUPTIVE:
        if pat.search(bare):
            return TIER_DISRUPTIVE, why
    return TIER_SAFE, ""


def classify_script(commands: Iterable[str]) -> list[dict]:
    """Per-command ``{command, tier, reason}`` — the preview the operator confirms."""
    rows = []
    for c in commands:
        tier, why = classify_command(c)
        rows.append({"command": c, "tier": tier, "reason": why})
    return rows


def assert_console_command(command: str, *, allow_disruptive: bool = False) -> str:
    """Return ``command`` if this console may send it, else raise.

    ``allow_disruptive`` is NOT a permission — the view resolves the permission
    and the typed confirmation before setting it. It is the record that a human
    was told what the command does and said yes anyway.
    """
    tier, why = classify_command(command)
    if tier == TIER_FORBIDDEN:
        raise ConsoleViolation(
            f"refused: {why}. This command has no path through SATOM at any "
            f"permission level — run it from the appliance console if you truly "
            f"mean it.")
    if tier == TIER_DISRUPTIVE and not allow_disruptive:
        raise ConsoleViolation(
            f"refused: {why}. Tick 'I understand this is disruptive' and type "
            f"the appliance name to send it.")
    return (command or "").strip()


# --------------------------------------------------------------------------- #
#  Reading the answer                                                          #
# --------------------------------------------------------------------------- #
#
# ``Return code`` is matched only when NEGATIVE. FortiOS prints
# ``Return code 0`` on success, and a marker that matches both outcomes is a
# marker that says nothing.
_ERROR_MARKERS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"Command fail", re.I), "command failed"),
    (re.compile(r"Return code\s+-\d+", re.I), "negative return code"),
    (re.compile(r"Unknown action", re.I), "unknown action"),
    (re.compile(r"(parsing error|command parse error|value parse error)", re.I), "parse error"),
    (re.compile(r"permission denied", re.I), "permission denied"),
    (re.compile(r"is invalid\b", re.I), "invalid value"),
    (re.compile(r"entry not found", re.I), "entry not found"),
    (re.compile(r"The (object|entry) is (in use|used)", re.I), "object still referenced"),
)


def classify_output(text: str) -> tuple[str, str]:
    """``(status, detail)`` — ``ok`` or ``error``, from the appliance's own words.

    SILENCE IS NOT AN ERROR HERE, unlike the reachability probes. A FortiOS
    ``config`` / ``edit`` / ``set`` / ``end`` that works prints nothing at all,
    so treating an empty answer as failure would mark every correct
    configuration line red. Callers that need to distinguish get ``empty`` on
    the row and decide for themselves.
    """
    body = text or ""
    for pat, detail in _ERROR_MARKERS:
        m = pat.search(body)
        if m:
            return "error", detail
    return "ok", ""


# --------------------------------------------------------------------------- #
#  Redaction                                                                   #
# --------------------------------------------------------------------------- #
# THE ``set`` IS NOT ANCHORED TO THE START OF THE LINE, and that is the whole
# point. A transcript line produced by :func:`run_script` reads
# ``$ set password S3cr3t!`` — with an anchor, the redactor matched nothing a
# real transcript ever contains and every bundle would have carried the
# password out of the building. Caught by a test, not by a review.
_SECRET_VALUE = re.compile(
    r"""^(?P<head>.*?\bset\s+(?:password|passwd|psk|secret|passphrase|key|
        private-key|auth-pwd|bind-password|admin-password|shared-secret)\s+)
        (?P<val>\S.*)$""",
    re.I | re.X | re.M)
_PEM = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.S)

REDACTED = "«redacted by SATOM»"


def redact(text: str) -> str:
    """Blank secret values in a transcript.

    Applied before ANY transcript is persisted, audited, or bundled. A TAC
    bundle is a file that leaves the building.
    """
    body = _PEM.sub(f"-----BEGIN PRIVATE KEY-----\n{REDACTED}\n-----END PRIVATE KEY-----",
                    text or "")
    return _SECRET_VALUE.sub(lambda m: m.group("head") + REDACTED, body)


# --------------------------------------------------------------------------- #
#  The session                                                                 #
# --------------------------------------------------------------------------- #
class FortiWriteSSH(FortiWebReadonlySSH):
    """A FortiOS CLI session that may also write, gated by :func:`classify_command`.

    Subclasses the read-only session so connection, host-key pinning, pager
    handling and prompt parsing stay in ONE implementation. Every one of those
    has a comment above it earned by an incident; a parallel copy here would
    lose them the first time one is fixed.
    """

    #: Output of the pager-disable exchange, kept because it is the only WRITE
    #: this session performs without being asked and is therefore a free signal
    #: about whether the account can write at all. It is a HINT, not a verdict:
    #: a box that refuses ``config system console`` for some unrelated reason
    #: would look identical, so it is reported as text, never as a boolean.
    pager_output: str = ""

    def _disable_pager(self) -> None:
        buf = []
        for cmd in ("config system console", "set output standard", "end"):
            self._shell.send(cmd + "\n")
            buf.append(self._read(quiet=0.5, maxt=4))
        self.pager_output = clean_output("".join(buf), "")

    def run(self, command: str, *, allow_disruptive: bool = False,
            quiet: float = 1.0, maxt: float = 30.0) -> str:
        """Validate, send, return cleaned output. Raises before sending on refusal."""
        command = assert_console_command(command, allow_disruptive=allow_disruptive)
        if not self._shell:
            raise FortiSSHError("SSH session is not connected")
        self._shell.send(command + "\n")
        return clean_output(self._read(quiet, maxt), command)


@dataclass
class CommandRow:
    command: str
    tier: str = TIER_SAFE
    status: str = "ok"          # ok | error | refused | not_run
    detail: str = ""
    output: str = ""
    empty: bool = False


@dataclass
class ScriptResult:
    appliance: str = ""
    rows: list[CommandRow] = field(default_factory=list)
    transcript: str = ""
    error: str = ""             # session-level failure (connect/auth)
    notes: list[str] = field(default_factory=list)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.rows if r.status in ("error", "refused"))


#: An operator pasting a 500-line config into a web form is doing something the
#: page cannot honestly supervise. Cut, and SAY the cut.
MAX_COMMANDS = 200


def run_script(appliance, commands: list[str], *, allow_disruptive: bool = False,
               secret: str | None = None, stop_on_error: bool = True,
               session_factory: Callable | None = None,
               quiet: float = 1.0, maxt: float = 30.0) -> ScriptResult:
    """Run a list of CLI commands in ONE session and return every answer.

    ``stop_on_error`` defaults to True because FortiOS is a MODAL cli: a failed
    ``config system dns`` leaves the session at the top level, and the ``set``
    lines that follow then land somewhere the operator did not intend. Running
    on regardless is how a typo in line 1 becomes a change in a different
    section of the configuration. Commands not reached are reported as
    ``not_run``, never dropped.
    """
    res = ScriptResult(appliance=getattr(appliance, "name", "") or "")

    if len(commands) > MAX_COMMANDS:
        res.notes.append(
            f"{len(commands)} commands submitted; only the first {MAX_COMMANDS} "
            f"were run — the remaining {len(commands) - MAX_COMMANDS} were not sent")
        commands = commands[:MAX_COMMANDS]

    # THE WHOLE SCRIPT IS GATED BEFORE THE SESSION OPENS. A forbidden command
    # on line 40 must not be discovered after lines 1-39 already changed the
    # appliance — half a config change is worse than none, and the operator
    # cannot tell from the page which half landed.
    plan = classify_script(commands)
    for row in plan:
        try:
            assert_console_command(row["command"], allow_disruptive=allow_disruptive)
        except ConsoleViolation as exc:
            res.error = str(exc)
            res.rows = [CommandRow(command=p["command"], tier=p["tier"],
                                   status="refused" if p["command"] == row["command"] else "not_run",
                                   detail=str(exc) if p["command"] == row["command"] else
                                          "not sent — the script was refused before it ran")
                        for p in plan]
            return res

    factory = session_factory or (lambda: FortiWriteSSH(appliance, secret=secret))
    lines: list[str] = []
    try:
        sess = factory()
        sess.connect()
    except Exception as exc:  # noqa: BLE001 — connect/auth surface is uniform
        res.error = str(exc)
        res.rows = [CommandRow(command=p["command"], tier=p["tier"], status="not_run",
                               detail="the session never opened") for p in plan]
        res.transcript = ""
        return res

    try:
        if getattr(sess, "pager_output", ""):
            lines.append(f"# pager setup\n{sess.pager_output}")
        halted = False
        for p in plan:
            row = CommandRow(command=p["command"], tier=p["tier"])
            if halted:
                row.status = "not_run"
                row.detail = "a previous command failed and the script stopped"
                res.rows.append(row)
                continue
            try:
                out = sess.run(p["command"], allow_disruptive=allow_disruptive,
                               quiet=quiet, maxt=maxt)
            except ConsoleViolation as exc:      # pragma: no cover - pre-gated
                row.status, row.detail = "refused", str(exc)
                halted = True
            except FortiSSHError as exc:
                row.status, row.detail = "error", str(exc)
                halted = True
            else:
                row.output = out
                row.empty = not out.strip()
                row.status, row.detail = classify_output(out)
                if row.status == "error" and stop_on_error:
                    halted = True
            lines.append(f"$ {row.command}\n{row.output}".rstrip())
            res.rows.append(row)
            if halted and stop_on_error and row.status in ("error", "refused"):
                res.notes.append(
                    f"stopped at {row.command!r} — the FortiOS CLI is modal, so "
                    f"the commands after a failure would have run in the wrong "
                    f"context")
    finally:
        try:
            sess.close()
        except Exception:  # noqa: BLE001
            pass

    res.transcript = redact("\n\n".join(lines).strip())
    return res


# --------------------------------------------------------------------------- #
#  Credential verification                                                     #
# --------------------------------------------------------------------------- #
#: One operator checking one credential is troubleshooting. The same form
#: driven in a loop is a password sprayer, and the difference is only ever
#: visible as a RATE. Every attempt is audited by the view; this is what stops
#: the tool from being useful for the second thing.
CRED_WINDOW = 300.0
CRED_MAX = 12
_cred_hits: dict[str, list[float]] = {}


def _throttle(actor: str, clock: Callable[[], float]) -> None:
    now = clock()
    hits = [t for t in _cred_hits.get(actor, []) if now - t < CRED_WINDOW]
    if len(hits) >= CRED_MAX:
        wait = int(CRED_WINDOW - (now - hits[0])) + 1
        _cred_hits[actor] = hits
        raise ConsoleViolation(
            f"{CRED_MAX} credential checks in {int(CRED_WINDOW)}s is the limit "
            f"for one operator — try again in {wait}s. This tool tests ONE "
            f"credential you already have; it is not a way to search for one.")
    hits.append(now)
    _cred_hits[actor] = hits


@dataclass
class CredCheck:
    host: str = ""
    username: str = ""
    reachable: bool = False
    authenticated: bool = False
    read_ok: bool = False
    firmware: str = ""
    hostname: str = ""
    write_hint: str = ""        # free text — never a boolean, see below
    error: str = ""
    elapsed_ms: int = 0


#: Failure messages that PROVE the device answered. A host-key mismatch is in
#: the list on purpose: the box completed a key exchange, so it is reachable —
#: and that particular failure is the one an operator most needs to see as
#: "something answered here" rather than "nothing is there".
_DEVICE_ANSWERED = ("auth failed", "authentication", "host key mismatch")

_VERSION_RE = re.compile(r"^\s*Version\s*:\s*(.+?)\s*$", re.I | re.M)
_HOSTNAME_RE = re.compile(r"^\s*Hostname\s*:\s*(.+?)\s*$", re.I | re.M)


def verify_credentials(host: str, username: str, password: str, *,
                       ssh_port: int = 22, timeout: float = 12.0,
                       actor: str = "anonymous",
                       session_factory: Callable | None = None,
                       clock: Callable[[], float] = time.monotonic) -> CredCheck:
    """Test ONE username/password against ONE FortiOS device over SSH.

    Answers three different questions that a single "login failed" would blur
    together, because the operator's next move differs for each:

    * ``reachable`` — did TCP/SSH answer at all? No means routing, firewall or
      a wrong port, and the credential was never tested.
    * ``authenticated`` — did the device accept the pair?
    * ``read_ok`` — can the account actually read? An account that logs in and
      can read nothing is a real FortiOS state (an admin profile with no
      access), and it looks like success to anything that only checks auth.

    ``write_hint`` is TEXT, not a boolean. The only evidence available without
    writing something on purpose is whether the automatic pager-disable was
    accepted, and a box that refused it for an unrelated reason is
    indistinguishable from a read-only account. Reporting a guess as a flag is
    how an operator ends up planning a change on an account that cannot make
    it — so the raw words are handed over instead.

    THE PASSWORD IS NEVER STORED and never appears in the result.
    """
    _throttle(actor or "anonymous", clock)
    res = CredCheck(host=host or "", username=username or "")
    if not (host or "").strip() or not (username or "").strip():
        res.error = "host and username are both required"
        return res

    target = SimpleNamespace(
        name=f"{username}@{host}", host=host, ssh_port=int(ssh_port or 22),
        username=username, password=password,
    )
    started = clock()
    factory = session_factory or (
        lambda: FortiWriteSSH(target, secret=password, timeout=timeout))
    sess = None
    try:
        sess = factory()
        sess.connect()
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        res.error = msg
        # ``FortiWebReadonlySSH.connect`` collapses every paramiko failure into
        # one FortiSSHError, so the states are told apart by the messages IT
        # writes. ``reachable`` is decided POSITIVELY — only a message that
        # proves the device answered sets it — because the default has to be
        # the safe reading: a connect that timed out never tested the
        # credential, and reporting that as "wrong password" sends the operator
        # to reset a credential that was fine.
        res.authenticated = False
        res.reachable = any(m in msg.lower() for m in _DEVICE_ANSWERED)
        res.elapsed_ms = int((clock() - started) * 1000)
        return res

    res.reachable = True
    res.authenticated = True
    try:
        res.write_hint = (getattr(sess, "pager_output", "") or "").strip()[:400]
        status = sess.run_readonly("get system status", quiet=0.8, maxt=15)
        st, _detail = classify_output(status)
        res.read_ok = bool(status.strip()) and st == "ok"
        if m := _VERSION_RE.search(status):
            res.firmware = m.group(1)[:120]
        if m := _HOSTNAME_RE.search(status):
            res.hostname = m.group(1)[:120]
        if not res.read_ok:
            res.error = ("the credential was accepted but 'get system status' "
                         "returned nothing usable — this account may have an "
                         "admin profile with no read access")
    except Exception as exc:  # noqa: BLE001
        res.error = f"logged in, but the status read failed: {exc}"
    finally:
        try:
            sess.close()
        except Exception:  # noqa: BLE001
            pass
    res.elapsed_ms = int((clock() - started) * 1000)
    return res


# --------------------------------------------------------------------------- #
#  TAC bundle                                                                  #
# --------------------------------------------------------------------------- #
def _bundle_dir() -> Path:
    from .logcollect import _diag_dir
    return _diag_dir()


def _safe_token(t: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", (t or "device")).strip("-") or "device"


def build_tac_bundle(appliance, transcript: str, *, stamp: str,
                     include_diagnostics: bool = True,
                     ticket: str = "", note: str = "",
                     capture: Callable | None = None) -> dict:
    """Write a ``.tar.gz`` for a Fortinet support ticket. Returns its metadata.

    ``stamp`` is passed IN rather than read from the clock so the caller owns
    the filename and the same bundle can be rebuilt deterministically in a test.

    A diagnostics capture that fails does NOT lose the bundle. The transcript is
    the part the operator watched happen and the part TAC asked for; dropping it
    because a battery of 32 read commands timed out would throw away the
    evidence to protect the annex.
    """
    name = f"tac-{_safe_token(getattr(appliance, 'name', 'device'))}-{stamp}.tar.gz"
    out = _bundle_dir() / name
    clean = redact(transcript or "")

    diagnostics = ""
    diag_note = ""
    if include_diagnostics:
        try:
            grab = capture or ssh_ops.capture_health
            blocks = grab(appliance)
            diagnostics = "\n\n".join(
                f"===== {c} =====\n{o}".rstrip() for c, o in blocks.items())
            diagnostics = redact(diagnostics)
        except Exception as exc:  # noqa: BLE001
            diag_note = (f"the diagnostic battery could not be captured ({exc}); "
                         f"this bundle holds the console transcript only")

    meta = {
        "appliance": getattr(appliance, "name", ""),
        "host": getattr(appliance, "host", ""),
        "kind": getattr(appliance, "kind", ""),
        "firmware": getattr(appliance, "firmware", ""),
        "ticket": ticket,
        "note": note,
        "stamp": stamp,
        "generated_by": "SATOM console",
        "redacted": True,
        "diagnostics_included": bool(diagnostics),
        "diagnostics_note": diag_note,
    }

    def _add(tar: tarfile.TarFile, arc: str, text: str) -> None:
        data = text.encode("utf-8")
        info = tarfile.TarInfo(arc)
        info.size = len(data)
        info.mtime = 0
        tar.addfile(info, BytesIO(data))

    out.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out, "w:gz") as tar:
        _add(tar, "meta.json", json.dumps(meta, indent=2, sort_keys=True))
        _add(tar, "console-session.txt", clean or "(no commands were run)")
        if diagnostics:
            _add(tar, "diagnostics.txt", diagnostics)
        if diag_note:
            _add(tar, "DIAGNOSTICS-MISSING.txt", diag_note)
    return {"name": name, "path": str(out), "size": out.stat().st_size, **meta}


__all__ = [
    "TIER_SAFE", "TIER_DISRUPTIVE", "TIER_FORBIDDEN", "ConsoleViolation",
    "parse_script", "classify_command", "classify_script",
    "assert_console_command", "classify_output", "redact", "REDACTED",
    "FortiWriteSSH", "CommandRow", "ScriptResult", "run_script", "MAX_COMMANDS",
    "CredCheck", "verify_credentials", "CRED_MAX", "CRED_WINDOW",
    "build_tac_bundle",
]
