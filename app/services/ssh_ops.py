"""Read-only SSH/CLI access to FortiWeb — the web port of the desktop ``ssh.py``.

A few FortiWeb operations have no REST equivalent (``get system ...``,
``diagnose ...``) and the upgrade runbook captures a health baseline over the
CLI. This module is the SSH counterpart to :mod:`app.clients.fortiweb`.

Hard read-only by design. Unlike the desktop module (which also imports/deletes
certificates over SSH), the **web console is locked to read commands** via
:func:`assert_readonly`: only ``get`` / ``show`` / ``diagnose`` are accepted.
``config`` / ``set`` / ``unset`` / ``edit`` / ``delete`` / ``execute`` / ``restore``
and friends are refused before anything is sent — so a console user can never
mutate or reboot the box from here.

Mechanism (verified on FortiWeb 7.6/8.0): the CLI is a restricted interactive
shell, so we ``invoke_shell`` (not ``exec_command``), send ``command + \\n`` and
read until the prompt goes idle, disabling the pager up front. The appliance's
single admin secret (GUI/API/SSH share it) is reused — no separate SSH secret.
Host keys are trust-on-first-use, persisted under ``data/known_hosts``: TOFU on
GENUINE first contact (no store yet), and a refusal to connect whenever a store
that DOES exist cannot be read in full (see :func:`_load_pins`).

Pure parsing helpers (``clean_output``/``assert_readonly``) are network-free and
unit-testable; the session itself needs a live appliance.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
# FortiWeb prompt: "FortiWeb # ", "FortiWeb (global) # ", "host (vdom) # ";
# FortiAuthenticator prints a bare "> ".
_PROMPT_LINE = re.compile(r"^(?:[\w.\-]+ (?:\(\S+\) )?# ?|> ?)$")

# Only these CLI verbs are ever sent from the web console — everything else is
# a write/exec and is refused. ``diag`` is FortiWeb's accepted abbreviation of
# ``diagnose``.
_READ_VERBS = frozenset({"get", "show", "diagnose", "diag"})


# ── The ONE exec command this console may send, and why it is not a verb ────
#
# Backend reachability needs ``execute ping`` from the DESTINATION appliance —
# the only vantage whose route to a real server decides whether a cloned policy
# serves anything. ``execute`` is NOT added to ``_READ_VERBS`` for it: that verb
# also spells ``execute reboot``, ``execute factoryreset`` and
# ``execute formatlogdisk``, so opening it would trade a diagnostic for the
# ability to wipe an appliance from a web form.
#
# What is allowed is the whole COMMAND, matched end to end, with the target
# constrained to a hostname / IPv4 / IPv6. There is no ``execute`` prefix to
# extend and nothing to chain onto: ``;``/``&``/``|`` cannot appear in a match.
_PROBE_COMMAND_RE = re.compile(
    r"^execute ping (?P<target>[A-Za-z0-9][A-Za-z0-9._:\-]{0,252})$")

# ``execute ping`` cannot be read the way every other command here is read.
# :meth:`FortiWebReadonlySSH._read` returns when the output goes QUIET, and a
# ping prints its header and then says nothing at all while it pings. Measured
# on fortiweb13 (7.6.8): a quiet-based read came back after 2.3 s holding only
# ``PING 198.51.100.1 (198.51.100.1): 56 data bytes`` — and the NEXT command in the
# same session came back EMPTY, because the first ping was still writing into
# the channel. Parsed, that reads "no answer", so every backend would have been
# reported unknown and the session would have desynchronised behind it.
#
# So a probe is read until it TERMINATES: a statistics line, a resolution
# failure, a refusal, or the prompt coming back.
#: A pattern that never matches: :meth:`FortiWebReadonlySSH._read_until` then
#: stops only on the returning prompt or the wall clock.
_NEVER = re.compile(r"(?!x)x")

_PROBE_DONE_RE = re.compile(
    r"packet loss|unknown host|cannot resolve|Name or service not known|"
    r"Parsing error|Command fail|Unknown action", re.I)


# ── The ONE schema command, and why it is not a verb either ─────────────────
#
# ``tree`` at the root of the CLI prints the whole configuration schema of the
# running build (every object, field, CLI id, type and option) — the API
# library's ``cli_tree`` evidence. It reads nothing but the schema and changes
# nothing. It is NOT added to ``_READ_VERBS``: a verb allowlist grows by
# accident ("tree" today, "tree <anything>" tomorrow). This gate matches the
# WHOLE command, so nothing can be appended to it.
_SCHEMA_COMMANDS = frozenset({"tree"})


class FortiSSHError(Exception):
    """SSH connect/auth/exec failure."""


class ReadOnlyViolation(Exception):
    """A command that is not a pure read was rejected before being sent."""


# Control characters are line EDITING keys to the interactive shell the command
# is typed into: backspace, Ctrl-U/W erase what was validated, Ctrl-A/E move the
# cursor, tab completes. ``show`` + eight backspaces + ``config system admin``
# validates as a ``show`` and runs as a write. Newline is not here: each line is
# validated on its own by the gates that accept more than one.
_CONTROL_CHARS = re.compile(r"[\x00-\x09\x0b-\x1f\x7f]")


def _refuse_control(cmd: str) -> None:
    m = _CONTROL_CHARS.search(cmd)
    if m:
        raise ReadOnlyViolation(
            "control character %r in the command — refused (the shell would "
            "read it as a line-editing key)" % m.group(0))


def _data_dir() -> Path:
    """``/opt/satom/data`` — beside the app package (parents[2]).

    An unusable data directory is FATAL, not a warning. The only thing SSH
    keeps here is the host-key store; a directory that cannot be created means
    an empty pin set, which ``AutoAddPolicy`` reads as first contact for every
    appliance, forever. Swallowing the OSError made that state permanent and
    silent — the one combination nobody ever notices.
    """
    d = Path(__file__).resolve().parents[2] / "data"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise FortiSSHError(
            f"SSH data directory {d} could not be created ({exc}); refusing to "
            f"connect without a host-key store") from exc
    return d


def _load_pins(cli, known: Path) -> None:
    """Load ``known_hosts`` into ``cli`` — or refuse the connect, naming it.

    The rule and its rationale live in :mod:`app.services.ssh_pinning`, which
    is shared with the two other channels that open SSH from this app
    (``cert_service`` autopull, which carries the node's TLS private key, and
    the ESXi shell transport, which runs commands as root on a hypervisor).
    Both of those had NO host-key store at all until this was unified; keeping
    a second copy of the rule here is how they would drift apart again.
    """
    from .ssh_pinning import load_pins
    load_pins(cli, known, FortiSSHError)


def clean_output(raw: str, command: str) -> str:
    """Strip ANSI, the echoed command, and trailing CLI prompt lines."""
    text = _ANSI.sub("", raw).replace("\r", "")
    lines = text.split("\n")
    if lines and lines[0].strip() == command.strip():
        lines = lines[1:]
    lines = [ln for ln in lines if not _PROMPT_LINE.match(ln.strip())]
    return "\n".join(lines).strip()


def assert_readonly(command: str) -> str:
    """Return ``command`` if every line is a pure read, else raise.

    Validates EACH non-empty line (so a pasted ``get x\\nset y`` can't sneak a
    write past a read first line). The first token of each line must be one of
    ``get`` / ``show`` / ``diagnose`` / ``diag``. A CRLF line ending is read as
    a newline; any other control character is refused.
    """
    cmd = (command or "").replace("\r\n", "\n")
    _refuse_control(cmd)
    cmd = cmd.strip()
    if not cmd:
        raise ReadOnlyViolation("empty command")
    for line in cmd.splitlines():
        line = line.strip()
        if not line:
            continue
        # split on ; so chained statements are each checked
        for stmt in re.split(r"[;&|]", line):
            stmt = stmt.strip()
            if not stmt:
                continue
            verb = stmt.split()[0].lower()
            if verb not in _READ_VERBS:
                raise ReadOnlyViolation(
                    f"'{verb}' is not a read-only command — only "
                    f"{', '.join(sorted(_READ_VERBS))} are allowed in the console"
                )
            # ``diagnose`` is not a read verb on its own: the trees carry
            # kill, clear, failover, sysrq crash… (services/diag_policy.py).
            from .diag_policy import blocked_reason
            why = blocked_reason(stmt)
            if why:
                raise ReadOnlyViolation(f"refused {stmt[:80]!r}: {why}")
    return cmd


def assert_probe_command(command: str) -> str:
    """Return ``command`` if it is EXACTLY a permitted reachability probe.

    A SECOND gate, deliberately not a relaxation of :func:`assert_readonly`.
    That one answers "is this a pure read?" and the answer for anything spelled
    ``execute`` is no — which stays true. This one answers a much narrower
    question with a whole-command match, so it cannot be widened by accident the
    way a verb allowlist can.
    """
    _refuse_control(command or "")
    cmd = (command or "").strip()
    if "\n" in cmd or not _PROBE_COMMAND_RE.match(cmd) or ".." in cmd:
        raise ReadOnlyViolation(
            "only 'execute ping <host>' may be sent as a reachability probe; "
            "refused %r" % ((command or "")[:80],))
    return cmd


def assert_schema_command(command: str) -> str:
    """Return ``command`` if it is EXACTLY a permitted schema dump (``tree``).

    A separate gate, like :func:`assert_probe_command`: whole-command match,
    no arguments, no second line, no chaining.
    """
    _refuse_control(command or "")
    cmd = (command or "").strip()
    if "\n" in cmd or "\r" in cmd or cmd not in _SCHEMA_COMMANDS:
        raise ReadOnlyViolation(
            "only %s may be sent as a schema dump; refused %r"
            % (", ".join("'%s'" % c for c in sorted(_SCHEMA_COMMANDS)), (command or "")[:80]))
    return cmd


# ── The help question, and why it is not a verb either ────────────────────
#
# Discovery (services/diag_tree.py) types ``<path> ?`` with NO newline: the
# shell lists the children of ``<path>`` and re-types the line. On FortiWeb a
# leaf can RUN when ``?`` follows it, so the path is held to the same battery
# rule as a command (services/diag_policy.py, strict) before anything is sent,
# and it may only be a ``diagnose`` path of plain words — no arguments with
# spaces inside, no second line, no chaining.
_HELP_PATH_RE = re.compile(r"^diagnose(?: [A-Za-z0-9][A-Za-z0-9_.\-]*){0,12}$")


def assert_help_path(path: str) -> str:
    """Return ``path`` if ``<path> ?`` may be typed for discovery, else raise."""
    _refuse_control(path or "")
    p = (path or "").strip()
    if "\n" in p or not _HELP_PATH_RE.match(p):
        raise ReadOnlyViolation(
            "only a 'diagnose …' path of plain words may be asked for help; "
            "refused %r" % ((path or "")[:80],))
    from .diag_policy import blocked_reason
    why = blocked_reason(p, strict=True)
    if why:
        raise ReadOnlyViolation(f"refused to ask for help on {p!r}: {why}")
    return p


# Curated read-only troubleshooting presets (label -> CLI command).
TROUBLESHOOT: dict[str, str] = {
    "System status": "get system status",
    "Performance": "get system performance",
    "HA status": "diagnose system ha status",
    "Update info": "diagnose system update info",
    "Hardware (VM)": "diagnose hardware sysinfo vm",
    "CPU": "diagnose hardware cpu list",
    "Memory": "diagnose hardware mem list",
    "Disk health": "diagnose hardware harddisk health",
    "NIC list": "diagnose hardware nic list",
    "Routing table": "diagnose network info routing-table all",
    "ARP list": "diagnose network arp list",
}

# The extra signal the flash before/after report wants beyond the shared battery.
_FLASH_EXTRA: list[str] = ["diagnose policy total-list"]


def flash_battery() -> list[str]:
    """Full read-only diagnostic battery captured before/after a firmware flash.

    Reuses the COMPLETE ``logcollect.DIAGNOSTIC_COMMANDS`` set (parity with the
    desktop upgrade runbook — 28 commands since 2026-10-14) plus ``diagnose policy total-list``,
    the one health signal the web flash report wants that the shared battery
    omits (→ 29 total). Imported lazily because ``logcollect`` imports from
    this module, so a top-level import would create a circular import.
    """
    from .logcollect import DIAGNOSTIC_COMMANDS  # lazy: breaks the import cycle
    return list(DIAGNOSTIC_COMMANDS) + _FLASH_EXTRA


class FortiWebReadonlySSH:
    """Interactive FortiWeb CLI session over SSH (paramiko), read commands only."""

    def __init__(self, appliance, secret: str | None = None, *, timeout: float = 15.0):
        self.appliance = appliance
        self._secret = secret if secret is not None else appliance.ssh_secret
        self._timeout = timeout
        self._client: Any = None
        self._shell: Any = None

    # -- lifecycle --------------------------------------------------------
    def connect(self) -> "FortiWebReadonlySSH":
        # One visible step inside a device job (job_progress): login, banner
        # and pager take ~3.5 s per session and used to be a silent gap
        # before the first command's step.
        from . import job_progress
        sink = job_progress.current()
        if sink is None:
            return self._connect()
        sink.before_call(f"ssh://{self.appliance.host}:{int(self.appliance.ssh_port or 22)}")
        started = time.monotonic()
        try:
            out = self._connect()
        except Exception as exc:
            sink.after_call("SSH", "connect", None, started, error=exc)
            raise
        sink.after_call("SSH", "connect", "ok", started)
        return out

    def _connect(self) -> "FortiWebReadonlySSH":
        import paramiko  # lazy: keeps the import cost off non-SSH paths

        known = _data_dir() / "known_hosts"
        cli = paramiko.SSHClient()
        # ABSENT and BROKEN are not the same state. No store at all is genuine
        # first contact and TOFU applies; a store that exists must load in FULL
        # or _load_pins refuses the connect — this session carries the
        # appliance admin secret.
        if known.exists():
            _load_pins(cli, known)
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # TOFU
        try:
            cli.connect(
                self.appliance.host,
                port=int(self.appliance.ssh_port or 22),
                username=getattr(self.appliance, "ssh_login", None) or self.appliance.username,
                password=self._secret,
                timeout=self._timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.AuthenticationException as e:
            raise FortiSSHError(f"SSH auth failed for {self.appliance.name}") from e
        except paramiko.BadHostKeyException as e:
            raise FortiSSHError(
                f"host key mismatch for {self.appliance.name} "
                f"({self.appliance.host}): the key pinned in {known} is not the "
                f"key this address offered. An address that moved to different "
                f"hardware looks exactly like this — find out which box answers "
                f"before clearing the pin; the admin secret was NOT sent") from e
        except Exception as e:  # noqa: BLE001 — uniform surface
            raise FortiSSHError(f"SSH connect failed: {e}") from e
        try:
            cli.save_host_keys(str(known))  # persist the TOFU key
        except OSError as e:
            cli.close()
            raise FortiSSHError(
                f"host key store {known} could not be written ({e}); the key "
                f"just accepted would not be pinned, so the next connect would "
                f"trust on first use all over again") from e
        self._client = cli
        self._shell = cli.invoke_shell(width=220, height=2000)
        self._read(quiet=0.8, maxt=6)  # drain login banner
        self._disable_pager()
        return self

    def close(self) -> None:
        try:
            if self._shell:
                self._shell.send("exit\n")
        except Exception:
            pass
        try:
            if self._client:
                self._client.close()
        finally:
            self._client = self._shell = None

    def __enter__(self) -> "FortiWebReadonlySSH":
        return self.connect()

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- exec -------------------------------------------------------------
    def _read(self, quiet: float = 1.0, maxt: float = 15.0) -> str:
        buf = ""
        last = start = time.time()
        sh = self._shell
        while True:
            if sh.recv_ready():
                buf += sh.recv(16384).decode("utf-8", "replace")
                last = time.time()
            else:
                time.sleep(0.15)
                now = time.time()
                if now - last > quiet or now - start > maxt:
                    break
        return buf

    def _disable_pager(self) -> None:
        # Disabling the pager is configuration, but it's the FortiWeb-blessed way
        # to get unchunked CLI output; it's not exposed to the console user.
        for cmd in ("config system console", "set output standard", "end"):
            self._shell.send(cmd + "\n")
            self._read(quiet=0.5, maxt=4)

    def run_readonly(self, command: str, *, quiet: float = 1.0, maxt: float = 25.0) -> str:
        """Validate the command is a pure read, send it, return cleaned output."""
        command = assert_readonly(command)
        if not self._shell:
            raise FortiSSHError("SSH session is not connected")
        # One visible step per command inside a device job (job_progress).
        from . import job_progress
        sink = job_progress.current()
        if sink is not None:
            sink.before_call(f"ssh://{self.appliance.host}:{int(self.appliance.ssh_port or 22)}")
        started = time.monotonic()
        try:
            self._shell.send(command + "\n")
            out = clean_output(self._read(quiet, maxt), command)
        except Exception as exc:
            if sink is not None:
                sink.after_call("SSH", command[:80], None, started, error=exc)
            raise
        if sink is not None:
            sink.after_call("SSH", command[:80], "ok", started)
        return out

    def _read_until(self, done, maxt: float) -> str:
        """Read until ``done`` matches, the prompt returns, or ``maxt`` elapses.

        Bounded by wall clock, never by silence: silence is the normal state of
        a command that is waiting on the network, and treating it as completion
        both truncates this answer and leaves the next command reading this
        one's output.
        """
        buf = ""
        start = time.time()
        sh = self._shell
        while time.time() - start < maxt:
            if sh.recv_ready():
                buf += sh.recv(16384).decode("utf-8", "replace")
                if done.search(buf):
                    # let the trailing statistics/prompt lines land
                    time.sleep(0.4)
                    while sh.recv_ready():
                        buf += sh.recv(16384).decode("utf-8", "replace")
                    break
                tail = _ANSI.sub("", buf).replace("\r", "").split("\n")[-1]
                if _PROMPT_LINE.match(tail.strip()) and len(buf.strip()) > len(tail):
                    break
            else:
                time.sleep(0.1)
        return buf

    def run_probe(self, command: str, *, maxt: float = 45.0) -> str:
        """Send a reachability probe (``execute ping <host>``) and return output.

        Separate from :meth:`run_readonly` because it is validated by a separate
        gate. ``maxt`` is generous on purpose: a ping to an unreachable host
        answers only when it times out, and cutting the read short produces
        output the parser reads as "no answer" — indistinguishable from a probe
        this session never managed to run.
        """
        command = assert_probe_command(command)
        if not self._shell:
            raise FortiSSHError("SSH session is not connected")
        self._shell.send(command + "\n")
        return clean_output(self._read_until(_PROBE_DONE_RE, maxt), command)

    def run_schema(self, command: str = "tree", *, maxt: float = 180.0) -> tuple[str, bool]:
        """Send the schema dump (``tree``); return ``(output, complete)``.

        Validated by :func:`assert_schema_command`. Read until the PROMPT comes
        back (a 1-2 MB dump has pauses a quiet-based read would mistake for
        the end), bounded by ``maxt``. ``complete`` is False when the prompt
        never came back: the caller stores that as a truncated dump, never as
        a schema. Paging was turned off by :meth:`connect` (the same session
        setup ``show full-configuration`` uses); nothing else is changed.
        """
        command = assert_schema_command(command)
        if not self._shell:
            raise FortiSSHError("SSH session is not connected")
        from . import job_progress
        sink = job_progress.current()
        if sink is not None:
            sink.before_call(f"ssh://{self.appliance.host}:{int(self.appliance.ssh_port or 22)}")
        started = time.monotonic()
        try:
            self._shell.send(command + "\n")
            raw = self._read_until(_NEVER, maxt)
        except Exception as exc:
            if sink is not None:
                sink.after_call("SSH", command, None, started, error=exc)
            raise
        if sink is not None:
            sink.after_call("SSH", command, "ok", started)
        tail = _ANSI.sub("", raw).replace("\r", "").rstrip("\n").split("\n")[-1]
        complete = bool(_PROMPT_LINE.match(tail.strip()))
        return clean_output(raw, command), complete

    def _read_echo(self, path: str, maxt: float) -> tuple[str, bool]:
        """Read until the shell re-types ``path`` after its prompt.

        ``#`` ends the prompt on FortiWeb/FortiADC/FortiGate/FortiAnalyzer,
        ``>`` on FortiAuthenticator. Returns ``(raw, returned)``; ``returned``
        is False when the wall clock ran out first (the node is running).
        """
        done = re.compile(r"[#>] ?" + re.escape(path) + r" ?$")
        buf = ""
        start = time.time()
        sh = self._shell
        while time.time() - start < maxt:
            if sh.recv_ready():
                buf += sh.recv(16384).decode("utf-8", "replace")
                tail = _ANSI.sub("", buf).replace("\r", "").replace("\x00", "")
                if done.search(tail.rstrip("\n").split("\n")[-1]):
                    return buf, True
            else:
                time.sleep(0.05)
        return buf, False

    def ask_help(self, path: str, *, timeout: float = 10.0) -> tuple[str, bool]:
        """Type ``<path> ?`` and return ``(raw answer, returned_to_prompt)``.

        Validated by :func:`assert_help_path`. Afterwards the re-typed line is
        erased with Ctrl-U; when the prompt did not come back (``?`` started
        something that keeps running) Ctrl-C is sent first.
        """
        path = assert_help_path(path)
        if not self._shell:
            raise FortiSSHError("SSH session is not connected")
        self._shell.send(path + " ?")
        raw, returned = self._read_echo(path, timeout)
        if not returned:
            self._shell.send("\x03")
            self._read(quiet=0.6, maxt=4)
        self._shell.send("\x15")
        self._read(quiet=0.25, maxt=2)
        return raw, returned

    def ask_complete(self, path: str, *, quiet: float = 0.8, maxt: float = 5.0) -> str:
        """Type ``<path> `` + TAB and return what the shell typed back.

        The fallback for nodes whose ``?`` closes the session (FortiWeb and
        FortiADC crash on single-child nodes, 2026-10-14). TAB only completes
        the line — nothing runs — and the line is erased with Ctrl-U after.
        Same gate as :meth:`ask_help`.
        """
        path = assert_help_path(path)
        if not self._shell:
            raise FortiSSHError("SSH session is not connected")
        self._shell.send(path + " \t")
        raw = self._read(quiet=quiet, maxt=maxt)
        self._shell.send("\x15")
        self._read(quiet=0.25, maxt=2)
        return raw

    def run_battery(self, commands: list[str]) -> dict[str, str]:
        """Run a list of read commands → {command: output} (each validated)."""
        return {c: self.run_readonly(c) for c in commands}


# --------------------------------------------------------------------------- #
#  One-shot conveniences (open → run → close)                                 #
# --------------------------------------------------------------------------- #
def run_command(appliance, command: str, *, timeout: float = 15.0) -> str:
    """Open a session, run one read-only command, close. Raises on write/exec."""
    command = assert_readonly(command)  # fail fast before any connect
    with FortiWebReadonlySSH(appliance, timeout=timeout) as ssh:
        return ssh.run_readonly(command)


def run_tree(appliance, *, timeout: float = 20.0, maxt: float = 180.0) -> tuple[str, bool]:
    """Open a session, run ``tree``, close. Returns ``(output, complete)``."""
    assert_schema_command("tree")
    with FortiWebReadonlySSH(appliance, timeout=timeout) as ssh:
        return ssh.run_schema("tree", maxt=maxt)


def capture_health(appliance, *, timeout: float = 25.0) -> dict[str, str]:
    """Run the read-only diagnostic battery → {command: output}."""
    with FortiWebReadonlySSH(appliance, timeout=timeout) as ssh:
        return ssh.run_battery(flash_battery())


def health_text(appliance) -> str:
    """The diagnostic battery rendered as one labelled text blob."""
    out = capture_health(appliance)
    blocks = [f"===== {cmd} =====\n{text}".rstrip() for cmd, text in out.items()]
    return "\n\n".join(blocks)


__all__ = [
    "FortiWebReadonlySSH", "FortiSSHError", "ReadOnlyViolation",
    "clean_output", "assert_readonly", "assert_probe_command", "assert_schema_command",
    "assert_help_path",
    "TROUBLESHOOT", "flash_battery",
    "run_command", "run_tree", "capture_health", "health_text",
]
