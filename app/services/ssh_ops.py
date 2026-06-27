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
Host keys are trust-on-first-use, persisted under ``data/known_hosts``.

Pure parsing helpers (``clean_output``/``assert_readonly``) are network-free and
unit-testable; the session itself needs a live appliance.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
# FortiWeb prompt: "FortiWeb # ", "FortiWeb (global) # ", "host (vdom) # "
_PROMPT_LINE = re.compile(r"^[\w.\-]+ (?:\(\S+\) )?# ?$")

# Only these CLI verbs are ever sent from the web console — everything else is
# a write/exec and is refused. ``diag`` is FortiWeb's accepted abbreviation of
# ``diagnose``.
_READ_VERBS = frozenset({"get", "show", "diagnose", "diag"})


class FortiSSHError(Exception):
    """SSH connect/auth/exec failure."""


class ReadOnlyViolation(Exception):
    """A command that is not a pure read was rejected before being sent."""


def _data_dir() -> Path:
    """``/opt/fortinet-manager/data`` — beside the app package (parents[2])."""
    d = Path(__file__).resolve().parents[2] / "data"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return d


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
    ``get`` / ``show`` / ``diagnose`` / ``diag``.
    """
    cmd = (command or "").strip()
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
    return cmd


# Curated read-only troubleshooting presets (label -> CLI command).
TROUBLESHOOT: dict[str, str] = {
    "System status": "get system status",
    "Performance": "get system performance",
    "HA status": "diagnose system ha status",
    "Update info": "diagnose system update info",
    "Hardware (VM)": "diagnose hardware sysinfo vm",
    "CPU": "diagnose hardware cpu",
    "Memory": "diagnose hardware mem list",
    "Disk health": "diagnose hardware harddisk health",
    "NIC list": "diagnose hardware nic list",
    "Routing table": "diagnose network info routing-table all",
    "ARP list": "diagnose network arp list",
}

# Read-only battery captured before/after a firmware upgrade (health baseline).
DIAGNOSTIC_BATTERY: list[str] = [
    "get system status",
    "get system performance",
    "diagnose system ha status",
    "diagnose hardware sysinfo vm",
    "diagnose hardware harddisk health",
    "diagnose network info routing-table all",
    "diagnose policy total-list",
]


class FortiWebReadonlySSH:
    """Interactive FortiWeb CLI session over SSH (paramiko), read commands only."""

    def __init__(self, appliance, secret: str | None = None, *, timeout: float = 15.0):
        self.appliance = appliance
        self._secret = secret if secret is not None else appliance.password
        self._timeout = timeout
        self._client: Any = None
        self._shell: Any = None

    # -- lifecycle --------------------------------------------------------
    def connect(self) -> "FortiWebReadonlySSH":
        import paramiko  # lazy: keeps the import cost off non-SSH paths

        known = _data_dir() / "known_hosts"
        cli = paramiko.SSHClient()
        if known.exists():
            try:
                cli.load_host_keys(str(known))
            except Exception:  # corrupt file shouldn't block a connect
                pass
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # TOFU
        try:
            cli.connect(
                self.appliance.host,
                port=int(self.appliance.ssh_port or 22),
                username=self.appliance.username,
                password=self._secret,
                timeout=self._timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.AuthenticationException as e:
            raise FortiSSHError(f"SSH auth failed for {self.appliance.name}") from e
        except Exception as e:  # noqa: BLE001 — uniform surface
            raise FortiSSHError(f"SSH connect failed: {e}") from e
        try:
            cli.save_host_keys(str(known))  # persist the TOFU key
        except Exception:
            pass
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
        self._shell.send(command + "\n")
        return clean_output(self._read(quiet, maxt), command)

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


def capture_health(appliance, *, timeout: float = 25.0) -> dict[str, str]:
    """Run the read-only diagnostic battery → {command: output}."""
    with FortiWebReadonlySSH(appliance, timeout=timeout) as ssh:
        return ssh.run_battery(DIAGNOSTIC_BATTERY)


def health_text(appliance) -> str:
    """The diagnostic battery rendered as one labelled text blob."""
    out = capture_health(appliance)
    blocks = [f"===== {cmd} =====\n{text}".rstrip() for cmd, text in out.items()]
    return "\n\n".join(blocks)


__all__ = [
    "FortiWebReadonlySSH", "FortiSSHError", "ReadOnlyViolation",
    "clean_output", "assert_readonly", "TROUBLESHOOT", "DIAGNOSTIC_BATTERY",
    "run_command", "capture_health", "health_text",
]
