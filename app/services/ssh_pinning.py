"""One implementation of SSH host-key pinning, for every channel that has one.

Three call sites open SSH from this app and each had its own answer:

  ssh_ops              a known_hosts store, loaded inside ``except: pass``
  cert_service.autopull no store at all -- and it carries the node's TLS
                        PRIVATE KEY back over that connection
  hypervisors/esxi_shell no store at all -- and it runs shell commands as root
                        on a hypervisor

Two of those were not weak pinning; they were no pinning. ``AutoAddPolicy``
with no store accepts whatever key answers, every time, forever, and never
notices when the answer changes.

Why that is not theoretical here: when this fleet recycled appliance IPs on
2026-08-03, host-key verification was the only thing that stopped SATOM from
presenting Fortinet admin credentials to an unrelated Proxmox Backup Server.
With ``admin-lockout-threshold: 3`` on those devices the admin accounts would
have been locked out permanently. The control worked on the one channel that
had it.

The rule this module enforces:

  an ABSENT store is first contact -- trust it and record the key;
  a store that EXISTS and cannot be read in full is a BROKEN control, not a
  missing one -- refuse, and name the file.

paramiko does not distinguish those on its own: ``load_host_keys`` silently
SKIPS every line it cannot parse and an empty file loads "successfully" into
an empty pin set, so four of five pins can vanish while the load reports
success. Every non-comment line is therefore parsed here first, and any
failure is fatal.
"""
from __future__ import annotations

from pathlib import Path


def load_pins(cli, known: Path, error) -> int:
    """Load *known* into *cli*, or raise *error* naming the file.

    Returns the number of pins loaded; 0 means the file was absent, which is
    the only empty state a caller may treat as first contact.
    """
    from paramiko.hostkeys import HostKeyEntry

    known = Path(known)
    if not known.exists():
        return 0
    try:
        text = known.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise error(
            "host key store %s could not be read (%s); refusing to connect — "
            "an unreadable store is indistinguishable from first contact and "
            "would accept any key offered" % (known, exc)) from exc
    pins = 0
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        err = None
        try:
            entry = HostKeyEntry.from_line(line, lineno)
        except Exception as exc:  # noqa: BLE001 — paramiko raises SSHException
            entry, err = None, exc
        if entry is None:
            raise error(
                "host key store %s is corrupt at line %d%s — refusing to "
                "connect: paramiko would silently SKIP that line and treat "
                "the host it pins as first contact"
                % (known, lineno, (" (%s)" % err) if err else ""))
        pins += 1
    if not pins:
        raise error(
            "host key store %s exists but holds no host keys; refusing to "
            "connect — a truncated store is not first contact. Remove the "
            "file deliberately if you really mean to re-pin from scratch."
            % known)
    cli.load_host_keys(str(known))
    return pins


def persist(cli, known: Path, error) -> None:
    """Record newly accepted keys. A failure here is fatal on purpose.

    Silently failing to persist means every subsequent connect is first
    contact again, so the pin never takes effect and the store stays empty
    forever -- a control that looks armed and has never once been armed.
    """
    known = Path(known)
    try:
        known.parent.mkdir(parents=True, exist_ok=True)
        cli.save_host_keys(str(known))
    except OSError as exc:
        try:
            cli.close()
        except Exception:  # noqa: BLE001
            pass
        raise error(
            "could not record the host key in %s (%s); refusing to continue — "
            "an unwritable store means every future connect is treated as "
            "first contact and the pin never takes effect" % (known, exc)) from exc
