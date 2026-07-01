"""Certificate-only WRITE access to FortiWeb over SSH.

The web console's general SSH (:mod:`app.services.ssh_ops`) is hard **read-only**
(``assert_readonly`` — only ``get`` / ``show`` / ``diagnose``). But uploading a
signed certificate WITH its private-key material is the one certificate task REST
cannot do (cmdb can't carry a PEM), so the Certificate Manager needs a WRITE path.

Rather than loosen the read-only console, this module adds a SEPARATE, tightly
scoped door: :class:`FortiWebCertSSH` can run ONLY the
``config system certificate local`` block (import a Local certificate + key, or
delete one) and ``get system certificate local`` (list). It never accepts a raw
command — callers pass structured data (name + PEM), the block is built here — so
there is no way to smuggle another ``config`` in. It reuses the read-only class's
connection machinery (paramiko ``invoke_shell``, TOFU host keys, pager off).

Verified block shape (FortiWeb 7.6/8.0):

    config system certificate local
      edit "<name>"
        set certificate "<CERT PEM>"
        set private-key "<KEY PEM>"
      next
    end
"""
from __future__ import annotations

import re

from .ssh_ops import FortiSSHError, FortiWebReadonlySSH, clean_output

# A FortiWeb object name (mkey) — refuse anything that could break out of the
# quoted CLI value or inject another statement.
_NAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,63}$")


class CertWriteViolation(Exception):
    """A certificate operation failed validation before anything was sent."""


def assert_cert_name(name: str) -> str:
    name = (name or "").strip()
    if not _NAME_RE.match(name):
        raise CertWriteViolation(
            f"invalid certificate name {name!r} — use letters, digits, '.', '-', '_' (<=63)")
    return name


def _validate_pem(pem: str, *, kind: str) -> str:
    pem = (pem or "").strip()
    if "-----BEGIN" not in pem or "-----END" not in pem:
        raise CertWriteViolation(f"{kind} is not PEM (missing BEGIN/END markers)")
    if '"' in pem:
        raise CertWriteViolation(f"{kind} contains a double-quote — refusing (CLI injection guard)")
    return pem


class FortiWebCertSSH(FortiWebReadonlySSH):
    """SSH session that can import/delete a Local certificate — and nothing else.

    Inherits connect/close/read/pager from the read-only class; the write methods
    below are the ONLY mutations it can perform, each built from validated inputs.
    """

    # -- internal: send a raw multi-line block and return cleaned output ---
    def _send_block(self, block: str, *, quiet: float = 1.2, maxt: float = 30.0) -> str:
        if not self._shell:
            raise FortiSSHError("SSH session is not connected")
        self._shell.send(block if block.endswith("\n") else block + "\n")
        return clean_output(self._read(quiet, maxt), block.splitlines()[0] if block else "")

    # -- public cert operations -------------------------------------------
    def import_local_certificate(self, name: str, cert_pem: str, key_pem: str) -> str:
        """Upload a Local certificate + private key. Returns the CLI output.

        Builds the ``config system certificate local`` block from the validated
        name/PEMs — the block is fixed, only the values vary, so no other config
        area is reachable from here."""
        name = assert_cert_name(name)
        cert_pem = _validate_pem(cert_pem, kind="certificate")
        key_pem = _validate_pem(key_pem, kind="private key")
        block = (
            "config system certificate local\n"
            f'edit "{name}"\n'
            f'set private-key "{key_pem}"\n'
            f'set certificate "{cert_pem}"\n'
            "next\n"
            "end\n"
        )
        out = self._send_block(block)
        low = out.lower()
        if "command fail" in low or "return code" in low or "cannot be" in low or "invalid" in low:
            raise FortiSSHError(f"certificate import reported an error:\n{out.strip()[:1000]}")
        return out

    def delete_local_certificate(self, name: str) -> str:
        """Delete a Local certificate by name (used by revoke → remove-from-box,
        only after the caller confirmed it is not bound to any server policy)."""
        name = assert_cert_name(name)
        block = (
            "config system certificate local\n"
            f'delete "{name}"\n'
            "end\n"
        )
        return self._send_block(block)

    def list_local_certificates(self) -> list[str]:
        """Names of the Local certificates on the box (a READ, via ``get``)."""
        out = self.run_readonly("get system certificate local")
        names: list[str] = []
        for line in out.splitlines():
            m = re.match(r"^\s*==?\s*\[\s*(.+?)\s*\]", line) or re.match(r"^name\s*:\s*(\S+)", line)
            if m:
                names.append(m.group(1).strip())
        return names


# --------------------------------------------------------------------------- #
#  One-shot conveniences (open → run → close)                                 #
# --------------------------------------------------------------------------- #
def deploy_certificate(appliance, name: str, cert_pem: str, key_pem: str,
                       *, secret: str | None = None, timeout: float = 20.0) -> str:
    """Open a cert-only session, import the cert+key, close. Raises on failure."""
    with FortiWebCertSSH(appliance, secret=secret, timeout=timeout) as ssh:
        return ssh.import_local_certificate(name, cert_pem, key_pem)


def remove_certificate(appliance, name: str, *, secret: str | None = None,
                       timeout: float = 20.0) -> str:
    with FortiWebCertSSH(appliance, secret=secret, timeout=timeout) as ssh:
        return ssh.delete_local_certificate(name)


__all__ = [
    "FortiWebCertSSH", "CertWriteViolation",
    "assert_cert_name", "deploy_certificate", "remove_certificate",
]
