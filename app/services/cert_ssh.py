"""Certificate-only WRITE access to FortiWeb over SSH.

The web console's general SSH (:mod:`app.services.ssh_ops`) is hard **read-only**
(``assert_readonly`` — only ``get`` / ``show`` / ``diagnose``). But uploading a
signed certificate WITH its private-key material is the one certificate task REST
cannot do (cmdb can't carry a PEM), so the Certificate Manager needs a WRITE path.

Rather than loosen the read-only console, this module adds a SEPARATE, tightly
scoped door: :class:`FortiWebCertSSH` can run ONLY a
``config system certificate <table>`` block (import a certificate + key, or
delete one) and ``get system certificate <table>`` (list). It never accepts a raw
command — callers pass a :class:`~app.services.cert_import.CertImportSpec` plus
structured data (name + PEM), the block is built here — so there is no way to
smuggle another ``config`` in. It reuses the read-only class's connection
machinery (paramiko ``invoke_shell``, TOFU host keys, pager off).

Verified block shape (FortiWeb 7.6/8.0):

    config system certificate local
      edit "<name>"
        set certificate "<CERT PEM>"
        set private-key "<KEY PEM>"
      next
    end

**The table is not always ``local``.** The 2026-08-19 sweep measured SIX
collections a cmdb POST cannot create at all — ``local``, ``ca``, ``sign-ca``,
``intermediate-certificate``, ``xml-server-certificate``,
``xml-client-certificate`` — and each names its fields slightly differently
(``ca`` and ``intermediate-certificate`` have no key at all;
``xml-client-certificate`` calls its key ``secret-key``). The table and the field
names come from :mod:`app.services.cert_import`, never from a caller's string:
the spec is looked up by collection, so an unknown collection cannot reach the
CLI at all.
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
    def import_certificate(self, spec, name: str, cert_pem: str,
                           key_pem: str = "", passphrase: str = "") -> str:
        """Upload a certificate (+ key, when the table has one). Returns the CLI output.

        ``spec`` is a :class:`~app.services.cert_import.CertImportSpec`; the table
        and every field name come from it, so the block stays fixed and only the
        values vary — no other config area is reachable from here.

        A key passed for a table that has NO key field is refused rather than
        dropped: silently discarding it would upload a keyless object and report
        success, which is the "created but empty" failure this module exists to
        avoid.
        """
        name = assert_cert_name(name)
        cert_pem = _validate_pem(cert_pem, kind="certificate")
        lines = [f"config system certificate {spec.cli_table}", f'edit "{name}"']
        if spec.key_field:
            key_pem = _validate_pem(key_pem, kind=spec.key_label.lower())
            lines.append(f'set {spec.key_field} "{key_pem}"')
        elif (key_pem or "").strip():
            raise CertWriteViolation(
                f"{spec.label} holds no private key — refusing to send one "
                f"(collection {spec.collection})")
        if passphrase:
            if not spec.passphrase_field:
                raise CertWriteViolation(
                    f"{spec.label} takes no key passphrase (collection {spec.collection})")
            if '"' in passphrase:
                raise CertWriteViolation(
                    "passphrase contains a double-quote — refusing (CLI injection guard)")
            lines.append(f'set {spec.passphrase_field} "{passphrase}"')
        lines += [f'set certificate "{cert_pem}"', "next", "end", ""]
        out = self._send_block("\n".join(lines))
        low = out.lower()
        if "command fail" in low or "return code" in low or "cannot be" in low or "invalid" in low:
            raise FortiSSHError(f"certificate import reported an error:\n{out.strip()[:1000]}")
        return out

    def import_local_certificate(self, name: str, cert_pem: str, key_pem: str) -> str:
        """Back-compat shim for the Certificate Manager's deploy path."""
        from .cert_import import SSH_ONLY_SPECS

        return self.import_certificate(SSH_ONLY_SPECS["system/certificate.local"],
                                       name, cert_pem, key_pem)

    def delete_certificate(self, spec, name: str) -> str:
        """Delete a certificate by name from ``spec``'s table."""
        name = assert_cert_name(name)
        block = (
            f"config system certificate {spec.cli_table}\n"
            f'delete "{name}"\n'
            "end\n"
        )
        return self._send_block(block)

    def delete_local_certificate(self, name: str) -> str:
        """Delete a Local certificate by name (used by revoke → remove-from-box,
        only after the caller confirmed it is not bound to any server policy)."""
        from .cert_import import SSH_ONLY_SPECS

        return self.delete_certificate(SSH_ONLY_SPECS["system/certificate.local"], name)

    def list_certificates(self, spec) -> list[str]:
        """Names in ``spec``'s table (a READ, via ``get``)."""
        out = self.run_readonly(f"get system certificate {spec.cli_table}")
        names: list[str] = []
        for line in out.splitlines():
            m = re.match(r"^\s*==?\s*\[\s*(.+?)\s*\]", line) or re.match(r"^name\s*:\s*(\S+)", line)
            if m:
                names.append(m.group(1).strip())
        return names

    def list_local_certificates(self) -> list[str]:
        """Names of the Local certificates on the box (a READ, via ``get``)."""
        from .cert_import import SSH_ONLY_SPECS

        return self.list_certificates(SSH_ONLY_SPECS["system/certificate.local"])


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


def import_into(appliance, collection: str, name: str, cert_pem: str,
                key_pem: str = "", passphrase: str = "", *,
                secret: str | None = None, timeout: float = 25.0) -> str:
    """Import into ANY of the six SSH-only certificate collections.

    The spec is resolved from the collection here — a collection REST *can*
    create never reaches the CLI, so this door cannot be widened by a caller
    passing a different string.
    """
    from .cert_import import spec_for

    spec = spec_for(collection)
    if spec is None:
        raise CertWriteViolation(
            f"{collection!r} is not an SSH-only certificate collection — "
            "create it through the REST editor")
    with FortiWebCertSSH(appliance, secret=secret, timeout=timeout) as ssh:
        return ssh.import_certificate(spec, name, cert_pem, key_pem, passphrase)


__all__ = [
    "FortiWebCertSSH", "CertWriteViolation",
    "assert_cert_name", "deploy_certificate", "remove_certificate", "import_into",
]
