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


class FortiWebCertSSH(FortiWebReadonlySSH):  # noqa: D101 - see below
    """SSH session that can import/delete a Local certificate — and nothing else.

    Inherits connect/close/read/pager from the read-only class; the write methods
    below are the ONLY mutations it can perform, each built from validated inputs.
    """

    #: "" until :meth:`enter_table` has run: "device" | "adom".
    _scope: str = ""

    # -- internal: send a raw multi-line block and return cleaned output ---
    def _send_block(self, block: str, *, quiet: float = 1.2, maxt: float = 30.0) -> str:
        if not self._shell:
            raise FortiSSHError("SSH session is not connected")
        self._shell.send(block if block.endswith("\n") else block + "\n")
        return clean_output(self._read(quiet, maxt), block.splitlines()[0] if block else "")

    # -- scope: WHERE the certificate table lives on THIS box --------------
    #
    # Measured on the same firmware (7.6.8), and the two answers disagree:
    #
    #   fortiweb12 (ADOMs enabled)  `config system certificate local` at the top
    #                               level -> "Parsing error at 'system'".
    #                               Reachable only after `config vdom` /
    #                               `edit <adom>`.
    #   fortiweb13 (no ADOMs)       the same command at the top level -> accepted,
    #                               and there is no `config vdom` to descend into.
    #
    # So neither shape may be assumed. Before this, the whole import block was
    # sent as ONE blob beginning with that command: on an ADOM box the first
    # line parse-errored and every following line — INCLUDING the PEM and the
    # PRIVATE KEY — was then interpreted at whatever prompt happened to be
    # current. The failure did not read as "wrong scope", it read as a broken
    # command.
    #
    # ONE primitive, used by the import, the delete and the list, so a fourth
    # caller cannot rediscover this the hard way.
    def _line(self, cmd: str, *, quiet: float = 1.0, maxt: float = 25.0) -> str:
        if not self._shell:
            raise FortiSSHError("SSH session is not connected")
        self._shell.send(cmd + "\n")
        return clean_output(self._read(quiet, maxt), cmd)

    @staticmethod
    def _refused(out: str) -> bool:
        return bool(re.search(r"Parsing error|Command fail|Unknown action",
                              out or "", re.I))

    def enter_table(self, cli_table: str) -> str:
        """Enter ``config system certificate <cli_table>``. Returns the scope.

        Top level FIRST, so a box without ADOMs behaves exactly as it did.
        Raises rather than proceeding: an unentered table means the next line
        would be read somewhere else entirely.
        """
        if not re.match(r"^[a-z0-9\-]{1,40}$", cli_table or ""):
            raise CertWriteViolation("unrecognised certificate table %r"
                                     % (cli_table,))
        if not self._refused(self._line("config system certificate %s" % cli_table)):
            self._scope = "device"
            return self._scope
        adom = str(getattr(self.appliance, "vdom", "") or "").strip() or "root"
        if self._refused(self._line("config vdom")):
            raise FortiSSHError(
                "the certificate table is not reachable at the top level and "
                "this appliance offers no vdom scope")
        if self._refused(self._line("edit %s" % assert_cert_name(adom))):
            self._line("end")
            raise FortiSSHError("could not enter vdom %r" % adom)
        if self._refused(self._line("config system certificate %s" % cli_table)):
            self._line("end")
            self._line("end")
            raise FortiSSHError("the certificate table %r is not reachable in "
                                "vdom %r either" % (cli_table, adom))
        self._scope = "adom"
        return self._scope

    def leave_table(self) -> None:
        """Climb back out of however many levels ``enter_table`` went in."""
        for _ in range(3 if getattr(self, "_scope", "") == "adom" else 1):
            try:
                self._line("end", quiet=0.5, maxt=8)
            except Exception:  # noqa: BLE001
                break
        self._scope = ""

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
        lines = [f'edit "{name}"']
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
        lines += [f'set certificate "{cert_pem}"', "next", ""]
        self.enter_table(spec.cli_table)
        try:
            out = self._send_block("\n".join(lines))
        finally:
            self.leave_table()
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
        self.enter_table(spec.cli_table)
        try:
            return self._send_block(f'delete "{name}"\n')
        finally:
            self.leave_table()

    def delete_local_certificate(self, name: str) -> str:
        """Delete a Local certificate by name (used by revoke → remove-from-box,
        only after the caller confirmed it is not bound to any server policy)."""
        from .cert_import import SSH_ONLY_SPECS

        return self.delete_certificate(SSH_ONLY_SPECS["system/certificate.local"], name)

    def list_certificates(self, spec) -> list[str]:
        """Names in ``spec``'s table (a READ, via ``get``)."""
        # ``get system certificate <table>`` at the top level answers "Parsing
        # error at 'system'" on an ADOM box — the same scope trap, and here it
        # returned an EMPTY name list, which reads as "the box has no
        # certificates" rather than as a failure.
        self.enter_table(spec.cli_table)
        try:
            out = self._line("get", quiet=1.4, maxt=40)
        finally:
            self.leave_table()
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
