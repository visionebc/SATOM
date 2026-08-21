"""Carrying certificate MATERIAL between appliances — over the CLI, never REST.

``cmdb`` cannot move a PEM. A local certificate POSTed over REST answers 200 and
lands with ``certificate: ""``; an OCSP signing certificate does the same, which
is worse than a refusal because the run reports success. So the clone reports
those objects and never writes them — until the operator turns THIS on.

WHAT THE APPLIANCE WILL AND WILL NOT EMIT — measured on fortiweb12 (7.6.8), and
the whole feature rests on it:

    get  (inside the entry)   ->  Subject / Issuer, ``certificate:`` EMPTY
    show (inside the entry)   ->  set certificate  "-----BEGIN CERTIFICATE..."
                                  set private-key  "-----BEGIN ... PRIVATE KEY..."

``show`` is the only verb that emits the bytes, and it emits the PRIVATE KEY
too. REST never does, for either field, which is why the tool's own
:mod:`clone` classifies these objects ``cert``.

⚠ THE SCOPE IS NOT OPTIONAL, AND IT IS NOT THE SAME ON EVERY BOX
    Measured, both directions, same firmware:

        fortiweb12 (ADOMs enabled)   config system certificate local  -> REFUSED
                                     at the top level; reachable only after
                                     ``config vdom`` / ``edit <adom>``
        fortiweb13 (no ADOMs)        the same command at the top level -> accepted

    A session that assumes either shape works on half the fleet, and the failure
    is a CLI parse error that reads like a broken command rather than a wrong
    scope. So the scope is DISCOVERED: top level first, ADOM second, and a
    session that reaches neither says so instead of returning empty material.

SECRECY
    A private key read here exists in memory for the length of one transfer and
    goes nowhere else. It is never put in a :class:`~app.services.clone.CloneItem`
    payload, never in a plan, never in a report, never in a log line. The only
    thing that leaves this module about a key is whether one was found.
"""
from __future__ import annotations

import re

from .cert_ssh import CertWriteViolation, FortiWebCertSSH, assert_cert_name  # noqa: F401

#: ``set <field> "<PEM>"`` as ``show`` prints it. The value is quoted and spans
#: lines, so this is deliberately non-greedy and DOTALL-bounded by the closing
#: quote — a line-wise parser would return the first line of a PEM.
_SET_PEM_RE = r'set\s+%s\s+"(-----BEGIN.*?-----END[^"]*?)"'

def bare(collection: str) -> str:
    """``cmdb/system/certificate.local`` -> ``system/certificate.local``.

    The clone's urns carry the ``cmdb/`` prefix and
    :func:`cert_import.spec_for` is keyed WITHOUT it. A lookup that missed on
    the prefix would answer "REST can create this" for a collection REST cannot
    create at all — the 200-that-drops-the-PEM, reported as a success.
    """
    c = (collection or "").strip()
    return c[5:] if c.startswith("cmdb/") else c


def required_fields(spec) -> tuple:
    """Which PEM fields must be present for a carry to be honest.

    DERIVED from the spec, never restated here. A hand-kept copy is how this
    stops agreeing with :mod:`cert_import` on the next collection someone adds,
    and the failure is silent: a key field missing from the copy is simply never
    read, so the certificate lands public-half-only and reports as carried.
    ``key_field`` is ``None`` for the collections that are public material (a CA,
    an intermediate CA, an OCSP signing certificate) and ``secret-key`` — not
    ``private-key`` — for an XML client certificate.
    """
    fields = ["certificate"]
    if getattr(spec, "key_field", None):
        fields.append(spec.key_field)
    return tuple(fields)


def parse_material(text: str, fields=("certificate", "private-key")) -> dict:
    """Pull the PEM values out of a ``show`` block. Returns ``{field: pem}``.

    Only fields that actually carry a PEM appear. A field present but empty is
    ABSENT here on purpose: ``set certificate ""`` means the entry is a shell,
    and returning it as a value would let a shell be copied as if it were a
    certificate.
    """
    body = (text or "").replace("\r", "")
    out: dict = {}
    for f in fields:
        m = re.search(_SET_PEM_RE % re.escape(f), body, re.S)
        if m:
            # No second BEGIN/END check here: _SET_PEM_RE cannot match without
            # both. A guard that repeats what the pattern already enforces is a
            # second safeguard over one hole, and it makes NEITHER of them
            # demonstrable — a mutation that removes either one changes nothing.
            out[f] = m.group(1).strip()
    return out


class CertScopeSSH(FortiWebCertSSH):
    """A session that READS certificate material, reusing the write class's scope.

    It subclasses the write class ON PURPOSE rather than the read-only one: the
    scope discovery (top level first, ADOM second) is measured behaviour of the
    appliance, not of a direction, and a second copy of it would drift the day
    one of the two is corrected. Nothing here calls an import.

    A THIRD narrow door, alongside :func:`ssh_ops.assert_readonly` and
    :func:`ssh_ops.assert_probe_command`, for the reason the second one exists:
    the console's verb allowlist stays exactly as tight as it is. No command
    here comes from a caller — the table is resolved from a collection and the
    entry name is validated, so the only strings that reach the wire are built
    below.
    """

    def show_entry(self, cli_table: str, name: str) -> str:
        """``show`` one entry of an already-entered table. Never a raw command."""
        name = assert_cert_name(name)
        if self._refused(self._line('edit "%s"' % name, maxt=20)):
            return ""
        body = self._line("show", quiet=1.6, maxt=60)
        # ``abort`` leaves the entry WITHOUT writing, and it has been seen to
        # fail on this firmware. Nothing was set, so ``next`` is equally
        # harmless — but one of the two must run or the session stays inside the
        # entry and every later command lands there.
        if self._refused(self._line("abort", quiet=0.5, maxt=8)):
            self._line("next", quiet=0.5, maxt=8)
        return body


def read_material(appliance, collection: str, name: str, *,
                  secret: str | None = None, timeout: float = 30.0) -> dict:
    """Read one certificate's material off ``appliance``.

    Returns ``{"ok", "complete", "material", "missing", "scope", "reason"}``.
    ``material`` maps field -> PEM and is the ONLY place a private key appears.

    ``complete`` is separate from ``ok`` and the distinction is the point: a
    certificate whose entry exists but whose key the box did not print is a
    certificate that CANNOT be carried, and copying its public half would create
    a certificate the destination can never serve with.
    """
    from .cert_import import spec_for

    spec = spec_for(bare(collection))
    if spec is None:
        raise CertWriteViolation(
            "%r is not an SSH-only certificate collection" % (collection,))
    table = spec.cli_table
    want = required_fields(spec)
    res = {"ok": False, "complete": False, "material": {}, "missing": list(want),
           "scope": "", "reason": ""}
    sess = CertScopeSSH(appliance, secret=secret, timeout=timeout)
    try:
        sess.connect()
        res["scope"] = sess.enter_table(table)
        body = sess.show_entry(table, name)
    except Exception as exc:  # noqa: BLE001
        res["reason"] = str(exc)
        return res
    finally:
        try:
            sess.leave_table()
        except Exception:  # noqa: BLE001
            pass
        try:
            sess.close()
        except Exception:  # noqa: BLE001
            pass
    if not body:
        res["reason"] = "the appliance does not list %r in %s" % (name, table)
        return res
    mat = parse_material(body, fields=want)
    res["ok"] = True
    res["material"] = mat
    res["missing"] = [f for f in want if f not in mat]
    res["complete"] = not res["missing"]
    if not res["complete"]:
        res["reason"] = ("the appliance printed no %s for %r — it cannot be "
                         "carried" % (" or ".join(res["missing"]), name))
    return res


def names_at(appliance, collection: str, *, secret: str | None = None,
             timeout: float = 25.0) -> list:
    """The entry names a certificate table holds, read over the CLI.

    Deliberately NOT read over REST. For ``ocsp-signing-certs`` a cmdb POST
    answers 200 and drops the PEM, and REST then prints ``certificate: ""`` for
    that shell AND for an entry that really holds one — so a REST-listed name is
    not evidence the destination has usable material. The CLI list is the one
    that means what it says, and this session has to open anyway.
    """
    from .cert_import import spec_for

    spec = spec_for(bare(collection))
    if spec is None:
        raise CertWriteViolation(
            "%r is not an SSH-only certificate collection" % (collection,))
    with FortiWebCertSSH(appliance, secret=secret, timeout=timeout) as sess:
        return sess.list_certificates(spec)


def carry(src_appliance, dst_appliance, collection: str, name: str, *,
          src_secret: str | None = None, dst_secret: str | None = None,
          timeout: float = 30.0) -> dict:
    """Read material off the source and import it into the destination.

    Returns ``{"ok", "carried", "reason", "scope"}``. NEVER returns the key.

    An INCOMPLETE read is refused, not partially written: half a certificate at
    the destination is an object that exists, reports as present, and cannot
    terminate a single connection.
    """
    out = {"ok": False, "carried": False, "reason": "", "scope": ""}
    got = read_material(src_appliance, collection, name, secret=src_secret,
                        timeout=timeout)
    out["scope"] = got["scope"]
    if not got["ok"] or not got["complete"]:
        out["reason"] = got["reason"] or "the source material could not be read"
        return out
    from . import cert_ssh
    from .cert_import import spec_for
    spec = spec_for(bare(collection))
    key_field = getattr(spec, "key_field", None)
    try:
        cert_ssh.import_into(dst_appliance, bare(collection), name,
                             got["material"].get("certificate", ""),
                             got["material"].get(key_field, "") if key_field else "",
                             secret=dst_secret, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        out["reason"] = "the destination refused it: %s" % exc
        return out
    finally:
        got["material"].clear()      # the key does not outlive the transfer
    out["ok"] = out["carried"] = True
    return out
