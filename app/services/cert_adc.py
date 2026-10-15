"""FortiADC certificate deployment (REST).

The FortiADC counterpart of :mod:`app.services.cert_ssh`. FortiWeb takes key
material over an SSH CLI block; FortiADC takes it over a REST multipart upload to
``/api/upload/certificate_local`` (``type=CertKey``) — VERIFIED LIVE on
FortiADC-KVM 8.0.3. Same contract: the manager only UPLOADS material a CA / third
party generated (REST cmdb can't carry a PEM), never generates keys.

``deploy_certificate`` mirrors ``cert_ssh.deploy_certificate`` so the shared
``cert_manager.create_certificate`` deploy step dispatches on ``appliance.kind``
with an identical call shape.
"""
from __future__ import annotations

import re

from ..clients.fortiadc import FortiADCClient, FortiADCError
from . import device_verify

_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,63}$")

#: The Local certificate store (cert + key pairs) — what an upload lands in.
LOCAL_STORE = "system_certificate_local"


class CertAdcError(RuntimeError):
    """A FortiADC certificate deploy failure."""


def assert_cert_name(name: str) -> str:
    name = (name or "").strip()
    if not _NAME_RE.match(name):
        raise CertAdcError(
            f"invalid certificate name {name!r} — use letters, digits, '.', '-', '_' (<=63)")
    return name


def _validate_pem(pem: str, *, kind: str) -> str:
    pem = (pem or "").strip()
    if "-----BEGIN" not in pem or "-----END" not in pem:
        raise CertAdcError(f"{kind} is not PEM (missing BEGIN/END markers)")
    return pem


def deploy_certificate(appliance, name: str, cert_pem: str, key_pem: str,
                       *, secret: str | None = None, bind_admin: bool = False) -> str:
    """Upload a Local certificate (cert + key) to a FortiADC over REST.

    Signature matches ``cert_ssh.deploy_certificate`` (``secret`` is accepted for
    call-shape parity; FortiADCClient reads the appliance's own decrypted
    password). Returns a short human-readable transcript. Raises
    :class:`CertAdcError` on refusal.
    """
    name = assert_cert_name(name)
    cert_pem = _validate_pem(cert_pem, kind="certificate")
    key_pem = _validate_pem(key_pem, kind="private key")
    client = FortiADCClient(appliance)
    try:
        client.upload_local_certificate(name, cert_pem, key_pem)
    except FortiADCError as exc:
        raise CertAdcError(f"FortiADC rejected the certificate upload: {exc}") from exc
    # An accepted upload is not proof the store now holds the certificate: it
    # is re-read by NAME only. The PEMs are never compared (the store answers
    # the decoded certificate, never the key, and certificate material has no
    # place in a verdict or an audit line).
    v = device_verify.adc_after_write(appliance, client, "create",
                                      logical=LOCAL_STORE, mkey=name,
                                      sent={"mkey": name})
    if device_verify.failed(v):
        raise CertAdcError(f"FortiADC accepted the upload of {name!r} but "
                           f"{device_verify.label(v)}")
    lines = [f"uploaded Local certificate {name!r} to {appliance.name} (REST, "
             + _outcome(v) + ")"]
    if bind_admin:
        try:
            client.bind_https_admin_cert(name)
            b = device_verify.adc_after_write(appliance, client, "update",
                                              logical="system_global", mkey="",
                                              sent={"https-server-cert": name})
            if device_verify.failed(b):
                lines.append(f"WARNING: admin-cert bind not applied: {device_verify.label(b)}")
            else:
                lines.append(f"bound admin HTTPS server cert → {name} ({_outcome(b)})")
        except FortiADCError as exc:
            lines.append(f"WARNING: admin-cert bind failed: {exc}")
    return "; ".join(lines)


def _outcome(v: dict) -> str:
    """The verdict as the transcript words it: "verified on the device" or
    "not verified: <why>" (a mismatch never reaches a success transcript)."""
    s = device_verify.label(v)
    return s[:1].lower() + s[1:]


def remove_certificate(appliance, name: str, *, secret: str | None = None) -> str:
    """Delete a Local certificate off a FortiADC over REST."""
    name = assert_cert_name(name)
    client = FortiADCClient(appliance)
    try:
        client.delete(LOCAL_STORE, name)
    except FortiADCError as exc:
        raise CertAdcError(f"FortiADC refused to delete {name!r}: {exc}") from exc
    # A delete is verified by ABSENCE (the measured ``{"payload": null}``): a
    # referenced certificate the box acknowledged and kept is a failure.
    v = device_verify.adc_after_write(appliance, client, "delete",
                                      logical=LOCAL_STORE, mkey=name)
    if device_verify.failed(v):
        raise CertAdcError(f"FortiADC accepted the delete of {name!r} but "
                           f"{device_verify.label(v)}")
    return f"deleted Local certificate {name!r} from {appliance.name} ({_outcome(v)})"


# --------------------------------------------------------------------------- #
#  Device-certificate SCAN (the ADC read side of the Cert Manager inventory)   #
# --------------------------------------------------------------------------- #
# Unlike FortiWeb (name-only cmdb rows; the X.509 detail needs an SSH read),
# FortiADC's REST cert payload ALREADY carries the decoded certificate —
# issuer/subject DN, validfrom/validto, serial, key type (verified live on
# fadc 8.0.3) — so the ADC scan is pure REST, no SSH session.
ADC_CERT_STORES = (
    ("local", "Local", "system_certificate_local"),
    ("ca", "CA", "system_certificate_ca"),
    ("intermediate_ca", "Intermediate CA", "system_certificate_intermediate_ca"),
    ("remote", "Remote", "system_certificate_remote"),
)


def _dn_part(dn: str, key: str) -> str:
    """Extract one RDN value from a slash-separated DN
    (``/C=US/O=Fortinet/CN=FortiADCVM/emailAddress=…``)."""
    m = re.search(r"/%s=([^/]*)" % re.escape(key), dn or "")
    return (m.group(1) if m else "").strip()


def _parse_validity(value: str):
    """``2019-02-27 15:50:09 PST`` → naive datetime (device-local; the trailing
    timezone token is dropped — day-level expiry is what the table shows)."""
    from datetime import datetime
    s = (value or "").strip()
    parts = s.split()
    if len(parts) >= 2:
        try:
            return datetime.strptime(" ".join(parts[:2]), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return None


def detail_from_payload(row: dict) -> dict:
    """cert_probe-shaped detail dict from a FortiADC certificate payload row
    (feeds ``DeviceCertificate.apply_detail`` — same contract as the FortiWeb
    SSH/PEM probes)."""
    if not isinstance(row, dict):
        return {}
    det = {
        "cn": _dn_part(row.get("subject", ""), "CN"),
        "issuer_cn": _dn_part(row.get("issuer", ""), "CN"),
        "serial": str(row.get("sn") or ""),
        "key_type": str(row.get("type") or ""),
        "not_before": _parse_validity(row.get("validfrom", "")),
        "not_after": _parse_validity(row.get("validto", "")),
    }
    return {k: v for k, v in det.items() if v}


def sweep_certificates(appliance, *, timeout: float = 6.0) -> dict:
    """Read every ADC certificate store over REST.

    Returns the same entry shape as the FortiWeb sweep —
    ``{appliance, online, error, certs[]}`` — with each cert additionally
    carrying its decoded ``detail`` (free on ADC: it rides the list payload).
    Best-effort: a failing FIRST store marks the box offline; a store missing
    on a given build contributes nothing.
    """
    entry = {"appliance": appliance, "online": True, "error": None, "certs": []}
    try:
        client = FortiADCClient(appliance, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        entry["online"] = False
        entry["error"] = type(exc).__name__
        return entry
    for idx, (_key, label, logical) in enumerate(ADC_CERT_STORES):
        try:
            rows, err = client.list_with_error(logical)
            if err:
                raise CertAdcError(err)
        except Exception as exc:  # noqa: BLE001
            if idx == 0:
                entry["online"] = False
                entry["error"] = str(exc)[:120] or type(exc).__name__
                break
            continue
        for row in rows:
            if not isinstance(row, dict) or not row.get("mkey"):
                continue
            entry["certs"].append({
                "name": str(row["mkey"]),
                "store": label,
                "type": str(row.get("type") or ""),
                "status": str(row.get("status") or ""),
                "comment": str(row.get("comments") or ""),
                "detail": detail_from_payload(row),
            })
    entry["certs"].sort(key=lambda c: (c["store"], c["name"].lower()))
    return entry


def bindings_index(client) -> dict:
    """One-pass ``cert_name -> [binding labels]`` for a FortiADC (best-effort —
    a failed leg just contributes nothing). See :func:`_bindings`."""
    idx, _complete = _bindings(client)
    return idx


def enumerate_usage(client, cert_name: str) -> tuple[bool, list]:
    """Fail-closed usage check for ONE cert: ``(complete, usage_rows)``.

    ``complete`` is False when ANY binding leg failed to read — the caller must
    then refuse a delete (same contract as the FortiWeb ``_enumerate_usage``).
    """
    idx, complete = _bindings(client)
    return complete, [{"kind": "adc", "target": lbl, "field": "",
                       "sub_mkey": None, "label": lbl, "probe": None}
                      for lbl in sorted(idx.get(cert_name, ()))]


def _bindings(client) -> tuple[dict, bool]:
    """``(cert_name -> {labels}, complete)`` for a FortiADC.

    The ADC binding chain (live-verified on fadc 8.0.3): a Local cert is a
    member of a **local cert group** (child table ``…_child_group_member``,
    field ``local_cert``); a **client SSL profile** binds a group
    (``local_certificate_group``); a **virtual server** binds a profile. Plus
    the admin GUI cert (``system_global.https-server-cert``). Read-only;
    ``complete`` goes False on any failed leg.
    """
    complete = True
    idx: dict[str, set] = {}
    cert_groups: dict[str, list] = {}
    try:
        groups, err = client.list_with_error("system_certificate_local_cert_group")
        if err:
            raise CertAdcError(err)
        for g in groups:
            gname = str(g.get("mkey", "")).strip()
            if not gname:
                continue
            members, merr = client.list_with_error(
                "system_certificate_local_cert_group_child_group_member", pkey=gname)
            if merr:
                complete = False
            certs = [str(m.get("local_cert", "")).strip()
                     for m in members if isinstance(m, dict) and m.get("local_cert")]
            cert_groups[gname] = certs
            for c in certs:
                idx.setdefault(c, set()).add(f"Cert group {gname}")
    except Exception:  # noqa: BLE001
        complete = False
    try:
        profiles, perr = client.list_with_error("load_balance_client_ssl_profile")
        if perr:
            raise CertAdcError(perr)
        group_profiles: dict[str, list] = {}
        for p in profiles:
            if not isinstance(p, dict):
                continue
            pname = str(p.get("mkey", "")).strip()
            grp = str(p.get("local_certificate_group", "")).strip()
            if pname and grp:
                group_profiles.setdefault(grp, []).append(pname)
                for c in cert_groups.get(grp, ()):
                    idx.setdefault(c, set()).add(f"SSL profile {pname}")
        vss, verr = client.list_with_error("load_balance_virtual_server")
        if verr:
            raise CertAdcError(verr)
        for vs in vss:
            if not isinstance(vs, dict):
                continue
            vname = str(vs.get("mkey", "")).strip()
            prof = str(vs.get("client_ssl_profile", "")).strip()
            if not (vname and prof):
                continue
            for grp, profs in group_profiles.items():
                if prof in profs:
                    for c in cert_groups.get(grp, ()):
                        idx.setdefault(c, set()).add(f"Virtual server {vname}")
    except Exception:  # noqa: BLE001
        complete = False
    try:
        g, gerr = client.list_with_error("system_global")
        if gerr:
            raise CertAdcError(gerr)
        if g and isinstance(g[0], dict):
            admin_cert = str(g[0].get("https-server-cert", "")).strip()
            if admin_cert:
                idx.setdefault(admin_cert, set()).add("Admin GUI (system_global)")
    except Exception:  # noqa: BLE001
        complete = False
    return idx, complete


# --------------------------------------------------------------------------- #
#  Swap: move every reference of one Local cert onto another                   #
# --------------------------------------------------------------------------- #
GROUP_TABLE = "system_certificate_local_cert_group"
MEMBER_TABLE = "system_certificate_local_cert_group_child_group_member"


def swap_references(appliance, old_name: str, new_name: str) -> dict:
    """Point every place that names *old_name* at *new_name*.

    On a FortiADC a certificate is referenced in exactly two places: as a
    member of a local cert group (an SSL profile binds the group, a virtual
    server binds the profile — so changing the member is the whole swap) and
    as the admin GUI cert. Each member is rewritten with a PUT on the child
    table and RE-READ: a member still naming the old cert is a failure.

    Returns ``{complete, done: [labels], failed: [(label, error)]}``.
    ``complete`` is False when the group walk could not be read — the caller
    must not treat "nothing found" as "nothing bound" then."""
    assert_cert_name(old_name)
    assert_cert_name(new_name)
    client = FortiADCClient(appliance)
    out = {"complete": True, "done": [], "failed": []}
    try:
        groups, err = client.list_with_error(GROUP_TABLE)
        if err:
            raise CertAdcError(err)
    except Exception as exc:  # noqa: BLE001
        out["complete"] = False
        out["failed"].append(("cert groups", str(exc)))
        groups = []
    for g in groups or []:
        gname = str(g.get("mkey", "")).strip() if isinstance(g, dict) else ""
        if not gname:
            continue
        members, merr = client.list_with_error(MEMBER_TABLE, pkey=gname)
        if merr:
            out["complete"] = False
            out["failed"].append((f"Cert group {gname}", merr))
            continue
        for m in members or []:
            if not (isinstance(m, dict) and str(m.get("local_cert", "")).strip() == old_name):
                continue
            label = f"Cert group {gname} (member {m.get('mkey')})"
            try:
                client.update(MEMBER_TABLE, str(m.get("mkey")),
                              dict(m, local_cert=new_name), pkey=gname)
                again, _e = client.list_with_error(MEMBER_TABLE, pkey=gname)
                now = next((x for x in again or [] if isinstance(x, dict)
                            and str(x.get("mkey")) == str(m.get("mkey"))), {})
                if str(now.get("local_cert", "")).strip() != new_name:
                    raise CertAdcError("the member still names "
                                       f"{now.get('local_cert')!r} after the write")
                out["done"].append(label)
            except Exception as exc:  # noqa: BLE001
                out["failed"].append((label, str(exc)))
    try:
        g, gerr = client.list_with_error("system_global")
        if gerr:
            raise CertAdcError(gerr)
        if g and isinstance(g[0], dict) and \
                str(g[0].get("https-server-cert", "")).strip() == old_name:
            try:
                client.bind_https_admin_cert(new_name)
                out["done"].append("Admin GUI (system_global)")
            except Exception as exc:  # noqa: BLE001
                out["failed"].append(("Admin GUI (system_global)", str(exc)))
    except Exception as exc:  # noqa: BLE001
        out["complete"] = False
        out["failed"].append(("system_global", str(exc)))
    return out
