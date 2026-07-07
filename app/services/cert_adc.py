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

_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,63}$")


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
    lines = [f"uploaded Local certificate {name!r} to {appliance.name} (REST)"]
    if bind_admin:
        try:
            client.bind_https_admin_cert(name)
            lines.append(f"bound admin HTTPS server cert → {name}")
        except FortiADCError as exc:
            lines.append(f"WARNING: admin-cert bind failed: {exc}")
    return "; ".join(lines)


def remove_certificate(appliance, name: str, *, secret: str | None = None) -> str:
    """Delete a Local certificate off a FortiADC over REST."""
    name = assert_cert_name(name)
    client = FortiADCClient(appliance)
    try:
        client.delete('system_certificate_local', name)
    except FortiADCError as exc:
        raise CertAdcError(f"FortiADC refused to delete {name!r}: {exc}") from exc
    return f"deleted Local certificate {name!r} from {appliance.name}"


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
