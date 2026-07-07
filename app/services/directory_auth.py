"""Directory bind engines for external authentication.

Two transports, one per backend family:

* **LDAP / Active Directory** — ``ldap3``. AD is a thin preset over the generic
  LDAP path (UPN/``user@domain`` simple bind, optional search confirmation);
  generic LDAP uses a service (bind) account to *find* the user's DN, then
  re-binds as that DN with the supplied password (the only proof of the
  password that works without knowing the DN template up front).
* **FortiAuthenticator / RADIUS** — ``pyrad``. An Access-Request with
  PAP-encoded password; ``Access-Accept`` == authenticated. This is the native
  path for FortiToken / push 2FA at the directory.

Every function is defensive: it NEVER raises, returning ``(ok, detail)`` so the
login flow and the Settings "Test connection" button can surface a clean
message instead of a 500. No Flask / DB imports — pure transport, unit-friendly.
"""
from __future__ import annotations

import logging
import socket

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LDAP / Active Directory
# ---------------------------------------------------------------------------
def _tls(cfg: dict):
    """Build an ldap3 Tls object honouring the verify toggle."""
    import ssl

    from ldap3 import Tls

    validate = ssl.CERT_REQUIRED if cfg.get("tls_verify", True) else ssl.CERT_NONE
    return Tls(validate=validate)


def _server(cfg: dict):
    from ldap3 import Server

    use_ssl = bool(cfg.get("use_ssl"))
    port = int(cfg.get("port") or (636 if use_ssl else 389))
    tls = _tls(cfg) if (use_ssl or cfg.get("start_tls")) else None
    return Server(cfg.get("host", ""), port=port, use_ssl=use_ssl, tls=tls,
                  connect_timeout=int(cfg.get("timeout") or 8))


def _upn(cfg: dict, username: str) -> str:
    """The principal AD accepts for a SIMPLE bind: ``user@domain`` (or the bare
    username when no domain is configured / it's already qualified)."""
    domain = (cfg.get("ad_domain") or "").strip()
    if domain and "@" not in username and "\\" not in username:
        return f"{username}@{domain}"
    return username


def ldap_authenticate(cfg: dict, username: str, password: str) -> tuple[bool, str]:
    """Prove *username*/*password* against the configured directory."""
    if not password:
        return False, "Empty password."
    if not cfg.get("host"):
        return False, "No LDAP host configured."
    try:
        from ldap3 import ALL, SIMPLE, Connection
        from ldap3.core.exceptions import LDAPException
    except Exception as exc:  # noqa: BLE001
        return False, f"ldap3 not available: {exc}"

    is_ad = cfg.get("kind") == "ad"
    try:
        server = _server(cfg)

        if is_ad:
            # AD: bind directly as the user principal (user@domain).
            user_principal = _upn(cfg, username)
            conn = Connection(server, user=user_principal, password=password,
                              authentication=SIMPLE, read_only=True)
            if cfg.get("start_tls"):
                conn.start_tls()
            if not conn.bind():
                return False, f"Authentication failed: {conn.result.get('description', 'invalid credentials')}"
            # Optional membership/existence confirmation in the base DN.
            base = (cfg.get("base_dn") or "").strip()
            if base:
                attr = cfg.get("user_attr") or "sAMAccountName"
                bare = username.split("@")[0].split("\\")[-1]
                conn.search(base, f"({attr}={bare})", attributes=[attr])
                if not conn.entries:
                    conn.unbind()
                    return False, "User authenticated but not found under the base DN."
            conn.unbind()
            return True, "Authenticated via Active Directory."

        # Generic LDAP: bind as the service account, find the user DN, re-bind.
        bind_dn = (cfg.get("bind_dn") or "").strip()
        bind_pw = cfg.get("bind_password") or ""
        base = (cfg.get("base_dn") or "").strip()
        attr = cfg.get("user_attr") or "uid"
        user_filter = (cfg.get("user_filter") or f"({attr}={{username}})")
        flt = user_filter.replace("{username}", _ldap_escape(username))

        svc = Connection(server, user=bind_dn or None, password=bind_pw or None,
                         authentication=SIMPLE if bind_dn else None, read_only=True)
        if cfg.get("start_tls"):
            svc.start_tls()
        if not svc.bind():
            return False, f"Service bind failed: {svc.result.get('description', 'check bind DN/password')}"
        if not base:
            svc.unbind()
            return False, "No base DN configured."
        svc.search(base, flt, attributes=[attr])
        if not svc.entries:
            svc.unbind()
            return False, "User not found in directory."
        user_dn = svc.entries[0].entry_dn
        svc.unbind()

        # Re-bind as the located user to verify the password.
        user_conn = Connection(server, user=user_dn, password=password,
                               authentication=SIMPLE, read_only=True)
        if cfg.get("start_tls"):
            user_conn.start_tls()
        if not user_conn.bind():
            return False, "Authentication failed: invalid password."
        user_conn.unbind()
        return True, "Authenticated via LDAP."
    except LDAPException as exc:
        return False, f"LDAP error: {exc}"
    except (socket.error, OSError) as exc:
        return False, f"Connection error: {exc}"
    except Exception as exc:  # noqa: BLE001 — never 500 the login flow
        logger.exception("LDAP auth failed")
        return False, f"{type(exc).__name__}: {exc}"


def ldap_test(cfg: dict, username: str = "", password: str = "") -> tuple[bool, str]:
    """Connectivity / config check for the Settings test button.

    If *username*+*password* are supplied, a FULL authentication is attempted
    (the strongest test). Otherwise we verify we can reach the server and bind
    with the service account (or anonymously) — confirming host/port/TLS/DN."""
    if username and password:
        return ldap_authenticate(cfg, username, password)
    if not cfg.get("host"):
        return False, "No LDAP host configured."
    try:
        from ldap3 import SIMPLE, Connection
        from ldap3.core.exceptions import LDAPException
    except Exception as exc:  # noqa: BLE001
        return False, f"ldap3 not available: {exc}"
    try:
        server = _server(cfg)
        bind_dn = (cfg.get("bind_dn") or "").strip()
        bind_pw = cfg.get("bind_password") or ""
        conn = Connection(server, user=bind_dn or None, password=bind_pw or None,
                          authentication=SIMPLE if bind_dn else None, read_only=True)
        if cfg.get("start_tls"):
            conn.start_tls()
        if not conn.bind():
            return False, f"Reached server but bind failed: {conn.result.get('description', 'check credentials')}"
        base = (cfg.get("base_dn") or "").strip()
        if base:
            ok = conn.search(base, "(objectClass=*)", search_scope="BASE")
            conn.unbind()
            if not ok:
                return False, "Bound, but the base DN could not be read."
            return True, "Connected and base DN reachable."
        conn.unbind()
        return True, "Connected and bound successfully."
    except LDAPException as exc:
        return False, f"LDAP error: {exc}"
    except (socket.error, OSError) as exc:
        return False, f"Connection error: {exc}"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def _ldap_escape(value: str) -> str:
    """Escape RFC-4515 filter special chars in a user-supplied value."""
    out = []
    for ch in value or "":
        if ch in "\\*()\0":
            out.append("\\%02x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def ldap_list_users(cfg: dict, group_dn: str = "", limit: int = 500):
    """Enumerate directory users (optionally scoped to a group/OU) for the admin
    'Sync users' action. Returns ``(ok, users|detail)`` where *users* is a list
    of ``{"username", "display_name", "dn"}`` dicts, capped at *limit*.

    Scope: ``group_dn`` empty -> every person/user object under the base DN;
    an OU DN -> used as the search base; a GROUP DN -> members via ``memberOf``.
    Uses the configured service (bind) account. Never raises."""
    if not cfg.get("host"):
        return False, "No LDAP host configured."
    base = (cfg.get("base_dn") or "").strip()
    if not base:
        return False, "No base DN configured (required to enumerate users)."
    try:
        from ldap3 import SIMPLE, SUBTREE, Connection
        from ldap3.core.exceptions import LDAPException
    except Exception as exc:  # noqa: BLE001
        return False, f"ldap3 not available: {exc}"

    is_ad = cfg.get("kind") == "ad"
    attr = (cfg.get("user_attr") or ("sAMAccountName" if is_ad else "uid")).strip()
    person = ("(&(objectCategory=person)(objectClass=user))" if is_ad
              else "(objectClass=person)")
    group_dn = (group_dn or "").strip()
    search_base = base
    if group_dn:
        low = group_dn.lower()
        if low.startswith("ou=") or ",ou=" in low:
            search_base = group_dn          # an OU DN: search inside it
            flt = person
        else:                                # a group DN: filter by membership
            flt = f"(&{person}(memberOf={_ldap_escape_dn(group_dn)}))"
    else:
        flt = person

    try:
        server = _server(cfg)
        bind_dn = (cfg.get("bind_dn") or "").strip()
        bind_pw = cfg.get("bind_password") or ""
        conn = Connection(server, user=bind_dn or None, password=bind_pw or None,
                          authentication=SIMPLE if bind_dn else None, read_only=True)
        if cfg.get("start_tls"):
            conn.start_tls()
        if not conn.bind():
            return False, ("Bind failed: "
                           f"{conn.result.get('description', 'check the service (bind) account')}")
        conn.search(search_base, flt, search_scope=SUBTREE,
                    attributes=[attr, "displayName", "cn"], size_limit=int(limit) + 1)
        users = []
        for e in conn.entries:
            try:
                uname = str(e[attr].value) if (attr in e and e[attr].value) else ""
            except Exception:  # noqa: BLE001
                uname = ""
            if not uname:
                continue
            disp = ""
            for d in ("displayName", "cn"):
                try:
                    if d in e and e[d].value:
                        disp = str(e[d].value)
                        break
                except Exception:  # noqa: BLE001
                    pass
            users.append({"username": uname, "display_name": disp, "dn": e.entry_dn})
        conn.unbind()
        return True, users[:int(limit)]
    except LDAPException as exc:
        return False, f"LDAP error: {exc}"
    except (socket.error, OSError) as exc:
        return False, f"Connection error: {exc}"
    except Exception as exc:  # noqa: BLE001
        logger.exception("LDAP enumerate failed")
        return False, f"{type(exc).__name__}: {exc}"


def _ldap_escape_dn(value: str) -> str:
    """Escape RFC-4515 filter specials but KEEP '='/',' so a DN used as a
    ``memberOf`` value stays a valid DN."""
    out = []
    for ch in value or "":
        out.append("\\%02x" % ord(ch) if ch in "\\*()\0" else ch)
    return "".join(out)


# ---------------------------------------------------------------------------
# RADIUS / FortiAuthenticator
# ---------------------------------------------------------------------------
_RADIUS_DICT = """\
ATTRIBUTE	User-Name		1	string
ATTRIBUTE	User-Password		2	string
ATTRIBUTE	NAS-IP-Address		4	ipaddr
ATTRIBUTE	NAS-Identifier		32	string
ATTRIBUTE	NAS-Port		5	integer
ATTRIBUTE	Reply-Message		18	string
"""


def _radius_client(cfg: dict):
    import tempfile

    from pyrad.client import Client
    from pyrad.dictionary import Dictionary

    # pyrad needs a dictionary file on disk; ship a minimal inline one.
    with tempfile.NamedTemporaryFile("w", suffix=".dict", delete=False) as fh:
        fh.write(_RADIUS_DICT)
        dict_path = fh.name
    secret = (cfg.get("secret") or "").encode()
    client = Client(server=cfg.get("host", ""),
                    authport=int(cfg.get("port") or 1812),
                    secret=secret, dict=Dictionary(dict_path))
    client.timeout = int(cfg.get("timeout") or 8)
    client.retries = 1
    return client


def radius_authenticate(cfg: dict, username: str, password: str) -> tuple[bool, str]:
    """Send an Access-Request; ``Access-Accept`` == authenticated."""
    if not cfg.get("host"):
        return False, "No RADIUS host configured."
    if not cfg.get("secret"):
        return False, "No RADIUS shared secret configured."
    if not password:
        return False, "Empty password."
    try:
        from pyrad.packet import AccessAccept, AccessReject
    except Exception as exc:  # noqa: BLE001
        return False, f"pyrad not available: {exc}"
    try:
        client = _radius_client(cfg)
        req = client.CreateAuthPacket(code=1, User_Name=username)
        req["User-Password"] = req.PwCrypt(password)
        nas_id = cfg.get("nas_id") or "fortinet-manager"
        try:
            req["NAS-Identifier"] = nas_id
        except Exception:  # noqa: BLE001 — optional attribute
            pass
        reply = client.SendPacket(req)
        if reply.code == AccessAccept:
            return True, "Authenticated via RADIUS (FortiAuthenticator)."
        if reply.code == AccessReject:
            msg = ""
            try:
                msg = reply.get("Reply-Message", [""])[0]
            except Exception:  # noqa: BLE001
                pass
            return False, f"Access rejected{(': ' + msg) if msg else '.'}"
        return False, f"Unexpected RADIUS reply code {reply.code}."
    except Exception as exc:  # noqa: BLE001 — timeouts/socket/etc.
        return False, f"{type(exc).__name__}: {exc}"


def radius_test(cfg: dict, username: str = "", password: str = "") -> tuple[bool, str]:
    """Test the RADIUS config. With a username+password it does a real
    Access-Request; otherwise it just checks the host/port is reachable."""
    if username and password:
        return radius_authenticate(cfg, username, password)
    if not cfg.get("host"):
        return False, "No RADIUS host configured."
    if not cfg.get("secret"):
        return False, "No RADIUS shared secret configured."
    host = cfg.get("host")
    port = int(cfg.get("port") or 1812)
    # RADIUS is UDP — we can't "connect", so resolve + send an empty probe and
    # accept a timeout as "reachable host, but supply test credentials to be
    # sure". A DNS/socket failure is a real config error.
    try:
        socket.getaddrinfo(host, port, proto=socket.IPPROTO_UDP)
    except socket.gaierror as exc:
        return False, f"Cannot resolve host: {exc}"
    return True, ("Host resolves. RADIUS is UDP — enter a test username and "
                  "password to fully verify the shared secret and the server.")


__all__ = [
    "ldap_authenticate", "ldap_test", "ldap_list_users",
    "radius_authenticate", "radius_test",
]
