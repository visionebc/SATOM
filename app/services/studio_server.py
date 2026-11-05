"""Plugin Studio "server" connections -- the wire part.

A ``server`` connection is a Linux web server prepared with
``hostctl/install-satom-webctl.sh``: an unprivileged account (``satom-mon``)
whose ``authorized_keys`` entry for SATOM's key is
``restrict,command="/usr/local/bin/satom-webctl"``. Whatever SATOM sends, the
server runs that one program, which reads one JSON request on stdin and
answers one JSON object on stdout. The list of things it can do is
:data:`OPERATIONS` here and ``OPERATIONS`` in ``satom-webctl.py`` -- nothing
else is reachable with the key, by construction on the SERVER.

What this module adds on SATOM's side, for every call:

* **SATOM always dials.** A server never connects to SATOM: there is nothing
  on SATOM it could reach (no listener, no credential of SATOM's on the host;
  ``hostguard`` also drops new connections from managed servers on both
  nodes). The destination is checked like every connection
  (``studio_http.resolve``: no loopback, link-local, this node, the HA peer).
* **The host key is pinned, always.** A call without a trusted host key is
  refused; the key is taken only by an explicit "Fetch and trust" on the
  connection page, and any other key answering later is refused. No
  trust-on-first-use inside a call.
* **No agent, no forwarding, no pty** are requested; the private key comes
  from the connection's secret (vault or Fernet) and never touches a file.
* **Writes are off unless the connection allows them** (``allow_writes``);
  the server can refuse them on its side too (``"read_only": true``).
* **Every answer goes through the ingestion gate**
  (``server_ingest.webctl_envelope``): size before parse, strict JSON, a
  closed schema per operation, all or nothing. A server can lie; it cannot
  inject.

DATABASE-FREE: the Script Library broker (outside the jail, no app context)
calls :func:`call` with the definition and the secret it was handed.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import socket
import time

from . import server_ingest as G
from . import studio_http as H

ConnectionError_ = H.ConnectionError_

#: operation -> True when it changes something on the server.
OPERATIONS = {op: writes for op, (writes, _schema) in G.WEBCTL_OPS.items()}
WRITE_OPERATIONS = tuple(sorted(op for op, w in OPERATIONS.items() if w))
DEFAULT_USER = "satom-mon"
REMOTE_COMMAND = "satom-webctl"
MAX_REQUEST = 12 * 1024 * 1024
MAX_ANSWER = G.WEBCTL_MAX_ANSWER
KEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa")


# --------------------------------------------------------------------------- #
#  keys                                                                        #
# --------------------------------------------------------------------------- #
def generate_key(comment: str) -> tuple[str, str]:
    """A new Ed25519 key pair: ``(private key in OpenSSH PEM, public line)``."""
    from cryptography.hazmat.primitives import serialization as S
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(S.Encoding.PEM, S.PrivateFormat.OpenSSH,
                            S.NoEncryption()).decode("ascii")
    return pem, public_key(pem, comment)


def public_key(pem: str, comment: str = "") -> str:
    """The ``authorized_keys`` line of a private key ('' if none or broken)."""
    if not pem:
        return ""
    try:
        from cryptography.hazmat.primitives import serialization as S
        key = S.load_ssh_private_key(pem.encode("ascii"), password=None)
        line = key.public_key().public_bytes(S.Encoding.OpenSSH,
                                             S.PublicFormat.OpenSSH).decode("ascii")
    except (ValueError, TypeError, UnicodeError):
        return ""
    comment = "".join(ch for ch in (comment or "") if ch.isalnum() or ch in "-_.@")[:64]
    return (line + " " + comment).strip()


def _pkey(pem: str):
    import paramiko
    try:
        return paramiko.Ed25519Key.from_private_key(io.StringIO(pem))
    except Exception:  # noqa: BLE001 -- any other type a key could be
        try:
            return paramiko.ECDSAKey.from_private_key(io.StringIO(pem))
        except Exception:  # noqa: BLE001
            raise ConnectionError_("the stored SSH key cannot be read: generate a new one") \
                from None


def fingerprint(host_key: str) -> str:
    """``SHA256:...`` of an ``"<type> <base64>"`` host key, like ssh-keygen -l."""
    try:
        blob = base64.b64decode(host_key.split()[1])
    except (IndexError, ValueError):
        return ""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def clean_host_key(value: str) -> str:
    """``"<type> <base64>"`` or ConnectionError_."""
    parts = str(value or "").split()
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        raise ConnectionError_("not an SSH host key")
    try:
        base64.b64decode(parts[1], validate=True)
    except ValueError:
        raise ConnectionError_("not an SSH host key") from None
    return "%s %s" % (parts[0], parts[1])


# --------------------------------------------------------------------------- #
#  transport                                                                   #
# --------------------------------------------------------------------------- #
def _transport(host: str, port: int, timeout: float):
    import paramiko
    ip = H.resolve(host, port)            # the destination check of every connection
    try:
        sock = socket.create_connection((ip, int(port)), timeout=timeout)
    except OSError as exc:
        raise ConnectionError_("%s:%s does not answer (%s)" % (host, port, exc.__class__.__name__)) \
            from None
    t = paramiko.Transport(sock)
    t.banner_timeout = timeout
    t.auth_timeout = timeout
    try:
        t.start_client(timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        t.close()
        raise ConnectionError_("SSH negotiation with %s failed (%s)"
                               % (host, exc.__class__.__name__)) from None
    return t


def fetch_host_key(host: str, port: int = 22, timeout: float = 15) -> str:
    """The host key ``host`` presents now -- for the explicit "Fetch and trust"
    on the connection page only, never inside a call."""
    t = _transport(host, port, timeout)
    try:
        k = t.get_remote_server_key()
        return "%s %s" % (k.get_name(), k.get_base64())
    finally:
        t.close()


def call(defn: dict, private_pem: str, op: str, args: dict | None = None, *,
         timeout: float | None = None) -> dict:
    """One satom-webctl operation. Returns its ``result``; raises
    ``ConnectionError_`` with what went wrong (never the server's raw bytes)."""
    if defn.get("kind") != "server":
        raise ConnectionError_("%s is not a server connection" % defn.get("slug"))
    if op not in OPERATIONS:
        raise ConnectionError_("unknown server operation %r (one of: %s)"
                               % (op, ", ".join(sorted(OPERATIONS))))
    if OPERATIONS[op] and not defn.get("allow_writes"):
        raise ConnectionError_("%s changes the server, and writes are off for connection "
                               "%s (tick Allow writes on its page)" % (op, defn.get("slug")))
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ConnectionError_("the arguments of %s are an object" % op)
    pinned = defn.get("host_key") or ""
    if not pinned:
        raise ConnectionError_("connection %s has no trusted host key: press Fetch and "
                               "trust on its page first" % defn.get("slug"))
    if not private_pem:
        raise ConnectionError_("connection %s has no SSH key: generate one on its page"
                               % defn.get("slug"))
    request = json.dumps({"op": op, "args": args}).encode("utf-8")
    if len(request) > MAX_REQUEST:
        raise ConnectionError_("the request is larger than %d MiB" % (MAX_REQUEST // 2 ** 20))
    timeout = float(timeout or defn.get("timeout") or 20)
    host, port = defn.get("host") or "", int(defn.get("port") or 22)
    started = time.monotonic()
    t = _transport(host, port, timeout)
    try:
        k = t.get_remote_server_key()
        if "%s %s" % (k.get_name(), k.get_base64()) != pinned:
            raise ConnectionError_(
                "the host key of %s changed (now %s, trusted %s): refused. If the server "
                "was rebuilt, fetch and trust its new key on the connection page"
                % (host, fingerprint("%s %s" % (k.get_name(), k.get_base64())),
                   fingerprint(pinned)))
        try:
            t.auth_publickey(defn.get("username") or DEFAULT_USER, _pkey(private_pem))
        except Exception as exc:  # noqa: BLE001
            raise ConnectionError_("%s refused SATOM's key for %s (%s): is satom-webctl "
                                   "installed with this public key?"
                                   % (host, defn.get("username") or DEFAULT_USER,
                                      exc.__class__.__name__)) from None
        chan = t.open_session(timeout=timeout)
        chan.settimeout(timeout)
        chan.exec_command(REMOTE_COMMAND)       # the server forces it anyway
        chan.sendall(request)
        chan.shutdown_write()
        chunks, size = [], 0
        while True:
            if time.monotonic() - started > timeout * 2:
                raise ConnectionError_("%s did not finish %s in %ds" % (host, op, timeout * 2))
            try:
                chunk = chan.recv(65536)
            except socket.timeout:
                raise ConnectionError_("%s did not answer %s within %ds" % (host, op, timeout)) \
                    from None
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_ANSWER:
                raise ConnectionError_("the answer of %s is larger than %d MiB: refused"
                                       % (host, MAX_ANSWER // 2 ** 20))
            chunks.append(chunk)
        chan.close()
    finally:
        t.close()
    raw = b"".join(chunks)
    verdict = G.ingest(raw, G.webctl_envelope(op), max_bytes=MAX_ANSWER)
    if not verdict.ok:
        raise ConnectionError_("the answer of %s to %s was refused by the ingestion gate "
                               "(%s; body %s)" % (host, op, verdict.reason, verdict.digest))
    env = verdict.data
    if not env["ok"]:
        raise ConnectionError_("%s: %s%s" % (host, env.get("error") or "error",
                                             (" -- " + env["detail"]) if env.get("detail") else ""))
    return env["result"]
