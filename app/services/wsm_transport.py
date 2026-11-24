"""Web Server Manager -- the wire: one operation over one SSH session, as the
operator's own Linux account, with ``sudo`` only when asked.

How one call goes (``call``):

1. **Destination checked, host key pinned.** The address passes
   ``studio_http.resolve`` (never loopback, link-local, this node or the HA
   peer: the manager administers OTHER servers, never SATOM) and the key the
   server presents must be the one pinned on its server connection, compared
   BEFORE any credential is offered. No trust-on-first-use.
2. **Authentication as the account.** Password (keyboard-interactive as a
   fallback), or a private key with its passphrase -- both handed in by the
   caller for this call only; nothing is written to disk, no agent, no
   forwarding, no pty.
3. **The helper is sent, not installed.** ``hostctl/satom-webctl.py`` +
   ``hostctl/satom-wsm.py``, compressed, travel on stdin behind a marker line
   and the server's own ``python3 -I`` runs them once. Elevation is a prefix:
   ``sudo -S -k -p ''`` with the password as the first stdin line (sudo reads
   that one line; the helper skips everything up to the marker, so a password
   sudo did not ask for is never read as code), or ``sudo -n`` for a NOPASSWD
   rule. ``-k`` makes sudo ask every time: a cached ticket never stands in for
   the password the operator was asked for. ``login`` is the same password
   flow through ``sudo -i -u root`` for servers whose policy only allows
   root's login shell: sudo hands the command to ``$SHELL -c`` with every
   non-alphanumeric character backslash-escaped (a backslash-newline joins
   lines), so the bootstrap travels as ONE line (base64), and root's profile
   may print before it, so the answer starts after :data:`OUT_MARKER`.
4. **The answer goes through the ingestion gate** (``server_ingest``): size
   before parse, strict JSON, the closed schemas of the satom-webctl
   operations where they apply and a strict generic shape elsewhere.

Every failure is a :class:`WsmError` with a stable ``code`` and a message
written by SATOM -- never the server's raw bytes, never a secret.
DATABASE-FREE: credentials and the pinned key are passed in.
"""
from __future__ import annotations

import base64
import io
import json
import shlex
import socket
import time
import uuid
import zlib
from pathlib import Path

from . import server_ingest as G
from . import studio_http as H

MARKER = b"--SATOM-WSM-BEGIN--"
OUT_MARKER = b"--SATOM-WSM-ANSWER--\n"
#: the elevations that read the sudo password as the first stdin line
PASSWORD_ELEVATIONS = ("sudo", "login")
MAX_ANSWER = 24 * 1024 * 1024
MAX_STDERR = 64 * 1024
HOSTCTL = Path(__file__).resolve().parents[2] / "hostctl"

BOOT = (
    "import sys,zlib\n"
    "b=sys.stdin.buffer\n"
    "while 1:\n"
    " l=b.readline()\n"
    " if not l or l.rstrip(b'\\r\\n')==%r:break\n"
    "n=int(b.readline())\n"
    "s=zlib.decompress(b.read(n))\n"
    "g={'__name__':'__wsm__'}\n"
    "exec(compile(s,'satom-wsm','exec'),g)\n"
    "g['session_main'](b)\n" % MARKER)

#: BOOT for ``sudo -i``: one line, only base64 inside, the answer behind OUT_MARKER
LOGIN_BOOT = ("import base64,sys;sys.stdout.write(%r);sys.stdout.flush();"
              "exec(base64.b64decode(%r))" % (OUT_MARKER.decode(),
                                              base64.b64encode(BOOT.encode()).decode()))


class WsmError(Exception):
    """``code``: connect | hostkey | auth | sudo_password | sudo_denied |
    no_python | timeout | gate | remote | config."""

    def __init__(self, code: str, message: str, *, remote_error: str = "", who=None):
        super().__init__(message)
        self.code = code
        self.remote_error = remote_error
        self.who = who or {}


_PAYLOAD_CACHE: dict = {}


def payload() -> bytes:
    """webctl + wsm, concatenated and compressed (cached by mtime)."""
    files = [HOSTCTL / "satom-webctl.py", HOSTCTL / "satom-wsm.py"]
    key = tuple(f.stat().st_mtime_ns for f in files)
    if _PAYLOAD_CACHE.get("key") != key:
        src = b"\n\n".join(f.read_bytes() for f in files)
        _PAYLOAD_CACHE.update(key=key, data=zlib.compress(src, 9))
    return _PAYLOAD_CACHE["data"]


def helper_version() -> str:
    for line in (HOSTCTL / "satom-wsm.py").read_text().splitlines():
        if line.startswith("WSM_VERSION"):
            return line.split('"')[1]
    return ""


def remote_command(elevate: str) -> str:
    """The command line sent to the server. ``elevate``: '' | 'sudo' | 'login' |
    'nopasswd'."""
    if elevate == "login":
        return "sudo -S -k -p '' -i -u root -- python3 -I -c " + shlex.quote(LOGIN_BOOT)
    base = "python3 -I -c " + shlex.quote(BOOT)
    if elevate == "sudo":
        return "sudo -S -k -p '' -- " + base
    if elevate == "nopasswd":
        return "sudo -n -- " + base
    return base


def build_stdin(request: dict, sudo_password: str = "") -> bytes:
    body = json.dumps(request).encode("utf-8")
    z = payload()
    head = (sudo_password.encode("utf-8") + b"\n") if sudo_password else b""
    return head + MARKER + b"\n" + str(len(z)).encode() + b"\n" + z + body


def _load_key(pem: str, passphrase: str):
    import paramiko
    pw = passphrase or None
    last = None
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(pem), password=pw)
        except paramiko.PasswordRequiredException:
            raise WsmError("auth", "the private key needs its passphrase") from None
        except paramiko.SSHException as exc:  # wrong type or wrong passphrase
            last = exc
        except (ValueError, TypeError) as exc:
            last = exc
    raise WsmError("auth", "the private key cannot be read (wrong passphrase, or not an "
                           "OpenSSH/PEM key: %s)" % last.__class__.__name__)


def _transport(host: str, port: int, timeout: float):
    import paramiko
    try:
        ip = H.resolve(host, port)
    except H.ConnectionError_ as exc:
        raise WsmError("connect", str(exc)) from None
    try:
        sock = socket.create_connection((ip, int(port)), timeout=timeout)
    except OSError as exc:
        raise WsmError("connect", "%s:%s does not answer (%s)" % (host, port,
                                                                  exc.__class__.__name__)) from None
    t = paramiko.Transport(sock)
    t.banner_timeout = timeout
    t.auth_timeout = timeout
    try:
        t.start_client(timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        t.close()
        raise WsmError("connect", "SSH negotiation with %s failed (%s)"
                       % (host, exc.__class__.__name__)) from None
    return t


def _auth(t, user: str, auth_type: str, secret: str, passphrase: str, host: str) -> None:
    import paramiko
    try:
        if auth_type == "key":
            t.auth_publickey(user, _load_key(secret, passphrase))
            return
        try:
            t.auth_password(user, secret)
        except paramiko.BadAuthenticationType as exc:
            if "keyboard-interactive" not in (exc.allowed_types or []):
                raise
            t.auth_interactive(user, lambda title, instr, prompts: [secret for _ in prompts])
    except WsmError:
        raise
    except paramiko.BadAuthenticationType as exc:
        raise WsmError("auth", "%s does not accept %s sign-in for %s (it accepts: %s)"
                       % (host, auth_type, user, ", ".join(exc.allowed_types or []))) from None
    except Exception as exc:  # noqa: BLE001
        raise WsmError("auth", "%s refused the sign-in of %s (%s): check the user name and "
                               "the %s" % (host, user, exc.__class__.__name__,
                                           "key" if auth_type == "key" else "password")) from None


def _gate(op: str, raw: bytes):
    schema = G.wsm_envelope(op)
    verdict = G.ingest(raw, schema, max_bytes=MAX_ANSWER)
    if not verdict.ok:
        raise WsmError("gate", "the answer to %s was refused by the ingestion gate (%s; body %s)"
                       % (op, verdict.reason, verdict.digest))
    return verdict.data


def answer_body(raw: bytes, elevate: str) -> bytes:
    """What the helper wrote. Under ``login`` whatever root's profile printed
    comes first and is dropped; no marker = the helper never started."""
    if elevate != "login":
        return raw
    i = raw.find(OUT_MARKER)
    return raw[i + len(OUT_MARKER):] if i >= 0 else b""


def _stderr_reason(err: str, elevate: str) -> WsmError | None:
    low = err.lower()
    if elevate and ("incorrect password" in low or "sorry, try again" in low
                    or "authentication failure" in low):
        return WsmError("sudo_password", "sudo did not accept the password")
    if elevate and "a password is required" in low:
        return WsmError("sudo_password", "sudo asks for a password: this credential is set to "
                                         "NOPASSWD but the server has no such rule")
    if elevate and ("not in the sudoers" in low or "is not allowed to run sudo" in low
                    or "may not run sudo" in low or "not allowed to execute" in low):
        return WsmError("sudo_denied", "the account is not allowed to use sudo on this server")
    if elevate and ("sudo: command not found" in low or "sudo: not found" in low):
        return WsmError("sudo_denied", "sudo is not installed on this server")
    if "python3" in low and ("not found" in low or "no such file" in low):
        return WsmError("no_python", "python3 is not installed on the server: the manager "
                                     "needs it (it is in every supported distribution)")
    if "this account is currently not available" in low or "nologin" in low:
        return WsmError("auth", "the account has no login shell on this server")
    return None


def call(target: dict, account: dict, op: str, args: dict | None = None, *,
         elevate: str = "", sudo_password: str = "", timeout: float = 120,
         by: str = "") -> dict:
    """One helper operation. ``target``: host, port, host_key. ``account``:
    user, auth_type (password | key), secret, passphrase. Returns
    ``{"result", "who", "session_id", "ms", "elevated"}``."""
    host, port = target.get("host") or "", int(target.get("port") or 22)
    pinned = target.get("host_key") or ""
    if not pinned:
        raise WsmError("hostkey", "this server has no trusted host key yet: open its page and "
                                  "press Fetch and trust")
    if not account.get("secret"):
        raise WsmError("auth", "no password or key was given for %s" % account.get("user"))
    if elevate in PASSWORD_ELEVATIONS and not sudo_password:
        raise WsmError("sudo_password", "the sudo password is needed for this operation")
    request = {"op": op, "args": args or {}, "by": by}
    stdin = build_stdin(request, sudo_password if elevate in PASSWORD_ELEVATIONS else "")
    session_id = uuid.uuid4().hex[:16]
    started = time.monotonic()
    t = _transport(host, port, min(timeout, 30))
    try:
        k = t.get_remote_server_key()
        if "%s %s" % (k.get_name(), k.get_base64()) != pinned:
            from .studio_server import fingerprint
            raise WsmError("hostkey", "the host key of %s changed (now %s, trusted %s): refused. "
                                      "If the server was rebuilt, trust its new key on the "
                                      "server page" % (host, fingerprint("%s %s" % (
                                          k.get_name(), k.get_base64())), fingerprint(pinned)))
        _auth(t, account.get("user") or "", account.get("auth_type") or "password",
              account.get("secret") or "", account.get("passphrase") or "", host)
        chan = t.open_session(timeout=30)
        chan.settimeout(5)
        chan.exec_command(remote_command(elevate))
        view = memoryview(stdin)
        while view:
            n = chan.send(view[:65536])
            view = view[n:]
        chan.shutdown_write()
        out, err, size = [], [], 0
        deadline = started + timeout
        while True:
            if time.monotonic() > deadline:
                raise WsmError("timeout", "%s did not finish %s within %ds" % (host, op, timeout))
            got = False
            if chan.recv_ready():
                c = chan.recv(65536)
                size += len(c)
                if size > MAX_ANSWER:
                    raise WsmError("gate", "the answer of %s is larger than %d MiB: refused"
                                   % (host, MAX_ANSWER // 2 ** 20))
                out.append(c)
                got = True
            if chan.recv_stderr_ready():
                c = chan.recv_stderr(65536)
                if sum(map(len, err)) < MAX_STDERR:
                    err.append(c)
                got = True
            if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                break
            if not got:
                time.sleep(0.02)
        rc = chan.recv_exit_status()
        chan.close()
    finally:
        t.close()
    raw = answer_body(b"".join(out), elevate)
    errtext = b"".join(err).decode("utf-8", "replace")
    if not raw.strip():
        reason = _stderr_reason(errtext, elevate)
        if reason:
            raise reason
        raise WsmError("remote", "%s answered nothing to %s (exit %s)" % (host, op, rc))
    env = _gate(op, raw)
    who = env.get("who") or {}
    if not env["ok"]:
        raise WsmError("remote", "%s%s" % (env.get("error") or "error",
                                           (": " + env["detail"]) if env.get("detail") else ""),
                       remote_error=env.get("error") or "", who=who)
    return {"result": env["result"], "who": who, "session_id": session_id,
            "ms": int((time.monotonic() - started) * 1000), "elevated": bool(elevate)}
