"""The jail every piece of operator-supplied Python runs in.

Two callers today: the integration-hooks runner (``hook_runner``) and the
Script Library runner (``script_runner``). Both execute code an administrator
typed into SATOM, as the unprivileged ``satom`` uid -- the same uid as the web
app. That uid alone, without a jail, opens the SATOM database over the Postgres
unix socket (``local all all peer``) and reads ``FERNET_KEY`` out of
``/proc/<gunicorn>/environ``. Measured on a1, 2026-10-15.

THE JAIL (``jail_argv``)
    bubblewrap with ``--unshare-all``: private user, pid, ipc, uts, cgroup AND
    network namespaces. Mounted: /usr (read-only), the interpreter's venv
    (read-only, packages only), the resolver and CA files, and the run's own
    work directory. Not mounted: /opt/satom, /run (no Postgres socket), /home,
    /etc/satom. No fallback: a node without bwrap refuses to run the code.

THE NETWORK (``EgressProxy``)
    A private network namespace has only its own loopback. A run that is
    allowed out (``network="egress"``) gets it through a proxy that the runner
    serves on a unix socket inside the work directory. Inside the jail a small
    relay (``sandbox_boot.py``) listens on 127.0.0.1:3128 and forwards to that
    socket; ``HTTP_PROXY``/``HTTPS_PROXY`` point at it, so urllib, requests
    and httpx go out with no code change, and ``satom_sdk.tcp()`` opens raw TCP
    (SSH to an appliance) through the same CONNECT.

    Why not the host network: on a1 loopback carries Redis (no password: the
    shared device-API cache and the login rate-limit counters), VictoriaMetrics
    (no auth at all) and gunicorn behind nginx. ``IPAddressDeny=localhost`` on
    the unit would also cut the runner's own database connection
    (``127.0.0.1:5432``), and slirp4netns/pasta need ``/dev/net/tun``, which
    the SATOM LXCs do not have.

    The rule: a connection is refused when its REAL peer, read after
    ``connect()``, is a loopback/unspecified/link-local address or equals the
    local address the kernel picked for it -- which is what happens for every
    address this host owns, on any interface. Checking the connected socket
    and not the name means DNS tricks (a name that resolves to 127.0.0.1, a
    rebinding answer) change nothing. Not a byte is relayed before the check.
"""
from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import threading
from pathlib import Path
from typing import Callable

BWRAP = "bwrap"
PROXY_PORT = 3128
PROXY_SOCK_NAME = ".satom-egress.sock"
BOOT_SRC = Path(__file__).resolve().parent / "sandbox_boot.py"
BOOT_NAME = "_satom_boot.py"

SANDBOX_MISSING = ("sandbox unavailable: bubblewrap (bwrap) is not installed on "
                   "this node, and operator code never runs outside it. Install "
                   "it from Settings > General > System packages.")

# What a networked run needs from /etc and nothing else: name resolution and
# the CA bundle. Not /etc/passwd, not /etc/satom, not /etc/postgresql.
_ETC_RO = ("/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf",
           "/etc/gai.conf", "/etc/ssl", "/etc/ca-certificates", "/etc/pki")

NETWORK_MODES = ("none", "egress")
_HEAD_MAX = 16 * 1024
_CONNECT_TIMEOUT = 10.0


# The top-level system directories, mirrored as THIS host lays them out. A
# usr-merged host (Debian 12, RHEL 9) has them as symlinks into /usr; SLES and
# Leap 15 have real /bin, /sbin, /lib and /lib64, and /lib64 holds the ELF
# loader and libc -- a made-up ``/lib64 -> usr/lib64`` there makes every exec
# in the jail fail with "execvp ...: No such file or directory" (SA-0002).
# A real directory is mounted read-only: it is system code, like /usr.
ROOT_DIRS = ("bin", "sbin", "lib", "lib64")


def root_dirs_argv(root: str = "/") -> list[str]:
    """bwrap flags that reproduce the host's /bin, /sbin, /lib, /lib64."""
    out: list[str] = []
    for name in ROOT_DIRS:
        host = os.path.join(root, name)
        if os.path.islink(host):
            out += ["--symlink", os.readlink(host), "/" + name]
        elif os.path.isdir(host):
            out += ["--ro-bind", host, "/" + name]
    return out


def available() -> bool:
    return shutil.which(BWRAP) is not None


def _interpreter_root(python: Path) -> str | None:
    """The venv the interpreter lives in, when it is not under /usr.

    Mounted read-only so ``import httpx`` keeps working; it holds packages,
    not secrets. A bare system interpreter needs nothing beyond /usr.
    """
    root = Path(python).parent.parent
    if (root / "pyvenv.cfg").is_file() and not str(root).startswith("/usr/"):
        return str(root)
    return None


def jail_argv(argv: list[str], workdir: str, *,
              ro_binds: tuple[str, ...] = ()) -> list[str] | None:
    """``argv`` wrapped in the jail, or None when bwrap is missing.

    The network namespace is ALWAYS private; egress, when a run has it, comes
    through :class:`EgressProxy` and the boot relay, never the host stack.
    The pid namespace hides every host process (and their environ), and ends
    every grandchild when the run's own process dies (the timeout kill).
    """
    bwrap = shutil.which(BWRAP)
    if bwrap is None:
        return None
    out = [bwrap, "--unshare-all", "--die-with-parent", "--new-session",
           "--ro-bind", "/usr", "/usr", *root_dirs_argv(),
           "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for path in _ETC_RO:
        out += ["--ro-bind-try", path, path]
    venv = _interpreter_root(Path(argv[0]))
    if venv:
        out += ["--ro-bind", venv, venv]
    for path in ro_binds:
        out += ["--ro-bind", path, path]
    out += ["--bind", workdir, workdir, "--chdir", workdir]
    return out + list(argv)


def boot_argv(python: str, script: str, workdir: str, *,
              network: str) -> list[str]:
    """The interpreter command line, through the boot relay when egress is on.

    -E ignores PYTHONPATH, -s drops the user site-dir, -B writes no .pyc.
    NOT -I: that implies -P, which drops the script's directory from sys.path
    and breaks ``import satom_sdk``.
    """
    base = [python, "-E", "-s", "-B"]
    if network != "egress":
        return base + [script]
    shutil.copyfile(BOOT_SRC, os.path.join(workdir, BOOT_NAME))
    return base + [BOOT_NAME, script]


def proxy_env(network: str) -> dict[str, str]:
    """Environment entries that route a run's traffic through the relay."""
    if network != "egress":
        return {}
    url = "http://127.0.0.1:%d" % PROXY_PORT
    return {"HTTP_PROXY": url, "HTTPS_PROXY": url, "ALL_PROXY": url,
            "http_proxy": url, "https_proxy": url, "all_proxy": url,
            "NO_PROXY": "", "no_proxy": "",
            "SATOM_EGRESS_PROXY": "127.0.0.1:%d" % PROXY_PORT}


# ---------------------------------------------------------------------------
#  egress policy
# ---------------------------------------------------------------------------
def _plain(ip: str) -> ipaddress._BaseAddress:
    addr = ipaddress.ip_address(ip.split("%", 1)[0])
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped or addr


def egress_verdict(peer_ip: str, local_ip: str) -> str | None:
    """None when the connection may proceed, else the reason it may not."""
    try:
        peer = _plain(peer_ip)
        local = _plain(local_ip)
    except ValueError:
        return "unparseable address"
    if peer.is_loopback or peer.is_unspecified:
        return "loopback of this node"
    if peer.is_link_local or peer.is_multicast:
        return "link-local/multicast address"
    if peer == local:
        return "an address of this node"
    return None


def _bind_unix(srv: socket.socket, path: str) -> None:
    """bind() a unix socket at ``path`` whatever its length.

    sun_path holds 108 bytes, so a long work directory (a long TMPDIR, a test
    runner's tmp_path) raised "AF_UNIX path too long" before the jail even
    started. The directory is reached through /proc/self/fd, which is short.
    """
    fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY | os.O_DIRECTORY)
    try:
        srv.bind("/proc/self/fd/%d/%s" % (fd, os.path.basename(path)))
    finally:
        os.close(fd)


class EgressProxy:
    """HTTP CONNECT + absolute-URI proxy on a unix socket, with the rule above.

    One per run, started before the jail and closed after it. ``log`` keeps a
    line per attempt (host:port, allowed or the refusal) for the run record.
    """

    def __init__(self, sock_path: str, *,
                 verdict: Callable[[str, str], str | None] = egress_verdict):
        self.sock_path = sock_path
        self.verdict = verdict
        self.log: list[str] = []
        self._lock = threading.Lock()
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._closed = False

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "EgressProxy":
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        _bind_unix(srv, self.sock_path)
        os.chmod(self.sock_path, 0o600)
        srv.listen(32)
        self._srv = srv
        self._thread = threading.Thread(target=self._accept_loop, daemon=True,
                                        name="satom-egress")
        self._thread.start()
        return self

    def close(self) -> None:
        self._closed = True
        if self._srv is not None:
            try:
                self._srv.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._srv.close()
            except OSError:
                pass
        try:
            os.unlink(self.sock_path)
        except OSError:
            pass

    def __enter__(self) -> "EgressProxy":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()

    def _note(self, line: str) -> None:
        with self._lock:
            if len(self.log) < 200:
                self.log.append(line)

    def _accept_loop(self) -> None:
        while not self._closed:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    # -- one client --------------------------------------------------------
    def _serve(self, client: socket.socket) -> None:
        upstream = None
        try:
            client.settimeout(30)
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = client.recv(4096)
                if not chunk:
                    return
                head += chunk
                if len(head) > _HEAD_MAX:
                    client.sendall(_reply(431, "request head too large"))
                    return
            head, _, rest = head.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            parts = lines[0].split(" ")
            if len(parts) != 3:
                client.sendall(_reply(400, "malformed request line"))
                return
            method, target, version = parts
            if method.upper() == "CONNECT":
                host, port = _split_hostport(target, 443)
                tunnel = True
            else:
                host, port, path = _split_url(target)
                tunnel = False
            if not host:
                client.sendall(_reply(400, "only absolute http:// URLs or CONNECT"))
                return
            upstream, reason = self._open(host, port)
            if upstream is None:
                self._note("%s:%s denied: %s" % (host, port, reason))
                client.sendall(_reply(403, "egress denied: %s" % reason))
                return
            self._note("%s:%s allowed" % (host, port))
            if tunnel:
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if rest:
                    upstream.sendall(rest)
            else:
                kept = [h for h in lines[1:]
                        if not h.lower().startswith(("proxy-", "connection:"))]
                kept.append("Connection: close")
                upstream.sendall(("%s %s %s\r\n" % (method, path, version)).encode("latin-1")
                                 + "\r\n".join(kept).encode("latin-1")
                                 + b"\r\n\r\n" + rest)
            client.settimeout(None)
            upstream.settimeout(None)
            _pump(client, upstream)
        except OSError:
            pass
        finally:
            for s in (client, upstream):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    def _open(self, host: str, port: int):
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            return None, "cannot resolve %s (%s)" % (host, exc.strerror or exc)
        last = "no address"
        for family, stype, proto, _, addr in infos:
            # Pre-check the candidate so a loopback answer is never connected
            # to at all; the post-connect check below is the authoritative one.
            pre = self.verdict(addr[0], "0.0.0.0" if family == socket.AF_INET else "::")
            if pre and "loopback" in pre:
                last = pre
                continue
            sock = socket.socket(family, stype, proto)
            sock.settimeout(_CONNECT_TIMEOUT)
            try:
                sock.connect(addr)
            except OSError as exc:
                sock.close()
                last = "connect failed (%s)" % (exc.strerror or exc)
                continue
            why = self.verdict(sock.getpeername()[0], sock.getsockname()[0])
            if why:
                sock.close()
                return None, why
            return sock, ""
        return None, last


def _split_hostport(target: str, default: int) -> tuple[str, int]:
    if target.startswith("["):
        host, _, tail = target[1:].partition("]")
        port = tail[1:] if tail.startswith(":") else ""
    else:
        host, _, port = target.rpartition(":") if ":" in target else (target, "", "")
    try:
        return host, int(port) if port else default
    except ValueError:
        return "", 0


def _split_url(target: str) -> tuple[str, int, str]:
    if not target.lower().startswith("http://"):
        return "", 0, ""
    rest = target[7:]
    hostport, slash, path = rest.partition("/")
    host, port = _split_hostport(hostport, 80)
    return host, port, "/" + path if slash else "/"


def _reply(code: int, text: str) -> bytes:
    body = (text + "\n").encode()
    return (b"HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nX-Satom-Egress: refused\r\n"
            b"Content-Length: %d\r\nConnection: close\r\n\r\n"
            % (code, b"Forbidden" if code == 403 else b"Error", len(body))) + body


def _pump(a: socket.socket, b: socket.socket) -> None:
    """Relay both directions until either side closes."""
    def one(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=one, args=(b, a), daemon=True)
    t.start()
    one(a, b)
    t.join()


# ---------------------------------------------------------------------------
#  one jailed run, start to finish
# ---------------------------------------------------------------------------
KILL_GRACE = 3.0
REAP_TIMEOUT = 5.0


class Outcome:
    __slots__ = ("exit_code", "output", "timed_out", "egress", "error")

    def __init__(self, exit_code=None, output="", timed_out=False, egress=None,
                 error=""):
        self.exit_code = exit_code
        self.output = output
        self.timed_out = timed_out
        self.egress = egress or []
        self.error = error


def kill_group(proc, grace: float = KILL_GRACE) -> None:
    """SIGTERM then SIGKILL the jail's process group.

    The pid namespace already ends every grandchild once bwrap's pid 1 goes,
    so killing the group (bwrap itself) is enough to end the whole tree.
    """
    import signal
    import time
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except OSError:
        pass
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.05)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass


def execute(python: str, script: str, workdir: str, *, env: dict[str, str],
            timeout: int, network: str = "none", pass_fds: tuple = (),
            stdin_data: str | None = None, ro_binds: tuple[str, ...] = (),
            verdict: Callable[[str, str], str | None] = egress_verdict
            ) -> Outcome:
    """Run ``script`` (a path relative to ``workdir``) in the jail.

    ``env`` is the COMPLETE environment (built from nothing by the caller);
    the proxy variables are added here when ``network == "egress"``.
    """
    import subprocess
    if network not in NETWORK_MODES:
        return Outcome(error="unknown network mode %r" % network)
    argv = jail_argv(boot_argv(python, script, workdir, network=network),
                     workdir, ro_binds=ro_binds)
    if argv is None:
        return Outcome(error=SANDBOX_MISSING)
    env = dict(env)
    env.update(proxy_env(network))
    proxy = None
    if network == "egress":
        proxy = EgressProxy(os.path.join(workdir, PROXY_SOCK_NAME),
                            verdict=verdict).start()
    try:
        try:
            proc = subprocess.Popen(
                argv, cwd=workdir, env=env,
                stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True, pass_fds=tuple(pass_fds), close_fds=True,
                text=True, errors="replace")
        except OSError as exc:
            return Outcome(error="could not start the jail: %s" % exc)
        timed_out = False
        try:
            out, _ = proc.communicate(input=stdin_data, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_group(proc)
            try:
                out, _ = proc.communicate(timeout=REAP_TIMEOUT)
            except (subprocess.TimeoutExpired, ValueError):
                out = ""
        return Outcome(exit_code=proc.returncode, output=out or "",
                       timed_out=timed_out,
                       egress=list(proxy.log) if proxy else [])
    finally:
        if proxy is not None:
            proxy.close()
