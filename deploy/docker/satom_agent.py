#!/usr/bin/env python3
"""SATOM operations agent -- the container runtime's privileged half.

On a host install the web worker never holds the privilege it asks for: it
writes a JSON request into ``data/update-requests/`` and a root runner
(``satom-updater.path``) re-validates it and does the work. This module is the
same model for the Docker stack, and it exists so that the four capabilities
``app/runtime.py`` renounces in a container can come back to the web UI
without handing the web process the keys to the host.

The boundary, in the order it is enforced
-----------------------------------------
1. **This is the only container that mounts ``/var/run/docker.sock``.** Access
   to the engine API is root on the host. ``tests/test_docker_agent.py`` fails
   if any other service in any compose file mounts it.
2. **It listens on nothing.** No port, no socket, no HTTP server. Its only
   input is a file in the ``satom-agent-requests`` volume, which ``web`` can
   write and nothing on the network can reach. It is not on the ``satom``
   network at all, so a compromised container there cannot even see it.
3. **The web worker's validation is a UX affordance; THIS one is the security
   boundary.** Every request is parsed here again, against a closed set of
   kinds, a closed set of keys per kind and a closed table of services. A
   compromised web worker can enqueue anything it likes and still only gets
   the curated set: restart a named service of this project, switch the stack
   to a release version, or install a certificate into ``satom-pki``. Never a
   free-form image, command, path, compose argument or service name.
4. **Results travel back as files.** The agent writes ``<uid>.json`` into the
   ``satom-agent-status`` volume, the same shape the host runner writes, so
   the UI's existing status polls work unchanged. It never calls the web.
5. **Every write into a volume the web can also write is symlink-safe.** The
   web owns those directories. A status file is written to a fresh O_EXCL
   temporary and renamed over the target, so a symlink planted at
   ``<uid>.json`` is replaced, never followed -- following it as root would
   let the web overwrite any file the agent can reach, including the stack's
   secrets.

Two deliberate omissions
------------------------
* **The agent never recreates itself.** An update recreates every service
  EXCEPT ``agent``; the agent keeps running the version it started with until
  an operator runs ``satom-docker up -d`` (or the installer's update). An
  agent that replaced itself mid-request would lose the status of the very
  request it was reporting, and a broken new agent would take the UI's only
  way back with it. The heartbeat reports both versions so the drift is
  visible rather than surprising.
* **No HA failover.** Promotion rewrites the database role of a node; on a
  container node it stays a manual PostgreSQL operation (docs/docker-compose.md
  §10.6) and the web refuses it outright (``ha_promote`` in app/runtime.py).

Stdlib only, on purpose: the file is reviewed as a security boundary, and every
dependency it does not import is one fewer thing to review.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Fixed configuration. Nothing here is read from a request.
# ---------------------------------------------------------------------------
#: Compose project whose containers this agent may touch. compose.yaml sets
#: ``name: satom`` and the installer wrapper passes ``-p satom``.
PROJECT = "satom"
QUEUE = Path(os.environ.get("SATOM_AGENT_QUEUE", "/queue"))
REQ_DIR = QUEUE / "requests"
STATUS_DIR = QUEUE / "status"
#: NOT ``*.json``: the UI lists ``update-status/*.json`` as update history, and
#: the heartbeat is not an update.
HEARTBEAT = STATUS_DIR / "agent.heartbeat"
DOCKER_SOCKET = "/var/run/docker.sock"
PKI_DIR = Path("/opt/satom/pki")
TLS_BOOTSTRAP = "/opt/satom/deploy/tls-bootstrap.sh"
#: Installer layout root (``/opt/satom-docker``), mounted at the SAME path it
#: has on the host so a helper container can be given host paths. Empty on a
#: manual checkout, where updates from the console are refused.
HOME = os.environ.get("SATOM_AGENT_HOME", "").strip()
RELEASE_REPO = "visionebc/SATOM"
#: The Docker CLI image the agent borrows to run ``docker build`` and
#: ``docker compose``. Pinned by major so compose understands ``!reset``
#: (>= 2.24.4, needed by the standby overlay).
CLI_IMAGE = "docker:27-cli"
APP_UID = 999
APP_GID = 999

POLL_SECONDS = 2.0
HEARTBEAT_SECONDS = 15.0
#: A request older than this at pickup is refused, not executed. A restart
#: queued while the agent was down must not fire hours later, on a stack the
#: operator has since fixed by hand.
REQUEST_MAX_AGE = 600
MAX_REQUEST_BYTES = 64 * 1024
MAX_PEM_BYTES = {"cert_pem": 32 * 1024, "key_pem": 16 * 1024, "chain_pem": 32 * 1024}
MAX_DOWNLOAD_BYTES = 400 * 1024 * 1024
WEB_HEALTH_TIMEOUT = 420

# ---------------------------------------------------------------------------
# The allowlist. ``app/services/container_ops.py`` keeps its own copy for the
# UI; tests/test_docker_agent.py fails if the two drift.
# ---------------------------------------------------------------------------
KINDS = ("ctr-restart", "ctr-update", "ctr-cert")
#: Metadata every request may carry. Informational only: nothing below
#: branches on it, it is copied into the status file for the history table.
COMMON_KEYS = frozenset({"id", "kind", "requested_by", "requested_at",
                         "node", "role", "origin"})
KIND_KEYS = {
    "ctr-restart": (frozenset({"service", "action"}), frozenset()),
    "ctr-update": (frozenset({"version"}), frozenset()),
    "ctr-cert": (frozenset({"cert_pem", "key_pem"}), frozenset({"chain_pem"})),
}
#: service -> actions. The same three rules as the host table
#: (app/services/service_control.py): nothing that would remove the only way
#: to undo it is ever stoppable -- not the console (web), not its front
#: (proxy), not the database.
SERVICE_POLICY = {
    "web": ("restart",),
    "scheduler": ("start", "stop", "restart"),
    "cron": ("start", "stop", "restart"),
    "proxy": ("restart",),
    "postgres": ("restart",),
    "redis": ("restart",),
    "victoria-metrics": ("restart",),
}
#: Refused even if a future edit lists them. Stopping the agent bricks the
#: queue that would start it again; tls-init is a run-once job, not a service.
FORBIDDEN_SERVICES = ("agent", "tls-init")

UID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}\Z")
VERSION_RE = re.compile(r"^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\Z")
_PEM_BLOCK = r"-----BEGIN [A-Z0-9 ]{1,40}-----\r?\n[A-Za-z0-9+/=\r\n]+-----END [A-Z0-9 ]{1,40}-----"
PEM_RE = re.compile(r"^(?:%s\s*)+$" % _PEM_BLOCK)
_CIDR_RE = re.compile(r"(?<![0-9.])((?:[0-9]{1,3}\.){3}0)/([0-9]{1,2})(?![0-9])")


class Refused(ValueError):
    """A request the agent will not execute. The message is shown verbatim."""


# ---------------------------------------------------------------------------
# Validation -- pure functions, no I/O. This is the part under mutation test.
# ---------------------------------------------------------------------------
def validate_request(raw: bytes, stem: str) -> tuple[str, dict]:
    """Parse one request file. Returns ``(kind, params)`` or raises Refused.

    ``stem`` is the file name without ``.json``; the id inside must equal it,
    so a request cannot report its result under someone else's status file.
    """
    if not UID_RE.match(stem or ""):
        raise Refused("request file name %r is not a request id" % (stem or "")[:64])
    if len(raw) > MAX_REQUEST_BYTES:
        raise Refused("request is larger than %d bytes" % MAX_REQUEST_BYTES)
    try:
        req = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refused("request is not valid UTF-8 JSON") from None
    if not isinstance(req, dict):
        raise Refused("request is not a JSON object")
    if req.get("id") != stem:
        raise Refused("request id does not match its file name")
    kind = req.get("kind")
    if kind not in KINDS:
        # A host-runner request (git update, pip, systemd unit, promote) lands
        # here on purpose: those have no container meaning, and naming the kind
        # tells the operator which surface sent it.
        raise Refused("request kind %r is not one the container agent performs "
                      "(accepted: %s)" % (str(kind)[:40], ", ".join(KINDS)))
    required, optional = KIND_KEYS[kind]
    keys = set(req)
    missing = required - keys
    if missing:
        raise Refused("missing field(s): %s" % ", ".join(sorted(missing)))
    extra = keys - required - optional - COMMON_KEYS
    if extra:
        raise Refused("unexpected field(s): %s" % ", ".join(sorted(extra)[:5]))
    for k in COMMON_KEYS & keys:
        if req[k] is not None and not isinstance(req[k], str):
            raise Refused("field %r must be a string" % k)
    params = {k: req[k] for k in (required | optional) if k in req}
    for k, v in params.items():
        if not isinstance(v, str):
            raise Refused("field %r must be a string" % k)
    if kind == "ctr-restart":
        check_service_action(params["service"], params["action"])
    elif kind == "ctr-update":
        check_version(params["version"])
    elif kind == "ctr-cert":
        for k in ("cert_pem", "key_pem", "chain_pem"):
            if k in params:
                check_pem(k, params[k], optional=(k == "chain_pem"))
    return kind, params


def check_service_action(service: str, action: str) -> None:
    if service in FORBIDDEN_SERVICES:
        raise Refused("service %r is never controlled from the console" % service)
    allowed = SERVICE_POLICY.get(service)
    if allowed is None:
        raise Refused("service %r is not a service of this stack" % service[:40])
    if action not in allowed:
        raise Refused("%r is not allowed on %r (allowed: %s)"
                      % (action[:20], service, ", ".join(allowed)))


def check_version(version: str) -> None:
    if not VERSION_RE.match(version):
        raise Refused("version %r is not X.Y.Z" % version[:40])


def check_pem(name: str, value: str, optional: bool = False) -> None:
    if optional and value == "":
        return
    if len(value.encode("utf-8")) > MAX_PEM_BYTES[name]:
        raise Refused("%s is larger than %d bytes" % (name, MAX_PEM_BYTES[name]))
    if not PEM_RE.match(value):
        raise Refused("%s is not PEM" % name)
    if name == "key_pem" and "PRIVATE KEY-----" not in value:
        raise Refused("key_pem does not contain a private key")
    if name != "key_pem" and "PRIVATE KEY" in value:
        # A private key pasted into the certificate slot would be copied into
        # public/server.crt, which the proxy serves to every client.
        raise Refused("%s contains a private key" % name)


def compose_files(home: str, env: dict) -> list[str]:
    """The ``-f`` list for this install -- the installer wrapper's logic
    (installers/satom-setup.sh write_wrapper), from fixed paths only."""
    d = os.path.join(home, "current", "deploy", "docker")
    f = ["-f", os.path.join(d, "compose.yaml")]
    if env.get("SATOM_ENV", "dev") == "prod":
        f += ["-f", os.path.join(d, "compose.prod.yaml")]
    if env.get("SATOM_NODE_ROLE", "primary") == "standby":
        f += ["-f", os.path.join(d, "compose.standby.yaml")]
    setup = os.path.join(home, "compose.setup.yaml")
    if os.path.isfile(setup):
        f += ["-f", setup]
    agent = os.path.join(d, "compose.agent.yaml")
    if env.get("SATOM_SETUP_AGENT", "no") == "yes" and os.path.isfile(agent):
        f += ["-f", agent]
    return f


def compose_argv(home: str, env: dict, *args: str) -> list[str]:
    return (["docker", "compose", "-p", PROJECT, "--project-directory",
             os.path.join(home, "current", "deploy", "docker")]
            + compose_files(home, env)
            + ["--env-file", os.path.join(home, "satom.env")] + list(args))


def parse_env(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Z_][A-Z0-9_]*)=(.*)$", line)
        if not m:
            continue
        v = m.group(2)
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        out[m.group(1)] = v
    return out


def env_set_text(text: str, key: str, value: str) -> str:
    """Replace every ``KEY=`` line with one, or append -- the installer's
    ``env_set``. The value is a validated image tag, never free text."""
    out, done = [], False
    for line in text.splitlines():
        if line.startswith(key + "="):
            if not done:
                out.append("%s=%s" % (key, value))
                done = True
            continue
        out.append(line)
    if not done:
        out.append("%s=%s" % (key, value))
    return "\n".join(out) + "\n"


def bad_network_literals(root: Path) -> list[str]:
    """Networks with host bits set -- the 2.1.1 mirror defect. Same scope and
    rule as the installer's ``bad_network_literals``: a tree carrying one does
    not boot, so it is not switched to."""
    files = [p for p in root.iterdir() if p.is_file()
             and p.suffix in (".py", ".yaml", ".yml")]
    for sub in ("app", "deploy", "migrations", "scripts"):
        d = root / sub
        if d.is_dir():
            files += [p for p in d.rglob("*") if p.is_file()
                      and p.suffix in (".py", ".yaml", ".yml")]
    bad = []
    for p in files:
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for m in _CIDR_RE.finditer(line):
                octets = [int(o) for o in m.group(1).split(".")]
                prefix = int(m.group(2))
                if any(o > 255 for o in octets) or prefix > 32:
                    continue
                try:
                    ipaddress.ip_network("%s/%d" % (m.group(1), prefix), strict=True)
                except ValueError:
                    bad.append("%s:%d: %s/%d" % (p.relative_to(root), n,
                                                 m.group(1), prefix))
    return bad


# ---------------------------------------------------------------------------
# Small I/O helpers
# ---------------------------------------------------------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print("[satom-agent] %s %s" % (now_iso(), msg), flush=True)


def write_owned(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Atomic, symlink-safe write into a directory the web can also write.

    O_EXCL on a random temporary name never follows a symlink, and rename()
    replaces a symlink at the target instead of writing through it. The file
    ends up owned by the app account so the web can read (and, for status
    files, rewrite) it.
    """
    tmp = path.parent / (".agent-%s.tmp" % secrets.token_hex(6))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, data)
        os.fchmod(fd, mode)
        try:
            os.fchown(fd, APP_UID, APP_GID)
        except PermissionError:
            pass  # tests run unprivileged
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))


def read_request(path: Path) -> bytes:
    """Read a request without following links and without trusting its size."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused("request is not a regular file")
        chunks, total = [], 0
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            total += len(b)
            if total > MAX_REQUEST_BYTES:
                raise Refused("request is larger than %d bytes" % MAX_REQUEST_BYTES)
            chunks.append(b)
        return b"".join(chunks)
    finally:
        os.close(fd)


class Status:
    """``<uid>.json`` in the host runner's shape (deploy/self_update_runner.py
    Status), so the existing UI polls render it."""

    def __init__(self, uid: str, req: dict | None, kind: str = ""):
        req = req or {}
        self.path = STATUS_DIR / (uid + ".json")
        self.d = {
            "id": uid, "state": "running", "steps": [], "kind": kind,
            "runner": "container-agent",
            "requested_by": _s(req.get("requested_by")),
            "node": _s(req.get("node")), "role": _s(req.get("role")),
            "origin": _s(req.get("origin")) or "manual",
            "started_at": now_iso(), "updated_at": now_iso(),
        }
        self.flush()

    def set(self, **kw) -> None:
        self.d.update(kw)
        self.flush()

    def step(self, name: str, ok: bool = True, detail: str = "") -> None:
        self.d["steps"].append({"name": name, "ok": bool(ok),
                                "detail": (detail or "").strip()[-500:],
                                "at": now_iso()})
        self.d["updated_at"] = now_iso()
        self.flush()
        log("%s %s: %s %s" % (self.d["id"], "ok " if ok else "ERR", name,
                               (detail or "")[:200]))

    def finish(self, state: str, **kw) -> None:
        self.d["state"] = state
        self.d.update(kw)
        self.d["updated_at"] = now_iso()
        self.flush()

    def flush(self) -> None:
        write_owned(self.path, json.dumps(self.d, indent=2).encode())


def _s(v) -> str:
    return v[:120] if isinstance(v, str) else ""


# ---------------------------------------------------------------------------
# Docker Engine API over the unix socket
# ---------------------------------------------------------------------------
class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


class DockerError(RuntimeError):
    pass


def api(method: str, path: str, body=None, timeout: float = 30,
        query: dict | None = None) -> tuple[int, bytes]:
    if query:
        path += "?" + urllib.parse.urlencode(
            {k: (json.dumps(v) if isinstance(v, (dict, list)) else v)
             for k, v in query.items()})
    conn = _UnixConnection(DOCKER_SOCKET, timeout)
    try:
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def api_json(method: str, path: str, body=None, timeout: float = 30,
             query: dict | None = None, ok=(200, 201, 204, 304)):
    st, raw = api(method, path, body, timeout, query)
    if st not in ok:
        raise DockerError("%s %s -> HTTP %s: %s" % (method, path.split("?")[0], st,
                                                   raw[:300].decode("utf-8", "replace")))
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def project_containers() -> list[dict]:
    """Every container of THIS project, one-off helpers excluded."""
    rows = api_json("GET", "/containers/json", query={
        "all": "1",
        "filters": {"label": ["com.docker.compose.project=%s" % PROJECT]}}) or []
    out = []
    for c in rows:
        lab = c.get("Labels") or {}
        if lab.get("com.docker.compose.oneoff", "False") == "True":
            continue
        out.append(c)
    return out


def service_containers(service: str) -> list[dict]:
    return [c for c in project_containers()
            if (c.get("Labels") or {}).get("com.docker.compose.service") == service]


def inspect(cid: str) -> dict:
    return api_json("GET", "/containers/%s/json" % urllib.parse.quote(cid)) or {}


def container_row(c: dict) -> dict:
    lab = c.get("Labels") or {}
    row = {"service": lab.get("com.docker.compose.service", ""),
           "name": (c.get("Names") or ["?"])[0].lstrip("/"),
           "state": c.get("State", ""), "status": c.get("Status", ""),
           "image": c.get("Image", ""), "health": ""}
    try:
        h = (inspect(c["Id"]).get("State") or {}).get("Health") or {}
        row["health"] = h.get("Status", "")
    except Exception:  # noqa: BLE001
        pass
    return row


def wait_service(service: str, timeout: float, want_healthy: bool) -> tuple[bool, str]:
    """Poll until every container of *service* runs (and is healthy when it
    has a healthcheck and *want_healthy*)."""
    deadline = time.monotonic() + timeout
    last = "no container"
    while time.monotonic() < deadline:
        cs = service_containers(service)
        if cs:
            states = []
            good = True
            for c in cs:
                st = inspect(c["Id"]).get("State") or {}
                h = (st.get("Health") or {}).get("Status", "")
                states.append("%s%s" % (st.get("Status", "?"), "/" + h if h else ""))
                if st.get("Status") != "running":
                    good = False
                elif want_healthy and h and h != "healthy":
                    good = False
            last = ", ".join(states)
            if good:
                return True, last
        time.sleep(3)
    return False, last


def image_tags(repo: str = "satom") -> list[str]:
    rows = api_json("GET", "/images/json", query={
        "filters": {"reference": [repo]}}) or []
    tags = []
    for r in rows:
        for t in r.get("RepoTags") or []:
            if t.startswith(repo + ":"):
                tags.append(t)
    return sorted(set(tags))


def ensure_cli_image(st: Status | None = None) -> None:
    st_code, _ = api("GET", "/images/%s/json" % urllib.parse.quote(CLI_IMAGE, safe=""))
    if st_code == 200:
        return
    repo, tag = CLI_IMAGE.split(":", 1)
    code, raw = api("POST", "/images/create", timeout=900,
                    query={"fromImage": repo, "tag": tag})
    text = raw.decode("utf-8", "replace")
    if code != 200 or '"error"' in text:
        raise DockerError("could not pull %s: %s" % (CLI_IMAGE, text[-300:]))
    if st:
        st.step("pull %s" % CLI_IMAGE, True)


def _demux(raw: bytes) -> str:
    """Docker's multiplexed log stream (8-byte frame headers, no TTY)."""
    out, i = [], 0
    while i + 8 <= len(raw):
        size = int.from_bytes(raw[i + 4:i + 8], "big")
        out.append(raw[i + 8:i + 8 + size])
        i += 8 + size
    if i == 0:
        return raw.decode("utf-8", "replace")
    return b"".join(out).decode("utf-8", "replace")


def run_helper(argv: list[str], timeout: float) -> tuple[int, str]:
    """Run *argv* in a throwaway Docker CLI container.

    The argv is built by this module from fixed paths -- no request field
    reaches it except a version that already matched VERSION_RE. The helper
    gets the socket and the installer directory at its HOST path (so compose
    can hand host paths to the daemon), and no network.
    """
    ensure_cli_image()
    body = {
        "Image": CLI_IMAGE, "Cmd": argv, "WorkingDir": HOME,
        "Labels": {"io.satom.agent.helper": "1"},
        "HostConfig": {
            "Binds": ["%s:%s" % (DOCKER_SOCKET, DOCKER_SOCKET), "%s:%s" % (HOME, HOME)],
            "NetworkMode": "none",
        },
    }
    created = api_json("POST", "/containers/create", body)
    cid = created["Id"]
    try:
        api_json("POST", "/containers/%s/start" % cid)
        res = api_json("POST", "/containers/%s/wait" % cid, timeout=timeout) or {}
        rc = int(res.get("StatusCode", 1))
        _st, raw = api("GET", "/containers/%s/logs" % cid,
                       query={"stdout": "1", "stderr": "1", "tail": "60"})
        return rc, _demux(raw)
    finally:
        try:
            api("DELETE", "/containers/%s" % cid, query={"force": "1"})
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
def do_restart(st: Status, service: str, action: str) -> None:
    check_service_action(service, action)  # re-checked at the point of use
    cs = service_containers(service)
    if not cs:
        raise Refused("service %r has no container in this stack" % service)
    for c in cs:
        path = "/containers/%s/%s" % (c["Id"], action)
        api_json("POST", path, query={"t": "20"} if action != "start" else None,
                 timeout=90)
        st.step("%s %s" % (action, (c.get("Names") or ["?"])[0].lstrip("/")), True)
    if action == "stop":
        return
    ok, detail = wait_service(service, 180, want_healthy=True)
    st.step("%s is up" % service, ok, detail)
    if not ok:
        raise DockerError("%s did not come back: %s" % (service, detail))


def do_cert(st: Status, params: dict) -> None:
    for k in ("cert_pem", "key_pem", "chain_pem"):
        if k in params:
            check_pem(k, params[k], optional=(k == "chain_pem"))
    d = tempfile.mkdtemp(prefix="satom-cert-")
    try:
        os.chmod(d, 0o700)
        args = [TLS_BOOTSTRAP, "import-cert", "--pki", str(PKI_DIR)]
        for k, flag, fn in (("cert_pem", "--cert", "cert.pem"),
                            ("key_pem", "--key", "key.pem"),
                            ("chain_pem", "--chain", "chain.pem")):
            if params.get(k):
                p = os.path.join(d, fn)
                with open(p, "w") as fh:
                    fh.write(params[k])
                os.chmod(p, 0o600)
                args += [flag, p]
        r = subprocess.run(args, capture_output=True, text=True, timeout=60)
        st.step("import-cert into satom-pki", r.returncode == 0,
                (r.stderr or r.stdout)[-400:])
        if r.returncode != 0:
            raise DockerError("import-cert refused the certificate")
    finally:
        shutil.rmtree(d, ignore_errors=True)
    do_restart(st, "proxy", "restart")


def _read_env() -> tuple[Path, str, dict]:
    p = Path(HOME) / "satom.env"
    text = p.read_text()
    return p, text, parse_env(text)


def _write_env(p: Path, text: str) -> None:
    tmp = p.parent / (".satom.env.%s" % secrets.token_hex(4))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, text.encode())
    finally:
        os.close(fd)
    os.replace(str(tmp), str(p))


def _relink(link: Path, target: Path) -> None:
    tmp = link.parent / (".%s.%s" % (link.name, secrets.token_hex(4)))
    os.symlink(str(target), str(tmp))
    os.replace(str(tmp), str(link))


def safe_extract(tgz: Path, dest: Path) -> None:
    """Extract a codeload tarball, stripping its top directory, refusing
    anything that would land outside *dest*."""
    def inside(rel: str) -> bool:
        n = os.path.normpath(rel)
        return not (os.path.isabs(rel) or n == ".." or n.startswith("../"))

    with tarfile.open(str(tgz), "r:gz") as tf:
        members = []
        for m in tf.getmembers():
            parts = m.name.split("/", 1)
            if len(parts) < 2 or not parts[1]:
                continue
            m.name = parts[1]
            # Checked here, not delegated to tarfile's "data" filter alone:
            # that filter only exists from Python 3.11.4, and this is the one
            # place a hostile archive meets a root process.
            if not inside(m.name):
                raise Refused("archive member %r would land outside the tree" % m.name[:80])
            if m.issym():
                target = os.path.join(os.path.dirname(m.name), m.linkname)
                if os.path.isabs(m.linkname) or not inside(target):
                    raise Refused("archive link %r points outside the tree" % m.name[:80])
            elif m.islnk():
                lp = m.linkname.split("/", 1)
                m.linkname = lp[1] if len(lp) == 2 else ""
                if not m.linkname or not inside(m.linkname):
                    raise Refused("archive hard link %r points outside the tree" % m.name[:80])
            elif not (m.isfile() or m.isdir()):
                raise Refused("archive member %r is not a file, directory or link" % m.name[:80])
            m.mode &= 0o755
            m.uid = m.gid = 0
            m.uname = m.gname = "root"
            members.append(m)
        if hasattr(tarfile, "data_filter"):
            tf.extractall(str(dest), members=members, filter="data")
        else:
            tf.extractall(str(dest), members=members)


def stage_release(st: Status, version: str) -> Path:
    rel = Path(HOME) / "releases"
    dest = rel / version
    if (dest / "Dockerfile").is_file():
        st.step("release tree v%s present" % version, True, str(dest))
        return dest
    rel.mkdir(parents=True, exist_ok=True)
    url = "https://codeload.github.com/%s/tar.gz/refs/tags/v%s" % (RELEASE_REPO, version)
    tmpd = Path(tempfile.mkdtemp(prefix="satom-src-", dir=str(rel)))
    try:
        tgz = tmpd / "src.tar.gz"
        with urllib.request.urlopen(url, timeout=60) as r, open(tgz, "wb") as fh:
            total = 0
            while True:
                b = r.read(1 << 20)
                if not b:
                    break
                total += len(b)
                if total > MAX_DOWNLOAD_BYTES:
                    raise DockerError("download larger than %d bytes" % MAX_DOWNLOAD_BYTES)
                fh.write(b)
        st.step("download v%s" % version, True, "%s (%d bytes)" % (url, total))
        tree = tmpd / "tree"
        tree.mkdir()
        safe_extract(tgz, tree)
        if not ((tree / "Dockerfile").is_file()
                and (tree / "deploy" / "docker" / "compose.yaml").is_file()):
            raise Refused("release v%s does not ship the Docker stack" % version)
        if not (tree / "deploy" / "docker" / "compose.agent.yaml").is_file():
            st.step("release v%s has no operations agent" % version, True,
                    "the console loses these controls after the switch; "
                    "use satom-docker from then on")
        bad = bad_network_literals(tree)
        if bad:
            raise Refused("release v%s carries invalid networks: %s"
                          % (version, "; ".join(bad[:3])))
        st.step("check release tree", True, "no invalid networks")
        os.replace(str(tree), str(dest))
        return dest
    finally:
        shutil.rmtree(str(tmpd), ignore_errors=True)


def do_update(st: Status, version: str) -> None:
    check_version(version)
    if not HOME:
        raise Refused("updating from the console needs the installer layout "
                      "(/opt/satom-docker). On a manual checkout build the new "
                      "tag and run ./satom-docker.sh up.")
    envp, env_text, env = _read_env()
    old_image = env.get("SATOM_IMAGE", "")
    image = "satom:%s" % version
    if old_image == image:
        raise Refused("the stack already runs %s" % image)
    st.set(target=version, previous=old_image)
    tree = stage_release(st, version)
    if image not in image_tags():
        st.step("build %s" % image, True, "started (5-15 min the first time)")
        rc, out = run_helper(["docker", "build", "-t", image, str(tree)], timeout=3600)
        st.step("build %s" % image, rc == 0, out[-400:])
        if rc != 0:
            raise DockerError("image build failed")
    else:
        st.step("image %s present" % image, True)

    home = Path(HOME)
    current = home / "current"
    previous_target = os.readlink(str(current)) if current.is_symlink() else ""

    def switch_to(target: Path, img: str, text: str) -> tuple[int, str]:
        _relink(current, target)
        _relink(target / "deploy" / "docker" / ".env", envp)
        _write_env(envp, env_set_text(text, "SATOM_IMAGE", img))
        e = parse_env(envp.read_text())
        rc, out = run_helper(compose_argv(HOME, e, "config", "--services"), timeout=120)
        if rc != 0:
            return rc, out
        svcs = [s for s in out.split() if re.match(r"^[a-z0-9-]+$", s) and s != "agent"]
        return run_helper(compose_argv(HOME, e, "up", "-d", "--remove-orphans", *svcs),
                          timeout=900)

    rc, out = switch_to(tree, image, env_text)
    st.step("recreate the stack on %s" % image, rc == 0, out[-400:])
    ok = rc == 0
    if ok:
        ok, detail = wait_service("web", WEB_HEALTH_TIMEOUT, want_healthy=True)
        st.step("web healthy on %s" % image, ok, detail)
    if ok:
        return
    # Roll back to exactly what was there: the previous tree, the previous
    # image line, and the stack recreated on it.
    if previous_target:
        rc2, out2 = switch_to(Path(previous_target), old_image, env_text)
        _write_env(envp, env_text)
        st.step("rollback to %s" % (old_image or "previous"), rc2 == 0, out2[-300:])
    raise DockerError("the update did not come up healthy; rolled back")


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------
_BUSY = {"id": ""}


def cert_info() -> dict:
    """The certificate the proxy serves, for the web to render.

    The web does not mount ``satom-pki``: the volume also holds the private
    key and the internal CA, and a read-only mount would still put them one
    permission bit away from the process that parses appliance input. So the
    agent forwards the PUBLIC certificate only -- and refuses to forward a
    file that contains key material, whatever its name says.
    """
    crt = PKI_DIR / "public" / "server.crt"
    info = {"present": False, "pem": "", "source": ""}
    try:
        pem = crt.read_text()
    except OSError:
        return info
    if "PRIVATE KEY" in pem or len(pem) > MAX_PEM_BYTES["cert_pem"] or not PEM_RE.match(pem):
        info["error"] = "public/server.crt is not a certificate-only PEM"
        return info
    info.update(present=True, pem=pem)
    try:
        info["source"] = json.loads((PKI_DIR / "public" / "meta.json").read_text()).get("source", "")
    except Exception:  # noqa: BLE001
        pass
    return info


def heartbeat_doc() -> dict:
    doc = {"ts": time.time(), "at": now_iso(), "busy": _BUSY["id"],
           "agent_version": _read(Path("/opt/satom/VERSION")),
           "layout": "installer" if HOME else "manual",
           "project": PROJECT, "policy": {k: list(v) for k, v in SERVICE_POLICY.items()}}
    try:
        doc["containers"] = [container_row(c) for c in project_containers()]
        doc["engine_ok"] = True
    except Exception as exc:  # noqa: BLE001
        doc["containers"] = []
        doc["engine_ok"] = False
        doc["engine_error"] = str(exc)[:300]
    web = [c for c in doc["containers"] if c["service"] == "web"]
    doc["stack_image"] = web[0]["image"] if web else ""
    versions = {}
    try:
        for t in image_tags():
            v = t.split(":", 1)[1]
            if VERSION_RE.match(v):
                versions.setdefault(v, {})["image"] = True
    except Exception:  # noqa: BLE001
        pass
    if HOME:
        rel = Path(HOME) / "releases"
        if rel.is_dir():
            for p in rel.iterdir():
                if VERSION_RE.match(p.name) and (p / "Dockerfile").is_file():
                    versions.setdefault(p.name, {})["tree"] = True
        try:
            doc["configured_image"] = parse_env((Path(HOME) / "satom.env").read_text()).get("SATOM_IMAGE", "")
        except OSError:
            doc["configured_image"] = ""
    doc["versions"] = {v: {"image": bool(d.get("image")), "tree": bool(d.get("tree"))}
                       for v, d in versions.items()}
    doc["cert"] = cert_info()
    return doc


def _read(p: Path) -> str:
    try:
        return p.read_text().strip()
    except OSError:
        return ""


def heartbeat_loop(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            write_owned(HEARTBEAT, json.dumps(heartbeat_doc(), indent=1).encode())
        except Exception as exc:  # noqa: BLE001
            log("heartbeat failed: %s" % exc)
        stop.wait(HEARTBEAT_SECONDS)


# ---------------------------------------------------------------------------
# Request loop
# ---------------------------------------------------------------------------
def handle(path: Path) -> None:
    stem = path.name[:-5]
    try:
        age = time.time() - os.lstat(str(path)).st_mtime
        raw = read_request(path)
    except (OSError, Refused) as exc:
        log("unreadable request %s: %s" % (path.name, exc))
        _unlink(path)
        return
    # The request is consumed before it is acted on: a cert request carries a
    # private key, and a request that crashed the agent must not replay forever.
    _unlink(path)
    safe_id = stem if UID_RE.match(stem) else ""
    try:
        req = json.loads(raw.decode("utf-8"))
        req = req if isinstance(req, dict) else {}
    except Exception:  # noqa: BLE001
        req = {}
    st = Status(safe_id, req, str(req.get("kind", ""))[:20]) if safe_id else None
    try:
        kind, params = validate_request(raw, stem)
        if age > REQUEST_MAX_AGE:
            raise Refused("request expired: queued %d s ago (limit %d s); "
                          "it is not executed late" % (age, REQUEST_MAX_AGE))
        st.step("validate", True, kind)
        _BUSY["id"] = safe_id
        if kind == "ctr-restart":
            st.set(target=params["service"], unit=params["service"],
                   action=params["action"])
            do_restart(st, params["service"], params["action"])
        elif kind == "ctr-update":
            do_update(st, params["version"])
        elif kind == "ctr-cert":
            st.set(target="proxy certificate")
            do_cert(st, params)
        st.finish("success")
    except Refused as exc:
        if st:
            st.step("validate", False, str(exc))
            st.finish("failed", error=str(exc))
        else:
            log("refused %s: %s" % (path.name, exc))
    except Exception as exc:  # noqa: BLE001
        if st:
            st.step("error", False, "%s: %s" % (type(exc).__name__, exc))
            st.finish("failed", error=str(exc)[:300])
        log("failed %s: %s" % (path.name, exc))
    finally:
        _BUSY["id"] = ""


def _unlink(p: Path) -> None:
    try:
        os.unlink(str(p))
    except OSError:
        pass


def prepare_dirs() -> None:
    """The volumes are created empty and root-owned. The web (uid 999) must be
    able to drop requests and its own 'queued' status rows."""
    for d, mode in ((REQ_DIR, 0o770), (STATUS_DIR, 0o775)):
        d.mkdir(parents=True, exist_ok=True)
        os.chown(str(d), APP_UID, APP_GID)
        os.chmod(str(d), mode)


def main() -> int:
    if not os.path.exists(DOCKER_SOCKET):
        log("no %s: this container must mount the Docker socket" % DOCKER_SOCKET)
        return 78
    prepare_dirs()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    t = threading.Thread(target=heartbeat_loop, args=(stop,), daemon=True)
    t.start()
    log("started: project=%s layout=%s queue=%s" % (PROJECT, "installer" if HOME else "manual", QUEUE))
    while not stop.is_set():
        try:
            for p in sorted(REQ_DIR.glob("*.json")):
                if stop.is_set():
                    break
                handle(p)
        except Exception as exc:  # noqa: BLE001
            log("loop error: %s" % exc)
        stop.wait(POLL_SECONDS)
    log("stopping")
    return 0


if __name__ == "__main__":
    sys.exit(main())
