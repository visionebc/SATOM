"""The connection broker — how a sandboxed script calls a Connection without
ever holding its credential.

One per Script Library run, started by ``script_runner`` before the jail and
closed after it, on a unix socket in the run's work directory (the same place
and the same lifetime as the egress proxy, ``sandbox.EgressProxy``). Inside
the jail ``satom_script.connection("crm")`` writes ONE JSON line per call and
reads one JSON line back; the broker, outside the jail, makes the call with
``studio_http`` and the secret it unwrapped at the start of the run.

So:
* the token, password or client secret never enters the jail — not in the
  environment, not on stdin, not in a file;
* a script reaches ONLY the connections it declares, and on each of them only
  what an app step reaches — the same core (``studio_http``): base-URL lock,
  no redirects, no step-set credential header, the destination check —
  whatever its network mode says: a script with ``network: none`` can still
  use its declared connections, and nothing else;
* every call is one line in the run record (``connection METHOD path →
  status``), next to the egress log.

DATABASE-FREE, like the runner that imports it.
"""
from __future__ import annotations

import json
import os
import socket
import threading
from typing import Any

from . import studio_http as H

SOCK_NAME = ".satom-conn.sock"
MAX_REQUEST = 3 * 1024 * 1024
MAX_CALLS = 500
#: Calls served at the same time. The broker runs in the runner process,
#: outside the jail: a script that opens sockets in a loop must not make it
#: start a thread (and hold a buffer) per socket.
MAX_CONCURRENT = 8


def _bind_unix(srv: socket.socket, path: str) -> None:
    fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY | os.O_DIRECTORY)
    try:
        srv.bind("/proc/self/fd/%d/%s" % (fd, os.path.basename(path)))
    finally:
        os.close(fd)


class ConnectionBroker:
    def __init__(self, sock_path: str, connections: dict[str, tuple[dict, str]], *,
                 verify=True, transport=None):
        self.sock_path = sock_path
        #: Test seam (an httpx.MockTransport); None = the network, checked.
        self.transport = transport
        self.connections = connections
        #: The trust bundle path (or True = public roots), for HTTPS and for a
        #: verified PostgreSQL connection.
        self.verify = verify
        self.tokens: dict = {}          # OAuth2 tokens, this run only
        self.log: list[str] = []
        self.calls = 0
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT)
        self._accepted = 0
        self._srv: socket.socket | None = None
        self._closed = False

    def secrets(self) -> dict[str, str]:
        return {"connection %s" % k: s for k, (_d, s) in self.connections.items() if s}

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> "ConnectionBroker":
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        _bind_unix(srv, self.sock_path)
        os.chmod(self.sock_path, 0o600)
        srv.listen(16)
        self._srv = srv
        threading.Thread(target=self._accept, daemon=True, name="satom-conn").start()
        return self

    def close(self) -> None:
        self._closed = True
        if self._srv is not None:
            for fn in (lambda: self._srv.shutdown(socket.SHUT_RDWR), self._srv.close):
                try:
                    fn()
                except OSError:
                    pass
        try:
            os.unlink(self.sock_path)
        except OSError:
            pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()

    def _note(self, line: str) -> None:
        with self._lock:
            if len(self.log) < 300:
                self.log.append(line)

    def _accept(self) -> None:
        while not self._closed:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            self._accepted += 1
            if self._accepted > MAX_CALLS + MAX_CONCURRENT:
                # Counted at accept, not after parsing: connections that never
                # send a request line are calls too.
                self._drop(conn, "more than %d connection calls in one run" % MAX_CALLS)
                continue
            if not self._slots.acquire(blocking=False):
                self._drop(conn, "more than %d connection calls at the same time"
                           % MAX_CONCURRENT)
                continue
            threading.Thread(target=self._serve_slot, args=(conn,), daemon=True).start()

    def _drop(self, conn, why: str) -> None:
        try:
            conn.settimeout(2)
            self._reply(conn, {"error": why})
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _serve_slot(self, conn) -> None:
        try:
            self._serve(conn)
        finally:
            self._slots.release()

    # -- one call ------------------------------------------------------------
    def _serve(self, client: socket.socket) -> None:
        try:
            client.settimeout(30)
            buf = bytearray()
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if b"\n" in chunk:
                    break
                if len(buf) > MAX_REQUEST:
                    self._reply(client, {"error": "request larger than %d KB"
                                         % (MAX_REQUEST // 1024)})
                    return
            try:
                req = json.loads(bytes(buf).split(b"\n", 1)[0].decode("utf-8"))
            except ValueError:
                self._reply(client, {"error": "malformed request"})
                return
            client.settimeout(None)
            self._reply(client, self.handle(req))
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    @staticmethod
    def _reply(client, obj) -> None:
        client.sendall(json.dumps(obj, default=str).encode("utf-8") + b"\n")

    def handle(self, req: Any) -> dict:
        """One call. Returns the answer, or ``{"error": ...}``. Never raises."""
        if not isinstance(req, dict):
            return {"error": "malformed request"}
        key = str(req.get("connection") or "")
        with self._lock:
            self.calls += 1
            over = self.calls > MAX_CALLS
        if over:
            return {"error": "more than %d connection calls in one run" % MAX_CALLS}
        if key not in self.connections:
            self._note("connection %s refused: not declared by this script" % key)
            return {"error": "connection %r is not declared by this script (or does "
                             "not exist)" % key}
        definition, secret = self.connections[key]
        if "sql" in req:
            params = req.get("params")
            if params is not None and not isinstance(params, (dict, list)):
                return {"error": "params must be a JSON object or list"}
            try:
                res = H.pg_request(definition, secret, str(req.get("sql") or ""), params,
                                   write=bool(req.get("write")),
                                   limit=int(req.get("max_rows") or 1000),
                                   ca=self.verify if isinstance(self.verify, str) else "")
            except (H.ConnectionError_, ValueError) as exc:
                self._note("connection %s sql failed: %s" % (key, exc))
                return {"error": str(exc)}
            self._note("connection %s sql %s → %s rows" % (
                key, "write" if req.get("write") else "read", len(res["rows"])))
            return res
        method = str(req.get("method") or "GET").upper()
        path = str(req.get("path") or "")
        body = req.get("json") if req.get("json") is not None else req.get("data")
        verify = self.verify if definition.get("verify_tls", True) else False
        try:
            res = H.http_request(
                definition, secret, method, path,
                query=req.get("params") if isinstance(req.get("params"), dict) else None,
                body=body,
                headers=req.get("headers") if isinstance(req.get("headers"), dict) else None,
                verify=verify, tokens=self.tokens, transport=self.transport)
        except H.ConnectionError_ as exc:
            self._note("connection %s %s %s failed: %s" % (key, method, path[:120], exc))
            return {"error": str(exc)}
        self._note("connection %s %s %s → %s" % (key, method, path[:120], res["status"]))
        text = res.get("text")
        if text is None:
            text = json.dumps(res.get("json")) if res.get("json") is not None else ""
        return {"status": res["status"], "headers": {"content-type": res.get("content_type", "")},
                "text": text, "elapsed_ms": res.get("ms")}
