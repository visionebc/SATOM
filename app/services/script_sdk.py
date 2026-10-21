"""``satom_script`` -- what a Script Library script imports.

In the repo this is ``app/services/script_sdk.py``; the runner copies it into
the run's work directory as ``satom_script.py`` (with ``satom_sdk.py`` next to
it for ``tcp``). Nothing of ``/opt/satom`` is on ``sys.path`` in the jail.

    from satom_script import inputs, result, log, tcp

    log("checking %s" % inputs["host"])
    result({"ok": True, "rows": [...]})

``inputs``  the form values, keyed by field name, typed (numbers are numbers,
            checkboxes are booleans). Read once from stdin. Database fields
            arrive as rows the server read for the user's ADOMs:
            ``lookup`` → ``{"value", "label", "row": {"table.col": ...}}``,
            ``lookup_multi`` → a list of those, ``dataset`` →
            ``{"columns": [...], "rows": [{"table.col": ...}], "truncated"}``.
            Cell values are text ('' for NULL).
``result``  one JSON document, shown as structured output of the run. Calling
            it again replaces the previous one. Not parsed out of stdout, so
            printing JSON cannot fake it.
``log``     a timestamped line on stdout (print() works too).
``secret``  a credential the script declares, from the vault:
            ``secret("FGT_ADMIN")["password"]``. Masked in the run record.
``tcp``     a TCP socket through the sandbox proxy, for SSH and other non-HTTP
            protocols (only when the script has network access); HTTP(S)
            clients use the proxy on their own.
``connection``  a Connection the script declares (App Studio):
            ``connection("crm").get("/tickets", params={"open": 1}).json()``.
            SATOM makes the call with the connection's credential, which the
            script never sees; only the connection's base URL is reachable,
            whatever the script's network mode. A PostgreSQL connection
            answers ``.query("SELECT ...", [params])`` (read-only unless
            ``write=True``).
            A connection pinned to an API Catalog version calls endpoints
            by id: ``connection("inv").op("getHost", {"id": 7}).json()``;
            ``.operations()`` lists them and ``.catalog()`` names the API and
            version. A request that is not an endpoint of that version is
            refused.
"""
from __future__ import annotations

import json
import os
import sys
import time

__all__ = ["inputs", "result", "log", "tcp", "secret", "script", "version",
           "connection", "ConnectionError"]

_RESULT_FD_ENV = "SATOM_RESULT_FD"


def _load() -> dict:
    if sys.stdin is None or sys.stdin.isatty():
        return {}
    try:
        data = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


_ctx = _load()
inputs: dict = dict(_ctx.get("inputs") or {})
_secrets: dict = dict(_ctx.get("secrets") or {})
script: str = str(_ctx.get("script") or "")
version = _ctx.get("version")


def secret(name: str) -> dict:
    """A credential the script declares: ``{"username": ..., "password": ...}``
    or ``{"value": ...}``. Values come from the vault for this run only and
    are masked in the run record."""
    if name not in _secrets:
        raise KeyError("credential %r is not available to this run: not declared "
                       "by the script, or not set in the vault" % name)
    return dict(_secrets[name])


def log(msg) -> None:
    sys.stdout.write("%s %s\n" % (time.strftime("%H:%M:%S"), msg))
    sys.stdout.flush()


def result(data) -> None:
    raw = os.environ.get(_RESULT_FD_ENV, "")
    if not raw.isdigit():
        return
    fd = int(raw)
    payload = json.dumps(data, default=str)
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
    except OSError:
        pass
    os.write(fd, payload.encode("utf-8"))


def tcp(host: str, port: int, timeout: float = 10.0):
    from satom_sdk import tcp as _tcp
    return _tcp(host, port, timeout)


_CONN_SOCK = ".satom-conn.sock"


class ConnectionError(Exception):  # noqa: A001 -- the name scripts expect
    """A connection call SATOM refused or that failed."""


class Response:
    def __init__(self, data: dict):
        self.status_code = int(data.get("status") or 0)
        self.status = self.status_code
        self.headers = dict(data.get("headers") or {})
        self.text = str(data.get("text") or "")
        self.truncated = bool(data.get("truncated"))
        self.elapsed_ms = data.get("elapsed_ms")

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self):
        return json.loads(self.text) if self.text.strip() else None

    def raise_for_status(self) -> "Response":
        if not self.ok:
            raise ConnectionError("HTTP %s: %s" % (self.status_code, self.text[:300]))
        return self

    def __repr__(self) -> str:
        return "<Response %s>" % self.status_code


def _broker(req: dict) -> dict:
    import socket
    home = os.environ.get("HOME") or os.getcwd()
    fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            s.connect("/proc/self/fd/%d/%s" % (fd, _CONN_SOCK))
        except OSError:
            raise ConnectionError("this run has no connections: declare them in the "
                                  "script's settings (App Studio connections)")
        s.sendall(json.dumps(req).encode("utf-8") + b"\n")
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
        os.close(fd)
    try:
        data = json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
    except ValueError:
        raise ConnectionError("no answer from the connection broker")
    if isinstance(data, dict) and data.get("error"):
        raise ConnectionError(data["error"])
    return data


class Connection:
    """A declared Connection. HTTP: ``get/post/put/patch/delete/request``.
    PostgreSQL: ``query``."""

    def __init__(self, key: str):
        self.key = key

    def request(self, method: str, path: str = "", *, params=None, json=None,
                data=None, headers=None) -> Response:
        return Response(_broker({"connection": self.key, "method": method,
                                 "path": path, "params": params, "json": json,
                                 "data": data, "headers": headers}))

    def get(self, path: str = "", **kw) -> Response:
        return self.request("GET", path, **kw)

    def post(self, path: str = "", **kw) -> Response:
        return self.request("POST", path, **kw)

    def put(self, path: str = "", **kw) -> Response:
        return self.request("PUT", path, **kw)

    def patch(self, path: str = "", **kw) -> Response:
        return self.request("PATCH", path, **kw)

    def delete(self, path: str = "", **kw) -> Response:
        return self.request("DELETE", path, **kw)

    def op(self, operation: str, path_params=None, *, params=None, json=None,
           data=None, headers=None) -> Response:
        """Call an endpoint of the API Catalog version the connection is
        pinned to, by id: ``op("getHost", {"id": 7})``. The method and the
        path come from the catalog; *path_params* fill its ``{name}`` parts."""
        return Response(_broker({"connection": self.key, "operation": str(operation),
                                 "path_params": path_params, "params": params,
                                 "json": json, "data": data, "headers": headers}))

    def catalog(self) -> dict:
        """``{"api", "version", "status", "operations": [...]}`` -- the API
        Catalog version this connection is pinned to."""
        return _broker({"connection": self.key, "list_operations": True})

    def operations(self) -> list:
        """The endpoints of the pinned version: ``[{"id", "method", "path",
        "summary", "body", "params"}]``."""
        return list(self.catalog().get("operations") or [])

    def query(self, sql: str, params=None, *, write: bool = False,
              max_rows: int = 1000) -> dict:
        return _broker({"connection": self.key, "sql": sql, "params": params,
                        "write": bool(write), "max_rows": max_rows})

    def __repr__(self) -> str:
        return "<Connection %s>" % self.key


def connection(key: str) -> Connection:
    """A Connection this script declares, by key."""
    return Connection(str(key))
