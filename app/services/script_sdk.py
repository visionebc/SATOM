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
``satom``   read-only SATOM data the script declares (``SATOM["satom"]`` in
            main.py, or the script's settings), for the person who runs it
            and in the ADOM it was started from -- what the pages show them:
            ``satom.devices(product="fortiweb")`` → list of devices
            (id, name, kind, version, host, ip, zone, line, department...);
            ``satom.lb_lookup("www.example.com")`` → ``{"rows", "members",
            "unmatched", ...}`` from SATOM's load-balancer cache (each row has
            ``_members``: ``[{ip, port, status}]``);
            ``satom.dns_lookup(["192.0.2.5"])`` → ``{"rows", "ptr", "unresolved",
            ...}`` through SATOM's DNS resolvers (``ptr``: ``[{ip, hostname}]``).
            Nothing here reaches a device, and nothing writes.

THE SATOM BLOCK
    main.py may say what it needs in one place, read (never run) by SATOM::

        SATOM = {
            "name": "LB members owner",
            "inputs": {"host": {"label": "Host name", "required": True}},
            "connections": ["cmdb"],
            "satom": ["lb_lookup", "dns_lookup"],
        }

    Saving the script takes its form, connections and SATOM data from it.

ON YOUR OWN COMPUTER (the developer kit, Plugin Studio > Scripts > kit)::

    python3 satom_script.py run main.py --input host=www.example.com --mocks mocks.json
    python3 satom_script.py form main.py

    ``--mocks`` answers ``connection()`` and ``satom.*`` from a JSON file
    (see the kit's README), and refuses what main.py does not declare --
    as SATOM would. No SATOM, no network.
"""
from __future__ import annotations

import json
import os
import sys
import time

__all__ = ["inputs", "result", "log", "tcp", "secret", "script", "version",
           "connection", "ConnectionError", "satom"]

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


#: Local runs of the developer kit: a JSON file of canned answers.
_MOCKS_ENV = "SATOM_SCRIPT_MOCKS"
#: Local runs: what main.py declares (``{"connections": [...], "satom": [...]}``).
_DECLARED_ENV = "SATOM_SCRIPT_DECLARED"


def _broker(req: dict) -> dict:
    if os.environ.get(_MOCKS_ENV):
        return _mocked(req)
    import socket
    home = os.environ.get("HOME") or os.getcwd()
    fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            s.connect("/proc/self/fd/%d/%s" % (fd, _CONN_SOCK))
        except OSError:
            raise ConnectionError("this run has no connections and no SATOM data: "
                                  "declare them in SATOM = {...} in main.py (or in the "
                                  "script's settings)")
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
    PostgreSQL: ``query``. Server (satom-webctl): ``server``."""

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

    def server(self, operation: str, **args) -> dict:
        """One satom-webctl operation on a server connection:
        ``server("files.list", server="nginx", name="shop", path="img")``.
        Returns the operation's result; raises ConnectionError when the
        server refused it or writes are off for the connection."""
        return _broker({"connection": self.key, "server_op": str(operation),
                        "args": args}).get("result")

    def __repr__(self) -> str:
        return "<Connection %s>" % self.key


def connection(key: str) -> Connection:
    """A Connection this script declares, by key."""
    return Connection(str(key))


class _Satom:
    """Read-only SATOM data (module docstring). Each call is one line in the
    run record; a call the script does not declare is refused."""

    @staticmethod
    def _call(op: str, args: dict):
        return _broker({"satom": op, "args": args}).get("data")

    def devices(self, product: str = "", *, zone: str = "", line: str = "",
                department: str = "", maintenance: str = "include",
                resolve: bool = True) -> list:
        """SATOM's managed devices (``product``: fortiweb, fortigate, fortiadc,
        fortianalyzer, fortiauthenticator; '' = all). ``maintenance="skip"``
        leaves out devices in maintenance; ``resolve`` fills ``ip`` of a device
        whose host is a name."""
        data = self._call("devices", {"product": product, "zone": zone, "line": line,
                                      "department": department,
                                      "maintenance": maintenance, "resolve": resolve})
        return list((data or {}).get("rows") or []) if isinstance(data, dict) else list(data or [])

    def lb_lookup(self, entries, *, exact: bool = False) -> dict:
        """Which FortiWeb / FortiADC virtual servers and pools answer for each
        name or address (SATOM's LB cache): ``rows`` (one per match, with
        ``_members``), ``members`` (every member IP once), ``unmatched``."""
        return self._call("lb_lookup", {"entries": entries, "exact": bool(exact)}) or {}

    def dns_lookup(self, entries, *, ttl: bool = False) -> dict:
        """Each name or address through SATOM's DNS resolvers: ``rows``,
        ``answers``, ``unresolved``, ``ptr`` (``[{ip, hostname}]`` for the
        addresses that have a PTR)."""
        return self._call("dns_lookup", {"entries": entries, "ttl": bool(ttl)}) or {}

    def __repr__(self) -> str:
        return "<satom data>"


satom = _Satom()


# --------------------------------------------------------------------------- #
#  the developer kit: local runs with canned answers                            #
# --------------------------------------------------------------------------- #
def _mocked(req: dict) -> dict:
    """What the broker would answer, from the mocks file. Refuses what main.py
    does not declare, like the broker."""
    if os.environ[_MOCKS_ENV] == os.devnull:
        raise ConnectionError("this local run has no --mocks file: connection() and "
                              "satom.* answer from it (see the kit's README)")
    try:
        with open(os.environ[_MOCKS_ENV], encoding="utf-8") as fh:
            mocks = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ConnectionError("mocks file: %s" % exc)
    try:
        declared = json.loads(os.environ.get(_DECLARED_ENV) or "null")
    except ValueError:
        declared = None
    if "satom" in req:
        op = str(req.get("satom"))
        if declared is not None and op not in (declared.get("satom") or []):
            raise ConnectionError("SATOM data %r is not declared by this script (add it "
                                  "to SATOM['satom'] in main.py)" % op)
        table = mocks.get("satom") or {}
        if op not in table:
            raise ConnectionError("no mock for satom.%s in the mocks file" % op)
        sys.stderr.write("[mock] satom.%s\n" % op)
        return {"data": table[op]}
    key = str(req.get("connection") or "")
    if declared is not None and key not in (declared.get("connections") or []):
        raise ConnectionError("connection %r is not declared by this script (add it to "
                              "SATOM['connections'] in main.py)" % key)
    table = (mocks.get("connections") or {}).get(key)
    if table is None:
        raise ConnectionError("no mock for connection %r in the mocks file" % key)
    if "sql" in req:
        ans = table.get("sql") if isinstance(table, dict) else None
        if ans is None:
            raise ConnectionError("no mock for SQL on connection %r" % key)
        sys.stderr.write("[mock] %s sql\n" % key)
        return ans
    if req.get("list_operations"):
        return table.get("catalog") or {"operations": []}
    if "server_op" in req:
        op = str(req.get("server_op"))
        ans = (table.get("server") or {}).get(op) if isinstance(table, dict) else None
        if ans is None:
            raise ConnectionError("no mock for server operation %s on connection %r (key "
                                  "\"server\": {\"%s\": ...})" % (op, key, op))
        sys.stderr.write("[mock] %s server %s\n" % (key, op))
        return {"result": ans}
    method = str(req.get("method") or "GET").upper()
    path = str(req.get("path") or "")
    if req.get("operation"):
        method, path = "OP", str(req["operation"])
    ans = None
    for k in ("%s %s" % (method, path), "%s *" % method, "*"):
        if isinstance(table, dict) and k in table:
            ans = table[k]
            break
    if ans is None:
        raise ConnectionError("no mock for %s %s on connection %r (keys like "
                              "\"GET /path\", \"GET *\" or \"*\")" % (method, path, key))
    sys.stderr.write("[mock] %s %s %s -> %s\n" % (key, method, path, ans.get("status", 200)))
    text = ans.get("text")
    if text is None:
        text = json.dumps(ans.get("json")) if "json" in ans else ""
    return {"status": int(ans.get("status", 200)), "text": text,
            "headers": {"content-type": "application/json" if "json" in ans else "text/plain"}}


def _cli(argv: list) -> int:
    """``run`` / ``form`` (module docstring)."""
    import argparse
    import subprocess
    import tempfile
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(prog="satom_script.py",
                                 description="Run a SATOM script on your computer.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run main.py with inputs and canned answers")
    r.add_argument("script", help="the script's main.py")
    r.add_argument("--input", "-i", action="append", default=[], metavar="NAME=VALUE")
    r.add_argument("--inputs", metavar="FILE.json", help="inputs as a JSON object")
    r.add_argument("--mocks", metavar="FILE.json",
                   help="canned answers for connection() and satom.* (see README)")
    f = sub.add_parser("form", help="show the form, connections and SATOM data of main.py")
    f.add_argument("script")
    args = ap.parse_args(argv)
    sys.path.insert(0, here)
    try:
        import script_manifest as MF
    except ImportError:
        MF = None
    with open(args.script, encoding="utf-8") as fh:
        source = fh.read()
    man = None
    if MF is not None:
        try:
            man = MF.parse(source)
        except MF.ManifestError as exc:
            sys.stderr.write("main.py line %s: %s\n" % (exc.line, exc))
            return 2
    if args.cmd == "form":
        print(json.dumps(man, indent=2) if man is not None
              else "main.py has no SATOM = {...} block: its form is set in SATOM's editor.")
        return 0
    inputs_ = {}
    if args.inputs:
        with open(args.inputs, encoding="utf-8") as fh:
            inputs_.update(json.load(fh))
    for item in args.input:
        name, sep, value = item.partition("=")
        if not sep:
            sys.stderr.write("--input %s: use NAME=VALUE\n" % item)
            return 2
        inputs_[name.strip()] = value
    for fld in (man or {}).get("fields") or []:
        name, ftype = fld["name"], fld.get("type") or "text"
        if name not in inputs_ and fld.get("default") is not None:
            inputs_[name] = fld["default"]
        if name not in inputs_:
            if fld.get("required"):
                sys.stderr.write("input %r is required (--input %s=...)\n" % (name, name))
                return 2
            inputs_[name] = False if ftype == "checkbox" else None
            continue
        v = inputs_[name]
        if ftype == "number" and isinstance(v, str):
            inputs_[name] = float(v) if "." in v else int(v)
        elif ftype == "checkbox" and isinstance(v, str):
            inputs_[name] = v.strip().lower() in ("1", "true", "yes", "on")
    env = dict(os.environ)
    env["PYTHONPATH"] = here + os.pathsep + env.get("PYTHONPATH", "")
    env[_MOCKS_ENV] = os.path.abspath(args.mocks) if args.mocks else os.devnull
    if man is not None:
        env[_DECLARED_ENV] = json.dumps({"connections": man.get("connections") or [],
                                         "satom": man.get("satom") or []})
    with tempfile.TemporaryFile() as res:
        env["SATOM_RESULT_FD"] = str(res.fileno())
        ctx = json.dumps({"inputs": inputs_, "script": os.path.basename(
            os.path.dirname(os.path.abspath(args.script))), "version": "local"})
        proc = subprocess.run([sys.executable, os.path.abspath(args.script)], input=ctx.encode(),
                              env=env, cwd=os.path.dirname(os.path.abspath(args.script)),
                              pass_fds=(res.fileno(),))
        res.seek(0)
        raw = res.read()
    if raw:
        print("--- result() ---")
        try:
            print(json.dumps(json.loads(raw.decode("utf-8")), indent=2))
        except ValueError:
            print(raw.decode("utf-8", "replace"))
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
