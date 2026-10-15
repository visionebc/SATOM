"""``satom_script`` -- what a Script Library script imports.

In the repo this is ``app/services/script_sdk.py``; the runner copies it into
the run's work directory as ``satom_script.py`` (with ``satom_sdk.py`` next to
it for ``tcp``). Nothing of ``/opt/satom`` is on ``sys.path`` in the jail.

    from satom_script import inputs, result, log, tcp

    log("checking %s" % inputs["host"])
    result({"ok": True, "rows": [...]})

``inputs``  the form values, keyed by field name, typed (numbers are numbers,
            checkboxes are booleans). Read once from stdin.
``result``  one JSON document, shown as structured output of the run. Calling
            it again replaces the previous one. Not parsed out of stdout, so
            printing JSON cannot fake it.
``log``     a timestamped line on stdout (print() works too).
``secret``  a credential the script declares, from the vault:
            ``secret("FGT_ADMIN")["password"]``. Masked in the run record.
``tcp``     a TCP socket through the sandbox proxy, for SSH and other non-HTTP
            protocols (only when the script has network access); HTTP(S)
            clients use the proxy on their own.
"""
from __future__ import annotations

import json
import os
import sys
import time

__all__ = ["inputs", "result", "log", "tcp", "secret", "script", "version"]

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
