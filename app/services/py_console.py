"""Sandboxed Python console — run ADMIN-authored ARBITRARY Python in a
bubblewrap jail with ZERO reach into the app.

This is the single most dangerous surface in the app, so the isolation is
belt-and-suspenders and its guarantees are pinned by
``tests/test_py_console.py``:

  * ``--clearenv``     -> the child inherits NO environment variables, so
                          ``FERNET_KEY`` / ``SECRET_KEY`` / ``DATABASE_URL``
                          (loaded into the gunicorn process from ``.env``) are
                          INVISIBLE inside the sandbox.
  * ``--unshare-all``  -> new user/pid/net/ipc/uts/cgroup namespaces. No network
                          namespace = no socket can leave the box (no exfil).
  * only ``/usr`` (+ the usr-merge symlinks), ``/proc``, ``/dev`` and a fresh
                          ``tmpfs /tmp`` are mounted. ``/opt/fortinet-manager``
                          (the ``.env``, the DB, the keyring, the code) is NOT
                          bound, so a script literally cannot open a secret or
                          write app state.
  * the workdir (harness + script + the read-only data bundle) is bound
                          READ-ONLY at ``/sandbox``.
  * wall-clock (``timeout``), CPU, address-space and process-count caps
                          (``prlimit``) stop infinite loops / fork bombs /
                          memory bombs.

The ``data`` bundle handed to the script is built by the CALLER via
``plugin_sandbox.load_datasets`` (the same masked, SELECT-only, curated path the
plugins use). The sandbox never touches the DB itself — it only receives a JSON
snapshot. A script can therefore transform/report on curated fleet data and
nothing else.

Verified live on LXC 248: bwrap 0.8.0 sandboxes correctly as the service user
``fortinet`` (uid 999), .env unreadable, network blocked.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any

# Absolute isolation caps (defence in depth; the hard guarantees are the
# namespaces + the minimal bind set — these just stop resource exhaustion).
_MEM_BYTES = 1024 * 1024 * 1024      # 1 GiB address space (RLIMIT_AS)
_MAX_PROCS = 256                     # fork-bomb ceiling (RLIMIT_NPROC, best-effort)
_MAX_FSIZE = 16 * 1024 * 1024        # 16 MiB any single file (tmpfs scratch)
_MAX_NOFILE = 128
_MAX_OUTPUT = 200_000                # cap captured stdout/stderr (chars)
_DEFAULT_TIMEOUT = 8
_MAX_TIMEOUT = 30

# The in-sandbox bootstrap: load the read-only bundle as ``data``, exec the
# admin's script as __main__, route errors to stderr with a clean exit code.
_HARNESS = r'''
import json, sys, traceback
try:
    with open("/sandbox/bundle.json") as fh:
        data = json.load(fh)
except Exception:
    data = {}
try:
    with open("/sandbox/script.py") as fh:
        _src = fh.read()
except Exception as exc:
    print("harness: cannot read script:", exc, file=sys.stderr)
    sys.exit(3)
try:
    _code = compile(_src, "<console>", "exec")
except SyntaxError:
    traceback.print_exc()
    sys.exit(2)
_g = {"__name__": "__main__", "__builtins__": __builtins__, "data": data}
try:
    exec(_code, _g)
except SystemExit:
    raise
except BaseException as exc:
    tb = exc.__traceback__
    if tb is not None:
        tb = tb.tb_next  # hide the harness exec frame; show only user frames
    traceback.print_exception(type(exc), exc, tb)
    sys.exit(1)
'''


def _bwrap_argv(workdir: str) -> list[str]:
    return [
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "HOME", "/sandbox",
        "--setenv", "LANG", "C.UTF-8",
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--symlink", "usr/sbin", "/sbin",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--ro-bind", workdir, "/sandbox",
        "--chdir", "/sandbox",
        "/usr/bin/python3", "-I", "-B", "/sandbox/harness.py",
    ]


def _norm_timeout(timeout: Any) -> int:
    try:
        return max(1, min(int(timeout), _MAX_TIMEOUT))
    except (TypeError, ValueError):
        return _DEFAULT_TIMEOUT


def run_python(source: str, bundle: dict[str, Any] | None = None, *,
               timeout: int = _DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Execute ``source`` in a bubblewrap sandbox; return a result dict.

    Result: ``{ok, stdout, stderr, returncode, timed_out, duration_ms}``.
    ``ok`` is True iff the script exited 0 and did not time out. Never raises for
    a script-level failure — a crash / timeout / OOM is reported in the dict.
    """
    timeout = _norm_timeout(timeout)

    if shutil.which("bwrap") is None:
        return {
            "ok": False, "returncode": None, "timed_out": False,
            "duration_ms": 0, "stdout": "",
            "stderr": "sandbox unavailable: bubblewrap (bwrap) is not installed",
        }

    workdir = tempfile.mkdtemp(prefix="pyc_")
    try:
        with open(os.path.join(workdir, "harness.py"), "w") as fh:
            fh.write(_HARNESS)
        with open(os.path.join(workdir, "script.py"), "w") as fh:
            fh.write(source or "")
        with open(os.path.join(workdir, "bundle.json"), "w") as fh:
            json.dump(bundle or {}, fh, default=str)
        for name in ("harness.py", "script.py", "bundle.json"):
            os.chmod(os.path.join(workdir, name), 0o644)
        os.chmod(workdir, 0o755)

        argv = [
            "timeout", "-k", "2", "-s", "KILL", str(timeout),
            "prlimit",
            f"--as={_MEM_BYTES}",
            f"--cpu={timeout + 1}",
            f"--nproc={_MAX_PROCS}",
            f"--fsize={_MAX_FSIZE}",
            f"--nofile={_MAX_NOFILE}",
            "--",
        ] + _bwrap_argv(workdir)

        started = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=timeout + 6,  # outer backstop beyond `timeout`
            )
            rc: int | None = proc.returncode
            out, err = proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            rc = None
            out = exc.stdout or ""
            err = exc.stderr or ""
            if isinstance(out, bytes):
                out = out.decode("utf-8", "replace")
            if isinstance(err, bytes):
                err = err.decode("utf-8", "replace")
        duration_ms = int((time.monotonic() - started) * 1000)

        # GNU `timeout` reports 124 (timed out) or 128+signal (killed via
        # -s KILL => 137). SIGXCPU from RLIMIT_CPU => 128+24 = 152.
        if rc in (124, 137, 152):
            timed_out = True
        if not timed_out and rc not in (0, None) and \
                duration_ms >= int(timeout * 900):
            # ran ~the whole wall clock then died -> almost certainly a timeout
            timed_out = True

        ok = (rc == 0) and not timed_out
        return {
            "ok": ok,
            "returncode": rc,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
            "stdout": (out or "")[:_MAX_OUTPUT],
            "stderr": (err or "")[:_MAX_OUTPUT],
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
