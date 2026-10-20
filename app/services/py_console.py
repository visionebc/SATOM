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
  * only ``/usr`` (+ the host /bin /sbin /lib /lib64, read-only), ``/proc``, ``/dev`` and a fresh
                          ``tmpfs /tmp`` are mounted. ``/opt/satom``
                          (the ``.env``, the DB, the keyring, the code) is NOT
                          bound, so a script literally cannot open a secret or
                          write app state.
  * the workdir (harness + script + the read-only data bundle) is bound
                          READ-ONLY at ``/sandbox``.
  * wall-clock (``timeout``), CPU, address-space and process-count caps
                          (``prlimit``) stop infinite loops / fork bombs /
                          memory bombs.
  * NOTHING is writable (2026-10-20): bwrap's own root and ``/dev`` are
                          remounted read-only and there is no ``/tmp``. Both
                          were tmpfs as large as half the host's RAM, and a
                          file written there is memory no RLIMIT_AS counts --
                          the console runs inside the web service, next to
                          gunicorn, with Postgres on the same node.
  * RLIMIT_NPROC counts every task of the satom uid on the node (measured:
                          ``--nproc=16`` stopped bwrap itself with 26 satom
                          tasks running), so the cap is set per run to the
                          tasks satom has NOW plus :data:`_EXTRA_TASKS`.
  * the output is read as it comes and kept up to :data:`_MAX_OUTPUT`;
                          ONE run at a time per node (``_LOCK_PATH``).

The ``data`` bundle handed to the script is built by the CALLER via
``plugin_sandbox.load_datasets`` (the same masked, SELECT-only, curated path the
plugins use). The sandbox never touches the DB itself — it only receives a JSON
snapshot. A script can therefore transform/report on curated fleet data and
nothing else.

Verified live on LXC 248: bwrap 0.8.0 sandboxes correctly as the service user
``fortinet`` (uid 999), .env unreadable, network blocked.
"""
from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any

from .sandbox import root_dirs_argv

# Absolute isolation caps (defence in depth; the hard guarantees are the
# namespaces + the minimal bind set — these just stop resource exhaustion).
_MEM_BYTES = 512 * 1024 * 1024       # 512 MiB address space per process (RLIMIT_AS)
#: Tasks the run may add to what the satom uid already has: bwrap (2) and
#: the interpreter, plus a little room. Threads are tasks too.
_EXTRA_TASKS = 6
_MAX_FSIZE = 16 * 1024 * 1024        # 16 MiB any single file (nothing is writable anyway)
_MAX_NOFILE = 128
_MAX_OUTPUT = 200_000                # cap captured stdout/stderr (bytes, each)
_LOCK_PATH = os.path.join(tempfile.gettempdir(), "satom-py-console.lock")
_LOCK_WAIT_S = 5.0
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
        *root_dirs_argv(),
        "--proc", "/proc",
        "--dev", "/dev",
        "--ro-bind", workdir, "/sandbox",
        "--remount-ro", "/",
        "--remount-ro", "/dev",
        "--chdir", "/sandbox",
        "/usr/bin/python3", "-I", "-B", "/sandbox/harness.py",
    ]


def _uid_tasks(uid: int | None = None) -> int:
    """Tasks (threads included) the uid owns right now -- what RLIMIT_NPROC
    counts."""
    uid = os.getuid() if uid is None else uid
    n = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open("/proc/%s/status" % pid, encoding="ascii", errors="replace") as fh:
                real, threads = None, 1
                for line in fh:
                    if line.startswith("Uid:"):
                        real = int(line.split()[1])
                    elif line.startswith("Threads:"):
                        threads = int(line.split()[1])
                        break
        except (OSError, ValueError, IndexError):
            continue
        if real == uid:
            n += threads
    return n


def _read_capped(stream, limit: int, out: list) -> None:
    kept = 0
    try:
        while True:
            chunk = stream.read1(65536)
            if not chunk:
                break
            if kept < limit:
                out.append(chunk[: limit - kept])
                kept += len(out[-1])
    except (OSError, ValueError):
        pass


class Busy(RuntimeError):
    """Another console run holds the node's slot."""


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

    lock = open(_LOCK_PATH, "a+")
    deadline = time.monotonic() + _LOCK_WAIT_S
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except OSError:
            if time.monotonic() > deadline:
                lock.close()
                return {"ok": False, "returncode": None, "timed_out": False,
                        "duration_ms": 0, "stdout": "",
                        "stderr": "the console is busy: another run is in progress on "
                                  "this node (one at a time). Try again in a moment."}
            time.sleep(0.2)
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
            f"--nproc={_uid_tasks() + _EXTRA_TASKS}",
            f"--fsize={_MAX_FSIZE}",
            f"--nofile={_MAX_NOFILE}",
            "--core=0",
            "--",
        ] + _bwrap_argv(workdir)

        started = time.monotonic()
        timed_out = False
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        bufs: tuple[list, list] = ([], [])
        readers = [threading.Thread(target=_read_capped, args=(st, _MAX_OUTPUT, b),
                                    daemon=True)
                   for st, b in ((proc.stdout, bufs[0]), (proc.stderr, bufs[1]))]
        for t in readers:
            t.start()
        try:
            rc: int | None = proc.wait(timeout=timeout + 6)  # backstop beyond `timeout`
        except subprocess.TimeoutExpired:
            timed_out = True
            rc = None
            try:
                os.killpg(proc.pid, 9)
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        for t in readers:
            t.join(5)
        out = b"".join(bufs[0]).decode("utf-8", "replace")
        err = b"".join(bufs[1]).decode("utf-8", "replace")
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
        try:
            fcntl.flock(lock, fcntl.LOCK_UN)
        finally:
            lock.close()
