"""Security contract for the sandboxed Python console (services.py_console).

Route B: the admin runs ARBITRARY Python, but inside a bubblewrap sandbox that
  * cannot see /opt/ofortmaut/.env or any secret file,
  * inherits NO environment variables (--clearenv) -> FERNET_KEY/DB creds gone,
  * has no network namespace (no exfiltration),
  * is wall-clock + CPU + memory + proc capped,
  * gets ONLY the curated read-only ``data`` bundle the caller passes in.

These tests ARE the security guarantee. If any of them starts passing WITHOUT
the sandbox actually enforcing it, the feature is unsafe -- do not ship.

Requires bubblewrap (bwrap); skipped otherwise.
"""
from __future__ import annotations

import shutil
import pytest

from app.services import py_console

pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="bubblewrap not installed")

BUNDLE = {
    "fleet_appliances": {
        "columns": ["id", "name"],
        "rows": [{"id": 1, "name": "fw1"}, {"id": 2, "name": "fw2"}],
    }
}


def run(src, bundle=None, **kw):
    b = BUNDLE if bundle is None else bundle
    return py_console.run_python(src, b, **kw)


def test_happy_path_reads_bundle_and_captures_stdout():
    r = run("print('rows=', len(data['fleet_appliances']['rows']))")
    assert r["ok"] is True
    assert r["returncode"] == 0
    assert "rows= 2" in r["stdout"]
    assert r["timed_out"] is False


def test_cannot_read_env_secret_file():
    r = run("import os; print('exists=', os.path.exists('/opt/ofortmaut/.env'))")
    assert "exists= False" in r["stdout"]


def test_environment_is_cleared_no_secrets():
    r = run(
        "import os\n"
        "for k in ('FERNET_KEY', 'DATABASE_URL', 'SECRET_KEY', 'SQLALCHEMY_DATABASE_URI'):\n"
        "    print(k, '=', repr(os.environ.get(k)))\n"
    )
    assert "FERNET_KEY = None" in r["stdout"]
    assert "DATABASE_URL = None" in r["stdout"]
    assert "SECRET_KEY = None" in r["stdout"]


def test_network_is_blocked():
    src = (
        "import socket\n"
        "try:\n"
        "    s = socket.create_connection(('192.0.2.34', 22), timeout=3)\n"
        "    print('NET_OPEN'); s.close()\n"
        "except Exception as e:\n"
        "    print('NET_BLOCKED', type(e).__name__)\n"
    )
    r = run(src)
    assert "NET_BLOCKED" in r["stdout"]
    assert "NET_OPEN" not in r["stdout"]


def test_cannot_write_outside_sandbox():
    src = (
        "try:\n"
        "    open('/opt/ofortmaut/pwned.txt', 'w').write('x')\n"
        "    print('WROTE')\n"
        "except Exception as e:\n"
        "    print('WRITE_BLOCKED', type(e).__name__)\n"
    )
    r = run(src)
    assert "WROTE" not in r["stdout"]
    assert "WRITE_BLOCKED" in r["stdout"]


def test_infinite_loop_times_out():
    r = run("while True:\n    pass\n", timeout=3)
    assert r["timed_out"] is True
    assert r["ok"] is False
    assert r["duration_ms"] <= 9000  # bounded, not runaway


def test_memory_is_capped():
    r = run("x = bytearray(4 * 1024**3)\nprint('ALLOCATED', len(x))", timeout=6)
    assert "ALLOCATED" not in r["stdout"]
    assert r["ok"] is False


def test_only_declared_bundle_is_present():
    r = run("print(sorted(data.keys()))")
    assert "['fleet_appliances']" in r["stdout"]


def test_syntax_error_is_reported_not_raised():
    r = run("this is not valid python !!!")
    assert r["ok"] is False
    assert r["returncode"] != 0
    assert "SyntaxError" in r["stderr"]


def test_runtime_traceback_goes_to_stderr():
    r = run("raise ValueError('boom-42')")
    assert r["ok"] is False
    assert "ValueError" in r["stderr"]
    assert "boom-42" in r["stderr"]
