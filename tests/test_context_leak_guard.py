"""The conftest guard against leaked Flask contexts actually bites.

Release run 28 (2026-09-22) went red because one test pushed an app context
and never popped it; the failure surfaced dozens of files later in a test that
was innocent. ``tests/conftest.py::_no_leaked_flask_context`` moves the red to
the culprit and pops the leak so nothing downstream inherits it.

These tests run a tiny pytest session in a subprocess against a COPY of the
real conftest, so they exercise the fixture itself, not a description of it.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

CONFTEST = Path(__file__).with_name("conftest.py")

_PROBE = '''
import flask
import pytest
from flask import has_app_context, has_request_context

_app = flask.Flask("probe")


def test_a_leaks_an_app_context():
    _app.app_context().push()


def test_b_the_next_test_starts_clean():
    assert not has_app_context()


def test_c_leaks_a_request_context():
    _app.test_request_context("/").push()


def test_d_still_clean_after_a_request_leak():
    assert not has_request_context()
    assert not has_app_context()


def test_e_with_block_is_fine():
    with _app.app_context():
        assert has_app_context()


@pytest.fixture(scope="module")
def module_ctx():
    ctx = _app.app_context()
    ctx.push()
    yield
    ctx.pop()


def test_f_wider_scoped_context_is_not_a_leak(module_ctx):
    assert has_app_context()
'''


def _run(tmp_path):
    shutil.copy(CONFTEST, tmp_path / "conftest.py")
    (tmp_path / "test_probe.py").write_text(_PROBE)
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-rA",
         "-q", str(tmp_path / "test_probe.py")],
        cwd=tmp_path, capture_output=True, text=True, timeout=120,
    )
    return proc.stdout + proc.stderr


def _outcome(out, name):
    """Every -rA summary verdict for one probe test. A test whose teardown
    fails is listed twice (PASSED for the call, ERROR for the teardown)."""
    rx = re.compile(r"^(PASSED|FAILED|ERROR) \S*::%s\b" % re.escape(name))
    return {m.group(1) for m in map(rx.match, out.splitlines()) if m}


def test_the_leaking_test_is_the_one_that_goes_red(tmp_path):
    out = _run(tmp_path)
    assert "ERROR" in _outcome(out, "test_a_leaks_an_app_context"), out
    assert "ERROR" in _outcome(out, "test_c_leaks_a_request_context"), out
    assert "Flask context(s) pushed" in out, out


def test_the_leak_is_popped_so_the_next_test_is_not_a_victim(tmp_path):
    out = _run(tmp_path)
    assert _outcome(out, "test_b_the_next_test_starts_clean") == {"PASSED"}, out
    assert _outcome(out, "test_d_still_clean_after_a_request_leak") == {"PASSED"}, out


def test_balanced_and_wider_scoped_contexts_are_not_reported(tmp_path):
    out = _run(tmp_path)
    assert _outcome(out, "test_e_with_block_is_fine") == {"PASSED"}, out
    assert _outcome(out, "test_f_wider_scoped_context_is_not_a_leak") == {"PASSED"}, out
