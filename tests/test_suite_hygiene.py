"""Guards for the suite's own plumbing: temp-root cleanup and the shard runner.

Two things here have the same failure shape, and it is the shape this repo
keeps rediscovering: **nothing fails when they break.**

  * ``tests/conftest.py`` creates a temp root per pytest PROCESS. When nothing
    removed it, the suite stayed green for a week while leaving 2837 orphaned
    directories on the node. An inode leak announces itself only when the
    filesystem runs out of them.

  * ``scripts/run_test_shards.sh`` decides whether it is safe to start. If its
    concurrency guard mis-answers, the visible result is a *green* run — two
    contending suites whose numbers mean nothing.

So every assertion below is derived from the artefact (the source of the
conftest, the real filenames on disk, the actual behaviour of a launched
process), never from a list typed out here.
"""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CONFTEST = REPO / "tests" / "conftest.py"
RUNNER = REPO / "scripts" / "run_test_shards.sh"
PLANNER = REPO / "scripts" / "test_shard_plan.py"


# ---------------------------------------------------------------------------
# conftest temp-root cleanup
# ---------------------------------------------------------------------------
def _module_level_mkdtemp_targets(src: str) -> list[str]:
    """Names bound to a module-level ``tempfile.mkdtemp(...)`` call."""
    tree = ast.parse(src)
    names: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        fn = node.value.func
        attr = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
        if attr != "mkdtemp":
            continue
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                names.append(tgt.id)
    return names


def _atexit_cleaned_names(src: str) -> set[str]:
    """Names passed to ``shutil.rmtree`` inside an atexit-registered function."""
    tree = ast.parse(src)
    cleaned: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        registered = any(
            (isinstance(d, ast.Attribute) and d.attr == "register")
            or (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                and d.func.attr == "register")
            for d in node.decorator_list
        )
        if not registered:
            continue
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            fn = sub.func
            if getattr(fn, "attr", "") != "rmtree":
                continue
            for arg in sub.args:
                if isinstance(arg, ast.Name):
                    cleaned.add(arg.id)
    return cleaned


def test_every_module_level_mkdtemp_in_conftest_is_registered_for_cleanup():
    """Derived from the conftest's own AST, so a SECOND mkdtemp breaks this."""
    src = CONFTEST.read_text(encoding="utf-8")
    targets = _module_level_mkdtemp_targets(src)
    assert targets, "conftest no longer creates a module-level temp root — " \
                    "if that is intentional, delete this guard deliberately"
    cleaned = _atexit_cleaned_names(src)
    missing = [t for t in targets if t not in cleaned]
    assert not missing, (
        f"module-level mkdtemp target(s) {missing} are never removed. Every "
        f"pytest process would leak one directory; sharding multiplies that "
        f"by the shard count."
    )


def test_the_temp_root_is_actually_gone_after_the_interpreter_exits(tmp_path):
    """The behavioural half: import conftest in a real child and watch it tidy.

    The AST guard above proves the code is *written*; only this proves it
    *works*. Both are needed — a decorator that silently fails to register
    would satisfy the first one alone.
    """
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import importlib.util, json, os, sys\n"
        f"spec = importlib.util.spec_from_file_location('cf', {str(CONFTEST)!r})\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(mod)\n"
        "print(json.dumps({'tmpdir': mod._TMPDIR, "
        "'existed': os.path.isdir(mod._TMPDIR)}))\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(probe)], cwd=str(REPO),
        capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, f"probe failed: {proc.stderr[-2000:]}"
    payload = json.loads(proc.stdout.strip().splitlines()[-1])

    assert payload["existed"], "conftest did not create its temp root at all"
    assert not os.path.isdir(payload["tmpdir"]), (
        f"{payload['tmpdir']} survived the interpreter exit — the atexit "
        f"cleanup did not run"
    )


def test_cleanup_survives_a_temp_root_that_is_already_gone(tmp_path):
    """A cleanup that raises would turn a green run red at the very last step."""
    probe = tmp_path / "probe2.py"
    probe.write_text(
        "import importlib.util, shutil, sys\n"
        f"spec = importlib.util.spec_from_file_location('cf', {str(CONFTEST)!r})\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(mod)\n"
        "shutil.rmtree(mod._TMPDIR)  # pull the rug out before atexit runs\n"
        "print('ok')\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(probe)], cwd=str(REPO),
        capture_output=True, text=True, timeout=180,
    )
    # The exit code is NOT enough: CPython prints an exception raised inside an
    # atexit hook to stderr and still exits 0, so a returncode assertion alone
    # passes while every run ends in a traceback. Measured, not assumed.
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "atexit" not in proc.stderr and "Traceback" not in proc.stderr, (
        f"the atexit cleanup raised when its directory was already gone — "
        f"every run would end with a traceback on stderr:\n{proc.stderr[-2000:]}"
    )


# ---------------------------------------------------------------------------
# shard planner
# ---------------------------------------------------------------------------
def _plan(tmp_path: Path, shards: int, *extra: str) -> tuple[int, str, list[Path]]:
    out = tmp_path / f"n{shards}"
    proc = subprocess.run(
        [sys.executable, str(PLANNER), "-n", str(shards),
         "--tests-dir", str(REPO / "tests"), "--out", str(out), *extra],
        capture_output=True, text=True, timeout=300,
    )
    manifests = sorted(out.glob("shard*.txt")) if out.is_dir() else []
    return proc.returncode, proc.stdout + proc.stderr, manifests


@pytest.mark.parametrize("shards", [2, 3, 4])
def test_the_partition_is_a_partition_of_the_files_on_disk(tmp_path, shards):
    """Union == every test file, and no file in two shards.

    A dropped file produces a GREEN run that never executed those tests. That
    is the single worst thing this tool could do, so it is checked against the
    real directory listing rather than a recorded count.
    """
    rc, out, manifests = _plan(tmp_path, shards)
    assert rc == 0, out
    assert len(manifests) == shards

    placed: list[str] = []
    for m in manifests:
        placed += [ln.strip() for ln in m.read_text().splitlines() if ln.strip()]

    on_disk = {f"tests/{p.name}" for p in (REPO / "tests").glob("test_*.py")}
    assert len(placed) == len(set(placed)), "a file was placed in two shards"
    assert set(placed) == on_disk, (
        f"partition != files on disk; missing={sorted(on_disk - set(placed))} "
        f"extra={sorted(set(placed) - on_disk)}"
    )


def test_the_split_is_balanced(tmp_path):
    rc, out, manifests = _plan(tmp_path, 3)
    assert rc == 0, out
    devs = [float(m.group(1))
            for m in re.finditer(r"([+-]\d+\.\d+)% from ideal", out)]
    assert len(devs) == 3, out
    assert max(abs(d) for d in devs) < 5.0, f"unbalanced split: {devs}\n{out}"


def test_measured_durations_change_the_split(tmp_path):
    """Proves the --durations path is wired, not dead code.

    A synthetic log makes one file enormously expensive; a weighting that
    ignored it would produce the same partition as the AST proxy.
    """
    names = sorted(p.name for p in (REPO / "tests").glob("test_*.py"))
    heavy = names[0]
    log = tmp_path / "shard1.log"
    log.write_text(
        "\n".join(f"9999.00s call tests/{heavy}::test_{i}" for i in range(5))
        + "\n" + "\n".join(f"0.01s call tests/{n}::test_x" for n in names[1:]),
        encoding="utf-8",
    )
    rc, out, manifests = _plan(tmp_path, 3, "--durations", str(log))
    assert rc == 0, out
    assert "measured seconds" in out, out

    # The single monstrous file must end up alone-ish: its shard should hold
    # far fewer files than the others, because it already fills the bin.
    sizes = sorted(len(m.read_text().splitlines()) for m in manifests)
    assert sizes[0] < sizes[-1] / 2, (
        f"the measured weighting did not dominate the split: {sizes}\n{out}"
    )


# ---------------------------------------------------------------------------
# shard runner
# ---------------------------------------------------------------------------
def test_runner_is_executable_and_refuses_to_run_unprivileged():
    """Executed for real, not read. The suite runs as a non-root user."""
    assert RUNNER.is_file(), f"{RUNNER} is missing"
    assert os.access(RUNNER, os.X_OK), f"{RUNNER} is not executable"
    if os.geteuid() == 0:
        pytest.skip("must be run as a non-root user to observe the refusal")
    proc = subprocess.run([str(RUNNER), "3"], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 2, (
        f"expected rc 2 for a non-root caller, got {proc.returncode}\n"
        f"{proc.stdout}{proc.stderr}"
    )
    assert "runuser" in (proc.stdout + proc.stderr)


@pytest.mark.parametrize("bad", ["0", "5", "abc", ""])
def test_runner_rejects_impossible_shard_counts(bad):
    """1..4 on a 4 vCPU box. Above that the OOM killer decides the result.

    Asserted on the MESSAGE, not just on rc 2: an unprivileged caller is also
    refused with rc 2, so the code alone cannot tell "bad argument" from
    "not root" and this test would pass with the validation deleted.
    """
    proc = subprocess.run([str(RUNNER), bad], capture_output=True,
                          text=True, timeout=60)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, f"{bad!r} was not rejected: {proc.returncode}\n{out}"
    assert "shard count must be" in out, (
        f"{bad!r} was rejected for the wrong reason — the argument check did "
        f"not run:\n{out}"
    )


def _extract_bash_function(name: str) -> str:
    src = RUNNER.read_text(encoding="utf-8")
    m = re.search(rf"^{name}\(\) \{{.*?^\}}", src, re.S | re.M)
    assert m, f"{name}() not found in {RUNNER}"
    return m.group(0)


def _is_real_pytest(pid: int) -> bool:
    """Call the runner's own is_real_pytest() against a live PID."""
    fn = _extract_bash_function("is_real_pytest")
    proc = subprocess.run(
        ["bash", "-c", f'{fn}\nis_real_pytest "$1"', "_", str(pid)],
        capture_output=True, text=True, timeout=30,
    )
    return proc.returncode == 0


def test_guard_ignores_a_process_that_merely_mentions_pytest():
    """The trap that has bitten this node twice, reproduced.

    ``pgrep -f '[p]ytest'`` returns any process whose command line carries the
    word — a log path, an echo, a comment. The bracket trick only stops the
    pattern from matching itself. Only argv parsing tells them apart.
    """
    # Two commands, deliberately: with a single one bash's last-command
    # optimisation execs straight into `sleep`, replacing argv and destroying
    # the very mention this test is about.
    decoy = subprocess.Popen(
        ["bash", "-c", "sleep 60  # this comment mentions pytest on purpose\nexit 0"]
    )
    try:
        time.sleep(0.3)
        assert "pytest" in Path(f"/proc/{decoy.pid}/cmdline").read_bytes() \
            .replace(b"\0", b" ").decode(), "decoy did not keep its argv"
        assert not _is_real_pytest(decoy.pid), (
            "the guard accepted a decoy that only MENTIONS pytest — it would "
            "refuse to start while nothing was running"
        )
    finally:
        decoy.send_signal(signal.SIGKILL)
        decoy.wait(timeout=10)


def test_guard_recognises_a_pytest_launcher_argv0():
    """The other half: a guard that never fires is not a guard.

    ``exec -a`` gives the child pytest's argv[0] without running pytest — two
    concurrent pytest processes on this tree are exactly what must never
    happen, including from inside a test.
    """
    real = subprocess.Popen(["bash", "-c", "exec -a pytest sleep 60"])
    try:
        time.sleep(0.3)
        assert _is_real_pytest(real.pid), (
            "the guard failed to recognise a pytest argv[0] — two suites could "
            "then run at once and invalidate both"
        )
    finally:
        real.send_signal(signal.SIGKILL)
        real.wait(timeout=10)


def test_guard_recognises_the_dash_m_pytest_form():
    """The form that ACTUALLY runs here, and the one argv[0] cannot catch.

    Every real invocation in this repo is ``venv/bin/python3 -m pytest``, whose
    argv[0] is *python3*. Covering only the argv[0] branch leaves the branch
    that matters permanently unexercised — which is exactly how this guard
    passed while the ``-m pytest`` rule was deleted.

    Built with ``exec -a`` again so nothing here launches a second pytest:
    argv[0] is python3 and the positional parameters supply the adjacent
    ``-m`` ``pytest`` pair.
    """
    real = subprocess.Popen(
        ["bash", "-c", "exec -a python3 bash -c 'sleep 60\nexit 0' -m pytest"]
    )
    try:
        time.sleep(0.3)
        argv = Path(f"/proc/{real.pid}/cmdline").read_bytes().split(b"\0")
        assert b"-m" in argv and b"pytest" in argv, f"decoy argv wrong: {argv}"
        assert argv[0].split(b"/")[-1] != b"pytest", (
            "this probe must NOT be catchable by the argv[0] rule, or it does "
            "not test the -m branch at all"
        )
        assert _is_real_pytest(real.pid), (
            "the guard missed the `python -m pytest` form — the only form this "
            "repo actually launches"
        )
    finally:
        real.send_signal(signal.SIGKILL)
        real.wait(timeout=10)


def test_aggregation_is_by_exit_code_and_treats_4_and_5_as_errors():
    """rc 4 (usage error) and rc 5 (no tests collected) are NOT passes.

    A manifest that names a renamed file collects nothing and exits 5. Read as
    "not failed", that is a shard reporting success for running no tests.
    """
    src = RUNNER.read_text(encoding="utf-8")
    body = re.search(r"^rc_label\(\) \{.*?^\}", src, re.S | re.M)
    assert body, "rc_label() not found"
    labels = body.group(0)
    for code in ("4", "5", "137"):
        m = re.search(rf"^\s*{code}\)\s*echo\s+\"(?P<label>[^\"]+)\"", labels, re.M)
        assert m, f"exit code {code} is unclassified — it would read as 'unexpected'"
        assert m.group("label").startswith("ERROR"), (
            f"exit code {code} is not classified as an error: {m.group('label')!r}"
        )
    assert re.search(r"^\s*0\)\s*echo\s+\"PASS", labels, re.M)


def test_runner_never_decides_the_result_by_grepping_the_log():
    """-q output truncates, a crashed shard prints no summary, and the string
    "0 failed" appears inside perfectly failing output. Exit codes only."""
    src = RUNNER.read_text(encoding="utf-8")
    # Strip comments first: the comment that EXPLAINS this rule necessarily
    # contains the words it forbids. (Seventh time in this repo that an
    # assertion answered itself with its own commentary.)
    code = "\n".join(ln for ln in src.splitlines()
                     if not ln.lstrip().startswith("#"))
    for forbidden in ("grep -c passed", 'grep "passed"', "grep -q failed"):
        assert forbidden not in code, f"result derived from log text: {forbidden}"
    assert 'SHARD_RC[$i]=$?' in code, "shard exit codes are not captured"


def test_planner_and_runner_are_owned_by_the_repo_not_by_scratch():
    """They lived in /var/tmp, which is wiped. A tool nobody can find again is
    a tool that gets rewritten from scratch, differently, next time."""
    assert PLANNER.is_file() and RUNNER.is_file()
    for p in (PLANNER, RUNNER):
        assert not str(p).startswith("/var/tmp"), p
