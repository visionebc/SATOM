"""[SATOM-LOUD-READ] No installer prompt may die silently.

Found by running, not by reading: driving the installer through a pipe with one
answer short, `read` got EOF, returned !=0 and `set -euo pipefail` killed the
script WITHOUT PRINTING ANYTHING -- the last visible line was the previous step.
Same class as [SATOM-LOUD-DB]. See docs/safeguards.md 10f.
"""
import pathlib
import re
import subprocess
import textwrap

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "installers" / "install-satom.sh"


def _executed_lines(text):
    """Lines that are EXECUTED: no comments or prose."""
    return [
        s for s in (l.strip() for l in text.splitlines())
        if s and not s.startswith("#")
    ]


def _installer():
    return INSTALLER.read_text(encoding="utf-8")


def _extract(func, text):
    m = re.search(r"^%s\(\) \{.*?^\}$" % re.escape(func), text, re.M | re.S)
    assert m, "function %s() not found" % func
    return m.group(0)


# ---------------------------------------------------------------- structural
def test_no_prompt_bypasses_the_loud_helpers():
    """A bare prompt `read` reintroduces the silent death.

    This is the guard that does not age: when adding a new prompt the author has
    to go through ask/ask_secret, or the suite fails. Checked against the
    EXECUTED lines -- the helper's own comment talks about `read` and would match.
    """
    raw = []
    for line in _executed_lines(_installer()):
        if not re.match(r"read -r[sp]", line):
            continue
        # The two `read`s that live INSIDE ask/ask_secret are the legitimate ones.
        if '"$__p" "$__v"' in line:
            continue
        raw.append(line)
    assert not raw, "prompts that bypass ask/ask_secret: %r" % raw


def test_every_prompt_goes_through_a_helper():
    """And that there actually are prompts (otherwise the previous test is vacuous)."""
    body = _installer()
    assert len(re.findall(r"^\s*ask ", body, re.M)) >= 8
    assert len(re.findall(r"^\s*ask_secret ", body, re.M)) >= 2


@pytest.mark.parametrize("func", ["ask", "ask_secret"])
def test_helper_reports_the_failure(func):
    """The helper has to SAY which prompt was left unanswered."""
    src = _extract(func, _installer())
    assert "_ask_die" in src, "%s() does not report the failure" % func
    assert "__rc" in src, "%s() does not look at read's exit code" % func


def test_the_error_names_the_prompt():
    src = _extract("_ask_die", _installer())
    # CAREFUL: in the shell it is escaped (\\"$1\\"), so an assertion on the
    # quoted form does NOT match. That it QUOTES the prompt is really proven by
    # test_eof_dies_loudly_not_silently, looking for it in the REAL stderr.
    assert "$1" in src, "the message does not interpolate the prompt that failed"
    assert "die " in src, "_ask_die does not abort"


# ---------------------------------------------------------------- functional
def _harness(tmp_path):
    """Builds a script with the installer's REAL code, not with a copy."""
    body = _installer()
    h = tmp_path / "h.sh"
    h.write_text(
        "set -euo pipefail\n"
        "INSTALL_LOG=/dev/null; c_red=; c_off=\n"
        'die() { echo "ERROR: $*" >&2; exit 1; }\n'
        + _extract("_ask_die", body) + "\n"
        + _extract("ask", body) + "\n"
        + _extract("ask_secret", body) + "\n",
        encoding="utf-8",
    )
    return h


def _run(h, stdin, call):
    return subprocess.run(
        ["bash", "-c", "source %s; %s" % (h, call)],
        input=stdin, capture_output=True, text=True,
    )


@pytest.mark.parametrize("call", ["ask V 'P: '", "ask_secret V 'P: '"])
def test_eof_dies_loudly_not_silently(tmp_path, call):
    """THE BUG: input exhausted -> rc!=0 and ZERO output. Now it has to speak."""
    r = _run(_harness(tmp_path), "", call)
    assert r.returncode != 0, "should abort"
    assert r.stderr.strip(), "died silently -- the bug is back"
    assert "P: " in r.stderr, "does not say which prompt it was: %r" % r.stderr


def test_partial_line_without_newline_is_a_valid_answer(tmp_path):
    """Ctrl-D after typing: `read` returns !=0 but there IS an answer."""
    r = _run(_harness(tmp_path), "partial", "ask V 'P: '; echo GOT=$V")
    assert r.returncode == 0, r.stderr
    assert "GOT=partial" in r.stdout


def test_normal_input_still_works(tmp_path):
    r = _run(_harness(tmp_path), "normal\n", "ask V 'P: '; echo GOT=$V")
    assert r.returncode == 0, r.stderr
    assert "GOT=normal" in r.stdout


def test_raw_read_is_the_silent_failure_we_are_preventing():
    """Anchors the OPPOSITE behaviour: without the helper, it dies mute.

    Without this, narrowing helper and test at the same time would leave them
    self-consistent.
    """
    r = subprocess.run(
        ["bash", "-c", 'set -euo pipefail; read -rp "P: " V; echo GOT=$V'],
        input="", capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert r.stderr.strip() == "", "broken premise: the raw read did speak"
