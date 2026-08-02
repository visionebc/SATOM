"""Guards for the operator CLI's presentation layer.

Every test here defends a property that is invisible while it holds and
expensive the day it breaks:

* Through a pipe the output must be plain bytes. An operator redirects this
  tool into a ticket and greps it; escape sequences in that file are noise
  they cannot remove.
* The output path must never raise. A diagnostic tool that dies while PRINTING
  its diagnosis, on a node that is already broken, is worse than no tool.
  This regressed once already: an em dash in a title crashed the whole command
  under an ASCII stdout.
* 'show tree' renders the live registry, so it cannot drift from what the
  build actually supports — but only if nothing lets a node go unlisted.
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "deploy"))

from satom_cli import cmd_tree  # noqa: E402
from satom_cli import main as cli_main  # noqa: E402
from satom_cli import tree as cli_tree  # noqa: E402
from satom_cli.context import Ctx  # noqa: E402
from satom_cli.render import (_V_BAD, _V_OK, _V_WARN, Result, Style,  # noqa: E402
                              render, style_of)

ANSI = re.compile(r"\x1b\[[0-9;]*m")

# Commands that touch nothing and finish fast — safe to run in a test.
SAFE = (["show", "tree"], ["show", "tree", "--commands"], ["show", "paths"],
        ["show", "ports"], ["?"], ["execute", "?"])


def _run(args, env=None, encoding_ascii=False):
    e = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    e.update(env or {})
    if encoding_ascii:
        e["PYTHONIOENCODING"] = "ascii"
    code = ("import sys; sys.path.insert(0, %r);"
            "from satom_cli.main import main; sys.exit(main())" % str(REPO / "deploy"))
    return subprocess.run([sys.executable, "-c", code] + args,
                          capture_output=True, text=True, env=e, cwd="/")


class _Ctx:
    """Minimal render context; Ctx() itself probes the node."""

    def __init__(self, json_mode=False, **style):
        self.json_mode = json_mode
        self.style = Style(**style)


# -- the pipe contract ----------------------------------------------------
@pytest.mark.parametrize("args", SAFE, ids=lambda a: " ".join(a))
def test_piped_output_carries_no_escape_sequences(args):
    out = _run(args)
    assert not ANSI.search(out.stdout), (
        "%s emitted colour through a pipe. Decoration is for a TTY; an "
        "operator redirects this into a ticket." % " ".join(args))


def test_json_mode_is_never_decorated_and_parses():
    out = _run(["show", "tree", "execute", "reload", "--json"])
    assert not ANSI.search(out.stdout)
    payload = json.loads(out.stdout)
    assert payload["data"]["tree"]["children"]["nginx"]["needs_root"] is True


def test_force_colour_flag_still_produces_plain_json():
    """--json is a machine contract; --color must not be able to poison it."""
    out = _run(["show", "tree", "--depth", "1", "--json", "--color"])
    assert not ANSI.search(out.stdout)
    json.loads(out.stdout)


def test_no_color_env_is_honoured():
    r = Result("ok", "t").rows("h", [("k", "pass")])
    lit = _render(_Ctx(color=True))
    assert ANSI.search(lit)
    os.environ["NO_COLOR"] = "1"
    try:
        plain = _render(_Ctx())
    finally:
        del os.environ["NO_COLOR"]
    assert not ANSI.search(plain)


def _render(ctx):
    import io
    import contextlib
    r = Result("ok", "title").rows("head", [("key", "pass")])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render(r, ctx)
    return buf.getvalue()


# -- the output path must not raise --------------------------------------
@pytest.mark.parametrize("args", SAFE, ids=lambda a: " ".join(a))
def test_ascii_stdout_never_crashes_the_command(args):
    """A serial console with an ASCII stdout is a normal recovery setting."""
    out = _run(args, encoding_ascii=True)
    assert "UnicodeEncodeError" not in out.stderr, out.stderr[-800:]
    assert out.returncode in (0, 1), out.stderr[-800:]


def test_unencodable_content_degrades_instead_of_raising():
    """Characters outside the fold table (a device name, a cert subject)."""
    import io
    import contextlib
    from satom_cli.render import harden_stream
    r = Result("ok", "device 中文 — ok").rows("x", [("n", "café")])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        harden_stream()          # must be a no-op on a StringIO, not a crash
        rc = render(r, _Ctx(color=False, ascii_only=True))
    assert rc == 0
    assert "—" not in buf.getvalue(), "the em dash should have been folded"


def test_harden_stream_survives_a_character_the_fold_table_does_not_know():
    """The SECOND layer, exercised on a real ASCII stdout.

    _FOLD covers the typography this code emits. This covers what it cannot
    know about: a device name, a certificate subject, a journal line. Without
    the reconfigure the print raises UnicodeEncodeError and the diagnostic dies
    while reporting the diagnosis.
    """
    code = ("import sys; sys.path.insert(0, %r);"
            "from satom_cli.render import harden_stream;"
            "harden_stream();"
            "print('device \u4e2d\u6587 caf\u00e9');"
            "print('SURVIVED')" % str(REPO / "deploy"))
    e = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    e["PYTHONIOENCODING"] = "ascii"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, env=e, cwd="/")
    assert "SURVIVED" in out.stdout, out.stderr[-500:]
    assert "UnicodeEncodeError" not in out.stderr


# -- 'show tree' must describe the real registry -------------------------
def test_tree_lists_every_runnable_command_in_the_registry():
    """A hand-maintained command list goes stale; this one must not be able to."""
    expected = {path for path, node in cli_tree.walk()
                if node.run is not None and not node.children}
    out = _run(["show", "tree", "--commands"])
    listed = set()
    for raw in out.stdout.splitlines():
        line = raw.strip()          # render indents body lines by two spaces
        if line.startswith("satom "):
            body = line[len("satom "):]
            # strip the mark column and the help text
            listed.add(tuple(body.split("  ")[0].split()))
    missing = expected - listed
    assert not missing, "not listed by 'show tree --commands': %s" % sorted(missing)


def test_tree_counts_match_the_registry():
    out = json.loads(_run(["show", "tree", "--json"]).stdout)
    runnable = sum(1 for _, n in cli_tree.walk()
                   if n.run is not None and not n.children)
    assert out["data"]["commands"] == runnable


def test_top_level_tree_is_the_same_handler_as_show_tree():
    """An alias, not a second implementation."""
    assert cli_tree.ROOT.children["tree"].run is cmd_tree.tree
    assert cli_tree.ROOT.children["show"].children["tree"].run is cmd_tree.tree


def test_tree_rejects_an_unknown_branch_with_usage_not_a_crash():
    out = _run(["show", "tree", "nosuchthing"])
    assert out.returncode == 2, out.stdout
    assert "no such command" in out.stdout


# -- truncation is a TTY affordance, never a pipe one ---------------------
LONG = "Recreate venv/ from requirements.txt. Needs --yes; keeps a freeze to roll back to."


def test_piped_tree_keeps_the_whole_help_text():
    out = _run(["show", "tree", "execute", "reinstall"])
    assert LONG in out.stdout, (
        "help was truncated through a pipe; there is no width to fit and the "
        "operator loses text they cannot recover")


def test_narrow_width_truncates_so_the_tree_stays_aligned():
    out = _run(["show", "tree", "execute", "reinstall", "--width", "80", "--color"])
    plain = ANSI.sub("", out.stdout)
    assert LONG not in plain
    assert "..." in plain or "…" in plain
    for line in plain.splitlines():
        assert len(line) <= 80, "line overflows the requested width: %r" % line


# -- colour semantics -----------------------------------------------------
STATE_WORDS = ("active", "inactive", "enabled", "disabled", "dead", "running")


@pytest.mark.parametrize("word", STATE_WORDS)
def test_state_words_are_never_painted_as_verdicts(word):
    """A state is not a verdict.

    satom-ha-datasync is 'inactive' on the primary BY DESIGN. Painting that red
    is the same false positive that had to be removed from 'get system health':
    a check that always complains is a check that gets ignored, and so is a
    colour that always complains.
    """
    assert word not in _V_OK | _V_WARN | _V_BAD
    import io
    import contextlib
    r = Result("ok", "t").rows("h", [("unit", word)])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render(r, _Ctx(color=True))
    body = [l for l in buf.getvalue().splitlines() if word in l][0]
    assert "\x1b[32m" not in body and "\x1b[31m" not in body, (
        "%r was painted as a verdict" % word)


def test_verdict_words_are_painted():
    import io
    import contextlib
    r = Result("ok", "t").rows("h", [("a", "pass"), ("b", "FAIL"), ("c", "WARN")])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render(r, _Ctx(color=True))
    text = buf.getvalue()
    assert "\x1b[32mpass" in text and "\x1b[31mFAIL" in text and "\x1b[33mWARN" in text


def test_blank_body_lines_carry_no_trailing_whitespace():
    import io
    import contextlib
    r = Result("ok", "t").lines("h", ["one", "", "two"])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render(r, _Ctx(color=False))
    assert "\n\n" in buf.getvalue()
    for line in buf.getvalue().splitlines():
        assert line == line.rstrip(), "trailing whitespace: %r" % line


# -- readline safety ------------------------------------------------------
def test_prompt_colour_is_bracketed_for_readline():
    """Unbracketed escapes make readline miscount the prompt width, and the
    cursor lands in the wrong column the moment the operator edits a line."""
    st = Style(color=True)
    frag = cli_main._prompt_color(st, "accent", "satom")
    assert frag.startswith("\001") and frag.endswith("\002")
    assert "\x1b[" in frag
    plain = cli_main._prompt_color(Style(color=False), "accent", "satom")
    assert plain == "satom"


def test_help_listing_does_not_dim_the_command_column():
    """In a command listing the key IS the actionable thing. Dimming both
    columns makes the whole table read as noise."""
    ctx = Ctx()
    ctx.style = Style(color=True)
    res = cli_main.help_for(cli_tree.ROOT, [], ctx)
    assert res.key_style.get(0) == "plain"
