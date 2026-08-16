"""Every ``satom …`` an operator is told to run must exist.

``tests/test_docs_publication.py`` already holds ``docs/cli.md`` to the live
command tree. Nothing held the two surfaces an operator is far more likely to
act on: **the manual**, and **the product's own pages**.

The gap was not theoretical. The API-versions page shipped telling the operator
to run ``satom api preflight <appliance> <object> <field>…``. There is no
``satom api`` — the real command is ``satom get api preflight`` — so following
the page's own instruction exits 2, *unknown command*. Nothing failed: the page
rendered, the tests passed, the CLI worked, and only the operator holding a
broken node at 3 a.m. found out. That is the same shape as every other guard in
this file's neighbourhood: **the artifact stays well-formed and the claim
quietly becomes false.**

Two decisions worth stating, because both were arrived at by measuring rather
than guessing:

* **Anchoring, not matching.** A naive ``satom <word>`` scan over the tree
  reports 14 hits and 12 of them are prose: ``/opt/satom/venv``,
  ``sudo -u satom ssh``, ``systemctl status satom satom-scheduler``,
  ``git -C /opt/satom remote set-url``. A guard whose output is mostly noise is
  a guard that gets an ``xfail``. A candidate is only an invocation when it sits
  at a place a command can start — a code fence, a shell prompt, a backtick, an
  HTML tag boundary — and is not preceded by a path separator.
* **Extra tokens after a leaf are arguments, not commands.**
  ``satom get device config fortiweb09`` must pass. Resolution therefore stops
  at the first leaf; only a *group* is entitled to reject an unknown child.
"""
from __future__ import annotations

import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.join(ROOT, "deploy") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "deploy"))

from satom_cli import tree as cli_tree  # noqa: E402

# The surfaces this guard owns. ``docs/cli.md`` is deliberately absent — it has
# its own generated-reference guard and adding it here would give one claim two
# owners, which is how the claim starts disagreeing with itself.
SCANNED = (
    ("docs", ("user-guide.md",)),
    ("app/templates", None),        # every template, recursively
)

# A command may start after: line start, a shell prompt, a backtick, or the end
# of an HTML tag. It may NOT start after a path separator ("/opt/satom/venv"),
# a hyphen, or another word ("status satom satom-scheduler").
_ANCHOR = r"(?:^|(?<=[`>])|(?<=^\$ )|(?<=\n\$ )|(?<=\n))"
CANDIDATE = re.compile(
    _ANCHOR + r"satom((?: [a-z][a-z0-9._-]*){1,6})", re.MULTILINE)


def _resolve(tokens):
    """(ok, reason) for a token path against the live tree."""
    node = cli_tree.ROOT
    for i, tok in enumerate(tokens):
        kids = dict(getattr(node, "children", None) or {})
        if not kids:
            return True, ""          # leaf reached — the rest are arguments
        if tok not in kids:
            prefix = " ".join(tokens[:i])
            return False, ("'satom %s' does not exist: %r is not a command under "
                           "'satom%s'" % (" ".join(tokens), tok,
                                          " " + prefix if prefix else ""))
        node = kids[tok]
    return True, ""


def _files():
    for base, names in SCANNED:
        d = os.path.join(ROOT, base)
        if names is not None:
            for n in names:
                p = os.path.join(d, n)
                if os.path.isfile(p):
                    yield p
            continue
        for dirpath, _dirs, files in os.walk(d):
            for fn in sorted(files):
                if fn.endswith((".html", ".md", ".txt")):
                    yield os.path.join(dirpath, fn)


def _invocations(text):
    """Yield (line_number, [tokens]) for every anchored invocation."""
    for m in CANDIDATE.finditer(text):
        yield text.count("\n", 0, m.start()) + 1, m.group(1).split()


def scan():
    """[(relpath, line, tokens, reason)] — the guard's whole finding set."""
    bad = []
    for path in _files():
        try:
            text = open(path, encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            continue
        for line, tokens in _invocations(text):
            ok, why = _resolve(tokens)
            if not ok:
                bad.append((os.path.relpath(path, ROOT), line, tokens, why))
    return bad


# ---------------------------------------------------------------------------
# the guard
# ---------------------------------------------------------------------------

def test_no_page_or_manual_tells_the_operator_to_run_a_command_that_does_not_exist():
    bad = scan()
    assert not bad, "\n".join(
        "%s:%d — %s" % (f, ln, why) for f, ln, _t, why in bad)


def test_the_api_versions_page_still_names_the_preflight_command_at_all():
    """The scan above proves the page names no *wrong* command. It cannot
    prove the page still names the *right* one — deleting the sentence would
    leave the scan perfectly green, and the operator with no way to learn the
    command exists. This is the half the scanner structurally cannot cover; a
    "no bad spelling" assertion here would be pure duplication of it.
    """
    page = open(os.path.join(ROOT, "app/templates/registry/versions.html"),
                encoding="utf-8").read()
    assert "satom get api preflight" in page


def test_scan_reports_a_bad_command_in_a_file_it_scans(tmp_path, monkeypatch):
    """Proves the finding path end-to-end, without waiting for the tree to be
    dirty. Without this, ``assert not bad`` is only ever exercised against an
    empty list — an assertion that has never once seen a finding is an
    assertion nobody has tested.
    """
    (tmp_path / "page.html").write_text(
        "<p>run <code>satom get apiversions</code> and "
        "<code>satom api preflight x y z</code></p>\n"
        "<p>the venv lives at /opt/satom/venv</p>", encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "SCANNED",
                        ((str(tmp_path), None),))
    monkeypatch.setattr(sys.modules[__name__], "ROOT", str(tmp_path))
    found = scan()
    assert len(found) == 2, found
    assert {tuple(t) for _f, _l, t, _w in found} == {
        ("get", "apiversions"), ("api", "preflight", "x", "y", "z")}
    assert all("does not exist" in w for *_x, w in found)


# ---------------------------------------------------------------------------
# the guard's own machinery — a scanner that finds nothing passes for the
# wrong reason, and one that finds everything gets disabled
# ---------------------------------------------------------------------------

def test_the_scanner_actually_reads_something():
    """A typo in SCANNED would make this suite green over zero bytes."""
    seen = list(_files())
    assert any(f.endswith("docs/user-guide.md") for f in seen)
    assert sum(1 for f in seen if f.endswith(".html")) > 50, len(seen)

    total = 0
    for f in seen:
        try:
            total += len(list(_invocations(open(f, encoding="utf-8").read())))
        except (OSError, UnicodeDecodeError):
            pass
    assert total > 20, "found %d invocations — the anchor is too strict" % total


@pytest.mark.parametrize("tokens,ok", [
    (["get", "api", "versions"], True),
    (["get", "api", "preflight"], True),
    (["get", "device", "config", "fortiweb09"], True),   # args after a leaf
    (["diagnose", "all"], True),
    (["api", "preflight"], False),                        # the shipped bug
    (["get", "monitor", "coverage"], False),              # wrong leaf
    (["show", "doc"], False),                             # near-miss of 'docs'
])
def test_resolution_accepts_real_paths_and_rejects_near_misses(tokens, ok):
    assert _resolve(tokens)[0] is ok


@pytest.mark.parametrize("text", [
    "run `satom get api versions` now",
    "```\nsatom diagnose all\n```",
    "$ satom get system health",
    "<code>satom get api preflight fw09 admin x</code>",
])
def test_anchor_finds_a_real_invocation(text):
    assert list(_invocations(text)), text


@pytest.mark.parametrize("text", [
    "the venv at /opt/satom/venv/bin/python3",
    "sudo -u satom ssh -i /opt/satom/.ssh/id_ha_rsync host id",
    "`systemctl status satom satom-scheduler`",
    "`git -C /opt/satom remote set-url origin https://example/x.git`",
    "moved from /monitoring/satom on 2026-08-05",
])
def test_anchor_ignores_prose_that_merely_contains_the_word(text):
    assert not list(_invocations(text)), text


def test_a_leaf_never_rejects_its_own_arguments():
    """Regression: an earlier draft walked past the leaf and flagged every
    argument as an unknown subcommand, which would have made the guard fire on
    ~every real example in the manual."""
    leaf = ["get", "device", "config"]
    assert _resolve(leaf)[0] is True
    assert _resolve(leaf + ["fortiweb09", "system", "dns"])[0] is True
