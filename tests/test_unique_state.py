"""Guards for safeguards.md 4b — a node must report state that exists only here.

The rule these protect: converging the standby is the reconciler's job, never a
side effect of unrelated work. The product cannot refuse a `git reset --hard`
typed by root, and should not — so the enforceable half is that a node can
always SAY what it alone holds before anyone discards it.

The incident: an applied update package on the primary reverted another
session's UNCOMMITTED work. It was recovered from the standby, which had not
yet been reconciled and was therefore the only surviving copy.
"""
import ast
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKS = ROOT / "deploy" / "satom_cli" / "cmd_checks.py"
SAFEGUARDS = ROOT / "docs" / "safeguards.md"

sys.path.insert(0, str(ROOT / "deploy"))


def _git_fn():
    """The AST of cmd_checks.git(), comments stripped by construction.

    Asserting against the raw source text would match the explanatory comments,
    which name every symbol the guard uses — the substring trap this repo has
    now hit eight times.
    """
    tree = ast.parse(CHECKS.read_text())
    return next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "git")


def _string_constants(node):
    return [n.value for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _git_argv_lists(node):
    """Every list literal in git() that looks like git arguments."""
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.List):
            elts = [e.value for e in n.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if elts:
                out.append(elts)
    return out


# ---------------------------------------------------------------- the read-out

def test_the_check_reports_a_state_that_exists_only_here_section():
    """Without the heading there is no read-out, whatever else it computes."""
    consts = _string_constants(_git_fn())
    assert "state that exists only here" in consts, (
        "diagnose git must publish a section naming what this node alone holds")


def test_dirty_tracked_files_are_collected():
    """`reset --hard` discards modifications to TRACKED files. That is the
    primary loss, so it must be measured."""
    argvs = _git_argv_lists(_git_fn())
    assert any("diff" in a and "--name-only" in a for a in argvs), (
        "the dirty-file list must come from `git diff --name-only HEAD`")


def test_dirty_paths_are_not_sliced_by_position():
    """run() strips captured output, so the first porcelain line loses its
    leading space and a fixed slice eats the first character of the filename.
    A truncated path is worse than no path: it sends the reader looking for a
    file that does not exist."""
    src = CHECKS.read_text()
    assert "x[3:]" not in src, (
        "parse bare paths; do not slice the porcelain 'XY ' prefix by position")


def test_unpushed_commits_are_counted_against_the_upstream_branch():
    argvs = _git_argv_lists(_git_fn())
    assert any("rev-list" in a and "--count" in a for a in argvs), (
        "commits absent from the upstream branch must be counted")


def test_parked_safety_refs_are_reported():
    """refs/backup/* is where preserve_local_commits() puts work it rescued.
    If those exist, this node is holding a recovery path."""
    consts = _string_constants(_git_fn())
    assert any("refs/backup" in c for c in consts), (
        "parked refs/backup/* refs must be surfaced")


# --------------------------------------------------------- the grading, and
# --------------------------------------------------------- what must NOT grade

def _escalation_ifs(fn):
    """Every `if` in git() whose body escalates the grade.

    Matched through the AST rather than by line text. A text filter here is
    exactly how the first version of this guard let a mutant through: the
    mutated condition contained both the term being looked for AND the term
    the filter used to exclude false positives, so it excluded the real one.
    """
    out = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.If):
            continue
        escalates = any(
            isinstance(c.func, ast.Attribute) and c.func.attr == "worst"
            for c in ast.walk(node) if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Attribute))
        if escalates:
            out.append(node)
    return out


def test_untracked_files_are_listed_but_do_not_grade():
    """`git reset --hard` does NOT delete untracked files, and the primary
    legitimately carries an untracked `reports` symlink. Grading them would be
    both false and permanently loud, and a permanent warn is indistinguishable
    from no check at all."""
    fn = _git_fn()
    guilty = []
    for node in _escalation_ifs(fn):
        names = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
        if "untracked" in names:
            guilty.append(ast.dump(node.test))
    assert not guilty, (
        "untracked files must not drive the grade: %r" % guilty)


def test_the_grade_is_driven_by_dirty_and_unpushed():
    """The other half. A condition that grades nothing satisfies the test above
    trivially, so state what MUST drive it."""
    fn = _git_fn()
    driving = set()
    for node in _escalation_ifs(fn):
        driving |= {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
    assert {"dirty", "ahead"} <= driving, (
        "modified tracked files and unpushed commits must drive the grade; "
        "found %r" % sorted(driving))


def test_untracked_files_are_still_reported():
    """Not grading is not the same as hiding."""
    argvs = _git_argv_lists(_git_fn())
    assert any("ls-files" in a and "--others" in a for a in argvs), (
        "untracked files must still be listed, just not graded")


def test_a_missing_upstream_is_reported_as_unknown_not_as_zero():
    """Zero unpushed commits is a comforting number the check has no basis for
    when there is no upstream branch to compare against."""
    consts = " ".join(_string_constants(_git_fn()))
    assert "cannot tell" in consts, (
        "with no upstream the count must be reported as unknown, not as zero")


def _unique_state_note():
    """THE note attached to the unique-state finding.

    git() carries a second, unrelated note (the missing-git-binary path) that
    also says "reconciler". Joining every string in the function and searching
    it matches that one instead, and the guard passes with its own subject
    deleted. Select the note by its own opening words.
    """
    for c in _string_constants(_git_fn()):
        if "no other node has" in c:
            return c.lower()
    return ""


def test_the_note_exists_at_all():
    assert _unique_state_note(), (
        "the unique-state finding must carry a note explaining the stakes")


def test_the_note_sends_the_operator_to_commit_and_push():
    note = _unique_state_note()
    assert "commit" in note and "push" in note, (
        "the note must name the action that makes the state survivable")


def test_the_note_names_the_standby_rule():
    """The read-out is the only place the operator meets this rule at the
    moment it matters."""
    note = _unique_state_note()
    assert "standby" in note and "reconciler" in note, (
        "the note must state that converging the standby is the reconciler's job")


# ------------------------------------------------------------------- the doc

def test_safeguards_documents_the_standby_rule():
    txt = SAFEGUARDS.read_text()
    assert "## 4b." in txt, "safeguards.md must carry the section"
    body = txt.split("## 4b.", 1)[1].split("\n## ", 1)[0].lower()
    assert "reconciler" in body
    assert "uncommitted" in body, "the incident must be recorded, not just the rule"


def test_safeguards_states_the_limit_that_this_is_not_an_interlock():
    """Overclaiming a read-out as an interlock is how a reader concludes the
    product will stop them, and then does not check."""
    txt = SAFEGUARDS.read_text()
    body = txt.split("## 4b.", 1)[1].split("\n## ", 1)[0].lower()
    assert "interlock" in body, (
        "the section must say plainly that nothing refuses the reset")


def test_safeguards_carries_a_verification_recipe_for_4b():
    txt = SAFEGUARDS.read_text()
    assert "### State that exists only here" in txt, (
        "every guard in this file owns a recipe proving it is armed")


def test_the_recipe_step_that_checks_for_over_loudness_is_discriminating():
    """An absolute `expect ok` only holds on a spotless tree. On a working node
    it reports a failure of the guard when what it found was uncommitted work —
    blaming the wrong half and training the reader to ignore the step."""
    txt = SAFEGUARDS.read_text()
    recipe = txt.split("### State that exists only here", 1)[1].split("\n### ", 1)[0]
    # The EXECUTABLE line, not the comment above it that explains why. The
    # comment says "Compare BEFORE and AFTER", so a bare substring search for
    # BEFORE passes with the command itself deleted -- the recipe would then
    # document a technique it no longer performs.
    lines = [ln.strip() for ln in recipe.splitlines() if not ln.strip().startswith("#")]
    assert any("BEFORE=$(" in ln for ln in lines), (
        "step 3 must capture the status BEFORE planting the untracked file")
    assert any("AFTER=$(" in ln for ln in lines), (
        "step 3 must capture the status AFTER, and compare -- a bare `expect ok` "
        "only holds on a spotless tree and blames the wrong half on a dirty one")


# ------------------------------------------------------- end-to-end behaviour

def _run_cli(tmp_repo, *args):
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(tmp_repo)}
    return subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, %r); "
         "from satom_cli import cmd_checks" % str(ROOT / "deploy"),
         *args],
        capture_output=True, text=True, env=env, timeout=60)


def test_the_module_imports_without_flask():
    """cmd_checks is part of the operator console: it must work when the app's
    virtualenv is exactly what is broken."""
    r = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, %r); "
         "import satom_cli.cmd_checks as m; print(m.git.__doc__ is not None)"
         % str(ROOT / "deploy")],
        capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "True" in r.stdout
