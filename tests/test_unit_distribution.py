"""Distribution of the things a code update is supposed to carry.

Three separate ways this product has already shipped a lie, all of the same
shape: *something exists in git, and nothing copies it onto the node*.

  2026-07-26  `UNIT_FILES` in `deploy/self_update_runner.py` was a HAND-WRITTEN
              list of six units. `deploy/` shipped ten. So
              `satom-alerts.{service,timer}` and
              `satom-cert-renew.{service,timer}` were never refreshed and the
              installed copies kept `User=fortinet` -- an account that does not
              exist on the node. They ran only because a drop-in overrode them,
              and nothing replicates that drop-in: `systemctl revert` (or a
              node restored from an older image) turns cert renewal into
              `status=217/USER`, silently, which is precisely the failure the
              `cert.renew_failed` signal exists to catch. A hand-written copy of
              a directory listing is a copy, and copies rot.

  2026-07-26  `/usr/local/sbin/satom-ha-datasync.sh` was installed exactly once,
              by a one-shot migration. The git source then gained two fixes (the
              venv interpreter, because openSUSE has no `/usr/bin/python3`; and
              a peer probe that exits non-zero when it cannot evaluate) and the
              RUNNING copy got neither. The replicator itself was reporting
              SUCCESS while replicating nothing.

  2026-08-05  `satom-git-publish` was retired, and three operator-facing
              surfaces kept telling operators to arm it -- including a citation
              of `deploy/satom-git-publish.sh`, a path that exists in no
              repository at all.

Plus the guard-that-cannot-fail-loud problem in `preserve_local_commits()`: a
`git rev-list` that FAILED left the count at 0, which is indistinguishable from
"there is nothing to preserve", and the caller walked into `git reset --hard`.
`docs/safeguards.md` promises "a guard that cannot do its job aborts the
operation"; folding a broken probe into a clean answer is the opposite.

Everything below is anchored to an ARTEFACT (a file that exists, a name in the
AST, an exact install invocation), never to prose. A guard that matches its own
explanatory comment proves nothing -- this repo has been bitten by that.
"""
from __future__ import annotations

import ast
import importlib.util
import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
DOCS = ROOT / "docs"
TEMPLATES = ROOT / "app" / "templates"

RUNNER_SRC = DEPLOY / "self_update_runner.py"
INSTALL_RUNNER = DEPLOY / "install-runner.sh"
INSTALLER = ROOT / "installers" / "install-satom.sh"

#: Unit templates ship in these three flavours. A `.socket` or `.mount` would
#: have to be added here AND to whatever distributes it.
UNIT_SUFFIXES = ("*.service", "*.timer", "*.path")

#: The ONLY unit that must keep running as root: it is the privileged runner.
PRIVILEGED_UNIT = "satom-updater.service"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def unit_templates() -> set[str]:
    names: set[str] = set()
    for pat in UNIT_SUFFIXES:
        names.update(p.name for p in DEPLOY.glob(pat))
    return names


def load_runner():
    """Import `deploy/self_update_runner.py` against THIS checkout.

    ``FM_APP_DIR`` is set first because the module resolves ``APP`` at import
    time and defaults to ``/opt/satom``; pointing it at the checkout keeps the
    test hermetic when it runs from anywhere else.
    """
    os.environ["FM_APP_DIR"] = str(ROOT)
    spec = importlib.util.spec_from_file_location("_satom_runner", RUNNER_SRC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def runner_ast() -> ast.Module:
    return ast.parse(RUNNER_SRC.read_text())


def module_level_value(tree: ast.Module, name: str):
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return node.value
    return None


def ast_string_constants(tree: ast.AST) -> list[str]:
    """Every string literal in the CODE. Comments are gone by construction --
    that is the whole reason this goes through `ast` and not through `in`."""
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def shell_code_text(path: Path) -> str:
    """Shell source with blank lines and whole-line comments removed.

    Same reason as `tests/test_deploy_scripts.py::code_lines`: three scripts in
    `deploy/` mention `runuser` only in a comment explaining why they do NOT
    use it, and the first version of that file flagged all three.
    """
    out = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(raw)
    return "\n".join(out)


# --------------------------------------------------------------------------
# FIX 1 -- every unit template deploy/ ships must be distributed
# --------------------------------------------------------------------------
def test_every_deploy_unit_template_is_distributed() -> None:
    """The exact 2026-07-26 regression: templates in git that no update copies.

    `alerts` and `cert-renew` were the casualties; the point of this assertion
    is that the NEXT unit added to `deploy/` cannot repeat it silently.
    """
    mod = load_runner()
    missing = sorted(unit_templates() - set(mod.UNIT_FILES))
    assert not missing, (
        "deploy/ ships unit template(s) that no distribution mechanism copies "
        "onto the node, so an update never refreshes them and the installed "
        "copy drifts forever (this is how three units kept User=fortinet, an "
        "account that does not exist):\n  " + "\n  ".join(missing))


def test_unit_files_is_not_a_hand_written_list() -> None:
    """The root cause was not the six names -- it was that they were TYPED.

    A literal tuple is a copy of a directory listing, and this one had been
    wrong for four units. Anchored to the AST node, so a hand-list restored
    under any formatting (or hidden behind a comment) still fails.
    """
    value = module_level_value(runner_ast(), "UNIT_FILES")
    assert value is not None, "UNIT_FILES is no longer assigned at module level"
    literal = isinstance(value, (ast.Tuple, ast.List)) and all(
        isinstance(e, ast.Constant) for e in value.elts)
    assert not literal, (
        "UNIT_FILES is a hand-written literal again. Derive it from what "
        "deploy/ actually contains: the hand-list drifted from ten templates "
        "to six and nobody noticed for weeks.")


def test_unit_files_lists_nothing_deploy_does_not_ship() -> None:
    """Counterweight to the test above: 'copy everything' must not become
    'copy things that do not exist'. A name here with no template would either
    be a silent no-op or, worse, install a RETIRED unit -- `satom-git-publish`
    and `satom-ha-datasync` are deliberately not templates."""
    mod = load_runner()
    phantom = sorted(set(mod.UNIT_FILES) - unit_templates())
    assert not phantom, (
        "UNIT_FILES names unit(s) with no template in deploy/: " + ", ".join(phantom))


def test_every_service_template_is_pinned_to_the_service_account() -> None:
    """The templates declare `User=root` and every update re-copies them, so
    the drop-in in NONROOT_UNITS is the ONLY thing keeping them de-privileged.
    A template not listed there is a unit that quietly returns to root."""
    mod = load_runner()
    services = {n for n in unit_templates() if n.endswith(".service")}
    missing = sorted(services - {PRIVILEGED_UNIT} - set(mod.NONROOT_UNITS))
    assert not missing, (
        "service template(s) that no drop-in de-privileges -- an update "
        "re-copies User=root over them: " + ", ".join(missing))


def test_the_privileged_updater_is_never_downgraded() -> None:
    """Counterweight: deriving NONROOT_UNITS from the templates must not sweep
    in the runner itself. It installs units and restarts services; as the
    service account it cannot do its job at all."""
    mod = load_runner()
    assert PRIVILEGED_UNIT not in mod.NONROOT_UNITS, (
        "%s was added to NONROOT_UNITS. It IS the privileged runner." % PRIVILEGED_UNIT)


# --------------------------------------------------------------------------
# FIX 2 -- /usr/local/sbin/satom-*.sh needs a distribution path
# --------------------------------------------------------------------------
def installer_sbin_scripts() -> set[str]:
    """The scripts `installers/install-satom.sh` copies into /usr/local/sbin.

    Read out of the installer rather than typed here so the two cannot drift:
    the whole defect being guarded is a hand-maintained second copy of a list.
    """
    text = INSTALLER.read_text()
    m = re.search(
        r"for\s+s\s+in\s+(.*?);\s*do\s*\n[^\n]*install[^\n]*/usr/local/sbin/",
        text, re.S)
    assert m, ("could not find the /usr/local/sbin install loop in %s -- if it "
               "moved, this guard has to follow it" % INSTALLER.name)
    return {w for w in m.group(1).replace("\\", " ").split() if w}


def test_the_installer_sbin_loop_is_still_readable() -> None:
    names = installer_sbin_scripts()
    assert names, "the installer's /usr/local/sbin loop parsed to nothing"
    for n in sorted(names):
        assert (DEPLOY / n).is_file(), (
            "the installer copies deploy/%s to /usr/local/sbin but that source "
            "does not exist" % n)


def test_sbin_helpers_are_reinstalled_by_an_every_update_mechanism() -> None:
    """`/usr/local/sbin/satom-ha-datasync.sh` sat 5297 bytes / Jul 26 while git
    held 5943 bytes / Aug 4, because its ONLY installer was a one-shot
    migration. Scripts outside the app tree are not reached by a code update
    unless something re-installs them, exactly like the operator CLI."""
    code = shell_code_text(INSTALL_RUNNER)
    missing = sorted(n for n in installer_sbin_scripts() if n not in code)
    assert not missing, (
        "these helper scripts land in /usr/local/sbin at install time and "
        "nothing re-installs them on update, so the running copy silently ages "
        "behind git: " + ", ".join(missing))


def test_sbin_copies_are_installed_root_owned() -> None:
    """A root-executed (or root-installed) script that the service account can
    rewrite is the escalation install-runner.sh exists to close. Anchored to
    the exact install invocation, not to the sentence explaining it."""
    code = shell_code_text(INSTALL_RUNNER)
    assert "install -o root -g root -m 0755" in code, (
        "the /usr/local/sbin copies are not installed root:root 0755 -- a "
        "helper writable by the service account is a root escalation")


def test_the_update_runner_reinstalls_the_out_of_tree_copies() -> None:
    """Both destructive paths (git update and offline package) must refresh
    them. `preserve`/`package_change` diverged once already."""
    consts = ast_string_constants(runner_ast())
    n = consts.count("install-runner.sh")
    assert n >= 2, (
        "deploy/self_update_runner.py invokes install-runner.sh %d time(s); "
        "both the git-update path and the offline-package path must refresh "
        "the out-of-tree copies" % n)


# --------------------------------------------------------------------------
# FIX 3 -- preserve_local_commits() must not fold a broken probe into "clean"
# --------------------------------------------------------------------------
class _Res:
    def __init__(self, rc=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = rc, stdout, stderr


class _Status:
    def __init__(self):
        self.steps = []

    def step(self, name, ok=True, detail=""):
        self.steps.append((name, ok, detail))


def _fake_git(rev_list: _Res, status: _Res, other: _Res | None = None):
    def git(*a, **kw):
        if a[:2] == ("rev-list", "--count"):
            return rev_list
        if a[0] == "status":
            return status
        return other or _Res(0, "deadbeefcafe")
    return git


def test_preserve_local_commits_refuses_when_the_commit_probe_fails(monkeypatch) -> None:
    """A failed `git rev-list` (bad ref, index.lock, timeout, safe.directory
    refusal) used to leave n == 0, which reads as "nothing to preserve" and
    returns None -- and `None is not False`, so the caller went straight into
    `git reset --hard`. The guard has to abort when it cannot DETERMINE whether
    parking was needed, not only when parking failed."""
    mod = load_runner()
    monkeypatch.setattr(mod, "git", _fake_git(
        _Res(128, "", "fatal: bad revision"), _Res(0, "")))
    assert mod.preserve_local_commits("origin/main", "abc123", _Status()) is False


def test_preserve_local_commits_refuses_when_the_dirty_probe_fails(monkeypatch) -> None:
    """Same defect on the other probe: a failed `git status` yielded an empty
    stdout, `dirty` became False, and uncommitted work was declared absent."""
    mod = load_runner()
    monkeypatch.setattr(mod, "git", _fake_git(
        _Res(0, "0\n"), _Res(128, "", "fatal: not a git repository")))
    assert mod.preserve_local_commits("origin/main", "abc123", _Status()) is False


def test_preserve_local_commits_returns_none_on_a_genuinely_clean_checkout(monkeypatch) -> None:
    """Counterweight. 'Refuse when unsure' must not become 'refuse always':
    a clean checkout already at the target has nothing to park and the update
    has to proceed, or every update aborts."""
    mod = load_runner()
    monkeypatch.setattr(mod, "git", _fake_git(_Res(0, "0\n"), _Res(0, "")))
    assert mod.preserve_local_commits("origin/main", "abc123", _Status()) is None


def test_preserve_local_commits_parks_local_commits_and_reports_true(monkeypatch) -> None:
    """Counterweight: the success path still works and still parks."""
    mod = load_runner()
    st = _Status()
    monkeypatch.setattr(mod, "git", _fake_git(_Res(0, "3\n"), _Res(0, "")))
    assert mod.preserve_local_commits("origin/main", "abc123", st) is True
    assert any("3 local commit" in n for n, _ok, _d in st.steps), st.steps


def test_every_caller_aborts_when_preservation_did_not_succeed() -> None:
    """The return value is only worth something if both destructive call sites
    still branch on it. There are two: the git reset and the whole-tree
    replacement from an offline package."""
    tree = runner_ast()
    sites = 0
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == "preserve_local_commits"):
                continue
            name = node.targets[0].id
            guarded = False
            for cand in ast.walk(fn):
                if not isinstance(cand, ast.If):
                    continue
                t = cand.test
                if not (isinstance(t, ast.Compare)
                        and isinstance(t.left, ast.Name) and t.left.id == name
                        and isinstance(t.comparators[0], ast.Constant)
                        and t.comparators[0].value is False):
                    continue
                if any(isinstance(x, ast.Raise) for x in ast.walk(cand)):
                    guarded = True
            assert guarded, (
                "%s() calls preserve_local_commits() and does not abort when it "
                "returns False -- that is a destructive operation running past "
                "its own safety guard" % fn.name)
            sites += 1
    assert sites == 2, (
        "expected 2 guarded preserve_local_commits() call sites, found %d" % sites)


# --------------------------------------------------------------------------
# FIX 4 + 5 -- the retired git publisher must not be advertised as live
# --------------------------------------------------------------------------
#: Surfaces an operator reads to decide what to arm and how replication works.
#: Scoped deliberately: `docs/metrics-architecture.md` and
#: `app/services/system_health.py` mention the timer to say it is RETIRED, and
#: `docs/safeguards.md` keeps it as a post-mortem. Naming it there is honest;
#: naming it in an install checklist or a topology diagram is an instruction.
OPERATOR_SURFACES = (
    DOCS / "git-backup-and-outage.md",
    DOCS / "INSTALL.md",
    DOCS / "privilege-model.md",
    TEMPLATES / "high_availability" / "index.html",
)


@pytest.mark.parametrize("surface", OPERATOR_SURFACES,
                         ids=lambda p: p.name if p.parent.name != "high_availability"
                         else "high_availability/index.html")
def test_operator_surfaces_do_not_advertise_the_retired_publisher(surface: Path) -> None:
    """`satom-git-publish` was retired on 2026-08-05 (timer disabled, `git
    ls-files reports` empty, `/reports/` gitignored). INSTALL.md still told the
    operator to arm the timer on both nodes and the HA page still drew it into
    the replication topology -- so the page an operator opens to CONFIRM their
    topology was describing a mechanism that has not run since Aug 5."""
    hits = [(n, ln.strip()) for n, ln in
            enumerate(surface.read_text().splitlines(), 1)
            if "satom-git-publish" in ln]
    assert not hits, (
        "%s presents the retired git SoT publisher to an operator. The SoT "
        "lives in data/sot/ and replicates via satom-ha-datasync:\n  %s"
        % (surface.name, "\n  ".join("%d: %s" % h for h in hits)))


@pytest.mark.parametrize("surface", (
    DOCS / "git-backup-and-outage.md",
    TEMPLATES / "high_availability" / "index.html",
), ids=("git-backup-and-outage.md", "high_availability/index.html"))
def test_operator_surfaces_name_the_real_source_of_truth(surface: Path) -> None:
    """Deleting the lie is half the job. Both surfaces exist to tell an
    operator where the device SoT actually lives, so they have to name the
    real store -- otherwise the fix reads as "this used to be somewhere"."""
    assert "data/sot" in surface.read_text(), (
        "%s no longer says where the device SoT lives. It is the "
        "content-addressed store under data/sot/ (docs/source-of-truth-spec.md, "
        "docs/metrics-architecture.md), replicated by satom-ha-datasync and "
        "carried in the backup bundles." % surface.name)


def _cited_deploy_paths(text: str) -> set[str]:
    return set(re.findall(r"deploy/[A-Za-z0-9_][A-Za-z0-9_.-]*", text))


DOC_AND_TEMPLATE_FILES = sorted(
    [p for p in DOCS.rglob("*.md")] + [p for p in TEMPLATES.rglob("*.html")])


@pytest.mark.parametrize("path", DOC_AND_TEMPLATE_FILES,
                         ids=lambda p: str(p.relative_to(ROOT)))
def test_docs_never_cite_a_deploy_path_that_does_not_exist(path: Path) -> None:
    """`docs/privilege-model.md` cited `deploy/satom-git-publish.sh::as_app` as
    the worked example of the runuser/id-u rule. `git ls-files` has never
    contained that file: the citation pointed a reader at a script that is
    genuinely unrecoverable, and made the rule unverifiable."""
    dangling = sorted(p for p in _cited_deploy_paths(path.read_text())
                      if not (ROOT / p).exists())
    assert not dangling, (
        "%s cites deploy path(s) that do not exist in this repository: %s"
        % (path.relative_to(ROOT), ", ".join(dangling)))
