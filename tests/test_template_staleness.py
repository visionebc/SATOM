"""`satom diagnose code` has to see the artifacts gunicorn caches.

The check compared the newest ``.py`` against each process start time, so a
change that touched ONLY templates was invisible to it — and templates are
exactly what gunicorn caches. Jinja compiles a template on first render and,
with auto-reload off (the production default), keeps the compiled copy for the
life of the worker. The cache is per worker and lazy, so after an edit some
workers serve new markup and some serve old: a nav entry that appears,
vanishes and comes back with no pattern. It reads as a navigation bug.

That happened here on 2026-08-06: a shared nav partial was edited, the service
was never restarted, and a ``test_client`` render — a fresh process reading
from disk — reported the change present while the live service served it on
0 of 30 requests.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "deploy"))

from satom_cli import cmd_checks  # noqa: E402

HOUR = 3600.0
START = 1_700_000_000.0  # arbitrary fixed process start


class FakeCtx:
    def __init__(self, app_dir):
        self.app_dir = Path(app_dir)
        self.host = "node"
        self.role = "primary"

    def unit(self, alias):
        return "satom-%s.service" % alias

    def unit_state(self, alias):
        return {"enabled": "enabled", "active": "active", "sub": "running"}


def _touch(path, mtime, body="x"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    os.utime(path, (mtime, mtime))
    return path


@pytest.fixture()
def tree(tmp_path, monkeypatch):
    """A minimal app tree plus a running web/scheduler/reconciler trio."""
    monkeypatch.setattr(cmd_checks, "_main_pid", lambda ctx, alias: 4242)
    monkeypatch.setattr(cmd_checks, "_proc_start_epoch", lambda pid: START)
    return FakeCtx(tmp_path)


def _rows(result):
    heading, (kind, rows) = result.sections[0]
    assert kind == "rows"
    return dict(rows)


# --------------------------------------------------------------------------
# the scanner
# --------------------------------------------------------------------------

def test_a_newer_template_is_found(tmp_path):
    _touch(tmp_path / "app/templates/base.html", START - HOUR)
    newest = _touch(tmp_path / "app/templates/partials/nav.html", START + HOUR)
    found, m = cmd_checks._newest_template(FakeCtx(tmp_path))
    assert found == newest
    assert m == pytest.approx(START + HOUR)


def test_editor_backups_are_not_loadable_artifacts(tmp_path):
    """A backup written seconds ago must not be reported as the newest template.

    app/templates on a live node carries *.bak, *.pre-<stamp> and *.retired-*
    files left by past edits. No Jinja loader will ever read them, so a bare
    newest-file scan would charge the web worker with staleness against markup
    that is not served — and send the operator to restart for nothing.
    """
    real = _touch(tmp_path / "app/templates/base.html", START - HOUR)
    for junk in ("base.html.bak", "base.html.pre-20260706-menu",
                 "index.html.retired-certmove", "old.html.bak-1783773825"):
        _touch(tmp_path / "app/templates" / junk, START + 10 * HOUR)
    found, m = cmd_checks._newest_template(FakeCtx(tmp_path))
    assert found == real, "a non-loadable backup was taken for a template"
    assert m == pytest.approx(START - HOUR)


def test_a_missing_template_tree_is_not_an_error(tmp_path):
    assert cmd_checks._newest_template(FakeCtx(tmp_path)) == (None, 0)


# --------------------------------------------------------------------------
# who the artifact is charged to
# --------------------------------------------------------------------------

def test_a_template_only_edit_marks_the_web_worker_stale(tree):
    _touch(tree.app_dir / "app/svc.py", START - HOUR)
    _touch(tree.app_dir / "app/templates/partials/nav.html", START + 2 * HOUR)

    result = cmd_checks.code(tree, [])

    assert result.status == "warn", "a template-only edit was reported as fresh"
    row = _rows(result)["web"]
    assert "STALE" in row and "template" in row, row


def test_a_template_only_edit_does_not_mark_the_sidecars_stale(tree):
    """The scheduler and reconciler never render templates.

    render_template appears nowhere outside the request path, so marking them
    stale for markup they do not load is a permanent false positive — the
    failure mode this repo has had to remove from `get system health` and from
    the status colouring already.
    """
    _touch(tree.app_dir / "app/svc.py", START - HOUR)
    _touch(tree.app_dir / "app/templates/partials/nav.html", START + 2 * HOUR)

    rows = _rows(cmd_checks.code(tree, []))

    for alias in ("scheduler", "reconciler"):
        assert "STALE" not in rows[alias], "%s blamed for a template: %s" % (alias, rows[alias])


def test_a_source_edit_still_marks_every_process_stale(tree):
    """The original behaviour must survive: .py staleness is not template-only."""
    _touch(tree.app_dir / "app/svc.py", START + 2 * HOUR)
    _touch(tree.app_dir / "app/templates/partials/nav.html", START - HOUR)

    result = cmd_checks.code(tree, [])
    rows = _rows(result)

    assert result.status == "warn"
    for alias in ("web", "scheduler", "reconciler"):
        assert "STALE" in rows[alias] and "source" in rows[alias], rows[alias]


def test_everything_current_stays_ok(tree):
    _touch(tree.app_dir / "app/svc.py", START - 2 * HOUR)
    _touch(tree.app_dir / "app/templates/base.html", START - HOUR)

    result = cmd_checks.code(tree, [])

    assert result.status == "ok"
    assert not [v for v in _rows(result).values() if "STALE" in v]


def test_both_artifacts_are_named_in_the_read_out(tree):
    """The operator has to know WHICH artifact moved, not just that one did."""
    _touch(tree.app_dir / "app/svc.py", START - HOUR)
    _touch(tree.app_dir / "app/templates/partials/nav.html", START + HOUR)
    rows = _rows(cmd_checks.code(tree, []))
    assert "nav.html" in rows["newest template"]
    assert "svc.py" in rows["newest source"]


def test_the_template_case_names_the_per_worker_cache(tree):
    """The intermittent symptom is the non-obvious part; the note must say it.

    Without this the operator reads 'STALE' and restarts, but never learns why
    the page was right half the time — so the next template edit gets debugged
    as a navigation bug all over again.
    """
    _touch(tree.app_dir / "app/svc.py", START - HOUR)
    _touch(tree.app_dir / "app/templates/partials/nav.html", START + HOUR)

    notes = " ".join(cmd_checks.code(tree, []).notes).lower()

    assert "worker" in notes
    assert "test_client" in notes, "the false-green verification path is not named"


# --------------------------------------------------------------------------
# the tripwire under TEMPLATE_CONSUMERS
# --------------------------------------------------------------------------

REQUEST_PATH_PREFIXES = ("app/views/", "app/auth/", "app/errors.py")


def test_only_request_path_modules_render_templates():
    """TEMPLATE_CONSUMERS == ("web",) is only true while this holds.

    If a background service starts rendering Jinja (an emailed report body, a
    scheduled export), its process caches templates too and has to be added to
    TEMPLATE_CONSUMERS — otherwise a template edit leaves it silently stale.
    """
    offenders, scanned = [], 0
    for path in sorted((REPO / "app").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        scanned += 1
        if "render_template" not in path.read_text(errors="replace"):
            continue
        rel = path.relative_to(REPO).as_posix()
        if not rel.startswith(REQUEST_PATH_PREFIXES):
            offenders.append(rel)

    assert scanned > 50, "the scan found almost nothing — it is not looking at app/"
    assert not offenders, (
        "these render Jinja outside the request path: %s. If any runs in a "
        "long-lived non-web process, add its alias to "
        "cmd_checks.TEMPLATE_CONSUMERS." % ", ".join(offenders)
    )


def test_the_suffix_list_covers_what_the_tree_actually_ships():
    """Every extension really present under app/templates is either loadable
    or is a backup — a new loadable extension must not be scanned past."""
    root = REPO / "app" / "templates"
    live = {p.suffix.lower() for p in root.rglob("*") if p.is_file()}
    unknown = {s for s in live if s not in cmd_checks.TEMPLATE_SUFFIXES}
    # backups are the only thing allowed to be unrecognised
    assert all(".bak" in s or s.startswith(".pre-") or s.startswith(".retired")
               for s in unknown), "unrecognised template extension: %s" % sorted(unknown)


# --------------------------------------------------------------------------
# the same hole on the source side
# --------------------------------------------------------------------------

def test_hidden_scratch_scripts_are_not_loadable_code(tmp_path):
    """A .py whose name starts with a dot can never be imported.

    Python module names cannot begin with a dot, so a hidden script is
    structurally unimportable — nothing loads it, ever. The working tree
    collects them (one-off patches, probes, mutation harnesses) and without
    this filter the check names a throwaway script as the reason to restart a
    long-running service. Same defect as an editor backup in the template
    tree: an artifact no loader reads, charged as if it were served.
    """
    real = _touch(tmp_path / "app/services/thresholds.py", START - HOUR)
    _touch(tmp_path / ".patch_a.py", START + 10 * HOUR)
    _touch(tmp_path / ".mutate.py", START + 12 * HOUR)
    _touch(tmp_path / "app/.probe.py", START + 14 * HOUR)

    found, m = cmd_checks._newest_source(FakeCtx(tmp_path))

    assert found == real, "a hidden scratch script was taken for loaded code"
    assert m == pytest.approx(START - HOUR)


def test_a_visible_top_level_module_still_counts(tmp_path):
    """The exclusion is about the leading dot, not about being top-level."""
    top = _touch(tmp_path / "wsgi.py", START + HOUR)
    _touch(tmp_path / "app/svc.py", START - HOUR)
    found, _ = cmd_checks._newest_source(FakeCtx(tmp_path))
    assert found == top


def test_scratch_files_alone_do_not_make_a_process_look_stale(tree):
    """End to end: only scratch churn must not send anyone to restart."""
    _touch(tree.app_dir / "app/svc.py", START - 2 * HOUR)
    _touch(tree.app_dir / "app/templates/base.html", START - HOUR)
    _touch(tree.app_dir / ".fixfac.py", START + 6 * HOUR)

    result = cmd_checks.code(tree, [])

    assert result.status == "ok", "scratch files triggered a restart recommendation"


# --------------------------------------------------------------------------
# The same dot-file reasoning, one layer out: git must not offer the scratch
# for staging either. `diagnose code` learning to skip these files stopped the
# false "restart your service" advice, but the files were still untracked and
# still visible, so an unrelated `git add -A` could sweep another session's
# throwaway into a commit. That has happened twice in this repo.
#
# Assert through git itself rather than by grepping .gitignore: the pattern
# syntax is git's, so only git can say whether a rule actually matches. A
# substring assertion would pass on a rule that is present and wrong.
# --------------------------------------------------------------------------

SCRATCH_NAMES = (".patch_a.py", ".smoke1.py", ".tsh.py", ".runsuite.sh",
                 ".suite.log", ".suite.rc")

REAL_SOURCE = ("wsgi.py", "app/__init__.py", "deploy/satom_cli/tree.py",
               "tests/conftest.py", "app/templates/base.html", ".gitignore")


def _ignored(name):
    """True when the ignore RULES match `name`.

    ``--no-index`` is load-bearing: without it git refuses to report a tracked
    path as ignored, so every "this must NOT be ignored" assertion below would
    pass vacuously — including against a rule of ``*``. Verified by mutation.
    """
    proc = subprocess.run(
        ["git", "--no-optional-locks", "check-ignore", "-q", "--no-index", "--", name],
        cwd=str(REPO), capture_output=True,
    )
    assert proc.returncode in (0, 1), (
        "git check-ignore failed: %s" % proc.stderr.decode()[:200])
    return proc.returncode == 0


@pytest.mark.parametrize("name", SCRATCH_NAMES)
def test_root_level_hidden_scratch_is_ignored_by_git(name):
    assert _ignored(name), (
        f"{name} is not ignored: an unrelated `git add -A` can sweep it into "
        "a commit, which is how uncommitted work was lost here twice"
    )


@pytest.mark.parametrize("name", REAL_SOURCE)
def test_the_scratch_rule_does_not_shadow_real_files(name):
    """Anti-vacuity: a rule of `*` would satisfy the test above and hide
    the entire tree. Source must stay visible to git."""
    assert not _ignored(name), f"{name} must never be ignored"


def test_no_tracked_file_is_shadowed_by_an_ignore_rule():
    """A tracked file matching an ignore rule keeps working until someone
    deletes and re-adds it, and then it silently will not come back."""
    tracked = subprocess.run(
        ["git", "--no-optional-locks", "ls-files"],
        cwd=str(REPO), capture_output=True, text=True,
    ).stdout.split()
    assert tracked, "expected a populated index"
    shadowed = [t for t in tracked if _ignored(t)]
    assert not shadowed, f"tracked but ignored: {shadowed}"


NESTED_SCRATCH = ("app/.probe.py", "deploy/.tmp.sh", "tests/.scratch.log")


@pytest.mark.parametrize("name", NESTED_SCRATCH)
def test_the_scratch_rule_stays_at_the_repo_root(name):
    """The rule is root-anchored, and that has to be observable.

    Without this, dropping the leading ``/`` is a silent no-op for every name
    the other tests use — they are all at the root. A wider rule would reach
    inside packages, and blast radius is the whole point of the anchor.
    """
    assert not _ignored(name), (
        f"{name} is ignored: the scratch rule escaped the repo root"
    )
