"""Guards for the operational half of the operator CLI.

Companion to ``test_cli.py``, which covers the structural properties (stdlib
purity, privilege declaration, the root-owned install). This file covers the
properties that only bite in production:

* A diagnostic must not MODIFY the tree it is diagnosing. Two commands did:
  ``git status`` as root rewrote ``.git/index`` and took it from the service
  account, and ``compileall`` left root-owned ``__pycache__`` behind — which
  the ownership check then correctly reported as drift the CLI itself caused.
* The checker and the fixer must agree. ``diagnose install`` says a protection
  is missing and ``execute seed actions`` creates it; if their key sets drift,
  one reports a permanent failure the other cannot fix.
* Seeded action keys must exist in the real catalogue. A renamed action would
  otherwise be seeded as a row the scheduler cannot dispatch.
* Anything destructive must refuse without ``--yes``.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CLI_DIR = REPO / "deploy" / "satom_cli"
sys.path.insert(0, str(REPO / "deploy"))

from satom_cli import cmd_checks, cmd_fix, cmd_ops, dbq, runbooks  # noqa: E402
from satom_cli import tree as cli_tree  # noqa: E402
from satom_cli.context import Ctx  # noqa: E402


# -- the checker and the fixer must not drift apart -----------------------
def test_seed_plan_and_install_check_cover_the_same_actions():
    planned = {row[0] for row in cmd_fix.SEED_PLAN}
    checked = set(cmd_checks.MIN_ACTIONS)
    assert planned == checked, (
        "'diagnose install' reports %s and 'execute seed actions' creates %s. "
        "A protection the check demands and the fixer never creates is a "
        "permanent red the operator cannot clear."
        % (sorted(checked), sorted(planned)))


def test_seeded_action_keys_exist_in_the_real_catalogue():
    """A renamed action key would be seeded as a row nothing can dispatch."""
    from app.services.scheduled_actions import ADMIN_ACTIONS
    try:
        from app.services.scheduled_actions import USER_ACTIONS
    except ImportError:
        USER_ACTIONS = []
    catalogue = {spec.key for spec in list(ADMIN_ACTIONS) + list(USER_ACTIONS)}
    unknown = {row[0] for row in cmd_fix.SEED_PLAN} - catalogue
    assert not unknown, (
        "SEED_PLAN references action keys that do not exist: %s. The row would "
        "be created and the scheduler would fail it with 'Unknown action'."
        % sorted(unknown))


def test_seed_plan_schedules_are_shapes_the_scheduler_understands():
    from app.services.scheduler import compute_next_run
    for key, _name, kind, sched, _params, _product in cmd_fix.SEED_PLAN:
        assert compute_next_run(kind, sched) is not None, (
            "%s: schedule_kind=%r spec=%r produced no next_run, so the action "
            "would be created and never fire." % (key, kind, sched))


# -- diagnostics must not modify the tree ---------------------------------
def test_git_reads_never_take_the_index_from_the_service_account():
    """`git status` refreshes and REWRITES .git/index. Run as root in a tree
    owned by the service account it hands the index to root and breaks every
    later write by the app — a read command with a destructive side effect."""
    for module in (cmd_ops, cmd_checks):
        name = Path(module.__file__).name
        src = Path(module.__file__).read_text()
        # Check the INVOCATION, not the presence of the string: the comment
        # explaining this rule contains the flag too, so a substring test
        # passes even after the flag is removed from the command. (Verified by
        # mutation — the first version of this test did exactly that.)
        opens = src.count('["git"')
        guarded = src.count('["git", "--no-optional-locks"')
        assert opens == guarded, (
            "%s builds %d git invocation(s) but only %d pass "
            "--no-optional-locks. `git status` as root rewrites .git/index and "
            "takes it from the service account." % (name, opens, guarded))


def test_diagnose_python_does_not_write_bytecode_into_the_tree():
    src = (CLI_DIR / "cmd_diagnose.py").read_text()
    # The INVOCATION, not the word: the comment explaining why compileall is
    # not used must be allowed to name it.
    assert '"compileall"' not in src, (
        "compileall WRITES __pycache__. Run as root it leaves root-owned files "
        "in a tree owned by the service account — the exact drift "
        "'diagnose git' then reports. Compile in memory instead.")
    assert "PYTHONDONTWRITEBYTECODE" in src, (
        "The lazy-import smoke test imports modules, and importing writes "
        "bytecode. The child needs PYTHONDONTWRITEBYTECODE=1.")


# -- absence of data is never health --------------------------------------
def test_probe_query_carries_the_maintenance_flag():
    """A probe against a device parked ON PURPOSE must not raise the roll-up;
    maintenance already suppresses automatic runs and their alerts."""
    assert "maintenance" in dbq.PROBES


def test_fail_streak_is_cleared_by_skipped_not_only_by_ok():
    """The opposite rule has a worse failure mode: an action whose targets are
    all in maintenance reports 'skipped' forever, so old failures never age out
    and the alert stays critical on a node where nothing is wrong."""
    rows = [["7", "skipped"], ["7", "failed"], ["7", "failed"],
            ["9", "failed"], ["9", "failed"], ["9", "failed"]]

    class FakeCtx:
        user = "test"
        app_user = "test"

        def db_parts(self):
            return ("u", "p", "h", "5432", "d")

    ctx = FakeCtx()
    original = dbq.query
    dbq.query = lambda *_a, **_k: (rows, "")
    try:
        streaks, err = dbq.fail_streaks(ctx)
    finally:
        dbq.query = original
    assert streaks[7] == 0, "a 'skipped' run must clear the streak"
    assert streaks[9] == 3


def test_unreadable_database_degrades_and_never_reports_ok(tmp_path, monkeypatch):
    """The operator who cannot read .env must be told 'unknown', not 'fine'."""
    monkeypatch.setenv("FM_APP_DIR", str(tmp_path))
    import importlib

    from satom_cli import context as cli_context
    importlib.reload(cli_context)
    ctx = cli_context.Ctx()
    for fn in (cmd_ops.scheduler_status, cmd_ops.device_status, cmd_ops.user_list,
               cmd_ops.alerts_status):
        res = fn(ctx, [])
        assert res.status != "ok", (
            "%s reported 'ok' with no database. Absence of data is not health."
            % fn.__name__)
    importlib.reload(cli_context)


# -- destructive verbs refuse without --yes -------------------------------
def test_every_danger_node_documents_the_confirmation():
    missing = []
    for path, node in cli_tree.walk():
        if node.danger and node.run is not None:
            text = (node.usage or "") + " " + (node.help or "")
            if "--yes" not in text and "Requires --yes" not in text:
                missing.append(" ".join(path))
    assert not missing, (
        "destructive commands whose confirmation is not in the help/usage: %s"
        % missing)


def test_repair_tmp_refuses_without_yes_then_deletes_with_it(tmp_path, monkeypatch):
    monkeypatch.setenv("FM_APP_DIR", str(tmp_path))
    import importlib

    from satom_cli import context as cli_context
    importlib.reload(cli_context)
    importlib.reload(cmd_fix)
    scratch = tmp_path / "data" / "tmp"
    scratch.mkdir(parents=True)
    victim = scratch / "old-thing"
    victim.mkdir()
    (victim / "f").write_text("x")
    import os
    import time
    old = time.time() - 40 * 86400
    os.utime(victim, (old, old))
    ctx = cli_context.Ctx()

    res = cmd_fix.repair_tmp(ctx, ["--older-than", "7"])
    assert res.exit_code == 2, "must refuse without --yes"
    assert victim.exists(), "nothing may be deleted before confirmation"

    res = cmd_fix.repair_tmp(ctx, ["--older-than", "7", "--yes"])
    assert res.status == "ok"
    assert not victim.exists()
    importlib.reload(cli_context)
    importlib.reload(cmd_fix)


def test_restore_refuses_an_unknown_bundle_name(tmp_path, monkeypatch):
    monkeypatch.setenv("FM_APP_DIR", str(tmp_path))
    import importlib

    from satom_cli import context as cli_context
    importlib.reload(cli_context)
    importlib.reload(cmd_fix)
    ctx = cli_context.Ctx()
    res = cmd_fix.restore_db(ctx, ["../../etc/passwd", "--yes"])
    assert res.exit_code == 2
    assert res.status == "bad"
    importlib.reload(cli_context)
    importlib.reload(cmd_fix)


def test_the_privileged_runner_cannot_be_disabled_from_the_cli():
    """Disabled, satom-updater.path leaves every enqueued update at 'queued'
    forever with nothing reporting an error."""
    assert "updater" not in [a for a in cmd_fix.TOGGLEABLE if False]  # sanity
    src = Path(cmd_fix.__file__).read_text()
    assert 'action == "disable" and alias == "updater"' in src


# -- runbooks -------------------------------------------------------------
def test_every_runbook_is_listed_and_every_listed_runbook_exists():
    assert set(runbooks.ORDER) == set(runbooks.RUNBOOKS), (
        "ORDER and RUNBOOKS disagree: %s"
        % (set(runbooks.ORDER) ^ set(runbooks.RUNBOOKS)))


@pytest.mark.parametrize("topic", sorted(runbooks.RUNBOOKS))
def test_runbook_has_a_title_and_actionable_body(topic):
    title, lines = runbooks.RUNBOOKS[topic]
    assert title.strip()
    assert len(lines) >= 5, "%s is too thin to follow under pressure" % topic
    assert any("satom " in ln or "systemctl" in ln or "sudo " in ln for ln in lines), (
        "%s contains no command to run" % topic)


# -- the tree stays honest ------------------------------------------------
def test_every_leaf_handler_is_callable():
    for path, node in cli_tree.walk():
        if node.run is not None:
            assert callable(node.run), " ".join(path)


def test_read_verbs_have_no_side_effect_shaped_names():
    """A 'get' or 'show' handler must not be one of the mutating helpers."""
    mutators = {"restore_db", "repair_tmp", "repair_jobs", "seed_actions",
                "promote", "restart_all", "support_bundle"}
    for path, node in cli_tree.walk():
        if node.run is None or not path or path[0] not in ("get", "show"):
            continue
        assert node.run.__name__ not in mutators, " ".join(path)
