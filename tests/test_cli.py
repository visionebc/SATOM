"""Guards for the operator CLI (deploy/satom_cli, /usr/local/sbin/satom).

Each test here exists because the property it checks is invisible in normal use
and catastrophic when it breaks:

* The CLI must import with NO third-party dependency, because its job is the
  node whose venv is broken. Nothing in normal operation would reveal a stray
  ``import flask`` until the day it matters.
* The command tree must declare help and privilege for every node, because an
  undeclared node fails with a traceback for the unprivileged operator.
* The installed binary must be a root-owned COPY outside the app tree. A
  symlink into /opt/satom would turn 'sudo satom' into a root escalation for a
  compromised web worker.
"""
import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CLI_DIR = REPO / "deploy" / "satom_cli"
sys.path.insert(0, str(REPO / "deploy"))

from satom_cli import main as cli_main  # noqa: E402
from satom_cli import tree as cli_tree  # noqa: E402
from satom_cli.context import RESTARTABLE, UNITS, Ctx  # noqa: E402
from satom_cli.render import EXIT_DENIED, EXIT_USAGE  # noqa: E402

# Anything outside the standard library. If the CLI grows a dependency on one
# of these at module level it stops working on exactly the broken node it was
# written for.
FORBIDDEN_ROOTS = {
    "flask", "sqlalchemy", "click", "psycopg", "psycopg2", "requests", "httpx",
    "paramiko", "yaml", "cryptography", "werkzeug", "app", "jinja2", "dotenv",
}

CLI_FILES = sorted(CLI_DIR.glob("*.py"))


@pytest.mark.parametrize("path", CLI_FILES, ids=lambda p: p.name)
def test_cli_modules_import_only_stdlib_at_module_level(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    offenders = []
    for node in tree.body:  # module level ONLY — lazy imports inside functions are fine
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            continue
        for name in names:
            root = name.split(".")[0]
            if root in FORBIDDEN_ROOTS:
                offenders.append(name)
    assert not offenders, (
        "%s imports %s at module level. The CLI must run on a node whose venv "
        "is broken — move it inside the function that needs it."
        % (path.name, offenders))


def test_cli_package_imports_without_the_app_venv():
    """Import the package in a bare interpreter with the repo NOT on sys.path."""
    code = ("import sys; sys.path.insert(0, %r);"
            "import satom_cli.main, satom_cli.tree, satom_cli.context;"
            "print('OK')" % str(REPO / "deploy"))
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, env=env, cwd="/")
    assert "OK" in out.stdout, out.stderr


def test_every_tree_node_declares_help_and_privilege():
    for path, node in cli_tree.walk():
        where = " ".join(path) or "<root>"
        assert node.help, "node %r has no help text" % where
        assert isinstance(node.needs_root, bool), "node %r has no privilege level" % where
        if node.run is None:
            assert node.children, "node %r is neither a group nor runnable" % where
        else:
            assert not node.children, ("node %r both runs and has children — the "
                                       "parser cannot resolve that" % where)


def test_read_only_verbs_never_require_root():
    """'get', 'show' and 'diagnose' must work for an unprivileged operator.

    This is the half of the tool that has to survive a broken box, and the
    operator is frequently not root yet when they start looking.
    """
    for verb in ("get", "show", "diagnose"):
        for path, node in cli_tree.walk(cli_tree.ROOT.children[verb], (verb,)):
            assert not node.needs_root, (
                "%s requires root; read-only verbs must not." % " ".join(path))


def test_every_state_changing_verb_requires_root():
    for path, node in cli_tree.walk(cli_tree.ROOT.children["execute"], ("execute",)):
        if node.run is None:
            continue
        # 'update status' only reads the status files.
        if path[-1] == "status":
            continue
        assert node.needs_root, "%s changes state but does not require root" % " ".join(path)


def _ctx(root=False):
    c = Ctx()
    c.is_root = root
    c.uid = 0 if root else 1000
    return c


def test_privileged_verb_refuses_without_root_and_does_not_raise():
    res = cli_main.dispatch(_ctx(root=False), ["execute", "restart", "web"])
    assert res.exit_code == EXIT_DENIED
    body = " ".join(l for _, (_, lines) in res.sections for l in map(str, lines))
    # The FULL command, arguments included: an operator who has to retype the
    # arguments from memory retypes them wrong.
    assert "sudo satom execute restart web" in body, (
        "the refusal must echo the whole command, not just the verb path")
    assert "show sudoers" in body, "it must say how to obtain the privilege"


def test_unknown_command_is_usage_error_not_crash():
    res = cli_main.dispatch(_ctx(), ["get", "sytem", "status"])
    assert res.exit_code == EXIT_USAGE
    assert "unknown command" in res.title


def test_question_mark_lists_children_at_every_level():
    for tokens in ([], ["get"], ["execute"], ["execute", "reinstall"]):
        res = cli_main.dispatch(_ctx(), tokens + ["?"])
        rows = [r for _, (kind, body) in res.sections if kind == "rows" for r in body]
        assert rows, "'%s ?' produced no completions" % " ".join(tokens)


def test_updater_unit_is_not_operator_restartable():
    """satom-updater is the privileged root runner. A CLI verb that restarts it
    is a CLI verb that re-enters the privilege boundary sideways."""
    assert "updater" in UNITS
    assert "updater" not in RESTARTABLE
    assert "postgres" not in RESTARTABLE


# -- installation integrity ----------------------------------------------
def test_launcher_loads_from_root_owned_path_not_the_app_tree():
    src = (REPO / "deploy" / "satom-cli-launcher").read_text()
    assert "/usr/local/lib/satom-cli" in src
    assert "/opt/satom" not in src.split('"""')[2] if src.count('"""') > 2 else True, (
        "the launcher must not put the app tree on sys.path")
    code = [l for l in src.splitlines() if not l.strip().startswith("#")]
    body = "\n".join(code)
    assert "sys.path.insert(0, \"/usr/local/lib/satom-cli\")" in body


def test_installer_copies_and_refuses_a_symlinked_binary():
    src = (REPO / "deploy" / "install-cli.sh").read_text()
    assert "cp -a" in src, "the CLI must be COPIED, never linked into the app tree"
    assert "chown -R root:root" in src
    assert "-L \"$BIN\"" in src, "the installer must reject a symlinked sudo target"
    assert "install -o root -g root -m 0755" in src


def test_diagnose_privilege_flags_a_service_account_grant():
    """The one sudoers line that must never exist is the one granting this CLI
    to the service account: it equals NOPASSWD: ALL for the web worker."""
    src = (CLI_DIR / "cmd_diagnose.py").read_text()
    assert "/usr/local/sbin/satom" in src
    assert "NOPASSWD: ALL" in src
