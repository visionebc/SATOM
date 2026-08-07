"""Guards for the seams the sealed envelope has to reach.

The module itself is guarded in test_recovery_seal.py. What is guarded here is
everything that decides whether the envelope is ever CARRIED anywhere -- because
an envelope that only exists on the node it protects is worth nothing, and that
failure is invisible: sealing succeeds, the state page says "sealed", and the
copy simply is not in the bundle.
"""
from __future__ import annotations

import ast
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "installers" / "install-satom.sh"
BACKUP = ROOT / "app" / "services" / "system_backup.py"

sys.path.insert(0, str(ROOT / "deploy"))


# --------------------------------------------------------------------- helpers

def shell_code(path: pathlib.Path) -> str:
    """Only the lines the shell EXECUTES.

    Comments in this repo explain the guards they sit next to, so a plain
    substring assertion happily matches the prose that describes a rule instead
    of the line that enforces it. That mistake has been made thirteen times
    here; it is not made again.
    """
    out = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        out.append(line.split(" #", 1)[0])
    return "\n".join(out)


def py_code(path: pathlib.Path) -> str:
    """Source with comments and docstrings removed, same reason."""
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body:
            first = body[0]
            if (isinstance(first, ast.Expr)
                    and isinstance(getattr(first, "value", None), ast.Constant)
                    and isinstance(first.value.value, str)):
                body.pop(0)
    return ast.unparse(tree)


def test_the_comment_stripper_is_not_vacuous():
    """If shell_code ever returns nothing, every guard below passes trivially."""
    code = shell_code(INSTALLER)
    assert len(code) > 10_000
    assert "SEAL_PASS" in code


# ------------------------------------------------------- installer: WHEN sealed

def test_the_passphrase_is_derived_outside_the_cluster_branch():
    """The correction that matters: sealing cannot be a cluster-join feature.

    A standalone node never joins, and a standalone node is the one with NO
    second copy of anything -- it needs the envelope more than a pair does, not
    less. So the passphrase must be derived on a path that a standalone install
    also takes.
    """
    code = shell_code(INSTALLER)
    m = re.search(r'if \[ "\$ROLE" = "secondary" \]; then\s*\n'
                  r'\s*SEAL_PASS=\$\(jget seal_passphrase\)\s*\n'
                  r'\s*else\s*\n'
                  r'([\s\S]{0,400}?)\nfi', code)
    assert m, "no role-split derivation of SEAL_PASS found"
    assert "generate_passphrase" in m.group(1), (
        "the non-secondary branch must MINT a passphrase; a standalone install "
        "reaching this point with nothing is the gap this guard exists for")


def test_the_secondary_inherits_the_passphrase_from_the_join_key():
    """Both nodes must open the SAME envelope, or the pair has two custodies
    and the operator holds one of them."""
    code = shell_code(INSTALLER)
    assert "seal_passphrase" in code
    assert '"seal_passphrase": "${SEAL_PASS}"' in code


def test_sealing_happens_only_after_the_health_check_passes():
    """An envelope built before the app is proven to start is an envelope
    built from a configuration that may never work."""
    code = shell_code(INSTALLER)
    health = code.index("healthz responde 200")
    # NOT "execute seal recovery --yes": that exact string also appears in a
    # remediation hint printed ~500 lines earlier, and index() would find the
    # hint. Anchor on the invocation's own shape instead.
    seal = code.index('SATOM_SEAL_PASSPHRASE="$SEAL_PASS" /usr/local/sbin/satom')
    assert health < seal, "seal runs before the health check"


def test_a_failed_seal_clears_the_passphrase_rather_than_printing_it():
    """Printing a passphrase for an envelope that was never written teaches
    the operator they have custody they do not have."""
    code = shell_code(INSTALLER)
    m = re.search(r'execute seal recovery --yes[\s\S]{0,400}?\bSEAL_PASS=""', code)
    assert m, "the failure branch must blank SEAL_PASS"


def test_the_passphrase_is_never_redirected_into_the_install_log():
    """The install log is a file that survives on disk next to the node. A
    passphrase in it is a passphrase stored, which defeats the seal."""
    code = shell_code(INSTALLER)
    for line in code.splitlines():
        if "$SEAL_PASS" in line or "${SEAL_PASS}" in line:
            assert "INSTALL_LOG" not in line, (
                "passphrase reaches the install log: %s" % line.strip())


def test_the_passphrase_is_shown_and_not_written_anywhere():
    code = shell_code(INSTALLER)
    assert re.search(r'echo\s+"\s*\$\{SEAL_PASS\}"', code), \
        "the banner must print the passphrase"
    for line in code.splitlines():
        if "SEAL_PASS" not in line:
            continue
        # /dev/null is the discard sink -- the opposite of what this guard
        # is about. The promise is that nothing SURVIVING on disk holds the
        # passphrase; treating the sink as a file would forbid the very fix
        # that keeps it out of the install log.
        probe = (line.replace(">>", "")
                     .replace(">/dev/null", "")
                     .replace("> /dev/null", ""))
        assert not re.search(r'>\s*"?\$?\{?[A-Za-z_/]', probe), \
            "passphrase redirected to a file: %s" % line.strip()


# ---------------------------------------------------------- bundle: WHERE it goes

def test_the_bundle_packages_the_sealed_envelope():
    """Anchored to the COPY CALL, not to the filename.

    The filename also appears in the "absent" branch and in the restore path,
    so a substring assertion stays green while the copy itself is deleted --
    which is exactly what the mutation harness demonstrated. The artefact this
    guard is about is the call that puts bytes in the staging directory.
    """
    tree = ast.parse(BACKUP.read_text())
    copies = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Attribute) and f.attr == "copy2"):
            continue
        if not node.args:
            continue
        src = ast.unparse(node.args[0])
        dst = ast.unparse(node.args[1]) if len(node.args) > 1 else ""
        if "seal_path()" in src and "recovery-seal.json" in dst:
            copies.append((src, dst))
    assert copies, (
        "no shutil.copy2(<seal_path()>, <stage>/recovery-seal.json) call: the "
        "bundle does not actually carry the envelope")


def test_an_absent_envelope_is_reported_not_silently_skipped():
    """A bundle with no envelope cannot rebuild anything, and it looks exactly
    like one that can. It has to say so."""
    code = py_code(BACKUP)
    assert "recovery-seal ABSENT" in code


def test_a_restore_keeps_the_nodes_own_envelope():
    """A live node is the authority on its own custody; the envelope frozen
    into an old bundle is by definition older. Overwriting would swap the
    passphrase the operator holds for one they rotated away from."""
    code = py_code(BACKUP)
    # Scope to restore_backup: the first mention of the envelope in this file
    # is in create_backup, and a regex from there proves nothing about restore.
    start = code.index("def restore_backup")
    seg = code[start:]
    assert "recovery-seal.json" in seg, "restore never looks for the envelope"
    assert "if not _seal.seal_path().exists()" in seg


def test_packaging_failure_never_fails_the_backup():
    """A backup that aborts over custody packaging trades the copy that works
    for the copy that is optional."""
    code = py_code(BACKUP)
    assert "recovery-seal error" in code


# ------------------------------------------------------------- CLI registration

def test_both_verbs_are_registered_as_root_and_dangerous():
    from satom_cli import tree as t
    found = {}
    for node in t.walk():
        path = node[0] if isinstance(node, tuple) else getattr(node, "path", "")
        found[" ".join(path) if isinstance(path, (list, tuple)) else str(path)] = node
    keys = [k for k in found if "seal recovery" in k]
    assert any("execute seal recovery" in k for k in keys), keys
    assert any("execute unseal recovery" in k for k in keys), keys


def test_the_seal_verbs_require_root_and_confirmation():
    src = (ROOT / "deploy" / "satom_cli" / "tree.py").read_text()
    for verb in ("seal_recovery", "unseal_recovery"):
        m = re.search(r'run=f\.%s,\s*([^)]*)\)' % verb, src)
        assert m, verb
        assert "needs_root=True" in m.group(1), verb
        assert "danger=True" in m.group(1), verb


def test_the_passphrase_is_taken_from_the_environment_not_an_argument():
    """A --passphrase flag lands in shell history, in ps output and in the
    sudo log: three copies of the one secret whose purpose is to have one."""
    code = py_code(ROOT / "deploy" / "satom_cli" / "cmd_fix.py")
    assert 'SEAL_ENV = ' in code or "SEAL_ENV=" in code
    assert "--passphrase" not in code


def test_diagnose_recovery_reports_seal_findings():
    code = py_code(ROOT / "deploy" / "satom_cli" / "cmd_checks.py")
    assert "recovery_seal" in code
    assert "_rs.check()" in code


def test_the_passphrase_never_reaches_the_child_process_argv():
    """_app_call runs ``python3 -c <snippet>``, so the snippet IS the child's
    command line -- readable in ``ps`` by every user on the box -- and any
    traceback echoes the offending source line. Interpolating the passphrase
    into the snippet leaked it to both. It travels in the environment instead.
    """
    code = py_code(ROOT / "deploy" / "satom_cli" / "cmd_fix.py")
    assert "_SEAL_CODE % (passphrase" not in code
    assert "_UNSEAL_CODE % passphrase" not in code
    assert "os.environ['SATOM_SEAL_PASSPHRASE']" in code
    assert "os.environ[SEAL_ENV] = passphrase" in code


def test_the_passphrase_is_removed_from_the_environment_afterwards():
    """Set for the child, not for the rest of the process. A CLI run that
    seals and then does something else must not carry the secret along."""
    code = py_code(ROOT / "deploy" / "satom_cli" / "cmd_fix.py")
    assert code.count("os.environ.pop(SEAL_ENV, None)") >= 2


def test_the_installers_seal_output_does_not_reach_the_install_log():
    """The install log survives on disk next to the node. It is the one place
    a traceback from the seal call could deposit a passphrase."""
    code = shell_code(INSTALLER)
    for line in code.splitlines():
        if "execute seal recovery --yes" in line and "satom" in line and "warn" not in line:
            assert "INSTALL_LOG" not in line, line.strip()
            assert "/dev/null" in line, line.strip()
